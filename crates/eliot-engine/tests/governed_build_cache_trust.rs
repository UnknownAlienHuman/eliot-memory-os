//! Executed proof for issue #1923 acceptance criterion A4: "a cache entry
//! from a different trust/source/toolchain fingerprint is not reused."
//!
//! This file links `eliot-engine` as an external crate and reaches the runtime
//! through the `eliot_engine::governed_build` module, which is the same public
//! surface a production composition root uses. It therefore drives the real
//! application entrypoint [`GovernedBuildRuntime::run_admitted`] and the whole
//! refusal chain end to end:
//!
//! ```text
//! GovernedBuildRuntime::run_admitted
//!   -> CachedDerivationService::lookup_governed
//!        -> CacheLane::identity_for           (trust/source/toolchain closure)
//!             -> CacheLane::lookup_identity
//!                  -> DerivedCacheStore::lookup
//!                       -> TrustPolicy::authenticate   <-- the trust gate
//! ```
//!
//! Contract anchors:
//!   * I02.22 "Derived-cache trust and reuse": missing, unreadable, untrusted,
//!     or mismatched cache is a *cache miss, not a correctness failure*, and
//!     no correctness path depends on cache availability.
//!   * I10.08.14: reuse only by an exact `BuildFingerprint`; a cache hit
//!     carries provenance and never creates a new compiler observation, and a
//!     test verdict is never reused merely because the binary is cached.
//!
//! Shape of the proof: an entry is published under trust fingerprint A (a
//! trusted producer holding a trusted cache root). A second governed BUILD then
//! presents trust fingerprint B (a different, untrusted producer). B must
//!
//!   1. not be served A's bytes,
//!   2. have the refusal recorded as evidence rather than swallowed, and
//!   3. still return the correct artifact, because the refusal is a miss and
//!      the genuine uncached derivation still runs and its bytes are read back
//!      from the declared artifact path.
//!
//! A final replay under fingerprint A then proves the refused lookup left the
//! valid entry intact instead of poisoning the store.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eliot_build_test_graph::{
    CacheLimits, CacheRejectReason, DERIVED_CACHE_SCHEMA_V1, DerivedCacheStore, FreshDerivation,
    RootDisposition, TrustPolicy,
};
use eliot_contracts::{
    ClockReading, ContractId, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
    ResourceGeneration, SourceId, StateFence, sha256_hex,
};
use eliot_engine::governed_build::{
    BuildExecution, GovernedBuildApplicationRequest, GovernedBuildOptions, GovernedBuildRuntime,
};
use eliot_instrument_api::{ExecutionStatus, InstrumentInvocation, InstrumentKind};
use eliot_instrument_runner::cache_lane::{CacheLane, CacheLaneAttestations};
use eliot_instrument_runner::registry::{
    InvalidationSet, ProviderRegistry, RegistryFreshness, ResolvedExecutableIdentity,
};
use eliot_instrument_runner::{
    KernelAdmissionError, KernelAdmittedProcess, KernelInstrumentAdmission,
};
use eliot_instrument_rustc::RUSTC_INSTRUMENT;
use eliot_platform::ClockObservation;
use eliot_process::{
    ActionLeaseRef, CancellationReceipt, DescendantEvidence, DispatchAuthorityId,
    DispatchPermitAuthority, DispatchValidationContext, EnvironmentProjection, EvidenceSinkError,
    ExitDisposition, ExitStatus, FencingToken, Generation, ImageId, JobId, KernelDispatchKey,
    OperationId, PermitIssuance, PhysicalProcessBinding, ProcessCallerSession, ProcessEvidence,
    ProcessEvidenceSink, ProcessExecutionError, ProcessExecutionView, ProcessExecutor,
    ProcessHealth, ProcessHealthStatus, ProcessId, ProcessIntent, ProcessOwnerBinding,
    ProcessRequest, ProcessSessionClass, ProcessStartReceipt, ProcessState, ProcessTreeId,
    ResourceLimits, SessionId, SuspendedProcessIdentity,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const RESOURCE_GENERATION: u64 = 3;
const REQUEST_ID: &str = "governed-build-trust-1923";
const SESSION_ID: &str = "governed-build-session-1923";

/// Trust fingerprint A: the producer and cache root the policy admits.
const TRUSTED_PRODUCER: &str = "governed-build-producer";
const TRUSTED_ROOT: &str = "governed-build-cache-root";
/// Trust fingerprint B: a different producer the same policy does not admit.
const FOREIGN_PRODUCER: &str = "foreign-trust-producer";

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

fn epoch() -> TestResult<EpochId> {
    let lineage = EpochLineageId::new(TEST_LINEAGE)?;
    let sequence = NonZeroU64::new(7).ok_or("non-zero state sequence")?;
    Ok(EpochId::new(lineage, sequence)?)
}

fn fence() -> TestResult<StateFence> {
    Ok(StateFence::new(
        epoch()?,
        ResourceGeneration::new(RESOURCE_GENERATION)?,
    ))
}

fn clock(known_ms: i64) -> ClockReading {
    ClockReading {
        valid_time_ms: Some(known_ms - 1),
        known_time_ms: Some(known_ms),
        transaction_sequence: None,
        monotonic_ns: Some(1),
    }
}

fn fingerprints() -> InvalidationSet {
    InvalidationSet {
        source: "source".to_owned(),
        lock: "lock".to_owned(),
        toolchain: "toolchain".to_owned(),
        env: "environment".to_owned(),
        exe: "executable".to_owned(),
        profile: "profile".to_owned(),
        parser: "parser".to_owned(),
    }
}

fn freshness(fingerprints: &InvalidationSet) -> RegistryFreshness<'_> {
    RegistryFreshness {
        generation: RESOURCE_GENERATION,
        normative_pair_digest: "normative",
        fingerprints,
    }
}

fn invocation() -> TestResult<InstrumentInvocation> {
    Ok(InstrumentInvocation {
        request: RequestMetadata {
            request_id: RequestId::new(REQUEST_ID)?,
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product")?,
            source_id: SourceId::new("source")?,
            state_fence: fence()?,
            clock: clock(100),
        },
        instrument: ContractId::new(RUSTC_INSTRUMENT)?,
        kind: InstrumentKind::Build,
        profile: "dev".to_owned(),
        target: "artifact".to_owned(),
        arguments: vec!["--crate-name".to_owned(), "cache_probe".to_owned()],
        input_artifacts: Vec::new(),
        declared_scope: "scope".to_owned(),
        requested_at: clock(100),
    })
}

/// The machine-derived executable observation the registry entry requires.
///
/// The closure binds `compiler_version` from this observation, so it must
/// carry an observed tool version. The path and digests are stable fixture
/// facts because this proof moves only the trust dimension.
fn executable() -> TestResult<ResolvedExecutableIdentity> {
    Ok(ResolvedExecutableIdentity::new(
        RUSTC_INSTRUMENT,
        "C:/toolchain/rustc.exe".to_owned(),
        "a".repeat(64),
        Some("rustc 1.89.0 (x86_64-pc-windows-msvc)".to_owned()),
        "b".repeat(64),
        vec!["--crate-name".to_owned(), "cache_probe".to_owned()],
    )?)
}

fn attestations(producer_id: &str, bytes: &[u8]) -> CacheLaneAttestations {
    CacheLaneAttestations {
        source_digest: sha256_hex(b"source-closure"),
        generated_input_digest: sha256_hex(b"generated-inputs"),
        config_digest: sha256_hex(b"config-features-environment"),
        producer_id: producer_id.to_owned(),
        producer_generation: 7,
        root_identity: TRUSTED_ROOT.to_owned(),
        root_acl_digest: sha256_hex(b"root-acl"),
        root_disposition: RootDisposition::Direct,
        schema_revision: DERIVED_CACHE_SCHEMA_V1.to_owned(),
        content_digest: sha256_hex(bytes),
    }
}

fn scratch_dir(tag: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!("eliot-1923-trust-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// The single Kernel dispatch-authority identity shared by the admission that
/// mints the permit and the executor that consumes it.
///
/// P-03 authenticates a permit against the consuming authority's exact
/// `(authority_id, key)` pair plus the revision heads and validation revision
/// the permit carries, so both sides of this proof must agree on all four.
const DISPATCH_AUTHORITY_ID: &str = "governed-build-dispatch-authority-1923";
const DISPATCH_KEY: [u8; 32] = [0x38; 32];
const VALIDATION_REVISION: u64 = 41;

fn revision_heads() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("authority".to_owned(), "a".repeat(64)),
        ("kernel".to_owned(), "c".repeat(64)),
        ("state".to_owned(), "b".repeat(64)),
    ])
}

// ---------------------------------------------------------------------------
// The process side: a real P-03 ceremony over a scripted build child.
// ---------------------------------------------------------------------------

struct NoopSink;

impl ProcessEvidenceSink for NoopSink {
    fn record(&self, _evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        Ok(())
    }
}

#[derive(Default)]
struct ScriptedCounts {
    starts: usize,
    inspections: usize,
    terminal_reported: bool,
}

/// Executor that runs one complete, real P-03 admission ceremony and then
/// reports the child as exited successfully, after writing its artifact bytes.
///
/// The counters let the proof distinguish "the cache refused and the build
/// really ran" from "nothing ran at all".
struct ScriptedExecutor {
    counts: Mutex<ScriptedCounts>,
    state: Mutex<Option<ProcessState>>,
    artifact: PathBuf,
    artifact_bytes: Vec<u8>,
}

impl ScriptedExecutor {
    fn new(artifact: PathBuf, artifact_bytes: Vec<u8>) -> Self {
        Self {
            counts: Mutex::new(ScriptedCounts::default()),
            state: Mutex::new(None),
            artifact,
            artifact_bytes,
        }
    }

    fn counts(&self) -> (usize, usize, bool) {
        let counts = self.counts.lock().expect("scripted executor counts");
        (counts.starts, counts.inspections, counts.terminal_reported)
    }
}

impl ProcessExecutor for ScriptedExecutor {
    async fn start(
        &self,
        request: ProcessRequest,
        _sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        self.counts.lock().expect("scripted executor counts").starts += 1;

        let intent = request.intent().clone();
        let fence = request.fence().clone();
        let revisions = revision_heads();

        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new(DISPATCH_AUTHORITY_ID).map_err(unavailable)?,
            KernelDispatchKey::from_secret_bytes(DISPATCH_KEY).map_err(unavailable)?,
        );
        // P-03 consumes a one-shot permit: the consuming authority must hold
        // the nonce in its own issued set. Re-issuing the identical permit over
        // the shared key is exactly what a real dispatch authority does as it
        // hands the sealed request to P-04; the permit used for consumption is
        // still the one bound inside the request.
        let _issued = authority
            .issue(
                &intent,
                PermitIssuance::new(
                    ActionLeaseRef::new("governed-build-admission-lease").map_err(unavailable)?,
                    fence.clone(),
                    revisions.clone(),
                    100,
                    10_000,
                    "governed-build-admission-nonce-1923",
                )
                .map_err(unavailable)?,
            )
            .map_err(unavailable)?;
        let suspended = SuspendedProcessIdentity::new(
            ProcessId::new("governed-build-pid").map_err(unavailable)?,
            intent.process_tree_id().clone(),
            intent.job_id().clone(),
            intent.image_id().clone(),
            intent.session_id().clone(),
            intent.generation(),
            PhysicalProcessBinding::new(
                4242,
                11,
                intent.executable(),
                "Local\\Eliot-Governed-Build-Proof",
            )
            .map_err(unavailable)?,
            120,
            intent.executable_sha256(),
        )?;
        let observed_clock: ClockObservation = serde_json::from_value(serde_json::json!({
            "valid_time_ms": 150,
            "known_time_ms": 150,
            "transaction_sequence": null,
            "monotonic_ns": 1
        }))
        .map_err(unavailable)?;
        let context = DispatchValidationContext::new(
            observed_clock,
            fence,
            epoch().map_err(unavailable)?,
            revisions,
            VALIDATION_REVISION,
        )
        .map_err(unavailable)?;
        let validated = authority
            .validate_and_consume(request, suspended, &context)
            .map_err(unavailable)?;

        let mut state = ProcessState::from_validated(&validated);
        state
            .mark_resumed(
                151,
                ProcessHealth::new(ProcessHealthStatus::Healthy, true, 151, None)
                    .map_err(unavailable)?,
            )
            .map_err(unavailable)?;
        let receipt = ProcessStartReceipt::new(&state).map_err(unavailable)?;

        // The genuine uncached derivation "produces" its artifact here.
        // `run` hashes these exact bytes after the terminal observation, so
        // the published content digest is observed rather than declared.
        std::fs::write(&self.artifact, &self.artifact_bytes).map_err(|error| {
            ProcessExecutionError::Unavailable(format!("artifact writeback failed: {error}"))
        })?;

        *self.state.lock().expect("scripted executor state") = Some(state);
        Ok(receipt)
    }

    async fn inspect(
        &self,
        _operation_id: OperationId,
    ) -> Result<ProcessExecutionView, ProcessExecutionError> {
        self.counts
            .lock()
            .expect("scripted executor counts")
            .inspections += 1;

        let mut guard = self.state.lock().expect("scripted executor state");
        let state = guard.as_mut().ok_or_else(|| {
            ProcessExecutionError::Unavailable("no admitted child to inspect".to_owned())
        })?;

        let mut counts = self.counts.lock().expect("scripted executor counts");
        if counts.terminal_reported {
            return Err(ProcessExecutionError::Unavailable(
                "the scripted proof child reports its terminal state exactly once".to_owned(),
            ));
        }
        counts.terminal_reported = true;
        drop(counts);

        let identity = state
            .view()
            .identity()
            .map(|identity| identity.process_id().clone())
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable("resumed identity missing".to_owned())
            })?;
        let descendants = DescendantEvidence::new(
            state.binding().clone(),
            identity,
            Vec::new(),
            true,
            true,
            Some("raw-evidence:governed-build-1923".to_owned()),
        )
        .map_err(unavailable)?;
        state
            .exit(
                ExitStatus::new(ExitDisposition::Completed, Some(0), None, 202)
                    .map_err(unavailable)?,
                descendants,
            )
            .map_err(unavailable)?;
        Ok(state.view())
    }

    async fn cancel(
        &self,
        _operation_id: OperationId,
    ) -> Result<CancellationReceipt, ProcessExecutionError> {
        Err(ProcessExecutionError::Unavailable(
            "the scripted proof child must never be cancelled".to_owned(),
        ))
    }

    async fn reconcile(
        &self,
        _operation_id: OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        Err(ProcessExecutionError::Unavailable(
            "the scripted proof child must never be reconciled".to_owned(),
        ))
    }
}

fn unavailable(error: impl std::fmt::Display) -> ProcessExecutionError {
    ProcessExecutionError::Unavailable(error.to_string())
}

// ---------------------------------------------------------------------------
// The proof.
// ---------------------------------------------------------------------------

// The proof is one continuous ceremony on purpose: seeding the trusted
// fingerprint, the refused foreign lookup, the fresh build that replaces it and
// the replay that shows the valid union survived are separated by no fixture
// reset, because splitting them would let a later step run against state an
// earlier step never established.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn foreign_trust_fingerprint_entry_is_never_reused_and_the_build_still_runs() -> TestResult {
    let dir = scratch_dir("refuse")?;
    let fingerprints = fingerprints();
    let registry =
        ProviderRegistry::ready(RESOURCE_GENERATION, "normative".to_owned(), &fingerprints)?;
    let freshness = freshness(&fingerprints);
    let executable = executable()?;
    let invocation = invocation()?;

    // The bytes fingerprint A holds. They are deliberately NOT the bytes the
    // scripted build produces, so a wrongly served hit would be detectable by
    // artifact content and not only by the rejection counter.
    let trusted_bytes = b"observed-build-artifact-under-trust-fingerprint-a".to_vec();
    let fresh_bytes = b"genuine-uncached-build-output".to_vec();

    // Warm the store under trust fingerprint A through the real store API,
    // exactly as a prior governed BUILD publication would have.
    let trust = TrustPolicy::new(
        vec![TRUSTED_PRODUCER.to_owned()],
        vec![TRUSTED_ROOT.to_owned()],
    )?;
    let mut store = DerivedCacheStore::new(CacheLimits::default());
    let trusted_attest = attestations(TRUSTED_PRODUCER, &trusted_bytes);
    let trusted_identity = CacheLane::identity_for(
        registry.resolve_current(&invocation, &freshness)?,
        Some(&executable),
        &trusted_attest,
    )?;
    store
        .publish(
            &trusted_identity,
            &trust,
            FreshDerivation::new(trusted_bytes.clone(), 1, false),
        )
        .map_err(|error| format!("seeding trust fingerprint A failed: {error:?}"))?;
    assert_eq!(
        store.counters().stores,
        1,
        "trust fingerprint A must be present before the foreign request"
    );

    // Fingerprint B moves only the trust dimension: the same source, toolchain,
    // root, and expected content digest, but a producer this policy does not
    // admit. That is exactly the "different trust fingerprint" of A4.
    let foreign_attest = attestations(FOREIGN_PRODUCER, &fresh_bytes);
    assert_eq!(
        foreign_attest.source_digest, trusted_attest.source_digest,
        "the source closure must be identical across both fingerprints"
    );
    assert_eq!(
        foreign_attest.root_identity, trusted_attest.root_identity,
        "only the producer identity may differ between the two fingerprints"
    );
    let foreign_identity = CacheLane::identity_for(
        registry.resolve_current(&invocation, &freshness)?,
        Some(&executable),
        &foreign_attest,
    )?;
    assert_ne!(
        foreign_identity.producer_id, trusted_identity.producer_id,
        "the two fingerprints must differ in producer"
    );
    assert_ne!(
        foreign_identity.digest().ok(),
        trusted_identity.digest().ok(),
        "the two fingerprints must not share one cache key"
    );
    let artifact_path = dir.join("governed-build-artifact.bin");
    let executor = Arc::new(ScriptedExecutor::new(
        artifact_path.clone(),
        fresh_bytes.clone(),
    ));

    let mut runtime = GovernedBuildRuntime::new(executor.clone(), store, trust);

    // I02.22: the untrusted request is a MISS, never a correctness failure.
    let outcome = runtime
        .run_admitted(
            GovernedBuildApplicationRequest {
                invocation: invocation.clone(),
                registry: &registry,
                freshness,
                executable: Some(&executable),
                attestations: foreign_attest,
                artifact_path: artifact_path.clone(),
                sink: Arc::new(NoopSink),
                options: GovernedBuildOptions::default(),
            },
            &ScriptedAdmission,
        )
        .await?;

    // (1) The foreign request was NOT served the trusted entry's bytes.
    assert!(
        !outcome.derivation.cached,
        "an entry stored under a different trust fingerprint was reused"
    );
    assert_ne!(
        outcome.derivation.artifact.bytes, trusted_bytes,
        "the foreign request was served trust fingerprint A's cached bytes"
    );

    // (2) The refusal is recorded as evidence rather than swallowed.
    let rejection = outcome
        .derivation
        .rejected
        .clone()
        .ok_or("the refused cross-trust lookup recorded no rejection")?;
    assert_eq!(
        rejection.reason,
        CacheRejectReason::UntrustedProducer,
        "the refusal must name the trust gate that refused it"
    );
    assert!(
        runtime
            .cache()
            .rejected()
            .iter()
            .any(|record| record.reason == CacheRejectReason::UntrustedProducer),
        "the store rejection log lost the cross-trust refusal"
    );

    // (3) The refusal did not suppress the build, and the artifact is correct.
    let BuildExecution::Fresh {
        operation_id,
        observation,
    } = &outcome.execution
    else {
        panic!("a refused cross-trust lookup must still run the admitted build");
    };
    assert_eq!(operation_id.as_str(), REQUEST_ID);
    assert!(
        outcome.cache_consulted,
        "the lookup was consulted and refused"
    );
    assert_eq!(
        observation.execution,
        ExecutionStatus::Succeeded,
        "the refused request must still reach a successful build result"
    );
    assert_eq!(
        outcome.derivation.artifact.bytes, fresh_bytes,
        "the returned artifact must be the bytes the admitted build produced"
    );
    assert_eq!(
        outcome.derivation.artifact.bytes,
        std::fs::read(&artifact_path)?,
        "the returned artifact must be the bytes read back from the declared path"
    );
    let (starts, inspections, terminal) = executor.counts();
    assert_eq!(starts, 1, "the admitted build was launched exactly once");
    assert!(inspections >= 1, "the build was observed at least once");
    assert!(terminal, "the build reached its terminal observation");

    // (4) The refused lookup preserved the valid union rather than poisoning
    // it: replaying the trusted fingerprint on the SAME runtime and the SAME
    // store still hits, and launches nothing. This is I02.22's "a result
    // derived from one observed subset cannot overwrite a broader valid cache
    // union" on the exact store the refusal touched.
    let must_not_launch = dir.join("must-not-launch.bin");
    let replay = runtime
        .run_admitted(
            GovernedBuildApplicationRequest {
                invocation,
                registry: &registry,
                freshness,
                executable: Some(&executable),
                attestations: attestations(TRUSTED_PRODUCER, &trusted_bytes),
                artifact_path: must_not_launch.clone(),
                sink: Arc::new(NoopSink),
                options: GovernedBuildOptions::default(),
            },
            &ScriptedAdmission,
        )
        .await?;
    assert!(
        replay.derivation.cached,
        "the valid entry stored under the trusted fingerprint must survive the refusal"
    );
    assert_eq!(replay.derivation.artifact.bytes, trusted_bytes);
    assert!(matches!(replay.execution, BuildExecution::CacheHit));
    assert!(replay.derivation.rejected.is_none());
    assert!(
        !must_not_launch.exists(),
        "a verified cache hit must never launch the admitted build"
    );

    Ok(())
}

/// A Kernel-admission owner that issues exactly one sealed P-03 request per
/// invocation. Every field comes from the invocation itself or from P-03; the
/// admission knows nothing about the cache, so the refusal cannot be an
/// artifact of this fixture.
struct ScriptedAdmission;

impl KernelInstrumentAdmission for ScriptedAdmission {
    fn admit(
        &self,
        invocation: &InstrumentInvocation,
    ) -> Result<KernelAdmittedProcess, KernelAdmissionError> {
        let generation =
            Generation::new(invocation.request.state_fence.resource_generation.value())
                .map_err(reject)?;
        let session_id = SessionId::new(SESSION_ID).map_err(reject)?;
        let fence = FencingToken::new(
            invocation.request.state_fence.authority_epoch.clone(),
            generation,
            "governed-build-fence-1923".to_owned(),
        )
        .map_err(reject)?;
        let intent = ProcessIntent::new(
            OperationId::new(invocation.request.request_id.as_str()).map_err(reject)?,
            ProcessTreeId::new("governed-build-tree-1923").map_err(reject)?,
            JobId::new("governed-build-job-1923").map_err(reject)?,
            ImageId::new("governed-build-image-1923").map_err(reject)?,
            session_id.clone(),
            generation,
            "C:/toolchain/rustc.exe",
            "a".repeat(64),
            invocation.arguments.clone(),
            "C:/worktrees/governed-build-1923",
            EnvironmentProjection::default(),
            ResourceLimits::new(30_000, Some(1_048_576), Some(1_048_576), 4096, 4096, 8)
                .map_err(reject)?,
        )
        .map_err(reject)?;

        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new(DISPATCH_AUTHORITY_ID).map_err(reject)?,
            KernelDispatchKey::from_secret_bytes(DISPATCH_KEY).map_err(reject)?,
        );
        let permit = authority
            .issue(
                &intent,
                PermitIssuance::new(
                    ActionLeaseRef::new("governed-build-admission-lease").map_err(reject)?,
                    fence,
                    revision_heads(),
                    100,
                    10_000,
                    "governed-build-admission-nonce-1923",
                )
                .map_err(reject)?,
            )
            .map_err(reject)?;
        let request = ProcessRequest::new(intent, permit)
            .map_err(|error| KernelAdmissionError::InvalidRequest(error.to_string()))?;

        let owner = ProcessOwnerBinding::new(
            "eliotd",
            "d".repeat(64),
            invocation.request.state_fence.authority_epoch.clone(),
            generation,
        )
        .map_err(reject)?;
        let caller =
            ProcessCallerSession::new(ProcessSessionClass::EliotdGeneration, owner, session_id)
                .map_err(reject)?;
        KernelAdmittedProcess::new(request, caller)
    }
}

fn reject(error: impl std::fmt::Display) -> KernelAdmissionError {
    KernelAdmissionError::Rejected(error.to_string())
}
