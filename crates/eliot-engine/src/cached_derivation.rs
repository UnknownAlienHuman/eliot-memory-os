//! Governed derived-artifact derivation consumer (issue #1898, I2.22).
//!
//! [`CachedDerivationService`] is the dedicated caller of the instrument
//! [`CacheLane`](eliot_instrument_runner::cache_lane::CacheLane) around a real
//! derivation. It mirrors the discipline of
//! [`VerificationRunnerService::run_current`](crate::verification::VerificationRunnerService::run_current):
//! resolve the invocation through a current registry, pin the
//! machine-derived executable identity, and refuse anything else — then
//! consult the derived cache before running derivation:
//!
//! ```text
//! hit  -> derivation is skipped; the hit carries artifact lineage only;
//! miss -> the genuine uncached derivation runs; its bytes are published.
//! ```
//!
//! Only [`InstrumentKind::Build`] derivations are cacheable. Test, verify,
//! inspect, lint, and format outputs are refused: reusing them as cached
//! artifacts would carry old verdicts or verdict-adjacent evidence across
//! candidates. A cache hit therefore never supplies a test or verifier
//! verdict — verdicts stay candidate-bound and are re-derived per candidate
//! by `eliot-verifier` from the artifact bytes.
//!
//! Identity elements come only from genuine owner facts: adapter, toolchain,
//! parser, and environment class from the resolved [`RegistryEntry`](eliot_instrument_runner::registry::RegistryEntry),
//! the compiler version from the machine-derived
//! [`ResolvedExecutableIdentity`](eliot_instrument_runner::registry::ResolvedExecutableIdentity),
//! and digests/producer/root/schema/content from caller attestations the
//! composition root actually observed. Telemetry is projected into the
//! existing [`CacheTelemetry`](eliot_observability::CacheTelemetry) owner
//! type; no parallel telemetry framework is introduced.

use eliot_build_test_graph::{
    CachedArtifact, DerivedCacheIdentity, DerivedCacheStore, FreshDerivation, RejectedCacheRecord,
    TrustPolicy,
};
use eliot_instrument_api::{InstrumentInvocation, InstrumentKind};
use eliot_instrument_runner::cache_lane::{CacheLane, CacheLaneAttestations};
use eliot_instrument_runner::registry::{
    ProviderRegistry, RegistryEntry, RegistryFreshness, ResolvedExecutableIdentity,
};
use eliot_observability::CacheTelemetry;

use crate::EngineError;

/// Inputs for one governed derivation, borrowed from their owners.
///
/// The invocation, executable observation, attestations, registry, and
/// freshness inputs all stay caller-owned; the service only reads them.
pub struct GovernedDerivationRequest<'a> {
    /// Admitted instrument invocation to derive for.
    pub invocation: &'a InstrumentInvocation,
    /// Machine-derived executable observation, if one was resolved.
    pub executable: Option<&'a ResolvedExecutableIdentity>,
    /// Caller-attested closure digests, producer, root, schema, and content.
    pub attest: &'a CacheLaneAttestations,
    /// Current provider registry the invocation must resolve through.
    pub registry: &'a ProviderRegistry,
    /// Caller freshness the resolution is pinned to.
    pub freshness: &'a RegistryFreshness<'a>,
}

/// One governed derivation outcome: artifact bytes plus cache telemetry.
///
/// There is deliberately no verdict field. A reused artifact carries lineage
/// only; the owning verifier derives a fresh candidate-bound verdict from
/// these bytes on every use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedDerivation {
    /// Reused or freshly derived artifact: lineage plus bytes, never verdicts.
    pub artifact: CachedArtifact,
    /// Owner-projected cache telemetry for instrument economics.
    pub telemetry: CacheTelemetry,
    /// Whether the artifact came from a verified cache hit.
    pub cached: bool,
    /// Rejection recorded while consulting the cache, if any.
    pub rejected: Option<RejectedCacheRecord>,
}

/// Dedicated consumer driving real derivations through derived-cache reuse.
pub struct CachedDerivationService {
    lane: CacheLane,
}

impl CachedDerivationService {
    /// Creates a consumer over an explicit store and trust policy.
    pub fn new(store: DerivedCacheStore, trust: TrustPolicy) -> Self {
        Self {
            lane: CacheLane::new(store, trust),
        }
    }

    /// Current store observation counters.
    #[must_use]
    pub const fn counters(&self) -> eliot_build_test_graph::CacheCounters {
        self.lane.counters()
    }

    /// Rejection records in insertion order.
    #[must_use]
    pub fn rejected(&self) -> Vec<RejectedCacheRecord> {
        self.lane.rejected()
    }

    /// Validates registry, build-kind, executable, and target admission
    /// without consulting the cache.
    ///
    /// A runtime caller uses this before launching a build when no expected
    /// artifact digest exists yet. The absence of a cache key must bypass
    /// reuse, but it must never bypass the BUILD-only admission boundary.
    pub fn validate_admission(
        &self,
        request: &GovernedDerivationRequest<'_>,
    ) -> Result<(), EngineError> {
        Self::admitted_entry(request).map(|_| ())
    }

    /// Consults the cache for an already declared artifact identity.
    ///
    /// `Some` is a verified hit and means the caller must not launch the
    /// underlying build. `None` is every miss shape, including an untrusted or
    /// corrupt entry; the caller must run its genuine uncached build and then
    /// use [`Self::publish_governed`] with the observed artifact bytes.
    pub fn lookup_governed(
        &mut self,
        request: &GovernedDerivationRequest<'_>,
    ) -> Result<Option<CachedDerivation>, EngineError> {
        let identity = Self::govern(request)?;
        Ok(match self.lane.lookup_identity(&identity) {
            eliot_build_test_graph::CacheLookup::Hit(artifact) => Some(Self::finish(
                request.invocation,
                &identity,
                artifact,
                true,
                None,
            )),
            eliot_build_test_graph::CacheLookup::Miss { .. } => None,
        })
    }

    /// Runs the full governed flow for a pre-declared expected digest.
    ///
    /// Governance (current registry resolution, build-kind gate, executable
    /// pinning, closure validation) runs first and fails closed. A verified
    /// hit returns the cached artifact without running `derive`. Any miss
    /// runs the genuine uncached derivation and publishes its bytes; a
    /// subsequent publish failure is recorded as a rejection and still
    /// returns the freshly derived bytes, so cache availability is never on
    /// the correctness path.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when governance fails (stale/unknown
    /// resolution, non-build kind, executable mismatch, invalid identity, or
    /// blank target). Derivation and publish outcomes are returned inside
    /// [`CachedDerivation`], never as errors.
    pub fn derive_governed(
        &mut self,
        request: &GovernedDerivationRequest<'_>,
        derive: impl FnOnce() -> FreshDerivation,
    ) -> Result<CachedDerivation, EngineError> {
        let identity = Self::govern(request)?;
        match self.lane.lookup_identity(&identity) {
            eliot_build_test_graph::CacheLookup::Hit(artifact) => Ok(Self::finish(
                request.invocation,
                &identity,
                artifact,
                true,
                None,
            )),
            eliot_build_test_graph::CacheLookup::Miss { reason } => {
                let rejected = if reason.is_recorded() {
                    self.lane.rejected().pop()
                } else {
                    None
                };
                let fresh = derive();
                if let Ok(artifact) = self.lane.publish_identity(&identity, fresh.clone()) {
                    Ok(Self::finish(
                        request.invocation,
                        &identity,
                        artifact,
                        false,
                        rejected,
                    ))
                } else {
                    let latest = self.lane.rejected().pop();
                    let digest = identity.digest().unwrap_or_else(|_| "unkeyed".to_owned());
                    let artifact = CachedArtifact::fresh(&identity, &digest, fresh.bytes);
                    Ok(Self::finish(
                        request.invocation,
                        &identity,
                        artifact,
                        false,
                        latest.or(rejected),
                    ))
                }
            }
        }
    }

    /// Publishes digest-bound bytes after a real derivation already ran.
    ///
    /// Cold-start shape: the caller executed the genuine derivation, observed
    /// the artifact bytes, attested their digest, and hands the bytes over
    /// for publication. Governance runs first and fails closed; a publish
    /// failure is recorded as a rejection and still returns the supplied
    /// bytes, so cache availability is never on the correctness path.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] only when governance fails. Publish failures
    /// are returned inside [`CachedDerivation`] as `rejected` evidence.
    pub fn publish_governed(
        &mut self,
        request: &GovernedDerivationRequest<'_>,
        fresh: FreshDerivation,
    ) -> Result<CachedDerivation, EngineError> {
        let identity = Self::govern(request)?;
        if let Ok(artifact) = self.lane.publish_identity(&identity, fresh.clone()) {
            Ok(Self::finish(
                request.invocation,
                &identity,
                artifact,
                false,
                None,
            ))
        } else {
            let latest = self.lane.rejected().pop();
            let digest = identity.digest().unwrap_or_else(|_| "unkeyed".to_owned());
            let artifact = CachedArtifact::fresh(&identity, &digest, fresh.bytes);
            Ok(Self::finish(
                request.invocation,
                &identity,
                artifact,
                false,
                latest,
            ))
        }
    }

    fn govern(
        request: &GovernedDerivationRequest<'_>,
    ) -> Result<DerivedCacheIdentity, EngineError> {
        let entry = Self::admitted_entry(request)?;
        CacheLane::identity_for(entry, request.executable, request.attest)
            .map_err(|error| rejected(&format!("cache identity is unusable: {error}")))
    }

    fn admitted_entry<'a>(
        request: &'a GovernedDerivationRequest<'a>,
    ) -> Result<&'a RegistryEntry, EngineError> {
        let entry = request
            .registry
            .resolve_current(request.invocation, request.freshness)
            .map_err(|error| rejected(&format!("registry rejected the derivation: {error}")))?;
        if request.invocation.kind != InstrumentKind::Build {
            return Err(rejected(&format!(
                "only BUILD derivations are cacheable; {:?} outputs must never be reused as artifacts",
                request.invocation.kind
            )));
        }
        entry
            .check_resolved_executable(request.executable)
            .map_err(|error| {
                rejected(&format!(
                    "executable identity rejected for the derivation: {error}"
                ))
            })?;
        if request.invocation.target.trim().is_empty()
            || request.invocation.target.chars().any(char::is_control)
        {
            return Err(rejected("derivation target cannot anchor cache telemetry"));
        }
        Ok(entry)
    }

    fn finish(
        invocation: &InstrumentInvocation,
        identity: &DerivedCacheIdentity,
        artifact: CachedArtifact,
        cached: bool,
        rejected: Option<RejectedCacheRecord>,
    ) -> CachedDerivation {
        let telemetry = CacheTelemetry {
            target_identity: invocation.target.clone(),
            cache_identity: identity.digest().ok(),
            lock_wait_ms: None,
            cache_hit: Some(cached),
        };
        CachedDerivation {
            artifact,
            telemetry,
            cached,
            rejected,
        }
    }
}

fn rejected(reason: &str) -> EngineError {
    EngineError::ServiceNotReady {
        service: "cache-derivation".to_owned(),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod cached_derivation_tests {
    use super::*;
    use eliot_build_test_graph::RootDisposition;
    use eliot_build_test_graph::{CacheLimits, CacheRejectReason, DERIVED_CACHE_SCHEMA_V1};
    use eliot_contracts::{
        ClockReading, ContractId, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SourceId, StateFence, sha256_hex,
    };
    use eliot_instrument_runner::registry::InvalidationSet;
    use eliot_instrument_rustc::RUSTC_INSTRUMENT;
    use std::num::NonZeroU64;
    use std::path::{Path, PathBuf};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const GENERATION: u64 = 11;
    const NORMATIVE_DIGEST: &str = "normative-pair-digest-fixture";
    const PRODUCER: &str = "engine-cache-proof-producer";
    const ROOT: &str = "engine-cache-proof-root";

    const PROBE_SOURCE: &str = r#"
fn main() {
    let total: u64 = (1..=1000).sum();
    assert_eq!(total, 500_500);
    println!("cache-proof-probe-ok");
}
"#;

    fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(std::io::Error::other(message.into()))
    }

    fn scratch_dir(tag: &str) -> TestResult<PathBuf> {
        let dir =
            std::env::temp_dir().join(format!("eliot-1898-cache-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn fence() -> TestResult<StateFence> {
        let lineage = EpochLineageId::new(TEST_LINEAGE)?;
        let Some(sequence) = NonZeroU64::new(7) else {
            return Err(test_error("sequence must be non-zero"));
        };
        Ok(StateFence::new(
            EpochId::new(lineage, sequence)?,
            ResourceGeneration::genesis(),
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
            source: "source-fp".to_owned(),
            lock: "lock-fp".to_owned(),
            toolchain: "toolchain-fp".to_owned(),
            env: "env-fp".to_owned(),
            exe: "exe-fp".to_owned(),
            profile: "profile-fp".to_owned(),
            parser: "parser-fp".to_owned(),
        }
    }

    fn ready_registry(fingerprints: &InvalidationSet) -> TestResult<ProviderRegistry> {
        Ok(ProviderRegistry::ready(
            GENERATION,
            NORMATIVE_DIGEST.to_owned(),
            fingerprints,
        )?)
    }

    /// Locates the real toolchain compiler behind `RUSTC` or `PATH`.
    fn find_rustc() -> TestResult<PathBuf> {
        if let Ok(candidate) = std::env::var("RUSTC") {
            let path = PathBuf::from(&candidate);
            if path.is_file() {
                return Ok(path);
            }
        }
        let exe = if cfg!(windows) { "rustc.exe" } else { "rustc" };
        if let Some(paths) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&paths) {
                let candidate = dir.join(exe);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
        Err(test_error("no real rustc available for the cache proof"))
    }

    fn rustc_version(exe: &Path) -> TestResult<String> {
        let output = std::process::Command::new(exe).arg("--version").output()?;
        if !output.status.success() {
            return Err(test_error("real rustc --version failed"));
        }
        let version = String::from_utf8(output.stdout)?;
        if version.trim().is_empty() {
            return Err(test_error("real rustc --version was empty"));
        }
        Ok(version.trim_end().to_owned())
    }

    /// Machine-derived observation of the real compiler: canonical path,
    /// content digest over the exact executable bytes, observed tool version,
    /// and an environment digest bound to both.
    fn rustc_observation(exe: &Path, version: &str) -> TestResult<ResolvedExecutableIdentity> {
        let bytes = std::fs::read(exe)?;
        let environment_digest = sha256_hex(format!("{version}|{}", exe.display()).as_bytes());
        Ok(ResolvedExecutableIdentity::new(
            RUSTC_INSTRUMENT,
            exe.to_string_lossy().into_owned(),
            sha256_hex(&bytes),
            Some(version.to_owned()),
            environment_digest,
            vec!["--crate-name".to_owned(), "cache_proof".to_owned()],
        )?)
    }

    fn invocation(target: &str) -> TestResult<InstrumentInvocation> {
        let request = RequestMetadata {
            request_id: RequestId::new("engine-cache-request-1")?,
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-1")?,
            source_id: SourceId::new("source-1")?,
            state_fence: fence()?,
            clock: clock(100),
        };
        Ok(InstrumentInvocation {
            request,
            instrument: ContractId::new(RUSTC_INSTRUMENT)?,
            kind: InstrumentKind::Build,
            profile: "dev-fast".to_owned(),
            target: target.to_owned(),
            arguments: vec!["--crate-name".to_owned(), "cache_proof".to_owned()],
            input_artifacts: Vec::new(),
            declared_scope: "engine-cache-scope".to_owned(),
            requested_at: clock(100),
        })
    }

    fn attestations(content: &[u8], argv_fingerprint: &str) -> CacheLaneAttestations {
        CacheLaneAttestations {
            source_digest: sha256_hex(PROBE_SOURCE.as_bytes()),
            generated_input_digest: sha256_hex(b"no-generated-inputs"),
            config_digest: sha256_hex(argv_fingerprint.as_bytes()),
            producer_id: PRODUCER.to_owned(),
            producer_generation: 1,
            root_identity: ROOT.to_owned(),
            root_acl_digest: sha256_hex(b"engine-cache-proof-root-acl"),
            root_disposition: RootDisposition::Direct,
            schema_revision: DERIVED_CACHE_SCHEMA_V1.to_owned(),
            content_digest: sha256_hex(content),
        }
    }

    fn service() -> TestResult<CachedDerivationService> {
        let trust = TrustPolicy::new(vec![PRODUCER.to_owned()], vec![ROOT.to_owned()])?;
        Ok(CachedDerivationService::new(
            DerivedCacheStore::new(CacheLimits::default()),
            trust,
        ))
    }

    /// Genuine uncached derivation: compiles the probe with the real
    /// toolchain and returns the exact compiler-emitted artifact bytes.
    fn compile_probe(rustc: &Path, dir: &Path) -> TestResult<Vec<u8>> {
        let source = dir.join("cache_probe.rs");
        std::fs::write(&source, PROBE_SOURCE)?;
        let exe = dir.join(if cfg!(windows) {
            "cache_probe.exe"
        } else {
            "cache_probe"
        });
        let output = std::process::Command::new(rustc)
            .arg("--edition=2021")
            .arg(&source)
            .arg("-o")
            .arg(&exe)
            .output()?;
        if !output.status.success() {
            return Err(test_error(format!(
                "real rustc compile failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(std::fs::read(&exe)?)
    }

    #[test]
    fn cold_publish_then_warm_hit_skips_real_compile() -> TestResult {
        let dir = scratch_dir("warm-hit")?;
        let rustc = find_rustc()?;
        let version = rustc_version(&rustc)?;
        let observed = rustc_observation(&rustc, &version)?;
        let fingerprints = fingerprints();
        let registry = ready_registry(&fingerprints)?;
        let freshness = RegistryFreshness {
            generation: GENERATION,
            normative_pair_digest: NORMATIVE_DIGEST,
            fingerprints: &fingerprints,
        };
        let target = dir.to_string_lossy().into_owned();
        let invocation = invocation(&target)?;
        let argv_fingerprint = format!("--edition=2021|{}", dir.join("cache_probe.rs").display());
        let mut service = service()?;

        // Cold start: the real toolchain derives artifact bytes first; the
        // attested digest is observed from those bytes, then published.
        let cold_bytes = compile_probe(&rustc, &dir)?;
        let attest = attestations(&cold_bytes, &argv_fingerprint);
        let request = GovernedDerivationRequest {
            invocation: &invocation,
            executable: Some(&observed),
            attest: &attest,
            registry: &registry,
            freshness: &freshness,
        };
        let cold = service
            .publish_governed(&request, FreshDerivation::new(cold_bytes.clone(), 2, false))?;
        assert!(!cold.cached);
        assert_eq!(cold.artifact.bytes, cold_bytes);
        assert_eq!(cold.telemetry.cache_hit, Some(false));
        assert_eq!(cold.telemetry.target_identity, target);
        assert!(cold.rejected.is_none());

        // Warm path: the identical closure hits; the real compile must not run.
        let mut compiles = 0usize;
        let warm = service.derive_governed(&request, || {
            compiles += 1;
            FreshDerivation::new(b"stale-bytes".to_vec(), 2, false)
        })?;
        assert!(warm.cached);
        assert_eq!(compiles, 0);
        assert_eq!(warm.artifact.bytes, cold_bytes);
        assert_eq!(warm.artifact.lineage.producer_id, PRODUCER);
        assert_eq!(warm.artifact.lineage.root_identity, ROOT);
        assert_eq!(
            warm.artifact.lineage.schema_revision,
            DERIVED_CACHE_SCHEMA_V1
        );
        assert_eq!(warm.telemetry.cache_hit, Some(true));
        assert_eq!(warm.telemetry.cache_identity, cold.telemetry.cache_identity);
        assert!(warm.rejected.is_none());
        assert_eq!(service.counters().hits, 1);
        Ok(())
    }

    #[test]
    fn build_only_gate_rejects_test_kind_without_deriving() -> TestResult {
        use eliot_instrument_nextest::NEXTEST_INSTRUMENT;

        let dir = scratch_dir("kind-gate")?;
        let fingerprints = fingerprints();
        let registry = ready_registry(&fingerprints)?;
        let freshness = RegistryFreshness {
            generation: GENERATION,
            normative_pair_digest: NORMATIVE_DIGEST,
            fingerprints: &fingerprints,
        };
        // A nextest TEST invocation resolves through the current registry,
        // so only the build-only gate can refuse it — never resolution.
        let request_id = RequestId::new("engine-cache-request-test-kind")?;
        let invocation = InstrumentInvocation {
            request: RequestMetadata {
                request_id,
                session_id: None,
                task_id: None,
                product_id: ProductId::new("product-1")?,
                source_id: SourceId::new("source-1")?,
                state_fence: fence()?,
                clock: clock(100),
            },
            instrument: ContractId::new(NEXTEST_INSTRUMENT)?,
            kind: InstrumentKind::Test,
            profile: "default".to_owned(),
            target: dir.to_string_lossy().into_owned(),
            arguments: vec!["-E".to_owned(), "test(probe)".to_owned()],
            input_artifacts: Vec::new(),
            declared_scope: "engine-cache-scope".to_owned(),
            requested_at: clock(100),
        };
        assert!(registry.resolve_current(&invocation, &freshness).is_ok());
        let bytes = b"test-output-that-must-never-be-cached".to_vec();
        let attest = attestations(&bytes, "kind-gate-argv");
        let mut service = service()?;
        let request = GovernedDerivationRequest {
            invocation: &invocation,
            executable: None,
            attest: &attest,
            registry: &registry,
            freshness: &freshness,
        };
        let mut derives = 0usize;
        let outcome = service.derive_governed(&request, || {
            derives += 1;
            FreshDerivation::new(bytes.clone(), 2, false)
        });
        assert!(outcome.is_err());
        assert_eq!(derives, 0);
        Ok(())
    }

    #[test]
    fn untrusted_producer_miss_runs_real_derive_and_preserves_valid() -> TestResult {
        let dir = scratch_dir("untrusted")?;
        let rustc = find_rustc()?;
        let version = rustc_version(&rustc)?;
        let observed = rustc_observation(&rustc, &version)?;
        let fingerprints = fingerprints();
        let registry = ready_registry(&fingerprints)?;
        let freshness = RegistryFreshness {
            generation: GENERATION,
            normative_pair_digest: NORMATIVE_DIGEST,
            fingerprints: &fingerprints,
        };
        let target = dir.to_string_lossy().into_owned();
        let invocation = invocation(&target)?;
        let argv_fingerprint = format!("--edition=2021|{}", dir.join("cache_probe.rs").display());
        let mut service = service()?;

        let cold_bytes = compile_probe(&rustc, &dir)?;
        let attest = attestations(&cold_bytes, &argv_fingerprint);
        let request = GovernedDerivationRequest {
            invocation: &invocation,
            executable: Some(&observed),
            attest: &attest,
            registry: &registry,
            freshness: &freshness,
        };
        let cold = service
            .publish_governed(&request, FreshDerivation::new(cold_bytes.clone(), 2, false))?;
        assert!(!cold.cached);

        let mut evil = attest.clone();
        evil.producer_id = "untrusted-producer".to_owned();
        let evil_request = GovernedDerivationRequest {
            invocation: &invocation,
            executable: Some(&observed),
            attest: &evil,
            registry: &registry,
            freshness: &freshness,
        };
        let mut derives = 0usize;
        let outcome = service.derive_governed(&evil_request, || {
            derives += 1;
            let bytes = compile_probe(&rustc, &dir).unwrap_or_else(|_| Vec::new());
            FreshDerivation::new(bytes, 1, false)
        })?;
        assert!(!outcome.cached);
        assert_eq!(derives, 1);
        assert!(matches!(
            outcome.rejected,
            Some(RejectedCacheRecord {
                reason: CacheRejectReason::UntrustedProducer,
                ..
            })
        ));

        let mut second_derives = 0usize;
        let again = service.derive_governed(&request, || {
            second_derives += 1;
            FreshDerivation::new(b"stale-bytes".to_vec(), 2, false)
        })?;
        assert!(again.cached);
        assert_eq!(second_derives, 0);
        assert_eq!(again.artifact.bytes, cold_bytes);
        assert!(!service.rejected().is_empty());
        Ok(())
    }

    #[test]
    fn content_mismatch_publish_never_fails_correctness() -> TestResult {
        let dir = scratch_dir("mismatch")?;
        let rustc = find_rustc()?;
        let version = rustc_version(&rustc)?;
        let observed = rustc_observation(&rustc, &version)?;
        let fingerprints = fingerprints();
        let registry = ready_registry(&fingerprints)?;
        let freshness = RegistryFreshness {
            generation: GENERATION,
            normative_pair_digest: NORMATIVE_DIGEST,
            fingerprints: &fingerprints,
        };
        let target = dir.to_string_lossy().into_owned();
        let invocation = invocation(&target)?;
        let argv_fingerprint = format!("--edition=2021|{}", dir.join("cache_probe.rs").display());
        let mut service = service()?;

        let wrong = attestations(b"declared-bytes", &argv_fingerprint);
        let request = GovernedDerivationRequest {
            invocation: &invocation,
            executable: Some(&observed),
            attest: &wrong,
            registry: &registry,
            freshness: &freshness,
        };
        let mut derives = 0usize;
        let outcome = service.derive_governed(&request, || {
            derives += 1;
            let bytes = compile_probe(&rustc, &dir).unwrap_or_else(|_| Vec::new());
            FreshDerivation::new(bytes, 1, true)
        })?;
        assert!(!outcome.cached);
        assert_eq!(derives, 1);
        assert!(!outcome.artifact.bytes.is_empty());
        assert!(matches!(
            outcome.rejected,
            Some(RejectedCacheRecord {
                reason: CacheRejectReason::ContentMismatch { .. },
                ..
            })
        ));
        Ok(())
    }
}
