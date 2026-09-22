//! Production BUILD/artifact caller for issue #1898.
//!
//! [`GovernedBuildRuntime`] is the application-facing edge that was missing
//! after the cache contract and library lane were added. It keeps the
//! authority split explicit: Kernel still supplies the admitted
//! [`InstrumentRequestPort`], P-04 still supplies the injected
//! [`ProcessExecutor`], and this module only coordinates a BUILD invocation
//! with cache consultation and observed artifact publication.
//!
//! The cache is consulted only when the caller has a valid expected artifact
//! digest (normally from an approved manifest). A miss, an absent expected
//! digest, or an invalid cache entry launches the genuine admitted build. The
//! process must reach a successful terminal observation before this module
//! reads the declared artifact path and hashes its actual bytes. No process
//! output or verifier verdict is fabricated here.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use eliot_build_test_graph::{DerivedCacheStore, FreshDerivation, TrustPolicy};
use eliot_contracts::sha256_hex;
use eliot_instrument_api::{ExecutionStatus, InstrumentInvocation};
use eliot_instrument_runner::registry::RegistryFreshness;
use eliot_instrument_runner::{
    CacheLaneAttestations, InstrumentBinding, InstrumentObservation, InstrumentRequestPort,
    InstrumentRunner, KernelInstrumentAdmission, KernelInstrumentRequestPort, ProviderRegistry,
    RegistryEntry, ResolvedExecutableIdentity, RunnerError,
};
use eliot_process::{OperationId, ProcessEvidenceSink, ProcessExecutor};
use thiserror::Error;

use crate::EngineError;
use crate::cached_derivation::{
    CachedDerivation, CachedDerivationService, GovernedDerivationRequest,
};

/// Default maximum time allowed for one admitted build to reach a terminal
/// process observation.
pub const DEFAULT_BUILD_TIMEOUT: Duration = Duration::from_mins(2);
/// Default bounded observation interval while a real build is running.
pub const DEFAULT_BUILD_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Runtime limits and cache-union metadata for one governed BUILD call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovernedBuildOptions {
    /// Maximum wall time spent waiting for a terminal process observation.
    pub timeout: Duration,
    /// Delay between bounded process observations.
    pub poll_interval: Duration,
    /// Number of independently observed members covered by the artifact.
    pub coverage_breadth: u64,
    /// Whether the cache contract explicitly permits replacement of a broader
    /// valid union by this derived artifact.
    pub replacement_declared: bool,
}

impl Default for GovernedBuildOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_BUILD_TIMEOUT,
            poll_interval: DEFAULT_BUILD_POLL_INTERVAL,
            coverage_breadth: 1,
            replacement_declared: false,
        }
    }
}

/// One admitted runtime BUILD request.
///
/// `attestations.content_digest` is the expected artifact digest when an
/// approved manifest exists. It may be empty only to request a cold build
/// whose content digest is observed from the output before publication. All
/// other attestation fields remain caller-owned facts and are never inferred
/// from the cache or the process result.
pub struct GovernedBuildRequest<'a> {
    /// Provider-neutral BUILD invocation.
    pub invocation: InstrumentInvocation,
    /// Kernel-owned port that returns the sealed process request.
    pub request_port: &'a dyn InstrumentRequestPort,
    /// Current provider registry used for admission and identity binding.
    pub registry: &'a ProviderRegistry,
    /// Freshness inputs for the registry resolution.
    pub freshness: RegistryFreshness<'a>,
    /// Machine-derived executable identity, if the registry entry requires it.
    pub executable: Option<&'a ResolvedExecutableIdentity>,
    /// Caller-owned dependency closure, producer, root, schema, and optional
    /// expected content digest.
    pub attestations: CacheLaneAttestations,
    /// Exact output path named by the admitted build contract.
    pub artifact_path: PathBuf,
    /// Evidence sink supplied by the process composition root.
    pub sink: Arc<dyn ProcessEvidenceSink>,
    /// Bounded wait and cache-union policy.
    pub options: GovernedBuildOptions,
}

/// Application-facing BUILD request whose process admission is supplied by
/// the active Kernel owner.
///
/// The public low-level [`GovernedBuildRequest`] remains available for callers
/// that already own an explicit `InstrumentRequestPort`.  Normal production
/// callers should use this shape with [`GovernedBuildRuntime::run_admitted`],
/// which installs the concrete Kernel-backed port and keeps request issuance
/// out of the engine.
pub struct GovernedBuildApplicationRequest<'a> {
    /// Provider-neutral BUILD invocation.
    pub invocation: InstrumentInvocation,
    /// Current provider registry used for admission and identity binding.
    pub registry: &'a ProviderRegistry,
    /// Freshness inputs for the registry resolution.
    pub freshness: RegistryFreshness<'a>,
    /// Machine-derived executable identity, if the registry entry requires it.
    pub executable: Option<&'a ResolvedExecutableIdentity>,
    /// Caller-owned dependency closure, producer, root, schema, and optional
    /// expected content digest.
    pub attestations: CacheLaneAttestations,
    /// Exact output path named by the admitted build contract.
    pub artifact_path: PathBuf,
    /// Evidence sink supplied by the process composition root.
    pub sink: Arc<dyn ProcessEvidenceSink>,
    /// Bounded wait and cache-union policy.
    pub options: GovernedBuildOptions,
}

/// How the artifact in [`GovernedBuildOutcome`] was obtained.
#[derive(Debug)]
pub enum BuildExecution {
    /// A verified cache hit supplied lineage and bytes, so no process launch
    /// occurred.
    CacheHit,
    /// The admitted process ran and produced the bytes read from the declared
    /// artifact path.
    Fresh {
        /// Exact process operation accepted by P-03.
        operation_id: OperationId,
        /// Terminal observation from the runner, including the physical view.
        observation: Box<InstrumentObservation>,
    },
}

/// Result of one governed BUILD/artifact call.
#[derive(Debug)]
pub struct GovernedBuildOutcome {
    /// Artifact lineage and bytes returned by the cache service.
    pub derivation: CachedDerivation,
    /// Whether a valid expected digest allowed a cache consultation.
    pub cache_consulted: bool,
    /// Cache hit or fresh process execution evidence.
    pub execution: BuildExecution,
}

/// Failures that prevent a governed BUILD from returning an artifact.
#[derive(Debug, Error)]
pub enum GovernedBuildError {
    /// Admission or cache identity failed before a safe result existed.
    #[error(transparent)]
    Engine(#[from] EngineError),
    /// The existing runner or process boundary rejected the operation.
    #[error(transparent)]
    Runner(#[from] RunnerError),
    /// Runtime options would create an unbounded or non-progressing wait.
    #[error("governed BUILD requires non-zero timeout and poll interval")]
    InvalidOptions,
    /// The process did not reach a terminal observation before the bound.
    #[error("governed BUILD timed out for operation {operation_id} after {timeout_ms}ms")]
    TimedOut {
        /// Operation that remains subject to the process boundary.
        operation_id: String,
        /// Configured wait bound.
        timeout_ms: u64,
    },
    /// The process reached a terminal state without a successful BUILD result.
    #[error("governed BUILD operation {operation_id} was not successful: {status:?}")]
    NonSuccessful {
        /// Operation observed.
        operation_id: String,
        /// Runner execution axis.
        status: ExecutionStatus,
    },
    /// The declared artifact could not be read as a regular, non-symlink file.
    #[error("governed BUILD artifact {path} is unavailable: {reason}")]
    ArtifactUnavailable {
        /// Declared output path.
        path: String,
        /// Exact local reason.
        reason: String,
    },
    /// A fresh build did not reproduce the manifest's expected artifact bytes.
    #[error("governed BUILD artifact digest mismatch: expected {expected}, observed {observed}")]
    ArtifactDigestMismatch {
        /// Digest from the approved artifact expectation.
        expected: String,
        /// Digest of bytes read after the build exited.
        observed: String,
    },
}

/// The real runtime caller for cache-aware BUILD derivations.
pub struct GovernedBuildRuntime<E> {
    runner: InstrumentRunner<E>,
    cache: CachedDerivationService,
}

impl<E> GovernedBuildRuntime<E> {
    /// Creates a runtime caller over the composition root's process executor
    /// and explicit cache policy.
    #[must_use]
    pub fn new(executor: Arc<E>, store: DerivedCacheStore, trust: TrustPolicy) -> Self {
        Self {
            runner: InstrumentRunner::new(executor),
            cache: CachedDerivationService::new(store, trust),
        }
    }

    /// Returns the underlying cache service counters/rejections for operator
    /// projection without creating a second telemetry owner.
    #[must_use]
    pub fn cache(&self) -> &CachedDerivationService {
        &self.cache
    }
}

impl<E: ProcessExecutor + 'static> GovernedBuildRuntime<E> {
    /// Runs a BUILD through the active Kernel admission owner and the existing
    /// InstrumentRunner/ProcessExecutor composition.
    ///
    /// This is the production application entrypoint for the cache-aware BUILD
    /// lane.  A valid cache hit returns before admission, while every miss
    /// obtains a fresh sealed `ProcessRequest` from `admission`; the engine
    /// never constructs or deserializes one itself.
    pub async fn run_admitted(
        &mut self,
        request: GovernedBuildApplicationRequest<'_>,
        admission: &dyn KernelInstrumentAdmission,
    ) -> Result<GovernedBuildOutcome, GovernedBuildError> {
        let port = KernelInstrumentRequestPort::new(admission);
        self.run(GovernedBuildRequest {
            invocation: request.invocation,
            request_port: &port,
            registry: request.registry,
            freshness: request.freshness,
            executable: request.executable,
            attestations: request.attestations,
            artifact_path: request.artifact_path,
            sink: request.sink,
            options: request.options,
        })
        .await
    }

    /// Runs one admitted BUILD through cache lookup, real process execution,
    /// artifact readback, and observed-content publication.
    ///
    /// A valid expected digest is required for a cache lookup. If it is absent
    /// or malformed, the call skips reuse and performs the real build before
    /// deriving the content digest from the resulting bytes. A cache rejection
    /// never suppresses that build or turns into a correctness failure.
    pub async fn run(
        &mut self,
        request: GovernedBuildRequest<'_>,
    ) -> Result<GovernedBuildOutcome, GovernedBuildError> {
        if request.options.timeout.is_zero() || request.options.poll_interval.is_zero() {
            return Err(GovernedBuildError::InvalidOptions);
        }

        let invocation = request.invocation.clone();
        let mut attestations = request.attestations.clone();
        let expected =
            valid_digest(&attestations.content_digest).then(|| attestations.content_digest.clone());
        let cache_miss_rejection = if expected.is_some() {
            let governed = GovernedDerivationRequest {
                invocation: &invocation,
                executable: request.executable,
                attest: &attestations,
                registry: request.registry,
                freshness: &request.freshness,
            };
            let before = self.cache.rejected();
            if let Some(derivation) = self.cache.lookup_governed(&governed)? {
                return Ok(GovernedBuildOutcome {
                    derivation,
                    cache_consulted: true,
                    execution: BuildExecution::CacheHit,
                });
            }
            newest_rejection(&before, &self.cache.rejected())
        } else {
            let governed = GovernedDerivationRequest {
                invocation: &invocation,
                executable: request.executable,
                attest: &attestations,
                registry: request.registry,
                freshness: &request.freshness,
            };
            // No expected digest means no reuse key. Preserve the BUILD-only
            // and executable admission boundary before launching anything.
            self.cache.validate_admission(&governed)?;
            None
        };

        let entry = request
            .registry
            .resolve_current(&invocation, &request.freshness)
            .map_err(|error| EngineError::ServiceNotReady {
                service: "cache-derivation".to_owned(),
                reason: format!("registry rejected the build launch: {error}"),
            })?;
        let (operation_id, observation, bytes) = self.execute_build(&request, entry).await?;
        let observed_digest = sha256_hex(&bytes);
        match expected.as_deref() {
            Some(expected) if expected != observed_digest => {
                return Err(GovernedBuildError::ArtifactDigestMismatch {
                    expected: expected.to_owned(),
                    observed: observed_digest,
                });
            }
            _ => {}
        }

        // The cache key is created from the bytes that the successful process
        // actually produced. This is the cold-build path when no manifest
        // digest was available, and the revalidation path after a cache miss.
        attestations.content_digest = observed_digest;
        let governed = GovernedDerivationRequest {
            invocation: &invocation,
            executable: request.executable,
            attest: &attestations,
            registry: request.registry,
            freshness: &request.freshness,
        };
        let mut derivation = self.cache.publish_governed(
            &governed,
            FreshDerivation::new(
                bytes,
                request.options.coverage_breadth,
                request.options.replacement_declared,
            ),
        )?;
        if derivation.rejected.is_none() {
            derivation.rejected = cache_miss_rejection;
        }
        Ok(GovernedBuildOutcome {
            derivation,
            cache_consulted: expected.is_some(),
            execution: BuildExecution::Fresh {
                operation_id,
                observation: Box::new(observation),
            },
        })
    }

    async fn execute_build(
        &self,
        request: &GovernedBuildRequest<'_>,
        entry: &RegistryEntry,
    ) -> Result<(OperationId, InstrumentObservation, Vec<u8>), GovernedBuildError> {
        let artifact_path = &request.artifact_path;
        if !artifact_path.is_absolute() {
            return Err(GovernedBuildError::ArtifactUnavailable {
                path: artifact_path.display().to_string(),
                reason: "artifact path must be absolute".to_owned(),
            });
        }

        // Binding is done through the existing request port; no command is
        // constructed or launched directly in this owner.
        let process_request = request.request_port.bind(&request.invocation)?;
        let mut binding =
            InstrumentBinding::from_request(request.invocation.clone(), process_request)?;
        binding.verify_executable(entry, request.executable)?;
        let receipt = self
            .runner
            .launch(&mut binding, Arc::clone(&request.sink))
            .await?;
        let operation_id = receipt.process.operation_id().clone();
        let deadline = tokio::time::Instant::now() + request.options.timeout;

        loop {
            let observation = self.runner.inspect(&binding).await?;
            if observation.view.lifecycle().is_terminal() {
                if observation.execution != ExecutionStatus::Succeeded {
                    return Err(GovernedBuildError::NonSuccessful {
                        operation_id: operation_id.as_str().to_owned(),
                        status: observation.execution,
                    });
                }
                let bytes = read_artifact(artifact_path)?;
                return Ok((operation_id, observation, bytes));
            }
            if tokio::time::Instant::now() >= deadline {
                // The process boundary remains authoritative. A best-effort
                // cancellation prevents this bounded caller from abandoning a
                // live child, while an unknown cancellation result is still
                // surfaced by the process owner on its next reconciliation.
                let _ = self.runner.cancel(&binding).await;
                return Err(GovernedBuildError::TimedOut {
                    operation_id: operation_id.as_str().to_owned(),
                    timeout_ms: duration_millis(request.options.timeout),
                });
            }
            tokio::time::sleep(request.options.poll_interval).await;
        }
    }
}

fn read_artifact(path: &Path) -> Result<Vec<u8>, GovernedBuildError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        GovernedBuildError::ArtifactUnavailable {
            path: path.display().to_string(),
            reason: error.to_string(),
        }
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(GovernedBuildError::ArtifactUnavailable {
            path: path.display().to_string(),
            reason: "declared artifact is not a regular non-symlink file".to_owned(),
        });
    }
    std::fs::read(path).map_err(|error| GovernedBuildError::ArtifactUnavailable {
        path: path.display().to_string(),
        reason: error.to_string(),
    })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn newest_rejection(
    before: &[eliot_build_test_graph::RejectedCacheRecord],
    after: &[eliot_build_test_graph::RejectedCacheRecord],
) -> Option<eliot_build_test_graph::RejectedCacheRecord> {
    let candidate = after.last()?.clone();
    if before
        .last()
        .is_some_and(|previous| previous.sequence == candidate.sequence)
    {
        None
    } else {
        Some(candidate)
    }
}

fn duration_millis(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_build_test_graph::{CacheLimits, DERIVED_CACHE_SCHEMA_V1};
    use eliot_contracts::{
        ClockReading, ContractId, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        SourceId, StateFence,
    };
    use eliot_instrument_api::InstrumentKind;
    use eliot_instrument_runner::cache_lane::CacheLane;
    use eliot_instrument_runner::registry::InvalidationSet;
    use eliot_instrument_rustc::RUSTC_INSTRUMENT;
    use eliot_process::{
        CancellationReceipt, EvidenceSinkError, ProcessEvidence, ProcessExecutionError,
        ProcessExecutionView, ProcessRequest, ProcessStartReceipt,
    };
    use std::num::NonZeroU64;

    struct NeverExecutor;

    impl ProcessExecutor for NeverExecutor {
        async fn start(
            &self,
            _request: ProcessRequest,
            _sink: Arc<dyn ProcessEvidenceSink>,
        ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
            Err(ProcessExecutionError::Unavailable(
                "cache-hit proof must not launch".to_owned(),
            ))
        }

        async fn inspect(
            &self,
            _operation_id: OperationId,
        ) -> Result<ProcessExecutionView, ProcessExecutionError> {
            Err(ProcessExecutionError::Unavailable(
                "cache-hit proof must not inspect".to_owned(),
            ))
        }

        async fn cancel(
            &self,
            _operation_id: OperationId,
        ) -> Result<CancellationReceipt, ProcessExecutionError> {
            Err(ProcessExecutionError::Unavailable(
                "cache-hit proof must not cancel".to_owned(),
            ))
        }

        async fn reconcile(
            &self,
            _operation_id: OperationId,
        ) -> Result<ProcessEvidence, ProcessExecutionError> {
            Err(ProcessExecutionError::Unavailable(
                "cache-hit proof must not reconcile".to_owned(),
            ))
        }
    }

    struct NeverPort;

    impl InstrumentRequestPort for NeverPort {
        fn bind(
            &self,
            _invocation: &InstrumentInvocation,
        ) -> Result<eliot_process::ProcessRequest, RunnerError> {
            Err(RunnerError::Binding(
                "cache-hit proof must not bind".to_owned(),
            ))
        }
    }

    struct NoopSink;

    impl ProcessEvidenceSink for NoopSink {
        fn record(&self, _evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
            Ok(())
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

    fn invocation() -> Result<InstrumentInvocation, Box<dyn std::error::Error + Send + Sync>> {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?;
        let sequence = NonZeroU64::new(7).ok_or("non-zero state sequence")?;
        let fence = StateFence::new(
            EpochId::new(lineage, sequence)?,
            eliot_contracts::ResourceGeneration::genesis(),
        );
        Ok(InstrumentInvocation {
            request: RequestMetadata {
                request_id: RequestId::new("governed-build-cache-hit")?,
                session_id: None,
                task_id: None,
                product_id: ProductId::new("product")?,
                source_id: SourceId::new("source")?,
                state_fence: fence,
                clock: ClockReading {
                    valid_time_ms: Some(100),
                    known_time_ms: Some(100),
                    transaction_sequence: None,
                    monotonic_ns: Some(1),
                },
            },
            instrument: ContractId::new(RUSTC_INSTRUMENT)?,
            kind: InstrumentKind::Build,
            profile: "dev".to_owned(),
            target: "artifact".to_owned(),
            arguments: vec!["--crate-name".to_owned(), "cache_hit".to_owned()],
            input_artifacts: Vec::new(),
            declared_scope: "scope".to_owned(),
            requested_at: ClockReading {
                valid_time_ms: Some(100),
                known_time_ms: Some(100),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
        })
    }

    fn attestations(bytes: &[u8]) -> CacheLaneAttestations {
        CacheLaneAttestations {
            source_digest: eliot_contracts::sha256_hex(b"source-closure"),
            generated_input_digest: eliot_contracts::sha256_hex(b"generated-inputs"),
            config_digest: eliot_contracts::sha256_hex(b"config-features-environment"),
            producer_id: "governed-build-producer".to_owned(),
            producer_generation: 7,
            root_identity: "governed-build-cache-root".to_owned(),
            root_acl_digest: eliot_contracts::sha256_hex(b"root-acl"),
            root_disposition: eliot_build_test_graph::RootDisposition::Direct,
            schema_revision: DERIVED_CACHE_SCHEMA_V1.to_owned(),
            content_digest: eliot_contracts::sha256_hex(bytes),
        }
    }

    #[tokio::test]
    async fn cache_hit_returns_lineage_without_binding_or_launching_build(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fingerprints = fingerprints();
        let registry = ProviderRegistry::ready(7, "normative".to_owned(), &fingerprints)?;
        let freshness = RegistryFreshness {
            generation: 7,
            normative_pair_digest: "normative",
            fingerprints: &fingerprints,
        };
        let executable = ResolvedExecutableIdentity::new(
            RUSTC_INSTRUMENT,
            "C:/toolchain/rustc.exe".to_owned(),
            "a".repeat(64),
            Some("rustc 1.89.0".to_owned()),
            "b".repeat(64),
            vec!["--crate-name".to_owned(), "cache_hit".to_owned()],
        )?;
        let bytes = b"observed-build-artifact".to_vec();
        let attest = attestations(&bytes);
        let invocation = invocation()?;
        let entry = registry.resolve_current(&invocation, &freshness)?;
        let identity = CacheLane::identity_for(entry, Some(&executable), &attest)?;
        let trust = TrustPolicy::new(
            vec![attest.producer_id.clone()],
            vec![attest.root_identity.clone()],
        )?;
        let mut store = DerivedCacheStore::new(CacheLimits::default());
        store
            .publish(
                &identity,
                &trust,
                FreshDerivation::new(bytes.clone(), 1, false),
            )
            .map_err(|error| {
                std::io::Error::other(format!("preload verified artifact: {error:?}"))
            })?;

        let mut runtime = GovernedBuildRuntime::new(Arc::new(NeverExecutor), store, trust);
        let outcome = runtime
            .run(GovernedBuildRequest {
                invocation,
                request_port: &NeverPort,
                registry: &registry,
                freshness,
                executable: Some(&executable),
                attestations: attest,
                artifact_path: std::env::temp_dir().join("governed-build-cache-hit.bin"),
                sink: Arc::new(NoopSink),
                options: GovernedBuildOptions::default(),
            })
            .await?;

        assert!(outcome.cache_consulted);
        assert!(matches!(outcome.execution, BuildExecution::CacheHit));
        assert_eq!(outcome.derivation.artifact.bytes, bytes);
        assert!(outcome.derivation.cached);
        assert!(runtime.cache().rejected().is_empty());
        Ok(())
    }
}
