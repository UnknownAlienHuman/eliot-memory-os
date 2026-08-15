//! Composition root for the isolated ELIOT build/test execution plane.
//!
//! Testd accepts a declared profile and a Kernel-issued, one-shot process
//! request.  Durable scheduling is delegated to `eliot-testd-core`; physical
//! process semantics are delegated to the shared Windows ProcessExecutor.  No
//! task finish, budget, memory, or canonical-write authority exists here.

#![forbid(unsafe_code)]

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use eliot_instrument_api::{InstrumentContractError, InstrumentInvocation};
use eliot_platform_windows::WindowsPlatform;
use eliot_process::{
    ProcessEvidenceSink, ProcessExecutionError, ProcessExecutor, ProcessStartReceipt,
};
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
use eliot_testd_core::{
    Lease, ProcessAdmissionPermit, TargetRoots, TestJob, TestdError, TestdStore,
    validate_running_lease,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use eliot_testd_core::{
    NormalizedEvidence, RawArtifact, VerificationReceipt, sha256_artifact, sha256_hex,
};

/// Stable daemon service identity.
pub const SERVICE_NAME: &str = "eliot-testd";
/// Stable line-protocol revision.
pub const PROTOCOL_VERSION: &str = "eliot.testd.v2";
/// Maximum number of profiles retained by one external worker pool.
pub const MAX_PROFILE_ARGUMENTS: usize = 128;

/// Declared external roots owned by one isolated test job.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetContract {
    /// Source/worktree target, never interpreted as a shell command.
    pub target: String,
    /// Dedicated build output root.
    pub build_root: String,
    /// Dedicated dependency/cache root.
    pub cache_root: String,
}

impl TargetContract {
    /// Validates and canonicalizes the source and isolated external roots.
    pub fn validate(&self, contour_root: &str) -> Result<(), TestdError> {
        self.validated_roots(contour_root).map(|_| ())
    }

    /// Returns the exact roots that are persisted with the durable job.
    pub fn validated_roots(&self, contour_root: &str) -> Result<TargetRoots, TestdError> {
        for (field, value) in [
            ("target", self.target.as_str()),
            ("build_root", self.build_root.as_str()),
            ("cache_root", self.cache_root.as_str()),
            ("allowed_contour_root", contour_root),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(TestdError::Invalid {
                    field,
                    reason: "must be non-blank and control-free",
                });
            }
        }
        let source_root = canonical_existing_root(Path::new(&self.target), "target")?;
        let contour_root =
            canonical_existing_root(Path::new(contour_root), "allowed_contour_root")?;
        if declared_paths_overlap(Path::new(&self.target), &contour_root) {
            return Err(TestdError::Invalid {
                field: "allowed_contour_root",
                reason: "external execution contour must not contain or be contained by target",
            });
        }
        if declared_paths_overlap(Path::new(&self.target), Path::new(&self.build_root)) {
            return Err(TestdError::Invalid {
                field: "build_root",
                reason: "must not be the source root or contained by it",
            });
        }
        if declared_paths_overlap(Path::new(&self.target), Path::new(&self.cache_root)) {
            return Err(TestdError::Invalid {
                field: "cache_root",
                reason: "must not be the source root or contained by it",
            });
        }
        let target_root = prepare_external_root(Path::new(&self.build_root), "build_root")?;
        let cache_root = prepare_external_root(Path::new(&self.cache_root), "cache_root")?;
        if target_root == source_root || target_root.starts_with(&source_root) {
            return Err(TestdError::Invalid {
                field: "build_root",
                reason: "must not be the source root or contained by it",
            });
        }
        if source_root.starts_with(&target_root) {
            return Err(TestdError::Invalid {
                field: "build_root",
                reason: "must not contain the source root",
            });
        }
        if cache_root != target_root {
            return Err(TestdError::Invalid {
                field: "cache_root",
                reason: "must equal the canonical build_root",
            });
        }
        if !strict_descendant(&target_root, &contour_root) {
            return Err(TestdError::Invalid {
                field: "build_root",
                reason: "must be a strict descendant of the allowed external execution contour",
            });
        }
        TargetRoots::new(
            contour_root.to_string_lossy(),
            source_root.to_string_lossy(),
            target_root.to_string_lossy(),
            cache_root.to_string_lossy(),
        )
    }
}

fn canonical_existing_root(path: &Path, field: &'static str) -> Result<PathBuf, TestdError> {
    validate_root_shape(path, field)?;
    reject_reparse_components(path, field)?;
    let canonical = std::fs::canonicalize(path).map_err(|_| TestdError::Invalid {
        field,
        reason: "must identify an existing root",
    })?;
    let _ = WindowsPlatform::new(canonical.clone()).map_err(|_| TestdError::Invalid {
        field,
        reason: "must be an existing non-reparse directory",
    })?;
    reject_reparse_components(&canonical, field)?;
    Ok(canonical)
}

fn prepare_external_root(path: &Path, field: &'static str) -> Result<PathBuf, TestdError> {
    validate_root_shape(path, field)?;
    reject_reparse_ancestors(path, field)?;
    std::fs::create_dir_all(path).map_err(|_| TestdError::Invalid {
        field,
        reason: "external root could not be created",
    })?;
    canonical_existing_root(path, field)
}

fn validate_root_shape(path: &Path, field: &'static str) -> Result<(), TestdError> {
    if !path.is_absolute() {
        return Err(TestdError::Invalid {
            field,
            reason: "must be an absolute path",
        });
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(TestdError::Invalid {
            field,
            reason: "parent traversal is forbidden",
        });
    }
    Ok(())
}

fn declared_paths_overlap(left: &Path, right: &Path) -> bool {
    if left == right || left.starts_with(right) || right.starts_with(left) {
        return true;
    }
    #[cfg(windows)]
    {
        let left = left.to_string_lossy().replace('/', "\\");
        let right = right.to_string_lossy().replace('/', "\\");
        let left = left.trim_end_matches('\\').to_ascii_lowercase();
        let right = right.trim_end_matches('\\').to_ascii_lowercase();
        return left == right
            || left.starts_with(&format!("{right}\\"))
            || right.starts_with(&format!("{left}\\"));
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn strict_descendant(path: &Path, parent: &Path) -> bool {
    if path == parent {
        return false;
    }
    #[cfg(windows)]
    {
        let path = path.to_string_lossy().replace('/', "\\");
        let parent = parent.to_string_lossy().replace('/', "\\");
        let path = path.trim_end_matches('\\').to_ascii_lowercase();
        let parent = parent.trim_end_matches('\\').to_ascii_lowercase();
        return path.starts_with(&format!("{parent}\\"));
    }
    #[cfg(not(windows))]
    {
        path.starts_with(parent)
    }
}

fn reject_reparse_components(path: &Path, field: &'static str) -> Result<(), TestdError> {
    reject_reparse_components_inner(path, field, false)
}

fn reject_reparse_ancestors(path: &Path, field: &'static str) -> Result<(), TestdError> {
    reject_reparse_components_inner(path, field, true)
}

fn reject_reparse_components_inner(
    path: &Path,
    field: &'static str,
    allow_missing_tail: bool,
) -> Result<(), TestdError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(TestdError::Invalid {
                    field,
                    reason: "parent traversal is forbidden",
                });
            }
            Component::Normal(part) => {
                current.push(part);
                let metadata = match std::fs::symlink_metadata(&current) {
                    Ok(metadata) => metadata,
                    Err(error)
                        if allow_missing_tail && error.kind() == std::io::ErrorKind::NotFound =>
                    {
                        break;
                    }
                    Err(_) => {
                        return Err(TestdError::Invalid {
                            field,
                            reason: "root traversal contains an unavailable component",
                        });
                    }
                };
                if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                    return Err(TestdError::Invalid {
                        field,
                        reason: "symlink or reparse traversal is forbidden",
                    });
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

/// Typed request accepted over the testd protocol.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestdJobRequest {
    pub job_id: String,
    pub project_id: String,
    pub invocation: InstrumentInvocation,
    pub target_contract: TargetContract,
    pub priority: i32,
}

/// Compatibility spelling for older protocol clients; it no longer contains
/// a private serialized process-request duplicate.
pub type TestRequest = TestdJobRequest;

/// A candidate receipt returned by testd after durable admission/observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestReceipt {
    pub job_id: String,
    pub operation_id: String,
    pub process_tree_id: String,
    pub generation: u64,
    pub authority_epoch: u64,
    pub invocation_digest: String,
    pub allowed_contour_root: String,
    pub source_root: String,
    pub target_root: String,
    pub cache_root: String,
    pub state: String,
}

/// Supplies a fresh consuming process request for each physical attempt.
pub trait ProcessRequestIssuer: Send + Sync {
    fn issue(
        &self,
        invocation: &InstrumentInvocation,
        target: &TargetContract,
    ) -> Result<ProcessAdmissionPermit, TestdError>;
}

/// Explicit failure issuer used by the standalone line protocol until Kernel
/// binds a live authority.  It prevents testd from minting local permits.
pub struct UnavailableProcessIssuer;

impl ProcessRequestIssuer for UnavailableProcessIssuer {
    fn issue(
        &self,
        _invocation: &InstrumentInvocation,
        _target: &TargetContract,
    ) -> Result<ProcessAdmissionPermit, TestdError> {
        Err(TestdError::Contract(
            "Kernel-issued ProcessRequest is required".to_owned(),
        ))
    }
}

/// Composition root over the durable TestdJob store.
pub struct TestdComposition {
    store: TestdStore,
    issuer: Arc<dyn ProcessRequestIssuer>,
}

impl TestdComposition {
    /// Opens the local execution-plane state and binds a request issuer.
    pub fn open(
        path: impl AsRef<std::path::Path>,
        issuer: Arc<dyn ProcessRequestIssuer>,
    ) -> Result<Self, TestdError> {
        Ok(Self {
            store: TestdStore::open(path, Default::default())?,
            issuer,
        })
    }

    /// Admits one exact typed profile through TestdJob/Fence admission.
    pub fn submit(&self, request: TestdJobRequest) -> Result<TestReceipt, TestdError> {
        request
            .invocation
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        if request.invocation.arguments.len() > MAX_PROFILE_ARGUMENTS {
            return Err(TestdError::Invalid {
                field: "invocation.arguments",
                reason: "profile argument limit exceeded",
            });
        }
        let permit = self
            .issuer
            .issue(&request.invocation, &request.target_contract)?;
        let roots = request
            .target_contract
            .validated_roots(permit.grant().contour_root())?;
        let job = self.store.submit(
            request.job_id,
            request.project_id,
            request.invocation,
            permit,
            roots,
            request.priority,
            unix_ms(),
        )?;
        Ok(receipt(&job))
    }

    /// Returns the durable status projection for one job.
    pub fn status(&self, job_id: &str) -> Result<TestReceipt, TestdError> {
        self.store
            .get(job_id)?
            .map(|job| receipt(&job))
            .ok_or_else(|| TestdError::Invalid {
                field: "job_id",
                reason: "unknown job",
            })
    }

    /// Cancels a queued or leased job under the durable store fence.
    pub fn cancel(&self, job_id: &str) -> Result<TestReceipt, TestdError> {
        self.cancel_with_lease(job_id, None, SERVICE_NAME)
    }

    /// Cancels a job with the exact current lease/authority when it is running.
    pub fn cancel_with_lease(
        &self,
        job_id: &str,
        lease: Option<&Lease>,
        actor: &str,
    ) -> Result<TestReceipt, TestdError> {
        let job = self.store.cancel(job_id, lease, actor, unix_ms())?;
        Ok(receipt(&job))
    }

    /// Starts one claimed stage through the shared ProcessExecutor.
    ///
    /// The request is intentionally supplied freshly by Kernel for this
    /// attempt; the durable TestdJob projection can never be substituted for
    /// its consuming permit.
    pub async fn start_claimed<E: ProcessExecutor + 'static>(
        &self,
        job: &TestJob,
        lease: &Lease,
        now: u64,
        permit: ProcessAdmissionPermit,
        executor: &E,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, TestdError> {
        let current = self
            .store
            .get(&job.job_id)?
            .ok_or_else(|| TestdError::Invalid {
                field: "job_id",
                reason: "unknown job",
            })?;
        validate_running_lease(&current, lease, now)?;
        current.target_roots.validate()?;
        let (request, grant) = permit.into_parts();
        request
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        grant.validate_for_process(
            &current.job_id,
            current.invocation.request.request_id.as_str(),
            &request,
        )?;
        if grant.contour_root() != current.target_roots.allowed_contour_root {
            return Err(TestdError::InvalidBinding);
        }
        let operation_id = request.operation_id().clone();
        let request_job_id = request.job_id().as_str().to_owned();
        let process_tree_id = request.process_tree_id().as_str().to_owned();
        let generation = request.generation().get();
        let authority_epoch = request.fence().authority_epoch();
        let digest = request.invocation_digest().to_owned();
        let environment = request.environment().non_secret();
        if request_job_id != current.process.job_id
            || operation_id.as_str() != current.process.operation_id
            || process_tree_id != current.process.process_tree_id
            || generation != current.process.generation
            || authority_epoch != current.process.authority_epoch
            || digest != current.process.invocation_digest
            || request.working_directory() != current.target_roots.source_root
            || environment.get("CARGO_TARGET_DIR") != Some(&current.target_roots.target_root)
            || environment.get("CARGO_HOME") != Some(&current.target_roots.cache_root)
        {
            return Err(TestdError::InvalidBinding);
        }
        executor
            .start(request, sink)
            .await
            .map_err(|error: ProcessExecutionError| TestdError::Contract(error.to_string()))
    }
}

/// Instantiates the sole concrete ProcessExecutor with an authority-owned
/// validation port.  Testd owns this instance's operation trees; Kernel owns
/// permit issuance and validation.
pub fn compose_process_executor(
    authority: Arc<dyn DispatchValidationPort>,
) -> WindowsProcessExecutor {
    WindowsProcessExecutor::new(authority)
}

fn receipt(job: &TestJob) -> TestReceipt {
    TestReceipt {
        job_id: job.job_id.clone(),
        operation_id: job.process.operation_id.clone(),
        process_tree_id: job.process.process_tree_id.clone(),
        generation: job.process.generation,
        authority_epoch: job.process.authority_epoch,
        invocation_digest: job.process.invocation_digest.clone(),
        allowed_contour_root: job.target_roots.allowed_contour_root.clone(),
        source_root: job.target_roots.source_root.clone(),
        target_root: job.target_roots.target_root.clone(),
        cache_root: job.target_roots.cache_root.clone(),
        state: format!("{:?}", job.state),
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u128::from(u64::MAX)) as u64
        })
}

/// Binary/protocol errors use the same typed TestdError surface.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("instrument contract: {0}")]
    Instrument(#[from] InstrumentContractError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "eliot-testd-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn target_root_substitution_and_source_containment_are_rejected() {
        let base = test_root("roots");
        let source = base.join("source");
        let external = base.join("external");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&external).unwrap();

        let substituted_cache = TargetContract {
            target: source.to_string_lossy().into_owned(),
            build_root: external.join("build").to_string_lossy().into_owned(),
            cache_root: external.join("cache").to_string_lossy().into_owned(),
        };
        assert!(
            substituted_cache
                .validated_roots(external.to_string_lossy().as_ref())
                .is_err()
        );

        let contained_build = TargetContract {
            target: source.to_string_lossy().into_owned(),
            build_root: source.join("build").to_string_lossy().into_owned(),
            cache_root: source.join("build").to_string_lossy().into_owned(),
        };
        assert!(
            contained_build
                .validated_roots(external.to_string_lossy().as_ref())
                .is_err()
        );
        let forged = serde_json::json!({
            "target": source.to_string_lossy(),
            "build_root": external.join("build").to_string_lossy(),
            "cache_root": external.join("build").to_string_lossy(),
            "allowed_contour_root": source.to_string_lossy(),
        });
        assert!(serde_json::from_value::<TargetContract>(forged).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn raw_digest_is_over_bytes_not_handle_text() {
        let mut artifact = RawArtifact::from_bytes(
            "stdout-handle",
            "text/plain",
            b"actual stdout".to_vec(),
            false,
        )
        .unwrap();
        assert_eq!(
            artifact.sha256,
            sha256_artifact(artifact.length, b"actual stdout")
        );
        artifact.sha256 = sha256_hex(artifact.handle.as_bytes());
        assert!(artifact.validate().is_err());
        artifact.sha256 = sha256_artifact(artifact.length, &artifact.bytes);
        artifact.length = artifact.length.saturating_add(1);
        assert!(artifact.validate().is_err());
    }
}
