//! Composition root for the isolated ELIOT build/test execution plane.
//!
//! Testd accepts a declared profile and a Kernel-issued, one-shot process
//! request.  Durable scheduling is delegated to `eliot-testd-core`; physical
//! process semantics are delegated to the shared Windows `ProcessExecutor`.  No
//! task finish, budget, memory, or canonical-write authority exists here.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::EpochId;
use eliot_instrument_api::{InstrumentContractError, InstrumentInvocation};
use eliot_platform::ClockObservation;
use eliot_platform_windows::WindowsPlatform;
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
    FencingToken, Generation, ImageId, JobId, KernelDispatchKey, OperationId, PermitIssuance,
    ProcessEvidenceSink, ProcessExecutionError, ProcessExecutor, ProcessIntent, ProcessRequest,
    ProcessStartReceipt, ProcessTreeId, SessionId, SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
use eliot_testd_core::{
    EvidenceCollector, KernelProcessAdmissionEvidence, KernelProcessAdmissionProvider,
    KernelProcessAdmissionRequest, Lease, ProcessAdmissionPermit, RetryPolicy, TargetRoots,
    TestJob, TestdError, TestdStore, is_admitted_testd_profile, issue_process_admission,
    testd_profile_binding, testd_profile_environment, testd_profile_resource_limits,
    validate_running_lease,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use eliot_testd_core::{
    NormalizedEvidence, RawArtifact, VerificationReceipt, sha256_artifact, sha256_hex,
};

pub mod kernel_client;
pub mod testd_material;
pub mod worker;
pub use kernel_client::{
    KernelTestdIpcClient, TESTD_ADMISSION_ADVERTISED, TESTD_ADMISSION_OPERATION,
    TESTD_ADMISSION_OPERATION_VERSION, advertise_testd_admission, route_testd_admission,
};
pub use worker::{ADMITTED_WORKER_LEASE_MS, drive_admitted_one_shot};

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
        left == right
            || left.starts_with(&format!("{right}\\"))
            || right.starts_with(&format!("{left}\\"))
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
        path.starts_with(&format!("{parent}\\"))
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

/// A candidate receipt returned by testd after durable admission/observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestReceipt {
    pub job_id: String,
    pub operation_id: String,
    pub process_tree_id: String,
    pub generation: u64,
    pub authority_epoch: EpochId,
    pub invocation_digest: String,
    pub allowed_contour_root: String,
    pub source_root: String,
    pub target_root: String,
    pub cache_root: String,
    pub state: String,
}

/// Explicit failure issuer used by the standalone line protocol until Kernel
/// binds a live authority.  It prevents testd from minting local permits.
pub struct UnavailableProcessIssuer;

impl KernelProcessAdmissionProvider for UnavailableProcessIssuer {
    fn admit(
        &self,
        _request: &KernelProcessAdmissionRequest,
    ) -> Result<KernelProcessAdmissionEvidence, TestdError> {
        Err(TestdError::Contract(
            "Kernel-issued ProcessRequest is required".to_owned(),
        ))
    }
}

/// Composition root over the durable `TestdJob` store.
pub struct TestdComposition {
    store: TestdStore,
    provider: Arc<dyn KernelProcessAdmissionProvider>,
}

impl TestdComposition {
    /// Opens the local execution-plane state and binds a request issuer.
    pub fn open(
        path: impl AsRef<std::path::Path>,
        provider: Arc<dyn KernelProcessAdmissionProvider>,
    ) -> Result<Self, TestdError> {
        Ok(Self {
            store: TestdStore::open(path, RetryPolicy::default())?,
            provider,
        })
    }

    /// Borrows the durable store backing this composition.
    ///
    /// The admitted one-shot worker claims and finishes through this exact
    /// handle so the lease, start, and finish views never diverge across
    /// handles. The borrow exposes no mutation beyond the store's own
    /// fenced transitions and weakens no check.
    #[must_use]
    pub fn store(&self) -> &TestdStore {
        &self.store
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
        let admission_request = KernelProcessAdmissionRequest {
            job_id: request.job_id.clone(),
            project_id: request.project_id.clone(),
            invocation: request.invocation.clone(),
            source_root: request.target_contract.target.clone(),
            target_root: request.target_contract.build_root.clone(),
            cache_root: request.target_contract.cache_root.clone(),
        };
        let permit = issue_process_admission(self.provider.as_ref(), &admission_request)?;
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
            .ok_or(TestdError::Invalid {
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

    /// Starts one claimed stage through the shared `ProcessExecutor`.
    ///
    /// The request is intentionally supplied freshly by Kernel for this
    /// attempt; the durable `TestdJob` projection can never be substituted for
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
        let current = self.store.get(&job.job_id)?.ok_or(TestdError::Invalid {
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
            || !authority_epoch.is_same_authority(&current.process.authority_epoch)
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

/// Instantiates the sole concrete `ProcessExecutor` with an authority-owned
/// validation port.  Testd owns this instance's operation trees; Kernel owns
/// permit issuance and validation.
pub fn compose_process_executor(
    authority: Arc<dyn DispatchValidationPort>,
) -> WindowsProcessExecutor {
    WindowsProcessExecutor::new(authority)
}

/// Ephemeral testd-owned dispatch authority (issue #20, DISPATCH-FINISH).
///
/// Local testd half of the merged User Broker pattern
/// (`bins/eliot-user-broker/src/lib.rs:120-216`) via the doctor copy
/// (`bins/eliot-doctor/src/dispatch_authority.rs:70-177`): the key is
/// generated in memory at composition time and never crosses a boundary;
/// `DispatchPermitAuthority` supplies the one-shot replay fence. It consumes
/// a validated dispatch grant (see
/// [`testd_material::DispatchGrant`], already proved fail-closed by the
/// reader) to build the single in-process [`ProcessRequest`] via
/// `FencingToken::new` + `PermitIssuance::new` +
/// `DispatchValidationContext::new` over a real
/// [`ClockObservation`](eliot_platform::ClockObservation) (never a native
/// JSON workaround) + `ProcessRequest::new`, exactly like the
/// broker/doctor, and it implements [`DispatchValidationPort`] so the real
/// [`WindowsProcessExecutor`] (via [`compose_process_executor`]) can
/// validate-and-consume behind it.
///
/// The [`ProcessIntent`] is derived only from the admitted profile binding
/// (see [`derive_testd_intent`]), never from argv, stdin, or environment.
pub struct TestdDispatchAuthority {
    authority: Mutex<DispatchPermitAuthority>,
    context: Mutex<Option<DispatchValidationContext>>,
}

impl TestdDispatchAuthority {
    /// Activates one ephemeral testd authority around fresh in-memory key
    /// material. The authority id names this process invocation; the key
    /// never leaves this process.
    pub fn new() -> Result<Self, TestdError> {
        let pid = std::process::id();
        let nanos = system_nanos();
        let authority_id = DispatchAuthorityId::new(format!("testd-dispatch-{pid}-{nanos}"))
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        let key = KernelDispatchKey::from_secret_bytes(fresh_key_bytes())
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
        })
    }

    /// Issues the single permit-bound process request for one validated
    /// grant and one admitted-profile intent.
    ///
    /// Mirrors the broker exactly: the fence comes from the grant epoch,
    /// generation, and fence nonce; the lease from the grant idempotency
    /// key; the `launch-grant` revision head and the one-shot nonce both
    /// carry the grant digest; issuance runs from just before `now_unix_ms`
    /// to the grant expiry; and the stored validation context pins
    /// revision 1. Freshness (`issued_at < expires_at`, and later
    /// `now < expires_at` at consume time) is enforced by the contour
    /// types, never assumed.
    pub fn issue(
        &self,
        intent: &ProcessIntent,
        grant: &crate::testd_material::DispatchGrant,
        now_unix_ms: u64,
    ) -> Result<ProcessRequest, TestdError> {
        let invalid = |error: eliot_process::ContractError| {
            TestdError::Contract(truncate_dispatch_detail(&error.to_string()))
        };
        let generation = Generation::new(grant.fence_generation).map_err(invalid)?;
        let fence = FencingToken::new(
            grant.authority_epoch.clone(),
            generation,
            grant.fence_nonce.clone(),
        )
        .map_err(invalid)?;
        let lease = ActionLeaseRef::new(grant.idempotency_key.clone()).map_err(invalid)?;
        let heads = BTreeMap::from([("launch-grant".to_owned(), grant.grant_digest.clone())]);
        let issuance = PermitIssuance::new(
            lease,
            fence.clone(),
            heads.clone(),
            now_unix_ms.saturating_sub(1).max(1),
            grant.expires_at,
            grant.grant_digest.clone(),
        )
        .map_err(invalid)?;
        let permit = self
            .authority
            .lock()
            .map_err(|_| TestdError::Contract("testd authority lock poisoned".to_owned()))?
            .issue(intent, issuance)
            .map_err(invalid)?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(i64::try_from(now_unix_ms).unwrap_or(i64::MAX)),
                known_time_ms: Some(i64::try_from(now_unix_ms).unwrap_or(i64::MAX)),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            grant.authority_epoch.clone(),
            heads,
            1,
        )
        .map_err(invalid)?;
        *self
            .context
            .lock()
            .map_err(|_| TestdError::Contract("testd context lock poisoned".to_owned()))? =
            Some(context);
        ProcessRequest::new(intent.clone(), permit).map_err(invalid)
    }
}

impl DispatchValidationPort for TestdDispatchAuthority {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let current = self
            .context
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("testd context lock poisoned".to_owned())
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable("missing testd validation context".to_owned())
            })?;
        self.authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("testd authority lock poisoned".to_owned())
            })?
            .validate_and_consume(request, observed, &current)
            .map_err(ProcessExecutionError::from)
    }
}

/// Derives the process-invocation component of the authority id from the
/// wall clock. Uniqueness (not secrecy) is load-bearing here: the id only
/// names the instance.
fn system_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        })
}

/// Generates fresh per-process key bytes from process-unique std sources
/// mixed through splitmix64, without adding a randomness dependency.
///
/// The load-bearing property is per-process uniqueness, not
/// unpredictability: the key never leaves this process, is never persisted,
/// and only binds permits issued by this same authority instance (which the
/// executor shares by `Arc`, never by value). The replay fence is
/// per-instance regardless, and the process exits after one shot.
fn fresh_key_bytes() -> [u8; 32] {
    static MIXER: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    let probe = 0u64;
    let stack = std::ptr::addr_of!(probe) as usize as u64;
    let pid = u64::from(std::process::id());
    let count = MIXER.fetch_add(1, Ordering::Relaxed);
    let mut state = system_nanos()
        ^ pid.wrapping_mul(0xBF58_476D_1CE4_E5B9)
        ^ stack.rotate_left(17)
        ^ count.wrapping_mul(0x94D0_49BB_1331_11EB);
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        chunk.copy_from_slice(&splitmix64(&mut state).to_le_bytes());
    }
    if out.iter().all(|byte| *byte == 0) {
        out[31] = 1;
    }
    out
}

/// Bounds third-party error detail carried into deny lines.
fn truncate_dispatch_detail(detail: &str) -> String {
    const LIMIT: usize = 256;
    detail.chars().take(LIMIT).collect()
}

/// Admitted identities for one profile-bound intent derivation.
///
/// Every identity arrives with the admitted material; no value is taken
/// from argv, stdin, or environment. The executable path and digest arrive
/// from [`resolve_testd_tool`] (installed file bytes); the argv,
/// environment, and limits come only from the closed registry binding.
pub struct TestdDerivedIntentParams {
    /// Admitted testd job identity.
    pub job_id: String,
    /// Admitted operation identity.
    pub operation_id: String,
    /// Admitted profile name (exactly one is admitted).
    pub profile: String,
    /// Admitted activation generation (non-zero).
    pub generation: u64,
    /// Dispatch session nonce; binds the process session identity.
    pub session_nonce: String,
    /// Resolved absolute tool path from [`resolve_testd_tool`].
    pub executable_absolute: String,
    /// SHA-256 over the resolved tool file bytes.
    pub executable_sha256: String,
    /// Admitted generation root used as the working directory.
    pub generation_root: String,
}

/// Derives one [`ProcessIntent`] only from the admitted profile binding
/// plus admitted identities.
///
/// The executable digest, argv, environment, and limits come exclusively
/// from the closed [`eliot_testd_core::TestdExecutableBinding`]: the
/// caller's invocation arguments are never consulted (registration already
/// refuses non-empty arguments). The working directory is always the
/// admitted generation root, never a caller path. Identity scaffolding
/// (operation, tree, job, image, session, generation) is derived
/// deterministically from admitted material, never invented.
pub fn derive_testd_intent(params: &TestdDerivedIntentParams) -> Result<ProcessIntent, TestdError> {
    for (value, field) in [
        (params.job_id.as_str(), "job_id"),
        (params.operation_id.as_str(), "operation_id"),
        (params.session_nonce.as_str(), "session_nonce"),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(TestdError::Invalid {
                field,
                reason: "must be non-blank and control-free",
            });
        }
    }
    if !is_admitted_testd_profile(&params.profile) {
        return Err(TestdError::Invalid {
            field: "profile",
            reason: "testd admits only the closed cargo-test tool-probe profile",
        });
    }
    let binding = testd_profile_binding(&params.profile, &params.executable_sha256)?;
    let executable = Path::new(&params.executable_absolute);
    if !executable.is_absolute()
        || executable
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(TestdError::Invalid {
            field: "executable",
            reason: "must be a resolved absolute tool path without parent traversal",
        });
    }
    let generation_root = Path::new(&params.generation_root);
    if !generation_root.is_absolute()
        || generation_root
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || !generation_root.is_dir()
    {
        return Err(TestdError::Invalid {
            field: "generation_root",
            reason: "must be an existing absolute generation root without parent traversal",
        });
    }
    let invalid = |error: eliot_process::ContractError| {
        TestdError::Contract(truncate_dispatch_detail(&error.to_string()))
    };
    let generation = Generation::new(params.generation).map_err(invalid)?;
    let intent = ProcessIntent::new(
        OperationId::new(params.operation_id.clone()).map_err(invalid)?,
        ProcessTreeId::new(format!("{}-tree", params.job_id)).map_err(invalid)?,
        JobId::new(params.job_id.clone()).map_err(invalid)?,
        ImageId::new(format!("testd-profile-{}", params.profile)).map_err(invalid)?,
        SessionId::new(params.session_nonce.clone()).map_err(invalid)?,
        generation,
        params.executable_absolute.clone(),
        binding.package_artifact_digest.clone(),
        binding.fixed_argv.clone(),
        params.generation_root.clone(),
        testd_profile_environment(&binding)?,
        testd_profile_resource_limits(&binding)?,
    )
    .map_err(invalid)?;
    Ok(intent)
}

/// Resolved installed tool for the admitted profile: the absolute
/// executable path plus the SHA-256 over its exact file bytes.
///
/// Searches the platform `PATH` for the registry's relative program
/// (`PATH` is platform tool configuration, not caller authority),
/// canonicalizes the located candidate exactly once at registration, and
/// hashes the installed file bytes. Canonicalization matters because a
/// platform toolchain shim (for example a `cargo.exe` symbolic link) is a
/// reparse point, and the executor's executable pinning refuses reparse
/// points fail-closed: the intent must name the installed file the shim
/// resolves to, so the executor pins and re-hashes those exact bytes. No
/// digest is hardcoded: the installed bytes differ per host, and the
/// executor re-hashes the file before any start, so a substituted file
/// fails there as well as in the binding digest.
pub struct ResolvedTestdTool {
    /// Resolved absolute installed tool path (canonical, no reparse).
    pub executable_absolute: String,
    /// SHA-256 over the resolved installed tool file bytes.
    pub executable_sha256: String,
}

/// Tool file names probed on `PATH`, in order.
#[cfg(windows)]
const TESTD_TOOL_FILE_NAMES: &[&str] = &["cargo.exe", "cargo"];
/// Tool file names probed on `PATH`, in order.
#[cfg(not(windows))]
const TESTD_TOOL_FILE_NAMES: &[&str] = &["cargo"];

/// Resolves the registry's relative program to its installed file.
///
/// Refuses anything but the closed relative program spelling (which
/// rejects absolute paths and parent traversal by equality), then probes
/// the platform `PATH` for the tool file. Each located candidate is
/// canonicalized once at registration and only a canonical target that is
/// an existing real file is accepted; candidates that do not resolve
/// (dangling shims, directories, reparse chains that resolve to nothing
/// usable) are skipped, and exhaustion fails closed.
pub fn resolve_testd_tool(program_path: &str) -> Result<ResolvedTestdTool, TestdError> {
    if program_path != eliot_testd_core::TESTD_PROFILE_PROGRAM {
        return Err(TestdError::Invalid {
            field: "program_path",
            reason: "testd admits only the closed relative tool program",
        });
    }
    let probe = Path::new(program_path);
    if probe.is_absolute()
        || probe
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(TestdError::Invalid {
            field: "program_path",
            reason: "absolute paths and parent traversal are forbidden",
        });
    }
    let path_var = std::env::var_os("PATH").ok_or(TestdError::Invalid {
        field: "program_path",
        reason: "the platform tool locator carries no PATH",
    })?;
    for directory in std::env::split_paths(&path_var) {
        for file_name in TESTD_TOOL_FILE_NAMES {
            let candidate = directory.join(file_name);
            if !candidate.is_file() {
                continue;
            }
            // Follow the platform shim exactly once: the executor pins
            // real files only, so the intent must name the installed
            // file, never the reparse point.
            let Ok(canonical) = std::fs::canonicalize(&candidate) else {
                continue;
            };
            if !canonical.is_file() {
                continue;
            }
            // Belt-and-braces: canonicalization already resolves the full
            // chain, so the target must not be a symlink itself; anything
            // unstatable fails closed to the next candidate.
            let Ok(canonical_metadata) = std::fs::symlink_metadata(&canonical) else {
                continue;
            };
            if canonical_metadata.file_type().is_symlink() {
                continue;
            }
            let Ok(bytes) = std::fs::read(&canonical) else {
                continue;
            };
            return Ok(ResolvedTestdTool {
                executable_absolute: canonical.to_string_lossy().into_owned(),
                executable_sha256: eliot_testd_core::sha256_hex(&bytes),
            });
        }
    }
    Err(TestdError::Invalid {
        field: "program_path",
        reason: "the admitted tool is not installed on the platform PATH",
    })
}

/// Typed outcome of driving one validated dispatch file through the bounded
/// admitted probe ([`drive_validated_dispatch_material`]).
///
/// HONEST-STOP: every post-derivation outcome is typed here; a refused
/// derivation or issuance (nothing executed) is `Err(TestdError)`, never an
/// invented outcome. Cancellation projects without executing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatedDispatchDriveOutcome {
    /// The single consuming start completed; verification owns disposition.
    Completed {
        /// Echo of the admitted job identity.
        job_id: String,
    },
    /// A cancelled admission was projected without executing.
    Cancelled {
        /// Echo of the admitted job identity.
        job_id: String,
    },
    /// Executor-owned unknown outcome: reconcile by the exact digest, never
    /// blind-retry.
    ReconcileRequired {
        /// Echo of the admitted job identity.
        job_id: String,
    },
}

/// Drives one validated dispatch file through the bounded admitted probe.
///
/// Broker pattern (mirroring `bins/eliot-user-broker` via the doctor copy):
/// the grant digest/epoch/fence arrive in the validated material, the
/// [`TestdDispatchAuthority`] issues from exactly that grant over a real
/// [`ClockObservation`](eliot_platform::ClockObservation), the
/// [`ProcessIntent`](eliot_process::ProcessIntent) derives only from the
/// admitted profile binding plus the installed tool bytes (never from argv,
/// stdin, or environment), the [`ProcessRequest`](eliot_process::ProcessRequest)
/// is built in-process, and the real composed [`WindowsProcessExecutor`]
/// runs exactly one start. No mock, fake, or canned digest participates.
///
/// DISPATCH-WIRE seam for W3 (`bins/eliot-kernel`, issue #461):
/// - Kernel main (W3-owned; this crate never edits it) composes the testd
///   side via installed digests: it stages the real built `eliot-testd`
///   image under the launch root, reads the staged bytes for the executable
///   digest (mirroring the native up-to-spawn template in
///   `bins/eliot-kernel/src/dispatch_launch.rs`), writes the seven-key
///   admitted-attempt file next to the staged image, and spawns the real
///   binary. The child binary reaches this function through its
///   `drive_material_probe` after the closed Kernel bootstrap and
///   advertisement gate.
/// - The Kernel-launch E2E lives in W3-owned `dispatch_launch.rs` tests and
///   follows the up-to-spawn template there; the child-side drive readiness
///   here (real tool resolution, real dispatch authority, real composed
///   executor, bounded `cargo --version` probe) is what that test drives.
///   Advertisement flips only via the dispatch contour
///   (`TESTD_ADMISSION_ADVERTISED`); this function never invents it.
///
/// Caller contract: `generation_root` is the admitted working directory. The
/// binary passes its dispatch-locator directory (the honest closed stand-in
/// for the bounded probe, which reads no working directory); the production
/// contour delivers the admitted generation root.
pub async fn drive_validated_dispatch_material(
    material: &crate::testd_material::ValidatedTestdMaterial,
    generation_root: &str,
    now_unix_ms: u64,
) -> Result<ValidatedDispatchDriveOutcome, TestdError> {
    if material.cancelled {
        return Ok(ValidatedDispatchDriveOutcome::Cancelled {
            job_id: material.job_id.clone(),
        });
    }
    let tool = resolve_testd_tool(eliot_testd_core::TESTD_PROFILE_PROGRAM)?;
    let params = TestdDerivedIntentParams {
        job_id: material.job_id.clone(),
        operation_id: material.operation_id.clone(),
        profile: material.profile.clone(),
        generation: material.generation,
        session_nonce: material.nonce.clone(),
        executable_absolute: tool.executable_absolute,
        executable_sha256: tool.executable_sha256,
        generation_root: generation_root.to_owned(),
    };
    let intent = derive_testd_intent(&params)?;
    let authority = TestdDispatchAuthority::new()?;
    let request = authority.issue(&intent, &material.grant, now_unix_ms)?;
    let executor = compose_process_executor(Arc::new(authority));
    let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(EvidenceCollector::default());
    match executor.start(request, sink).await {
        Ok(_) => Ok(ValidatedDispatchDriveOutcome::Completed {
            job_id: material.job_id.clone(),
        }),
        Err(ProcessExecutionError::UnknownOutcome) => {
            Ok(ValidatedDispatchDriveOutcome::ReconcileRequired {
                job_id: material.job_id.clone(),
            })
        }
        Err(error) => Err(TestdError::Contract(truncate_dispatch_detail(
            &error.to_string(),
        ))),
    }
}

/// Drives exactly one admitted one-shot claim through the worker.
///
/// Thin binary entry used by `main` on the admitted path: durable claim,
/// fresh bound admission, the single consuming start, observation, raw
/// capture, and deterministic finish/cancel all live in
/// [`worker::drive_admitted_one_shot`]. This only binds the composition's own
/// store handle so claim, finish, and start observe one durable view.
/// `Succeeded` stays a local status projection and is never canonical.
pub fn run_admitted_one_shot<E: ProcessExecutor + 'static>(
    composition: &TestdComposition,
    presented: kernel_client::PresentedAdmission,
    executor: &E,
    owner: &str,
    lease_ms: u64,
    now: u64,
) -> Result<TestReceipt, TestdError> {
    let store = composition.store();
    worker::drive_admitted_one_shot(
        composition,
        store,
        presented,
        executor,
        owner,
        lease_ms,
        now,
    )
}

fn receipt(job: &TestJob) -> TestReceipt {
    TestReceipt {
        job_id: job.job_id.clone(),
        operation_id: job.process.operation_id.clone(),
        process_tree_id: job.process.process_tree_id.clone(),
        generation: job.process.generation,
        authority_epoch: job.process.authority_epoch.clone(),
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
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Binary/protocol errors use the same typed `TestdError` surface.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("instrument contract: {0}")]
    Instrument(#[from] InstrumentContractError),
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures intentionally panic when construction or filesystem setup invariants fail"
)]
mod tests {
    use super::kernel_client::{
        PresentedAdmission, TESTD_ADMISSION_OPERATION, TESTD_ADMISSION_OPERATION_VERSION,
        TestdAdmissionRequest, canonical_invocation_digest,
    };
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId};
    use eliot_process::{
        ActionLeaseRef, CancellationReceipt, DispatchAuthorityId, DispatchPermitAuthority,
        EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation, ImageId, JobId,
        KernelDispatchKey, OperationId, PermitIssuance, ProcessEvidence, ProcessEvidenceSink,
        ProcessExecutionError, ProcessExecutionView, ProcessExecutor, ProcessIntent,
        ProcessRequest, ProcessStartReceipt, ProcessTreeId, ResourceLimits, SessionId,
    };
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;
    use std::sync::Mutex;

    fn test_epoch(sequence: u64) -> EpochId {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_root(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "eliot-testd-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    struct ExternalKernelProvider {
        process: Mutex<Option<ProcessRequest>>,
        contour_root: String,
    }

    impl KernelProcessAdmissionProvider for ExternalKernelProvider {
        fn admit(
            &self,
            _request: &KernelProcessAdmissionRequest,
        ) -> Result<KernelProcessAdmissionEvidence, TestdError> {
            let process = self
                .process
                .lock()
                .map_err(|_| TestdError::Contract("provider lock failed".to_owned()))?
                .take()
                .ok_or_else(|| TestdError::Contract("process was already consumed".to_owned()))?;
            Ok(KernelProcessAdmissionEvidence {
                process,
                contour_root: self.contour_root.clone(),
                grant_id: "grant-external-1".to_owned(),
            })
        }
    }

    fn external_process_request(source: &str, target: &str, cache: &str) -> ProcessRequest {
        let generation = Generation::new(1).unwrap();
        let intent = ProcessIntent::new(
            OperationId::new("operation-1").unwrap(),
            ProcessTreeId::new("tree-1").unwrap(),
            JobId::new("job-1").unwrap(),
            ImageId::new("image-1").unwrap(),
            SessionId::new("session-1").unwrap(),
            generation,
            "C:\\tools\\worker.exe",
            "c".repeat(64),
            vec!["--check".to_owned()],
            source,
            EnvironmentProjection::new(
                BTreeMap::from([
                    ("CARGO_TARGET_DIR".to_owned(), target.to_owned()),
                    ("CARGO_HOME".to_owned(), cache.to_owned()),
                ]),
                Vec::new(),
                EnvironmentInheritance::None,
            )
            .unwrap(),
            ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4).unwrap(),
        )
        .unwrap();
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("authority-1").unwrap(),
            KernelDispatchKey::from_secret_bytes([0x5a; 32]).unwrap(),
        );
        let permit = authority
            .issue(
                &intent,
                PermitIssuance::new(
                    ActionLeaseRef::new("lease-1").unwrap(),
                    FencingToken::new(test_epoch(7), generation, "fence-1").unwrap(),
                    BTreeMap::from([
                        ("authority".to_owned(), "a".repeat(64)),
                        ("state".to_owned(), "b".repeat(64)),
                    ]),
                    1,
                    2,
                    "nonce-1",
                )
                .unwrap(),
            )
            .unwrap();
        ProcessRequest::new(intent, permit).unwrap()
    }

    fn external_invocation() -> InstrumentInvocation {
        serde_json::from_value(serde_json::json!({
            "request": {
                "request_id": "operation-1",
                "session_id": null,
                "task_id": null,
                "product_id": "product-1",
                "source_id": "source-1",
                "state_fence": {
                    "authority_epoch": {
                        "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                        "sequence": 7
                    },
                    "resource_generation": 1,
                    "task_revision": null,
                    "policy_revision": null,
                    "integration_revision": null
                },
                "clock": {
                    "valid_time_ms": 1,
                    "known_time_ms": 1,
                    "transaction_sequence": null,
                    "monotonic_ns": 1
                }
            },
            "instrument": "eliot.instrument.test",
            "kind": "TEST",
            "profile": "cargo-test",
            "target": "C:\\source",
            "arguments": [],
            "input_artifacts": [],
            "declared_scope": "workspace",
            "requested_at": {
                "valid_time_ms": 1,
                "known_time_ms": 1,
                "transaction_sequence": null,
                "monotonic_ns": 1
            }
        }))
        .unwrap()
    }

    #[test]
    fn external_kernel_provider_seals_bound_permit_without_caller_contour() {
        let source = "C:\\source";
        let target = "C:\\contour\\build";
        let contour = "C:\\contour";
        let provider = ExternalKernelProvider {
            process: Mutex::new(Some(external_process_request(source, target, target))),
            contour_root: contour.to_owned(),
        };
        let invocation = external_invocation();
        let request = KernelProcessAdmissionRequest {
            job_id: "job-1".to_owned(),
            project_id: "project-1".to_owned(),
            invocation,
            source_root: source.to_owned(),
            target_root: target.to_owned(),
            cache_root: target.to_owned(),
        };
        let permit = issue_process_admission(&provider, &request).unwrap();
        assert_eq!(permit.grant().contour_root(), contour);
        let (process, grant) = permit.into_parts();
        assert_eq!(process.job_id().as_str(), "job-1");
        assert_eq!(grant.contour_root(), contour);

        let forged = serde_json::json!({
            "target": source,
            "build_root": target,
            "cache_root": target,
            "allowed_contour_root": "C:\\caller-widened"
        });
        assert!(serde_json::from_value::<TargetContract>(forged).is_err());
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

    /// Minimal test-only executor: counts consuming starts and reports the
    /// executor-owned unknown path, which the worker must reconcile by exact
    /// identity instead of retrying blind. Inspection, cancellation, and
    /// reconciliation are unreachable on the covered paths.
    struct OneShotTestExecutor {
        starts: Mutex<usize>,
    }

    impl ProcessExecutor for OneShotTestExecutor {
        async fn start(
            &self,
            _request: ProcessRequest,
            _sink: Arc<dyn ProcessEvidenceSink>,
        ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
            *self.starts.lock().unwrap() += 1;
            Err(ProcessExecutionError::UnknownOutcome)
        }

        async fn inspect(
            &self,
            _operation_id: OperationId,
        ) -> Result<ProcessExecutionView, ProcessExecutionError> {
            Err(ProcessExecutionError::NotFound)
        }

        async fn cancel(
            &self,
            _operation_id: OperationId,
        ) -> Result<CancellationReceipt, ProcessExecutionError> {
            Err(ProcessExecutionError::NotFound)
        }

        async fn reconcile(
            &self,
            _operation_id: OperationId,
        ) -> Result<ProcessEvidence, ProcessExecutionError> {
            Err(ProcessExecutionError::NotFound)
        }
    }

    /// Submitted-job fixture reusing the existing provider/process doubles:
    /// one durable TEST job admitted through `ExternalKernelProvider` over
    /// real temporary roots.
    struct AdmittedDriveFixture {
        base: PathBuf,
        composition: TestdComposition,
        invocation: InstrumentInvocation,
        source: String,
        build: String,
        contour: String,
    }

    fn admitted_drive_fixture(label: &str) -> AdmittedDriveFixture {
        let base = test_root(label);
        let source_dir = base.join("source");
        let contour_dir = base.join("external");
        let build_dir = contour_dir.join("build");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::create_dir_all(&build_dir).unwrap();
        // Canonicalize up front: the durable projection persists canonical
        // roots, the fresh seal compares exact strings, and `start_claimed`
        // binds the presented process to the durable roots by string
        // equality, so every party must seal the canonical form.
        let source = std::fs::canonicalize(&source_dir)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let build = std::fs::canonicalize(&build_dir)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let contour = std::fs::canonicalize(&contour_dir)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let provider = ExternalKernelProvider {
            process: Mutex::new(Some(external_process_request(&source, &build, &build))),
            contour_root: contour.clone(),
        };
        let composition =
            TestdComposition::open(base.join("testd-state.redb"), Arc::new(provider)).unwrap();
        let invocation = external_invocation();
        composition
            .submit(TestdJobRequest {
                job_id: "job-1".to_owned(),
                project_id: "project-1".to_owned(),
                invocation: invocation.clone(),
                target_contract: TargetContract {
                    target: source.clone(),
                    build_root: build.clone(),
                    cache_root: build.clone(),
                },
                priority: 0,
            })
            .unwrap();
        AdmittedDriveFixture {
            base,
            composition,
            invocation,
            source,
            build,
            contour,
        }
    }

    fn presented_for(fixture: &AdmittedDriveFixture, cancelled: bool) -> PresentedAdmission {
        let invocation_digest = canonical_invocation_digest(&fixture.invocation).unwrap();
        let envelope = TestdAdmissionRequest {
            wire_id: TESTD_ADMISSION_OPERATION.to_owned(),
            wire_version: TESTD_ADMISSION_OPERATION_VERSION,
            job_id: "job-1".to_owned(),
            invocation_id: "operation-1".to_owned(),
            invocation_digest,
            authority_epoch: test_epoch(7),
            generation: 1,
            request_digest: String::new(),
        }
        .with_computed_digest()
        .unwrap();
        PresentedAdmission {
            request: envelope,
            invocation: fixture.invocation.clone(),
            process: external_process_request(&fixture.source, &fixture.build, &fixture.build),
            epoch: test_epoch(7),
            evidence_ref: "evidence-1".to_owned(),
            cancelled,
        }
    }

    #[test]
    fn admitted_one_shot_drives_claim_to_reconcile_receipt() {
        let fixture = admitted_drive_fixture("admitted-drive");
        let presented = presented_for(&fixture, false);
        let executor = OneShotTestExecutor {
            starts: Mutex::new(0),
        };
        let receipt = run_admitted_one_shot(
            &fixture.composition,
            presented,
            &executor,
            SERVICE_NAME,
            ADMITTED_WORKER_LEASE_MS,
            unix_ms(),
        )
        .unwrap();
        assert_eq!(receipt.job_id, "job-1");
        assert_eq!(receipt.state, "RetryWait");
        // The durable projection retains canonical source roots, while the
        // allowed contour keeps the provider-sealed string; both are checked
        // in the exact form the validators persist.
        let expected_source = std::fs::canonicalize(fixture.base.join("source"))
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(receipt.source_root, expected_source);
        assert_eq!(receipt.allowed_contour_root, fixture.contour);
        assert_eq!(*executor.starts.lock().unwrap(), 1);
        std::fs::remove_dir_all(fixture.base).unwrap();
    }

    #[test]
    fn admitted_cancelled_presentation_projects_cancel_without_start() {
        let fixture = admitted_drive_fixture("admitted-cancel");
        let presented = presented_for(&fixture, true);
        let executor = OneShotTestExecutor {
            starts: Mutex::new(0),
        };
        let receipt = run_admitted_one_shot(
            &fixture.composition,
            presented,
            &executor,
            SERVICE_NAME,
            ADMITTED_WORKER_LEASE_MS,
            unix_ms(),
        )
        .unwrap();
        assert_eq!(receipt.job_id, "job-1");
        assert_eq!(receipt.state, "Cancelled");
        assert_eq!(*executor.starts.lock().unwrap(), 0);
        std::fs::remove_dir_all(fixture.base).unwrap();
    }

    /// Resolves the admitted tool through the platform `PATH`, hashes the
    /// installed file bytes, and proves the closed binding digest binds
    /// while tampered bindings fail. Returns the resolved tool for the
    /// Drive half below.
    fn admitted_tool_binding() -> super::ResolvedTestdTool {
        use eliot_testd_core::{
            TESTD_ADMITTED_PROFILE, TESTD_PROFILE_PROGRAM, is_admitted_testd_profile, sha256_hex,
            testd_binding_digest, testd_definition_digest, testd_profile_binding,
            validate_testd_binding_digest,
        };

        assert!(is_admitted_testd_profile(TESTD_ADMITTED_PROFILE));
        assert!(!is_admitted_testd_profile("other-profile"));

        // Real tool resolution: PATH lookup plus a hash over the installed
        // file bytes. Fails honestly when the toolchain is absent.
        let tool = super::resolve_testd_tool(TESTD_PROFILE_PROGRAM)
            .expect("admitted tool must resolve on PATH");
        let reread = std::fs::read(&tool.executable_absolute).expect("tool bytes must read");
        assert_eq!(tool.executable_sha256, sha256_hex(&reread));

        // Closed binding: validates, and its digest binds.
        let binding = testd_profile_binding(TESTD_ADMITTED_PROFILE, &tool.executable_sha256)
            .expect("admitted binding must validate");
        assert!(binding.validate().is_ok());
        let digest = testd_binding_digest(&binding).expect("binding digest must compute");
        assert!(validate_testd_binding_digest(&binding, &digest).is_ok());
        // The static definition digest is stable for identical input.
        let first = testd_definition_digest().expect("definition digest must compute");
        let second = testd_definition_digest().expect("definition digest must compute");
        assert_eq!(first, second);

        // Tampered bindings fail: a substituted artifact digest no longer
        // binds, widened argv refuses validation, and an unregistered
        // profile never resolves.
        let mut substituted = binding.clone();
        substituted.package_artifact_digest = "0".repeat(64);
        assert!(substituted.validate().is_ok());
        assert!(matches!(
            validate_testd_binding_digest(&substituted, &digest),
            Err(TestdError::InvalidBinding)
        ));
        let mut widened = binding.clone();
        widened.fixed_argv.push("--evil".to_owned());
        assert!(widened.validate().is_err());
        assert!(testd_profile_binding("other-profile", &tool.executable_sha256).is_err());
        tool
    }

    /// DISPATCH-FINISH behaviour: the admitted profile binding digest
    /// binds, a tampered binding fails, the dispatch authority constructs,
    /// and the Drive intent derives only from the admitted profile.
    ///
    /// Every identity here is real: the tool resolves through the platform
    /// `PATH` and its digest hashes the installed file bytes, the epoch
    /// comes from `EpochId::new` over a parsed lineage, the fence and lease
    /// rebuild through the broker constructors inside the authority, and
    /// the final start runs through the real composed
    /// `WindowsProcessExecutor`. No mock, fake, or canned digest
    /// participates.
    #[test]
    fn admitted_profile_binding_digest_binds_and_authority_derives_intent() {
        use eliot_testd_core::{TESTD_ADMITTED_PROFILE, TESTD_PROFILE_WALL_TIMEOUT_MS, sha256_hex};
        use std::task::{Context, Poll, Waker};

        fn block_on_drive_test<F: std::future::Future>(future: F) -> F::Output {
            let waker = Waker::noop();
            let mut context = Context::from_waker(waker);
            let mut pinned = Box::pin(future);
            loop {
                match pinned.as_mut().poll(&mut context) {
                    Poll::Ready(output) => return output,
                    Poll::Pending => std::thread::yield_now(),
                }
            }
        }

        let tool = admitted_tool_binding();
        // The ephemeral authority constructs and issues through the real
        // contour constructors against a validated grant.

        // The ephemeral authority constructs and issues through the real
        // contour constructors against a validated grant.
        let authority =
            super::TestdDispatchAuthority::new().expect("dispatch authority must construct");
        let epoch = test_epoch(7);
        let now = super::unix_ms();
        assert_ne!(now, 0);
        let grant = super::testd_material::DispatchGrant {
            grant_digest: sha256_hex(b"testd-dispatch-finish-test-grant"),
            authority_epoch: epoch,
            fence_generation: 1,
            fence_nonce: "testd-test-fence-01".to_owned(),
            idempotency_key: "testd-test-lease-01".to_owned(),
            expires_at: now.saturating_add(60_000),
        };
        assert!(grant.expires_at > now);

        // The Drive intent derives only from the admitted binding plus
        // admitted identities: fixed argv, closed environment, binding
        // caps, and the installed executable hash.
        let cwd =
            std::env::temp_dir().join(format!("eliot-testd-drive-{}-{now}", std::process::id()));
        std::fs::create_dir_all(&cwd).expect("probe cwd must create");
        let params = super::TestdDerivedIntentParams {
            job_id: "job-testd-drive-1".to_owned(),
            operation_id: "testd-op-drive-1".to_owned(),
            profile: TESTD_ADMITTED_PROFILE.to_owned(),
            generation: 1,
            session_nonce: "testd-drive-session-01".to_owned(),
            executable_absolute: tool.executable_absolute.clone(),
            executable_sha256: tool.executable_sha256.clone(),
            generation_root: cwd.to_string_lossy().into_owned(),
        };
        let intent =
            super::derive_testd_intent(&params).expect("intent must derive from the binding");
        assert_eq!(intent.executable(), tool.executable_absolute.as_str());
        assert_eq!(intent.executable_sha256(), tool.executable_sha256.as_str());
        assert_eq!(intent.argv().to_vec(), vec!["--version".to_owned()]);
        assert!(intent.environment().non_secret().is_empty());
        assert_eq!(
            intent.resource_limits().wall_timeout_ms(),
            TESTD_PROFILE_WALL_TIMEOUT_MS
        );
        assert_eq!(intent.operation_id().as_str(), "testd-op-drive-1");
        assert_eq!(intent.generation().get(), 1);
        intent.validate().expect("derived intent must validate");

        let request = authority
            .issue(&intent, &grant, now)
            .expect("authority must issue");
        request.validate().expect("issued request must validate");

        // The real composed executor runs the bounded probe. On Windows
        // `cargo --version` exits fast under the binding caps; elsewhere
        // the Windows executor is unavailable by design.
        let executor = super::compose_process_executor(Arc::new(authority));
        let sink: Arc<dyn eliot_process::ProcessEvidenceSink> =
            Arc::new(eliot_testd_core::EvidenceCollector::default());
        let started = block_on_drive_test(executor.start(request, sink));
        #[cfg(windows)]
        assert!(started.is_ok(), "bounded probe must start: {started:?}");
        #[cfg(not(windows))]
        assert!(matches!(
            started,
            Err(eliot_process::ProcessExecutionError::Unavailable(_))
        ));
        std::fs::remove_dir_all(&cwd).expect("probe cwd must clean");
    }

    /// The dispatch-wire drive seam projects cancellation without executing:
    /// a cancelled [`ValidatedTestdMaterial`](super::testd_material::ValidatedTestdMaterial)
    /// returns `Cancelled` before tool resolution, intent derivation, or any
    /// start. The live `Completed` path is proven through the binary's
    /// child-side E2E, which now drives [`super::drive_validated_dispatch_material`].
    #[test]
    fn validated_dispatch_drive_projects_cancel_without_executing() {
        use std::task::{Context, Poll, Waker};

        fn block_on_cancel_test<F: std::future::Future>(future: F) -> F::Output {
            let waker = Waker::noop();
            let mut context = Context::from_waker(waker);
            let mut pinned = Box::pin(future);
            loop {
                match pinned.as_mut().poll(&mut context) {
                    Poll::Ready(output) => return output,
                    Poll::Pending => std::thread::yield_now(),
                }
            }
        }

        let epoch = test_epoch(7);
        let generation = Generation::new(1).unwrap();
        let fence = FencingToken::new(epoch.clone(), generation, "fence-1").unwrap();
        let material = super::testd_material::ValidatedTestdMaterial {
            job_id: "job-testd-cancel-1".to_owned(),
            operation_id: "testd-op-1".to_owned(),
            profile: "cargo-test".to_owned(),
            profile_binding_digest: "a".repeat(64),
            request_digest: "b".repeat(64),
            admission_digest: "c".repeat(64),
            epoch,
            generation: 1,
            nonce: "testd-dispatch-cancel-01".to_owned(),
            grant_digest: "d".repeat(64),
            grant: super::testd_material::DispatchGrant {
                grant_digest: "d".repeat(64),
                authority_epoch: test_epoch(7),
                fence_generation: 1,
                fence_nonce: "fence-1".to_owned(),
                idempotency_key: "lease-1".to_owned(),
                expires_at: 2,
            },
            fence,
            cancelled: true,
        };
        let outcome = block_on_cancel_test(super::drive_validated_dispatch_material(
            &material,
            "C:\\unused-generation-root",
            1,
        ));
        assert!(
            matches!(
                outcome,
                Ok(super::ValidatedDispatchDriveOutcome::Cancelled { ref job_id })
                if job_id == "job-testd-cancel-1"
            ),
            "cancelled material must project cancellation without executing, got {outcome:?}"
        );
    }
}
