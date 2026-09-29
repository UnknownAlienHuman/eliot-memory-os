//! Profile-specific supervision adapters and root proofs.
//!
//! This module consumes provider-neutral projections of the descriptor-owned
//! profile selection. It does not depend on `eliot-installation`; callers must
//! validate the complete descriptor and then pass its exact root roles here.
//! `UserMode` is current-user and least-privilege only. `PortableDev` is retained
//! under the repository root and remains process/Job supervised by Host.

use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{FileIdentity, UserOwnedRootLease, WindowsAdapterError};

/// Profile selector projected by Host from the validated installation
/// descriptor without introducing a platform-to-installation dependency.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileSelection {
    /// Current-user installation with a per-user Task Scheduler adapter.
    UserMode,
    /// Repository-local disposable profile with direct Host Job supervision.
    PortableDev,
}

/// The four distinct I3.1 root roles, projected as exact descriptor paths.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRootPaths {
    /// Immutable versioned binaries.
    pub immutable_binaries: PathBuf,
    /// Durable installation/profile state.
    pub durable_data: PathBuf,
    /// User configuration (kept separate from cache).
    pub user_config: PathBuf,
    /// User cache (kept separate from configuration).
    pub user_cache: PathBuf,
    /// Digest-bound `RuntimeStateRoots` paths, each retaining its role name.
    pub runtime_state_roots: Vec<(String, PathBuf)>,
}

/// Provider-neutral request made only after the `RuntimeLaunchDescriptor` has
/// passed its digest, profile, and exact four-root equality checks.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRootRequest {
    /// The profile selected by the signed/digest-bound descriptor.
    pub profile: ProfileSelection,
    /// Stable installation identity from the descriptor epoch.
    pub installation_id: String,
    /// Optional profile installation key, when the selected profile has one.
    pub installation_key: Option<String>,
    /// Exact component identity.
    pub component: String,
    /// Exact immutable version identity.
    pub version: String,
    /// Exact active generation identity.
    pub generation: String,
    /// Authority descriptor path selected for this immutable Host generation.
    pub authority_descriptor_path: PathBuf,
    /// Authority descriptor digest selected for this immutable generation.
    pub authority_descriptor_sha256: String,
    /// Authority generation encoded by the canonical Host bootstrap.
    pub authority_generation: u64,
    /// The four profile-governed roots plus every runtime state root.
    pub roots: ProfileRootPaths,
    /// Canonical repository root for `PortableDev`; absent for `UserMode`.
    pub repository_root: Option<PathBuf>,
}

/// One root role backed by a live no-follow current-user directory handle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRootObservation {
    /// Descriptor role name, such as `immutable_binaries` or
    /// `runtime_state_roots.host_state_root`.
    pub role: String,
    /// Canonical path obtained from the retained OS handle.
    pub canonical_path: PathBuf,
    /// File-object identity observed from that handle.
    pub identity: FileIdentity,
}

/// Selection/root receipt returned after every required root was independently
/// opened, checked for current-user ownership and reparse substitution, and
/// rechecked after the complete set was acquired.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelectionReceipt {
    /// Exact selected profile.
    pub profile: ProfileSelection,
    /// Installation identity bound into the receipt.
    pub installation_id: String,
    /// Optional profile installation key bound into the receipt.
    pub installation_key: Option<String>,
    /// Component identity bound into the receipt.
    pub component: String,
    /// Version identity bound into the receipt.
    pub version: String,
    /// Generation identity bound into the receipt.
    pub generation: String,
    /// Approved authority descriptor selected for the generation.
    pub authority_descriptor_path: PathBuf,
    /// Digest of the exact descriptor bytes selected for the generation.
    pub authority_descriptor_sha256: String,
    /// Authority generation selected by the descriptor.
    pub authority_generation: u64,
    /// Current account SID proven as owner of every retained root.
    pub owner_sid: String,
    /// Current interactive session bound by the retained OS identity proof.
    pub session_id: u32,
    /// Distinct role-to-file-object observations for all requested roots.
    pub roots: Vec<ProfileRootObservation>,
}

/// Fixed Host action installed by the `UserMode` current-user launcher.
///
/// `bootstrap_arguments` must be the already-admitted, nonce-free
/// `HostLaunchOptions` argv tail; the adapter adds its private supervisor mode
/// switch and refuses any attempt to route this task through SCM.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentUserTaskRequest {
    /// Durable installation transaction that owns this planned registration.
    pub transaction_id: String,
    /// Stable effect ID from the immutable installation plan.
    pub effect_id: String,
    /// Descriptor-bound root request validated before task mutation.
    pub roots: ProfileRootRequest,
    /// Exact approved Host image path from `RuntimeLaunchDescriptor`.
    pub executable: PathBuf,
    /// Exact image digest from `RuntimeLaunchDescriptor`.
    pub executable_sha256: String,
    /// Exact Task Scheduler working directory, bound to immutable binaries.
    pub working_directory: PathBuf,
    /// Exact nonce-free Host bootstrap argv accepted by the current-user Host.
    pub bootstrap_arguments: Vec<String>,
}

impl CurrentUserTaskRequest {
    /// Computes the canonical SHA-256 binding for this exact retained request.
    ///
    /// Transaction owners use this when validating a persisted receipt or
    /// unknown outcome, so the stored digest is always recomputed from the
    /// complete request bytes.
    ///
    /// # Errors
    /// Returns `InvalidInput` if canonical request serialization fails.
    pub fn request_digest(&self) -> Result<String, WindowsAdapterError> {
        let canonical = serde_json::to_vec(self).map_err(|_| WindowsAdapterError::InvalidInput)?;
        Ok(crate::sha256_hex(&canonical))
    }
}

/// Task Scheduler registration/readback proof for one current-user Host task.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentUserTaskReceipt {
    /// SHA-256 of the exact canonical request bytes retained below.
    pub request_digest: String,
    /// Root/profile selection observation bound to task registration.
    pub selection: ProfileSelectionReceipt,
    /// Stable per-installation Task Scheduler path.
    pub task_name: String,
    /// Current-user account SID selected by Task Scheduler.
    pub sid: String,
    /// Interactive session in which registration was observed.
    pub session_id: u32,
    /// Exact canonical executable read back from the task action.
    pub executable: PathBuf,
    /// Exact immutable image digest verified before registration.
    pub executable_sha256: String,
    /// Exact working directory read back from the task action.
    pub working_directory: PathBuf,
    /// Exact argument vector, including the `UserMode` switch pair and bootstrap.
    pub arguments: Vec<String>,
    /// Digest of the exact Task Scheduler XML read back after registration.
    pub task_xml_sha256: String,
    /// Original exact descriptor-derived plan request, retained for restart
    /// readback and current-user root revalidation.
    pub request: CurrentUserTaskRequest,
}

/// One Task Scheduler launch acceptance, distinct from Host process readiness.
/// The engine PID belongs to Task Scheduler; Host must prove its executable
/// process through the existing authenticated runtime/process handshake.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentUserTaskRunReceipt {
    /// Task identity whose XML was checked immediately before `RunEx`.
    pub task_name: String,
    /// Exact current-user SID used by `RunEx`.
    pub sid: String,
    /// Interactive session used by `RunEx`.
    pub session_id: u32,
    /// Task Scheduler engine PID for the accepted run, not the Host action PID.
    pub engine_process_id: u32,
    /// XML digest bound to the accepted run request.
    pub task_xml_sha256: String,
}

/// Read-only Task Scheduler inspection after a restart. A `Matching` result
/// proves the exact planned action and XML digest currently read back; it does
/// not alone prove that this transaction created the task. The transaction
/// owner must join it to a persisted pre-effect absence observation or receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentUserTaskObservation {
    /// No task exists at the exact descriptor-derived identity.
    Absent {
        task_name: String,
        sid: String,
        session_id: u32,
    },
    /// The task's exact action/principal/trigger and XML readback match.
    Matching {
        task_xml_sha256: String,
        sid: String,
        session_id: u32,
        /// Complete exact current readback joined to the original request.
        ///
        /// Boxed for storage only: the readback carries the entire retained
        /// original request, and every field remains present and unaltered.
        receipt: Box<CurrentUserTaskReceipt>,
    },
    /// A task exists but its exact binding cannot be established.
    Mismatch {
        task_name: String,
        observed_xml_sha256: Option<String>,
        sid: String,
        session_id: u32,
    },
}

/// Task Scheduler command-line mode used only by the `UserMode` task action.
pub const USER_MODE_SUPERVISOR_SWITCH: &str = "--eliot-profile-supervisor";

/// Registration failure after task creation. If exact cleanup cannot be
/// confirmed, the request, task identity, and available XML digests remain
/// attached so the caller can surface and reconcile the committed task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurrentUserTaskRegistrationError {
    /// Registration was rejected or cleanup was confirmed.
    Rejected(WindowsAdapterError),
    /// Task creation committed but post-registration validation failed and
    /// exact deletion could not be confirmed.
    CleanupRequired {
        /// Boxed for storage only; the full committed receipt is retained.
        receipt: Box<CurrentUserTaskReceipt>,
        cause: WindowsAdapterError,
        cleanup_error: WindowsAdapterError,
    },
    /// Task creation committed before an exact registration receipt could be
    /// read back. The original request, intended XML digest and any observed
    /// XML digest are retained as an explicit reconciliation obligation.
    CommittedUnknown {
        /// Boxed for storage only; the exact original request is retained.
        request: Box<CurrentUserTaskRequest>,
        /// SHA-256 of the exact canonical request bytes.
        request_digest: String,
        task_name: String,
        requested_xml_sha256: String,
        observed_xml_sha256: Option<String>,
        cause: WindowsAdapterError,
        cleanup_error: WindowsAdapterError,
    },
}

impl std::fmt::Display for CurrentUserTaskRegistrationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(error) => error.fmt(formatter),
            Self::CleanupRequired {
                receipt,
                cause,
                cleanup_error,
            } => write!(
                formatter,
                "task registration needs cleanup for {} (XML SHA-256 {}) after {cause}; exact removal failed: {cleanup_error}",
                receipt.task_name, receipt.task_xml_sha256
            ),
            Self::CommittedUnknown {
                task_name,
                requested_xml_sha256,
                observed_xml_sha256,
                cause,
                cleanup_error,
                ..
            } => write!(
                formatter,
                "Task Scheduler committed {task_name} (requested XML SHA-256 {requested_xml_sha256}, observed XML SHA-256 {observed_xml_sha256:?}) but registration readback failed with {cause}; exact cleanup failed: {cleanup_error}"
            ),
        }
    }
}

impl std::error::Error for CurrentUserTaskRegistrationError {}

impl From<WindowsAdapterError> for CurrentUserTaskRegistrationError {
    fn from(error: WindowsAdapterError) -> Self {
        Self::Rejected(error)
    }
}

/// Registers a fixed, least-privilege current-user logon task for a validated
/// `UserMode` profile. All I3.1 roots remain retained and are rechecked across
/// Task Scheduler registration/readback.
///
/// # Errors
/// Returns a typed adapter error when the descriptor root binding is invalid,
/// the approved Host image is absent/substituted, the bootstrap is not the
/// exact nonce-free Host contract, or Task Scheduler readback differs.
pub fn register_current_user_task(
    request: &CurrentUserTaskRequest,
) -> Result<CurrentUserTaskReceipt, CurrentUserTaskRegistrationError> {
    if request.roots.profile != ProfileSelection::UserMode
        || !crate::valid_sha256_hex(&request.executable_sha256)
    {
        return Err(WindowsAdapterError::InvalidInput.into());
    }
    let retained_roots = open_profile_root_leases(&request.roots)?;
    let selection = retained_roots.selection.clone();
    validate_user_mode_bootstrap(request, &selection)?;
    let request_digest = current_user_task_request_digest(request)?;
    let (executable, root_lease) = retain_user_mode_host_image(request)?;

    let task_name = task_name_for_selection(&selection)?;
    let arguments = task_arguments(&request.bootstrap_arguments)?;
    let platform_receipt = match crate::platform_security::register_user_mode_profile_task(
        &crate::platform_security::UserModeProfileTaskSpec {
            task_name: task_name.clone(),
            transaction_id: request.transaction_id.clone(),
            effect_id: request.effect_id.clone(),
            installation_id: selection.installation_id.clone(),
            installation_key: selection
                .installation_key
                .clone()
                .ok_or(WindowsAdapterError::InvalidInput)?,
            component: selection.component.clone(),
            version: selection.version.clone(),
            generation: selection.generation.clone(),
            roots_digest: root_binding_digest(&selection),
            executable: executable.clone(),
            executable_sha256: request.executable_sha256.clone(),
            working_directory: request.working_directory.clone(),
            arguments,
            expected_sid: selection.owner_sid.clone(),
            expected_session_id: selection.session_id,
        },
    ) {
        Ok(receipt) => receipt,
        Err(crate::platform_security::UserModeProfileTaskRegistrationError::Rejected(error)) => {
            return Err(error.into());
        }
        Err(crate::platform_security::UserModeProfileTaskRegistrationError::CleanupRequired(
            unknown,
        )) => {
            return Err(CurrentUserTaskRegistrationError::CommittedUnknown {
                request: Box::new(request.clone()),
                request_digest,
                task_name: unknown.task_name,
                requested_xml_sha256: unknown.requested_xml_sha256,
                observed_xml_sha256: unknown.observed_xml_sha256,
                cause: unknown.cause,
                cleanup_error: unknown.cleanup_error,
            });
        }
    };
    let task_receipt = current_user_task_receipt(
        request.clone(),
        request_digest,
        selection.clone(),
        executable.clone(),
        &platform_receipt,
    );
    if retained_roots.verify_stable_identity().is_err() {
        return Err(cleanup_after_registration(
            task_receipt,
            WindowsAdapterError::IdentityMismatch,
        ));
    }
    let revalidated = match retain_profile_roots(&request.roots) {
        Ok(roots) => roots,
        Err(error) => {
            return Err(cleanup_after_registration(task_receipt, error));
        }
    };
    if revalidated.selection != selection
        || revalidated.verify_stable_identity().is_err()
        || root_lease.verify_stable_identity().is_err()
    {
        return Err(cleanup_after_registration(
            task_receipt,
            WindowsAdapterError::IdentityMismatch,
        ));
    }
    Ok(task_receipt)
}

/// Validates and retains the exact approved Host image, its immutable-binaries
/// parent lease, and the digest-bound authority descriptor below that same root.
fn retain_user_mode_host_image(
    request: &CurrentUserTaskRequest,
) -> Result<(PathBuf, UserOwnedRootLease), WindowsAdapterError> {
    let executable =
        crate::validate_pinned_artifact(&request.executable, &request.executable_sha256)?;
    let immutable_root = &request.roots.roots.immutable_binaries;
    if !executable
        .parent()
        .is_some_and(|parent| crate::windows_paths_equal(parent, immutable_root))
        || !executable
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("eliot-host.exe"))
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    if !crate::windows_paths_equal(&request.working_directory, immutable_root) {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let root_lease = UserOwnedRootLease::open_existing(immutable_root)
        .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
    root_lease
        .validate_child_parent(&executable)
        .and_then(|()| root_lease.verify_stable_identity())
        .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
    let descriptor = crate::validate_pinned_artifact(
        &request.roots.authority_descriptor_path,
        &request.roots.authority_descriptor_sha256,
    )?;
    if !crate::windows_paths_equal(&descriptor, &request.roots.authority_descriptor_path)
        || !descriptor
            .parent()
            .is_some_and(|parent| crate::windows_paths_equal(parent, immutable_root))
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok((executable, root_lease))
}

fn current_user_task_receipt(
    request: CurrentUserTaskRequest,
    request_digest: String,
    selection: ProfileSelectionReceipt,
    executable: PathBuf,
    platform: &crate::platform_security::UserModeProfileTaskReceipt,
) -> CurrentUserTaskReceipt {
    CurrentUserTaskReceipt {
        request_digest,
        selection,
        task_name: platform.task_name.clone(),
        sid: platform.sid.clone(),
        session_id: platform.session_id,
        executable,
        executable_sha256: request.executable_sha256.clone(),
        working_directory: platform.working_directory.clone(),
        arguments: request.bootstrap_arguments.clone(),
        task_xml_sha256: platform.task_xml_sha256.clone(),
        request,
    }
}

fn current_user_task_request_digest(
    request: &CurrentUserTaskRequest,
) -> Result<String, WindowsAdapterError> {
    request.request_digest()
}

fn cleanup_after_registration(
    receipt: CurrentUserTaskReceipt,
    cause: WindowsAdapterError,
) -> CurrentUserTaskRegistrationError {
    match remove_current_user_task(&receipt) {
        Ok(()) => CurrentUserTaskRegistrationError::Rejected(cause),
        Err(cleanup_error) => CurrentUserTaskRegistrationError::CleanupRequired {
            receipt: Box::new(receipt),
            cause,
            cleanup_error,
        },
    }
}

/// Starts only the exact task recorded by a live registration receipt and
/// returns a bounded Task Scheduler engine state/PID observation. The Host
/// executable must be admitted through its authenticated runtime/process
/// handshake before it can be described as live.
///
/// # Errors
/// Returns a typed adapter error when current-user identity or exact XML
/// readback differs, Task Scheduler refuses the run, or no running PID can be
/// read back.
pub fn run_current_user_task(
    receipt: &CurrentUserTaskReceipt,
) -> Result<CurrentUserTaskRunReceipt, WindowsAdapterError> {
    let retained_roots = open_profile_root_leases(&receipt.request.roots)?;
    if !same_selection_except_session(&receipt.selection, &retained_roots.selection) {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let platform = platform_task_receipt(receipt, &retained_roots.selection)?;
    let run = crate::platform_security::run_user_mode_profile_task(&platform)?;
    retained_roots.verify_stable_identity()?;
    Ok(CurrentUserTaskRunReceipt {
        task_name: run.task_name,
        sid: run.sid,
        session_id: run.session_id,
        engine_process_id: run.engine_process_id,
        task_xml_sha256: run.task_xml_sha256,
    })
}

/// Deletes only the exact task whose name, action and XML digest still match
/// the registration receipt.
///
/// # Errors
/// Returns a typed adapter error when ownership, task readback or the cleanup
/// postcondition cannot be proved.
pub fn remove_current_user_task(
    receipt: &CurrentUserTaskReceipt,
) -> Result<(), WindowsAdapterError> {
    let retained_roots = open_profile_root_leases(&receipt.request.roots)?;
    if !same_selection_except_session(&receipt.selection, &retained_roots.selection) {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let platform = platform_task_receipt(receipt, &retained_roots.selection)?;
    crate::platform_security::unregister_user_mode_profile_task(&platform)?;
    retained_roots.verify_stable_identity()
}

/// Inspects the exact task requested by a committed `UserMode` installation
/// effect. A supplied receipt additionally binds the observed XML digest to a
/// previously persisted postcondition.
///
/// # Errors
/// Returns an adapter error when current-user identity or descriptor-root
/// proof cannot be re-established, or Task Scheduler cannot be queried.
pub fn inspect_current_user_task(
    request: &CurrentUserTaskRequest,
    expected_receipt: Option<&CurrentUserTaskReceipt>,
) -> Result<CurrentUserTaskObservation, WindowsAdapterError> {
    if request.roots.profile != ProfileSelection::UserMode
        || !crate::valid_sha256_hex(&request.executable_sha256)
        || !crate::windows_paths_equal(
            &request.working_directory,
            &request.roots.roots.immutable_binaries,
        )
    {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let request_digest = current_user_task_request_digest(request)?;
    let retained_roots = open_profile_root_leases(&request.roots)?;
    let selection = retained_roots.selection.clone();
    validate_user_mode_bootstrap(request, &selection)?;
    let executable =
        crate::validate_pinned_artifact(&request.executable, &request.executable_sha256)?;
    if !executable
        .parent()
        .is_some_and(|parent| crate::windows_paths_equal(parent, &request.working_directory))
        || !executable
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("eliot-host.exe"))
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let task_name = task_name_for_selection(&selection)?;
    let spec = platform_task_spec(request, &selection, executable.clone())?;
    if let Some(receipt) = expected_receipt
        && (receipt.request != *request
            || receipt.request_digest != request_digest
            || !same_selection_except_session(&receipt.selection, &selection)
            || receipt.task_name != task_name
            || receipt.executable != executable
            || receipt.executable_sha256 != request.executable_sha256
            || receipt.working_directory != request.working_directory
            || receipt.arguments != request.bootstrap_arguments
            || receipt.sid != selection.owner_sid
            || receipt.session_id == 0)
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let observed = crate::platform_security::inspect_user_mode_profile_task(&spec)?;
    retained_roots.verify_stable_identity()?;
    let Some(observed) = observed else {
        return Ok(CurrentUserTaskObservation::Absent {
            task_name,
            sid: selection.owner_sid,
            session_id: selection.session_id,
        });
    };
    let observed_digest = observed.task_xml_sha256;
    if observed.matches_request
        && expected_receipt.is_none_or(|receipt| observed_digest == receipt.task_xml_sha256)
    {
        let receipt = CurrentUserTaskReceipt {
            request_digest,
            selection: selection.clone(),
            task_name,
            sid: selection.owner_sid.clone(),
            session_id: selection.session_id,
            executable,
            executable_sha256: request.executable_sha256.clone(),
            working_directory: request.working_directory.clone(),
            arguments: request.bootstrap_arguments.clone(),
            task_xml_sha256: observed_digest.clone(),
            request: request.clone(),
        };
        platform_task_receipt(&receipt, &selection)?;
        return Ok(CurrentUserTaskObservation::Matching {
            task_xml_sha256: observed_digest,
            sid: selection.owner_sid,
            session_id: selection.session_id,
            receipt: Box::new(receipt),
        });
    }
    Ok(CurrentUserTaskObservation::Mismatch {
        task_name,
        observed_xml_sha256: Some(observed_digest),
        sid: selection.owner_sid,
        session_id: selection.session_id,
    })
}

fn platform_task_receipt(
    receipt: &CurrentUserTaskReceipt,
    current_selection: &ProfileSelectionReceipt,
) -> Result<crate::platform_security::UserModeProfileTaskReceipt, WindowsAdapterError> {
    if receipt.request.roots.profile != ProfileSelection::UserMode
        || receipt.selection.profile != ProfileSelection::UserMode
        || !same_selection_except_session(&receipt.selection, current_selection)
        || receipt.request_digest != current_user_task_request_digest(&receipt.request)?
        || !crate::valid_sha256_hex(&receipt.task_xml_sha256)
        || receipt.request.executable_sha256 != receipt.executable_sha256
        || receipt.request.working_directory != receipt.working_directory
        || receipt.request.bootstrap_arguments != receipt.arguments
        || receipt.task_name != task_name_for_selection(&receipt.selection)?
        || receipt.sid != current_selection.owner_sid
        || receipt.session_id == 0
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(crate::platform_security::UserModeProfileTaskReceipt {
        task_name: receipt.task_name.clone(),
        transaction_id: receipt.request.transaction_id.clone(),
        effect_id: receipt.request.effect_id.clone(),
        installation_id: receipt.selection.installation_id.clone(),
        installation_key: receipt
            .selection
            .installation_key
            .clone()
            .ok_or(WindowsAdapterError::InvalidInput)?,
        component: receipt.selection.component.clone(),
        version: receipt.selection.version.clone(),
        generation: receipt.selection.generation.clone(),
        roots_digest: root_binding_digest(current_selection),
        executable: receipt.executable.clone(),
        executable_sha256: receipt.executable_sha256.clone(),
        working_directory: receipt.working_directory.clone(),
        arguments: task_arguments(&receipt.arguments)?,
        sid: current_selection.owner_sid.clone(),
        session_id: current_selection.session_id,
        task_xml_sha256: receipt.task_xml_sha256.clone(),
    })
}

fn same_selection_except_session(
    registered: &ProfileSelectionReceipt,
    current: &ProfileSelectionReceipt,
) -> bool {
    registered.profile == current.profile
        && registered.installation_id == current.installation_id
        && registered.installation_key == current.installation_key
        && registered.component == current.component
        && registered.version == current.version
        && registered.generation == current.generation
        && registered.authority_descriptor_path == current.authority_descriptor_path
        && registered.authority_descriptor_sha256 == current.authority_descriptor_sha256
        && registered.authority_generation == current.authority_generation
        && registered.owner_sid == current.owner_sid
        && registered.session_id != 0
        && current.session_id != 0
        && registered.roots == current.roots
}

/// Revalidates the descriptor-bound `UserMode` or `PortableDev` roots against the
/// current OS identity and returns every role's file-object identity.
///
/// # Errors
/// Returns a typed adapter error when the profile anchor, role separation,
/// current-user SID, root ownership, path identity, or reparse proof fails.
pub fn validate_profile_roots(
    request: &ProfileRootRequest,
) -> Result<ProfileSelectionReceipt, WindowsAdapterError> {
    Ok(open_profile_root_leases(request)?.selection.clone())
}

/// Live current-user root handles retained for one Host composition.
/// The exact descriptor-derived selection receipt and all no-follow leases
/// remain bound until this value is dropped.
pub struct ProfileRootLeaseSet {
    selection: ProfileSelectionReceipt,
    leases: Vec<UserOwnedRootLease>,
    local_app_data: Option<crate::platform_security::CurrentUserLocalAppDataRootLease>,
}

impl ProfileRootLeaseSet {
    /// Returns the exact profile/root observations bound by the retained leases.
    #[must_use]
    pub fn selection(&self) -> &ProfileSelectionReceipt {
        &self.selection
    }

    /// Rechecks every retained file-object identity and its declared path
    /// before a production use.
    ///
    /// # Errors
    /// Returns `IdentityMismatch` when any pinned object changed or became
    /// unreadable.
    pub fn verify_stable_identity(&self) -> Result<(), WindowsAdapterError> {
        for lease in &self.leases {
            lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        }
        if let Some(anchor) = &self.local_app_data {
            anchor
                .verify_stable_identity()
                .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        }
        Ok(())
    }
}

/// Opens and retains a profile's complete descriptor-bound current-user root
/// set for a Host or installer operation.
pub fn open_profile_root_leases(
    request: &ProfileRootRequest,
) -> Result<ProfileRootLeaseSet, WindowsAdapterError> {
    let retained = retain_profile_roots(request)?;
    Ok(ProfileRootLeaseSet {
        selection: retained.selection,
        leases: retained.leases,
        local_app_data: retained.local_app_data,
    })
}

struct RetainedProfileRoots {
    selection: ProfileSelectionReceipt,
    leases: Vec<UserOwnedRootLease>,
    local_app_data: Option<crate::platform_security::CurrentUserLocalAppDataRootLease>,
}

impl RetainedProfileRoots {
    fn verify_stable_identity(&self) -> Result<(), WindowsAdapterError> {
        for lease in &self.leases {
            lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        }
        if let Some(anchor) = &self.local_app_data {
            anchor
                .verify_stable_identity()
                .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        }
        Ok(())
    }
}

fn retain_profile_roots(
    request: &ProfileRootRequest,
) -> Result<RetainedProfileRoots, WindowsAdapterError> {
    validate_request_shape(request)?;

    let local_app_data = if request.profile == ProfileSelection::UserMode {
        Some(
            crate::current_user_local_app_data_root()
                .map_err(|_| WindowsAdapterError::Unavailable)?,
        )
    } else {
        None
    };
    let repository = match request.profile {
        ProfileSelection::UserMode => {
            if request.repository_root.is_some() {
                return Err(WindowsAdapterError::InvalidInput);
            }
            validate_user_mode_layout(
                request,
                // `local_app_data` is `Some` exactly for `ProfileSelection::UserMode`,
                // which is the arm that reaches this point. The `ok_or` keeps the
                // invariant explicit without panicking on a platform anchor that
                // could never be absent here.
                local_app_data
                    .as_deref()
                    .ok_or(WindowsAdapterError::Unavailable)?,
            )?;
            None
        }
        ProfileSelection::PortableDev => {
            let repository = request
                .repository_root
                .as_deref()
                .ok_or(WindowsAdapterError::InvalidInput)?;
            if !repository.is_absolute() || request.installation_key.is_some() {
                return Err(WindowsAdapterError::InvalidInput);
            }
            validate_portable_layout(request, repository)?;
            Some(open_user_root(repository)?)
        }
    };

    let root_requests = profile_role_requests(request);

    let repository_path = repository.as_ref().map(|lease| lease.path().to_path_buf());
    let repository_identity = repository.as_ref().map(UserOwnedRootLease::identity);
    let repository_sid = repository
        .as_ref()
        .map(|lease| lease.current_user_sid().to_owned());
    let mut leases = Vec::with_capacity(root_requests.len() + usize::from(repository.is_some()));
    if let Some(repository) = repository {
        leases.push(repository);
    }
    let mut observations = Vec::with_capacity(root_requests.len());
    let mut owner_sid = repository_sid;
    let local_app_data_lease = if request.profile == ProfileSelection::UserMode {
        Some(
            crate::platform_security::retain_current_user_local_app_data_root()
                .map_err(|_| WindowsAdapterError::IdentityMismatch)?,
        )
    } else {
        None
    };
    let mut session_id = None;
    if let Some(anchor) = &local_app_data_lease {
        if local_app_data
            .as_deref()
            .is_none_or(|expected| !crate::windows_paths_equal(anchor.path(), expected))
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let sid = anchor.current_user_sid();
        if owner_sid.as_deref().is_some_and(|expected| expected != sid) {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        owner_sid = Some(sid.to_owned());
        session_id = Some(anchor.session_id());
    }
    let mut role_roots = retain_role_roots(
        request.profile,
        root_requests,
        local_app_data.as_deref(),
        local_app_data_lease.as_ref(),
        repository_path.as_deref(),
        repository_identity,
        owner_sid,
    )?;
    observations.append(&mut role_roots.observations);
    leases.append(&mut role_roots.leases);
    finish_profile_selection(
        request,
        observations,
        leases,
        local_app_data_lease,
        role_roots.owner_sid,
        session_id,
    )
}

/// Projects the four fixed profile root roles plus every runtime state root,
/// preserving the descriptor's role names as the observation keys.
fn profile_role_requests(request: &ProfileRootRequest) -> Vec<(String, PathBuf)> {
    let mut root_requests = vec![
        (
            "immutable_binaries".to_owned(),
            request.roots.immutable_binaries.clone(),
        ),
        (
            "durable_data".to_owned(),
            request.roots.durable_data.clone(),
        ),
        ("user_config".to_owned(), request.roots.user_config.clone()),
        ("user_cache".to_owned(), request.roots.user_cache.clone()),
    ];
    root_requests.extend(request.roots.runtime_state_roots.iter().cloned());
    root_requests
}

/// The observations, retained leases, and single observed owner SID produced by
/// one pass over the profile's non-anchor role roots.
struct RetainedRoleRoots {
    observations: Vec<ProfileRootObservation>,
    leases: Vec<UserOwnedRootLease>,
    owner_sid: Option<String>,
}

/// Opens and retains every non-anchor profile role root, observing the exact
/// current-user owner SID that binds them all together.
fn retain_role_roots(
    profile: ProfileSelection,
    root_requests: Vec<(String, PathBuf)>,
    local_app_data: Option<&Path>,
    local_app_data_lease: Option<&crate::platform_security::CurrentUserLocalAppDataRootLease>,
    repository_path: Option<&Path>,
    repository_identity: Option<FileIdentity>,
    mut owner_sid: Option<String>,
) -> Result<RetainedRoleRoots, WindowsAdapterError> {
    let mut observations = Vec::with_capacity(root_requests.len());
    let mut leases = Vec::new();
    for (role, path) in root_requests {
        if role == "runtime_state_roots.profile_anchor_root" {
            let expected_anchor = match profile {
                ProfileSelection::UserMode => local_app_data,
                ProfileSelection::PortableDev => repository_path,
            }
            .ok_or(WindowsAdapterError::IdentityMismatch)?;
            if !crate::windows_paths_equal(&path, expected_anchor) {
                return Err(WindowsAdapterError::IdentityMismatch);
            }
            observations.push(ProfileRootObservation {
                role,
                canonical_path: local_app_data_lease.map_or_else(
                    || expected_anchor.to_path_buf(),
                    |lease| lease.path().to_path_buf(),
                ),
                identity: repository_identity
                    .or_else(|| {
                        local_app_data_lease.map(
                            crate::platform_security::CurrentUserLocalAppDataRootLease::identity,
                        )
                    })
                    .ok_or(WindowsAdapterError::IdentityMismatch)?,
            });
            continue;
        }
        let lease = open_user_root(&path)?;
        if let Some(repository) = repository_path
            && !is_contained_by(repository, lease.path())
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        if let Some(expected_sid) = owner_sid.as_deref() {
            if lease.current_user_sid() != expected_sid {
                return Err(WindowsAdapterError::IdentityMismatch);
            }
        } else {
            owner_sid = Some(lease.current_user_sid().to_owned());
        }
        observations.push(ProfileRootObservation {
            role,
            canonical_path: lease
                .canonical_path()
                .map_err(|_| WindowsAdapterError::Unavailable)?,
            identity: lease.identity(),
        });
        leases.push(lease);
    }
    Ok(RetainedRoleRoots {
        observations,
        leases,
        owner_sid,
    })
}

/// Proves the complete postcondition of a retained profile root set and builds
/// the selection receipt bound to the current process identity.
fn finish_profile_selection(
    request: &ProfileRootRequest,
    observations: Vec<ProfileRootObservation>,
    leases: Vec<UserOwnedRootLease>,
    local_app_data_lease: Option<crate::platform_security::CurrentUserLocalAppDataRootLease>,
    mut owner_sid: Option<String>,
    session_id: Option<u32>,
) -> Result<RetainedProfileRoots, WindowsAdapterError> {
    if observations.len() != 13 || !validate_role_paths(&observations) {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    for lease in &leases {
        lease
            .verify_stable_identity()
            .and_then(|()| lease.verify_path_identity())
            .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
    }
    let current = crate::current_process_named_pipe_expectation()?;
    if owner_sid
        .as_deref()
        .is_some_and(|sid| sid != current.expected_sid())
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    owner_sid = Some(current.expected_sid().to_owned());
    if session_id.is_some_and(|session| session != current.expected_session_id()) {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let session_id = current.expected_session_id();
    if let Some(anchor) = &local_app_data_lease {
        anchor
            .verify_stable_identity()
            .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
    }
    let owner_sid = owner_sid.ok_or(WindowsAdapterError::IdentityMismatch)?;
    let selection = ProfileSelectionReceipt {
        profile: request.profile,
        installation_id: request.installation_id.clone(),
        installation_key: request.installation_key.clone(),
        component: request.component.clone(),
        version: request.version.clone(),
        generation: request.generation.clone(),
        authority_descriptor_path: request.authority_descriptor_path.clone(),
        authority_descriptor_sha256: request.authority_descriptor_sha256.clone(),
        authority_generation: request.authority_generation,
        owner_sid,
        session_id,
        roots: observations,
    };
    Ok(RetainedProfileRoots {
        selection,
        leases,
        local_app_data: local_app_data_lease,
    })
}

fn validate_user_mode_bootstrap(
    request: &CurrentUserTaskRequest,
    selection: &ProfileSelectionReceipt,
) -> Result<(), WindowsAdapterError> {
    let arguments = &request.bootstrap_arguments;
    if arguments.len() != 10
        || arguments
            .iter()
            .any(|argument| argument == USER_MODE_SUPERVISOR_SWITCH)
        || arguments[0] != "--config-descriptor"
        || arguments[2] != "--config-descriptor-sha256"
        || arguments[4] != "--installation-id"
        || arguments[6] != "--tx-plan-generation"
        || arguments[8] != "--host-state-root"
        || arguments[5] != selection.installation_id
        || !crate::windows_paths_equal(
            Path::new(&arguments[1]),
            &request.roots.authority_descriptor_path,
        )
        || arguments[3] != request.roots.authority_descriptor_sha256
        || arguments[7] != request.roots.authority_generation.to_string()
        || !Path::new(&arguments[9]).is_absolute()
        || !selection.roots.iter().any(|root| {
            root.role == "runtime_state_roots.host_state_root"
                && crate::windows_paths_equal(&root.canonical_path, Path::new(&arguments[9]))
        })
        || arguments
            .iter()
            .any(|argument| argument == "--registration-nonce")
    {
        return Err(WindowsAdapterError::InvalidInput);
    }
    Ok(())
}

fn task_name_for_selection(
    selection: &ProfileSelectionReceipt,
) -> Result<String, WindowsAdapterError> {
    let key = selection
        .installation_key
        .as_deref()
        .ok_or(WindowsAdapterError::InvalidInput)?;
    let task_key = crate::sha256_hex(format!("{}\0{key}", selection.installation_id).as_bytes());
    Ok(format!(r"\Eliot\UserMode\{task_key}"))
}

fn root_binding_digest(selection: &ProfileSelectionReceipt) -> String {
    use std::fmt::Write as _;
    let mut binding = format!(
        "{:?}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\n",
        selection.profile,
        selection.installation_id,
        selection.installation_key.as_deref().unwrap_or_default(),
        selection.component,
        selection.version,
        selection.generation,
        selection.authority_descriptor_path.display(),
        selection.authority_descriptor_sha256,
    );
    let _ = writeln!(binding, "{}", selection.authority_generation);
    for root in &selection.roots {
        let _ = writeln!(
            binding,
            "{}\0{}\0{}\0{}",
            root.role,
            root.canonical_path.display(),
            root.identity.volume_serial_number,
            root.identity.file_index
        );
    }
    crate::sha256_hex(binding.as_bytes())
}

fn task_arguments(arguments: &[String]) -> Result<String, WindowsAdapterError> {
    if arguments
        .iter()
        .any(|argument| argument == USER_MODE_SUPERVISOR_SWITCH)
    {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let mut encoded = Vec::with_capacity(arguments.len() + 1);
    encoded.push(quote_windows_argument(USER_MODE_SUPERVISOR_SWITCH));
    encoded.push("user_mode".to_owned());
    for argument in arguments {
        if argument.chars().any(char::is_control) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        encoded.push(quote_windows_argument(argument));
    }
    Ok(encoded.join(" "))
}

fn platform_task_spec(
    request: &CurrentUserTaskRequest,
    selection: &ProfileSelectionReceipt,
    executable: PathBuf,
) -> Result<crate::platform_security::UserModeProfileTaskSpec, WindowsAdapterError> {
    Ok(crate::platform_security::UserModeProfileTaskSpec {
        task_name: task_name_for_selection(selection)?,
        transaction_id: request.transaction_id.clone(),
        effect_id: request.effect_id.clone(),
        installation_id: selection.installation_id.clone(),
        installation_key: selection
            .installation_key
            .clone()
            .ok_or(WindowsAdapterError::InvalidInput)?,
        component: selection.component.clone(),
        version: selection.version.clone(),
        generation: selection.generation.clone(),
        roots_digest: root_binding_digest(selection),
        executable,
        executable_sha256: request.executable_sha256.clone(),
        working_directory: request.working_directory.clone(),
        arguments: task_arguments(&request.bootstrap_arguments)?,
        expected_sid: selection.owner_sid.clone(),
        expected_session_id: selection.session_id,
    })
}

fn quote_windows_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return argument.to_owned();
    }
    let mut quoted = String::from("\"");
    let mut slashes = 0usize;
    for character in argument.chars() {
        match character {
            '\\' => slashes = slashes.saturating_add(1),
            '"' => {
                quoted.push_str(&"\\".repeat(slashes.saturating_mul(2).saturating_add(1)));
                quoted.push('"');
                slashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(slashes));
                quoted.push(character);
                slashes = 0;
            }
        }
    }
    quoted.push_str(&"\\".repeat(slashes.saturating_mul(2)));
    quoted.push('"');
    quoted
}

fn validate_request_shape(request: &ProfileRootRequest) -> Result<(), WindowsAdapterError> {
    let identities = [
        request.installation_id.as_str(),
        request.component.as_str(),
        request.version.as_str(),
        request.generation.as_str(),
    ];
    if identities.iter().any(|value| !valid_path_segment(value))
        || request
            .installation_key
            .as_deref()
            .is_some_and(|value| !is_lower_sha256(value))
        || !has_exact_runtime_root_roles(&request.roots.runtime_state_roots)
        || !request.authority_descriptor_path.is_absolute()
        || !is_lower_sha256(&request.authority_descriptor_sha256)
        || request.authority_generation == 0
        || [
            &request.roots.immutable_binaries,
            &request.roots.durable_data,
            &request.roots.user_config,
            &request.roots.user_cache,
        ]
        .iter()
        .any(|path| !path.is_absolute())
    {
        return Err(WindowsAdapterError::InvalidInput);
    }
    if !request
        .authority_descriptor_path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("authority.json"))
        || !request
            .authority_descriptor_path
            .parent()
            .is_some_and(|parent| {
                crate::windows_paths_equal(parent, &request.roots.immutable_binaries)
            })
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(())
}

fn validate_user_mode_layout(
    request: &ProfileRootRequest,
    local_app_data: &Path,
) -> Result<(), WindowsAdapterError> {
    let expected_binaries = local_app_data
        .join("Programs")
        .join("Eliot")
        .join(&request.component)
        .join(&request.version);
    let expected_data = local_app_data.join("Eliot").join("data");
    let expected_config = local_app_data.join("Eliot").join("config");
    let expected_cache = local_app_data.join("Eliot").join("cache");
    let expected_installation = local_app_data.join("Eliot").join("installations").join(
        request
            .installation_key
            .as_deref()
            .ok_or(WindowsAdapterError::InvalidInput)?,
    );
    if !crate::windows_paths_equal(&request.roots.immutable_binaries, &expected_binaries)
        || !crate::windows_paths_equal(&request.roots.durable_data, &expected_data)
        || !crate::windows_paths_equal(&request.roots.user_config, &expected_config)
        || !crate::windows_paths_equal(&request.roots.user_cache, &expected_cache)
        || !runtime_root_matches(
            request,
            "runtime_state_roots.installation_root",
            &expected_installation,
        )
        || !runtime_root_matches(
            request,
            "runtime_state_roots.host_state_root",
            &expected_installation.join("host"),
        )
        || !runtime_root_matches(
            request,
            "runtime_state_roots.kernel_ors_root",
            &expected_installation.join("kernel").join("state"),
        )
        || !runtime_root_matches(
            request,
            "runtime_state_roots.kernel_work_root",
            &expected_installation.join("kernel").join("work"),
        )
        || !runtime_root_matches(
            request,
            "runtime_state_roots.store_data_root",
            &expected_installation.join("store").join("data"),
        )
        || !runtime_root_matches(
            request,
            "runtime_state_roots.store_work_root",
            &expected_installation.join("store").join("work"),
        )
        || !runtime_root_matches(
            request,
            "runtime_state_roots.store_temp_root",
            &expected_installation.join("store").join("tmp"),
        )
        || !runtime_root_matches(
            request,
            "runtime_state_roots.watchdog_state_root",
            &expected_installation.join("watchdog"),
        )
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(())
}

fn validate_portable_layout(
    request: &ProfileRootRequest,
    repository: &Path,
) -> Result<(), WindowsAdapterError> {
    let expected_binaries = repository
        .join("target")
        .join("eliot-dev")
        .join(&request.generation);
    let expected_state = repository.join(".eliot-dev").join("state");
    let expected_config = repository.join(".eliot-dev").join("config");
    let expected_cache = repository.join(".eliot-dev").join("cache");
    let installation_root = request
        .roots
        .runtime_state_roots
        .iter()
        .find(|(role, _)| role == "runtime_state_roots.installation_root")
        .map(|(_, path)| path)
        .ok_or(WindowsAdapterError::InvalidInput)?;
    let expected_runtime_roots = [
        (
            "runtime_state_roots.profile_anchor_root",
            repository.to_path_buf(),
        ),
        (
            "runtime_state_roots.installation_root",
            repository.to_path_buf(),
        ),
        (
            "runtime_state_roots.host_state_root",
            repository.join("host"),
        ),
        (
            "runtime_state_roots.kernel_ors_root",
            repository.join("kernel").join("state"),
        ),
        (
            "runtime_state_roots.kernel_work_root",
            repository.join("kernel").join("work"),
        ),
        (
            "runtime_state_roots.store_data_root",
            repository.join("store").join("data"),
        ),
        (
            "runtime_state_roots.store_work_root",
            repository.join("store").join("work"),
        ),
        (
            "runtime_state_roots.store_temp_root",
            repository.join("store").join("tmp"),
        ),
        (
            "runtime_state_roots.watchdog_state_root",
            repository.join("watchdog"),
        ),
    ];
    if !crate::windows_paths_equal(&request.roots.immutable_binaries, &expected_binaries)
        || !crate::windows_paths_equal(&request.roots.durable_data, &expected_state)
        || !crate::windows_paths_equal(&request.roots.user_config, &expected_config)
        || !crate::windows_paths_equal(&request.roots.user_cache, &expected_cache)
        || !crate::windows_paths_equal(installation_root, repository)
        || expected_runtime_roots
            .iter()
            .any(|(role, expected)| !runtime_root_matches(request, role, expected))
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(())
}

fn runtime_root_matches(request: &ProfileRootRequest, role: &str, expected: &Path) -> bool {
    request
        .roots
        .runtime_state_roots
        .iter()
        .find(|(candidate, _)| candidate == role)
        .is_some_and(|(_, path)| crate::windows_paths_equal(path, expected))
}

fn open_user_root(path: &Path) -> Result<UserOwnedRootLease, WindowsAdapterError> {
    let lease = UserOwnedRootLease::open_existing(path)
        .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
    lease
        .verify_stable_identity()
        .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
    Ok(lease)
}

fn valid_path_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_contained_by(root: &Path, path: &Path) -> bool {
    path.ancestors()
        .any(|ancestor| crate::windows_paths_equal(root, ancestor))
}

fn has_exact_runtime_root_roles(roots: &[(String, PathBuf)]) -> bool {
    const REQUIRED: [&str; 9] = [
        "runtime_state_roots.profile_anchor_root",
        "runtime_state_roots.installation_root",
        "runtime_state_roots.host_state_root",
        "runtime_state_roots.kernel_ors_root",
        "runtime_state_roots.kernel_work_root",
        "runtime_state_roots.store_data_root",
        "runtime_state_roots.store_work_root",
        "runtime_state_roots.store_temp_root",
        "runtime_state_roots.watchdog_state_root",
    ];
    let mut roles = std::collections::BTreeSet::new();
    for (role, path) in roots {
        if !REQUIRED.contains(&role.as_str()) || !roles.insert(role.as_str()) || !path.is_absolute()
        {
            return false;
        }
    }
    roles.len() == REQUIRED.len() && REQUIRED.iter().all(|role| roles.contains(role))
}

fn validate_role_paths(roots: &[ProfileRootObservation]) -> bool {
    let required_profile_roots = [
        "immutable_binaries",
        "durable_data",
        "user_config",
        "user_cache",
    ];
    let mut profile_paths = Vec::with_capacity(required_profile_roots.len());
    let mut roles = std::collections::BTreeSet::new();
    for root in roots {
        if !roles.insert(root.role.as_str()) {
            return false;
        }
        if required_profile_roots.contains(&root.role.as_str()) {
            profile_paths.push(root.canonical_path.as_path());
        }
    }
    if profile_paths.len() != required_profile_roots.len() {
        return false;
    }
    for left in 0..profile_paths.len() {
        for right in left + 1..profile_paths.len() {
            if crate::windows_paths_equal(profile_paths[left], profile_paths[right])
                || is_contained_by(profile_paths[left], profile_paths[right])
                || is_contained_by(profile_paths[right], profile_paths[left])
            {
                return false;
            }
        }
    }
    let expected_all = required_profile_roots.len() + 9;
    roles.len() == expected_all
}
