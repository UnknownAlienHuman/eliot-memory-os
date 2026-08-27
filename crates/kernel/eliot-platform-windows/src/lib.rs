//! Concrete Windows adapters for the P-01 platform ports.
//!
//! Windows implementation details are deliberately kept behind this facade.
//! Public values expose only provider-neutral P-01 results and typed P-02
//! mechanics evidence. Raw handles, provider records, secret bytes, and Win32
//! implementation details never escape this crate.

#![deny(unsafe_op_in_unsafe_fn)]
// Non-Windows builds retain the public typed-unavailability surface while the
// private Win32 mechanisms are intentionally unreachable. Keep dead-code
// enforcement strict on Windows, where those mechanisms must remain live.
#![cfg_attr(not(windows), allow(dead_code))]
#![cfg_attr(
    not(windows),
    allow(
        clippy::needless_return,
        clippy::unnecessary_wraps,
        clippy::unused_self
    )
)]

#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_platform::{
    AdapterPathInput, ClockPort, ClockRequest, FileKind, FilesystemObservation,
    FilesystemOperation, FilesystemPort, InstallationObservation, InstallationOperation,
    InstallationPort, InstallationRequest, InstallationState, NotificationObservation,
    NotificationPort, NotificationRequest, PlatformHandle, PortError, PortOutcome, SecretPort,
    SecretRequest, ServiceObservation, ServiceOperation, ServicePort, ServiceRequest, ServiceState,
    SessionObservation, SessionPort, SessionRequest, UnknownReason, WorkScopePath,
};
use sha2::{Digest, Sha256};

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static TEST_PROTECTED_ROOT: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}

/// Explicit test-only controls for exercising the production retained-path
/// and post-commit-unknown branches without changing the default graph.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use std::path::{Path, PathBuf};

    /// Restores the previous protected-root override when dropped.
    pub struct ProtectedRootOverride {
        previous: Option<PathBuf>,
    }

    impl Drop for ProtectedRootOverride {
        fn drop(&mut self) {
            super::TEST_PROTECTED_ROOT.with(|slot| {
                slot.replace(self.previous.take());
            });
        }
    }

    /// Selects one explicit thread-local disposable root for a bounded test.
    /// Production builds do not contain this surface.
    pub fn override_protected_root(root: &Path) -> ProtectedRootOverride {
        let previous =
            super::TEST_PROTECTED_ROOT.with(|slot| slot.replace(Some(root.to_path_buf())));
        ProtectedRootOverride { previous }
    }

    /// Forces the next owned-receipt replacement to report a post-commit
    /// identity-unknown outcome after the durable rename.
    pub fn force_next_owned_runtime_receipt_unknown() {
        super::runtime_receipt_publication::force_next_owned_runtime_receipt_unknown();
    }
}

mod directory_publication;
mod installer_authority_key;
mod installer_root;
mod kernel_front_door_expectation;
mod kernel_front_door_server;
mod named_pipe_peer_auth;
mod named_pipe_process_admission;
mod nonce_generation;
mod owned_directory_retirement;
mod package_staging;
mod platform_security;
mod process_identity;
mod process_job;
mod process_path_lease;
mod protected_path;
mod runtime_receipt_publication;
mod secret_store;
mod service_registration;
mod supervision_authority_key;
mod tcp_listener_owner;

use crate::service_registration::{exact_path_text, utf16_text};

pub use directory_publication::{
    DirectoryPublicationError, DirectoryPublicationOutcome, DirectoryPublicationReceipt,
    DirectoryPublicationUnknown, DirectoryPublicationUnknownReceipt, OwnedDirectoryPublication,
};
pub(crate) use directory_publication::{
    create_owned_directory_relative, rename_directory_from_handle,
    retain_directory_publication_contour, validate_directory_publication_absolute,
    verify_directory_publication_contour,
};
pub use installer_authority_key::{
    INSTALLATION_AUTHORITY_KEY_FILE_BYTES, INSTALLATION_AUTHORITY_KEY_FILE_VERSION,
    INSTALLATION_AUTHORITY_KEY_ID_MAX_BYTES, INSTALLATION_AUTHORITY_KEY_MAGIC,
    INSTALLATION_AUTHORITY_KEY_ROOT_RELATIVE, INSTALLATION_AUTHORITY_SIGNER_ID,
    InstallationAuthorityKeyError, InstallationAuthorityKeyExpectation,
    InstallationAuthorityKeyMetadata, InstallationAuthorityKeySigner,
    WindowsInstallationAuthorityKeyProvider, WindowsInstallationAuthorityKeyStore,
};
pub use installer_root::{
    InstallerProtectedFileReadback, InstallerRootAbsentSnapshot, InstallerRootCreateAttempt,
    InstallerRootCreateDisposition, InstallerRootError, InstallerRootObjectSnapshot,
    InstallerRootPrimitiveCreate, InstallerRootPrimitiveObservation, InstallerRootPrimitiveSpec,
    InstallerRootProfile, InstallerRootStage, WindowsInstallerRootPrimitive, is_process_elevated,
    windows_path_identity_digest, windows_paths_equal,
};
pub use kernel_front_door_expectation::{KernelFrontDoorAclMode, KernelFrontDoorServerExpectation};
#[cfg(test)]
pub(crate) use kernel_front_door_server::KernelFrontDoorAce;
pub use kernel_front_door_server::KernelFrontDoorServerProof;
#[cfg(windows)]
pub use kernel_front_door_server::authenticate_kernel_front_door_server;
#[cfg(windows)]
pub(crate) use kernel_front_door_server::{OwnedProcessHandle, PinnedExecutable};
#[cfg(test)]
pub(crate) use kernel_front_door_server::{
    classify_kernel_front_door_acl, validate_kernel_front_door_artifact,
};
#[cfg(all(test, windows))]
pub(crate) use kernel_front_door_server::{
    validate_kernel_front_door_executable_identity, validate_kernel_front_door_process_identity,
};
pub(crate) use named_pipe_peer_auth::PEER_SET_GENERIC_ALL_MAPPED;
pub use named_pipe_peer_auth::observe_named_pipe_peer_process_in_job;
#[cfg(test)]
pub(crate) use named_pipe_peer_auth::{
    admit_named_pipe_peer_process, pipe_dacl_principal_allowed, validate_peer_set_ace_fields,
    validate_peer_set_sids,
};
#[cfg(windows)]
pub use named_pipe_peer_auth::{
    authenticate_named_pipe_client, authenticate_named_pipe_client_with_peer_set,
    authenticate_named_pipe_server, authenticate_named_pipe_server_with_peer_set,
};
pub use named_pipe_process_admission::{
    NamedPipePeerEvidence, NamedPipePeerExpectation, NamedPipePeerJobBinding,
    NamedPipePeerProcessBinding, current_process_named_pipe_expectation,
    observe_named_pipe_peer_process, observe_running_eliot_host_process,
};
#[cfg(test)]
pub(crate) use nonce_generation::{
    ACTIVATION_NONCE_HEX_BYTES, ACTIVATION_NONCE_PREFIX, ACTIVATION_NONCE_RANDOM_BYTES,
};
pub(crate) use nonce_generation::{fill_system_random, hex_lower};
pub use nonce_generation::{
    fresh_activation_nonce, fresh_activation_nonce_material, fresh_kernel_activation_nonce,
    fresh_service_registration_nonce,
};
pub use owned_directory_retirement::{
    OwnedDirectoryObservation, OwnedDirectoryObservedEntry, OwnedDirectoryRetirementEntry,
    OwnedDirectoryRetirementError, OwnedDirectoryRetirementOutcome,
    OwnedDirectoryRetirementPrecondition, OwnedDirectoryRetirementUnknown,
    observe_owned_directory_exact, retire_owned_directory_exact,
};
pub use package_staging::{
    AGENT_BRIDGE_STAGE_WIRE, AGENT_BRIDGE_STAGE_WIRE_VERSION, AgentBridgeStagePrepared,
    AgentBridgeStagingCreateDisposition, AgentBridgeStagingReceipt, AgentBridgeStagingRequest,
    AuthenticodeError, AuthenticodeEvidence, AuthenticodeVerdict, AuthenticodeVerifier,
    MAX_ENUMERATED_ENTRIES, PackageFileSpec, PackageManifest, PackageRelativePath,
    PackageSourceFileObservation, PackageSourceObservation, PackageStager, PackageStagingError,
    PackageStagingObservation, PackageStagingStage, PeCoffError, PeCoffEvidence,
    StagePackageAuthorization, StagePackageExpectedFile, StagedDirectoryReceipt, StagedFileReceipt,
    StagingReceipt, TrustedSourceBundle, TrustedSourceFileLease, WindowsAuthenticodeVerifier,
    ordinal_cmp_str, ordinal_component_cmp, ordinal_eq_str, ordinal_path_cmp, parse_pe_coff,
    prepare_agent_bridge_stage, publish_agent_bridge_stage, reconcile_agent_bridge_stage,
    validate_package_relative_path,
};
use platform_security::NamedPipeAuthDiscriminator;
pub(crate) use platform_security::verify_exact_file_security;
pub use platform_security::{
    AGENT_BRIDGE_DECLARATION_READ_ACCESS_MASK, AGENT_BRIDGE_FILE_TRAVERSE_ACCESS_MASK,
    AgentBridgeDeclarationReadLease, AgentBridgeFinalReadLease,
    AgentBridgeSecurityConvergenceReceipt, NamedPipePeerKind, NamedPipePeerProfile,
    NamedPipePeerSelection, NamedPipePeerSet, WATCHDOG_FALLBACK_TASK_NAME,
    WatchdogTaskRegistration, WatchdogTaskRegistrationReceipt, WatchdogTaskRunReceipt,
    WindowsStoreCredentialTargetGenerator, converge_agent_bridge_security,
    open_agent_bridge_declaration_read_lease, open_agent_bridge_final_read_lease,
    register_interactive_watchdog_task, run_registered_watchdog_task, validate_pinned_artifact,
    verify_agent_bridge_security,
};
#[cfg(test)]
use platform_security::{watchdog_task_readback_matches, watchdog_task_xml};
pub use process_identity::{FileIdentity, ProcessIdentity, is_process_builtin_administrator};
pub(crate) use process_identity::{
    file_identity, file_identity_from_handle, inspect_process_handle, inspect_process_identity,
    process_token_identity, process_token_is_builtin_administrator, same_process_identity,
    same_process_image_path, same_windows_path, thread_token_is_builtin_administrator,
    token_identity, valid_process_image_path,
};
pub use process_job::{
    ExistingJobMemberObservation, JobObject, JobObjectIdentity, JobObjectLimits, JobObservationGap,
    JobProcessHistory, PinnedRuntimeFile, ProcessObservation, RecoverableJobBinding,
    RecoverableJobObject, RunningExistingJobChild, RunningJobChild, RunningJobObservation,
    SuspendedExistingJobChild, SuspendedJobChild, SuspendedLaunchSpec, SuspendedProcessEvidence,
    SuspendedValidationError, TerminatedExistingJobChild, TerminatedJobChild,
    ValidatedSuspendedExistingJobChild, ValidatedSuspendedJobChild, cancel_capture_thread_io,
};
pub use process_path_lease::RetainedProcessPathLease;
pub use protected_path::{
    ProtectedPathError, ProtectedPathLease, ProtectedPathStage, ProtectedRootLease,
    canonical_windows_path, prepare_protected_directory, protected_program_data_path,
    protected_program_data_root, read_protected_file, require_protected_program_data_path,
    validate_protected_file,
};
pub use runtime_receipt_publication::{
    PublicationOutcome, PublicationPrecondition, PublicationReceipt, PublicationUnknown,
    PublicationUnknownReceipt, publish_atomic_owned_runtime_receipt,
};
use secret_store::valid_credential_key;
pub use secret_store::{
    CredentialSecret, HostCredentialMutationCapability, InstallerSecretCreateDisposition,
    InstallerSecretObservation, ProtectedSecret, WindowsInstallerSecretProvider,
};
pub use service_registration::{
    ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME,
    ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK, ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
    ELIOT_WATCHDOG_SERVICE_NAME, ServiceAccount, ServiceBootstrapArguments,
    ServiceControlGrantReadback, ServiceRegistrationCurrent, ServiceRegistrationInspection,
    ServiceRegistrationOutcome, ServiceRegistrationRequest, ServiceRegistrationRuntimeInspection,
    ServiceRuntimeObservation, ServiceSidType, ServiceStartMode, ServiceStartOutcome,
    ServiceStopOutcome,
};
pub use supervision_authority_key::{
    SealedSupervisionAuthorityKey, SupervisionAuthorityKeyError,
    SupervisionAuthorityKeyStoreRequest, WindowsSupervisionAuthorityKeyProvider,
    WindowsSupervisionAuthorityKeyStore,
};
pub use tcp_listener_owner::{
    TcpListenerOwnerError, TcpListenerOwnerObservation, observe_loopback_tcp_listener_owner,
};

/// Failure returned by a Windows-only primitive before it can be projected
/// into a provider-neutral P-01 outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAdapterError {
    InvalidInput,
    NotFound,
    AlreadyExists,
    Unavailable,
    PermissionDenied,
    Timeout,
    Failed,
    IdentityMismatch,
    AclMismatch,
}

impl std::fmt::Display for WindowsAdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Windows adapter failure: {self:?}")
    }
}

impl std::error::Error for WindowsAdapterError {}

/// Canonical failure disposition for the installation-wide Host owner lease.
///
/// The lease deliberately distinguishes a live owner from a mutex abandoned
/// by a terminated owner and from an indeterminate Win32 result.  Host must
/// fail closed for all three cases; only a clean, immediate acquisition is an
/// admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostOwnerLeaseError {
    /// The named mutex is currently owned by another Host process.
    LiveOwner,
    /// A pre-existing named object cannot be trusted without a DACL proof.
    ExistingObject,
    /// The previous owner terminated without completing durable shutdown.
    AbandonedOwner,
    /// Windows could not classify the owner state; recovery is required.
    OwnershipUncertain { win32_error: u32 },
    /// Creation/opening failed before ownership could be classified.
    CreationFailed { win32_error: u32 },
    /// This primitive is intentionally unavailable off Windows.
    UnsupportedPlatform,
}

impl std::fmt::Display for HostOwnerLeaseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LiveOwner => formatter.write_str("installation-wide Host owner is live"),
            Self::ExistingObject => formatter.write_str(
                "installation-wide Host owner object already exists; refusing unverified ownership",
            ),
            Self::AbandonedOwner => {
                formatter.write_str("installation-wide Host owner was abandoned; recovery required")
            }
            Self::OwnershipUncertain { win32_error } => write!(
                formatter,
                "installation-wide Host owner state is uncertain (Win32 error {win32_error})"
            ),
            Self::CreationFailed { win32_error } => write!(
                formatter,
                "installation-wide Host owner mutex creation failed (Win32 error {win32_error})"
            ),
            Self::UnsupportedPlatform => {
                formatter.write_str("installation-wide Host owner lease requires Windows")
            }
        }
    }
}

impl std::error::Error for HostOwnerLeaseError {}

/// Prefix for the installation-wide cross-process Host owner mutex.
pub const HOST_OWNER_MUTEX_PREFIX: &str = "Global\\Eliot-Host-Owner-";

/// Shared in-process authority gate between a Host owner lease and every
/// capability derived from it.  The gate is held for the complete mutation,
/// so release/Drop can revoke the capability before closing the OS mutex.
/// Prefix for the Host-owned per-target Credential Manager interlock.
///
/// The gate is held for every complete Host or credential mutation, so lease
/// release cannot revoke or close the owner mutex underneath an in-flight
/// operation.
#[derive(Debug, Default)]
struct HostLeaseAuthority {
    gate: Mutex<()>,
    revoked: AtomicBool,
}

/// Failure returned when an explicit owner release cannot classify its
/// ReleaseMutex/CloseHandle effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostOwnerLeaseReleaseError {
    /// Releasing mutex ownership failed, but the handle close was attempted.
    ReleaseMutex { win32_error: u32 },
    /// Closing the owner handle failed after ownership was released or was not held.
    CloseHandle { win32_error: u32 },
    /// This primitive is intentionally unavailable off Windows.
    UnsupportedPlatform,
}

impl std::fmt::Display for HostOwnerLeaseReleaseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReleaseMutex { win32_error } => write!(
                formatter,
                "Host owner ReleaseMutex failed (Win32 error {win32_error})"
            ),
            Self::CloseHandle { win32_error } => write!(
                formatter,
                "Host owner CloseHandle failed (Win32 error {win32_error})"
            ),
            Self::UnsupportedPlatform => formatter.write_str("Host owner release requires Windows"),
        }
    }
}

impl std::error::Error for HostOwnerLeaseReleaseError {}

#[cfg(windows)]
fn protected_path_io_error(
    stage: ProtectedPathStage,
    error: &std::io::Error,
) -> ProtectedPathError {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        .map_or(ProtectedPathError::Io, |code| ProtectedPathError::Win32 {
            stage,
            code,
        })
}

#[cfg(not(windows))]
fn protected_path_io_error(
    _stage: ProtectedPathStage,
    _error: &std::io::Error,
) -> ProtectedPathError {
    ProtectedPathError::Io
}

/// Resolves the current user's canonical `LocalAppData` root without applying an
/// ACL or accepting a caller-authored fallback.
///
/// # Errors
///
/// Returns an error when the OS known-folder lookup is unavailable, the root
/// cannot be canonicalized, or its contour contains a reparse point.
pub fn current_user_local_app_data_root() -> Result<PathBuf, ProtectedPathError> {
    let raw = known_folder_path(KnownFolder::LocalAppData)?;
    reject_reparse_chain(&raw, true)?;
    let canonical = canonical_windows_path(&raw)?;
    validate_directory_no_reparse(&canonical)?;
    Ok(canonical)
}

/// Fixed current-user configuration observation below the OS-known
/// `LocalAppData\Eliot` root. A missing file is deliberately provisional and
/// must not be treated as durable authority.
#[derive(Debug)]
pub enum LocalAppDataConfigObservation {
    Absent { path: PathBuf },
    Present(LocalAppDataConfigRead),
}

/// Read-only, identity-bound observation of the fixed Governor config file.
pub struct LocalAppDataConfigRead {
    path: PathBuf,
    root_identity: FileIdentity,
    parent_identity: FileIdentity,
    file_identity: FileIdentity,
    size: u64,
    sha256: String,
    bytes: Vec<u8>,
    #[cfg(windows)]
    root: std::fs::File,
    #[cfg(windows)]
    parents: Vec<std::fs::File>,
    #[cfg(windows)]
    file: std::fs::File,
}

impl std::fmt::Debug for LocalAppDataConfigRead {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalAppDataConfigRead")
            .field("path", &self.path)
            .field("root_identity", &self.root_identity)
            .field("parent_identity", &self.parent_identity)
            .field("file_identity", &self.file_identity)
            .field("size", &self.size)
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}

impl LocalAppDataConfigObservation {
    /// Returns true only for a present, retained observation.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        matches!(self, Self::Present(_))
    }

    /// Missing config is always provisional rather than durable authority.
    #[must_use]
    pub const fn is_provisional_absent(&self) -> bool {
        matches!(self, Self::Absent { .. })
    }
}

impl LocalAppDataConfigRead {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn root_identity(&self) -> FileIdentity {
        self.root_identity
    }

    #[must_use]
    pub const fn parent_identity(&self) -> FileIdentity {
        self.parent_identity
    }

    #[must_use]
    pub const fn file_identity(&self) -> FileIdentity {
        self.file_identity
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Returns the bounded bytes read twice through the same retained handle.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Re-reads the same retained file handle and verifies every retained
    /// root/parent/file identity, final path, size and hash.
    ///
    /// # Errors
    ///
    /// Returns an error when an identity, path, or bounded content read is
    /// not stable.
    pub fn verify_stable(&self) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            let root = file_identity_from_handle(&self.root).map_err(|_| ProtectedPathError::Io)?;
            let parent_handle = self.parents.last().ok_or(ProtectedPathError::Io)?;
            let parent =
                file_identity_from_handle(parent_handle).map_err(|_| ProtectedPathError::Io)?;
            let file = file_identity_from_handle(&self.file).map_err(|_| ProtectedPathError::Io)?;
            if root != self.root_identity
                || parent != self.parent_identity
                || file != self.file_identity
            {
                return Err(ProtectedPathError::Io);
            }
            let path = final_windows_path_from_handle(&self.file)?;
            if !windows_paths_equal(&path, &self.path) {
                return Err(ProtectedPathError::Io);
            }
            let bytes = read_same_handle_twice(&self.file, self.size)?;
            if bytes != self.bytes || format!("{:x}", Sha256::digest(&bytes)) != self.sha256 {
                return Err(ProtectedPathError::Io);
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }
}

/// Observes the fixed `LocalAppData\Eliot\config\governor.toml` file using
/// the OS known folder, never `LOCALAPPDATA` environment substitution.
///
/// # Errors
///
/// Returns an error when the known folder, retained contour, ACL, or bounded
/// same-handle read cannot be proven safe.
pub fn observe_current_user_config(
    max_bytes: u64,
) -> Result<LocalAppDataConfigObservation, ProtectedPathError> {
    let local_app_data = current_user_local_app_data_root()?;
    let eliot_root = local_app_data.join("Eliot");
    let config_path = eliot_root.join("config").join("governor.toml");
    observe_fixed_local_app_data_config(&eliot_root, &config_path, max_bytes)
}

/// Alias naming the fixed OS-known-folder observation explicitly.
///
/// # Errors
///
/// Propagates errors from [`observe_current_user_config`].
pub fn observe_local_app_data_config(
    max_bytes: u64,
) -> Result<LocalAppDataConfigObservation, ProtectedPathError> {
    observe_current_user_config(max_bytes)
}

fn observe_fixed_local_app_data_config(
    root: &Path,
    config_path: &Path,
    max_bytes: u64,
) -> Result<LocalAppDataConfigObservation, ProtectedPathError> {
    #[cfg(windows)]
    {
        if max_bytes == 0 || !config_path.starts_with(root) {
            return Err(ProtectedPathError::InvalidPath);
        }
        match std::fs::symlink_metadata(root) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ProtectedPathError::ReparsePoint);
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(ProtectedPathError::InvalidRoot);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LocalAppDataConfigObservation::Absent {
                    path: config_path.to_path_buf(),
                });
            }
            Err(_) => return Err(ProtectedPathError::Io),
        }
        let parent = config_path
            .parent()
            .ok_or(ProtectedPathError::InvalidPath)?;
        match std::fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ProtectedPathError::ReparsePoint);
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(ProtectedPathError::InvalidPath);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LocalAppDataConfigObservation::Absent {
                    path: config_path.to_path_buf(),
                });
            }
            Err(_) => return Err(ProtectedPathError::Io),
        }
        let root_lease = UserOwnedRootReadLease::open_existing(root)?;
        let relative_parent = parent
            .strip_prefix(root)
            .map_err(|_| ProtectedPathError::InvalidPath)?;
        let parent_handles =
            open_user_owned_directory_read_only_contour(root, relative_parent, &root_lease.sid)?;
        let parent_handle = parent_handles
            .last()
            .ok_or(ProtectedPathError::InvalidPath)?;
        let parent_identity =
            file_identity_from_handle(parent_handle).map_err(|_| ProtectedPathError::Io)?;
        let file = match open_user_owned_file_read_only(config_path, &root_lease.sid) {
            Ok(value) => value,
            Err(ProtectedPathError::Io) if !config_path.exists() => {
                return Ok(LocalAppDataConfigObservation::Absent {
                    path: config_path.to_path_buf(),
                });
            }
            Err(error) => return Err(error),
        };
        let file_identity = file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)?;
        let bytes = read_same_handle_twice(&file, max_bytes)?;
        let size = bytes.len() as u64;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let observed_path = final_windows_path_from_handle(&file)?;
        if !windows_paths_equal(&observed_path, config_path) {
            return Err(ProtectedPathError::Io);
        }
        Ok(LocalAppDataConfigObservation::Present(
            LocalAppDataConfigRead {
                path: observed_path,
                root_identity: root_lease.identity,
                parent_identity,
                file_identity,
                size,
                sha256,
                bytes,
                root: root_lease.handle,
                parents: parent_handles,
                file,
            },
        ))
    }
    #[cfg(not(windows))]
    {
        let _ = (root, config_path, max_bytes);
        Err(ProtectedPathError::UnsupportedPlatform)
    }
}

#[derive(Clone, Copy)]
enum KnownFolder {
    LocalAppData,
}

#[cfg(windows)]
fn known_folder_hresult_error(status: i32) -> ProtectedPathError {
    ProtectedPathError::Win32 {
        stage: ProtectedPathStage::KnownFolderPath,
        code: u32::from_ne_bytes(status.to_ne_bytes()),
    }
}

#[cfg(windows)]
fn known_folder_path(folder: KnownFolder) -> Result<PathBuf, ProtectedPathError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::S_OK;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath};

    let folder_id = match folder {
        KnownFolder::LocalAppData => &FOLDERID_LocalAppData,
    };
    let mut path = std::ptr::null_mut();
    let status = unsafe {
        // SAFETY: the folder id is static, null token selects the process user,
        // and `path` receives task-allocator memory released below.
        SHGetKnownFolderPath(folder_id, 0, std::ptr::null_mut(), &raw mut path)
    };
    if status != S_OK {
        unsafe {
            // SAFETY: CoTaskMemFree accepts null and any pointer returned by the API.
            CoTaskMemFree(path.cast());
        }
        return Err(known_folder_hresult_error(status));
    }
    if path.is_null() {
        unsafe {
            // SAFETY: CoTaskMemFree accepts null.
            CoTaskMemFree(path.cast());
        }
        return Err(ProtectedPathError::InvalidRoot);
    }
    let mut length = 0_usize;
    while length <= 32_767 {
        let terminated = unsafe {
            // SAFETY: SHGetKnownFolderPath returned a NUL-terminated Windows path.
            *path.add(length) == 0
        };
        if terminated {
            break;
        }
        length += 1;
    }
    if length > 32_767 {
        unsafe {
            // SAFETY: `path` is still the task-allocator pointer returned above.
            CoTaskMemFree(path.cast());
        }
        return Err(ProtectedPathError::InvalidRoot);
    }
    let value = unsafe {
        // SAFETY: `length` was bounded by scanning the API-owned NUL-terminated buffer.
        OsString::from_wide(std::slice::from_raw_parts(path, length))
    };
    unsafe {
        // SAFETY: `path` is released exactly once after its contents are copied.
        CoTaskMemFree(path.cast());
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(ProtectedPathError::InvalidRoot);
    }
    Ok(path)
}

#[cfg(not(windows))]
fn known_folder_path(_folder: KnownFolder) -> Result<PathBuf, ProtectedPathError> {
    Err(ProtectedPathError::UnsupportedPlatform)
}

/// Read-only retained lease for a file in the installer-provisioned System
/// runtime contour. Unlike [`ProtectedPathLease`], this adapter never asks
/// the `LocalService` caller for `WRITE_DAC` and never rewrites ACLs. It proves
/// the immutable `BA+LS+SY` runtime-file DACL installed by the transaction,
/// then retains no-follow directory/file handles for the complete read.
pub struct ProtectedRuntimePathLease {
    path: PathBuf,
    identity: FileIdentity,
    #[cfg(windows)]
    _directories: Vec<std::fs::File>,
    #[cfg(windows)]
    file: std::fs::File,
}

impl std::fmt::Debug for ProtectedRuntimePathLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedRuntimePathLease")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl ProtectedRuntimePathLease {
    /// Opens one existing absolute file under the OS-resolved `ProgramData`
    /// runtime contour with the installer `BA+LS+SY` ACL proof.
    ///
    /// # Errors
    ///
    /// Returns an error when the path, no-follow containment, ACL, or retained
    /// file identity cannot be proven.
    pub fn open_existing_absolute(path: &Path) -> Result<Self, ProtectedPathError> {
        Self::open_absolute(path, false)
    }

    /// Opens one existing runtime file read-only with exclusive sharing. This
    /// is an opt-in canary fence; ordinary runtime lease sharing is unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected path, ACL, or retained identity
    /// cannot be proven.
    pub fn open_existing_absolute_exclusive(path: &Path) -> Result<Self, ProtectedPathError> {
        Self::open_absolute_exclusive(path)
    }

    /// Creates or opens one runtime state file without changing its
    /// installer-provisioned ACL. Creation requires the already-provisioned
    /// `LocalService` write permission on the parent runtime root.
    ///
    /// # Errors
    ///
    /// Returns an error when the path, no-follow containment, ACL, or retained
    /// file identity cannot be proven, or when the caller lacks the required
    /// write permission for a state file.
    pub fn open_or_create_absolute(path: &Path) -> Result<Self, ProtectedPathError> {
        Self::open_absolute(path, true)
    }

    fn open_absolute(path: &Path, create: bool) -> Result<Self, ProtectedPathError> {
        Self::open_absolute_mode(path, create, false)
    }

    fn open_absolute_exclusive(path: &Path) -> Result<Self, ProtectedPathError> {
        Self::open_absolute_mode(path, false, true)
    }

    fn open_absolute_mode(
        path: &Path,
        create: bool,
        exclusive: bool,
    ) -> Result<Self, ProtectedPathError> {
        let root = expected_root()?;
        ensure_protected_containment(&root, path)?;
        let canonical = if create {
            match std::fs::symlink_metadata(path) {
                Ok(_) => canonical_windows_path(path)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let parent = path.parent().ok_or(ProtectedPathError::InvalidPath)?;
                    let canonical_parent = canonical_windows_path(parent)?;
                    let leaf = path.file_name().ok_or(ProtectedPathError::InvalidPath)?;
                    canonical_parent.join(leaf)
                }
                Err(_) => return Err(ProtectedPathError::Io),
            }
        } else {
            canonical_windows_path(path)?
        };
        ensure_protected_containment(&root, &canonical)?;
        let relative = canonical
            .strip_prefix(&root)
            .map_err(|_| ProtectedPathError::InvalidPath)?;
        let components = protected_components(relative)?;
        #[cfg(windows)]
        {
            let parent = components[..components.len() - 1].iter().fold(
                PathBuf::new(),
                |mut value, component| {
                    value.push(component);
                    value
                },
            );
            let directories = if parent.as_os_str().is_empty() {
                vec![pin_directory(&root).map_err(|_| ProtectedPathError::Io)?]
            } else {
                protected_path::pin_protected_directory_contour(&root, &parent)?
            };
            let file = if exclusive {
                open_runtime_read_file_exclusive(&canonical)?
            } else {
                open_runtime_file(&canonical, create)?
            };
            let identity = file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)?;
            Ok(Self {
                path: canonical,
                identity,
                _directories: directories,
                file,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (canonical, components, exclusive);
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Returns the exact path retained by this lease.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the retained file identity.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Rechecks the retained file identity without reopening it by path.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained handle cannot be inspected or its
    /// identity no longer matches the lease.
    pub fn verify_stable_identity(&self) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            let identity =
                file_identity_from_handle(&self.file).map_err(|_| ProtectedPathError::Io)?;
            if identity != self.identity {
                return Err(ProtectedPathError::Io);
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Reopens the exact runtime file read-only and compares its identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the path cannot be reopened safely or its identity
    /// no longer matches the lease.
    pub fn verify_path_identity(&self) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            let file = open_runtime_read_file(&self.path)?;
            let identity = file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)?;
            if identity != self.identity {
                return Err(ProtectedPathError::Io);
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Reads bounded bytes through the retained read-only handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained handle cannot be read or the file
    /// exceeds `limit`.
    pub fn read_bounded(&self, limit: u64) -> Result<Vec<u8>, ProtectedPathError> {
        #[cfg(windows)]
        {
            let mut file = self.file.try_clone().map_err(|_| ProtectedPathError::Io)?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| ProtectedPathError::Io)?;
            let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
            if metadata.len() > limit {
                return Err(ProtectedPathError::SizeExceeded);
            }
            let mut bytes = Vec::with_capacity(metadata.len().try_into().unwrap_or(0));
            file.read_to_end(&mut bytes)
                .map_err(|_| ProtectedPathError::Io)?;
            if bytes.len() as u64 > limit {
                return Err(ProtectedPathError::SizeExceeded);
            }
            Ok(bytes)
        }
        #[cfg(not(windows))]
        {
            let _ = limit;
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }
}

#[cfg(windows)]
fn open_runtime_read_file(path: &Path) -> Result<std::fs::File, ProtectedPathError> {
    open_runtime_file(path, false)
}

#[cfg(windows)]
fn open_runtime_read_file_exclusive(path: &Path) -> Result<std::fs::File, ProtectedPathError> {
    open_runtime_file_with_share(path, false, 0)
}

#[cfg(windows)]
fn open_runtime_file(path: &Path, create: bool) -> Result<std::fs::File, ProtectedPathError> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
    open_runtime_file_with_share(path, create, FILE_SHARE_READ | FILE_SHARE_WRITE)
}

#[cfg(windows)]
fn open_runtime_file_with_share(
    path: &Path,
    create: bool,
    share_mode: u32,
) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(create)
        .access_mode(runtime_file_access_mode(create))
        .share_mode(share_mode)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = if create {
        options.create_new(true).open(path).or_else(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                let mut existing = std::fs::OpenOptions::new();
                existing
                    .read(true)
                    .write(true)
                    .access_mode(runtime_file_access_mode(true))
                    .share_mode(share_mode)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(path)
            } else {
                Err(error)
            }
        })
    } else {
        options.open(path)
    }
    .map_err(|_| ProtectedPathError::Io)?;
    let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::InvalidPath);
    }
    #[cfg(any(test, feature = "test-support"))]
    if test_protected_root().is_some() {
        return Ok(file);
    }
    #[cfg(any(test, feature = "test-support"))]
    let descriptor = if test_protected_root().is_some() {
        OwnedSecurityDescriptor::for_user_owned_storage(&current_process_sid()?, false)
    } else {
        OwnedSecurityDescriptor::for_installer_system_object(false)
    }
    .map_err(|_| ProtectedPathError::AclMismatch)?;
    #[cfg(not(any(test, feature = "test-support")))]
    let descriptor = OwnedSecurityDescriptor::for_installer_system_object(false)
        .map_err(|_| ProtectedPathError::AclMismatch)?;
    verify_readonly_acl(&file, &descriptor)?;
    Ok(file)
}

#[cfg(windows)]
fn runtime_file_access_mode(create: bool) -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};
    if create {
        FILE_GENERIC_READ | FILE_GENERIC_WRITE
    } else {
        FILE_GENERIC_READ
    }
}

#[cfg(windows)]
fn verify_readonly_acl(
    file: &std::fs::File,
    expected: &OwnedSecurityDescriptor,
) -> Result<(), ProtectedPathError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, SE_DACL_PROTECTED,
    };
    let expected_dacl = expected
        .dacl()
        .map_err(|_| ProtectedPathError::AclMismatch)?;
    let expected_owner = expected
        .owner()
        .map_err(|_| ProtectedPathError::AclMismatch)?;
    let expected_owner =
        sid_to_string(expected_owner).map_err(|_| ProtectedPathError::AclMismatch)?;
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut owner: PSID = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() || owner.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(ProtectedPathError::AclMismatch);
    }
    let mut present = 0;
    let mut actual_dacl = std::ptr::null_mut();
    let mut defaulted = 0;
    let dacl_matches = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut actual_dacl,
            &raw mut defaulted,
        ) != 0
            && present != 0
            && !actual_dacl.is_null()
            && (*actual_dacl).AclSize == (*expected_dacl).AclSize
            && std::slice::from_raw_parts(
                actual_dacl.cast::<u8>(),
                usize::from((*actual_dacl).AclSize),
            ) == std::slice::from_raw_parts(
                expected_dacl.cast::<u8>(),
                usize::from((*expected_dacl).AclSize),
            )
    };
    let mut control = 0_u16;
    let mut revision = 0_u32;
    let protected = unsafe {
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) != 0
            && control & SE_DACL_PROTECTED != 0
    };
    let owner_matches = sid_to_string(owner).is_ok_and(|actual| actual == expected_owner);
    unsafe { LocalFree(descriptor.cast()) };
    if !owner_matches || !dacl_matches || !protected {
        return Err(ProtectedPathError::AclMismatch);
    }
    Ok(())
}

/// A user-owned `portable_dev` root lease.
///
/// This contour is intentionally separate from [`ProtectedPathLease`]: it is
/// for an explicit, already-existing absolute directory owned by the current
/// process identity, rather than the installation-wide `ProgramData` policy.
/// The root handle is retained with delete sharing disabled for the lifetime
/// of the lease.
pub struct UserOwnedRootLease {
    path: PathBuf,
    identity: FileIdentity,
    sid: String,
    #[cfg(windows)]
    handle: std::fs::File,
}

/// Read-only retained lease for an already-provisioned current-user root.
///
/// Acquisition verifies the current process SID as owner and requires the
/// exact protected user-root DACL, but never requests `WRITE_DAC` or changes
/// security state. Provisioning remains an explicit installer effect.
pub struct UserOwnedRootReadLease {
    path: PathBuf,
    identity: FileIdentity,
    sid: String,
    #[cfg(windows)]
    handle: std::fs::File,
}

impl std::fmt::Debug for UserOwnedRootReadLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UserOwnedRootReadLease")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .field("sid", &self.sid)
            .finish_non_exhaustive()
    }
}

impl UserOwnedRootReadLease {
    /// Opens and verifies one existing current-user directory without changing it.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing/relative/reparse root, a different owner,
    /// a non-protected or unexpected DACL, or an unavailable retained handle.
    pub fn open_existing(root: &Path) -> Result<Self, ProtectedPathError> {
        #[cfg(windows)]
        {
            let declared = validate_user_owned_root(root)?;
            let path = canonical_windows_path(&declared)?;
            if !path.is_absolute() {
                return Err(ProtectedPathError::InvalidRoot);
            }
            reject_reparse_chain(&path, true)?;
            let sid = current_process_sid()?;
            let handle = open_user_owned_directory_read_only(&path, &sid)?;
            let identity =
                file_identity_from_handle(&handle).map_err(|_| ProtectedPathError::Io)?;
            Ok(Self {
                path,
                identity,
                sid,
                handle,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = root;
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Returns the current process SID verified as directory owner.
    #[must_use]
    pub fn current_user_sid(&self) -> &str {
        &self.sid
    }

    /// Returns the retained directory-object identity.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Returns the canonical DOS/UNC path from the retained handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained handle cannot be resolved or this
    /// operation is unsupported on the current platform.
    pub fn canonical_path(&self) -> Result<PathBuf, ProtectedPathError> {
        #[cfg(windows)]
        {
            final_windows_path_from_handle(&self.handle)
        }
        #[cfg(not(windows))]
        {
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Re-checks the retained directory identity without reopening by path.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained handle cannot be inspected, changed
    /// identity, or is unsupported on the current platform.
    pub fn verify_stable_identity(&self) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            let identity =
                file_identity_from_handle(&self.handle).map_err(|_| ProtectedPathError::Io)?;
            if identity != self.identity {
                return Err(ProtectedPathError::Io);
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }
}

impl std::fmt::Debug for UserOwnedRootLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UserOwnedRootLease")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .field("sid", &self.sid)
            .finish_non_exhaustive()
    }
}

impl UserOwnedRootLease {
    /// Opens one existing absolute directory for the current process SID.
    ///
    /// Every existing ancestor is checked for symlink/reparse substitution,
    /// and the opened root receives an exact protected DACL containing only
    /// `SYSTEM` and the current process SID.
    ///
    /// # Errors
    ///
    /// Returns an error when the root is not an existing safe directory, the
    /// current SID cannot be resolved, or the protected DACL proof fails.
    pub fn open_existing(root: &Path) -> Result<Self, ProtectedPathError> {
        #[cfg(windows)]
        {
            let path = validate_user_owned_root(root)?;
            let sid = current_process_sid()?;
            let handle = open_user_owned_directory(&path, &sid)?;
            let identity =
                file_identity_from_handle(&handle).map_err(|_| ProtectedPathError::Io)?;
            Ok(Self {
                path,
                identity,
                sid,
                handle,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = root;
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Returns the explicit root path retained by this lease.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the current process SID captured during acquisition.
    #[must_use]
    pub fn current_user_sid(&self) -> &str {
        &self.sid
    }

    /// Returns the root file-object identity captured from the retained handle.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Returns the canonical DOS/UNC root path from the retained directory handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained handle cannot be resolved or this
    /// operation is unsupported on the current platform.
    pub fn canonical_path(&self) -> Result<PathBuf, ProtectedPathError> {
        #[cfg(windows)]
        {
            final_windows_path_from_handle(&self.handle)
        }
        #[cfg(not(windows))]
        {
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Re-checks that the retained root handle still names the same object.
    ///
    /// # Errors
    ///
    /// Returns an error when the handle cannot be inspected or its identity
    /// no longer matches the acquisition proof.
    pub fn verify_stable_identity(&self) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            let identity =
                file_identity_from_handle(&self.handle).map_err(|_| ProtectedPathError::Io)?;
            (identity == self.identity)
                .then_some(())
                .ok_or(ProtectedPathError::Io)
        }
        #[cfg(not(windows))]
        {
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Validates the parent contour of one child path below this retained
    /// root without requiring the final child to exist.
    ///
    /// This is used for an atomic publication destination whose final file is
    /// intentionally absent on the first materialization. Every existing
    /// directory is opened with no-follow semantics and the same protected
    /// current-user DACL proof as [`UserOwnedPathLease::open_existing`].
    ///
    /// # Errors
    ///
    /// Returns an error when the path is outside the root, its parent contour
    /// is missing or substituted, or the retained root is no longer stable.
    pub fn validate_child_parent(&self, path: &Path) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            self.verify_stable_identity()?;
            if !path.is_absolute() {
                return Err(ProtectedPathError::InvalidPath);
            }
            ensure_user_owned_containment(&self.path, path)?;
            let parent = path.parent().ok_or(ProtectedPathError::InvalidPath)?;
            let relative_parent = parent
                .strip_prefix(&self.path)
                .map_err(|_| ProtectedPathError::InvalidPath)?;
            let _directories =
                open_user_owned_directory_contour(&self.path, relative_parent, &self.sid)?;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }
}

/// A retained file lease under a [`UserOwnedRootLease`].
///
/// The file must already exist.  The retained root, every parent directory,
/// and the file itself use no-follow handles with delete sharing disabled.
pub struct UserOwnedPathLease {
    path: PathBuf,
    identity: FileIdentity,
    sid: String,
    #[cfg(windows)]
    _root: std::fs::File,
    #[cfg(windows)]
    _directories: Vec<std::fs::File>,
    #[cfg(windows)]
    file: std::fs::File,
}

impl std::fmt::Debug for UserOwnedPathLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UserOwnedPathLease")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .field("sid", &self.sid)
            .finish_non_exhaustive()
    }
}

impl UserOwnedPathLease {
    /// Opens one existing absolute file below the retained root.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is outside the root, is a reparse
    /// substitution, cannot be opened with no-delete sharing, or fails the
    /// DACL/identity proof.
    pub fn open_existing(
        root: &UserOwnedRootLease,
        path: &Path,
    ) -> Result<Self, ProtectedPathError> {
        #[cfg(windows)]
        {
            if !path.is_absolute() {
                return Err(ProtectedPathError::InvalidPath);
            }
            ensure_user_owned_containment(&root.path, path)?;
            let parent = path.parent().ok_or(ProtectedPathError::InvalidPath)?;
            let relative_parent = parent
                .strip_prefix(&root.path)
                .map_err(|_| ProtectedPathError::InvalidPath)?;
            let directories =
                open_user_owned_directory_contour(&root.path, relative_parent, &root.sid)?;
            let file = open_user_owned_file(path, &root.sid)?;
            let identity = file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)?;
            let root_handle = root
                .handle
                .try_clone()
                .map_err(|_| ProtectedPathError::Io)?;
            Ok(Self {
                path: path.to_path_buf(),
                identity,
                sid: root.sid.clone(),
                _root: root_handle,
                _directories: directories,
                file,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (root, path);
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Returns the explicit file path retained by this lease.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the current process SID captured by the root lease.
    #[must_use]
    pub fn current_user_sid(&self) -> &str {
        &self.sid
    }

    /// Returns the file-object identity captured from the retained handle.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Re-checks the identity of the retained file handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained handle cannot be inspected or its
    /// identity no longer matches the acquisition proof.
    pub fn verify_stable_identity(&self) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            let identity =
                file_identity_from_handle(&self.file).map_err(|_| ProtectedPathError::Io)?;
            (identity == self.identity)
                .then_some(())
                .ok_or(ProtectedPathError::Io)
        }
        #[cfg(not(windows))]
        {
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Reopens the path with no-follow semantics and proves stable identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the path cannot be reopened safely or its object
    /// identity differs from the retained handle.
    pub fn verify_path_identity(&self) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            let file = open_user_owned_file(&self.path, &self.sid)?;
            let identity = file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)?;
            (identity == self.identity)
                .then_some(())
                .ok_or(ProtectedPathError::Io)
        }
        #[cfg(not(windows))]
        {
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Reads bytes from the retained handle without reopening the path.
    ///
    /// # Errors
    ///
    /// Returns an error when handle I/O fails or the file exceeds `limit`.
    pub fn read_bounded(&self, limit: u64) -> Result<Vec<u8>, ProtectedPathError> {
        #[cfg(windows)]
        {
            let mut file = self.file.try_clone().map_err(|_| ProtectedPathError::Io)?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| ProtectedPathError::Io)?;
            let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
            if metadata.len() > limit {
                return Err(ProtectedPathError::SizeExceeded);
            }
            let mut bytes = Vec::with_capacity(metadata.len().try_into().unwrap_or(0));
            file.read_to_end(&mut bytes)
                .map_err(|_| ProtectedPathError::Io)?;
            if bytes.len() as u64 > limit {
                return Err(ProtectedPathError::SizeExceeded);
            }
            Ok(bytes)
        }
        #[cfg(not(windows))]
        {
            let _ = limit;
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }
}

#[cfg(windows)]
fn validate_user_owned_root(root: &Path) -> Result<PathBuf, ProtectedPathError> {
    if !root.is_absolute() {
        return Err(ProtectedPathError::InvalidRoot);
    }
    if root.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return Err(ProtectedPathError::InvalidRoot);
    }
    reject_reparse_chain(root, true)?;
    validate_directory_no_reparse(root)?;
    Ok(root.to_path_buf())
}

#[cfg(windows)]
fn ensure_user_owned_containment(root: &Path, path: &Path) -> Result<(), ProtectedPathError> {
    if path == root || !path.starts_with(root) {
        return Err(ProtectedPathError::InvalidPath);
    }
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ProtectedPathError::InvalidPath)?;
    if relative
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(ProtectedPathError::InvalidPath);
    }
    Ok(())
}

#[cfg(windows)]
fn current_process_sid() -> Result<String, ProtectedPathError> {
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(ProtectedPathError::AclMismatch);
    }
    let result = token_identity(token)
        .map(|(sid, _)| sid)
        .map_err(|_| ProtectedPathError::AclMismatch);
    unsafe { windows_sys::Win32::Foundation::CloseHandle(token) };
    result
}

#[cfg(not(windows))]
fn current_process_sid() -> Result<String, ProtectedPathError> {
    Err(ProtectedPathError::UnsupportedPlatform)
}

#[cfg(windows)]
fn open_user_owned_directory(path: &Path, sid: &str) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, WRITE_DAC, WRITE_OWNER,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.access_mode(FILE_GENERIC_READ | WRITE_DAC | WRITE_OWNER);
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|_| ProtectedPathError::Io)?;
    let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    protect_user_owned_opened_handle(&file, true, sid)?;
    Ok(file)
}

#[cfg(windows)]
fn open_user_owned_directory_read_only(
    path: &Path,
    sid: &str,
) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.access_mode(FILE_GENERIC_READ);
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|_| ProtectedPathError::Io)?;
    let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    verify_user_owned_opened_handle_read_only(&file, sid)?;
    Ok(file)
}

#[cfg(windows)]
fn open_user_owned_directory_contour(
    root: &Path,
    relative: &Path,
    sid: &str,
) -> Result<Vec<std::fs::File>, ProtectedPathError> {
    let mut directories = vec![open_user_owned_directory(root, sid)?];
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(ProtectedPathError::InvalidPath);
        };
        current.push(component);
        directories.push(open_user_owned_directory(&current, sid)?);
    }
    Ok(directories)
}

#[cfg(windows)]
fn open_user_owned_directory_read_only_contour(
    root: &Path,
    relative: &Path,
    sid: &str,
) -> Result<Vec<std::fs::File>, ProtectedPathError> {
    let mut directories = vec![open_user_owned_directory_read_only(root, sid)?];
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(ProtectedPathError::InvalidPath);
        };
        current.push(component);
        directories.push(open_user_owned_directory_read_only(&current, sid)?);
    }
    Ok(directories)
}

#[cfg(windows)]
fn open_user_owned_file(path: &Path, sid: &str) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_SHARE_READ, FILE_SHARE_WRITE, WRITE_DAC, WRITE_OWNER,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.access_mode(FILE_GENERIC_READ | WRITE_DAC | WRITE_OWNER);
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|_| ProtectedPathError::Io)?;
    let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    if !metadata.is_file() {
        return Err(ProtectedPathError::InvalidPath);
    }
    protect_user_owned_opened_handle(&file, false, sid)?;
    Ok(file)
}

#[cfg(windows)]
fn open_user_owned_file_read_only(
    path: &Path,
    sid: &str,
) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_SHARE_READ,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|_| ProtectedPathError::Io)?;
    let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    if !metadata.is_file() {
        return Err(ProtectedPathError::InvalidPath);
    }
    ensure_single_user_file_link(&file)?;
    verify_user_owned_opened_handle_read_only(&file, sid)?;
    Ok(file)
}

#[cfg(windows)]
fn ensure_single_user_file_link(file: &std::fs::File) -> Result<(), ProtectedPathError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let observed = unsafe {
        // SAFETY: the retained file handle is live and the output points to
        // initialized storage for the documented structure.
        GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut information)
    };
    if observed == 0 || information.nNumberOfLinks != 1 {
        return Err(ProtectedPathError::Io);
    }
    Ok(())
}

#[cfg(windows)]
fn read_same_handle_twice(
    file: &std::fs::File,
    max_bytes: u64,
) -> Result<Vec<u8>, ProtectedPathError> {
    fn read_once(file: &std::fs::File, max_bytes: u64) -> Result<Vec<u8>, ProtectedPathError> {
        let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
        if metadata.len() > max_bytes {
            return Err(ProtectedPathError::SizeExceeded);
        }
        let mut clone = file.try_clone().map_err(|_| ProtectedPathError::Io)?;
        clone
            .seek(SeekFrom::Start(0))
            .map_err(|_| ProtectedPathError::Io)?;
        let mut bytes = Vec::with_capacity(metadata.len().try_into().unwrap_or(0));
        clone
            .read_to_end(&mut bytes)
            .map_err(|_| ProtectedPathError::Io)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(ProtectedPathError::Io);
        }
        Ok(bytes)
    }
    let first = read_once(file, max_bytes)?;
    let second = read_once(file, max_bytes)?;
    if first != second {
        return Err(ProtectedPathError::Io);
    }
    Ok(first)
}

fn protected_components(relative: &Path) -> Result<Vec<std::ffi::OsString>, ProtectedPathError> {
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(ProtectedPathError::InvalidPath);
    }
    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(component) => {
                if component.is_empty() {
                    return Err(ProtectedPathError::InvalidPath);
                }
                components.push(component.to_os_string());
            }
            _ => return Err(ProtectedPathError::InvalidPath),
        }
    }
    if components.is_empty() {
        return Err(ProtectedPathError::InvalidPath);
    }
    Ok(components)
}

fn expected_root() -> Result<PathBuf, ProtectedPathError> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(root) = test_protected_root() {
        return canonical_windows_path(&root);
    }
    protected_program_data_root()
}

#[cfg(any(test, feature = "test-support"))]
fn test_protected_root() -> Option<PathBuf> {
    TEST_PROTECTED_ROOT.with(|slot| slot.borrow().clone())
}

fn ensure_protected_containment(root: &Path, path: &Path) -> Result<(), ProtectedPathError> {
    if !path.is_absolute() || !path.starts_with(root) {
        return Err(ProtectedPathError::InvalidPath);
    }
    reject_reparse_chain(path, false)?;
    for ancestor in path.ancestors().take_while(|candidate| *candidate != root) {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() || is_reparse_point(&metadata) => {
                return Err(ProtectedPathError::ReparsePoint);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(protected_path_io_error(
                    ProtectedPathStage::SymlinkMetadata,
                    &error,
                ));
            }
        }
    }
    Ok(())
}

fn reject_reparse_chain(path: &Path, require_existing: bool) -> Result<(), ProtectedPathError> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() || is_reparse_point(&metadata) => {
                return Err(ProtectedPathError::ReparsePoint);
            }
            Ok(_) => {}
            Err(error) if !require_existing && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ProtectedPathError::InvalidRoot);
            }
            Err(error) => {
                return Err(protected_path_io_error(
                    ProtectedPathStage::SymlinkMetadata,
                    &error,
                ));
            }
        }
    }
    Ok(())
}

fn validate_directory_no_reparse(path: &Path) -> Result<(), ProtectedPathError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| protected_path_io_error(ProtectedPathStage::SymlinkMetadata, &error))?;
    if !metadata.is_dir() {
        return Err(ProtectedPathError::InvalidRoot);
    }
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(ProtectedPathError::ReparsePoint);
    }
    Ok(())
}

#[cfg(windows)]
fn protect_user_owned_opened_handle(
    file: &std::fs::File,
    directory: bool,
    sid: &str,
) -> Result<(), ProtectedPathError> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    if !valid_sid_text(sid) {
        return Err(ProtectedPathError::AclMismatch);
    }
    let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    if directory != metadata.is_dir() {
        return Err(ProtectedPathError::InvalidPath);
    }
    let expected = OwnedSecurityDescriptor::for_user_owned_storage(sid, directory)
        .map_err(|_| ProtectedPathError::AclMismatch)?;
    let dacl = expected
        .dacl()
        .map_err(|_| ProtectedPathError::AclMismatch)?;
    let owner = expected
        .owner()
        .map_err(|_| ProtectedPathError::AclMismatch)?;
    let security = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION;
    let status = unsafe {
        windows_sys::Win32::Security::Authorization::SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            security,
            owner,
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if status != 0 {
        return Err(ProtectedPathError::AclMismatch);
    }
    let mut observed_owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            security,
            &raw mut observed_owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() || observed_owner.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(ProtectedPathError::AclMismatch);
    }
    let mut present = 0;
    let mut actual_dacl = std::ptr::null_mut();
    let mut defaulted = 0;
    let dacl_matches = unsafe {
        windows_sys::Win32::Security::GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut actual_dacl,
            &raw mut defaulted,
        ) != 0
            && present != 0
            && !actual_dacl.is_null()
            && (*actual_dacl).AclSize == (*dacl).AclSize
            && std::slice::from_raw_parts(
                actual_dacl.cast::<u8>(),
                usize::from((*actual_dacl).AclSize),
            ) == std::slice::from_raw_parts(dacl.cast::<u8>(), usize::from((*dacl).AclSize))
    };
    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    let protected = unsafe {
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) != 0
            && control & SE_DACL_PROTECTED != 0
    };
    let owner_matches = sid_to_string(observed_owner).is_ok_and(|observed| observed == sid);
    unsafe { LocalFree(descriptor.cast()) };
    if !owner_matches || !dacl_matches || !protected {
        return Err(ProtectedPathError::AclMismatch);
    }
    Ok(())
}

#[cfg(windows)]
fn verify_user_owned_opened_handle_read_only(
    file: &std::fs::File,
    sid: &str,
) -> Result<(), ProtectedPathError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    };

    if !valid_sid_text(sid) {
        return Err(ProtectedPathError::AclMismatch);
    }
    let expected = OwnedSecurityDescriptor::for_user_owned_storage(sid, true)
        .map_err(|_| ProtectedPathError::AclMismatch)?;
    let expected_dacl = expected
        .dacl()
        .map_err(|_| ProtectedPathError::AclMismatch)?;
    let security = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION;
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        // SAFETY: the retained handle is live and every output points to a valid local.
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            security,
            &raw mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() || owner.is_null() {
        if !descriptor.is_null() {
            unsafe {
                // SAFETY: descriptor was allocated by GetSecurityInfo.
                LocalFree(descriptor.cast());
            }
        }
        return Err(ProtectedPathError::AclMismatch);
    }
    let owner_matches = sid_to_string(owner).is_ok_and(|observed| observed == sid);
    let mut present = 0;
    let mut actual_dacl = std::ptr::null_mut();
    let mut defaulted = 0;
    let dacl_matches = unsafe {
        // SAFETY: descriptor and expected DACL remain live for these bounded reads.
        windows_sys::Win32::Security::GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut actual_dacl,
            &raw mut defaulted,
        ) != 0
            && present != 0
            && !actual_dacl.is_null()
            && (*actual_dacl).AclSize == (*expected_dacl).AclSize
            && std::slice::from_raw_parts(
                actual_dacl.cast::<u8>(),
                usize::from((*actual_dacl).AclSize),
            ) == std::slice::from_raw_parts(
                expected_dacl.cast::<u8>(),
                usize::from((*expected_dacl).AclSize),
            )
    };
    let mut control = 0_u16;
    let mut revision = 0_u32;
    let protected = unsafe {
        // SAFETY: descriptor is live and control/revision outputs are valid locals.
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) != 0
            && control & SE_DACL_PROTECTED != 0
    };
    unsafe {
        // SAFETY: descriptor is released exactly once after all reads complete.
        LocalFree(descriptor.cast());
    }
    if !owner_matches || !dacl_matches || !protected {
        return Err(ProtectedPathError::AclMismatch);
    }
    Ok(())
}

/// Returns the canonical named mutex for one validated installation identity.
///
/// The identity itself never enters the object-manager name.  SHA-256 keeps
/// the name deterministic across service and console processes while avoiding
/// truncation or object-name collisions from user-controlled identity text.
#[must_use]
pub fn host_owner_mutex_name(installation: &PlatformHandle) -> String {
    let digest = Sha256::digest(installation.as_str().as_bytes());
    let mut suffix = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(suffix, "{byte:02x}");
    }
    format!("{HOST_OWNER_MUTEX_PREFIX}{suffix}")
}

/// Process-owned installation-wide Host admission lease.
///
/// The handle remains held for the entire `HostComposition` lifetime. A mutex
/// object is not a durable recovery record: every pre-existing object is
/// rejected and never treated as permission to resume.
pub struct HostOwnerLease {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
    owns: bool,
    name: String,
    authority: Arc<HostLeaseAuthority>,
}

/// Compile-time proof that the caller owns the installation Host epoch.
///
/// The field is intentionally private and the only constructor is exposed by
/// [`HostOwnerLease::activation_capability`].  Consumers can carry this proof
/// across crate boundaries, but cannot forge or deserialize one.
#[derive(Debug)]
pub struct HostOwnerEpochCapability {
    authority: Arc<HostLeaseAuthority>,
}

/// Opaque live guard held for the complete Host-owned registry mutation.
///
/// The guard cannot be forged or inspected by consumers; dropping it releases
/// the same in-process gate used by [`HostOwnerLease::release`] and `Drop`.
#[must_use]
pub struct HostOwnerEpochGuard<'a> {
    _gate: MutexGuard<'a, ()>,
}

impl HostOwnerEpochCapability {
    /// Acquires a live guard while this capability is still backed by its
    /// unreleased owner lease.
    ///
    /// # Errors
    /// Returns [`WindowsAdapterError::IdentityMismatch`] after the lease has
    /// been released or dropped, or when the authority gate is poisoned.
    pub fn live_guard(&self) -> Result<HostOwnerEpochGuard<'_>, WindowsAdapterError> {
        let gate = self
            .authority
            .gate
            .lock()
            .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        if self.authority.revoked.load(Ordering::Acquire) {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(HostOwnerEpochGuard { _gate: gate })
    }
}

impl HostOwnerLease {
    /// Acquires the canonical installation-wide Host owner mutex.
    ///
    /// Existing ownership, unverified named objects, ACL/access failures, and
    /// any unclassified Win32 result are all returned as errors. The caller
    /// may proceed only on `Ok`, which means this process created and owns the
    /// mutex.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the mutex already exists, creation or
    /// ownership classification fails, or the platform is unsupported.
    pub fn acquire(installation: &PlatformHandle) -> Result<Self, HostOwnerLeaseError> {
        let name = host_owner_mutex_name(installation);
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{
                ERROR_ALREADY_EXISTS, ERROR_INVALID_PARAMETER, GetLastError,
            };
            use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
            use windows_sys::Win32::System::Threading::CreateMutexW;

            let wide_name = nul_terminated_wide(std::ffi::OsStr::new(&name)).map_err(|_| {
                HostOwnerLeaseError::CreationFailed {
                    win32_error: ERROR_INVALID_PARAMETER,
                }
            })?;
            let descriptor = OwnedSecurityDescriptor::for_host_owner().map_err(|_| {
                HostOwnerLeaseError::CreationFailed {
                    win32_error: unsafe { GetLastError() },
                }
            })?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(
                    |_| HostOwnerLeaseError::CreationFailed {
                        win32_error: ERROR_INVALID_PARAMETER,
                    },
                )?,
                lpSecurityDescriptor: descriptor.raw,
                bInheritHandle: 0,
            };
            // SAFETY: `wide_name`, `descriptor`, and `attributes` remain live
            // for the complete CreateMutexW call.  The returned handle is
            // transferred to this RAII owner exactly once.
            let handle = unsafe { CreateMutexW(&raw const attributes, 1, wide_name.as_ptr()) };
            let creation_error = unsafe { GetLastError() };
            if handle.is_null() {
                return Err(HostOwnerLeaseError::CreationFailed {
                    win32_error: creation_error,
                });
            }
            match creation_error {
                0 => Ok(Self {
                    handle,
                    owns: true,
                    name,
                    authority: Arc::new(HostLeaseAuthority::default()),
                }),
                ERROR_ALREADY_EXISTS => {
                    // Never wait on or join an object we did not create.  Its
                    // DACL and ownership history are not independently
                    // verified; a normal clean Host closes the last handle so
                    // the next start creates a fresh protected object.
                    if unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) } == 0 {
                        Err(HostOwnerLeaseError::OwnershipUncertain {
                            win32_error: unsafe { GetLastError() },
                        })
                    } else {
                        Err(HostOwnerLeaseError::ExistingObject)
                    }
                }
                win32_error => {
                    if unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) } == 0 {
                        Err(HostOwnerLeaseError::OwnershipUncertain {
                            win32_error: unsafe { GetLastError() },
                        })
                    } else {
                        Err(HostOwnerLeaseError::OwnershipUncertain { win32_error })
                    }
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = name;
            let _ = installation;
            Err(HostOwnerLeaseError::UnsupportedPlatform)
        }
    }

    /// Returns the exact canonical mutex name held by this lease.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether this capability was created for the exact installation
    /// identity supplied by the caller.
    #[must_use]
    pub fn is_for_installation(&self, installation: &PlatformHandle) -> bool {
        self.name == host_owner_mutex_name(installation)
    }

    /// Returns a Host-only activation capability while this owner lease is held.
    #[must_use]
    pub fn activation_capability(&self) -> HostOwnerEpochCapability {
        HostOwnerEpochCapability {
            authority: Arc::clone(&self.authority),
        }
    }

    /// Creates the inert capability used by provider-neutral tests on targets
    /// without a Windows owner mutex. Production Windows callers must obtain
    /// this value from [`Self::activation_capability`] instead.
    #[cfg(not(windows))]
    pub fn unsupported_platform_test_capability() -> HostOwnerEpochCapability {
        HostOwnerEpochCapability {
            authority: Arc::new(HostLeaseAuthority::default()),
        }
    }

    /// Releases the owner mutex after the caller has durably recorded a
    /// release-pending Host disposition. Drop remains a last-resort close for
    /// error paths; callers must finalize clean state only after `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns a typed error when releasing or closing the mutex fails, or
    /// when this operation is unavailable on the current platform.
    pub fn release(&mut self) -> Result<(), HostOwnerLeaseReleaseError> {
        // Serialize revocation with every derived Host or credential mutation.
        // A poisoned gate is still recovered so capability state is revoked
        // before touching the OS owner mutex.
        let _gate = self
            .authority
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.authority.revoked.store(true, Ordering::Release);
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
            use windows_sys::Win32::System::Threading::ReleaseMutex;
            if self.handle.is_null() {
                return Ok(());
            }
            // A failed ReleaseMutex must retain both ownership state and the
            // handle. Closing here would abandon the durable admission gate
            // and make a later retry impossible to classify safely.
            if self.owns && unsafe { ReleaseMutex(self.handle) } == 0 {
                return Err(HostOwnerLeaseReleaseError::ReleaseMutex {
                    win32_error: unsafe { GetLastError() },
                });
            }
            self.owns = false;
            if unsafe { CloseHandle(self.handle) } == 0 {
                return Err(HostOwnerLeaseReleaseError::CloseHandle {
                    win32_error: unsafe { GetLastError() },
                });
            }
            self.handle = std::ptr::null_mut();
            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err(HostOwnerLeaseReleaseError::UnsupportedPlatform)
        }
    }
}

#[cfg(windows)]
impl Drop for HostOwnerLease {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::ReleaseMutex;
        let _gate = self
            .authority
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.authority.revoked.store(true, Ordering::Release);
        if self.handle.is_null() {
            return;
        }
        if self.owns {
            // SAFETY: this process owns the mutex after fresh creation; the
            // handle remains valid until CloseHandle.
            let _ = unsafe { ReleaseMutex(self.handle) };
        }
        // SAFETY: this wrapper uniquely owns the handle until Drop.
        unsafe { CloseHandle(self.handle) };
    }
}

/// Returns the stable identity of one existing regular file without following
/// a reparse point.
///
/// The helper is intentionally narrow: it does not infer a source root,
/// canonicalize caller input, or replace the retained source-bundle contour.
/// It exists for producers that must bind a validated release artifact to the
/// exact file object before immutable publication.
///
/// # Errors
///
/// Returns [`ProtectedPathError::InvalidPath`] for a relative path,
/// [`ProtectedPathError::ReparsePoint`] for a non-file or reparse-point
/// target, [`ProtectedPathError::Io`] when the file cannot be opened or its
/// identity cannot be read, and [`ProtectedPathError::UnsupportedPlatform`]
/// on non-Windows targets.
pub fn file_identity_for_path(path: &Path) -> Result<FileIdentity, ProtectedPathError> {
    if !path.is_absolute() {
        return Err(ProtectedPathError::InvalidPath);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| ProtectedPathError::Io)?;
        let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ProtectedPathError::ReparsePoint);
        }
        file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(ProtectedPathError::UnsupportedPlatform)
    }
}

/// Reads the stable identity from one caller-retained file handle.  This
/// deliberately avoids reopening the associated pathname.
///
/// # Errors
///
/// Returns `Io` when Windows cannot query the handle identity, or
/// `UnsupportedPlatform` on non-Windows targets.
pub fn file_identity_for_open_handle(
    file: &std::fs::File,
) -> Result<FileIdentity, ProtectedPathError> {
    #[cfg(windows)]
    {
        file_identity_from_handle(file).map_err(|_| ProtectedPathError::Io)
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        Err(ProtectedPathError::UnsupportedPlatform)
    }
}

/// Opens one existing regular file without following a reparse point and
/// retains DELETE access for a later handle-bound disposition operation.
/// The returned identity belongs to the retained handle, not to a pathname
/// metadata query.
///
/// # Errors
///
/// Returns a typed protected-path error when the path is relative, missing,
/// a reparse point, not a regular file, or its stable identity cannot be
/// observed.
pub fn open_no_follow_file_for_delete(
    path: &Path,
) -> Result<(FileIdentity, std::fs::File), ProtectedPathError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        if !path.is_absolute() {
            return Err(ProtectedPathError::InvalidPath);
        }
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(FILE_GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(path).map_err(|_| ProtectedPathError::Io)?;
        let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ProtectedPathError::ReparsePoint);
        }
        if !metadata.is_file() {
            return Err(ProtectedPathError::InvalidPath);
        }
        let identity = file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)?;
        if identity.volume_serial_number == 0 || identity.file_index == 0 {
            return Err(ProtectedPathError::Io);
        }
        Ok((identity, file))
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(ProtectedPathError::UnsupportedPlatform)
    }
}

/// Opens one existing regular file read-only without following a reparse
/// point and retains the exact object identity for a caller's validation
/// contour. The handle deliberately does not request DELETE access.
///
/// # Errors
///
/// Returns a typed protected-path error when the path is relative, missing,
/// a reparse point, not a regular file, or its stable identity cannot be
/// observed.
pub fn open_no_follow_file(
    path: &Path,
) -> Result<(FileIdentity, std::fs::File), ProtectedPathError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        if !path.is_absolute() {
            return Err(ProtectedPathError::InvalidPath);
        }
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(FILE_GENERIC_READ)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(path).map_err(|_| ProtectedPathError::Io)?;
        let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ProtectedPathError::ReparsePoint);
        }
        if !metadata.is_file() {
            return Err(ProtectedPathError::InvalidPath);
        }
        let identity = file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)?;
        if identity.volume_serial_number == 0 || identity.file_index == 0 {
            return Err(ProtectedPathError::Io);
        }
        Ok((identity, file))
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(ProtectedPathError::UnsupportedPlatform)
    }
}

/// Creates one absent regular file without following a reparse point and
/// retains DELETE access plus the exact object identity from the create call.
/// This is the create-new counterpart of [`open_no_follow_file_for_delete`].
///
/// # Errors
///
/// Returns a typed protected-path error when the path is relative, already
/// exists, is a reparse point, is not a regular file, or its stable identity
/// cannot be observed.
pub fn create_no_follow_file_for_delete(
    path: &Path,
) -> Result<(FileIdentity, std::fs::File), ProtectedPathError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        if !path.is_absolute() {
            return Err(ProtectedPathError::InvalidPath);
        }
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(path).map_err(|_| ProtectedPathError::Io)?;
        let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ProtectedPathError::ReparsePoint);
        }
        if !metadata.is_file() {
            return Err(ProtectedPathError::InvalidPath);
        }
        let identity = file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)?;
        if identity.volume_serial_number == 0 || identity.file_index == 0 {
            return Err(ProtectedPathError::Io);
        }
        Ok((identity, file))
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(ProtectedPathError::UnsupportedPlatform)
    }
}

/// Opens one existing directory without following a reparse point and keeps
/// its parent-object identity pinned for the duration of the caller's
/// operation.
///
/// # Errors
///
/// Returns a typed protected-path error when the path is relative, missing,
/// a reparse point, not a directory, or its stable identity cannot be
/// observed.
pub fn open_no_follow_directory(
    path: &Path,
) -> Result<(FileIdentity, std::fs::File), ProtectedPathError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        if !path.is_absolute() {
            return Err(ProtectedPathError::InvalidPath);
        }
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .access_mode(FILE_GENERIC_READ)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(path).map_err(|_| ProtectedPathError::Io)?;
        let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ProtectedPathError::ReparsePoint);
        }
        if !metadata.is_dir() {
            return Err(ProtectedPathError::InvalidPath);
        }
        let identity = file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)?;
        if identity.volume_serial_number == 0 || identity.file_index == 0 {
            return Err(ProtectedPathError::Io);
        }
        Ok((identity, file))
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(ProtectedPathError::UnsupportedPlatform)
    }
}

/// Creates the Agent Bridge child directory only when absent, retaining the
/// returned object identity. Existing objects are reopened without following
/// reparse points and are never replaced. The child initially inherits the
/// canonical service-only Host contour; the elevated installer converges its
/// final traversal ACL later.
#[cfg(windows)]
pub fn ensure_agent_bridge_directory(
    host_state_root: &Path,
) -> Result<FileIdentity, WindowsAdapterError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ | FILE_ADD_SUBDIRECTORY)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let parent = options.open(host_state_root).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            WindowsAdapterError::NotFound
        } else if error.kind() == std::io::ErrorKind::PermissionDenied {
            WindowsAdapterError::PermissionDenied
        } else {
            WindowsAdapterError::Failed
        }
    })?;
    let metadata = parent.metadata().map_err(|_| WindowsAdapterError::Failed)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let child = match directory_publication::create_owned_directory_relative(
        &parent,
        "agent-bridge",
        std::ptr::null_mut(),
    ) {
        Ok(child) => child,
        Err(DirectoryPublicationError::AlreadyExists) => {
            directory_publication::open_owned_directory_relative(&parent, "agent-bridge")
                .map_err(|_| WindowsAdapterError::IdentityMismatch)?
        }
        Err(DirectoryPublicationError::ReparsePoint) => {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Err(_) => return Err(WindowsAdapterError::Failed),
    };
    let metadata = child.metadata().map_err(|_| WindowsAdapterError::Failed)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    file_identity_from_handle(&child).map_err(|_| WindowsAdapterError::Failed)
}

#[cfg(not(windows))]
pub fn ensure_agent_bridge_directory(
    host_state_root: &Path,
) -> Result<FileIdentity, WindowsAdapterError> {
    let _ = host_state_root;
    Err(WindowsAdapterError::Unavailable)
}

/// Deletes one retained regular file object by handle after checking its
/// exact volume/file identity.  The operation never re-resolves a pathname,
/// so a replacement at the former name cannot redirect deletion to a foreign
/// object.
///
/// The handle must have been opened with `DELETE` access.  Callers that cannot
/// retain a suitable handle must fail closed rather than fall back to
/// `remove_file(path)`.
///
/// # Errors
///
/// Returns a typed protected-path error when the handle is not a regular
/// non-reparse file, its identity differs from the expected object, or the
/// handle-bound disposition cannot be applied.
pub fn delete_owned_file_handle(
    file: std::fs::File,
    expected_identity: FileIdentity,
) -> Result<(), ProtectedPathError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FileDispositionInfo,
            SetFileInformationByHandle,
        };

        let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ProtectedPathError::ReparsePoint);
        }
        if file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)?
            != expected_identity
        {
            return Err(ProtectedPathError::InvalidPath);
        }
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        let ok = unsafe {
            // SAFETY: the caller supplied a live handle with DELETE access;
            // the disposition buffer has the documented layout and size.
            SetFileInformationByHandle(
                file.as_raw_handle().cast(),
                FileDispositionInfo,
                (&raw const disposition).cast(),
                u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                    .map_err(|_| ProtectedPathError::Io)?,
            )
        };
        if ok == 0 {
            return Err(ProtectedPathError::Io);
        }
        drop(file);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (file, expected_identity);
        Err(ProtectedPathError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
pub(crate) struct OwnedKernelHandle(pub(crate) windows_sys::Win32::Foundation::HANDLE);

// SAFETY: Windows kernel handles are process-global. This wrapper uniquely
// owns and closes its handle, so moving it between threads is sound.
#[cfg(windows)]
unsafe impl Send for OwnedKernelHandle {}

#[cfg(windows)]
impl OwnedKernelHandle {
    pub(crate) fn new(
        handle: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<Self, WindowsAdapterError> {
        if handle.is_null() {
            Err(last_windows_adapter_error())
        } else {
            Ok(Self(handle))
        }
    }

    pub(crate) fn into_file(self) -> std::fs::File {
        use std::os::windows::io::FromRawHandle;
        let handle = self.0;
        std::mem::forget(self);
        // SAFETY: unique ownership of the live handle moves into `File` once.
        unsafe { std::fs::File::from_raw_handle(handle) }
    }
}

#[cfg(windows)]
impl Drop for OwnedKernelHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns the handle until this Drop.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
struct OwnedSecurityDescriptor {
    raw: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
}

#[cfg(windows)]
impl OwnedSecurityDescriptor {
    fn for_job_owner() -> Result<Self, WindowsAdapterError> {
        Self::from_sddl("D:P(A;;GA;;;SY)(A;;GA;;;OW)")
    }

    fn for_host_owner() -> Result<Self, WindowsAdapterError> {
        Self::from_sddl("D:P(A;;GA;;;SY)(A;;GA;;;OW)")
    }

    /// Protected durable state is writable only by `LocalSystem` and the local
    /// Administrators group.  The descriptor is protected from inheriting a
    /// weaker parent DACL before it is applied to the opened no-follow handle.
    fn for_protected_storage() -> Result<Self, WindowsAdapterError> {
        // Use the concrete file-all mask because Windows expands generic `GA`
        // before storing a file-object DACL. The post-write byte proof below
        // must compare the descriptor that Windows actually persists.
        Self::from_sddl("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
    }

    fn for_installer_system_object(directory: bool) -> Result<Self, WindowsAdapterError> {
        let inheritance = if directory { "OICI" } else { "" };
        Self::from_sddl(&format!(
            "O:SYD:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)(A;{inheritance};FA;;;LS)"
        ))
    }

    /// Exact security descriptor for the installation-authority key root and
    /// immutable key slots.  This intentionally omits `LocalService` and all
    /// broad user principals: the signing seed is an installer authority, not
    /// a runtime service secret.
    #[cfg(windows)]
    fn for_installer_authority_key() -> Result<Self, WindowsAdapterError> {
        Self::from_sddl("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)")
    }

    fn for_local_service_host_marker() -> Result<Self, WindowsAdapterError> {
        // The marker is Host transaction authority, not administrator UI
        // state.  Granting BA full access lets an unrelated administrator
        // strand a LocalService credential by deleting or rewriting only the
        // marker.  Host (LocalService) and recovery-capable LocalSystem are
        // sufficient owners for this protected file.
        Self::from_sddl("O:LSD:P(A;;FA;;;SY)(A;;FA;;;LS)")
    }

    /// Exact protected service DACL for Host-owned Watchdog lifecycle control.
    /// SYSTEM and Administrators retain installer/OS authority; the resolved
    /// `EliotHost` service SID receives only the concrete minimal runtime mask.
    fn for_watchdog_host_control(host_service_sid: &str) -> Result<Self, WindowsAdapterError> {
        if !valid_service_sid_text(host_service_sid) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Self::from_sddl(&format!(
            "D:P(A;;0x000F01FF;;;SY)(A;;0x000F01FF;;;BA)(A;;0x{ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK:08X};;;{host_service_sid})"
        ))
    }

    fn for_user_owned_storage(sid: &str, directory: bool) -> Result<Self, WindowsAdapterError> {
        if !valid_sid_text(sid) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        // Bind the owner explicitly.  An elevated interactive token can use
        // BUILTIN\Administrators as its default owner even though its user SID
        // is still the intended owner of this per-user contour.
        // `FA` is the concrete file-all mask. Windows expands generic `GA`
        // before storing the DACL, so using `GA` would defeat byte proof.
        let inheritance = if directory { "OICI" } else { "" };
        Self::from_sddl(&format!(
            "O:{sid}D:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;{sid})"
        ))
    }

    fn dacl(&self) -> Result<*const windows_sys::Win32::Security::ACL, WindowsAdapterError> {
        use windows_sys::Win32::Security::GetSecurityDescriptorDacl;
        let mut present = 0;
        let mut dacl = std::ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: `self.raw` is the descriptor allocated by
        // ConvertStringSecurityDescriptorToSecurityDescriptorW and remains
        // valid for this call; all output pointers are valid locals.
        if unsafe {
            GetSecurityDescriptorDacl(
                self.raw,
                &raw mut present,
                &raw mut dacl,
                &raw mut defaulted,
            )
        } == 0
            || present == 0
            || dacl.is_null()
        {
            return Err(WindowsAdapterError::AclMismatch);
        }
        Ok(dacl.cast_const())
    }

    fn owner(&self) -> Result<windows_sys::Win32::Security::PSID, WindowsAdapterError> {
        use windows_sys::Win32::Security::GetSecurityDescriptorOwner;
        let mut owner = std::ptr::null_mut();
        let mut defaulted = 0;
        if unsafe { GetSecurityDescriptorOwner(self.raw, &raw mut owner, &raw mut defaulted) } == 0
            || owner.is_null()
        {
            return Err(WindowsAdapterError::AclMismatch);
        }
        Ok(owner)
    }

    fn from_sddl(sddl: &str) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let sddl = sddl
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut raw = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated and `raw` is a valid out pointer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(last_windows_adapter_error());
        }
        Ok(Self { raw })
    }
}

#[cfg(windows)]
impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: Win32 allocated the descriptor and this wrapper owns it.
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.raw.cast()) };
        }
    }
}

/// Windows implementation of the P-01 ports.
pub struct WindowsPlatform {
    root: PathBuf,
    #[cfg(windows)]
    _root_pin: std::fs::File,
}

impl WindowsPlatform {
    /// Binds the adapter to an absolute, existing, non-reparse work root.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPath` when the root is not absolute, existing, and
    /// non-reparse.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, PortError> {
        let root = root.into();
        validate_root(&root)?;
        #[cfg(windows)]
        let root_pin = pin_directory(&root).map_err(|_| PortError::InvalidPath)?;
        Ok(Self {
            root,
            #[cfg(windows)]
            _root_pin: root_pin,
        })
    }

    /// Returns the validated filesystem identity of a path below the work root.
    ///
    /// # Errors
    ///
    /// Returns a typed path or provider error when containment or identity
    /// validation cannot be established.
    pub fn file_identity(&self, path: &WorkScopePath) -> Result<FileIdentity, PortError> {
        let input = path.adapter_input();
        let full = self.resolve(&input)?;
        file_identity(&full).map_err(|_| PortError::Provider(provider_failed()))
    }

    /// Reads a process identity from one live query handle.
    ///
    /// The returned start time and image path are bound to the queried handle;
    /// callers must compare the complete value before reusing a PID.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error when Windows cannot open or inspect the
    /// process, including insufficient query privilege.
    pub fn process_identity(&self, process_id: u32) -> Result<ProcessIdentity, PortError> {
        if process_id == 0 {
            return Err(PortError::InvalidPath);
        }
        inspect_process_identity(process_id)
            .map_err(|error| PortError::Provider(provider_from_io(&error)))
    }

    /// Registers one validated ELIOT own-process service through SCM.
    ///
    /// This P-02-specific API deliberately does not reinterpret P-01's smaller
    /// `ServiceRequest::Register` shape. P-10 supplies this exact request at
    /// composition time. Existing services are never treated as matching
    /// configuration without a separate reconciliation step.
    ///
    /// # Errors
    /// Returns a typed adapter error for invalid input, permission denial or a
    /// pre-effect provider failure.
    pub fn register_service(
        &self,
        request: &ServiceRegistrationRequest,
    ) -> Result<ServiceRegistrationOutcome, WindowsAdapterError> {
        register_service(request)
    }

    /// Updates one existing canonical service and verifies the complete SCM
    /// configuration after the provider call.
    ///
    /// # Errors
    /// Returns a typed adapter error if the request cannot be admitted before
    /// the provider call.
    pub fn update_service_registration(
        &self,
        request: &ServiceRegistrationRequest,
    ) -> Result<ServiceRegistrationOutcome, WindowsAdapterError> {
        update_service_registration(request)
    }

    /// Deletes one canonical service and requires an `Absent` post-readback.
    ///
    /// # Errors
    /// Returns a typed adapter error if the request cannot be admitted before
    /// the provider call.
    pub fn delete_service_registration(
        &self,
        request: &ServiceRegistrationRequest,
    ) -> Result<ServiceRegistrationOutcome, WindowsAdapterError> {
        delete_service_registration(request)
    }

    /// Reads back the complete canonical registration without mutating SCM.
    ///
    /// # Errors
    ///
    /// This inspection preserves provider uncertainty in
    /// [`ServiceRegistrationInspection::Unknown`] rather than returning an
    /// error that a caller could accidentally reinterpret as absence.
    #[must_use]
    pub fn inspect_service_registration(
        &self,
        request: &ServiceRegistrationRequest,
    ) -> ServiceRegistrationInspection {
        inspect_service_registration(request)
    }

    /// Reads back the complete canonical registration and its current SCM
    /// process state without mutating the service.
    ///
    /// This is the mechanics observation used to reconcile a single service
    /// start across `Stopped`, `Starting`, and `Running`. A live PID is never
    /// accepted alone: creation time and image path are captured through the
    /// same process handle and compared with the approved registration image.
    #[must_use]
    pub fn inspect_service_registration_runtime(
        &self,
        request: &ServiceRegistrationRequest,
    ) -> ServiceRegistrationRuntimeInspection {
        inspect_service_registration_runtime(request)
    }

    /// Starts one exact canonical service at most once.
    ///
    /// The operation performs a fresh exact configuration/runtime admission,
    /// issues at most one `StartServiceW`, and immediately performs the same
    /// stable configuration/PID/start-time/image readback. A `Starting`
    /// result is returned as wait/reconcile state; callers must not issue a
    /// second start while it remains in progress.
    ///
    /// # Errors
    /// Returns a typed adapter error when the provider cannot be opened before
    /// the mutation boundary. A post-boundary ambiguity is preserved as
    /// [`ServiceStartOutcome::EffectUnknown`].
    pub fn start_service_registration(
        &self,
        request: &ServiceRegistrationRequest,
    ) -> Result<ServiceStartOutcome, WindowsAdapterError> {
        if request.bootstrap().is_none() {
            return Err(WindowsAdapterError::InvalidInput);
        }
        start_service_registration(request)
    }

    /// Stops one exact canonical service at most once for start-effect
    /// rollback. A caller must bind an observed runtime identity digest before
    /// a running service becomes eligible for the stop mutation.
    ///
    /// # Errors
    /// Returns a typed adapter error when the provider cannot be opened before
    /// the mutation boundary. A post-boundary ambiguity is preserved as
    /// [`ServiceStopOutcome::EffectUnknown`].
    pub fn stop_service_registration(
        &self,
        request: &ServiceRegistrationRequest,
    ) -> Result<ServiceStopOutcome, WindowsAdapterError> {
        if request.bootstrap().is_none() {
            return Err(WindowsAdapterError::InvalidInput);
        }
        stop_service_registration(request)
    }

    /// Publishes bytes by staging beside the destination and replacing it once.
    ///
    /// # Errors
    ///
    /// Returns a typed path or provider error when staging, replacement, or
    /// post-publication identity observation fails.
    pub fn publish_atomic(
        &self,
        path: &WorkScopePath,
        bytes: &[u8],
    ) -> Result<PublicationOutcome, PortError> {
        self.publish_atomic_outcome(path, bytes)
    }

    /// Publishes bytes and requires a fully observed receipt.
    ///
    /// Callers that cannot reconcile an externally visible effect must use
    /// [`Self::publish_atomic`] and preserve its `Unknown` variant.
    ///
    /// # Errors
    ///
    /// Returns a typed path/provider error when publication fails before the
    /// replacement is committed or when an unknown outcome is forced into a
    /// receipt-only call.
    pub fn publish_atomic_receipt(
        &self,
        path: &WorkScopePath,
        bytes: &[u8],
    ) -> Result<PublicationReceipt, PortError> {
        match self.publish_atomic(path, bytes)? {
            PublicationOutcome::Published(receipt) => Ok(receipt),
            PublicationOutcome::Unknown(_) => Err(PortError::Provider(unknown_provider())),
        }
    }

    /// Publishes bytes and preserves the post-commit unknown state.
    ///
    /// # Errors
    ///
    /// Returns a typed path or provider error before replacement. A successful
    /// replacement followed by an unobservable identity is returned as
    /// [`PublicationOutcome::Unknown`] rather than as a retryable error.
    pub fn publish_atomic_outcome(
        &self,
        path: &WorkScopePath,
        bytes: &[u8],
    ) -> Result<PublicationOutcome, PortError> {
        let input = path.adapter_input();
        let destination = self.resolve(&input)?;
        let parent = destination.parent().ok_or(PortError::InvalidPath)?;
        let parent_pin = pin_ancestors(&self.root, parent)?;
        let temporary = create_temporary(parent, bytes)?;
        let staged_identity = match file_identity(&temporary) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                return Err(PortError::Provider(provider_from_io(&error)));
            }
        };
        if let Err(error) = validate_destination(&destination) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        let result = replace_file(&temporary, &destination);
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result?;
        // MoveFileExW uses WRITE_THROUGH; flush the pinned directory when the
        // filesystem accepts directory flushes, without inventing a second
        // publication failure after the replacement has committed.
        flush_directory(&parent_pin);
        let identity = file_identity(&destination).map_err(|_| {
            // Replacement may already have committed. This is deliberately not
            // retried: the caller must reconcile the externally visible effect.
            PortError::Provider(unknown_provider())
        });
        Ok(match identity {
            Ok(identity) if identity == staged_identity => {
                PublicationOutcome::Published(PublicationReceipt { identity })
            }
            Ok(_) => PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::DestinationIdentityChanged,
                expected_identity: staged_identity,
            }),
            Err(_) => PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::PostCommitIdentityUnavailable,
                expected_identity: staged_identity,
            }),
        })
    }

    fn resolve(&self, input: &AdapterPathInput) -> Result<PathBuf, PortError> {
        let mut resolved = self.root.clone();
        for component in input.normalized_identity.split('/') {
            validate_component(component)?;
            resolved.push(component);
        }
        validate_containment(&self.root, &resolved)?;
        Ok(resolved)
    }

    fn resolve_component(&self, component: &str) -> Result<PathBuf, PortError> {
        validate_component(component)?;
        let path = self.root.join(component);
        validate_containment(&self.root, &path)?;
        Ok(path)
    }
}

/// Exact case-insensitive Windows basename matcher used by conservative
/// process enumeration. Directory components and prefixes never match.
#[must_use]
pub fn process_basename_matches(observed: &str, expected: &str) -> bool {
    std::path::Path::new(observed)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
}

/// Reports whether any process currently has the exact requested basename.
/// This helper deliberately does not infer ownership, path, or identity.
///
/// # Errors
///
/// Returns an adapter error for an invalid basename, an unavailable process
/// snapshot, or an unsupported platform.
pub fn any_running_process_named(basename: &str) -> Result<bool, WindowsAdapterError> {
    if basename.is_empty()
        || std::path::Path::new(basename)
            .file_name()
            .and_then(|v| v.to_str())
            != Some(basename)
    {
        return Err(WindowsAdapterError::InvalidInput);
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        };
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(last_windows_adapter_error());
        }
        let mut entry = PROCESSENTRY32W {
            dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>())
                .map_err(|_| WindowsAdapterError::Failed)?,
            ..Default::default()
        };
        let mut matched = false;
        let first = unsafe { Process32FirstW(snapshot, &raw mut entry) } != 0;
        let mut terminal_error = 0_u32;
        if first {
            loop {
                let length = entry
                    .szExeFile
                    .iter()
                    .position(|unit| *unit == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..length]);
                if process_basename_matches(&name, basename) {
                    matched = true;
                    break;
                }
                if unsafe { Process32NextW(snapshot, &raw mut entry) } == 0 {
                    terminal_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                    break;
                }
            }
        } else {
            terminal_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        }
        unsafe { CloseHandle(snapshot) };
        if matched || terminal_error == ERROR_NO_MORE_FILES {
            Ok(matched)
        } else {
            let error_code = i32::try_from(terminal_error).unwrap_or(i32::MAX);
            let error = std::io::Error::from_raw_os_error(error_code);
            Err(windows_adapter_from_io(&error))
        }
    }
    #[cfg(not(windows))]
    {
        let _ = basename;
        Err(WindowsAdapterError::Unavailable)
    }
}

/// Conservative fixed-name observation for the legacy Governor executable.
///
/// # Errors
///
/// Propagates process snapshot errors from [`any_running_process_named`].
pub fn is_eliot_governor_running() -> Result<bool, WindowsAdapterError> {
    any_running_process_named("eliot-governor.exe")
}

impl FilesystemPort for WindowsPlatform {
    fn execute(
        &mut self,
        request: &eliot_platform::FilesystemRequest,
    ) -> PortOutcome<FilesystemObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        let input = request.path.adapter_input();
        let path = match self.resolve(&input) {
            Ok(path) => path,
            Err(error) => return PortOutcome::Error(error),
        };
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return PortOutcome::Known(FilesystemObservation {
                    path: request.path.clone(),
                    kind: FileKind::Missing,
                    size: None,
                    content_digest: None,
                });
            }
            Err(error) => return inspect_failure(&error),
        };
        if is_reparse_point(&metadata) {
            return PortOutcome::Unknown(UnknownReason::Indeterminate);
        }
        let kind = if metadata.is_file() {
            FileKind::File
        } else if metadata.is_dir() {
            FileKind::Directory
        } else if metadata.file_type().is_symlink() {
            FileKind::Symlink
        } else {
            FileKind::Other
        };
        let observation = FilesystemObservation {
            path: request.path.clone(),
            kind,
            size: metadata.is_file().then_some(metadata.len()),
            content_digest: None,
        };
        match request.operation {
            FilesystemOperation::Stat => PortOutcome::Known(observation),
            FilesystemOperation::Read => PortOutcome::Partial {
                value: observation,
                missing: vec![handle("content_digest")],
            },
            FilesystemOperation::Write { .. } | FilesystemOperation::Remove => {
                PortOutcome::Unknown(UnknownReason::Unsupported)
            }
        }
    }
}

impl ServicePort for WindowsPlatform {
    fn execute(&mut self, request: &ServiceRequest) -> PortOutcome<ServiceObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        match request.operation {
            ServiceOperation::Inspect => inspect_service(request.service.as_str()),
            // P-01 deliberately carries no binary path, account or start-mode
            // registration configuration. Guessing those would fabricate SCM
            // authority, so registration remains a typed unsupported outcome.
            ServiceOperation::Register | ServiceOperation::Unregister => {
                PortOutcome::Unknown(UnknownReason::Unsupported)
            }
            ServiceOperation::Start | ServiceOperation::Stop => {
                mutate_service(request.service.as_str(), request.operation)
            }
        }
    }
}

impl ClockPort for WindowsPlatform {
    fn read(&mut self, request: &ClockRequest) -> PortOutcome<eliot_platform::ClockObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        let valid_time_ms = unix_millis(SystemTime::now());
        let monotonic_ns = Some(
            u64::try_from(
                monotonic_origin()
                    .elapsed()
                    .as_nanos()
                    .min(u128::from(u64::MAX)),
            )
            .unwrap_or(u64::MAX),
        );
        PortOutcome::Known(eliot_platform::ClockObservation {
            valid_time_ms,
            known_time_ms: valid_time_ms,
            transaction_sequence: None,
            monotonic_ns,
        })
    }
}

impl SecretPort for WindowsPlatform {
    fn inspect(
        &mut self,
        request: &SecretRequest,
    ) -> PortOutcome<eliot_platform::SecretObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        inspect_credential(request)
    }
}

impl NotificationPort for WindowsPlatform {
    fn deliver(&mut self, request: &NotificationRequest) -> PortOutcome<NotificationObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        // I11.6 normal delivery belongs to the interactive User Broker and a
        // WinUI/AppNotificationManager owner. This low-level adapter is not a
        // second toast authority; callers must keep the result unavailable
        // until that owner returns authenticated OS acceptance evidence.
        let _ = request;
        PortOutcome::Unknown(UnknownReason::Unsupported)
    }
}

impl WindowsPlatform {
    /// Delivers the narrowly scoped X-01 recovery banner. This is not the
    /// normal notification route: it is used only by the separately signed
    /// Watchdog fallback composition and requires a live, non-elevated user
    /// session plus a bounded shell callback observation.
    pub fn deliver_recovery_banner(
        &mut self,
        request: &NotificationRequest,
    ) -> PortOutcome<NotificationObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        if !interactive_non_elevated_session() {
            return PortOutcome::Unknown(UnknownReason::NotObserved);
        }
        match deliver_shell_notification(request) {
            Ok(true) => PortOutcome::Known(NotificationObservation {
                notification: request.notification.clone(),
                delivered: true,
            }),
            Ok(false) => PortOutcome::Unknown(UnknownReason::NotObserved),
            Err(_) => PortOutcome::Unknown(UnknownReason::Indeterminate),
        }
    }
}

/// Delivers one bounded Shell balloon and returns the observed API result.
///
/// The P-01 request contains only opaque notification/audience/digest handles,
/// so the adapter never treats caller text as a trusted title or body. The
/// Shell accepts the recovery banner through `NIM_MODIFY`; `true` means the
/// bounded callback pump observed `NIN_BALLOONSHOW`, not that a human clicked
/// or read the notification.
#[cfg(windows)]
fn deliver_shell_notification(_request: &NotificationRequest) -> Result<bool, WindowsAdapterError> {
    use std::mem::size_of;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::UI::Shell::{
        NIF_ICON, NIF_INFO, NIF_MESSAGE, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY,
        NOTIFYICONDATAW, Shell_NotifyIconW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, IDI_INFORMATION, LoadIconW, WM_APP, WS_EX_TOOLWINDOW,
        WS_POPUP,
    };

    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_TOOLWINDOW,
            windows_sys::core::w!("STATIC"),
            windows_sys::core::w!("Eliot notification"),
            WS_POPUP,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            null(),
        )
    };
    if hwnd.is_null() {
        return Ok(false);
    }

    let mut data = NOTIFYICONDATAW {
        cbSize: u32::try_from(size_of::<NOTIFYICONDATAW>())
            .map_err(|_| WindowsAdapterError::InvalidInput)?,
        hWnd: hwnd,
        uID: 1,
        uFlags: NIF_ICON | NIF_MESSAGE | NIF_INFO,
        uCallbackMessage: WM_APP + 1,
        hIcon: unsafe { LoadIconW(null_mut(), IDI_INFORMATION) },
        dwInfoFlags: NIIF_INFO,
        ..Default::default()
    };
    fill_utf16(&mut data.szTip, "Eliot");
    // P-01 carries opaque handles, not presentation text.  Keep the banner
    // useful without leaking audience or evidence identifiers into the
    // desktop shell; the canonical UI resolves those handles separately.
    fill_utf16(&mut data.szInfoTitle, "Eliot notification");
    fill_utf16(
        &mut data.szInfo,
        "Eliot has a notification requiring review. Open Eliot recovery status.",
    );
    // The union is intentionally written only after the structure has been
    // zero-initialized; this selects the documented balloon timeout member.
    data.Anonymous.uTimeout = 10_000;

    let added = unsafe { Shell_NotifyIconW(NIM_ADD, &raw const data) != 0 };
    if !added {
        unsafe {
            DestroyWindow(hwnd);
        }
        return Ok(false);
    }
    let accepted = unsafe { Shell_NotifyIconW(NIM_MODIFY, &raw const data) != 0 };
    let delivered = if accepted {
        wait_for_shell_balloon(hwnd, data.uCallbackMessage)
    } else {
        false
    };
    // Keep the icon and hidden window alive until the bounded callback wait;
    // deleting immediately emits NIN_BALLOONHIDE and would falsify delivery.
    unsafe {
        let _ = Shell_NotifyIconW(NIM_DELETE, &raw const data);
        DestroyWindow(hwnd);
    }
    Ok(delivered)
}

#[cfg(windows)]
fn wait_for_shell_balloon(hwnd: windows_sys::Win32::Foundation::HWND, callback: u32) -> bool {
    use std::time::{Duration, Instant};

    use windows_sys::Win32::UI::Shell::NIN_BALLOONSHOW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, TranslateMessage,
    };

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let mut message = MSG::default();
        let mut observed = false;
        while unsafe { PeekMessageW(&raw mut message, hwnd, 0, 0, PM_REMOVE) } != 0 {
            if message.message == callback
                && message.lParam == isize::try_from(NIN_BALLOONSHOW).unwrap_or_default()
            {
                observed = true;
            }
            unsafe {
                TranslateMessage(&raw const message);
                DispatchMessageW(&raw const message);
            }
        }
        if observed {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[cfg(not(windows))]
fn deliver_shell_notification(_request: &NotificationRequest) -> Result<bool, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn interactive_non_elevated_session() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let Ok(expectation) = current_process_named_pipe_expectation() else {
        return false;
    };
    if expectation.expected_session_id() == 0 {
        return false;
    }
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut length = 0_u32;
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>()).unwrap_or_default(),
            &raw mut length,
        ) != 0
    };
    unsafe {
        CloseHandle(token);
    }
    result && elevation.TokenIsElevated == 0
}

#[cfg(not(windows))]
const fn interactive_non_elevated_session() -> bool {
    false
}

fn fill_utf16(buffer: &mut [u16], value: &str) {
    let max = buffer.len().saturating_sub(1);
    let encoded = value.encode_utf16().take(max).collect::<Vec<_>>();
    buffer[..encoded.len()].copy_from_slice(&encoded);
    if let Some(terminator) = buffer.get_mut(encoded.len()) {
        *terminator = 0;
    }
}

impl SessionPort for WindowsPlatform {
    fn inspect(&mut self, request: &SessionRequest) -> PortOutcome<SessionObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        inspect_session(request)
    }
}

impl InstallationPort for WindowsPlatform {
    fn execute(&mut self, request: &InstallationRequest) -> PortOutcome<InstallationObservation> {
        if let Err(error) = request.validate() {
            return PortOutcome::Error(error);
        }
        if request.operation != InstallationOperation::Inspect {
            return PortOutcome::Unknown(UnknownReason::Unsupported);
        }
        for component in &request.components {
            if let Err(error) = validate_component(component.as_str()) {
                return PortOutcome::Error(error);
            }
        }
        let mut components = Vec::new();
        for component in &request.components {
            let path = match self.resolve_component(component.as_str()) {
                Ok(path) => path,
                Err(error) => return PortOutcome::Error(error),
            };
            let metadata = match std::fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return PortOutcome::Unknown(classify_unknown(&error)),
            };
            if is_reparse_point(&metadata) {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            if !metadata.is_file() {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            components.push(component.clone());
        }
        let state = if components.is_empty() {
            InstallationState::Absent
        } else if components.len() == request.components.len() {
            InstallationState::Present
        } else {
            InstallationState::Inconsistent
        };
        PortOutcome::Known(InstallationObservation {
            installation: request.installation.clone(),
            state,
            components,
        })
    }
}

fn handle(value: &str) -> eliot_platform::PlatformHandle {
    eliot_platform::PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
}

fn provider_failed() -> eliot_platform::ProviderError {
    eliot_platform::ProviderError {
        code: eliot_platform::ProviderErrorCode::Failed,
        retryable: false,
    }
}

fn inspect_failure(error: &std::io::Error) -> PortOutcome<FilesystemObservation> {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => {
            PortOutcome::Error(PortError::Provider(provider_from_io(error)))
        }
        _ => PortOutcome::Unknown(UnknownReason::Indeterminate),
    }
}

fn classify_unknown(error: &std::io::Error) -> UnknownReason {
    match error.kind() {
        std::io::ErrorKind::Unsupported => UnknownReason::Unsupported,
        _ => UnknownReason::Indeterminate,
    }
}

fn unknown_provider() -> eliot_platform::ProviderError {
    eliot_platform::ProviderError {
        code: eliot_platform::ProviderErrorCode::Unavailable,
        retryable: false,
    }
}

fn provider_from_io(error: &std::io::Error) -> eliot_platform::ProviderError {
    use std::io::ErrorKind;
    let code = match error.kind() {
        ErrorKind::PermissionDenied => eliot_platform::ProviderErrorCode::PermissionDenied,
        ErrorKind::NotFound => eliot_platform::ProviderErrorCode::Unavailable,
        ErrorKind::TimedOut => eliot_platform::ProviderErrorCode::Timeout,
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => {
            eliot_platform::ProviderErrorCode::Unavailable
        }
        _ => eliot_platform::ProviderErrorCode::Failed,
    };
    eliot_platform::ProviderError {
        code,
        retryable: matches!(
            code,
            eliot_platform::ProviderErrorCode::Unavailable
                | eliot_platform::ProviderErrorCode::Timeout
        ),
    }
}

fn unix_millis(time: SystemTime) -> Option<i64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
}

/// Computes a lowercase SHA-256 digest for cross-crate identity binding.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Observes bytes available to the caller on the volume containing `path`.
///
/// This is an observation only. Policy thresholds remain owned by the
/// installation contract, and every error must be treated as an unknown
/// outcome rather than as sufficient free space.
///
/// # Errors
///
/// Returns [`WindowsAdapterError::InvalidInput`] for a relative path and a
/// classified adapter error when Windows cannot observe the volume.
#[cfg(windows)]
pub fn observe_volume_free_space(path: &Path) -> Result<u64, WindowsAdapterError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    if !path.is_absolute() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut available = 0_u64;
    let result = unsafe {
        // SAFETY: `path` is NUL-terminated and `available` is a live writable
        // `u64`; the unused output pointers are explicitly null.
        GetDiskFreeSpaceExW(
            path.as_ptr(),
            &raw mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        return Err(last_windows_adapter_error());
    }
    Ok(available)
}

#[cfg(not(windows))]
pub fn observe_volume_free_space(path: &Path) -> Result<u64, WindowsAdapterError> {
    if !path.is_absolute() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    Err(WindowsAdapterError::Unavailable)
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn unique_suffix() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}-{}",
        std::process::id(),
        unix_millis(SystemTime::now()).unwrap_or_default(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

fn validate_component(value: &str) -> Result<(), PortError> {
    let path = WorkScopePath::new(value)?;
    if path.normalized_identity() != value || value.contains(':') {
        return Err(PortError::InvalidPath);
    }
    Ok(())
}

fn create_temporary(parent: &Path, bytes: &[u8]) -> Result<PathBuf, PortError> {
    for _ in 0..64 {
        let path = parent.join(format!(".eliot-atomic-{}", unique_suffix()));
        let result = create_new_file(&path, bytes);
        match result {
            Ok(()) => {
                #[cfg(windows)]
                {
                    let _protected = protected_path::open_protected_file(&path, false)
                        .map_err(|_| PortError::Provider(provider_failed()))?;
                }
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(PortError::Provider(provider_from_io(&error))),
        }
    }
    Err(PortError::Provider(eliot_platform::ProviderError {
        code: eliot_platform::ProviderErrorCode::Timeout,
        retryable: true,
    }))
}

#[cfg(windows)]
fn create_new_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staging entry is not a file",
        ));
    }
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(windows))]
fn create_new_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(windows)]
fn pin_directory(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "reparse directory",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn pin_ancestors(root: &Path, path: &Path) -> Result<Vec<std::fs::File>, PortError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| PortError::InvalidPath)?;
    let mut current = root.to_path_buf();
    let mut pins = vec![pin_directory(root).map_err(|_| PortError::InvalidPath)?];
    for component in relative.components() {
        current.push(component.as_os_str());
        pins.push(pin_directory(&current).map_err(|_| PortError::InvalidPath)?);
    }
    Ok(pins)
}

#[cfg(not(windows))]
fn pin_ancestors(_root: &Path, _path: &Path) -> Result<Vec<std::fs::File>, PortError> {
    Ok(Vec::new())
}

fn monotonic_origin() -> &'static std::time::Instant {
    static ORIGIN: OnceLock<std::time::Instant> = OnceLock::new();
    ORIGIN.get_or_init(std::time::Instant::now)
}

fn validate_root(root: &Path) -> Result<(), PortError> {
    if !root.is_absolute() || !root.is_dir() {
        return Err(PortError::InvalidPath);
    }
    if std::fs::symlink_metadata(root).map_or(true, |metadata| {
        metadata.file_type().is_symlink() || is_reparse_point(&metadata)
    }) {
        return Err(PortError::InvalidPath);
    }
    Ok(())
}

fn validate_containment(root: &Path, path: &Path) -> Result<(), PortError> {
    if !path.starts_with(root) {
        return Err(PortError::InvalidPath);
    }
    for ancestor in path.ancestors().take_while(|candidate| *candidate != root) {
        let metadata = match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(PortError::InvalidPath),
        };
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(PortError::InvalidPath);
        }
    }
    Ok(())
}

fn validate_destination(path: &Path) -> Result<(), PortError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if is_reparse_point(&metadata) || !metadata.is_file() => {
            Err(PortError::InvalidPath)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(PortError::Provider(provider_from_io(&error))),
    }
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn flush_directory(pins: &[std::fs::File]) {
    if let Some(directory) = pins.last() {
        let _ = directory.sync_all();
    }
}

#[cfg(not(windows))]
fn flush_directory(_pins: &[std::fs::File]) {}

#[cfg(windows)]
fn final_windows_path_from_handle(file: &std::fs::File) -> Result<PathBuf, ProtectedPathError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

    let handle = file.as_raw_handle().cast();
    let required = unsafe {
        // SAFETY: query call uses a live retained handle and no output buffer.
        GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, 0)
    };
    if required == 0 {
        return Err(protected_path_io_error(
            ProtectedPathStage::GetFinalPathNameByHandleW,
            &std::io::Error::last_os_error(),
        ));
    }
    let mut buffer =
        vec![0_u16; usize::try_from(required).map_err(|_| ProtectedPathError::Io)? + 1];
    let written = unsafe {
        // SAFETY: buffer is writable for the declared length and handle remains live.
        GetFinalPathNameByHandleW(
            handle,
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).map_err(|_| ProtectedPathError::Io)?,
            0,
        )
    };
    if written == 0 {
        return Err(protected_path_io_error(
            ProtectedPathStage::GetFinalPathNameByHandleW,
            &std::io::Error::last_os_error(),
        ));
    }
    if usize::try_from(written).map_err(|_| ProtectedPathError::Io)? >= buffer.len() {
        return Err(ProtectedPathError::Io);
    }
    let path = String::from_utf16(
        &buffer[..usize::try_from(written).map_err(|_| ProtectedPathError::Io)?],
    )
    .map_err(|_| ProtectedPathError::InvalidPath)?;
    normalize_final_windows_path_text(&path)
}

#[cfg(windows)]
fn normalize_final_windows_path_text(path: &str) -> Result<PathBuf, ProtectedPathError> {
    let normalized = if let Some(unc) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(dos) = path.strip_prefix(r"\\?\") {
        dos.to_owned()
    } else {
        path.to_owned()
    };
    let normalized = PathBuf::from(normalized);
    if !normalized.is_absolute() {
        return Err(ProtectedPathError::InvalidPath);
    }
    Ok(normalized)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> Result<(), PortError> {
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let source = wide(source);
    let destination = wide(destination);
    for attempt in 0..=40 {
        // SAFETY: both strings are NUL-terminated and remain alive for the call.
        let ok = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        let transient = matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_ACCESS_DENIED.cast_signed()
                    || code == ERROR_SHARING_VIOLATION.cast_signed()
        );
        if !transient || attempt == 40 {
            return Err(PortError::Provider(provider_from_io(&error)));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    unreachable!("bounded replacement loop always returns")
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> Result<(), PortError> {
    std::fs::rename(source, destination)
        .map_err(|error| PortError::Provider(provider_from_io(&error)))
}

#[cfg(windows)]
fn wide(value: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn valid_sid_text(value: &str) -> bool {
    let Some(tail) = value.strip_prefix("S-1-") else {
        return false;
    };
    let parts = tail.split('-').collect::<Vec<_>>();
    if parts.is_empty() || parts.len() > 16 || value.len() > 184 {
        return false;
    }
    parts.iter().enumerate().all(|(index, part)| {
        !part.is_empty()
            && (part == &"0" || !part.starts_with('0'))
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && if index == 0 {
                part.parse::<u64>()
                    .is_ok_and(|authority| authority <= 0x0000_FFFF_FFFF_FFFF)
            } else {
                part.parse::<u32>().is_ok()
            }
    })
}

fn valid_service_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|character| !character.is_control() && !matches!(character, '/' | '\\' | ','))
}

fn valid_display_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && value.chars().all(|character| !character.is_control())
}

fn canonical_runtime_service_display_name(name: &str) -> Option<&'static str> {
    match name {
        ELIOT_HOST_SERVICE_NAME => Some(ELIOT_HOST_SERVICE_DISPLAY_NAME),
        ELIOT_WATCHDOG_SERVICE_NAME => Some(ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME),
        _ => None,
    }
}

/// Quotes one argv element using the Windows command-line backslash rules.
/// The executable is always quoted; ordinary arguments are quoted only when
/// required by whitespace or an embedded quote.
#[cfg(windows)]
fn quote_service_os_argument(value: &std::ffi::OsStr, force: bool) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let raw = value.encode_wide().collect::<Vec<_>>();
    let needs_quotes = force
        || raw.is_empty()
        || raw
            .iter()
            .any(|unit| matches!(*unit, 9 | 10 | 11 | 12 | 13 | 32))
        || raw.contains(&(u16::from(b'"')));
    if !needs_quotes {
        return raw;
    }
    let mut quoted = Vec::with_capacity(raw.len() + 2);
    quoted.push(u16::from(b'"'));
    let mut backslashes = 0usize;
    for unit in raw {
        if unit == u16::from(b'\\') {
            backslashes += 1;
        } else if unit == u16::from(b'"') {
            quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2 + 1));
            quoted.push(unit);
            backslashes = 0;
        } else {
            quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
            quoted.push(unit);
            backslashes = 0;
        }
    }
    quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
    quoted.push(u16::from(b'"'));
    quoted
}

#[cfg(not(windows))]
fn quote_service_argument(value: &str, force: bool) -> String {
    let needs_quotes =
        force || value.is_empty() || value.chars().any(char::is_whitespace) || value.contains('"');
    if !needs_quotes {
        return value.to_owned();
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            quoted.push(character);
            backslashes = 0;
        } else {
            quoted.extend(std::iter::repeat_n('\\', backslashes));
            quoted.push(character);
            backslashes = 0;
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

#[allow(
    clippy::too_many_arguments,
    reason = "the digest input mirrors every QUERY_SERVICE_CONFIGW identity field"
)]
fn service_configuration_digest(
    binary: &[u16],
    display: &[u16],
    account: &[u16],
    service_type: u32,
    start_type: u32,
    error_control: u32,
    tag_id: u32,
    load_order_group: &[u16],
    dependencies: &[Vec<u16>],
    service_sid_type: u32,
) -> String {
    let mut bytes = Vec::new();
    for (tag, value) in [(b'b', binary), (b'd', display), (b'a', account)] {
        bytes.push(tag);
        bytes.extend((value.len() as u64).to_le_bytes());
        for unit in value {
            let normalized = if tag == b'a' {
                char::from_u32(u32::from(*unit))
                    .map_or(*unit, |character| character.to_ascii_lowercase() as u16)
            } else {
                *unit
            };
            bytes.extend(normalized.to_le_bytes());
        }
    }
    bytes.push(b'l');
    bytes.extend((load_order_group.len() as u64).to_le_bytes());
    bytes.extend(load_order_group.iter().flat_map(|unit| unit.to_le_bytes()));
    bytes.push(b'p');
    bytes.extend((dependencies.len() as u64).to_le_bytes());
    for dependency in dependencies {
        bytes.extend((dependency.len() as u64).to_le_bytes());
        bytes.extend(dependency.iter().flat_map(|unit| unit.to_le_bytes()));
    }
    for (tag, value) in [
        (b't', service_type),
        (b's', start_type),
        (b'e', error_control),
        (b'g', tag_id),
        (b'i', service_sid_type),
    ] {
        bytes.push(tag);
        bytes.extend(value.to_le_bytes());
    }
    sha256_hex(&bytes)
}

fn windows_adapter_from_io(error: &std::io::Error) -> WindowsAdapterError {
    #[cfg(windows)]
    if let Some(code) = error.raw_os_error() {
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND,
            ERROR_PATH_NOT_FOUND, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_TIMEOUT,
        };
        if matches!(
            code,
            value if value == ERROR_FILE_NOT_FOUND.cast_signed()
                || value == ERROR_PATH_NOT_FOUND.cast_signed()
                || value == ERROR_NOT_FOUND.cast_signed()
                || value == ERROR_SERVICE_DOES_NOT_EXIST.cast_signed()
        ) {
            return WindowsAdapterError::Unavailable;
        }
        if code == ERROR_ALREADY_EXISTS.cast_signed() {
            return WindowsAdapterError::AlreadyExists;
        }
        if code == ERROR_ACCESS_DENIED.cast_signed() {
            return WindowsAdapterError::PermissionDenied;
        }
        if code == ERROR_TIMEOUT.cast_signed() {
            return WindowsAdapterError::Timeout;
        }
    }
    match error.kind() {
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
            WindowsAdapterError::InvalidInput
        }
        std::io::ErrorKind::PermissionDenied => WindowsAdapterError::PermissionDenied,
        std::io::ErrorKind::NotFound => WindowsAdapterError::Unavailable,
        std::io::ErrorKind::AlreadyExists => WindowsAdapterError::AlreadyExists,
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset => {
            WindowsAdapterError::Unavailable
        }
        std::io::ErrorKind::TimedOut => WindowsAdapterError::Timeout,
        _ => WindowsAdapterError::Failed,
    }
}

#[cfg(windows)]
fn last_windows_adapter_error() -> WindowsAdapterError {
    windows_adapter_from_io(&std::io::Error::last_os_error())
}

#[cfg(not(windows))]
fn last_windows_adapter_error() -> WindowsAdapterError {
    WindowsAdapterError::Unavailable
}

#[cfg(windows)]
fn sid_to_string(sid: windows_sys::Win32::Security::PSID) -> Result<String, WindowsAdapterError> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 || text.is_null() {
        return Err(last_windows_adapter_error());
    }
    let mut length = 0_usize;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    let value = unsafe { std::ffi::OsString::from_wide(std::slice::from_raw_parts(text, length)) }
        .to_string_lossy()
        .into_owned();
    unsafe { LocalFree(text.cast()) };
    if valid_sid_text(&value) {
        Ok(value)
    } else {
        Err(WindowsAdapterError::Failed)
    }
}

/// Resolves the exact deterministic SID for one canonical ELIOT SCM service.
///
/// The account alias is used only as an input to `LookupAccountNameW`; callers
/// receive and persist the canonical `S-1-5-80-...` SID string. No DPAPI-NG
/// descriptor is ever built from the alias.
#[cfg(windows)]
pub fn resolve_service_sid(service_name: &str) -> Result<String, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError};
    use windows_sys::Win32::Security::{IsValidSid, LookupAccountNameW, SID_NAME_USE};
    if !canonical_runtime_service_name(service_name) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let account = format!("NT SERVICE\\{service_name}")
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut sid_bytes = 0_u32;
    let mut domain_chars = 0_u32;
    let mut sid_use: SID_NAME_USE = 0;
    let first = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            std::ptr::null_mut(),
            &raw mut sid_bytes,
            std::ptr::null_mut(),
            &raw mut domain_chars,
            &raw mut sid_use,
        )
    };
    if first != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || sid_bytes == 0 {
        return Err(last_windows_adapter_error());
    }
    let mut sid = vec![0_u8; usize::try_from(sid_bytes).map_err(|_| WindowsAdapterError::Failed)?];
    let domain_len = usize::try_from(domain_chars).map_err(|_| WindowsAdapterError::Failed)?;
    let mut domain = vec![0_u16; domain_len.max(1)];
    if unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &raw mut sid_bytes,
            domain.as_mut_ptr(),
            &raw mut domain_chars,
            &raw mut sid_use,
        )
    } == 0
        || unsafe { IsValidSid(sid.as_ptr().cast_mut().cast()) } == 0
    {
        return Err(last_windows_adapter_error());
    }
    let sid = sid_to_string(sid.as_mut_ptr().cast())?;
    if !valid_service_sid_text(&sid) {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(sid)
}

#[cfg(not(windows))]
pub fn resolve_service_sid(_service_name: &str) -> Result<String, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

/// Resolves an explicitly selected Windows account name to its canonical SID.
///
/// The account text is lookup input only.  The returned value is serialized
/// from the OS-owned SID object and is the only identity suitable for an
/// installation profile; callers must never persist the account alias itself.
#[cfg(windows)]
pub fn resolve_account_sid(account_name: &str) -> Result<String, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError};
    use windows_sys::Win32::Security::{IsValidSid, LookupAccountNameW, SID_NAME_USE};

    if account_name.trim().is_empty()
        || account_name.chars().any(char::is_control)
        || account_name.encode_utf16().any(|unit| unit == 0)
        || account_name.len() > 512
    {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let account = account_name
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut sid_bytes = 0_u32;
    let mut domain_chars = 0_u32;
    let mut sid_use: SID_NAME_USE = 0;
    let first = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            std::ptr::null_mut(),
            &raw mut sid_bytes,
            std::ptr::null_mut(),
            &raw mut domain_chars,
            &raw mut sid_use,
        )
    };
    if first != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || sid_bytes == 0 {
        return Err(last_windows_adapter_error());
    }
    // Windows SIDs are small; reject a hostile size before allocation.
    if sid_bytes > 68 * 1024 || domain_chars > 32 * 1024 {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let mut sid = vec![0_u8; usize::try_from(sid_bytes).map_err(|_| WindowsAdapterError::Failed)?];
    let mut domain = vec![0_u16; usize::try_from(domain_chars).unwrap_or(0).max(1)];
    if unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &raw mut sid_bytes,
            domain.as_mut_ptr(),
            &raw mut domain_chars,
            &raw mut sid_use,
        )
    } == 0
        || unsafe { IsValidSid(sid.as_ptr().cast_mut().cast()) } == 0
    {
        return Err(last_windows_adapter_error());
    }
    let resolved = sid_to_string(sid.as_mut_ptr().cast())?;
    if !valid_sid_text(&resolved) {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(resolved)
}

#[cfg(not(windows))]
pub fn resolve_account_sid(_account_name: &str) -> Result<String, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

fn valid_service_sid_text(value: &str) -> bool {
    valid_sid_text(value)
        && value
            .strip_prefix("S-1-5-80-")
            .is_some_and(|tail| tail.split('-').count() == 5)
}

#[cfg(windows)]
fn set_service_sid_type(
    service: windows_sys::Win32::Foundation::HANDLE,
    sid_type: ServiceSidType,
) -> bool {
    use windows_sys::Win32::System::Services::{
        ChangeServiceConfig2W, SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_SID_INFO,
    };
    let info = SERVICE_SID_INFO {
        dwServiceSidType: sid_type.raw(),
    };
    unsafe {
        ChangeServiceConfig2W(
            service,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            (&raw const info).cast(),
        ) != 0
    }
}

/// Computes the canonical digest of the exact protected Watchdog service DACL
/// for one resolved `EliotHost` service SID.
///
/// The physical readback must first prove byte equality with the same DACL;
/// this portable semantic digest then lets durable installer records reject a
/// SID, mask, protection-mode or administrator/SYSTEM-rights substitution.
///
/// # Errors
///
/// Returns [`WindowsAdapterError::InvalidInput`] unless `host_service_sid` is
/// an exact service-SID string.
pub fn watchdog_service_security_descriptor_digest(
    host_service_sid: &str,
) -> Result<String, WindowsAdapterError> {
    if !valid_service_sid_text(host_service_sid) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    Ok(sha256_hex(
        format!(
            "eliot-watchdog-service-dacl:v1\0protected\0SY:000F01FF\0BA:000F01FF\0{host_service_sid}:{ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK:08X}"
        )
        .as_bytes(),
    ))
}

#[cfg(windows)]
fn service_registration_mutation_access(request: &ServiceRegistrationRequest) -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};
    use windows_sys::Win32::System::Services::{
        SERVICE_CHANGE_CONFIG, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    };

    SERVICE_CHANGE_CONFIG
        | SERVICE_QUERY_CONFIG
        | SERVICE_QUERY_STATUS
        | READ_CONTROL
        | if request.requires_host_service_control_grant() {
            WRITE_DAC
        } else {
            0
        }
}

#[cfg(windows)]
fn read_watchdog_host_control_grant(
    service: windows_sys::Win32::Foundation::HANDLE,
    request: &ServiceRegistrationRequest,
) -> Result<Option<ServiceControlGrantReadback>, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_SERVICE};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, PSECURITY_DESCRIPTOR,
        SE_DACL_PROTECTED,
    };

    if !request.requires_host_service_control_grant() {
        return Ok(None);
    }
    let host_service_sid = resolve_service_sid(ELIOT_HOST_SERVICE_NAME)?;
    let expected = OwnedSecurityDescriptor::for_watchdog_host_control(&host_service_sid)?;
    let expected_dacl = expected.dacl()?;
    let mut actual_dacl = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // `PROTECTED_DACL_SECURITY_INFORMATION` is a SetSecurityInfo-only flag.
    // Query the DACL under READ_CONTROL, then prove protection from the
    // returned descriptor's `SE_DACL_PROTECTED` control bit below.
    let status = unsafe {
        GetSecurityInfo(
            service,
            SE_SERVICE,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut actual_dacl,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() || actual_dacl.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(if status == ERROR_ACCESS_DENIED {
            WindowsAdapterError::PermissionDenied
        } else {
            WindowsAdapterError::Failed
        });
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    let protected = unsafe {
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) != 0
            && control & SE_DACL_PROTECTED != 0
    };
    let dacl_matches = unsafe {
        (*actual_dacl).AclSize == (*expected_dacl).AclSize
            && std::slice::from_raw_parts(
                actual_dacl.cast::<u8>(),
                usize::from((*actual_dacl).AclSize),
            ) == std::slice::from_raw_parts(
                expected_dacl.cast::<u8>(),
                usize::from((*expected_dacl).AclSize),
            )
    };
    let digest = watchdog_service_security_descriptor_digest(&host_service_sid);
    unsafe { LocalFree(descriptor.cast()) };
    if !protected || !dacl_matches {
        return Err(WindowsAdapterError::AclMismatch);
    }
    ServiceControlGrantReadback::new(
        ELIOT_HOST_SERVICE_NAME,
        host_service_sid,
        ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
        digest?,
    )
    .map(Some)
}

#[cfg(windows)]
fn install_watchdog_host_control_grant(
    service: windows_sys::Win32::Foundation::HANDLE,
    request: &ServiceRegistrationRequest,
) -> Result<Option<ServiceControlGrantReadback>, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{SE_SERVICE, SetSecurityInfo};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    if !request.requires_host_service_control_grant() {
        return Ok(None);
    }
    let host_service_sid = resolve_service_sid(ELIOT_HOST_SERVICE_NAME)?;
    let expected = OwnedSecurityDescriptor::for_watchdog_host_control(&host_service_sid)?;
    let status = unsafe {
        SetSecurityInfo(
            service,
            SE_SERVICE,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            expected.dacl()?,
            std::ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(WindowsAdapterError::PermissionDenied);
    }
    read_watchdog_host_control_grant(service, request)
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "creation, exact DACL installation and authoritative readback form one fail-closed SCM effect"
)]
fn register_service(
    request: &ServiceRegistrationRequest,
) -> Result<ServiceRegistrationOutcome, WindowsAdapterError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{ERROR_SERVICE_EXISTS, ERROR_SERVICE_MARKED_FOR_DELETE};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, CreateServiceW, OpenSCManagerW, SC_MANAGER_CREATE_SERVICE,
        SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_ERROR_NORMAL,
        SERVICE_WIN32_OWN_PROCESS,
    };

    if request.bootstrap().is_none() {
        return Err(WindowsAdapterError::InvalidInput);
    }

    match inspect_service_registration(request) {
        ServiceRegistrationInspection::Matching {
            observation,
            control_grant,
        } => {
            return Ok(ServiceRegistrationOutcome::PreexistingMatching {
                observation,
                control_grant,
            });
        }
        ServiceRegistrationInspection::Mismatched => {
            return Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation);
        }
        ServiceRegistrationInspection::Unknown => {
            return Ok(ServiceRegistrationOutcome::EffectUnknown);
        }
        ServiceRegistrationInspection::Absent => {}
    }
    let wide_text = |value: &OsStr| value.encode_wide().chain(Some(0)).collect::<Vec<_>>();
    let service_name = wide_text(OsStr::new(request.service_name()));
    let display_name = wide_text(OsStr::new(request.display_name()));
    let binary_command = request
        .binary_command_wide()
        .into_iter()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let account = match request.account() {
        ServiceAccount::LocalSystem => None,
        ServiceAccount::LocalService => Some(wide_text(OsStr::new("NT AUTHORITY\\LocalService"))),
        ServiceAccount::NetworkService => {
            Some(wide_text(OsStr::new("NT AUTHORITY\\NetworkService")))
        }
    };
    let account_ptr = account
        .as_ref()
        .map_or(std::ptr::null(), std::vec::Vec::as_ptr);
    let start_type = match request.start_mode() {
        ServiceStartMode::Automatic => SERVICE_AUTO_START,
        ServiceStartMode::Demand => SERVICE_DEMAND_START,
        ServiceStartMode::Disabled => SERVICE_DISABLED,
    };
    let manager = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_CREATE_SERVICE,
        )
    };
    if manager.is_null() {
        return Err(last_windows_adapter_error());
    }
    let desired_access = service_registration_mutation_access(request);
    let service = unsafe {
        CreateServiceW(
            manager,
            service_name.as_ptr(),
            display_name.as_ptr(),
            desired_access,
            SERVICE_WIN32_OWN_PROCESS,
            start_type,
            SERVICE_ERROR_NORMAL,
            binary_command.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            account_ptr,
            std::ptr::null(),
        )
    };
    if service.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { CloseServiceHandle(manager) };
        if matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_SERVICE_EXISTS.cast_signed()
                    || code == ERROR_SERVICE_MARKED_FOR_DELETE.cast_signed()
        ) {
            // A concurrent creator is not transaction ownership.  Preserve
            // the ambiguity so the durable installer cannot adopt or delete
            // a service it did not create.
            return Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation);
        }
        return Err(windows_adapter_from_io(&error));
    }
    if !set_service_sid_type(service, request.service_sid_type()) {
        unsafe {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
        return Ok(ServiceRegistrationOutcome::EffectUnknown);
    }
    if install_watchdog_host_control_grant(service, request).is_err() {
        unsafe {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
        return Ok(ServiceRegistrationOutcome::EffectUnknown);
    }
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    match inspect_service_registration(request) {
        ServiceRegistrationInspection::Matching {
            observation,
            control_grant,
        } => Ok(ServiceRegistrationOutcome::CreatedNow {
            observation,
            control_grant,
        }),
        ServiceRegistrationInspection::Absent
        | ServiceRegistrationInspection::Mismatched
        | ServiceRegistrationInspection::Unknown => Ok(ServiceRegistrationOutcome::EffectUnknown),
    }
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    reason = "configuration replacement, DACL replacement and exact readback form one fail-closed SCM effect"
)]
fn update_service_registration(
    request: &ServiceRegistrationRequest,
) -> Result<ServiceRegistrationOutcome, WindowsAdapterError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Services::{
        ChangeServiceConfigW, CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, SERVICE_WIN32_OWN_PROCESS,
    };
    if request.bootstrap().is_none() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let Some(expected_current) = request.expected_current() else {
        return Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation);
    };
    if expected_current.service_name() != request.service_name() {
        return Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation);
    }
    let wide = |value: &str| {
        OsStr::new(value)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>()
    };
    let name = wide(request.service_name());
    let display = wide(request.display_name());
    let command = request
        .binary_command_wide()
        .into_iter()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let account = wide("NT AUTHORITY\\LocalService");
    let empty_load_order_group = [0_u16];
    let empty_dependencies = [0_u16, 0_u16];
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Ok(ServiceRegistrationOutcome::EffectUnknown);
    }
    let desired_access = service_registration_mutation_access(request);
    let service = unsafe { OpenServiceW(manager, name.as_ptr(), desired_access) };
    if service.is_null() {
        unsafe { CloseServiceHandle(manager) };
        return Ok(ServiceRegistrationOutcome::EffectUnknown);
    }
    let Some(configuration) = query_service_configuration(service) else {
        unsafe {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
        return Ok(ServiceRegistrationOutcome::EffectUnknown);
    };
    if !service_current_matches(request, expected_current, &configuration) {
        unsafe {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
        return Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation);
    }
    let changed = unsafe {
        ChangeServiceConfigW(
            service,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            empty_load_order_group.as_ptr(),
            std::ptr::null_mut(),
            empty_dependencies.as_ptr(),
            account.as_ptr(),
            std::ptr::null(),
            display.as_ptr(),
        )
    };
    let sid_changed = changed != 0 && set_service_sid_type(service, request.service_sid_type());
    let grant_changed =
        sid_changed && install_watchdog_host_control_grant(service, request).is_ok();
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    if !grant_changed {
        return Ok(ServiceRegistrationOutcome::EffectUnknown);
    }
    match inspect_service_registration(request) {
        ServiceRegistrationInspection::Matching {
            observation,
            control_grant,
        } => Ok(ServiceRegistrationOutcome::Updated {
            observation,
            control_grant,
        }),
        ServiceRegistrationInspection::Absent
        | ServiceRegistrationInspection::Mismatched
        | ServiceRegistrationInspection::Unknown => Ok(ServiceRegistrationOutcome::EffectUnknown),
    }
}

#[cfg(not(windows))]
fn update_service_registration(
    _request: &ServiceRegistrationRequest,
) -> Result<ServiceRegistrationOutcome, WindowsAdapterError> {
    Ok(ServiceRegistrationOutcome::EffectUnknown)
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)]
fn delete_service_registration(
    request: &ServiceRegistrationRequest,
) -> Result<ServiceRegistrationOutcome, WindowsAdapterError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, DeleteService, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
        SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    };
    if request.bootstrap().is_none() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let Some(expected_current) = request.expected_current() else {
        return Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation);
    };
    if expected_current.service_name() != request.service_name() {
        return Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation);
    }
    let name = std::ffi::OsStr::new(request.service_name())
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Ok(ServiceRegistrationOutcome::EffectUnknown);
    }
    let service = unsafe {
        OpenServiceW(
            manager,
            name.as_ptr(),
            0x0001_0000 | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )
    };
    if service.is_null() {
        unsafe { CloseServiceHandle(manager) };
        return Ok(ServiceRegistrationOutcome::EffectUnknown);
    }
    let Some(configuration) = query_service_configuration(service) else {
        unsafe {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
        return Ok(ServiceRegistrationOutcome::EffectUnknown);
    };
    if !service_current_matches(request, expected_current, &configuration) {
        unsafe {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
        return Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation);
    }
    let deleted = unsafe { DeleteService(service) };
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    if deleted == 0 {
        return Ok(ServiceRegistrationOutcome::EffectUnknown);
    }
    match inspect_service_registration(request) {
        ServiceRegistrationInspection::Absent => Ok(ServiceRegistrationOutcome::Deleted),
        ServiceRegistrationInspection::Matching { .. }
        | ServiceRegistrationInspection::Mismatched
        | ServiceRegistrationInspection::Unknown => Ok(ServiceRegistrationOutcome::EffectUnknown),
    }
}

#[cfg(not(windows))]
fn delete_service_registration(
    _request: &ServiceRegistrationRequest,
) -> Result<ServiceRegistrationOutcome, WindowsAdapterError> {
    Ok(ServiceRegistrationOutcome::EffectUnknown)
}

fn canonical_runtime_service_name(name: &str) -> bool {
    matches!(name, ELIOT_HOST_SERVICE_NAME | ELIOT_WATCHDOG_SERVICE_NAME)
}

#[cfg(test)]
fn service_readback_is_acceptable(readback: &ServiceRegistrationInspection) -> bool {
    matches!(readback, ServiceRegistrationInspection::Matching { .. })
}

#[cfg(windows)]
#[derive(Clone)]
struct ServiceConfigurationReadback {
    binary: Vec<u16>,
    display: Vec<u16>,
    account: Vec<u16>,
    load_order_group: Vec<u16>,
    dependencies: Vec<Vec<u16>>,
    service_type: u32,
    start_type: u32,
    error_control: u32,
    tag_id: u32,
    service_sid_type: u32,
}

#[cfg(windows)]
fn exact_service_configuration_matches(
    request: &ServiceRegistrationRequest,
    configuration: &ServiceConfigurationReadback,
) -> bool {
    let expected_account = utf16_text("NT AUTHORITY\\LocalService");
    configuration.service_type == 0x0000_0010
        && configuration.start_type == 0x0000_0002
        && configuration.error_control == 0x0000_0001
        && configuration.tag_id == 0
        && configuration.binary == request.binary_command_wide()
        && configuration.display == utf16_text(request.display_name())
        && configuration.load_order_group.is_empty()
        && configuration.dependencies.is_empty()
        && utf16_eq_ignore_ascii_case(&configuration.account, &expected_account)
        && configuration.service_sid_type == request.service_sid_type().raw()
}

#[cfg(windows)]
fn service_current_matches(
    request: &ServiceRegistrationRequest,
    expected: &ServiceRegistrationCurrent,
    configuration: &ServiceConfigurationReadback,
) -> bool {
    expected.service_name() == request.service_name()
        && service_configuration_digest(
            &configuration.binary,
            &configuration.display,
            &configuration.account,
            configuration.service_type,
            configuration.start_type,
            configuration.error_control,
            configuration.tag_id,
            &configuration.load_order_group,
            &configuration.dependencies,
            configuration.service_sid_type,
        ) == expected.configuration_digest()
}

fn utf16_eq_ignore_ascii_case(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            char::from_u32(u32::from(*left))
                .zip(char::from_u32(u32::from(*right)))
                .is_some_and(|(left, right)| left.eq_ignore_ascii_case(&right))
        })
}

#[cfg(windows)]
fn query_service_configuration(
    service: windows_sys::Win32::Foundation::HANDLE,
) -> Option<ServiceConfigurationReadback> {
    use windows_sys::Win32::System::Services::{QUERY_SERVICE_CONFIGW, QueryServiceConfigW};
    let mut required = 0;
    unsafe {
        QueryServiceConfigW(service, std::ptr::null_mut(), 0, &raw mut required);
    }
    if required == 0 {
        return None;
    }
    let config_size = std::mem::size_of::<QUERY_SERVICE_CONFIGW>();
    let buffer_bytes = required as usize;
    if buffer_bytes < config_size {
        return None;
    }
    let words = buffer_bytes.saturating_add(config_size - 1) / config_size;
    let mut buffer = vec![QUERY_SERVICE_CONFIGW::default(); words];
    if unsafe { QueryServiceConfigW(service, buffer.as_mut_ptr(), required, &raw mut required) }
        == 0
    {
        return None;
    }
    let config = &buffer[0];
    let buffer_start = buffer.as_ptr().cast::<u8>();
    Some(ServiceConfigurationReadback {
        binary: service_config_wide(config.lpBinaryPathName, buffer_start, buffer_bytes)?,
        display: service_config_wide(config.lpDisplayName, buffer_start, buffer_bytes)?,
        account: service_config_wide(config.lpServiceStartName, buffer_start, buffer_bytes)?,
        load_order_group: service_config_wide_or_empty(
            config.lpLoadOrderGroup,
            buffer_start,
            buffer_bytes,
        )?,
        dependencies: service_config_multi_sz(config.lpDependencies, buffer_start, buffer_bytes)?,
        service_type: config.dwServiceType,
        start_type: config.dwStartType,
        error_control: config.dwErrorControl,
        tag_id: config.dwTagId,
        service_sid_type: query_service_sid_type(service)?,
    })
}

#[cfg(windows)]
fn query_service_sid_type(service: windows_sys::Win32::Foundation::HANDLE) -> Option<u32> {
    use windows_sys::Win32::System::Services::{
        QueryServiceConfig2W, SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_SID_INFO,
        SERVICE_SID_TYPE_NONE, SERVICE_SID_TYPE_UNRESTRICTED,
    };
    let mut info = SERVICE_SID_INFO::default();
    let mut required = 0_u32;
    let size = u32::try_from(std::mem::size_of::<SERVICE_SID_INFO>()).ok()?;
    if unsafe {
        QueryServiceConfig2W(
            service,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            (&raw mut info).cast(),
            size,
            &raw mut required,
        )
    } == 0
        || !matches!(
            info.dwServiceSidType,
            SERVICE_SID_TYPE_NONE | SERVICE_SID_TYPE_UNRESTRICTED
        )
    {
        return None;
    }
    Some(info.dwServiceSidType)
}

#[cfg(windows)]
fn service_config_buffer_tail_words(
    pointer: *const u16,
    buffer_start: *const u8,
    buffer_bytes: usize,
) -> Option<usize> {
    let start = buffer_start as usize;
    let end = start.checked_add(buffer_bytes)?;
    let pointer_address = pointer as usize;
    if pointer_address < start
        || pointer_address >= end
        || !pointer_address.is_multiple_of(std::mem::align_of::<u16>())
    {
        return None;
    }
    let remaining_bytes = end.checked_sub(pointer_address)?;
    if !remaining_bytes.is_multiple_of(std::mem::size_of::<u16>()) {
        return None;
    }
    Some(remaining_bytes / std::mem::size_of::<u16>())
}

#[cfg(windows)]
fn service_config_wide(
    pointer: *const u16,
    buffer_start: *const u8,
    buffer_bytes: usize,
) -> Option<Vec<u16>> {
    if pointer.is_null() {
        return None;
    }
    let bounded = unsafe {
        std::slice::from_raw_parts(
            pointer,
            service_config_buffer_tail_words(pointer, buffer_start, buffer_bytes)?,
        )
    };
    let length = bounded.iter().position(|unit| *unit == 0)?;
    Some(bounded[..length].to_vec())
}

#[cfg(windows)]
fn service_config_wide_or_empty(
    pointer: *const u16,
    buffer_start: *const u8,
    buffer_bytes: usize,
) -> Option<Vec<u16>> {
    if pointer.is_null() {
        Some(Vec::new())
    } else {
        service_config_wide(pointer, buffer_start, buffer_bytes)
    }
}

#[cfg(windows)]
fn service_config_multi_sz(
    pointer: *const u16,
    buffer_start: *const u8,
    buffer_bytes: usize,
) -> Option<Vec<Vec<u16>>> {
    if pointer.is_null() {
        return Some(Vec::new());
    }
    let bounded = unsafe {
        std::slice::from_raw_parts(
            pointer,
            service_config_buffer_tail_words(pointer, buffer_start, buffer_bytes)?,
        )
    };
    let mut dependencies = Vec::new();
    let mut offset = 0usize;
    loop {
        let tail = bounded.get(offset..)?;
        if tail.first() == Some(&0) {
            if !dependencies.is_empty() || tail.get(1) == Some(&0) {
                return Some(dependencies);
            }
            return None;
        }
        let length = tail.iter().position(|unit| *unit == 0)?;
        dependencies.push(tail[..length].to_vec());
        offset = offset.checked_add(length)?.checked_add(1)?;
    }
}

#[cfg(windows)]
fn classify_service_runtime_observation(
    request: &ServiceRegistrationRequest,
    state: ServiceState,
    checkpoint: u32,
    wait_hint_ms: u32,
    process_id: u32,
    process: Option<ProcessIdentity>,
) -> ServiceRegistrationRuntimeInspection {
    let requires_process = matches!(state, ServiceState::Running | ServiceState::Stopping);
    let permits_process = matches!(
        state,
        ServiceState::Starting | ServiceState::Running | ServiceState::Stopping
    );
    if matches!(
        state,
        ServiceState::Unknown | ServiceState::Absent | ServiceState::Failed
    ) || (!permits_process && process_id != 0)
        || (requires_process && process_id == 0)
        || (process_id == 0 && process.is_some())
        || (process_id != 0 && process.is_none())
    {
        return ServiceRegistrationRuntimeInspection::Unknown;
    }
    if let Some(process) = &process
        && (process.process_id != process_id
            || !process.is_usable()
            || !same_windows_path(&process.image_path, &exact_path_text(request.binary_path())))
    {
        return ServiceRegistrationRuntimeInspection::Mismatched;
    }
    ServiceRegistrationRuntimeInspection::Matching {
        observation: ServiceRuntimeObservation {
            service_name: request.service_name().to_owned(),
            configuration_digest: request.expected_configuration_digest(),
            state,
            checkpoint,
            wait_hint_ms,
            process,
        },
    }
}

#[cfg(windows)]
const fn service_runtime_sample_is_stable(
    first_state: u32,
    first_process_id: u32,
    confirmed_state: u32,
    confirmed_process_id: u32,
) -> bool {
    first_state == confirmed_state && first_process_id == confirmed_process_id
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the two-sample SCM/config/process identity contour must remain one ordered fail-closed observation"
)]
fn inspect_service_registration_runtime(
    request: &ServiceRegistrationRequest,
) -> ServiceRegistrationRuntimeInspection {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
        SERVICE_START_PENDING, SERVICE_STATUS_PROCESS, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    };

    let name = std::ffi::OsStr::new(request.service_name())
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: null machine/database selects the local SCM; access is query-only.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return ServiceRegistrationRuntimeInspection::Unknown;
    }
    // SAFETY: name is NUL-terminated and manager is a live query handle.
    let service = unsafe {
        OpenServiceW(
            manager,
            name.as_ptr(),
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL,
        )
    };
    if service.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { CloseServiceHandle(manager) };
        return if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST.cast_signed()) {
            ServiceRegistrationRuntimeInspection::Absent
        } else {
            ServiceRegistrationRuntimeInspection::Unknown
        };
    }

    let result = (|| {
        let Some(configuration) = query_service_configuration(service) else {
            return ServiceRegistrationRuntimeInspection::Unknown;
        };
        if !exact_service_configuration_matches(request, &configuration) {
            return ServiceRegistrationRuntimeInspection::Mismatched;
        }
        match read_watchdog_host_control_grant(service, request) {
            Ok(_) => {}
            Err(WindowsAdapterError::AclMismatch | WindowsAdapterError::IdentityMismatch) => {
                return ServiceRegistrationRuntimeInspection::Mismatched;
            }
            Err(_) => return ServiceRegistrationRuntimeInspection::Unknown,
        }
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0;
        let status_size =
            u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>()).unwrap_or(u32::MAX);
        // SAFETY: status is writable storage and service is a live query handle.
        if unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (&raw mut status).cast(),
                status_size,
                &raw mut needed,
            )
        } == 0
        {
            return ServiceRegistrationRuntimeInspection::Unknown;
        }
        let process = (status.dwProcessId != 0)
            .then(|| inspect_process_identity(status.dwProcessId).ok())
            .flatten();
        let mut confirmed_status = SERVICE_STATUS_PROCESS::default();
        let mut confirmed_needed = 0;
        // Re-read SCM after opening the process. A stop/restart or PID reuse
        // between the first status sample and handle-bound identity capture
        // must never be published as one atomic Running observation.
        if unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (&raw mut confirmed_status).cast(),
                status_size,
                &raw mut confirmed_needed,
            )
        } == 0
            || !service_runtime_sample_is_stable(
                status.dwCurrentState,
                status.dwProcessId,
                confirmed_status.dwCurrentState,
                confirmed_status.dwProcessId,
            )
        {
            return ServiceRegistrationRuntimeInspection::Unknown;
        }
        let Some(confirmed_configuration) = query_service_configuration(service) else {
            return ServiceRegistrationRuntimeInspection::Unknown;
        };
        if !exact_service_configuration_matches(request, &confirmed_configuration) {
            return ServiceRegistrationRuntimeInspection::Mismatched;
        }
        let confirmed_process = (confirmed_status.dwProcessId != 0)
            .then(|| inspect_process_identity(confirmed_status.dwProcessId).ok())
            .flatten();
        if process != confirmed_process {
            return ServiceRegistrationRuntimeInspection::Unknown;
        }
        let state = match confirmed_status.dwCurrentState {
            SERVICE_STOPPED => ServiceState::Stopped,
            SERVICE_START_PENDING => ServiceState::Starting,
            SERVICE_RUNNING => ServiceState::Running,
            SERVICE_STOP_PENDING => ServiceState::Stopping,
            _ => ServiceState::Unknown,
        };
        classify_service_runtime_observation(
            request,
            state,
            confirmed_status.dwCheckPoint,
            confirmed_status.dwWaitHint,
            confirmed_status.dwProcessId,
            confirmed_process,
        )
    })();
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    result
}

#[cfg(not(windows))]
fn inspect_service_registration_runtime(
    _request: &ServiceRegistrationRequest,
) -> ServiceRegistrationRuntimeInspection {
    ServiceRegistrationRuntimeInspection::Unknown
}

fn runtime_identity_digest_from_configuration(
    configuration_digest: &str,
    process: &ProcessIdentity,
) -> String {
    sha256_hex(
        format!(
            "{}:{}:{}:{}",
            configuration_digest, process.process_id, process.start_time_100ns, process.image_path
        )
        .as_bytes(),
    )
}

fn start_outcome_from_inspection(
    inspection: ServiceRegistrationRuntimeInspection,
    call_issued: bool,
) -> ServiceStartOutcome {
    match inspection {
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_running() && call_issued =>
        {
            ServiceStartOutcome::Started { observation }
        }
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_starting() && call_issued =>
        {
            ServiceStartOutcome::Started { observation }
        }
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_running() =>
        {
            ServiceStartOutcome::AlreadyRunning { observation }
        }
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_starting() =>
        {
            ServiceStartOutcome::AlreadyStarting { observation }
        }
        _ => ServiceStartOutcome::EffectUnknown,
    }
}

fn stop_outcome_from_inspection(
    inspection: ServiceRegistrationRuntimeInspection,
    call_issued: bool,
) -> ServiceStopOutcome {
    match inspection {
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_stopped() && call_issued =>
        {
            ServiceStopOutcome::Stopped { observation }
        }
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_stopping() && call_issued =>
        {
            ServiceStopOutcome::Stopped { observation }
        }
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_stopped() =>
        {
            ServiceStopOutcome::AlreadyStopped { observation }
        }
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_stopping() =>
        {
            ServiceStopOutcome::AlreadyStopping { observation }
        }
        _ => ServiceStopOutcome::EffectUnknown,
    }
}

#[cfg(windows)]
fn admit_stop_runtime_observation(
    inspection: ServiceRegistrationRuntimeInspection,
    expected_digest: &str,
) -> Result<(), ServiceStopOutcome> {
    match inspection {
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_stopped() =>
        {
            Err(ServiceStopOutcome::AlreadyStopped { observation })
        }
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_stopping()
                && observation.runtime_identity_digest().as_deref() == Some(expected_digest) =>
        {
            Err(ServiceStopOutcome::AlreadyStopping { observation })
        }
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_running()
                && observation.runtime_identity_digest().as_deref() == Some(expected_digest) =>
        {
            let _ = observation;
            Ok(())
        }
        _ => Err(ServiceStopOutcome::EffectUnknown),
    }
}

#[cfg(windows)]
fn start_service_registration(
    request: &ServiceRegistrationRequest,
) -> Result<ServiceStartOutcome, WindowsAdapterError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START,
        SERVICE_STATUS_PROCESS, SERVICE_STOPPED,
    };

    if request.bootstrap().is_none() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    match inspect_service_registration_runtime(request) {
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_running() =>
        {
            return Ok(ServiceStartOutcome::AlreadyRunning { observation });
        }
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_starting() =>
        {
            return Ok(ServiceStartOutcome::AlreadyStarting { observation });
        }
        ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.is_stopped() => {}
        _ => return Ok(ServiceStartOutcome::EffectUnknown),
    }

    let name = std::ffi::OsStr::new(request.service_name())
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: null machine/database selects the local SCM; both handles are
    // closed on every path below.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(last_windows_adapter_error());
    }
    // SAFETY: the name is NUL-terminated and access is limited to exact
    // configuration/status validation plus one start mutation.
    let service = unsafe {
        OpenServiceW(
            manager,
            name.as_ptr(),
            SERVICE_START | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )
    };
    if service.is_null() {
        unsafe { CloseServiceHandle(manager) };
        return Ok(ServiceStartOutcome::EffectUnknown);
    }

    let result = (|| {
        let Some(configuration) = query_service_configuration(service) else {
            return ServiceStartOutcome::EffectUnknown;
        };
        if !exact_service_configuration_matches(request, &configuration) {
            return ServiceStartOutcome::EffectUnknown;
        }
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0_u32;
        let status_size =
            u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>()).unwrap_or(u32::MAX);
        // SAFETY: status is writable storage and service is a live handle.
        if unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (&raw mut status).cast(),
                status_size,
                &raw mut needed,
            )
        } == 0
        {
            return ServiceStartOutcome::EffectUnknown;
        }
        if status.dwCurrentState != SERVICE_STOPPED {
            return start_outcome_from_inspection(
                inspect_service_registration_runtime(request),
                false,
            );
        }
        // SAFETY: service is the live exact-configuration handle and no
        // arguments are supplied. This is the sole StartServiceW call.
        let start_succeeded = unsafe {
            windows_sys::Win32::System::Services::StartServiceW(service, 0, std::ptr::null())
        } != 0;
        let post_start = inspect_service_registration_runtime(request);
        if !start_succeeded {
            // A post-call state change is not proof that this call owned it.
            // Preserve the ambiguity and never retry blindly.
            return ServiceStartOutcome::EffectUnknown;
        }
        start_outcome_from_inspection(post_start, true)
    })();
    // SAFETY: both handles are owned by this function.
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    Ok(result)
}

#[cfg(not(windows))]
fn start_service_registration(
    _request: &ServiceRegistrationRequest,
) -> Result<ServiceStartOutcome, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn stop_service_registration(
    request: &ServiceRegistrationRequest,
) -> Result<ServiceStopOutcome, WindowsAdapterError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
        SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_CONTROL_STOP, SERVICE_QUERY_CONFIG,
        SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
        SERVICE_STOP,
    };

    if request.bootstrap().is_none() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let Some(expected_digest) = request.expected_runtime_identity_digest() else {
        return Ok(ServiceStopOutcome::EffectUnknown);
    };
    if let Err(outcome) = admit_stop_runtime_observation(
        inspect_service_registration_runtime(request),
        expected_digest,
    ) {
        return Ok(outcome);
    }

    let name = std::ffi::OsStr::new(request.service_name())
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: null machine/database selects the local SCM; both handles are
    // closed on every path below.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(last_windows_adapter_error());
    }
    // SAFETY: access is limited to exact configuration/status validation plus
    // one stop mutation.
    let service = unsafe {
        OpenServiceW(
            manager,
            name.as_ptr(),
            SERVICE_STOP | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )
    };
    if service.is_null() {
        unsafe { CloseServiceHandle(manager) };
        return Ok(ServiceStopOutcome::EffectUnknown);
    }
    let result = (|| {
        let Some(configuration) = query_service_configuration(service) else {
            return ServiceStopOutcome::EffectUnknown;
        };
        if !exact_service_configuration_matches(request, &configuration) {
            return ServiceStopOutcome::EffectUnknown;
        }
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0_u32;
        let status_size =
            u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>()).unwrap_or(u32::MAX);
        // SAFETY: status is writable storage and service is live.
        if unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (&raw mut status).cast(),
                status_size,
                &raw mut needed,
            )
        } == 0
        {
            return ServiceStopOutcome::EffectUnknown;
        }
        if status.dwCurrentState != SERVICE_RUNNING {
            return stop_outcome_from_inspection(
                inspect_service_registration_runtime(request),
                false,
            );
        }
        // Re-admit the exact process immediately before the mutation. This
        // closes the stale-PID window between the initial admission and the
        // SCM handle operation; any remaining provider race is Unknown.
        match inspect_service_registration_runtime(request) {
            ServiceRegistrationRuntimeInspection::Matching { observation }
                if observation.is_running()
                    && observation.runtime_identity_digest().as_deref()
                        == Some(expected_digest) =>
            {
                let _ = observation;
            }
            _ => return ServiceStopOutcome::EffectUnknown,
        }
        let mut stop_status = SERVICE_STATUS::default();
        // SAFETY: service is the live exact-configuration handle. This is the
        // sole ControlService stop call for this effect attempt.
        let stop_succeeded =
            unsafe { ControlService(service, SERVICE_CONTROL_STOP, &raw mut stop_status) } != 0;
        let post_stop = inspect_service_registration_runtime(request);
        if !stop_succeeded {
            // A false stop result followed by a changed runtime state is not
            // proof that this transaction owned the mutation.  Quarantine
            // rather than turning a concurrent actor's transition into a
            // successful rollback receipt.
            return ServiceStopOutcome::EffectUnknown;
        }
        stop_outcome_from_inspection(post_stop, true)
    })();
    // SAFETY: both handles are owned by this function.
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    Ok(result)
}

#[cfg(not(windows))]
fn stop_service_registration(
    _request: &ServiceRegistrationRequest,
) -> Result<ServiceStopOutcome, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn inspect_service_registration(
    request: &ServiceRegistrationRequest,
) -> ServiceRegistrationInspection {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG,
    };

    let name = OsStr::new(request.service_name())
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return ServiceRegistrationInspection::Unknown;
    }
    let service =
        unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_CONFIG | READ_CONTROL) };
    if service.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { CloseServiceHandle(manager) };
        return if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST.cast_signed()) {
            ServiceRegistrationInspection::Absent
        } else {
            ServiceRegistrationInspection::Unknown
        };
    }

    let Some(configuration) = query_service_configuration(service) else {
        unsafe {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
        return ServiceRegistrationInspection::Unknown;
    };
    let matches = exact_service_configuration_matches(request, &configuration)
        && match request.service_sid_type() {
            ServiceSidType::None => true,
            ServiceSidType::Unrestricted => resolve_service_sid(request.service_name()).is_ok(),
        };
    let control_grant = if matches {
        match read_watchdog_host_control_grant(service, request) {
            Ok(value) => Some(value),
            Err(WindowsAdapterError::AclMismatch | WindowsAdapterError::IdentityMismatch) => None,
            Err(_) => {
                unsafe {
                    CloseServiceHandle(service);
                    CloseServiceHandle(manager);
                }
                return ServiceRegistrationInspection::Unknown;
            }
        }
    } else {
        None
    };
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    if !matches || control_grant.is_none() {
        return ServiceRegistrationInspection::Mismatched;
    }
    service_registration_inspection_from_status(
        inspect_service(request.service_name()),
        control_grant.unwrap_or_default(),
    )
}

#[cfg(not(windows))]
fn inspect_service_registration(
    _request: &ServiceRegistrationRequest,
) -> ServiceRegistrationInspection {
    ServiceRegistrationInspection::Unknown
}

fn service_registration_inspection_from_status(
    status: PortOutcome<ServiceObservation>,
    control_grant: Option<ServiceControlGrantReadback>,
) -> ServiceRegistrationInspection {
    match status {
        PortOutcome::Known(observation) => ServiceRegistrationInspection::Matching {
            observation,
            control_grant,
        },
        PortOutcome::Partial { .. } | PortOutcome::Unknown(_) | PortOutcome::Error(_) => {
            ServiceRegistrationInspection::Unknown
        }
    }
}

#[cfg(not(windows))]
fn register_service(
    _request: &ServiceRegistrationRequest,
) -> Result<ServiceRegistrationOutcome, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn inspect_service(name: &str) -> PortOutcome<ServiceObservation> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STATUS_PROCESS, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    };
    let service_name = name.to_owned();
    let name = OsStr::new(name)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: null machine/database selects the local SCM; access is query-only.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return PortOutcome::Unknown(UnknownReason::Indeterminate);
    }
    // SAFETY: name is NUL-terminated and manager is live.
    let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        unsafe { CloseServiceHandle(manager) };
        let error = std::io::Error::last_os_error();
        return classify_service_error(&service_name, &error);
    }
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut size = 0;
    // SAFETY: status is valid storage and the service handle is query-only/live.
    let status_size =
        u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>()).unwrap_or(u32::MAX);
    let ok = unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            (&raw mut status).cast(),
            status_size,
            &raw mut size,
        )
    };
    let query_error = (ok == 0).then(std::io::Error::last_os_error);
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    if let Some(error) = query_error {
        return PortOutcome::Error(PortError::Provider(provider_from_io(&error)));
    }
    let state = match status.dwCurrentState {
        SERVICE_STOPPED => ServiceState::Stopped,
        SERVICE_START_PENDING => ServiceState::Starting,
        SERVICE_RUNNING => ServiceState::Running,
        SERVICE_STOP_PENDING => ServiceState::Stopping,
        _ => ServiceState::Unknown,
    };
    let observation = ServiceObservation {
        service: handle(&service_name),
        state,
        generation: None,
        process: None,
    };
    if status.dwProcessId == 0 {
        PortOutcome::Known(observation)
    } else if inspect_process_identity(status.dwProcessId).is_ok() {
        // P-01's ServiceProcessRecord requires an authority epoch. Windows
        // does not issue that authority, so preserve the observed service
        // state and expose exact process identity only through
        // WindowsPlatform::process_identity.
        PortOutcome::Partial {
            value: observation,
            missing: vec![handle("authority_bound_process_record")],
        }
    } else {
        PortOutcome::Partial {
            value: observation,
            missing: vec![handle("process_identity")],
        }
    }
}

#[cfg(windows)]
fn mutate_service(name: &str, operation: ServiceOperation) -> PortOutcome<ServiceObservation> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
        SERVICE_CONTROL_STOP, SERVICE_START, SERVICE_STATUS, SERVICE_STOP, StartServiceW,
    };
    let name_wide = std::ffi::OsStr::new(name)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let access = match operation {
        ServiceOperation::Start => SERVICE_START,
        ServiceOperation::Stop => SERVICE_STOP,
        ServiceOperation::Inspect | ServiceOperation::Register | ServiceOperation::Unregister => {
            return PortOutcome::Unknown(UnknownReason::Unsupported);
        }
    };
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return PortOutcome::Error(PortError::Provider(provider_from_io(
            &std::io::Error::last_os_error(),
        )));
    }
    let service = unsafe { OpenServiceW(manager, name_wide.as_ptr(), access) };
    if service.is_null() {
        unsafe { CloseServiceHandle(manager) };
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST.cast_signed()) {
            return PortOutcome::Known(ServiceObservation {
                service: handle(name),
                state: ServiceState::Absent,
                generation: None,
                process: None,
            });
        }
        return PortOutcome::Error(PortError::Provider(provider_from_io(&error)));
    }
    let ok = match operation {
        ServiceOperation::Start => unsafe { StartServiceW(service, 0, std::ptr::null()) },
        ServiceOperation::Stop => {
            let mut status = SERVICE_STATUS::default();
            unsafe { ControlService(service, SERVICE_CONTROL_STOP, &raw mut status) }
        }
        ServiceOperation::Inspect | ServiceOperation::Register | ServiceOperation::Unregister => 0,
    };
    let error = (ok == 0).then(std::io::Error::last_os_error);
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    if let Some(error) = error {
        return PortOutcome::Error(PortError::Provider(provider_from_io(&error)));
    }
    reconcile_service_effect(inspect_service(name))
}

fn reconcile_service_effect(
    observation: PortOutcome<ServiceObservation>,
) -> PortOutcome<ServiceObservation> {
    match observation {
        PortOutcome::Known(_) | PortOutcome::Partial { .. } => observation,
        PortOutcome::Unknown(_) | PortOutcome::Error(_) => {
            PortOutcome::Unknown(UnknownReason::Indeterminate)
        }
    }
}

#[cfg(not(windows))]
fn mutate_service(_name: &str, _operation: ServiceOperation) -> PortOutcome<ServiceObservation> {
    PortOutcome::Unknown(UnknownReason::Unsupported)
}

#[cfg(not(windows))]
fn inspect_service(_name: &str) -> PortOutcome<ServiceObservation> {
    PortOutcome::Unknown(UnknownReason::Unsupported)
}

#[cfg(windows)]
pub(crate) fn job_process_ids(
    job: windows_sys::Win32::Foundation::HANDLE,
) -> std::io::Result<Vec<u32>> {
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::System::JobObjects::{
        JOBOBJECT_BASIC_PROCESS_ID_LIST, JobObjectBasicProcessIdList, QueryInformationJobObject,
    };
    let mut capacity = 16_usize;
    loop {
        let bytes = std::mem::size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>()
            .checked_add(
                capacity
                    .saturating_sub(1)
                    .checked_mul(std::mem::size_of::<usize>())
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Job process list is too large",
                        )
                    })?,
            )
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Job process list is too large",
                )
            })?;
        let words = bytes.div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        let bytes = u32::try_from(buffer.len() * std::mem::size_of::<usize>()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Job process buffer is too large",
            )
        })?;
        let mut returned = 0_u32;
        let queried = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicProcessIdList,
                buffer.as_mut_ptr().cast(),
                bytes,
                &raw mut returned,
            )
        };
        let header = unsafe { &*buffer.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() };
        if queried != 0 {
            let count = usize::try_from(header.NumberOfProcessIdsInList).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Job process count invalid")
            })?;
            if count > capacity {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Job process list exceeded its supplied buffer",
                ));
            }
            let ids = unsafe { std::slice::from_raw_parts(header.ProcessIdList.as_ptr(), count) };
            return ids
                .iter()
                .copied()
                .filter(|pid| *pid != 0)
                .map(|pid| {
                    u32::try_from(pid).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Job PID does not fit u32",
                        )
                    })
                })
                .collect();
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_MORE_DATA.cast_signed()) {
            return Err(error);
        }
        let assigned = usize::try_from(header.NumberOfAssignedProcesses).unwrap_or(capacity + 1);
        capacity = assigned.max(capacity.saturating_mul(2));
        if capacity > 4_096 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Job process list exceeded its safety bound",
            ));
        }
    }
}

#[cfg(windows)]
fn nul_terminated_wide(value: &std::ffi::OsStr) -> std::io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows string contains an embedded NUL",
        ));
    }
    Ok(wide.into_iter().chain(std::iter::once(0)).collect())
}

#[cfg(windows)]
fn os_has_nul(value: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().any(|unit| unit == 0)
}

#[cfg(windows)]
fn validate_complete_environment(
    environment: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<(), WindowsAdapterError> {
    let mut names = std::collections::BTreeSet::new();
    for (name, value) in environment {
        let Some(name_text) = name.to_str() else {
            return Err(WindowsAdapterError::InvalidInput);
        };
        if name_text.is_empty()
            || name_text.contains('=')
            || os_has_nul(name)
            || value.to_str().is_none()
            || os_has_nul(value)
            || !names.insert(name_text.to_uppercase())
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn wait_for_job_empty(
    job: windows_sys::Win32::Foundation::HANDLE,
    timeout: std::time::Duration,
) -> Result<(), WindowsAdapterError> {
    let started = std::time::Instant::now();
    loop {
        if job_process_ids(job)
            .map_err(|error| windows_adapter_from_io(&error))?
            .is_empty()
        {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(WindowsAdapterError::Timeout);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(windows)]
fn quote_windows_argument(value: &std::ffi::OsStr) -> std::io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let value = value.encode_wide().collect::<Vec<_>>();
    if value.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "process argument contains an embedded NUL",
        ));
    }
    // Quote every argument. This is CommandLineToArgvW/CRT compatible and
    // therefore handles embedded quotes and trailing backslashes even when an
    // argument contains no whitespace.
    let mut quoted = vec![u16::from(b'"')];
    let mut backslashes = 0_usize;
    for unit in value {
        if unit == u16::from(b'\\') {
            backslashes = backslashes.saturating_add(1);
        } else if unit == u16::from(b'"') {
            quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2 + 1));
            quoted.push(unit);
            backslashes = 0;
        } else {
            quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
            quoted.push(unit);
            backslashes = 0;
        }
    }
    quoted.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
    quoted.push(u16::from(b'"'));
    Ok(quoted)
}

#[cfg(windows)]
fn command_line(executable: &Path, arguments: &[std::ffi::OsString]) -> std::io::Result<Vec<u16>> {
    let mut line = Vec::new();
    for (index, argument) in std::iter::once(executable.as_os_str())
        .chain(arguments.iter().map(std::ffi::OsString::as_os_str))
        .enumerate()
    {
        if index > 0 {
            line.push(u16::from(b' '));
        }
        line.extend(quote_windows_argument(argument)?);
    }
    line.push(0);
    Ok(line)
}

#[cfg(windows)]
fn command_environment(environment: &[(std::ffi::OsString, std::ffi::OsString)]) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let mut entries = environment.to_vec();
    entries.sort_by_key(|(name, _)| name.to_string_lossy().to_uppercase());
    let mut block = Vec::new();
    for (name, value) in entries {
        block.extend(name.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

#[cfg(windows)]
fn classify_service_error(name: &str, error: &std::io::Error) -> PortOutcome<ServiceObservation> {
    use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST.cast_signed()) {
        PortOutcome::Known(ServiceObservation {
            service: handle(name),
            state: ServiceState::Absent,
            generation: None,
            process: None,
        })
    } else {
        PortOutcome::Error(PortError::Provider(provider_from_io(error)))
    }
}

#[cfg(windows)]
fn inspect_credential(request: &SecretRequest) -> PortOutcome<eliot_platform::SecretObservation> {
    if !is_windows_secret_provider(request.reference.provider.as_str()) {
        return PortOutcome::Unknown(UnknownReason::Unsupported);
    }
    if !valid_credential_key(request.reference.key.as_str()) {
        return PortOutcome::Error(PortError::InvalidPath);
    }
    match eliot_windows_ipc::credential_status_current_user(request.reference.key.as_str()) {
        Ok(status) => PortOutcome::Known(eliot_platform::SecretObservation {
            reference: request.reference.clone(),
            present: status.present,
            version: status
                .version
                .and_then(|version| PlatformHandle::new(version.to_string()).ok()),
        }),
        Err(error) => PortOutcome::Error(PortError::Provider(provider_from_io(&error))),
    }
}

fn is_windows_secret_provider(value: &str) -> bool {
    matches!(
        value,
        "windows-credential-manager" | "windows-credential-manager-dpapi" | "dpapi"
    )
}

#[cfg(not(windows))]
fn inspect_credential(_request: &SecretRequest) -> PortOutcome<eliot_platform::SecretObservation> {
    PortOutcome::Unknown(UnknownReason::Unsupported)
}

#[cfg(windows)]
fn inspect_session(request: &SessionRequest) -> PortOutcome<SessionObservation> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTSActive, WTSConnectState, WTSFreeMemory,
        WTSQuerySessionInformationW, WTSUserName,
    };
    let Ok(requested) = request.session.as_str().parse::<u32>() else {
        return PortOutcome::Unknown(UnknownReason::NotObserved);
    };
    let mut state_ptr = std::ptr::null_mut();
    let mut state_bytes = 0_u32;
    // SAFETY: WTS owns the returned buffer and receives valid output pointers.
    let state_ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            requested,
            WTSConnectState,
            &raw mut state_ptr,
            &raw mut state_bytes,
        )
    } != 0;
    if !state_ok || state_ptr.is_null() || state_bytes < 4 {
        if !state_ptr.is_null() {
            // SAFETY: state_ptr was returned by WTSQuerySessionInformationW.
            unsafe { WTSFreeMemory(state_ptr.cast()) };
        }
        return PortOutcome::Unknown(UnknownReason::Indeterminate);
    }
    // SAFETY: WTS returned at least four bytes for WTSConnectState.
    let state = unsafe { std::ptr::read_unaligned(state_ptr.cast::<i32>()) };
    // SAFETY: state_ptr was returned by WTSQuerySessionInformationW.
    unsafe { WTSFreeMemory(state_ptr.cast()) };

    let mut user_ptr = std::ptr::null_mut();
    let mut user_bytes = 0_u32;
    // SAFETY: WTS owns the returned buffer and receives valid output pointers.
    let user_ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            requested,
            WTSUserName,
            &raw mut user_ptr,
            &raw mut user_bytes,
        )
    } != 0;
    if !user_ok || user_ptr.is_null() {
        if !user_ptr.is_null() {
            // SAFETY: user_ptr was returned by WTSQuerySessionInformationW.
            unsafe { WTSFreeMemory(user_ptr.cast()) };
        }
        return PortOutcome::Unknown(UnknownReason::NotObserved);
    }
    let user_len = usize::try_from(user_bytes).unwrap_or(0) / 2;
    // SAFETY: user_bytes describes the UTF-16 buffer returned by WTS.
    let user_units = unsafe { std::slice::from_raw_parts(user_ptr, user_len) };
    let user = std::ffi::OsString::from_wide(user_units)
        .to_string_lossy()
        .trim_end_matches('\0')
        .to_owned();
    // SAFETY: user_ptr was returned by WTSQuerySessionInformationW.
    unsafe { WTSFreeMemory(user_ptr.cast()) };
    PortOutcome::Known(SessionObservation {
        session: request.session.clone(),
        user: PlatformHandle::new(user).ok(),
        interactive: state == WTSActive,
    })
}

#[cfg(test)]
fn session_matches(requested: u32, current: u32) -> bool {
    requested == current
}

#[cfg(not(windows))]
fn inspect_session(_request: &SessionRequest) -> PortOutcome<SessionObservation> {
    PortOutcome::Unknown(UnknownReason::Unsupported)
}

#[cfg(test)]
mod tests;
