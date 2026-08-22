//! Concrete Windows adapters for the P-01 platform ports.
//!
//! Windows implementation details are deliberately kept behind this facade.
//! Public values expose only provider-neutral P-01 results and typed P-02
//! mechanics evidence. Raw handles, provider records, secret bytes, and Win32
//! implementation details never escape this crate.

#![deny(unsafe_op_in_unsafe_fn)]

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_platform::{
    AdapterPathInput, ClockPort, ClockRequest, FileKind, FilesystemObservation,
    FilesystemOperation, FilesystemPort, InstallationObservation, InstallationOperation,
    InstallationPort, InstallationRequest, InstallationState, KernelActivationNonce,
    NotificationObservation, NotificationPort, NotificationRequest, PlatformHandle, PortError,
    PortOutcome, SecretPort, SecretRequest, ServiceObservation, ServiceOperation, ServicePort,
    ServiceRequest, ServiceState, SessionObservation, SessionPort, SessionRequest, UnknownReason,
    WorkScopePath,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static TEST_PROTECTED_ROOT: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
    static TEST_RECEIPT_PUBLICATION_UNKNOWN: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
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
        super::TEST_RECEIPT_PUBLICATION_UNKNOWN.with(|slot| slot.set(true));
    }
}

mod installer_authority_key;
mod installer_root;
mod owned_directory_retirement;
mod package_staging;
mod supervision_authority_key;
mod tcp_listener_owner;

pub use installer_authority_key::{
    INSTALLATION_AUTHORITY_KEY_FILE_BYTES, INSTALLATION_AUTHORITY_KEY_FILE_VERSION,
    INSTALLATION_AUTHORITY_KEY_ID_MAX_BYTES, INSTALLATION_AUTHORITY_KEY_MAGIC,
    INSTALLATION_AUTHORITY_KEY_ROOT_RELATIVE, INSTALLATION_AUTHORITY_SIGNER_ID,
    InstallationAuthorityKeyError, InstallationAuthorityKeyExpectation,
    InstallationAuthorityKeyMetadata, InstallationAuthorityKeySigner,
    WindowsInstallationAuthorityKeyProvider, WindowsInstallationAuthorityKeyStore,
};
pub use installer_root::{
    InstallerProtectedFileReadback, InstallerRootAbsentSnapshot, InstallerRootCreateDisposition,
    InstallerRootError, InstallerRootObjectSnapshot, InstallerRootPrimitiveCreate,
    InstallerRootPrimitiveObservation, InstallerRootPrimitiveSpec, InstallerRootProfile,
    WindowsInstallerRootPrimitive, is_process_elevated, windows_path_identity_digest,
    windows_paths_equal,
};
pub use owned_directory_retirement::{
    OwnedDirectoryObservation, OwnedDirectoryObservedEntry, OwnedDirectoryRetirementEntry,
    OwnedDirectoryRetirementError, OwnedDirectoryRetirementOutcome,
    OwnedDirectoryRetirementPrecondition, OwnedDirectoryRetirementUnknown,
    observe_owned_directory_exact, retire_owned_directory_exact,
};
pub use package_staging::{
    AuthenticodeError, AuthenticodeEvidence, AuthenticodeVerdict, AuthenticodeVerifier,
    MAX_ENUMERATED_ENTRIES, PackageFileSpec, PackageManifest, PackageRelativePath,
    PackageSourceFileObservation, PackageSourceObservation, PackageStager, PackageStagingError,
    PackageStagingObservation, PeCoffError, PeCoffEvidence, StagedDirectoryReceipt,
    StagedFileReceipt, StagingReceipt, TrustedSourceBundle, WindowsAuthenticodeVerifier,
    ordinal_cmp_str, ordinal_component_cmp, ordinal_eq_str, ordinal_path_cmp, parse_pe_coff,
    validate_package_relative_path,
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
/// The name is derived from the installation owner and the exact credential
/// target.  It is an inter-process exclusion primitive, not a durable
/// transaction record; the protected Host marker and installation journal
/// remain the authority for recovery.
const HOST_CREDENTIAL_MUTEX_PREFIX: &str = "Global\\Eliot-Host-Credential-";

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

/// Protected `ProgramData` path policy used by Host, installation and
/// Watchdog durable state.  The policy is intentionally shared so a caller
/// cannot substitute a per-user or arbitrary working-directory root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedPathError {
    /// `ProgramData` is missing, relative or cannot be canonicalized safely.
    InvalidRoot,
    /// The requested path is absolute, traverses a parent, or escapes the
    /// canonical `ProgramData` contour.
    InvalidPath,
    /// A path component or target is a symlink/junction/reparse point.
    ReparsePoint,
    /// The protected service/admin ACL could not be applied or verified.
    AclMismatch,
    /// The filesystem operation failed before a safe classification existed.
    Io,
    /// The protected file exceeded the caller's explicit bounded read limit.
    SizeExceeded,
    /// Durable protected storage is intentionally unavailable off Windows.
    UnsupportedPlatform,
}

impl std::fmt::Display for ProtectedPathError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRoot => "ProgramData protected root is invalid",
            Self::InvalidPath => "path is outside the protected ProgramData contour",
            Self::ReparsePoint => "protected path contains a reparse point",
            Self::AclMismatch => "protected path ACL does not match service/admin policy",
            Self::Io => "protected path I/O failed",
            Self::SizeExceeded => "protected file exceeds its bounded read limit",
            Self::UnsupportedPlatform => "protected ProgramData storage requires Windows",
        })
    }
}

impl std::error::Error for ProtectedPathError {}

/// Returns the canonical `ProgramData` directory after rejecting reparse
/// substitution in the root and its existing ancestors.
///
/// # Errors
///
/// Returns an error when the root is absent, relative, cannot be canonicalized,
/// or contains a reparse point.
pub fn protected_program_data_root() -> Result<PathBuf, ProtectedPathError> {
    let raw = known_folder_path(KnownFolder::ProgramData)?;
    reject_reparse_chain(&raw, true)?;
    let canonical = canonical_windows_path(&raw)?;
    validate_directory_no_reparse(&canonical)?;
    Ok(canonical)
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

#[derive(Clone, Copy)]
enum KnownFolder {
    ProgramData,
    LocalAppData,
}

#[cfg(windows)]
fn known_folder_path(folder: KnownFolder) -> Result<PathBuf, ProtectedPathError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::S_OK;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_LocalAppData, FOLDERID_ProgramData, SHGetKnownFolderPath,
    };

    let folder_id = match folder {
        KnownFolder::ProgramData => &FOLDERID_ProgramData,
        KnownFolder::LocalAppData => &FOLDERID_LocalAppData,
    };
    let mut path = std::ptr::null_mut();
    let status = unsafe {
        // SAFETY: the folder id is static, null token selects the process user,
        // and `path` receives task-allocator memory released below.
        SHGetKnownFolderPath(folder_id, 0, std::ptr::null_mut(), &raw mut path)
    };
    if status != S_OK || path.is_null() {
        unsafe {
            // SAFETY: CoTaskMemFree accepts null and any pointer returned by the API.
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

/// Canonicalizes one existing path and converts Windows' internal verbatim
/// result into the DOS/UNC form admitted at provider-neutral contract seams.
///
/// This conversion applies only after the OS resolves an existing path. It
/// does not make a caller-supplied device or verbatim path contract-valid.
///
/// # Errors
///
/// Returns an error when canonicalization fails or the OS result is not an
/// absolute DOS/UNC path.
pub fn canonical_windows_path(path: &Path) -> Result<PathBuf, ProtectedPathError> {
    let canonical = std::fs::canonicalize(path).map_err(|_| ProtectedPathError::Io)?;
    #[cfg(windows)]
    {
        normalize_final_windows_path_text(&canonical.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        Ok(canonical)
    }
}

/// Resolves a fixed relative path below the canonical `ProgramData` root.
/// Missing leaf components are allowed so callers can create them under the
/// protected parent; existing components are checked before the result is
/// returned.
///
/// # Errors
///
/// Returns an error when the relative path is invalid or escapes the protected
/// root, or when the root cannot be verified safely.
pub fn protected_program_data_path(
    relative: impl AsRef<Path>,
) -> Result<PathBuf, ProtectedPathError> {
    let relative = relative.as_ref();
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(ProtectedPathError::InvalidPath);
    }
    let root = protected_program_data_root()?;
    let path = root.join(relative);
    ensure_protected_containment(&root, &path)?;
    Ok(path)
}

/// Requires a caller-provided path to equal one fixed ProgramData-relative
/// identity and to remain below the canonical root.  This is the boundary
/// used by public Host/Watchdog open APIs to reject arbitrary roots.
///
/// # Errors
///
/// Returns an error when the supplied path differs from the fixed protected
/// identity or cannot be proven to remain within the protected root.
pub fn require_protected_program_data_path(
    path: &Path,
    relative: impl AsRef<Path>,
) -> Result<PathBuf, ProtectedPathError> {
    let expected = protected_program_data_path(relative)?;
    if path != expected {
        return Err(ProtectedPathError::InvalidPath);
    }
    ensure_protected_containment(&expected_root()?, path)?;
    Ok(expected)
}

/// A retained no-follow lease for one protected `ProgramData` file.
///
/// The lease owns a no-delete-sharing handle for every existing directory
/// component and for the final file.  Consequently, once this value has been
/// acquired, a concurrent rename, junction substitution, or deletion cannot
/// replace the object used by a path-based consumer such as redb.  Callers
/// must retain this value for the complete lifetime of that consumer.
pub struct ProtectedPathLease {
    path: PathBuf,
    identity: FileIdentity,
    #[cfg(windows)]
    _directories: Vec<std::fs::File>,
    #[cfg(windows)]
    file: std::fs::File,
}

/// Retained read-only lease for one existing directory below the OS-resolved
/// `ProgramData` contour.
///
/// Unlike [`ProtectedPathLease`], acquisition never creates a sentinel and
/// never writes an ACL. Root creation and ACL application remain explicit
/// installation transaction effects.
pub struct ProtectedRootLease {
    path: PathBuf,
    identity: FileIdentity,
    #[cfg(windows)]
    directories: Vec<std::fs::File>,
}

impl std::fmt::Debug for ProtectedRootLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedRootLease")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl ProtectedRootLease {
    /// Opens an existing absolute `ProgramData` descendant and retains a
    /// no-follow, no-delete-sharing handle for its complete directory contour.
    ///
    /// # Errors
    ///
    /// Returns an error when the path escapes `ProgramData`, contains a reparse
    /// point, is not an existing directory, or cannot be retained read-only.
    pub fn open_existing(path: &Path) -> Result<Self, ProtectedPathError> {
        let root = expected_root()?;
        ensure_protected_containment(&root, path)?;
        let canonical = canonical_windows_path(path)?;
        ensure_protected_containment(&root, &canonical)?;
        let relative = canonical
            .strip_prefix(&root)
            .map_err(|_| ProtectedPathError::InvalidPath)?;
        #[cfg(windows)]
        {
            let directories = pin_protected_directory_contour(&root, relative)?;
            let retained = directories.last().ok_or(ProtectedPathError::InvalidPath)?;
            let identity =
                file_identity_from_handle(retained).map_err(|_| ProtectedPathError::Io)?;
            Ok(Self {
                path: canonical,
                identity,
                directories,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = relative;
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Returns the OS-resolved DOS/UNC directory path.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained directory handle is unavailable,
    /// cannot be resolved, or the adapter is unsupported on this platform.
    pub fn canonical_path(&self) -> Result<PathBuf, ProtectedPathError> {
        #[cfg(windows)]
        {
            final_windows_path_from_handle(
                self.directories
                    .last()
                    .ok_or(ProtectedPathError::InvalidPath)?,
            )
        }
        #[cfg(not(windows))]
        {
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Returns the retained directory-object identity.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Re-reads identity from the retained directory handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained handle is unavailable, cannot be
    /// inspected, changed identity, or is unsupported on this platform.
    pub fn verify_stable_identity(&self) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            let retained = self
                .directories
                .last()
                .ok_or(ProtectedPathError::InvalidPath)?;
            let identity =
                file_identity_from_handle(retained).map_err(|_| ProtectedPathError::Io)?;
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

impl std::fmt::Debug for ProtectedPathLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedPathLease")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl ProtectedPathLease {
    /// Opens or creates one protected `ProgramData` file and retains its
    /// no-follow component handles.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid path, reparse point, ACL mismatch,
    /// filesystem failure, or unsupported platform.
    pub fn open_or_create(relative: impl AsRef<Path>) -> Result<Self, ProtectedPathError> {
        Self::open_relative(relative.as_ref(), true)
    }

    /// Opens one existing protected `ProgramData` file and retains its
    /// no-follow component handles.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected file or its contour cannot be
    /// opened and verified without following a reparse point.
    pub fn open_existing(relative: impl AsRef<Path>) -> Result<Self, ProtectedPathError> {
        Self::open_relative(relative.as_ref(), false)
    }

    /// Opens one existing absolute path only after canonicalizing it into the
    /// exact protected `ProgramData` contour.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is outside the protected contour or the
    /// retained file cannot be opened and verified safely.
    pub fn open_existing_absolute(path: &Path) -> Result<Self, ProtectedPathError> {
        let root = expected_root()?;
        ensure_protected_containment(&root, path)?;
        let canonical = canonical_windows_path(path)?;
        ensure_protected_containment(&root, &canonical)?;
        let relative = canonical
            .strip_prefix(&root)
            .map_err(|_| ProtectedPathError::InvalidPath)?;
        Self::open_relative(relative, false)
    }

    /// Returns the exact path used to open the retained file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the identity observed from the retained no-follow file handle.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Returns the DOS/UNC path resolved from the retained handle. Windows
    /// verbatim prefixes are removed before the path crosses the contract seam.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained handle cannot be resolved or this
    /// operation is unsupported on the current platform.
    pub fn canonical_path(&self) -> Result<PathBuf, ProtectedPathError> {
        #[cfg(windows)]
        {
            final_windows_path_from_handle(&self.file)
        }
        #[cfg(not(windows))]
        {
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Re-reads the identity from the retained handle and rejects any
    /// impossible handle/object change.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained handle cannot be inspected, its
    /// identity changed, or retained-handle verification is unavailable.
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

    /// Opens the path again with no-follow/no-delete-sharing and compares its
    /// identity to the retained lease.  This is the post-open proof required
    /// for redb, which accepts a path rather than an already-open handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the path cannot be reopened without following a
    /// reparse point or its identity differs from the retained handle.
    pub fn verify_path_identity(&self) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            let file = open_protected_file(&self.path, false)?;
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

    /// Reads bounded bytes from the retained file handle.  No path is opened
    /// during this operation.
    ///
    /// # Errors
    ///
    /// Returns an error when handle I/O fails, the file exceeds `limit`, or the
    /// retained-handle implementation is unavailable.
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

    fn open_relative(relative: &Path, create: bool) -> Result<Self, ProtectedPathError> {
        let components = protected_components(relative)?;
        let root = expected_root()?;
        let path = root.join(relative);
        ensure_protected_containment(&root, &path)?;
        #[cfg(windows)]
        {
            Self::open_at_root(&root, relative, &components, create)
        }
        #[cfg(not(windows))]
        {
            let _ = (create, path);
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    #[cfg(windows)]
    fn open_at_root(
        root: &Path,
        relative: &Path,
        components: &[std::ffi::OsString],
        create: bool,
    ) -> Result<Self, ProtectedPathError> {
        let parent = components[..components.len() - 1].iter().fold(
            PathBuf::new(),
            |mut path, component| {
                path.push(component);
                path
            },
        );
        let file_name = &components[components.len() - 1];
        let directories = open_directory_contour(root, &parent, create)?;
        let file_path = root.join(relative);
        debug_assert_eq!(file_path, root.join(&parent).join(file_name));
        let file = open_protected_file(&file_path, create)?;
        protect_opened_handle(&file, false)?;
        let identity = file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)?;
        Ok(Self {
            path: file_path,
            identity,
            _directories: directories,
            file,
        })
    }
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
                pin_protected_directory_contour(&root, &parent)?
            };
            let file = open_runtime_file(&canonical, create)?;
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
            let _ = (canonical, components);
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
fn open_runtime_file(path: &Path, create: bool) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(create)
        .access_mode(runtime_file_access_mode(create))
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = if create {
        options.create_new(true).open(path).or_else(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                let mut existing = std::fs::OpenOptions::new();
                existing
                    .read(true)
                    .write(true)
                    .access_mode(runtime_file_access_mode(true))
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
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

#[cfg(windows)]
fn open_user_owned_directory(path: &Path, sid: &str) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, WRITE_DAC,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.access_mode(FILE_GENERIC_READ | WRITE_DAC);
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
fn open_user_owned_file(path: &Path, sid: &str) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_SHARE_READ, FILE_SHARE_WRITE, WRITE_DAC,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.access_mode(FILE_GENERIC_READ | WRITE_DAC);
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|_| ProtectedPathError::Io)?;
    let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
    if !metadata.is_file() {
        return Err(ProtectedPathError::InvalidPath);
    }
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    protect_user_owned_opened_handle(&file, false, sid)?;
    Ok(file)
}

/// Creates and protects one `ProgramData` descendant directory.  Components
/// are created one at a time while each parent no-follow handle is retained.
///
/// # Errors
///
/// Returns an error when the path escapes the protected root, contains a
/// reparse point, cannot receive the protected ACL, or cannot be created.
pub fn prepare_protected_directory(path: &Path) -> Result<(), ProtectedPathError> {
    let root = expected_root()?;
    ensure_protected_containment(&root, path)?;
    let relative = path
        .strip_prefix(&root)
        .map_err(|_| ProtectedPathError::InvalidPath)?;
    protected_components(relative)?;
    #[cfg(windows)]
    {
        let _directories = open_directory_contour(&root, relative, true)?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err(ProtectedPathError::UnsupportedPlatform)
    }
}

/// Validates and retains an existing protected file immediately before a
/// path-based consumer opens it.  Production consumers should retain the
/// returned lease instead of calling this convenience validator.
///
/// # Errors
///
/// Returns an error when the file is outside the protected root or its
/// no-follow identity and ACL cannot be verified.
pub fn validate_protected_file(path: &Path) -> Result<(), ProtectedPathError> {
    let _lease = ProtectedPathLease::open_existing_absolute(path)?;
    Ok(())
}

/// Reads one protected file through a retained no-follow handle.  The path is
/// never reopened after the lease is acquired.
///
/// # Errors
///
/// Returns an error when the file cannot be opened safely, handle I/O fails,
/// or the file exceeds `limit`.
pub fn read_protected_file(path: &Path, limit: u64) -> Result<Vec<u8>, ProtectedPathError> {
    ProtectedPathLease::open_existing_absolute(path)?.read_bounded(limit)
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
            Err(_) => return Err(ProtectedPathError::Io),
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
            Err(_) => return Err(ProtectedPathError::Io),
        }
    }
    Ok(())
}

fn validate_directory_no_reparse(path: &Path) -> Result<(), ProtectedPathError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ProtectedPathError::Io)?;
    if !metadata.is_dir() {
        return Err(ProtectedPathError::InvalidRoot);
    }
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(ProtectedPathError::ReparsePoint);
    }
    Ok(())
}

#[cfg(windows)]
fn open_directory_contour(
    root: &Path,
    relative: &Path,
    create: bool,
) -> Result<Vec<std::fs::File>, ProtectedPathError> {
    let components = if relative.as_os_str().is_empty() {
        Vec::new()
    } else {
        protected_components(relative)?
    };
    let mut current = root.to_path_buf();
    let mut directories = vec![pin_directory(root).map_err(|_| ProtectedPathError::Io)?];
    for component in components {
        current.push(component);
        let directory = match open_protected_directory(&current) {
            Ok(directory) => directory,
            Err(ProtectedPathError::Io) if create => match std::fs::create_dir(&current) {
                Ok(()) => open_protected_directory(&current)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    open_protected_directory(&current)?
                }
                Err(_) => return Err(ProtectedPathError::Io),
            },
            Err(error) => return Err(error),
        };
        directories.push(directory);
    }
    Ok(directories)
}

#[cfg(windows)]
fn pin_protected_directory_contour(
    root: &Path,
    relative: &Path,
) -> Result<Vec<std::fs::File>, ProtectedPathError> {
    let components = protected_components(relative)?;
    let mut current = root.to_path_buf();
    let mut directories = vec![pin_directory(root).map_err(|_| ProtectedPathError::Io)?];
    for component in components {
        current.push(component);
        directories.push(pin_directory(&current).map_err(|_| ProtectedPathError::Io)?);
    }
    Ok(directories)
}

#[cfg(windows)]
fn open_protected_directory(path: &Path) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, WRITE_DAC,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.access_mode(FILE_GENERIC_READ | WRITE_DAC);
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|_| ProtectedPathError::Io)?;
    let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    protect_opened_handle(&file, true)?;
    Ok(file)
}

#[cfg(windows)]
fn open_protected_file(path: &Path, create: bool) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true);
    options.access_mode(legacy_protected_file_access_mode());
    // Deliberately omit FILE_SHARE_DELETE.  The retained handle is the
    // substitution barrier for redb's path-based open.
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = if create {
        options.create_new(true).open(path).or_else(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                let mut existing = std::fs::OpenOptions::new();
                existing.read(true).write(true);
                existing.access_mode(legacy_protected_file_access_mode());
                existing.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
                existing.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
                existing.open(path)
            } else {
                Err(error)
            }
        })
    } else {
        options.open(path)
    }
    .map_err(|_| ProtectedPathError::Io)?;
    let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
    if !metadata.is_file() {
        return Err(ProtectedPathError::InvalidPath);
    }
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    Ok(file)
}

#[cfg(windows)]
fn legacy_protected_file_access_mode() -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, WRITE_DAC,
    };
    FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC
}

#[cfg(windows)]
fn protect_opened_handle(file: &std::fs::File, directory: bool) -> Result<(), ProtectedPathError> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    #[cfg(any(test, feature = "test-support"))]
    if test_protected_root().is_some() {
        return protect_user_owned_opened_handle(file, directory, &current_process_sid()?);
    }
    let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    if directory != metadata.is_dir() {
        return Err(ProtectedPathError::InvalidPath);
    }
    let descriptor = OwnedSecurityDescriptor::for_protected_storage()
        .map_err(|_| ProtectedPathError::AclMismatch)?;
    let dacl = descriptor
        .dacl()
        .map_err(|_| ProtectedPathError::AclMismatch)?;
    let security = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let status = unsafe {
        windows_sys::Win32::Security::Authorization::SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            security,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if status != 0 {
        return Err(ProtectedPathError::AclMismatch);
    }
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() {
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
    unsafe { LocalFree(descriptor.cast()) };
    if !dacl_matches || !protected {
        return Err(ProtectedPathError::AclMismatch);
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
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
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
    let security = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let status = unsafe {
        windows_sys::Win32::Security::Authorization::SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            security,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if status != 0 {
        return Err(ProtectedPathError::AclMismatch);
    }
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            security,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() {
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
    unsafe { LocalFree(descriptor.cast()) };
    if !dacl_matches || !protected {
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

    /// Issues the opaque Host-only credential mutation capability.
    ///
    /// The capability can only be derived from a freshly-created owner lease;
    /// callers cannot construct the raw `LocalService` Credential Manager
    /// primitive directly.  The lease itself must remain live for the Host
    /// composition lifetime.
    ///
    /// # Errors
    ///
    /// Returns `IdentityMismatch` when this lease no longer owns its mutex.
    pub fn credential_mutation_capability(
        &self,
    ) -> Result<HostCredentialMutationCapability, WindowsAdapterError> {
        let _gate = self
            .authority
            .gate
            .lock()
            .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        if !self.owns || self.authority.revoked.load(Ordering::Acquire) {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(HostCredentialMutationCapability {
            installation_digest: host_owner_identity_digest(&self.name),
            authority: Arc::clone(&self.authority),
        })
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

/// Stable identity of a Windows file object.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    /// Volume serial number.
    pub volume_serial_number: u32,
    /// File index on the volume.
    pub file_index: u64,
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

/// Result of publishing bytes through the Windows atomic replacement path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    /// Identity of the published file after replacement.
    pub identity: FileIdentity,
}

/// Caller-proven identity and content fence for replacing one existing owned
/// runtime receipt.  A digest without the retained file identity is never a
/// sufficient replacement precondition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationPrecondition {
    /// Exact retained destination identity observed by the caller.
    pub identity: FileIdentity,
    /// SHA-256 of the exact canonical bytes observed through that identity.
    pub sha256: String,
}

impl PublicationPrecondition {
    /// Captures the compare-and-swap fence from the exact bytes read through
    /// the retained destination identity. The digest is deliberately over the
    /// complete serialized file, not an inner receipt/content digest.
    #[must_use]
    pub fn from_bytes(identity: FileIdentity, bytes: &[u8]) -> Self {
        Self {
            identity,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }
}

/// A publication whose external effect cannot be classified as committed.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicationUnknown {
    /// Replacement committed, but the post-commit identity read was unavailable.
    PostCommitIdentityUnavailable,
    /// The destination was replaced again before the receipt could be bound.
    DestinationIdentityChanged,
}

/// Reconciliation evidence returned after a replacement whose final provider
/// observation was inconclusive. The staged file identity is always retained
/// so a caller may reopen and compare identity, path, and content; bytes alone
/// never classify this result as published.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationUnknownReceipt {
    /// Provider classification of the ambiguous post-commit observation.
    pub reason: PublicationUnknown,
    /// Exact identity of the same-parent staged file moved into place.
    pub expected_identity: FileIdentity,
}

/// Publication result that does not overclaim after a post-commit failure.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum PublicationOutcome {
    Published(PublicationReceipt),
    Unknown(PublicationUnknownReceipt),
}

#[cfg(windows)]
const OWNED_RUNTIME_RECEIPT_PUBLICATION_LOCK: &str = ".eliot-owned-runtime-receipt.publish.lock";

/// Publishes one Kernel-owned runtime receipt below the canonical protected
/// `ProgramData` contour. The optional identity/content pair is a
/// compare-and-swap fence for a receipt previously proven by the caller; an
/// unbound existing destination is never replaced. No-follow parent pins are
/// retained through replacement and the final bytes and identity are read
/// back exactly.
///
/// # Errors
///
/// Returns a typed path, identity, or provider error before publication, and
/// preserves a post-commit unknown outcome when the final identity/readback
/// cannot be classified.
#[allow(clippy::too_many_lines)]
pub fn publish_atomic_owned_runtime_receipt(
    path: &Path,
    bytes: &[u8],
    expected_existing: Option<&PublicationPrecondition>,
) -> Result<PublicationOutcome, PortError> {
    #[cfg(not(windows))]
    {
        let _ = (path, bytes, expected_existing);
        return Err(PortError::Provider(provider_failed()));
    }
    #[cfg(windows)]
    {
        if !path.is_absolute() || bytes.is_empty() {
            return Err(PortError::InvalidPath);
        }
        if expected_existing.is_some_and(|expected| {
            expected.sha256.len() != 64
                || !expected
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(PortError::IdentityConflict);
        }
        let root = expected_root().map_err(|_| PortError::InvalidPath)?;
        ensure_protected_containment(&root, path).map_err(|_| PortError::InvalidPath)?;
        let canonical = match std::fs::symlink_metadata(path) {
            Ok(metadata) if is_reparse_point(&metadata) || metadata.file_type().is_symlink() => {
                return Err(PortError::InvalidPath);
            }
            Ok(_) => canonical_windows_path(path).map_err(|_| PortError::InvalidPath)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = path.parent().ok_or(PortError::InvalidPath)?;
                let parent = canonical_windows_path(parent).map_err(|_| PortError::InvalidPath)?;
                let leaf = path.file_name().ok_or(PortError::InvalidPath)?;
                parent.join(leaf)
            }
            Err(_) => return Err(PortError::InvalidPath),
        };
        ensure_protected_containment(&root, &canonical).map_err(|_| PortError::InvalidPath)?;
        let parent = canonical.parent().ok_or(PortError::InvalidPath)?;
        let pins = pin_ancestors(&root, parent)?;

        // Every writer using this production primitive owns the same retained,
        // protected sibling handle before it observes the destination.  The
        // predecessor remains pinned without FILE_SHARE_DELETE until the
        // commit boundary; only then is it released while this protocol lease
        // still excludes another authorized publisher.  A bypassing
        // create-new race is independently stopped by the no-replace move.
        let _publication_lock = acquire_owned_runtime_receipt_publication_lock(parent)?;

        let mut existing = match open_runtime_read_file(&canonical) {
            Ok(mut file) => {
                let identity = file_identity_from_handle(&file)
                    .map_err(|_| PortError::Provider(provider_failed()))?;
                let mut existing_bytes = Vec::new();
                file.read_to_end(&mut existing_bytes)
                    .map_err(|_| PortError::Provider(provider_failed()))?;
                let actual = format!("{:x}", Sha256::digest(&existing_bytes));
                match expected_existing {
                    Some(expected)
                        if expected.sha256 == actual && expected.identity == identity =>
                    {
                        Some(file)
                    }
                    Some(_) | None => return Err(PortError::IdentityConflict),
                }
            }
            Err(_) => match std::fs::symlink_metadata(&canonical) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if expected_existing.is_some() {
                        return Err(PortError::IdentityConflict);
                    }
                    None
                }
                _ => return Err(PortError::Provider(provider_failed())),
            },
        };
        let temporary = create_temporary(parent, bytes)?;
        let Ok(staged_identity) = file_identity(&temporary) else {
            let _ = std::fs::remove_file(&temporary);
            return Err(PortError::Provider(provider_failed()));
        };
        if let Err(error) = validate_destination(&canonical) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        if let Some(file) = existing.as_mut() {
            let current_identity = file_identity_from_handle(file)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            if file.seek(SeekFrom::Start(0)).is_err() {
                let _ = std::fs::remove_file(&temporary);
                return Err(PortError::Provider(provider_failed()));
            }
            let mut current_bytes = Vec::new();
            if file.read_to_end(&mut current_bytes).is_err() {
                let _ = std::fs::remove_file(&temporary);
                return Err(PortError::Provider(provider_failed()));
            }
            let actual = format!("{:x}", Sha256::digest(&current_bytes));
            if expected_existing.is_none_or(|expected| {
                expected.sha256 != actual || expected.identity != current_identity
            }) {
                let _ = std::fs::remove_file(&temporary);
                return Err(PortError::IdentityConflict);
            }
        }
        drop(existing);
        let commit = if expected_existing.is_some() {
            replace_file(&temporary, &canonical)
        } else {
            move_file_create_new(&temporary, &canonical)
        };
        if let Err(error) = commit {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        flush_directory(&pins);
        #[cfg(any(test, feature = "test-support"))]
        if TEST_RECEIPT_PUBLICATION_UNKNOWN.with(|slot| slot.replace(false)) {
            return Ok(PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::PostCommitIdentityUnavailable,
                expected_identity: staged_identity,
            }));
        }
        let Ok(identity) = file_identity(&canonical) else {
            return Ok(PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::PostCommitIdentityUnavailable,
                expected_identity: staged_identity,
            }));
        };
        if identity != staged_identity {
            return Ok(PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::DestinationIdentityChanged,
                expected_identity: staged_identity,
            }));
        }
        let Ok(mut readback) = open_runtime_read_file(&canonical) else {
            return Ok(PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::PostCommitIdentityUnavailable,
                expected_identity: staged_identity,
            }));
        };
        let mut readback_bytes = Vec::new();
        if readback.read_to_end(&mut readback_bytes).is_err() {
            return Ok(PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::PostCommitIdentityUnavailable,
                expected_identity: staged_identity,
            }));
        }
        if readback_bytes != bytes {
            return Ok(PublicationOutcome::Unknown(PublicationUnknownReceipt {
                reason: PublicationUnknown::DestinationIdentityChanged,
                expected_identity: staged_identity,
            }));
        }
        Ok(PublicationOutcome::Published(PublicationReceipt {
            identity,
        }))
    }
}

/// Failure before a create-new directory publication can commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryPublicationError {
    /// A caller path is relative, traversing, non-canonical or not an owned
    /// same-parent temporary name.
    InvalidPath,
    /// An ancestor, parent or source directory is a reparse point.
    ReparsePoint,
    /// The destination already exists, including a concurrent create race.
    AlreadyExists,
    /// A retained source, parent or destination object changed identity.
    IdentityMismatch,
    /// Windows failed before the move committed.
    Io,
    /// The primitive is intentionally unavailable off Windows.
    UnsupportedPlatform,
}

impl std::fmt::Display for DirectoryPublicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "directory publication path is invalid",
            Self::ReparsePoint => "directory publication contour contains a reparse point",
            Self::AlreadyExists => "directory publication destination already exists",
            Self::IdentityMismatch => "directory publication identity changed",
            Self::Io => "directory publication I/O failed before commit",
            Self::UnsupportedPlatform => "directory publication requires Windows",
        })
    }
}

impl std::error::Error for DirectoryPublicationError {}

/// Exact identity receipt after a create-new directory move is read back.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPublicationReceipt {
    /// Caller-declared final path, validated against retained handles.
    pub destination_path: String,
    /// Canonical retained parent path used by the move.
    pub canonical_parent_path: String,
    /// Identity of the retained destination parent.
    pub parent_identity: FileIdentity,
    /// Identity of the owned temporary directory before the move.
    pub source_identity: FileIdentity,
    /// Identity of the destination directory after the move.
    pub destination_identity: FileIdentity,
}

/// Why a committed directory move could not be promoted to a receipt.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DirectoryPublicationUnknown {
    /// Test or provider discrimination made the post-commit read unavailable.
    PostCommitReadbackUnavailable,
    /// The retained moved handle no longer named the expected destination.
    PostCommitPathChanged,
    /// The moved or reopened destination identity could not be measured.
    PostCommitIdentityUnavailable,
    /// The moved or reopened destination was not the exact source object.
    PostCommitIdentityChanged,
}

/// Durable facts retained when the move committed but readback is uncertain.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPublicationUnknownReceipt {
    /// Exact reason receipt promotion was withheld.
    pub reason: DirectoryPublicationUnknown,
    /// Caller-declared final path of the committed move.
    pub destination_path: String,
    /// Canonical retained parent path used by the move.
    pub canonical_parent_path: String,
    /// Identity of the retained destination parent.
    pub parent_identity: FileIdentity,
    /// Exact identity of the owned temporary directory passed to the move.
    pub source_identity: FileIdentity,
}

/// Create-new directory publication result. A successful OS move never
/// becomes `Err`: post-commit ambiguity is returned with reconcilable facts.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum DirectoryPublicationOutcome {
    /// Destination path and directory identity were read back exactly.
    Published(DirectoryPublicationReceipt),
    /// The move committed, but receipt promotion requires reconciliation.
    CommittedUnknown(DirectoryPublicationUnknownReceipt),
}

/// Prepared process-owned create-new directory publication.
///
/// Construction retains the complete destination-parent contour through
/// no-follow, no-delete-sharing handles *before* it creates the same-parent
/// temporary directory. The contour remains live while the caller fills and
/// reads back the temporary tree, and until publication or rollback finishes.
pub struct OwnedDirectoryPublication {
    temporary: PathBuf,
    destination: PathBuf,
    initial_temporary_identity: FileIdentity,
    #[cfg(windows)]
    contour: DirectoryPublicationContour,
    /// The source directory object is retained from construction through the
    /// move.  It is opened no-follow with delete sharing so existing staging
    /// readback can coexist with the retained authority, while all
    /// identity/readback observations remain bound to this exact object rather
    /// than a later pathname lookup.
    #[cfg(windows)]
    temporary_handle: Option<std::fs::File>,
    committed: bool,
}

impl std::fmt::Debug for OwnedDirectoryPublication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedDirectoryPublication")
            .field("temporary", &self.temporary)
            .field("destination", &self.destination)
            .field(
                "initial_temporary_identity",
                &self.initial_temporary_identity,
            )
            .field("committed", &self.committed)
            .finish_non_exhaustive()
    }
}

impl OwnedDirectoryPublication {
    /// Retain the exact destination contour and create one absent owned
    /// same-parent temporary directory.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid or reparse paths, an existing final
    /// destination, identity substitution, provider I/O failure, or a
    /// non-Windows platform.
    pub fn create(destination: &Path) -> Result<Self, DirectoryPublicationError> {
        #[cfg(windows)]
        {
            prepare_owned_directory_publication(destination)
        }
        #[cfg(not(windows))]
        {
            let _ = destination;
            Err(DirectoryPublicationError::UnsupportedPlatform)
        }
    }

    /// Exact absolute temporary directory held below the retained parent.
    #[must_use]
    pub fn temporary_path(&self) -> &Path {
        &self.temporary
    }

    /// Identity captured immediately after create-new temporary allocation.
    #[must_use]
    pub const fn temporary_identity(&self) -> FileIdentity {
        self.initial_temporary_identity
    }

    /// Atomically move the completely materialized temporary directory to the
    /// absent destination with write-through and no replacement semantics.
    ///
    /// The supplied identity must be independently measured by the caller's
    /// complete pre-commit readback. A successful Windows move is never
    /// reported as `Err`; uncertain post-commit readback returns a typed
    /// reconcilable outcome.
    ///
    /// # Errors
    ///
    /// Returns only pre-commit path, destination-race, identity or I/O errors.
    pub fn publish(
        mut self,
        precommit_temporary_identity: FileIdentity,
    ) -> Result<DirectoryPublicationOutcome, DirectoryPublicationError> {
        #[cfg(windows)]
        {
            self.publish_inner(precommit_temporary_identity, || {}, None)
        }
        #[cfg(not(windows))]
        {
            let _ = precommit_temporary_identity;
            Err(DirectoryPublicationError::UnsupportedPlatform)
        }
    }
}

impl Drop for OwnedDirectoryPublication {
    fn drop(&mut self) {
        if self.committed || !self.temporary.is_absolute() {
            return;
        }
        #[cfg(windows)]
        {
            // Recursive directory deletion cannot be made identity-bound by
            // checking a pathname, closing the check handle, and then calling
            // `remove_dir_all`: a replacement can win that gap.  Keep the
            // retained source/contour handles as the authority and quarantine
            // an uncommitted tree instead.  The caller's bounded cleanup layer
            // may remove it later through its own handle-bound protocol; this
            // destructor never deletes by an unbound pathname.
        }
    }
}

/// Handle-bound identity of a live Windows process.
///
/// The PID is only a lookup key.  `start_time_100ns` and `image_path` are
/// measured through the same live process handle and therefore make PID
/// reuse or image substitution observable to the caller.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub process_id: u32,
    pub start_time_100ns: u64,
    pub image_path: String,
}

/// Stable name of one owner-scoped Windows Job Object.
///
/// This is mechanics identity only. It carries no process-dispatch authority.
#[cfg(windows)]
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct JobObjectIdentity {
    name: String,
}

#[cfg(windows)]
impl JobObjectIdentity {
    /// Validates one exact Job Object name.
    ///
    /// # Errors
    /// Returns `InvalidInput` for an empty name, embedded NUL, or a name wider
    /// than the bounded Windows object-manager representation used here.
    pub fn new(name: impl Into<String>) -> Result<Self, WindowsAdapterError> {
        let name = name.into();
        if !valid_job_object_name(&name) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self { name })
    }

    /// Revalidates shape after deserializing a raw durable binding.
    ///
    /// This check grants no authority and does not prove that the named kernel
    /// object exists. [`RecoverableJobObject::open`] still has to reopen the
    /// Job and compare a fresh handle-bound root observation.
    ///
    /// # Errors
    /// Returns `InvalidInput` for an invalid or unbounded object-manager name.
    pub fn validate(&self) -> Result<(), WindowsAdapterError> {
        if valid_job_object_name(&self.name) {
            Ok(())
        } else {
            Err(WindowsAdapterError::InvalidInput)
        }
    }

    /// Returns the exact Windows object-manager name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(windows)]
fn valid_job_object_name(name: &str) -> bool {
    let length = name.encode_utf16().count();
    length != 0 && length <= 240 && !name.chars().any(char::is_control)
}

/// Windows Job resource ceilings configured before the first process is
/// assigned. P-04 maps its provider-neutral P-03 limits into this mechanics
/// value; the type itself grants no launch authority.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobObjectLimits {
    cpu_time_ms: Option<u64>,
    memory_bytes: Option<u64>,
    active_process_limit: Option<u32>,
}

#[cfg(windows)]
impl JobObjectLimits {
    /// Creates validated optional Job limits.
    ///
    /// # Errors
    /// Returns `InvalidInput` when a supplied ceiling is zero or cannot be
    /// represented by the Win32 Job Object structures.
    pub fn new(
        cpu_time_ms: Option<u64>,
        memory_bytes: Option<u64>,
        active_process_limit: Option<u32>,
    ) -> Result<Self, WindowsAdapterError> {
        if matches!(cpu_time_ms, Some(0))
            || matches!(memory_bytes, Some(0))
            || matches!(active_process_limit, Some(0))
            || memory_bytes.is_some_and(|value| usize::try_from(value).is_err())
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        if let Some(cpu_time_ms) = cpu_time_ms {
            let ticks = cpu_time_ms
                .checked_mul(10_000)
                .ok_or(WindowsAdapterError::InvalidInput)?;
            i64::try_from(ticks).map_err(|_| WindowsAdapterError::InvalidInput)?;
        }
        Ok(Self {
            cpu_time_ms,
            memory_bytes,
            active_process_limit,
        })
    }
}

/// Historical process membership observed from the Job completion port.
///
/// `complete` is true only after the kernel reported an empty Job and every
/// process-announcement event was resolved through a retained process handle.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservation {
    process: ProcessIdentity,
    executable: FileIdentity,
}

/// Durable raw binding used only to reopen and revalidate one named Job.
///
/// The value is not authority: `RecoverableJobObject::open` must re-observe
/// the exact root identity before returning a live mechanics handle.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverableJobBinding {
    job: JobObjectIdentity,
    root: ProcessObservation,
}

#[cfg(windows)]
impl RecoverableJobBinding {
    /// Validates only the bounded serialized shape.
    ///
    /// The result is not proof of a live process or Job. Callers must pass the
    /// binding to [`RecoverableJobObject::open`] for fresh kernel revalidation.
    ///
    /// # Errors
    /// Returns `InvalidInput` for malformed Job or root-process identity.
    pub fn validate(&self) -> Result<(), WindowsAdapterError> {
        self.job.validate()?;
        let root = self.root.process();
        let image_length = root.image_path.encode_utf16().count();
        if root.process_id == 0
            || root.start_time_100ns == 0
            || image_length == 0
            || image_length > 32_767
            || root.image_path.chars().any(char::is_control)
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(())
    }

    /// Returns the bound Job Object identity.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        &self.job
    }

    /// Returns the exact root process/image observation.
    #[must_use]
    pub const fn root(&self) -> &ProcessObservation {
        &self.root
    }
}

#[cfg(windows)]
impl ProcessObservation {
    /// Returns the retained-handle process identity.
    #[must_use]
    pub const fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    /// Returns the file-object identity of the observed executable image.
    #[must_use]
    pub const fn executable_file_identity(&self) -> FileIdentity {
        self.executable
    }

    fn stable_key(&self) -> String {
        format!(
            "{}:volume:{}:file:{}",
            self.process.stable_key(),
            self.executable.volume_serial_number,
            self.executable.file_index
        )
    }
}

/// Why a Job history cannot be claimed complete.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobObservationGap {
    /// At least one kernel process notification could not be resolved to an
    /// exact retained process/image identity before the process disappeared.
    IdentityCaptureFailed,
}

/// Historical process membership observed from the Job completion port.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobProcessHistory {
    processes: Vec<ProcessObservation>,
    complete: bool,
    job_empty: bool,
    capture_gap: Option<JobObservationGap>,
    resource_limit_triggered: bool,
}

#[cfg(windows)]
impl JobProcessHistory {
    /// Returns all distinct process identities observed during this Job life.
    #[must_use]
    pub fn processes(&self) -> &[ProcessObservation] {
        &self.processes
    }

    /// Returns whether the historical membership observation is complete.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns whether the Job was observed with zero active members.
    #[must_use]
    pub const fn job_empty(&self) -> bool {
        self.job_empty
    }

    /// Returns the explicit observation gap that prevented completeness.
    #[must_use]
    pub const fn capture_gap(&self) -> Option<JobObservationGap> {
        self.capture_gap
    }

    /// Returns whether the kernel emitted a CPU, memory, or process-count
    /// limit notification for this Job.
    #[must_use]
    pub const fn resource_limit_triggered(&self) -> bool {
        self.resource_limit_triggered
    }
}

impl ProcessIdentity {
    fn is_usable(&self) -> bool {
        self.process_id != 0
            && self.start_time_100ns != 0
            && valid_process_image_path(&self.image_path)
    }

    /// Stable comparison key; a PID alone is never sufficient.
    #[must_use]
    pub fn stable_key(&self) -> String {
        format!(
            "windows-pid:{}:start:{}:image:{}",
            self.process_id, self.start_time_100ns, self.image_path
        )
    }
}

/// OS-observed process identity that may be used to pin named-pipe admission.
///
/// The identity is private and this type has no deserializer or public
/// constructor. Callers can obtain it only through
/// [`observe_named_pipe_peer_process`], which opens and observes the live
/// process handle. The contained identity is evidence, not request data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPipePeerProcessBinding {
    identity: ProcessIdentity,
}

impl NamedPipePeerProcessBinding {
    fn from_observed(identity: ProcessIdentity) -> Result<Self, WindowsAdapterError> {
        if !identity.is_usable() {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self { identity })
    }

    /// Returns the read-only process evidence captured by the platform.
    #[must_use]
    pub const fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    /// Returns the observed process identifier.
    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.identity.process_id
    }

    /// Returns the observed process creation time in Windows 100-nanosecond
    /// units.
    #[must_use]
    pub const fn start_time_100ns(&self) -> u64 {
        self.identity.start_time_100ns
    }

    /// Returns the observed process image path.
    #[must_use]
    pub fn image_path(&self) -> &str {
        &self.identity.image_path
    }
}

/// OS-observed process identity retained together with one exact owner Job.
///
/// The Job name is only a lookup key.  Admission reopens and re-observes the
/// named Job, process identity, and current membership before accepting a
/// pipe peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPipePeerJobBinding {
    process: NamedPipePeerProcessBinding,
    job_name: String,
}

impl NamedPipePeerJobBinding {
    fn from_observed(
        process: NamedPipePeerProcessBinding,
        job_name: impl Into<String>,
    ) -> Result<Self, WindowsAdapterError> {
        let job_name = job_name.into();
        if !valid_named_job_identity(&job_name) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self { process, job_name })
    }

    /// Returns the retained handle-bound process evidence.
    #[must_use]
    pub const fn process_binding(&self) -> &NamedPipePeerProcessBinding {
        &self.process
    }

    /// Returns the exact owner-scoped Job identity.
    #[must_use]
    pub fn job_name(&self) -> &str {
        &self.job_name
    }
}

/// Expected authorization context for a named-pipe server.
///
/// The expectation is inert policy input.  It becomes evidence only after the
/// platform adapter observes the pipe handle, server process and token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPipePeerExpectation {
    expected_sid: String,
    expected_session_id: u32,
    approved_process: Option<NamedPipePeerProcessBinding>,
    approved_job_process: Option<NamedPipePeerJobBinding>,
    builtin_administrators: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamedPipeAuthDiscriminator {
    Ordinary,
    BuiltinAdministrators,
}

/// Installer-pinned inputs for the separately registered Watchdog fallback
/// task.  This value is configuration, not an authority token: registration
/// still proves the live caller's SID/session and verifies both immutable
/// artifact/config digests before touching Task Scheduler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogTaskRegistration {
    task_name: String,
    notify_executable: PathBuf,
    verifier_path: PathBuf,
    envelope_path: PathBuf,
    expected_sid: String,
    expected_session_id: u32,
    notify_artifact_sha256: String,
    verifier_sha256: String,
}

impl WatchdogTaskRegistration {
    /// Creates a registration request from installer-pinned paths and
    /// digests.  The live SID/session and protected file identities are proved
    /// by [`register_interactive_watchdog_task`].
    ///
    /// # Errors
    ///
    /// Returns an error when any fixed identity, absolute path, session, SID,
    /// or artifact digest is invalid.
    #[allow(
        clippy::too_many_arguments,
        reason = "installer-pinned paths, identity, session, and digests remain explicit"
    )]
    pub fn new(
        task_name: impl Into<String>,
        notify_executable: impl Into<PathBuf>,
        verifier_path: impl Into<PathBuf>,
        envelope_path: impl Into<PathBuf>,
        expected_sid: impl Into<String>,
        expected_session_id: u32,
        notify_artifact_sha256: impl Into<String>,
        verifier_sha256: impl Into<String>,
    ) -> Result<Self, WindowsAdapterError> {
        let task_name = task_name.into();
        let notify_executable = notify_executable.into();
        let verifier_path = verifier_path.into();
        let envelope_path = envelope_path.into();
        let expected_sid = expected_sid.into();
        let notify_artifact_sha256 = notify_artifact_sha256.into();
        let verifier_sha256 = verifier_sha256.into();
        if task_name != WATCHDOG_FALLBACK_TASK_NAME
            || !notify_executable.is_absolute()
            || !verifier_path.is_absolute()
            || !envelope_path.is_absolute()
            || !valid_sid_text(&expected_sid)
            || expected_session_id == 0
            || !valid_sha256_hex(&notify_artifact_sha256)
            || !valid_sha256_hex(&verifier_sha256)
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self {
            task_name,
            notify_executable,
            verifier_path,
            envelope_path,
            expected_sid,
            expected_session_id,
            notify_artifact_sha256,
            verifier_sha256,
        })
    }

    #[must_use]
    pub fn task_name(&self) -> &str {
        &self.task_name
    }

    #[must_use]
    pub fn notify_executable(&self) -> &Path {
        &self.notify_executable
    }

    #[must_use]
    pub fn verifier_path(&self) -> &Path {
        &self.verifier_path
    }

    #[must_use]
    pub fn envelope_path(&self) -> &Path {
        &self.envelope_path
    }

    #[must_use]
    pub fn expected_sid(&self) -> &str {
        &self.expected_sid
    }

    #[must_use]
    pub const fn expected_session_id(&self) -> u32 {
        self.expected_session_id
    }

    #[must_use]
    pub fn notify_artifact_sha256(&self) -> &str {
        &self.notify_artifact_sha256
    }

    #[must_use]
    pub fn verifier_sha256(&self) -> &str {
        &self.verifier_sha256
    }
}

/// Observation returned only after Task Scheduler accepted the exact
/// interactive-user registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogTaskRegistrationReceipt {
    task_name: String,
    sid: String,
    session_id: u32,
    notify_artifact_sha256: String,
    verifier_sha256: String,
    task_xml_sha256: String,
}

impl WatchdogTaskRegistrationReceipt {
    #[must_use]
    pub fn task_name(&self) -> &str {
        &self.task_name
    }

    #[must_use]
    pub fn sid(&self) -> &str {
        &self.sid
    }

    #[must_use]
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    #[must_use]
    pub fn notify_artifact_sha256(&self) -> &str {
        &self.notify_artifact_sha256
    }

    #[must_use]
    pub fn verifier_sha256(&self) -> &str {
        &self.verifier_sha256
    }

    #[must_use]
    pub fn task_xml_sha256(&self) -> &str {
        &self.task_xml_sha256
    }
}

/// Fixed scheduler identity for the X-01 fallback.  A caller cannot choose a
/// second task name or turn this route into a general command scheduler.
pub const WATCHDOG_FALLBACK_TASK_NAME: &str = r"\Eliot\WatchdogFallback";
const WATCHDOG_FALLBACK_TASK_FOLDER: &str = r"\Eliot";
const WATCHDOG_FALLBACK_TASK_LEAF: &str = "WatchdogFallback";

/// Registers the signed Watchdog fallback for the current interactive user.
///
/// The COM call uses `TASK_LOGON_INTERACTIVE_TOKEN` with empty credentials;
/// this boundary never manufactures, accepts or persists a logon token.  The
/// task runs only in the installer-bound interactive SID/session and invokes
/// the fixed no-stdin `--watchdog-fallback` mode.
///
/// # Errors
///
/// Returns an error when pinned registration evidence is invalid, the caller
/// identity mismatches, or Task Scheduler registration/readback fails.
pub fn register_interactive_watchdog_task(
    registration: &WatchdogTaskRegistration,
) -> Result<WatchdogTaskRegistrationReceipt, WindowsAdapterError> {
    validate_watchdog_registration(registration)?;
    #[cfg(windows)]
    {
        register_watchdog_task_windows(registration)
    }
    #[cfg(not(windows))]
    {
        let _ = registration;
        Err(WindowsAdapterError::Unavailable)
    }
}

#[cfg(windows)]
fn validate_watchdog_registration(
    registration: &WatchdogTaskRegistration,
) -> Result<(), WindowsAdapterError> {
    let current = current_process_named_pipe_expectation()?;
    if current.expected_sid() != registration.expected_sid
        || current.expected_session_id() != registration.expected_session_id
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let executable = validate_pinned_artifact(
        &registration.notify_executable,
        &registration.notify_artifact_sha256,
    )?;
    if executable != registration.notify_executable {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let root = protected_program_data_root().map_err(|_| WindowsAdapterError::Unavailable)?;
    ensure_protected_containment(&root, &registration.verifier_path)
        .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
    ensure_protected_containment(&root, &registration.envelope_path)
        .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
    let verifier = ProtectedPathLease::open_existing_absolute(&registration.verifier_path)
        .map_err(|_| WindowsAdapterError::Unavailable)?;
    verifier
        .verify_stable_identity()
        .and_then(|()| verifier.verify_path_identity())
        .map_err(|_| WindowsAdapterError::Unavailable)?;
    let bytes = verifier
        .read_bounded(64 * 1024)
        .map_err(|_| WindowsAdapterError::Unavailable)?;
    if sha256_hex(&bytes) != registration.verifier_sha256 {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(not(windows))]
fn validate_watchdog_registration(
    _registration: &WatchdogTaskRegistration,
) -> Result<(), WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

/// Validates an installer-pinned executable with no-follow/reparse checks and
/// returns the exact canonical path used for the digest proof.
///
/// # Errors
///
/// Returns an error when the path or digest is invalid, the artifact is absent
/// or a reparse point, its identity changes, or its digest mismatches.
pub fn validate_pinned_artifact(
    path: &Path,
    expected_sha256: &str,
) -> Result<PathBuf, WindowsAdapterError> {
    if !path.is_absolute() || !valid_sha256_hex(expected_sha256) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    #[cfg(windows)]
    {
        use std::io::Read;
        use std::os::windows::fs::OpenOptionsExt;

        reject_reparse_chain(path, true).map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        let canonical = std::fs::canonicalize(path).map_err(|_| WindowsAdapterError::NotFound)?;
        reject_reparse_chain(&canonical, true)
            .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).share_mode(
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
        );
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
        let mut file = options
            .open(&canonical)
            .map_err(|_| WindowsAdapterError::NotFound)?;
        let metadata = file
            .metadata()
            .map_err(|_| WindowsAdapterError::Unavailable)?;
        if !metadata.is_file() || is_reparse_point(&metadata) {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        if metadata.len() > 256 * 1024 * 1024 {
            return Err(WindowsAdapterError::InvalidInput);
        }
        let mut bytes = Vec::with_capacity(metadata.len().try_into().unwrap_or(0));
        file.read_to_end(&mut bytes)
            .map_err(|_| WindowsAdapterError::Unavailable)?;
        if sha256_hex(&bytes) != expected_sha256 {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(canonical)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, expected_sha256);
        Err(WindowsAdapterError::Unavailable)
    }
}

#[cfg(windows)]
fn register_watchdog_task_windows(
    registration: &WatchdogTaskRegistration,
) -> Result<WatchdogTaskRegistrationReceipt, WindowsAdapterError> {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::TaskScheduler::{
        CLSID_CTaskScheduler, ITaskService, TASK_CREATE_OR_UPDATE, TASK_LOGON_INTERACTIVE_TOKEN,
    };
    use windows::Win32::System::Variant::VARIANT;
    use windows::core::BSTR;

    let initialized = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if initialized.0 < 0 {
        return Err(WindowsAdapterError::Unavailable);
    }
    let result = (|| {
        let service: ITaskService =
            unsafe { CoCreateInstance(&CLSID_CTaskScheduler, None, CLSCTX_INPROC_SERVER) }
                .map_err(|_| WindowsAdapterError::Unavailable)?;
        let empty = VARIANT::default();
        unsafe {
            service
                .Connect(&empty, &empty, &empty, &empty)
                .map_err(|_| WindowsAdapterError::Unavailable)?;
        }
        let root = unsafe {
            service
                .GetFolder(&BSTR::from("\\"))
                .map_err(|_| WindowsAdapterError::Unavailable)?
        };
        let folder = get_or_create_watchdog_folder(&root, &empty)?;
        let xml = watchdog_task_xml(registration);
        let registered = match unsafe {
            folder.RegisterTask(
                &BSTR::from(WATCHDOG_FALLBACK_TASK_LEAF),
                &BSTR::from(xml),
                TASK_CREATE_OR_UPDATE.0,
                &empty,
                &empty,
                TASK_LOGON_INTERACTIVE_TOKEN,
                &empty,
            )
        } {
            Ok(registered) => registered,
            Err(_) => {
                // RegisterTask may have committed before its response was
                // lost. Reopen the exact leaf and classify by readback.
                unsafe {
                    folder
                        .GetTask(&BSTR::from(WATCHDOG_FALLBACK_TASK_LEAF))
                        .map_err(|_| WindowsAdapterError::Unavailable)?
                }
            }
        };
        let actual_xml = readback_watchdog_task(&registered, registration)?;
        Ok(WatchdogTaskRegistrationReceipt {
            task_name: registration.task_name.clone(),
            sid: registration.expected_sid.clone(),
            session_id: registration.expected_session_id,
            notify_artifact_sha256: registration.notify_artifact_sha256.clone(),
            verifier_sha256: registration.verifier_sha256.clone(),
            task_xml_sha256: sha256_hex(actual_xml.as_bytes()),
        })
    })();
    unsafe {
        CoUninitialize();
    }
    result
}

/// Requests one immediate run of an already registered fallback task after
/// the protected Watchdog envelope is present.  A scheduler/API failure is
/// returned as `Unavailable` so callers retain an unknown/reconcile cursor;
/// it is never projected as a successful notification.
///
/// # Errors
///
/// Returns an error when pinned registration or envelope evidence is invalid,
/// or when Task Scheduler cannot start and verify the fixed task.
pub fn run_registered_watchdog_task(
    registration: &WatchdogTaskRegistration,
) -> Result<WatchdogTaskRunReceipt, WindowsAdapterError> {
    validate_watchdog_registration(registration)?;
    let envelope = ProtectedPathLease::open_existing_absolute(&registration.envelope_path)
        .map_err(|_| WindowsAdapterError::NotFound)?;
    envelope
        .verify_stable_identity()
        .and_then(|()| envelope.verify_path_identity())
        .and_then(|()| envelope.read_bounded(64 * 1024).map(|_| ()))
        .map_err(|_| WindowsAdapterError::Unavailable)?;
    #[cfg(windows)]
    {
        run_registered_watchdog_task_windows(registration)
    }
    #[cfg(not(windows))]
    {
        let _ = registration;
        Err(WindowsAdapterError::Unavailable)
    }
}

/// Observation returned only after Task Scheduler accepted a bounded run
/// request for the registered interactive SID/session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogTaskRunReceipt {
    task_name: String,
    sid: String,
    session_id: u32,
    task_xml_sha256: String,
}

impl WatchdogTaskRunReceipt {
    #[must_use]
    pub fn task_name(&self) -> &str {
        &self.task_name
    }

    #[must_use]
    pub fn sid(&self) -> &str {
        &self.sid
    }

    #[must_use]
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    #[must_use]
    pub fn task_xml_sha256(&self) -> &str {
        &self.task_xml_sha256
    }
}

#[cfg(windows)]
fn run_registered_watchdog_task_windows(
    registration: &WatchdogTaskRegistration,
) -> Result<WatchdogTaskRunReceipt, WindowsAdapterError> {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::TaskScheduler::{
        CLSID_CTaskScheduler, ITaskService, TASK_RUN_USE_SESSION_ID,
    };
    use windows::Win32::System::Variant::VARIANT;
    use windows::core::BSTR;

    let initialized = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if initialized.0 < 0 {
        return Err(WindowsAdapterError::Unavailable);
    }
    let result = (|| {
        let service: ITaskService =
            unsafe { CoCreateInstance(&CLSID_CTaskScheduler, None, CLSCTX_INPROC_SERVER) }
                .map_err(|_| WindowsAdapterError::Unavailable)?;
        let empty = VARIANT::default();
        unsafe {
            service
                .Connect(&empty, &empty, &empty, &empty)
                .map_err(|_| WindowsAdapterError::Unavailable)?;
        }
        let root = unsafe {
            service
                .GetFolder(&BSTR::from("\\"))
                .map_err(|_| WindowsAdapterError::Unavailable)?
        };
        let folder = unsafe {
            root.GetFolder(&BSTR::from(WATCHDOG_FALLBACK_TASK_FOLDER))
                .map_err(|_| WindowsAdapterError::Unavailable)?
        };
        let task = unsafe {
            folder
                .GetTask(&BSTR::from(WATCHDOG_FALLBACK_TASK_LEAF))
                .map_err(|_| WindowsAdapterError::Unavailable)?
        };
        let actual_xml = readback_watchdog_task(&task, registration)?;
        let session_id = i32::try_from(registration.expected_session_id())
            .map_err(|_| WindowsAdapterError::InvalidInput)?;
        if unsafe {
            task.RunEx(
                &empty,
                TASK_RUN_USE_SESSION_ID.0,
                session_id,
                &BSTR::from(registration.expected_sid()),
            )
        }
        .is_err()
        {
            // A lost HRESULT is not proof of a failed run. Re-read the exact
            // task to reject replacement, then retain the unknown outcome
            // because XML cannot bind a later state to this invocation.
            let _ = readback_watchdog_task(&task, registration)?;
            return Err(WindowsAdapterError::Unavailable);
        }
        Ok(WatchdogTaskRunReceipt {
            task_name: registration.task_name.clone(),
            sid: registration.expected_sid.clone(),
            session_id: registration.expected_session_id,
            task_xml_sha256: sha256_hex(actual_xml.as_bytes()),
        })
    })();
    unsafe {
        CoUninitialize();
    }
    result
}

#[cfg(windows)]
fn readback_watchdog_task(
    task: &windows::Win32::System::TaskScheduler::IRegisteredTask,
    registration: &WatchdogTaskRegistration,
) -> Result<String, WindowsAdapterError> {
    let actual_path = unsafe { task.Path().map_err(|_| WindowsAdapterError::Unavailable)? };
    let actual_xml = unsafe { task.Xml().map_err(|_| WindowsAdapterError::Unavailable)? };
    let actual_xml =
        String::try_from(&actual_xml).map_err(|_| WindowsAdapterError::IdentityMismatch)?;
    if actual_path != registration.task_name()
        || !watchdog_task_readback_matches(registration, &actual_xml)
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    Ok(actual_xml)
}

#[allow(
    clippy::too_many_lines,
    reason = "the fail-closed Task Scheduler XML shape remains one contiguous predicate"
)]
fn watchdog_task_readback_matches(
    registration: &WatchdogTaskRegistration,
    actual_xml: &str,
) -> bool {
    let Some(task) = xml_section(actual_xml, "Task") else {
        return false;
    };
    let Some(registration_info) = xml_section(task, "RegistrationInfo") else {
        return false;
    };
    let Some(triggers) = xml_section(task, "Triggers") else {
        return false;
    };
    let Some(principals) = xml_section(task, "Principals") else {
        return false;
    };
    let Some(settings) = xml_section(task, "Settings") else {
        return false;
    };
    let Some(actions) = xml_section(task, "Actions") else {
        return false;
    };
    if opening_tag(actual_xml, "Task")
        != Some(
            r#"<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">"#,
        )
        || !has_exact_tag_shape(
            registration_info,
            &[
                ("RegistrationInfo", 1),
                ("Author", 1),
                ("Description", 1),
                ("URI", 1),
            ],
        )
        || opening_tag(principals, "Principal") != Some(r#"<Principal id="Author">"#)
        || opening_tag(actions, "Actions") != Some(r#"<Actions Context="Author">"#)
        || !has_exact_tag_shape(
            triggers,
            &[
                ("Triggers", 1),
                ("LogonTrigger", 1),
                ("Enabled", 1),
                ("UserId", 1),
            ],
        )
        || !has_exact_tag_shape(
            principals,
            &[
                ("Principals", 1),
                ("Principal", 1),
                ("UserId", 1),
                ("LogonType", 1),
                ("RunLevel", 1),
            ],
        )
        || !has_exact_tag_shape(
            settings,
            &[
                ("Settings", 1),
                ("MultipleInstancesPolicy", 1),
                ("DisallowStartIfOnBatteries", 1),
                ("StopIfGoingOnBatteries", 1),
                ("AllowHardTerminate", 1),
                ("StartWhenAvailable", 1),
                ("ExecutionTimeLimit", 1),
                ("Priority", 1),
            ],
        )
        || !has_exact_tag_shape(
            actions,
            &[
                ("Actions", 1),
                ("Exec", 1),
                ("Command", 1),
                ("Arguments", 1),
                ("WorkingDirectory", 1),
            ],
        )
    {
        return false;
    }
    let escaped_sid = xml_escape(registration.expected_sid());
    let escaped_executable = xml_escape(&registration.notify_executable.display().to_string());
    let escaped_working_directory = xml_escape(
        &registration
            .notify_executable
            .parent()
            .unwrap_or_else(|| Path::new("\\"))
            .display()
            .to_string(),
    );
    let escaped_verifier = xml_escape(&registration.verifier_path.display().to_string());
    let escaped_envelope = xml_escape(&registration.envelope_path.display().to_string());
    let description = format!(
        "X-01 signed one-shot Watchdog fallback; verifier={escaped_verifier}; envelope={escaped_envelope}; artifact={}; verifier_sha256={}",
        registration.notify_artifact_sha256(),
        registration.verifier_sha256()
    );
    element_text(actual_xml, "URI") == Some(registration.task_name())
        && element_text(triggers, "Enabled") == Some("true")
        && element_text(triggers, "UserId") == Some(escaped_sid.as_str())
        && element_text(principals, "UserId") == Some(escaped_sid.as_str())
        && element_text(principals, "LogonType") == Some("InteractiveToken")
        && element_text(principals, "RunLevel") == Some("LeastPrivilege")
        && element_text(settings, "MultipleInstancesPolicy") == Some("IgnoreNew")
        && element_text(settings, "DisallowStartIfOnBatteries") == Some("false")
        && element_text(settings, "StopIfGoingOnBatteries") == Some("false")
        && element_text(settings, "AllowHardTerminate") == Some("true")
        && element_text(settings, "StartWhenAvailable") == Some("true")
        && element_text(settings, "ExecutionTimeLimit") == Some("PT5M")
        && element_text(settings, "Priority") == Some("7")
        && element_text(actions, "Command") == Some(escaped_executable.as_str())
        && element_text(actions, "Arguments") == Some("--watchdog-fallback")
        && element_text(actions, "WorkingDirectory") == Some(escaped_working_directory.as_str())
        && element_text(registration_info, "Author") == Some("Eliot installer")
        && element_text(registration_info, "Description") == Some(description.as_str())
        && element_text(actual_xml, "Description") == Some(description.as_str())
}

fn watchdog_task_xml(registration: &WatchdogTaskRegistration) -> String {
    let task_name = xml_escape(registration.task_name());
    let sid = xml_escape(registration.expected_sid());
    let executable = xml_escape(&registration.notify_executable.display().to_string());
    let working_directory = xml_escape(
        &registration
            .notify_executable
            .parent()
            .unwrap_or_else(|| Path::new("\\"))
            .display()
            .to_string(),
    );
    let verifier = xml_escape(&registration.verifier_path.display().to_string());
    let envelope = xml_escape(&registration.envelope_path.display().to_string());
    let artifact_digest = xml_escape(registration.notify_artifact_sha256());
    let verifier_digest = xml_escape(registration.verifier_sha256());
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Eliot installer</Author>
    <Description>X-01 signed one-shot Watchdog fallback; verifier={verifier}; envelope={envelope}; artifact={artifact_digest}; verifier_sha256={verifier_digest}</Description>
    <URI>{task_name}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{sid}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{sid}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{executable}</Command>
      <Arguments>--watchdog-fallback</Arguments>
      <WorkingDirectory>{working_directory}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"#
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(windows)]
fn get_or_create_watchdog_folder(
    root: &windows::Win32::System::TaskScheduler::ITaskFolder,
    empty: &windows::Win32::System::Variant::VARIANT,
) -> Result<windows::Win32::System::TaskScheduler::ITaskFolder, WindowsAdapterError> {
    use windows::core::BSTR;
    match unsafe { root.GetFolder(&BSTR::from(WATCHDOG_FALLBACK_TASK_FOLDER)) } {
        Ok(folder) => Ok(folder),
        Err(_) => unsafe {
            root.CreateFolder(&BSTR::from("Eliot"), empty)
                .or_else(|_| root.GetFolder(&BSTR::from(WATCHDOG_FALLBACK_TASK_FOLDER)))
        }
        .map_err(|_| WindowsAdapterError::Unavailable),
    }
}

fn xml_section<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}");
    let start = xml.find(&open)?;
    let open_end = xml[start..].find('>')? + start + 1;
    let close = format!("</{tag}>");
    let close_start = xml[open_end..].find(&close)? + open_end;
    if count_xml_open_tag(xml, tag) != 1 {
        return None;
    }
    Some(&xml[start..close_start + close.len()])
}

fn element_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if xml.match_indices(&open).count() != 1 || xml.match_indices(&close).count() != 1 {
        return None;
    }
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim())
}

fn opening_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let prefix = format!("<{tag}");
    let start = xml.match_indices(&prefix).find_map(|(index, _)| {
        matches!(
            xml.get(index + prefix.len()..)
                .and_then(|rest| rest.chars().next()),
            Some(' ' | '>' | '/')
        )
        .then_some(index)
    })?;
    let end = xml[start..].find('>')? + start + 1;
    Some(&xml[start..end])
}

fn count_xml_open_tag(xml: &str, tag: &str) -> usize {
    let prefix = format!("<{tag}");
    xml.match_indices(&prefix)
        .filter(|(index, _)| {
            matches!(
                xml.get(index + prefix.len()..)
                    .and_then(|rest| rest.chars().next()),
                Some(' ' | '>' | '/')
            )
        })
        .count()
}

fn has_exact_tag_shape(xml: &str, expected: &[(&str, usize)]) -> bool {
    let names = xml_open_tag_names(xml);
    let expected_total = expected.iter().map(|(_, count)| *count).sum::<usize>();
    names.len() == expected_total
        && expected
            .iter()
            .all(|(tag, count)| names.iter().filter(|name| name.as_str() == *tag).count() == *count)
}

fn xml_open_tag_names(xml: &str) -> Vec<String> {
    let bytes = xml.as_bytes();
    let mut names = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let Some(relative) = xml[index..].find('<') else {
            break;
        };
        let start = index + relative;
        let Some(next) = bytes.get(start + 1).copied() else {
            break;
        };
        if matches!(next, b'/' | b'!' | b'?') {
            index = start + 1;
            continue;
        }
        let name_start = start + 1;
        let name_end = (name_start..bytes.len())
            .find(|candidate| {
                matches!(
                    bytes[*candidate],
                    b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/'
                )
            })
            .unwrap_or(bytes.len());
        if name_end > name_start {
            names.push(xml[name_start..name_end].to_owned());
        }
        index = name_end.saturating_add(1);
    }
    names
}

impl NamedPipePeerExpectation {
    /// Creates inert expected SID/session policy.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the SID is not canonical SID text.
    pub fn new(
        expected_sid: impl Into<String>,
        expected_session_id: u32,
    ) -> Result<Self, WindowsAdapterError> {
        let expected_sid = expected_sid.into();
        if !valid_sid_text(&expected_sid) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self {
            expected_sid,
            expected_session_id,
            approved_process: None,
            approved_job_process: None,
            builtin_administrators: false,
        })
    }

    /// Creates inert policy for an elevated installer client. The live pipe
    /// client is impersonated and its token must have the built-in
    /// Administrators group enabled; its exact user SID/session are still
    /// returned as evidence and bound to the connected process.
    ///
    /// # Errors
    ///
    /// This constructor currently cannot fail; the `Result` preserves the
    /// constructor shape shared with validated peer expectations.
    pub fn new_for_builtin_administrators() -> Result<Self, WindowsAdapterError> {
        Ok(Self {
            expected_sid: "S-1-5-32-544".to_owned(),
            expected_session_id: 0,
            approved_process: None,
            approved_job_process: None,
            builtin_administrators: true,
        })
    }

    /// Creates an expectation that additionally admits one exact OS-observed
    /// process binding. A PID supplied by a request cannot replace this
    /// binding.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the SID or binding is invalid.
    pub fn new_with_process_binding(
        expected_sid: impl Into<String>,
        expected_session_id: u32,
        approved_process: NamedPipePeerProcessBinding,
    ) -> Result<Self, WindowsAdapterError> {
        let mut expectation = Self::new(expected_sid, expected_session_id)?;
        expectation.approved_process = Some(approved_process);
        Ok(expectation)
    }

    /// Creates an expectation that requires one exact OS-observed process and
    /// its current membership in one exact owner Job.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the SID, session, or Job identity is invalid.
    pub fn new_with_process_and_job_binding(
        expected_sid: impl Into<String>,
        expected_session_id: u32,
        approved_process: NamedPipePeerJobBinding,
    ) -> Result<Self, WindowsAdapterError> {
        let mut expectation = Self::new(expected_sid, expected_session_id)?;
        expectation.approved_process = Some(approved_process.process.clone());
        expectation.approved_job_process = Some(approved_process);
        Ok(expectation)
    }

    /// Adds one exact OS-observed process binding to this expectation.
    ///
    /// This is a typed builder rather than a request-field setter: admission
    /// still obtains the observed identity from the operating system.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the binding is invalid.
    pub fn with_process_binding(
        mut self,
        approved_process: NamedPipePeerProcessBinding,
    ) -> Result<Self, WindowsAdapterError> {
        self.approved_process = Some(approved_process);
        Ok(self)
    }

    /// Adds one exact OS-observed process and Job binding to this expectation.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the retained Job identity is invalid.
    pub fn with_process_and_job_binding(
        mut self,
        approved_process: NamedPipePeerJobBinding,
    ) -> Result<Self, WindowsAdapterError> {
        self.approved_process = Some(approved_process.process.clone());
        self.approved_job_process = Some(approved_process);
        Ok(self)
    }

    #[must_use]
    pub fn expected_sid(&self) -> &str {
        &self.expected_sid
    }

    #[must_use]
    pub const fn expected_session_id(&self) -> u32 {
        self.expected_session_id
    }

    /// Whether admission requires enabled built-in Administrators membership
    /// instead of equality with one account SID/session.
    #[must_use]
    pub const fn requires_builtin_administrators(&self) -> bool {
        self.builtin_administrators
    }

    fn auth_discriminator(&self) -> NamedPipeAuthDiscriminator {
        if self.builtin_administrators {
            NamedPipeAuthDiscriminator::BuiltinAdministrators
        } else {
            NamedPipeAuthDiscriminator::Ordinary
        }
    }

    /// Returns the optional exact OS-observed process binding admitted by this
    /// policy.
    #[must_use]
    pub fn approved_process_binding(&self) -> Option<&NamedPipePeerProcessBinding> {
        self.approved_process.as_ref()
    }

    /// Returns the optional exact process/Job binding admitted by this policy.
    #[must_use]
    pub fn approved_process_job_binding(&self) -> Option<&NamedPipePeerJobBinding> {
        self.approved_job_process.as_ref()
    }
}

/// Sealed observation of the server at the other end of a live pipe handle.
///
/// Fields are private and this type is not deserializable, so callers cannot
/// turn a PID or SID string into authenticated transport authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPipePeerEvidence {
    process: ProcessIdentity,
    sid: String,
    session_id: u32,
}

impl NamedPipePeerEvidence {
    #[must_use]
    pub fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    #[must_use]
    pub fn sid(&self) -> &str {
        &self.sid
    }

    #[must_use]
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }
}

/// User-scoped DPAPI ciphertext.  The bytes carry no authority and are not
/// serializable by this crate.
pub struct ProtectedSecret(Vec<u8>);

impl ProtectedSecret {
    /// Adopts opaque DPAPI ciphertext returned by durable storage.
    ///
    /// # Errors
    /// Returns [`WindowsAdapterError::InvalidInput`] for empty ciphertext.
    pub fn from_ciphertext(ciphertext: Vec<u8>) -> Result<Self, WindowsAdapterError> {
        if ciphertext.is_empty() {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self(ciphertext))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Secret bytes read from Credential Manager.  Debug/serde are deliberately
/// absent and memory is cleared when the value is dropped.
pub struct CredentialSecret(Vec<u8>);

impl CredentialSecret {
    /// Moves already-secret bytes into a zeroizing owner.
    ///
    /// # Errors
    /// Empty or oversized `WinCred` blobs are rejected.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, WindowsAdapterError> {
        if bytes.is_empty() || bytes.len() > 2560 {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for CredentialSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Readback of one installer-owned Credential Manager target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerSecretObservation {
    /// The exact target does not exist.
    Absent,
    /// The exact target contains a bounded 256-bit ownership key.
    Present,
}

/// Result of creating an installer ownership key at an already-durable target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerSecretCreateDisposition {
    /// This call created the exact Credential Manager entry.
    Created,
    /// The exact target already contained a valid ownership key.
    AlreadyExists,
}

/// Narrow current-user Credential Manager provider for installer ownership keys.
///
/// The provider never returns generated key bytes from creation. Callers durably
/// persist only the unpredictable target returned by [`Self::fresh_reference`]
/// and must commit that reference before calling [`Self::create_at`].
///
/// This is an OS/Credential Manager primitive, not transaction authority. The
/// current-user SID and `CredMan` vault are the trust boundary; the installation
/// adapter alone combines this primitive with durable intent and an HMAC-bound
/// receipt. User/portable profiles therefore have the explicitly weaker
/// same-user boundary provided by Windows Credential Manager.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsInstallerSecretProvider;

impl WindowsInstallerSecretProvider {
    const KEY_BYTES: usize = 32;
    const REFERENCE_RANDOM_BYTES: usize = 16;

    /// Creates a provider without opening or changing Credential Manager.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the exact Windows SID owning this current-user provider scope.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error when the process token cannot be observed.
    pub fn principal_sid(&self) -> Result<PlatformHandle, WindowsAdapterError> {
        let sid = current_process_sid().map_err(|_| WindowsAdapterError::Unavailable)?;
        PlatformHandle::new(sid).map_err(|_| WindowsAdapterError::InvalidInput)
    }

    /// Issues a non-secret unpredictable Credential Manager target.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error when Windows CSPRNG is unavailable.
    pub fn fresh_reference(&self) -> Result<PlatformHandle, WindowsAdapterError> {
        let mut random = [0_u8; Self::REFERENCE_RANDOM_BYTES];
        fill_system_random(&mut random)?;
        let reference = format!("eliot/installer-root/v1/{}", hex_lower(&random));
        random.fill(0);
        PlatformHandle::new(reference).map_err(|_| WindowsAdapterError::InvalidInput)
    }

    /// Authoritatively observes the exact target without creating it.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error for invalid targets, provider failure, or
    /// a present credential whose secret is not exactly 256 bits.
    pub fn inspect(
        &self,
        reference: &PlatformHandle,
    ) -> Result<InstallerSecretObservation, WindowsAdapterError> {
        if !valid_installer_credential_target(reference.as_str()) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        match credential_read_optional(reference.as_str())? {
            Some(secret) if secret.expose().len() == Self::KEY_BYTES => {
                Ok(InstallerSecretObservation::Present)
            }
            Some(_) => Err(WindowsAdapterError::InvalidInput),
            None => Ok(InstallerSecretObservation::Absent),
        }
    }

    /// Creates a 256-bit key at an exact target whose intent is already durable.
    ///
    /// Key bytes are generated inside this call, written to Credential Manager,
    /// and cleared before return. Existing valid entries are never overwritten.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error for invalid targets, RNG failure, or
    /// Credential Manager failure.
    pub fn create_at(
        &self,
        reference: &PlatformHandle,
    ) -> Result<InstallerSecretCreateDisposition, WindowsAdapterError> {
        if !valid_installer_credential_target(reference.as_str()) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        match self.inspect(reference)? {
            InstallerSecretObservation::Present => {
                return Ok(InstallerSecretCreateDisposition::AlreadyExists);
            }
            InstallerSecretObservation::Absent => {}
        }
        let mut secret = [0_u8; Self::KEY_BYTES];
        fill_system_random(&mut secret)?;
        let result = credential_write(reference.as_str(), &secret);
        secret.fill(0);
        result?;
        match self.inspect(reference)? {
            InstallerSecretObservation::Present => Ok(InstallerSecretCreateDisposition::Created),
            InstallerSecretObservation::Absent => Err(WindowsAdapterError::Unavailable),
        }
    }

    /// Reads the exact 256-bit key into a zeroizing value.
    ///
    /// # Errors
    ///
    /// Missing, inaccessible, or malformed entries fail closed.
    pub fn read(
        &self,
        reference: &PlatformHandle,
    ) -> Result<CredentialSecret, WindowsAdapterError> {
        if !valid_installer_credential_target(reference.as_str()) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        let secret = credential_read(reference.as_str())?;
        if secret.expose().len() != Self::KEY_BYTES {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(secret)
    }

    /// Deletes an exact terminal ownership credential.
    ///
    /// # Errors
    ///
    /// Missing and inaccessible entries remain explicit failures.
    pub fn delete(&self, reference: &PlatformHandle) -> Result<(), WindowsAdapterError> {
        if !valid_installer_credential_target(reference.as_str()) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        credential_delete(reference.as_str())
    }
}

/// Dedicated Windows OS-CSPRNG target factory for the `LocalService` Store
/// credential namespace.
///
/// This semantic factory is intentionally separate from installer ownership
/// references and Kernel activation nonces. It returns only the non-secret
/// Credential Manager target; credential bytes are generated and written by
/// the authenticated Store credential effect.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsStoreCredentialTargetGenerator;

impl WindowsStoreCredentialTargetGenerator {
    const RANDOM_BYTES: usize = 16;

    /// Constructs a target factory without touching Credential Manager.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Issues one unpredictable `eliot/store/v1/<32 lowercase hex>` target.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error when the Windows OS CSPRNG is
    /// unavailable or the bounded target cannot be represented.
    pub fn fresh_target(&self) -> Result<PlatformHandle, WindowsAdapterError> {
        let mut random = [0_u8; Self::RANDOM_BYTES];
        fill_system_random(&mut random)?;
        let target = format!("{STORE_CREDENTIAL_TARGET_PREFIX}{}", hex_lower(&random));
        random.fill(0);
        PlatformHandle::new(target).map_err(|_| WindowsAdapterError::InvalidInput)
    }
}

/// Raw current-token Credential Manager primitive used by the `LocalService`
/// Host.  It is deliberately private: callers must obtain the opaque
/// Host-owned capability from a live [`HostOwnerLease`].
#[derive(Clone, Copy, Debug, Default)]
struct WindowsLocalServiceCredentialProvider;

#[allow(
    clippy::trivially_copy_pass_by_ref,
    clippy::unused_self,
    reason = "the provider methods are kept as an opaque instance boundary"
)]
impl WindowsLocalServiceCredentialProvider {
    /// Creates the primitive without reading or mutating Credential Manager.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the current process-token SID.
    ///
    /// # Errors
    /// Returns an error when the process token cannot be observed.
    pub fn principal_sid(&self) -> Result<PlatformHandle, WindowsAdapterError> {
        let sid = current_process_sid().map_err(|_| WindowsAdapterError::Unavailable)?;
        PlatformHandle::new(sid).map_err(|_| WindowsAdapterError::InvalidInput)
    }

    /// Generates 256 secret bits in a zeroizing value without persisting them.
    ///
    /// # Errors
    /// Returns an error when the Windows CSPRNG is unavailable.
    pub fn generate_secret(&self) -> Result<CredentialSecret, WindowsAdapterError> {
        let mut secret = vec![0_u8; 32];
        fill_system_random(&mut secret)?;
        Ok(CredentialSecret(secret))
    }

    /// Reads an exact target under the current token.
    ///
    /// # Errors
    /// Returns an error for invalid targets or provider failure.
    pub fn read_optional(
        &self,
        target: &PlatformHandle,
    ) -> Result<Option<CredentialSecret>, WindowsAdapterError> {
        if !valid_credential_key(target.as_str()) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        credential_read_optional(target.as_str())
    }

    /// Writes exact bytes. This raw `WinCred` call can replace an entry; durable
    /// marker ownership and an immediately preceding absence check are required.
    ///
    /// # Errors
    /// Returns an error for invalid targets or provider failure.
    pub fn write(
        &self,
        target: &PlatformHandle,
        secret: &CredentialSecret,
    ) -> Result<(), WindowsAdapterError> {
        if !valid_credential_key(target.as_str()) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        credential_write(target.as_str(), secret.expose())
    }

    /// Deletes the exact target.
    ///
    /// # Errors
    /// Missing and inaccessible targets fail closed.
    pub fn delete(&self, target: &PlatformHandle) -> Result<(), WindowsAdapterError> {
        if !valid_credential_key(target.as_str()) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        credential_delete(target.as_str())
    }
}

/// Opaque capability for the authenticated Host credential boundary.
///
/// The capability owns no secret and exposes only operations needed by the
/// Host composition.  The write-if-absent operation holds a protected,
/// per-installation/per-target mutex across the final read, `CredWriteW`, and
/// authoritative readback.  This closes the real `WinCred` read/write race;
/// a second observation immediately before `CredWriteW` is not an atomic
/// ownership check.
#[derive(Debug)]
pub struct HostCredentialMutationCapability {
    installation_digest: String,
    authority: Arc<HostLeaseAuthority>,
}

#[allow(
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::trivially_copy_pass_by_ref,
    clippy::unused_self,
    reason = "this opaque capability deliberately preserves the provider API boundary"
)]
impl HostCredentialMutationCapability {
    pub fn principal_sid(&self) -> Result<PlatformHandle, WindowsAdapterError> {
        self.with_authority(|| WindowsLocalServiceCredentialProvider::new().principal_sid())
    }

    pub fn read_optional(
        &self,
        target: &PlatformHandle,
    ) -> Result<Option<CredentialSecret>, WindowsAdapterError> {
        self.with_authority(|| WindowsLocalServiceCredentialProvider::new().read_optional(target))
    }

    pub fn generate_secret(&self) -> Result<CredentialSecret, WindowsAdapterError> {
        self.with_authority(|| WindowsLocalServiceCredentialProvider::new().generate_secret())
    }

    pub fn write_if_absent(
        &self,
        target: &PlatformHandle,
        secret: CredentialSecret,
    ) -> Result<CredentialSecret, WindowsAdapterError> {
        self.with_authority(|| {
            let primitive = WindowsLocalServiceCredentialProvider::new();
            primitive.with_target_interlock(&self.installation_digest, target, || {
                if primitive.read_optional(target)?.is_some() {
                    return Err(WindowsAdapterError::AlreadyExists);
                }
                primitive.write(target, &secret)?;
                primitive
                    .read_optional(target)?
                    .ok_or(WindowsAdapterError::Unavailable)
            })
        })
    }

    pub fn delete(&self, target: &PlatformHandle) -> Result<(), WindowsAdapterError> {
        self.with_authority(|| {
            let primitive = WindowsLocalServiceCredentialProvider::new();
            primitive.with_target_interlock(&self.installation_digest, target, || {
                primitive.delete(target)
            })
        })
    }

    pub fn delete_if_matching(
        &self,
        target: &PlatformHandle,
        expected_digest: &PlatformHandle,
        mut verify: impl FnMut(&CredentialSecret) -> bool,
    ) -> Result<(), WindowsAdapterError> {
        self.with_authority(|| {
            let primitive = WindowsLocalServiceCredentialProvider::new();
            primitive.with_target_interlock(&self.installation_digest, target, || {
                if let Some(value) = primitive.read_optional(target)? {
                    if format!("{:x}", Sha256::digest(value.expose())) != expected_digest.as_str()
                        || !verify(&value)
                    {
                        return Err(WindowsAdapterError::IdentityMismatch);
                    }
                    primitive.delete(target)?;
                }
                if primitive.read_optional(target)?.is_some() {
                    return Err(WindowsAdapterError::Unavailable);
                }
                Ok(())
            })
        })
    }

    fn with_authority<T>(
        &self,
        operation: impl FnOnce() -> Result<T, WindowsAdapterError>,
    ) -> Result<T, WindowsAdapterError> {
        let _gate = self
            .authority
            .gate
            .lock()
            .map_err(|_| WindowsAdapterError::IdentityMismatch)?;
        if self.authority.revoked.load(Ordering::Acquire) {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        operation()
    }
}

fn host_owner_identity_digest(name: &str) -> String {
    format!("{:x}", Sha256::digest(name.as_bytes()))
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    clippy::unused_self,
    reason = "the provider methods are kept as an opaque instance boundary"
)]
impl WindowsLocalServiceCredentialProvider {
    fn with_target_interlock<T>(
        &self,
        installation_digest: &str,
        target: &PlatformHandle,
        operation: impl FnOnce() -> Result<T, WindowsAdapterError>,
    ) -> Result<T, WindowsAdapterError> {
        let _interlock = HostCredentialInterlock::acquire(installation_digest, target)?;
        operation()
    }
}

struct HostCredentialInterlock {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
}

impl HostCredentialInterlock {
    fn acquire(
        installation_digest: &str,
        target: &PlatformHandle,
    ) -> Result<Self, WindowsAdapterError> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0};
            use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
            use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};
            let digest =
                Sha256::digest(format!("{installation_digest}\0{}", target.as_str()).as_bytes());
            let mut suffix = String::with_capacity(digest.len() * 2);
            for byte in digest {
                use std::fmt::Write as _;
                let _ = write!(suffix, "{byte:02x}");
            }
            let name = format!("{HOST_CREDENTIAL_MUTEX_PREFIX}{suffix}");
            let wide_name = nul_terminated_wide(std::ffi::OsStr::new(&name))
                .map_err(|_| WindowsAdapterError::InvalidInput)?;
            let descriptor = OwnedSecurityDescriptor::for_host_owner()?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                    .map_err(|_| WindowsAdapterError::InvalidInput)?,
                lpSecurityDescriptor: descriptor.raw,
                bInheritHandle: 0,
            };
            let handle = unsafe { CreateMutexW(&raw const attributes, 0, wide_name.as_ptr()) };
            if handle.is_null() {
                return Err(last_windows_adapter_error());
            }
            let wait = unsafe { WaitForSingleObject(handle, u32::MAX) };
            if wait == WAIT_OBJECT_0 {
                Ok(Self { handle })
            } else {
                let _ = unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
                Err(if wait == WAIT_ABANDONED {
                    WindowsAdapterError::IdentityMismatch
                } else {
                    last_windows_adapter_error()
                })
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (installation_digest, target);
            Err(WindowsAdapterError::Unavailable)
        }
    }
}

#[cfg(windows)]
impl Drop for HostCredentialInterlock {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::ReleaseMutex;
        let _ = unsafe { ReleaseMutex(self.handle) };
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

/// Account under which SCM starts an ELIOT-owned Windows service.
///
/// Password-bearing custom accounts are intentionally absent. P-10 must use a
/// separately governed credential path before such an account can be added.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceAccount {
    LocalSystem,
    LocalService,
    NetworkService,
}

/// SCM start mode admitted by the P-02 registration adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceStartMode {
    Automatic,
    Demand,
    Disabled,
}

/// Exact SCM service-SID mode admitted by the installation adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceSidType {
    /// The service has no service SID in its process token.
    None,
    /// SCM adds the deterministic `NT SERVICE\\<name>` SID to the token.
    Unrestricted,
}

impl ServiceSidType {
    const fn raw(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Unrestricted => 1,
        }
    }
}

/// Canonical SCM names owned by the Runtime Live installer.
pub const ELIOT_HOST_SERVICE_NAME: &str = "EliotHost";
pub const ELIOT_WATCHDOG_SERVICE_NAME: &str = "EliotWatchdog";
pub const ELIOT_HOST_SERVICE_DISPLAY_NAME: &str = "Eliot Host";
pub const ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME: &str = "Eliot Watchdog";

/// Exact service-object rights granted to the `EliotHost` service SID on the
/// canonical `EliotWatchdog` registration.
///
/// The mask is deliberately concrete rather than generic: query-config and
/// query-status are required for the retained readback contour, start/stop are
/// the only mutations admitted to Host, and `READ_CONTROL` is required to
/// reverify the protected DACL. It excludes change-config, delete, write-DACL,
/// write-owner, pause/continue and user-defined control rights.
pub const ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK: u32 =
    0x0000_0001 | 0x0000_0004 | 0x0000_0010 | 0x0000_0020 | 0x0002_0000;

/// Authoritative readback of the one narrow service-object grant installed by
/// the privileged installer for the non-elevated Host service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceControlGrantReadback {
    principal_service: String,
    principal_sid: String,
    access_mask: u32,
    security_descriptor_digest: String,
}

impl ServiceControlGrantReadback {
    fn new(
        principal_service: impl Into<String>,
        principal_sid: impl Into<String>,
        access_mask: u32,
        security_descriptor_digest: impl Into<String>,
    ) -> Result<Self, WindowsAdapterError> {
        let value = Self {
            principal_service: principal_service.into(),
            principal_sid: principal_sid.into(),
            access_mask,
            security_descriptor_digest: security_descriptor_digest.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the canonical service whose deterministic SID receives the
    /// grant.
    #[must_use]
    pub fn principal_service(&self) -> &str {
        &self.principal_service
    }

    /// Returns the OS-resolved `S-1-5-80-...` service SID.
    #[must_use]
    pub fn principal_sid(&self) -> &str {
        &self.principal_sid
    }

    /// Returns the exact concrete service-object access mask.
    #[must_use]
    pub const fn access_mask(&self) -> u32 {
        self.access_mask
    }

    /// Returns the digest of the protected, byte-exact service DACL contour.
    #[must_use]
    pub fn security_descriptor_digest(&self) -> &str {
        &self.security_descriptor_digest
    }

    /// Validates the typed readback without touching SCM.
    ///
    /// # Errors
    ///
    /// Returns [`WindowsAdapterError::IdentityMismatch`] when the principal,
    /// concrete access mask, or descriptor digest differs from the canonical
    /// Host-to-Watchdog control grant.
    pub fn validate(&self) -> Result<(), WindowsAdapterError> {
        if self.principal_service != ELIOT_HOST_SERVICE_NAME
            || !valid_service_sid_text(&self.principal_sid)
            || self.access_mask != ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK
            || !valid_sha256_hex(&self.security_descriptor_digest)
            || !watchdog_service_security_descriptor_digest(&self.principal_sid)
                .is_ok_and(|expected| expected == self.security_descriptor_digest)
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(())
    }
}

/// Provider-neutral, typed authority passed to an SCM service through argv.
///
/// The four named values are deliberately not read from ambient environment
/// state. `extra_args` is retained in caller order and is validated as argv
/// data; it is never accepted as an already-rendered command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceBootstrapArguments {
    config_descriptor_path: PathBuf,
    config_descriptor_digest: String,
    installation_id: String,
    transaction_plan_generation: u64,
    host_state_root: Option<PathBuf>,
    registration_nonce: Option<String>,
    extra_args: Vec<String>,
}

impl ServiceBootstrapArguments {
    /// Creates the canonical bootstrap binding used by durable services.
    ///
    /// # Errors
    /// Returns `InvalidInput` when a path, digest, identity, generation, or
    /// extra argv value is not canonical.
    pub fn new<I, S>(
        config_descriptor_path: impl Into<PathBuf>,
        config_descriptor_digest: impl Into<String>,
        installation_id: impl Into<String>,
        transaction_plan_generation: u64,
        extra_args: I,
    ) -> Result<Self, WindowsAdapterError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let config_descriptor_path = config_descriptor_path.into();
        let config_descriptor_digest = config_descriptor_digest.into();
        let installation_id = installation_id.into();
        let extra_args = extra_args.into_iter().map(Into::into).collect::<Vec<_>>();
        if !config_descriptor_path.is_absolute()
            || !valid_os_path(config_descriptor_path.as_path())
            || !valid_sha256_hex(&config_descriptor_digest)
            || !valid_bootstrap_identity(&installation_id)
            || transaction_plan_generation == 0
            || extra_args.iter().any(|arg| !valid_bootstrap_text(arg))
            || extra_args.iter().any(|arg| is_reserved_bootstrap_arg(arg))
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self {
            config_descriptor_path,
            config_descriptor_digest,
            installation_id,
            transaction_plan_generation,
            host_state_root: None,
            registration_nonce: None,
            extra_args,
        })
    }

    /// Binds a Host service bootstrap to one explicit installer-provisioned
    /// runtime root. Other service roles may leave this selector absent.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the root is not an absolute valid OS path.
    pub fn with_host_state_root(
        mut self,
        host_state_root: impl Into<PathBuf>,
    ) -> Result<Self, WindowsAdapterError> {
        let host_state_root = host_state_root.into();
        if !host_state_root.is_absolute()
            || host_state_root.as_os_str().is_empty()
            || !valid_os_path(&host_state_root)
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        self.host_state_root = Some(host_state_root);
        Ok(self)
    }

    /// Binds this bootstrap to one durable installer registration intent.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the nonce is not canonical SHA-256 text.
    pub fn with_registration_nonce(
        mut self,
        registration_nonce: impl Into<String>,
    ) -> Result<Self, WindowsAdapterError> {
        let registration_nonce = registration_nonce.into();
        if !valid_sha256_hex(&registration_nonce) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        self.registration_nonce = Some(registration_nonce);
        Ok(self)
    }

    #[must_use]
    pub fn config_descriptor_path(&self) -> &Path {
        &self.config_descriptor_path
    }

    #[must_use]
    pub fn config_descriptor_digest(&self) -> &str {
        &self.config_descriptor_digest
    }

    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    #[must_use]
    pub const fn transaction_plan_generation(&self) -> u64 {
        self.transaction_plan_generation
    }

    /// Returns the exact per-installation Host runtime-root selector, when
    /// this bootstrap is for the Host service.
    #[must_use]
    pub fn host_state_root(&self) -> Option<&Path> {
        self.host_state_root.as_deref()
    }

    #[must_use]
    pub const fn tx_plan_generation(&self) -> u64 {
        self.transaction_plan_generation
    }

    #[must_use]
    pub fn registration_nonce(&self) -> Option<&str> {
        self.registration_nonce.as_deref()
    }

    #[must_use]
    pub fn extra_args(&self) -> &[String] {
        &self.extra_args
    }

    /// Returns typed fields rendered as ordered argv values.
    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        let config_descriptor_path = exact_path_text(&self.config_descriptor_path);
        let mut argv = vec![
            "--config-descriptor".to_owned(),
            config_descriptor_path,
            "--config-descriptor-sha256".to_owned(),
            self.config_descriptor_digest.clone(),
            "--installation-id".to_owned(),
            self.installation_id.clone(),
            "--tx-plan-generation".to_owned(),
            self.transaction_plan_generation.to_string(),
        ];
        if let Some(root) = &self.host_state_root {
            argv.extend([
                "--host-state-root".to_owned(),
                exact_path_text(root.as_path()),
            ]);
        }
        if let Some(nonce) = &self.registration_nonce {
            argv.extend(["--registration-nonce".to_owned(), nonce.clone()]);
        }
        argv.extend(self.extra_args.iter().cloned());
        argv
    }

    #[cfg(windows)]
    fn argv_os(&self) -> Vec<std::ffi::OsString> {
        let mut argv = vec![
            std::ffi::OsString::from("--config-descriptor"),
            self.config_descriptor_path.as_os_str().to_os_string(),
            std::ffi::OsString::from("--config-descriptor-sha256"),
            std::ffi::OsString::from(&self.config_descriptor_digest),
            std::ffi::OsString::from("--installation-id"),
            std::ffi::OsString::from(&self.installation_id),
            std::ffi::OsString::from("--tx-plan-generation"),
            std::ffi::OsString::from(self.transaction_plan_generation.to_string()),
        ];
        if let Some(root) = &self.host_state_root {
            argv.extend([
                std::ffi::OsString::from("--host-state-root"),
                root.as_os_str().to_os_string(),
            ]);
        }
        if let Some(nonce) = &self.registration_nonce {
            argv.extend([
                std::ffi::OsString::from("--registration-nonce"),
                std::ffi::OsString::from(nonce),
            ]);
        }
        argv.extend(
            self.extra_args
                .iter()
                .cloned()
                .map(std::ffi::OsString::from),
        );
        argv
    }
}

/// Exact current configuration identity required before installer mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRegistrationCurrent {
    service_name: String,
    configuration_digest: String,
}

impl ServiceRegistrationCurrent {
    /// Creates an expected current SCM identity and configuration digest.
    ///
    /// # Errors
    /// Returns `InvalidInput` for a non-canonical service name or digest.
    pub fn new(
        service_name: impl Into<String>,
        configuration_digest: impl Into<String>,
    ) -> Result<Self, WindowsAdapterError> {
        let service_name = service_name.into();
        let configuration_digest = configuration_digest.into();
        if !canonical_runtime_service_name(&service_name)
            || !valid_sha256_hex(&configuration_digest)
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        Ok(Self {
            service_name,
            configuration_digest,
        })
    }

    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[must_use]
    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }
}

fn valid_bootstrap_text(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\0')
}

fn valid_bootstrap_identity(value: &str) -> bool {
    valid_bootstrap_text(value) && !value.contains('"')
}

fn is_reserved_bootstrap_arg(value: &str) -> bool {
    matches!(
        value,
        "--config-descriptor"
            | "--config-descriptor-sha256"
            | "--installation-id"
            | "--tx-plan-generation"
            | "--host-state-root"
            | "--registration-nonce"
    )
}

fn utf16_text(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn exact_utf16_text(value: &[u16]) -> String {
    String::from_utf16(value).unwrap_or_default()
}

fn exact_path_text(path: &Path) -> String {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        exact_utf16_text(&path.as_os_str().encode_wide().collect::<Vec<_>>())
    }
    #[cfg(not(windows))]
    {
        path.to_str().unwrap_or_default().to_owned()
    }
}

fn valid_os_path(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
        String::from_utf16(&units).is_ok()
            && units
                .iter()
                .all(|unit| *unit != 0 && !matches!(unit, 9..=13))
    }
    #[cfg(not(windows))]
    {
        path.to_str().is_some_and(|value| {
            !value
                .chars()
                .any(|character| character == '\0' || character.is_control())
        })
    }
}

/// Validated, password-free request for registering one own-process service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRegistrationRequest {
    service_name: String,
    display_name: String,
    binary_path: PathBuf,
    start_mode: ServiceStartMode,
    account: ServiceAccount,
    service_sid_type: ServiceSidType,
    bootstrap: Option<ServiceBootstrapArguments>,
    expected_current: Option<ServiceRegistrationCurrent>,
    expected_runtime_identity_digest: Option<String>,
}

impl ServiceRegistrationRequest {
    /// Creates an inert SCM registration request.
    ///
    /// # Errors
    /// Returns `InvalidInput` for invalid names or a non-absolute/non-file image.
    pub fn new(
        service_name: impl Into<String>,
        display_name: impl Into<String>,
        binary_path: impl Into<PathBuf>,
        start_mode: ServiceStartMode,
        account: ServiceAccount,
    ) -> Result<Self, WindowsAdapterError> {
        let service_name = service_name.into();
        let display_name = display_name.into();
        let binary_path = binary_path.into();
        if !valid_service_name(&service_name)
            || !valid_display_name(&display_name)
            || !binary_path.is_absolute()
            || !binary_path.is_file()
            || !valid_os_path(binary_path.as_path())
            || !canonical_runtime_service_name(&service_name)
            || canonical_runtime_service_display_name(&service_name)
                .is_some_and(|expected| display_name != expected)
            || start_mode != ServiceStartMode::Automatic
            || account != ServiceAccount::LocalService
            || exact_path_text(binary_path.as_path()).contains('"')
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        let service_sid_type = if service_name == ELIOT_HOST_SERVICE_NAME {
            ServiceSidType::Unrestricted
        } else {
            ServiceSidType::None
        };
        Ok(Self {
            service_name,
            display_name,
            binary_path,
            start_mode,
            account,
            service_sid_type,
            bootstrap: None,
            expected_current: None,
            expected_runtime_identity_digest: None,
        })
    }

    /// Creates a request with the immutable, argv-only bootstrap authority.
    ///
    /// # Errors
    /// Returns `InvalidInput` when the service shape or bootstrap binding is
    /// not canonical.
    pub fn with_bootstrap(
        service_name: impl Into<String>,
        display_name: impl Into<String>,
        binary_path: impl Into<PathBuf>,
        start_mode: ServiceStartMode,
        account: ServiceAccount,
        bootstrap: ServiceBootstrapArguments,
    ) -> Result<Self, WindowsAdapterError> {
        let mut request = Self::new(service_name, display_name, binary_path, start_mode, account)?;
        request.bootstrap = Some(bootstrap);
        Ok(request)
    }

    /// Binds the exact current service configuration allowed for installer
    /// update or delete.
    /// # Errors
    /// Returns `InvalidInput` when the expected service identity does not
    /// match this request's canonical service name.
    pub fn with_expected_current(
        mut self,
        expected_current: ServiceRegistrationCurrent,
    ) -> Result<Self, WindowsAdapterError> {
        if expected_current.service_name() != self.service_name {
            return Err(WindowsAdapterError::InvalidInput);
        }
        self.expected_current = Some(expected_current);
        Ok(self)
    }

    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    #[must_use]
    pub const fn start_mode(&self) -> ServiceStartMode {
        self.start_mode
    }

    #[must_use]
    pub const fn account(&self) -> ServiceAccount {
        self.account
    }

    /// Returns the exact SCM service-SID mode required by this registration.
    #[must_use]
    pub const fn service_sid_type(&self) -> ServiceSidType {
        self.service_sid_type
    }

    /// Returns whether this registration requires the installer-owned
    /// `EliotHost` service-control grant and exact DACL readback.
    #[must_use]
    pub fn requires_host_service_control_grant(&self) -> bool {
        self.service_name == ELIOT_WATCHDOG_SERVICE_NAME
    }

    #[must_use]
    pub fn bootstrap(&self) -> Option<&ServiceBootstrapArguments> {
        self.bootstrap.as_ref()
    }

    #[must_use]
    pub fn expected_current(&self) -> Option<&ServiceRegistrationCurrent> {
        self.expected_current.as_ref()
    }

    /// Binds a rollback request to the exact process identity observed by the
    /// caller. The digest is evidence, not a caller-supplied PID; the typed
    /// stop primitive validates it again against a fresh SCM/process readback
    /// immediately before issuing its one stop call.
    ///
    /// # Errors
    /// Returns `InvalidInput` for a digest that is not canonical lowercase
    /// SHA-256 text.
    pub fn with_expected_runtime_identity_digest(
        mut self,
        digest: impl Into<String>,
    ) -> Result<Self, WindowsAdapterError> {
        let digest = digest.into();
        if !valid_sha256_hex(&digest) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        self.expected_runtime_identity_digest = Some(digest);
        Ok(self)
    }

    /// Returns the process identity digest bound to a rollback request, when
    /// one was supplied by the caller.
    #[must_use]
    pub fn expected_runtime_identity_digest(&self) -> Option<&str> {
        self.expected_runtime_identity_digest.as_deref()
    }

    #[must_use]
    pub fn expected_configuration_digest(&self) -> String {
        service_configuration_digest(
            &self.binary_command_wide(),
            &utf16_text(self.display_name()),
            &utf16_text("NT AUTHORITY\\LocalService"),
            0x0000_0010,
            0x0000_0002,
            0x0000_0001,
            0,
            &[],
            &[],
            self.service_sid_type.raw(),
        )
    }

    #[cfg(windows)]
    fn binary_command_wide(&self) -> Vec<u16> {
        let mut command = quote_service_os_argument(self.binary_path.as_os_str(), true);
        if let Some(bootstrap) = &self.bootstrap {
            for argument in bootstrap.argv_os() {
                command.push(' ' as u16);
                command.extend(quote_service_os_argument(&argument, false));
            }
        }
        command
    }

    #[cfg(not(windows))]
    fn binary_command_wide(&self) -> Vec<u16> {
        let mut command = quote_service_argument(&exact_path_text(&self.binary_path), true);
        if let Some(bootstrap) = &self.bootstrap {
            for argument in bootstrap.argv() {
                command.push(' ');
                command.push_str(&quote_service_argument(&argument, false));
            }
        }
        command.encode_utf16().collect()
    }

    #[must_use]
    pub fn binary_command(&self) -> String {
        exact_utf16_text(&self.binary_command_wide())
    }
}

/// Registration result preserving whether an external SCM effect requires
/// reconciliation before it can be called successful.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceRegistrationOutcome {
    /// The SCM object was absent and this call created it successfully.
    CreatedNow {
        observation: ServiceObservation,
        control_grant: Option<ServiceControlGrantReadback>,
    },
    /// The exact object was already present before this call.
    PreexistingMatching {
        observation: ServiceObservation,
        control_grant: Option<ServiceControlGrantReadback>,
    },
    Registered {
        observation: ServiceObservation,
        control_grant: Option<ServiceControlGrantReadback>,
    },
    Updated {
        observation: ServiceObservation,
        control_grant: Option<ServiceControlGrantReadback>,
    },
    Unchanged {
        observation: ServiceObservation,
        control_grant: Option<ServiceControlGrantReadback>,
    },
    Deleted,
    AlreadyAbsent,
    ExistingRequiresReconciliation,
    EffectUnknown,
}

/// Read-only classification of one canonical Runtime Live SCM registration.
///
/// `Matching` means the SCM name, binary command, own-process service type,
/// automatic start mode, and `LocalService` account all match the validated
/// request.  Every other variant is fail-closed for Host startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceRegistrationInspection {
    /// Exact configuration and current service state were observed.
    Matching {
        observation: ServiceObservation,
        control_grant: Option<ServiceControlGrantReadback>,
    },
    /// The canonical service name is not registered.
    Absent,
    /// A service exists at the canonical name with different configuration.
    Mismatched,
    /// SCM could not provide authoritative configuration and state readback.
    Unknown,
}

/// Exact read-only SCM runtime observation for one validated registration.
///
/// This is deliberately separate from [`eliot_platform::ServiceObservation`]:
/// Windows can authoritatively observe a service PID, process creation time,
/// and image path, but it cannot invent ELIOT's semantic authority epoch.
/// The configuration digest binds the observation to the complete canonical
/// service command, account, type, and start-mode request used for readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRuntimeObservation {
    service_name: String,
    configuration_digest: String,
    state: ServiceState,
    checkpoint: u32,
    wait_hint_ms: u32,
    process: Option<ProcessIdentity>,
}

impl ServiceRuntimeObservation {
    /// Returns the exact canonical SCM service name.
    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Returns the digest of the complete configuration admitted during this
    /// same readback.
    #[must_use]
    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }

    /// Returns the current SCM lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ServiceState {
        self.state
    }

    /// Returns whether SCM reports the service as fully stopped.
    #[must_use]
    pub const fn is_stopped(&self) -> bool {
        matches!(self.state, ServiceState::Stopped)
    }

    /// Returns whether SCM reports an in-progress start transition.
    #[must_use]
    pub const fn is_starting(&self) -> bool {
        matches!(self.state, ServiceState::Starting)
    }

    /// Returns whether SCM reports the service as running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self.state, ServiceState::Running)
    }

    /// Returns whether SCM reports an in-progress stop transition.
    #[must_use]
    pub const fn is_stopping(&self) -> bool {
        matches!(self.state, ServiceState::Stopping)
    }

    /// Returns the SCM progress checkpoint for a pending transition.
    #[must_use]
    pub const fn checkpoint(&self) -> u32 {
        self.checkpoint
    }

    /// Returns the SCM provider's bounded-wait hint in milliseconds.
    #[must_use]
    pub const fn wait_hint_ms(&self) -> u32 {
        self.wait_hint_ms
    }

    /// Returns the handle-observed PID, creation time, and image identity when
    /// the current state has a live service process.
    #[must_use]
    pub const fn process(&self) -> Option<&ProcessIdentity> {
        self.process.as_ref()
    }

    /// Computes the stable digest that a rollback request must bind before it
    /// can issue a stop call. The digest covers the exact admitted service
    /// configuration and the handle-observed PID, creation time, and image.
    #[must_use]
    pub fn runtime_identity_digest(&self) -> Option<String> {
        self.process.as_ref().map(|process| {
            runtime_identity_digest_from_configuration(&self.configuration_digest, process)
        })
    }
}

/// Read-only classification of exact SCM configuration plus runtime state.
///
/// `Matching` is returned only when the canonical registration matches and
/// every process identity required by the observed state is available from a
/// live process handle. Unknown provider state or an inaccessible live
/// process remains fail-closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceRegistrationRuntimeInspection {
    /// Exact configuration and runtime state were observed together.
    Matching {
        observation: ServiceRuntimeObservation,
    },
    /// The canonical service name is not registered.
    Absent,
    /// The registration or live image differs from the validated request.
    Mismatched,
    /// SCM or the live process could not be observed authoritatively.
    Unknown,
}

/// Result of one exact-registration-bound SCM start attempt.
///
/// The operation is deliberately separate from the provider-neutral
/// `ServicePort::Start` request. It performs one fresh registration/runtime
/// admission and issues at most one `StartServiceW` call. `Started` means that
/// the call was issued and the post-call readback remained authoritative; it
/// does not claim that SCM has already reached `Running`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceStartOutcome {
    /// One `StartServiceW` call was issued and the post-call readback matches.
    Started {
        observation: ServiceRuntimeObservation,
    },
    /// The exact service was already running; no start call was issued.
    AlreadyRunning {
        observation: ServiceRuntimeObservation,
    },
    /// SCM reported an in-progress start; no start call was issued.
    AlreadyStarting {
        observation: ServiceRuntimeObservation,
    },
    /// A provider/readback race or failure prevented an authoritative result.
    EffectUnknown,
}

/// Result of one exact-registration-bound SCM stop attempt used for rollback
/// of a start effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceStopOutcome {
    /// One stop call was issued and the post-call readback matches.
    Stopped {
        observation: ServiceRuntimeObservation,
    },
    /// The exact service was already stopped; no stop call was issued.
    AlreadyStopped {
        observation: ServiceRuntimeObservation,
    },
    /// SCM reported an in-progress stop; no stop call was issued.
    AlreadyStopping {
        observation: ServiceRuntimeObservation,
    },
    /// A provider/readback race or failure prevented an authoritative result.
    EffectUnknown,
}

#[cfg(windows)]
static JOB_OBJECT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[cfg(windows)]
struct OwnedKernelHandle(windows_sys::Win32::Foundation::HANDLE);

// SAFETY: Windows kernel handles are process-global. This wrapper uniquely
// owns and closes its handle, so moving it between threads is sound.
#[cfg(windows)]
unsafe impl Send for OwnedKernelHandle {}

#[cfg(windows)]
impl OwnedKernelHandle {
    fn new(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<Self, WindowsAdapterError> {
        if handle.is_null() {
            Err(last_windows_adapter_error())
        } else {
            Ok(Self(handle))
        }
    }

    fn into_file(self) -> std::fs::File {
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
        Self::from_sddl("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
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
        // `FA` is the concrete file-all mask. Windows expands generic `GA`
        // before storing the DACL, so using `GA` would defeat byte proof.
        let inheritance = if directory { "OICI" } else { "" };
        Self::from_sddl(&format!(
            "D:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;{sid})"
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

/// Verifies the exact owner, protected DACL and descriptor bytes on a live
/// handle.  This narrow helper is shared by protected installer primitives so
/// they cannot accidentally downgrade to a path-only ACL check.
#[cfg(windows)]
pub(crate) fn verify_exact_file_security(
    file: &std::fs::File,
    expected: &OwnedSecurityDescriptor,
    expected_owner: &str,
) -> Result<(), WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    };

    let expected_dacl = expected.dacl()?;
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        // SAFETY: `file` owns a live handle and all output pointers are valid
        // locals; Windows owns `descriptor` until LocalFree below.
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() || owner.is_null() {
        if !descriptor.is_null() {
            // SAFETY: descriptor was allocated by GetSecurityInfo.
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(
            if status == windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED {
                WindowsAdapterError::PermissionDenied
            } else {
                WindowsAdapterError::AclMismatch
            },
        );
    }

    let mut present = 0;
    let mut actual_dacl = std::ptr::null_mut();
    let mut defaulted = 0;
    let dacl_matches = unsafe {
        // SAFETY: both descriptors remain live for these bounded ACL reads.
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
        // SAFETY: descriptor remains live and output locals are valid.
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) != 0
            && control & SE_DACL_PROTECTED != 0
    };
    let owner_matches = sid_to_string(owner).is_ok_and(|observed| observed == expected_owner);
    // SAFETY: descriptor is released exactly once after all reads complete.
    unsafe { LocalFree(descriptor.cast()) };
    if dacl_matches && protected && owner_matches {
        Ok(())
    } else {
        Err(WindowsAdapterError::AclMismatch)
    }
}

/// RAII wrapper for a named Windows Job Object configured to terminate
/// assigned processes when the sole owning handle closes.
#[cfg(windows)]
pub struct JobObject {
    handle: windows_sys::Win32::Foundation::HANDLE,
    identity: JobObjectIdentity,
}

// SAFETY: a Job Object handle is process-global and uniquely owned here.
#[cfg(windows)]
unsafe impl Send for JobObject {}

#[cfg(windows)]
impl JobObject {
    /// Creates a Job Object with kill-on-close configured before publication.
    ///
    /// # Errors
    /// Returns a typed adapter error when creation or configuration fails.
    pub fn new_kill_on_close() -> Result<Self, WindowsAdapterError> {
        let sequence = JOB_OBJECT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let identity = JobObjectIdentity::new(format!(
            "Local\\Eliot-P02-{}-{sequence}",
            std::process::id()
        ))?;
        Self::new_named_kill_on_close(identity)
    }

    /// Creates a fresh named Job Object and rejects an existing name.
    ///
    /// The protected DACL grants full access only to `LocalSystem` and the
    /// creating owner. A new generation therefore cannot silently join an
    /// older Job with the same durable identity.
    ///
    /// # Errors
    /// Returns `AlreadyExists` for a name collision or another typed adapter
    /// error when Windows rejects creation or limit configuration.
    pub fn new_named_kill_on_close(
        identity: JobObjectIdentity,
    ) -> Result<Self, WindowsAdapterError> {
        Self::new_named_kill_on_close_with_limits(identity, JobObjectLimits::default())
    }

    /// Creates a fresh named kill-on-close Job with exact resource ceilings.
    ///
    /// All limits are installed before any process can be assigned.
    ///
    /// # Errors
    /// Returns a typed adapter error for name collision, invalid conversion,
    /// or rejected Job configuration.
    pub fn new_named_kill_on_close_with_limits(
        identity: JobObjectIdentity,
        resource_limits: JobObjectLimits,
    ) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
            JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        let name = nul_terminated_wide(std::ffi::OsStr::new(identity.name()))
            .map_err(|error| windows_adapter_from_io(&error))?;
        let descriptor = OwnedSecurityDescriptor::for_job_owner()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| WindowsAdapterError::Failed)?,
            lpSecurityDescriptor: descriptor.raw,
            bInheritHandle: 0,
        };
        // SAFETY: name, descriptor and attributes remain live for the call.
        let handle = unsafe { CreateJobObjectW(&raw const attributes, name.as_ptr()) };
        // SAFETY: GetLastError immediately observes the creation disposition.
        let creation_error = unsafe { GetLastError() };
        if handle.is_null() {
            return Err(last_windows_adapter_error());
        }
        if creation_error == ERROR_ALREADY_EXISTS {
            // SAFETY: this path owns the handle returned for the old object.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
            return Err(WindowsAdapterError::AlreadyExists);
        }
        let mut job_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if let Some(cpu_time_ms) = resource_limits.cpu_time_ms {
            let ticks = cpu_time_ms
                .checked_mul(10_000)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or(WindowsAdapterError::InvalidInput)?;
            job_info.BasicLimitInformation.PerJobUserTimeLimit = ticks;
            job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
        }
        if let Some(memory_bytes) = resource_limits.memory_bytes {
            job_info.JobMemoryLimit =
                usize::try_from(memory_bytes).map_err(|_| WindowsAdapterError::InvalidInput)?;
            job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        }
        if let Some(active_process_limit) = resource_limits.active_process_limit {
            job_info.BasicLimitInformation.ActiveProcessLimit = active_process_limit;
            job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        }
        let length = u32::try_from(std::mem::size_of_val(&job_info))
            .map_err(|_| WindowsAdapterError::Failed)?;
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw const job_info).cast(),
                length,
            )
        } != 0;
        if !configured {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
            return Err(last_windows_adapter_error());
        }
        Ok(Self { handle, identity })
    }

    /// Returns the durable Job Object identity.
    #[must_use]
    pub const fn identity(&self) -> &JobObjectIdentity {
        &self.identity
    }

    /// Assigns an existing process and returns its exact observed identity.
    ///
    /// # Errors
    /// Returns a typed adapter error for invalid identity, access or assignment failure.
    pub fn assign_process(&self, process_id: u32) -> Result<ProcessIdentity, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        };
        if process_id == 0 {
            return Err(WindowsAdapterError::InvalidInput);
        }
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE,
                0,
                process_id,
            )
        };
        if process.is_null() {
            return Err(last_windows_adapter_error());
        }
        let assigned = self.assign_process_handle(process);
        let result = if assigned.is_ok() {
            inspect_process_handle(process_id, process)
                .map_err(|error| windows_adapter_from_io(&error))
        } else {
            Err(assigned.err().unwrap_or(WindowsAdapterError::Failed))
        };
        unsafe { CloseHandle(process) };
        result
    }

    fn assign_process_handle(
        &self,
        process: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), WindowsAdapterError> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        if unsafe { AssignProcessToJobObject(self.handle, process) } == 0 {
            Err(last_windows_adapter_error())
        } else {
            Ok(())
        }
    }

    fn contains_process(&self, process_id: u32) -> Result<bool, WindowsAdapterError> {
        job_process_ids(self.handle)
            .map(|processes| processes.into_iter().any(|pid| pid == process_id))
            .map_err(|error| windows_adapter_from_io(&error))
    }

    /// Terminates every process currently assigned to this job.
    ///
    /// # Errors
    /// Returns a typed adapter error when Windows rejects termination.
    pub fn terminate(&self, exit_code: u32) -> Result<(), WindowsAdapterError> {
        let ok = unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.handle, exit_code)
        };
        if ok == 0 {
            Err(last_windows_adapter_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
impl Drop for JobObject {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}

/// Handle to an existing named Job Object during restart reconciliation.
///
/// Reopening proves only current kernel membership. Historical descendants
/// must be unioned with the caller-owned durable raw-observation ledger; this
/// type intentionally exposes no `complete` history claim.
#[cfg(windows)]
pub struct RecoverableJobObject {
    handle: OwnedKernelHandle,
    binding: RecoverableJobBinding,
}

#[cfg(windows)]
impl RecoverableJobObject {
    /// Opens one existing named Job with query and terminate access.
    ///
    /// # Errors
    /// Returns `NotFound` when kill-on-close already removed the Job, or a
    /// typed access/platform error otherwise.
    pub fn open(binding: RecoverableJobBinding) -> Result<Self, WindowsAdapterError> {
        const JOB_OBJECT_QUERY_ACCESS: u32 = 0x0004;
        const JOB_OBJECT_TERMINATE_ACCESS: u32 = 0x0008;
        const JOB_OBJECT_ASSIGN_PROCESS_ACCESS: u32 = 0x0001;
        use windows_sys::Win32::System::JobObjects::OpenJobObjectW;
        binding.validate()?;
        let name = nul_terminated_wide(std::ffi::OsStr::new(binding.job_identity().name()))
            .map_err(|error| windows_adapter_from_io(&error))?;
        // SAFETY: name is NUL-terminated and the call returns a new handle.
        let handle = unsafe {
            OpenJobObjectW(
                JOB_OBJECT_QUERY_ACCESS
                    | JOB_OBJECT_TERMINATE_ACCESS
                    | JOB_OBJECT_ASSIGN_PROCESS_ACCESS,
                0,
                name.as_ptr(),
            )
        };
        if handle.is_null() {
            let error = std::io::Error::last_os_error();
            if matches!(error.kind(), std::io::ErrorKind::NotFound) {
                return Err(WindowsAdapterError::NotFound);
            }
            return Err(windows_adapter_from_io(&error));
        }
        let recovered = Self {
            handle: OwnedKernelHandle::new(handle)?,
            binding,
        };
        let live = recovered.live_processes()?;
        if !live
            .iter()
            .any(|process| process == recovered.binding.root())
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(recovered)
    }

    /// Returns the exact Job identity used to reopen the object.
    #[must_use]
    pub const fn identity(&self) -> &JobObjectIdentity {
        self.binding.job_identity()
    }

    /// Returns the durable binding revalidated when this handle was opened.
    #[must_use]
    pub const fn binding(&self) -> &RecoverableJobBinding {
        &self.binding
    }

    /// Returns current live members with PID-reuse-safe process/image identity.
    ///
    /// # Errors
    /// Returns a typed adapter error when membership or identity cannot be read.
    pub fn live_processes(&self) -> Result<Vec<ProcessObservation>, WindowsAdapterError> {
        job_process_ids(self.handle.0)
            .map_err(|error| windows_adapter_from_io(&error))?
            .into_iter()
            .map(open_observed_job_process)
            .map(|result| result.map(|process| process.observation))
            .collect()
    }

    /// Returns the current active member count.
    ///
    /// # Errors
    /// Returns a typed adapter error when the Job cannot be queried.
    pub fn active_process_count(&self) -> Result<u32, WindowsAdapterError> {
        u32::try_from(
            job_process_ids(self.handle.0)
                .map_err(|error| windows_adapter_from_io(&error))?
                .len(),
        )
        .map_err(|_| WindowsAdapterError::Failed)
    }

    #[cfg(windows)]
    fn assign_process_handle(
        &self,
        process: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<(), WindowsAdapterError> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        if unsafe { AssignProcessToJobObject(self.handle.0, process) } == 0 {
            Err(last_windows_adapter_error())
        } else {
            Ok(())
        }
    }

    #[cfg(windows)]
    fn contains_process(&self, process_id: u32) -> Result<bool, WindowsAdapterError> {
        job_process_ids(self.handle.0)
            .map(|processes| processes.into_iter().any(|pid| pid == process_id))
            .map_err(|error| windows_adapter_from_io(&error))
    }

    /// Terminates all current members.
    ///
    /// # Errors
    /// Returns a typed adapter error when Windows rejects termination.
    pub fn terminate(&self, exit_code: u32) -> Result<(), WindowsAdapterError> {
        // SAFETY: the reopened Job handle remains live for the call.
        if unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.handle.0, exit_code)
        } == 0
        {
            Err(last_windows_adapter_error())
        } else {
            Ok(())
        }
    }

    /// Waits until no live member remains.
    ///
    /// # Errors
    /// Returns a typed adapter error when current membership cannot be read.
    pub fn wait_for_empty(
        &self,
        timeout: std::time::Duration,
    ) -> Result<bool, WindowsAdapterError> {
        let started = std::time::Instant::now();
        loop {
            if self.active_process_count()? == 0 {
                return Ok(true);
            }
            if started.elapsed() >= timeout {
                return Ok(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Launches one validated child into this already-open Job Object.
    ///
    /// The returned typestate borrows this recovery handle for its whole
    /// lifetime. It therefore cannot outlive the shared Job owner and never
    /// owns, closes, or terminates that Job. Only the new process is owned by
    /// the member typestate.
    ///
    /// # Errors
    /// Returns a typed adapter error when the retained root is no longer a
    /// member, launch material is invalid, assignment fails, or exact member
    /// identity cannot be observed before publication.
    pub fn spawn_member(
        &self,
        spec: SuspendedLaunchSpec,
    ) -> Result<SuspendedExistingJobChild<'_>, WindowsAdapterError> {
        if !self
            .live_processes()?
            .iter()
            .any(|process| process == self.binding.root())
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        spawn_existing_job_member(self, spec)
    }
}

#[cfg(windows)]
struct OwnedProcessHandle(windows_sys::Win32::Foundation::HANDLE);

// SAFETY: Windows kernel handles are process-global. This wrapper retains
// unique ownership and closes the handle exactly once in Drop.
#[cfg(windows)]
unsafe impl Send for OwnedProcessHandle {}

#[cfg(windows)]
impl OwnedProcessHandle {
    fn new(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<Self, WindowsAdapterError> {
        if handle.is_null() {
            Err(last_windows_adapter_error())
        } else {
            Ok(Self(handle))
        }
    }
}

#[cfg(windows)]
impl Drop for OwnedProcessHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
struct SuspendedProcessCleanup {
    process: windows_sys::Win32::Foundation::HANDLE,
    armed: bool,
}

#[cfg(windows)]
impl SuspendedProcessCleanup {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(windows)]
impl Drop for SuspendedProcessCleanup {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
        if self.armed && !self.process.is_null() {
            let _ = unsafe { TerminateProcess(self.process, 0xE1_04) };
            let _ = unsafe { WaitForSingleObject(self.process, 5_000) };
        }
    }
}

#[cfg(windows)]
struct PinnedExecutable {
    _file: std::fs::File,
    identity: FileIdentity,
}

#[cfg(windows)]
impl PinnedExecutable {
    fn open(path: &Path) -> Result<Self, WindowsAdapterError> {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_READ, GetFileInformationByHandle,
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| windows_adapter_from_io(&error))?;
        let metadata = file
            .metadata()
            .map_err(|error| windows_adapter_from_io(&error))?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(WindowsAdapterError::InvalidInput);
        }
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut information) }
            == 0
        {
            return Err(last_windows_adapter_error());
        }
        Ok(Self {
            _file: file,
            identity: FileIdentity {
                volume_serial_number: information.dwVolumeSerialNumber,
                file_index: (u64::from(information.nFileIndexHigh) << 32)
                    | u64::from(information.nFileIndexLow),
            },
        })
    }
}

/// Read-pinned protected runtime input retained while a Host contour is
/// running. The no-follow handle prevents replacement or reparse substitution
/// after digest verification.
#[cfg(windows)]
pub struct PinnedRuntimeFile {
    _file: PinnedExecutable,
}

#[cfg(windows)]
impl PinnedRuntimeFile {
    /// Opens one regular non-reparse runtime input with replacement-blocking
    /// sharing semantics.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is not a regular absolute file, crosses
    /// a reparse point, or cannot be opened with replacement-blocking sharing.
    pub fn open(path: &Path) -> Result<Self, WindowsAdapterError> {
        Ok(Self {
            _file: PinnedExecutable::open(path)?,
        })
    }
}

/// Complete deterministic input to the Windows suspended-launch primitive.
///
/// This value contains mechanics only. It is not a dispatch permit and carries
/// no authority. Environment inheritance is intentionally unavailable: callers
/// must supply the complete child environment explicitly.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuspendedLaunchSpec {
    executable: PathBuf,
    arguments: Vec<std::ffi::OsString>,
    working_directory: PathBuf,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
}

#[cfg(windows)]
impl SuspendedLaunchSpec {
    /// Creates a deterministic launch specification without granting authority.
    ///
    /// # Errors
    /// Returns `InvalidInput` unless the executable and working directory are
    /// absolute existing paths and all argument/environment material is valid
    /// Windows UTF-16 without duplicate case-insensitive environment names.
    pub fn new(
        executable: impl Into<PathBuf>,
        arguments: Vec<std::ffi::OsString>,
        working_directory: impl Into<PathBuf>,
        environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    ) -> Result<Self, WindowsAdapterError> {
        let executable = executable.into();
        let working_directory = working_directory.into();
        if !executable.is_absolute()
            || !executable.is_file()
            || !working_directory.is_absolute()
            || !working_directory.is_dir()
            || os_has_nul(executable.as_os_str())
            || os_has_nul(working_directory.as_os_str())
            || arguments.iter().any(|argument| os_has_nul(argument))
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        validate_complete_environment(&environment)?;
        Ok(Self {
            executable,
            arguments,
            working_directory,
            environment,
        })
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    #[must_use]
    pub fn arguments(&self) -> &[std::ffi::OsString] {
        &self.arguments
    }

    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    #[must_use]
    pub fn environment(&self) -> &[(std::ffi::OsString, std::ffi::OsString)] {
        &self.environment
    }
}

/// Fresh mechanics evidence observed while the process is still suspended.
///
/// This type is deliberately non-serializable and non-cloneable. It is never
/// an authority receipt; only the caller-provided validator can return the
/// opaque validation token required by the next typestate.
#[cfg(windows)]
pub struct SuspendedProcessEvidence {
    process: ProcessIdentity,
    executable: FileIdentity,
    job: JobObjectIdentity,
    requested_executable: PathBuf,
    arguments: Vec<std::ffi::OsString>,
    working_directory: PathBuf,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    command_line_utf16: Vec<u16>,
    job_process_count: u32,
}

#[cfg(windows)]
impl SuspendedProcessEvidence {
    #[must_use]
    pub fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    #[must_use]
    pub const fn executable_file_identity(&self) -> FileIdentity {
        self.executable
    }

    /// Returns the fresh, owner-scoped Job Object identity.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        &self.job
    }

    /// Builds the raw durable binding required for later named-Job recovery.
    #[must_use]
    pub fn recoverable_job_binding(&self) -> RecoverableJobBinding {
        RecoverableJobBinding {
            job: self.job.clone(),
            root: ProcessObservation {
                process: self.process.clone(),
                executable: self.executable,
            },
        }
    }

    #[must_use]
    pub fn requested_executable(&self) -> &Path {
        &self.requested_executable
    }

    #[must_use]
    pub fn arguments(&self) -> &[std::ffi::OsString] {
        &self.arguments
    }

    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    #[must_use]
    pub fn environment(&self) -> &[(std::ffi::OsString, std::ffi::OsString)] {
        &self.environment
    }

    #[must_use]
    pub fn command_line_utf16(&self) -> &[u16] {
        &self.command_line_utf16
    }

    #[must_use]
    pub const fn job_process_count(&self) -> u32 {
        self.job_process_count
    }
}

/// Failure of the consuming caller-owned validation transition.
#[cfg(windows)]
#[derive(Debug, Eq, PartialEq)]
pub enum SuspendedValidationError<E> {
    Mechanics(WindowsAdapterError),
    Rejected(E),
}

#[cfg(windows)]
const JOB_COMPLETION_KEY: usize = 0x454c_494f;
#[cfg(windows)]
const JOB_OBSERVER_SHUTDOWN_KEY: usize = 0x454e_4421;
#[cfg(windows)]
const JOB_OBJECT_MSG_END_OF_JOB_TIME: u32 = 1;
#[cfg(windows)]
const JOB_OBJECT_MSG_END_OF_PROCESS_TIME: u32 = 2;
#[cfg(windows)]
const JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT: u32 = 3;
#[cfg(windows)]
const JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO: u32 = 4;
#[cfg(windows)]
const JOB_OBJECT_MSG_NEW_PROCESS: u32 = 6;
#[cfg(windows)]
const JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT: u32 = 9;
#[cfg(windows)]
const JOB_OBJECT_MSG_JOB_MEMORY_LIMIT: u32 = 10;

#[cfg(windows)]
struct ObservedJobProcess {
    observation: ProcessObservation,
    _process: OwnedProcessHandle,
    _executable: PinnedExecutable,
}

#[cfg(windows)]
#[derive(Default)]
struct JobProcessObserverState {
    processes: Vec<ObservedJobProcess>,
    observation_incomplete: bool,
    active_process_zero: bool,
    resource_limit_triggered: bool,
}

#[cfg(windows)]
struct JobProcessObserver {
    completion_port: OwnedKernelHandle,
    state: std::sync::Arc<(
        std::sync::Mutex<JobProcessObserverState>,
        std::sync::Condvar,
    )>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
impl JobProcessObserver {
    fn attach(job: windows_sys::Win32::Foundation::HANDLE) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::IO::CreateIoCompletionPort;
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JobObjectAssociateCompletionPortInformation,
            SetInformationJobObject,
        };
        // SAFETY: this documented form creates one standalone completion port.
        let completion_port =
            unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, 1) };
        let completion_port = OwnedKernelHandle::new(completion_port)?;
        let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: JOB_COMPLETION_KEY as *mut std::ffi::c_void,
            CompletionPort: completion_port.0,
        };
        let length = u32::try_from(std::mem::size_of_val(&association))
            .map_err(|_| WindowsAdapterError::Failed)?;
        // SAFETY: both handles and the exact association structure are live.
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectAssociateCompletionPortInformation,
                (&raw const association).cast(),
                length,
            )
        } == 0
        {
            return Err(last_windows_adapter_error());
        }
        let state = std::sync::Arc::new((
            std::sync::Mutex::new(JobProcessObserverState::default()),
            std::sync::Condvar::new(),
        ));
        let thread_state = std::sync::Arc::clone(&state);
        let raw_port = completion_port.0 as usize;
        let thread = std::thread::Builder::new()
            .name("eliot-p02-job-observer".to_owned())
            .spawn(move || job_process_observer_loop(raw_port, &thread_state))
            .map_err(|error| windows_adapter_from_io(&error))?;
        Ok(Self {
            completion_port,
            state,
            thread: Some(thread),
        })
    }

    fn capture_pid(&self, process_id: u32) -> Result<(), WindowsAdapterError> {
        let process = open_observed_job_process(process_id)?;
        let (state, _) = &*self.state;
        let mut state = state.lock().map_err(|_| WindowsAdapterError::Failed)?;
        if !state
            .processes
            .iter()
            .any(|observed| observed.observation == process.observation)
        {
            state.processes.push(process);
        }
        Ok(())
    }

    fn capture_live_members(
        &self,
        job: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<bool, WindowsAdapterError> {
        let process_ids = job_process_ids(job).map_err(|error| windows_adapter_from_io(&error))?;
        for process_id in &process_ids {
            if self.capture_pid(*process_id).is_err() {
                let (state, _) = &*self.state;
                let mut state = state.lock().map_err(|_| WindowsAdapterError::Failed)?;
                state.observation_incomplete = true;
            }
        }
        Ok(process_ids.is_empty())
    }

    fn snapshot(
        &self,
        job: windows_sys::Win32::Foundation::HANDLE,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        let job_empty = self.capture_live_members(job)?;
        self.snapshot_with_empty(job_empty)
    }

    fn wait_for_empty_history(
        &self,
        job: windows_sys::Win32::Foundation::HANDLE,
        timeout: std::time::Duration,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        let started = std::time::Instant::now();
        loop {
            if self.capture_live_members(job)? {
                break;
            }
            if started.elapsed() >= timeout {
                return self.snapshot_with_empty(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let (state, notification) = &*self.state;
        let mut state = state.lock().map_err(|_| WindowsAdapterError::Failed)?;
        while !state.active_process_zero {
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                break;
            }
            let (next, wait) = notification
                .wait_timeout(state, remaining)
                .map_err(|_| WindowsAdapterError::Failed)?;
            state = next;
            if wait.timed_out() {
                break;
            }
        }
        Ok(history_from_observer_state(&state, true))
    }

    fn snapshot_with_empty(
        &self,
        job_empty: bool,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        let (state, _) = &*self.state;
        let state = state.lock().map_err(|_| WindowsAdapterError::Failed)?;
        Ok(history_from_observer_state(&state, job_empty))
    }

    fn shutdown(&mut self) {
        use windows_sys::Win32::System::IO::PostQueuedCompletionStatus;

        if self.thread.is_none() {
            return;
        }
        // SAFETY: the port stays live until the observer thread is joined.
        let _ = unsafe {
            PostQueuedCompletionStatus(
                self.completion_port.0,
                0,
                JOB_OBSERVER_SHUTDOWN_KEY,
                std::ptr::null(),
            )
        };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(windows)]
impl Drop for JobProcessObserver {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(windows)]
fn history_from_observer_state(
    state: &JobProcessObserverState,
    job_empty: bool,
) -> JobProcessHistory {
    let mut processes = state
        .processes
        .iter()
        .map(|observed| observed.observation.clone())
        .collect::<Vec<_>>();
    processes.sort_by_key(ProcessObservation::stable_key);
    processes.dedup();
    JobProcessHistory {
        processes,
        complete: job_empty && state.active_process_zero && !state.observation_incomplete,
        job_empty,
        capture_gap: state
            .observation_incomplete
            .then_some(JobObservationGap::IdentityCaptureFailed),
        resource_limit_triggered: state.resource_limit_triggered,
    }
}

#[cfg(windows)]
fn open_observed_job_process(process_id: u32) -> Result<ObservedJobProcess, WindowsAdapterError> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    if process_id == 0 {
        return Err(WindowsAdapterError::InvalidInput);
    }
    // SAFETY: OpenProcess returns a newly owned handle or null.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    let process = OwnedProcessHandle::new(handle)?;
    let identity = inspect_process_handle(process_id, process.0)
        .map_err(|error| windows_adapter_from_io(&error))?;
    let executable = PinnedExecutable::open(Path::new(&identity.image_path))?;
    let observation = ProcessObservation {
        process: identity,
        executable: executable.identity,
    };
    Ok(ObservedJobProcess {
        observation,
        _process: process,
        _executable: executable,
    })
}

#[cfg(windows)]
fn job_process_observer_loop(
    raw_port: usize,
    shared: &std::sync::Arc<(
        std::sync::Mutex<JobProcessObserverState>,
        std::sync::Condvar,
    )>,
) {
    use windows_sys::Win32::System::IO::GetQueuedCompletionStatus;
    let completion_port = raw_port as windows_sys::Win32::Foundation::HANDLE;
    loop {
        let mut message = 0_u32;
        let mut completion_key = 0_usize;
        let mut overlapped = std::ptr::null_mut();
        // SAFETY: all out pointers are live and the observer owns the port.
        let dequeued = unsafe {
            GetQueuedCompletionStatus(
                completion_port,
                &raw mut message,
                &raw mut completion_key,
                &raw mut overlapped,
                u32::MAX,
            )
        };
        if completion_key == JOB_OBSERVER_SHUTDOWN_KEY {
            break;
        }
        if dequeued == 0 || completion_key != JOB_COMPLETION_KEY {
            continue;
        }
        let (state, notification) = &**shared;
        if message == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO {
            if let Ok(mut state) = state.lock() {
                state.active_process_zero = true;
                notification.notify_all();
            }
            continue;
        }
        if matches!(
            message,
            JOB_OBJECT_MSG_END_OF_JOB_TIME
                | JOB_OBJECT_MSG_END_OF_PROCESS_TIME
                | JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT
                | JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT
                | JOB_OBJECT_MSG_JOB_MEMORY_LIMIT
        ) {
            if let Ok(mut state) = state.lock() {
                state.resource_limit_triggered = true;
                notification.notify_all();
            }
            continue;
        }
        if message != JOB_OBJECT_MSG_NEW_PROCESS {
            continue;
        }
        let Ok(process_id) = u32::try_from(overlapped as usize) else {
            if let Ok(mut state) = state.lock() {
                state.observation_incomplete = true;
            }
            continue;
        };
        let observed = open_observed_job_process(process_id);
        if let Ok(mut state) = state.lock() {
            state.active_process_zero = false;
            match observed {
                Ok(process)
                    if !state
                        .processes
                        .iter()
                        .any(|existing| existing.observation == process.observation) =>
                {
                    state.processes.push(process);
                }
                Ok(_) => {}
                Err(_) => state.observation_incomplete = true,
            }
        }
    }
}

#[cfg(windows)]
struct ProcThreadAttributeList {
    _storage: Vec<usize>,
    list: windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST,
}

#[cfg(windows)]
impl ProcThreadAttributeList {
    fn for_inherited_handles(
        handles: &[windows_sys::Win32::Foundation::HANDLE],
    ) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::{
            InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            UpdateProcThreadAttribute,
        };
        let mut bytes = 0_usize;
        // SAFETY: the documented sizing call writes only `bytes`.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &raw mut bytes);
        }
        if bytes == 0 {
            return Err(last_windows_adapter_error());
        }
        let words = bytes.div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let list = storage.as_mut_ptr().cast::<std::ffi::c_void>();
        // SAFETY: storage is aligned, sufficiently large, and retained.
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &raw mut bytes) } == 0 {
            return Err(last_windows_adapter_error());
        }
        let attribute = usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
            .map_err(|_| WindowsAdapterError::Failed)?;
        // SAFETY: list and exact handle slice are live for this call.
        if unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                attribute,
                handles.as_ptr().cast::<std::ffi::c_void>(),
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            let error = last_windows_adapter_error();
            // SAFETY: list was initialized above.
            unsafe {
                windows_sys::Win32::System::Threading::DeleteProcThreadAttributeList(list);
            }
            return Err(error);
        }
        Ok(Self {
            _storage: storage,
            list,
        })
    }
}

#[cfg(windows)]
impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        // SAFETY: list remains initialized and its storage is still live.
        unsafe {
            windows_sys::Win32::System::Threading::DeleteProcThreadAttributeList(self.list);
        }
    }
}

#[cfg(windows)]
fn inheritable_pipe() -> Result<(OwnedKernelHandle, OwnedKernelHandle), WindowsAdapterError> {
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| WindowsAdapterError::Failed)?,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: output pointers and security attributes are valid for the call.
    if unsafe { CreatePipe(&raw mut read, &raw mut write, &raw const attributes, 0) } == 0 {
        return Err(last_windows_adapter_error());
    }
    Ok((
        OwnedKernelHandle::new(read)?,
        OwnedKernelHandle::new(write)?,
    ))
}

#[cfg(windows)]
fn make_non_inheritable(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(), WindowsAdapterError> {
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    // SAFETY: the live handle is borrowed only for this call.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        Err(last_windows_adapter_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
struct JobChildHandles {
    process: OwnedProcessHandle,
    thread: OwnedProcessHandle,
    job: JobObject,
    spawn_identity: ProcessIdentity,
    executable: PinnedExecutable,
    spec: SuspendedLaunchSpec,
    command_line_utf16: Vec<u16>,
    stdout: Option<std::fs::File>,
    stderr: Option<std::fs::File>,
    observer: JobProcessObserver,
    terminal: bool,
}

#[cfg(windows)]
impl JobChildHandles {
    fn fresh_evidence(&self) -> Result<SuspendedProcessEvidence, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::GetProcessId;
        let process_id = unsafe { GetProcessId(self.process.0) };
        if process_id == 0 || process_id != self.spawn_identity.process_id {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let process = inspect_process_handle(process_id, self.process.0)
            .map_err(|error| windows_adapter_from_io(&error))?;
        if process.start_time_100ns != self.spawn_identity.start_time_100ns
            || !same_windows_path(&process.image_path, &self.spawn_identity.image_path)
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let observed_file = file_identity(Path::new(&process.image_path))
            .map_err(|error| windows_adapter_from_io(&error))?;
        if observed_file != self.executable.identity || !self.job.contains_process(process_id)? {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let count = u32::try_from(
            job_process_ids(self.job.handle)
                .map_err(|error| windows_adapter_from_io(&error))?
                .len(),
        )
        .map_err(|_| WindowsAdapterError::Failed)?;
        if count == 0 {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(SuspendedProcessEvidence {
            process,
            executable: observed_file,
            job: self.job.identity().clone(),
            requested_executable: self.spec.executable.clone(),
            arguments: self.spec.arguments.clone(),
            working_directory: self.spec.working_directory.clone(),
            environment: self.spec.environment.clone(),
            command_line_utf16: self.command_line_utf16.clone(),
            job_process_count: count,
        })
    }

    fn active_process_count(&self) -> Result<u32, WindowsAdapterError> {
        u32::try_from(
            job_process_ids(self.job.handle)
                .map_err(|error| windows_adapter_from_io(&error))?
                .len(),
        )
        .map_err(|_| WindowsAdapterError::Failed)
    }

    fn history(&self) -> Result<JobProcessHistory, WindowsAdapterError> {
        self.observer.snapshot(self.job.handle)
    }

    fn wait_for_empty_history(
        &self,
        timeout: std::time::Duration,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        self.observer
            .wait_for_empty_history(self.job.handle, timeout)
    }

    fn root_exit_code(&self) -> Result<Option<i32>, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0_u32;
                if unsafe { GetExitCodeProcess(self.process.0, &raw mut code) } == 0 {
                    return Err(last_windows_adapter_error());
                }
                Ok(Some(i32::from_ne_bytes(code.to_ne_bytes())))
            }
            _ => Err(last_windows_adapter_error()),
        }
    }

    fn terminate_and_reap(
        &mut self,
        requested_exit_code: u32,
    ) -> Result<(i32, JobProcessHistory), WindowsAdapterError> {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        self.job.terminate(requested_exit_code)?;
        wait_for_job_empty(self.job.handle, std::time::Duration::from_secs(5))?;
        if unsafe { WaitForSingleObject(self.process.0, 5_000) } != WAIT_OBJECT_0 {
            return Err(WindowsAdapterError::Timeout);
        }
        let exit_code = self.root_exit_code()?.ok_or(WindowsAdapterError::Failed)?;
        let history = self
            .observer
            .wait_for_empty_history(self.job.handle, std::time::Duration::from_secs(5))?;
        self.terminal = true;
        Ok((exit_code, history))
    }

    fn best_effort_cleanup(&mut self) {
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
        if self.terminal {
            return;
        }
        let _ = unsafe { TerminateProcess(self.process.0, 0xE1_04) };
        let _ = self.job.terminate(0xE1_04);
        let _ = wait_for_job_empty(self.job.handle, std::time::Duration::from_secs(5));
        let _ = unsafe { WaitForSingleObject(self.process.0, 5_000) };
        self.terminal = true;
    }
}

#[cfg(windows)]
impl Drop for JobChildHandles {
    fn drop(&mut self) {
        self.best_effort_cleanup();
    }
}

#[cfg(windows)]
struct ExistingJobMemberHandles {
    process: OwnedProcessHandle,
    thread: OwnedProcessHandle,
    spawn_identity: ProcessIdentity,
    executable: PinnedExecutable,
    spec: SuspendedLaunchSpec,
    command_line_utf16: Vec<u16>,
    stdout: Option<std::fs::File>,
    stderr: Option<std::fs::File>,
    job_identity: JobObjectIdentity,
    terminal: bool,
}

#[cfg(windows)]
impl ExistingJobMemberHandles {
    fn fresh_evidence(
        &self,
        job: &RecoverableJobObject,
    ) -> Result<SuspendedProcessEvidence, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::GetProcessId;
        let process_id = unsafe { GetProcessId(self.process.0) };
        if process_id == 0 || process_id != self.spawn_identity.process_id {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let process = inspect_process_handle(process_id, self.process.0)
            .map_err(|error| windows_adapter_from_io(&error))?;
        if process.start_time_100ns != self.spawn_identity.start_time_100ns
            || !same_windows_path(&process.image_path, &self.spawn_identity.image_path)
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let observed_file = file_identity(Path::new(&process.image_path))
            .map_err(|error| windows_adapter_from_io(&error))?;
        if observed_file != self.executable.identity
            || !same_windows_path(&process.image_path, &self.spec.executable.to_string_lossy())
            || !job.contains_process(process_id)?
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let count = u32::try_from(
            job_process_ids(job.handle.0)
                .map_err(|error| windows_adapter_from_io(&error))?
                .len(),
        )
        .map_err(|_| WindowsAdapterError::Failed)?;
        if count == 0 {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(SuspendedProcessEvidence {
            process,
            executable: observed_file,
            job: self.job_identity.clone(),
            requested_executable: self.spec.executable.clone(),
            arguments: self.spec.arguments.clone(),
            working_directory: self.spec.working_directory.clone(),
            environment: self.spec.environment.clone(),
            command_line_utf16: self.command_line_utf16.clone(),
            job_process_count: count,
        })
    }

    fn process_observation(&self) -> Result<Option<i32>, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0_u32;
                if unsafe { GetExitCodeProcess(self.process.0, &raw mut code) } == 0 {
                    return Err(last_windows_adapter_error());
                }
                Ok(Some(i32::from_ne_bytes(code.to_ne_bytes())))
            }
            _ => Err(last_windows_adapter_error()),
        }
    }

    fn terminate_and_reap(
        &mut self,
        requested_exit_code: u32,
        job: &RecoverableJobObject,
    ) -> Result<TerminatedExistingJobChild, WindowsAdapterError> {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
        if unsafe { TerminateProcess(self.process.0, requested_exit_code) } == 0 {
            let error = last_windows_adapter_error();
            if self.process_observation()?.is_none() {
                return Err(error);
            }
        }
        if unsafe { WaitForSingleObject(self.process.0, 5_000) } != WAIT_OBJECT_0 {
            return Err(WindowsAdapterError::Timeout);
        }
        let observed_exit_code = self
            .process_observation()?
            .ok_or(WindowsAdapterError::Failed)?;
        let job_member_count = job.active_process_count()?;
        self.terminal = true;
        Ok(TerminatedExistingJobChild {
            process: self.spawn_identity.clone(),
            job: self.job_identity.clone(),
            requested_exit_code,
            observed_exit_code,
            job_member_count,
        })
    }

    fn best_effort_cleanup(&mut self) {
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
        if self.terminal {
            return;
        }
        let _ = unsafe { TerminateProcess(self.process.0, 0xE1_04) };
        let _ = unsafe { WaitForSingleObject(self.process.0, 5_000) };
        self.terminal = true;
    }
}

#[cfg(windows)]
impl Drop for ExistingJobMemberHandles {
    fn drop(&mut self) {
        self.best_effort_cleanup();
    }
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "existing-Job launch keeps assignment and fail-closed cleanup contiguous"
)]
fn spawn_existing_job_member(
    job: &RecoverableJobObject,
    spec: SuspendedLaunchSpec,
) -> Result<SuspendedExistingJobChild<'_>, WindowsAdapterError> {
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    };
    let executable = PinnedExecutable::open(&spec.executable)?;
    let application = nul_terminated_wide(spec.executable.as_os_str())
        .map_err(|error| windows_adapter_from_io(&error))?;
    let command_line_utf16 = command_line(&spec.executable, &spec.arguments)
        .map_err(|error| windows_adapter_from_io(&error))?;
    let mut command_line = command_line_utf16.clone();
    let mut environment = command_environment(&spec.environment);
    let current_directory = nul_terminated_wide(spec.working_directory.as_os_str())
        .map_err(|error| windows_adapter_from_io(&error))?;
    let (stdin_read, stdin_write) = inheritable_pipe()?;
    let (stdout_read, stdout_write) = inheritable_pipe()?;
    let (stderr_read, stderr_write) = inheritable_pipe()?;
    make_non_inheritable(stdin_write.0)?;
    make_non_inheritable(stdout_read.0)?;
    make_non_inheritable(stderr_read.0)?;
    let inherited_handles = [stdin_read.0, stdout_write.0, stderr_write.0];
    let attributes = ProcThreadAttributeList::for_inherited_handles(&inherited_handles)?;
    let mut startup = STARTUPINFOEXW {
        StartupInfo: windows_sys::Win32::System::Threading::STARTUPINFOW {
            cb: u32::try_from(std::mem::size_of::<STARTUPINFOEXW>())
                .map_err(|_| WindowsAdapterError::Failed)?,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: stdin_read.0,
            hStdOutput: stdout_write.0,
            hStdError: stderr_write.0,
            ..Default::default()
        },
        lpAttributeList: attributes.list,
    };
    let mut information = PROCESS_INFORMATION::default();
    // SAFETY: all buffers and the STARTUPINFOEX attribute list remain live;
    // handle inheritance is restricted to the explicit standard handles.
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | CREATE_NO_WINDOW
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_mut_ptr().cast(),
            current_directory.as_ptr(),
            &raw mut startup.StartupInfo,
            &raw mut information,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    if information.hProcess.is_null() || information.hThread.is_null() {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
        };
        let cleanup_process = if information.hProcess.is_null() && information.dwProcessId != 0 {
            unsafe { OpenProcess(PROCESS_TERMINATE | 0x0010_0000, 0, information.dwProcessId) }
        } else {
            information.hProcess
        };
        if !cleanup_process.is_null() {
            let _ = unsafe { TerminateProcess(cleanup_process, 0xE1_04) };
            let _ = unsafe { WaitForSingleObject(cleanup_process, 5_000) };
            if cleanup_process != information.hProcess {
                unsafe { CloseHandle(cleanup_process) };
            }
        }
        if !information.hThread.is_null() {
            unsafe { CloseHandle(information.hThread) };
        }
        if !information.hProcess.is_null() {
            unsafe { CloseHandle(information.hProcess) };
        }
        return Err(WindowsAdapterError::Failed);
    }
    drop(stdin_read);
    drop(stdin_write);
    drop(stdout_write);
    drop(stderr_write);
    let process = OwnedProcessHandle::new(information.hProcess)?;
    let thread = OwnedProcessHandle::new(information.hThread)?;
    let mut cleanup = SuspendedProcessCleanup {
        process: process.0,
        armed: true,
    };
    let spawn_identity = inspect_process_handle(information.dwProcessId, process.0)
        .map_err(|error| windows_adapter_from_io(&error))?;
    let mut inner = ExistingJobMemberHandles {
        process,
        thread,
        spawn_identity,
        executable,
        spec,
        command_line_utf16,
        stdout: Some(stdout_read.into_file()),
        stderr: Some(stderr_read.into_file()),
        job_identity: job.identity().clone(),
        terminal: false,
    };
    job.assign_process_handle(inner.process.0)?;
    if !job.contains_process(inner.spawn_identity.process_id)? {
        inner.best_effort_cleanup();
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let observed_file = file_identity(Path::new(&inner.spawn_identity.image_path))
        .map_err(|error| windows_adapter_from_io(&error))?;
    if observed_file != inner.executable.identity
        || !same_windows_path(
            &inner.spawn_identity.image_path,
            &inner.spec.executable.to_string_lossy(),
        )
    {
        inner.best_effort_cleanup();
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    cleanup.disarm();
    Ok(SuspendedExistingJobChild { job, inner })
}

#[cfg(windows)]
impl<'job> SuspendedExistingJobChild<'job> {
    /// Returns the process identifier captured from the newly-created handle.
    /// The PID is only a diagnostic lookup key; all validation remains
    /// handle-bound and includes start time and image identity.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.inner.spawn_identity.process_id
    }

    /// Consumes the suspended member and requires caller-owned policy to
    /// return an opaque validation token before resume.
    ///
    /// # Errors
    /// Returns [`SuspendedValidationError::Mechanics`] when exact process or
    /// Job membership cannot be re-observed, or `Rejected` for the caller's
    /// policy error. Both paths kill and reap only this candidate.
    pub fn validate<V, E, F>(
        mut self,
        validator: F,
    ) -> Result<ValidatedSuspendedExistingJobChild<'job, V>, SuspendedValidationError<E>>
    where
        F: FnOnce(&SuspendedProcessEvidence) -> Result<V, E>,
    {
        let evidence = match self.inner.fresh_evidence(self.job) {
            Ok(evidence) => evidence,
            Err(error) => {
                self.inner.best_effort_cleanup();
                return Err(SuspendedValidationError::Mechanics(error));
            }
        };
        let validation = match validator(&evidence) {
            Ok(validation) => validation,
            Err(error) => {
                self.inner.best_effort_cleanup();
                return Err(SuspendedValidationError::Rejected(error));
            }
        };
        Ok(ValidatedSuspendedExistingJobChild {
            job: self.job,
            inner: self.inner,
            evidence,
            validation,
        })
    }

    /// Consumes and terminates only this suspended member.
    ///
    /// # Errors
    /// Returns a typed adapter error when the member cannot be terminated or
    /// reaped within the bounded wait.
    pub fn terminate(
        mut self,
        exit_code: u32,
    ) -> Result<TerminatedExistingJobChild, WindowsAdapterError> {
        self.inner.terminate_and_reap(exit_code, self.job)
    }
}

#[cfg(windows)]
impl<'job, V> ValidatedSuspendedExistingJobChild<'job, V> {
    #[must_use]
    pub fn evidence(&self) -> &SuspendedProcessEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn validation(&self) -> &V {
        &self.validation
    }

    /// Consumes the validated member and resumes exactly once.
    ///
    /// Fresh exact identity and Job membership are checked immediately before
    /// and after `ResumeThread`. Any unknown or inconsistent result kills and
    /// reaps only this member; the shared Job and its root remain untouched.
    ///
    /// # Errors
    /// Returns a typed adapter error when validation evidence changes,
    /// `ResumeThread` is unknown, or post-resume identity/membership is not
    /// exact. The candidate is killed and reaped on every error path.
    pub fn resume(mut self) -> Result<RunningExistingJobChild<'job, V>, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::ResumeThread;
        let before = match self.inner.fresh_evidence(self.job) {
            Ok(evidence) => evidence,
            Err(error) => {
                self.inner.best_effort_cleanup();
                return Err(error);
            }
        };
        if before.process != self.evidence.process
            || before.executable != self.evidence.executable
            || before.job != self.evidence.job
        {
            self.inner.best_effort_cleanup();
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let resumed = unsafe { ResumeThread(self.inner.thread.0) };
        if resumed == u32::MAX || resumed != 1 {
            let error = if resumed == u32::MAX {
                last_windows_adapter_error()
            } else {
                WindowsAdapterError::IdentityMismatch
            };
            self.inner.best_effort_cleanup();
            return Err(error);
        }
        let after = match self.inner.fresh_evidence(self.job) {
            Ok(evidence) => evidence,
            Err(error) => {
                self.inner.best_effort_cleanup();
                return Err(error);
            }
        };
        if after.process != before.process
            || after.executable != before.executable
            || after.job != before.job
        {
            self.inner.best_effort_cleanup();
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(RunningExistingJobChild {
            job: self.job,
            inner: self.inner,
            evidence: after,
            validation: self.validation,
        })
    }

    /// Consumes and terminates only this suspended member.
    ///
    /// # Errors
    /// Returns a typed adapter error when the member cannot be terminated or
    /// reaped within the bounded wait.
    pub fn terminate(
        mut self,
        exit_code: u32,
    ) -> Result<TerminatedExistingJobChild, WindowsAdapterError> {
        self.inner.terminate_and_reap(exit_code, self.job)
    }
}

#[cfg(windows)]
impl<V> RunningExistingJobChild<'_, V> {
    #[must_use]
    pub fn evidence(&self) -> &SuspendedProcessEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn validation(&self) -> &V {
        &self.validation
    }

    /// Returns the shared Job identity without exposing a Job handle.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        self.job.identity()
    }

    #[must_use]
    pub fn process(&self) -> &ProcessIdentity {
        self.evidence.process()
    }

    #[must_use]
    pub const fn executable_file_identity(&self) -> FileIdentity {
        self.evidence.executable_file_identity()
    }

    #[must_use]
    pub fn take_stdout(&mut self) -> Option<std::fs::File> {
        self.inner.stdout.take()
    }

    #[must_use]
    pub fn take_stderr(&mut self) -> Option<std::fs::File> {
        self.inner.stderr.take()
    }

    /// Observes only this process and the current member count of the shared
    /// Job. It never terminates the Job.
    ///
    /// # Errors
    /// Returns a typed adapter error when process exit state or Job membership
    /// cannot be observed.
    pub fn observe(&self) -> Result<ExistingJobMemberObservation, WindowsAdapterError> {
        let active_processes = self.job.active_process_count()?;
        match self.inner.process_observation()? {
            None => Ok(ExistingJobMemberObservation::Running { active_processes }),
            Some(exit_code) => Ok(ExistingJobMemberObservation::Exited {
                exit_code,
                active_processes,
            }),
        }
    }

    /// Terminates and reaps only this member process. The shared Job and all
    /// other members remain alive.
    ///
    /// # Errors
    /// Returns a typed adapter error when the member cannot be terminated or
    /// reaped within the bounded wait.
    pub fn terminate(
        mut self,
        exit_code: u32,
    ) -> Result<TerminatedExistingJobChild, WindowsAdapterError> {
        self.inner.terminate_and_reap(exit_code, self.job)
    }
}

/// Newly created suspended child. Validation and resume are consuming
/// typestate transitions, so neither transition can be repeated.
#[cfg(windows)]
pub struct SuspendedJobChild {
    inner: JobChildHandles,
}

/// Suspended child carrying the opaque token returned by caller-owned policy.
#[cfg(windows)]
pub struct ValidatedSuspendedJobChild<V> {
    inner: JobChildHandles,
    evidence: SuspendedProcessEvidence,
    validation: V,
}

/// Resumed child contained by the same kill-on-close Job Object.
#[cfg(windows)]
pub struct RunningJobChild<V> {
    inner: JobChildHandles,
    evidence: SuspendedProcessEvidence,
    validation: V,
}

/// Newly created suspended member of an already authenticated/reopened Job.
///
/// The lifetime ties the candidate to the retained recovery capability. The
/// candidate owns only its process resources; the shared Job remains owned by
/// [`RecoverableJobObject`].
#[cfg(windows)]
pub struct SuspendedExistingJobChild<'job> {
    job: &'job RecoverableJobObject,
    inner: ExistingJobMemberHandles,
}

/// Suspended existing-Job member carrying the caller-owned validation token.
#[cfg(windows)]
pub struct ValidatedSuspendedExistingJobChild<'job, V> {
    job: &'job RecoverableJobObject,
    inner: ExistingJobMemberHandles,
    evidence: SuspendedProcessEvidence,
    validation: V,
}

/// Running process member contained by an existing Job without owning it.
#[cfg(windows)]
pub struct RunningExistingJobChild<'job, V> {
    job: &'job RecoverableJobObject,
    inner: ExistingJobMemberHandles,
    evidence: SuspendedProcessEvidence,
    validation: V,
}

/// Idempotent observation of one running member in an existing Job.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExistingJobMemberObservation {
    Running {
        active_processes: u32,
    },
    Exited {
        exit_code: i32,
        active_processes: u32,
    },
}

/// Terminal receipt for one member process. The shared Job is never
/// terminated as part of producing this receipt.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminatedExistingJobChild {
    process: ProcessIdentity,
    job: JobObjectIdentity,
    requested_exit_code: u32,
    observed_exit_code: i32,
    job_member_count: u32,
}

#[cfg(windows)]
impl TerminatedExistingJobChild {
    /// Returns the exact process identity captured before launch.
    #[must_use]
    pub const fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    /// Returns the shared Job identity without exposing a Job handle.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        &self.job
    }

    #[must_use]
    pub const fn requested_exit_code(&self) -> u32 {
        self.requested_exit_code
    }

    #[must_use]
    pub const fn observed_exit_code(&self) -> i32 {
        self.observed_exit_code
    }

    /// Returns the number of remaining Job members after this process was
    /// reaped. A non-zero value is expected when the Kernel root remains live.
    #[must_use]
    pub const fn remaining_job_members(&self) -> u32 {
        self.job_member_count
    }
}

/// Typed, idempotent observation of a resumed child.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunningJobObservation {
    Running {
        active_processes: u32,
    },
    RootExited {
        exit_code: i32,
        active_processes: u32,
    },
    Exited {
        exit_code: i32,
    },
}

/// Terminal receipt produced by one consuming termination transition.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminatedJobChild {
    process: ProcessIdentity,
    job: JobObjectIdentity,
    history: JobProcessHistory,
    requested_exit_code: u32,
    observed_exit_code: i32,
    job_empty: bool,
    root_reaped: bool,
}

#[cfg(windows)]
impl TerminatedJobChild {
    #[must_use]
    pub fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    /// Returns the exact Job Object identity consumed by termination.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        &self.job
    }

    /// Returns the final historical process-membership observation.
    #[must_use]
    pub const fn history(&self) -> &JobProcessHistory {
        &self.history
    }

    #[must_use]
    pub const fn requested_exit_code(&self) -> u32 {
        self.requested_exit_code
    }

    #[must_use]
    pub const fn observed_exit_code(&self) -> i32 {
        self.observed_exit_code
    }

    #[must_use]
    pub const fn job_empty(&self) -> bool {
        self.job_empty
    }

    #[must_use]
    pub const fn root_reaped(&self) -> bool {
        self.root_reaped
    }
}

#[cfg(windows)]
impl SuspendedJobChild {
    /// Creates a child suspended in a fresh kill-on-close Job Object.
    ///
    /// # Errors
    /// Returns a typed adapter error for invalid deterministic material or any
    /// executable pin, process creation, identity, or Job assignment failure.
    pub fn spawn(spec: SuspendedLaunchSpec) -> Result<Self, WindowsAdapterError> {
        let sequence = JOB_OBJECT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let identity = JobObjectIdentity::new(format!(
            "Local\\Eliot-P02-{}-{sequence}",
            std::process::id()
        ))?;
        Self::spawn_named(spec, identity)
    }

    /// Creates a child suspended in one exact fresh named Job Object.
    ///
    /// The Job completion port is attached before assignment, and only the
    /// child-side standard handles are inheritable. Validation and resume stay
    /// separate consuming transitions.
    ///
    /// # Errors
    /// Returns a typed adapter error for a Job-name collision or any pipe,
    /// process, identity, or assignment failure.
    pub fn spawn_named(
        spec: SuspendedLaunchSpec,
        job_identity: JobObjectIdentity,
    ) -> Result<Self, WindowsAdapterError> {
        Self::spawn_named_with_limits(spec, job_identity, JobObjectLimits::default())
    }

    /// Creates a child suspended in a fresh named Job with resource ceilings.
    ///
    /// # Errors
    /// Returns a typed adapter error before resume when any limit, Job, pipe,
    /// process, identity, or assignment operation fails.
    #[allow(
        clippy::too_many_lines,
        reason = "suspended launch and fail-closed cleanup ordering remain contiguous"
    )]
    pub fn spawn_named_with_limits(
        spec: SuspendedLaunchSpec,
        job_identity: JobObjectIdentity,
        resource_limits: JobObjectLimits,
    ) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOEXW,
        };
        let executable = PinnedExecutable::open(&spec.executable)?;
        let application = nul_terminated_wide(spec.executable.as_os_str())
            .map_err(|error| windows_adapter_from_io(&error))?;
        let command_line_utf16 = command_line(&spec.executable, &spec.arguments)
            .map_err(|error| windows_adapter_from_io(&error))?;
        let mut command_line = command_line_utf16.clone();
        let mut environment = command_environment(&spec.environment);
        let current_directory = nul_terminated_wide(spec.working_directory.as_os_str())
            .map_err(|error| windows_adapter_from_io(&error))?;
        let (stdin_read, stdin_write) = inheritable_pipe()?;
        let (stdout_read, stdout_write) = inheritable_pipe()?;
        let (stderr_read, stderr_write) = inheritable_pipe()?;
        make_non_inheritable(stdin_write.0)?;
        make_non_inheritable(stdout_read.0)?;
        make_non_inheritable(stderr_read.0)?;
        let inherited_handles = [stdin_read.0, stdout_write.0, stderr_write.0];
        let attributes = ProcThreadAttributeList::for_inherited_handles(&inherited_handles)?;
        let job = JobObject::new_named_kill_on_close_with_limits(job_identity, resource_limits)?;
        let observer = JobProcessObserver::attach(job.handle)?;
        let mut startup = STARTUPINFOEXW {
            StartupInfo: windows_sys::Win32::System::Threading::STARTUPINFOW {
                cb: u32::try_from(std::mem::size_of::<STARTUPINFOEXW>())
                    .map_err(|_| WindowsAdapterError::Failed)?,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: stdin_read.0,
                hStdOutput: stdout_write.0,
                hStdError: stderr_write.0,
                ..Default::default()
            },
            lpAttributeList: attributes.list,
        };
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: all buffers and the STARTUPINFOEX attribute list remain live;
        // handle inheritance is restricted to `inherited_handles`.
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_NO_WINDOW
                    | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_mut_ptr().cast(),
                current_directory.as_ptr(),
                &raw mut startup.StartupInfo,
                &raw mut information,
            )
        } == 0
        {
            return Err(last_windows_adapter_error());
        }
        if information.hProcess.is_null() || information.hThread.is_null() {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::{
                OpenProcess, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
            };
            let cleanup_process = if information.hProcess.is_null() && information.dwProcessId != 0
            {
                unsafe { OpenProcess(PROCESS_TERMINATE | 0x0010_0000, 0, information.dwProcessId) }
            } else {
                information.hProcess
            };
            if !cleanup_process.is_null() {
                let _ = unsafe { TerminateProcess(cleanup_process, 0xE1_04) };
                let _ = unsafe { WaitForSingleObject(cleanup_process, 5_000) };
                if cleanup_process != information.hProcess {
                    unsafe { CloseHandle(cleanup_process) };
                }
            }
            if !information.hThread.is_null() {
                unsafe { CloseHandle(information.hThread) };
            }
            if !information.hProcess.is_null() {
                unsafe { CloseHandle(information.hProcess) };
            }
            return Err(WindowsAdapterError::Failed);
        }
        // Parent keeps only the read sides. Closing the sole parent stdin
        // writer gives the child deterministic EOF instead of inherited input.
        drop(stdin_read);
        drop(stdin_write);
        drop(stdout_write);
        drop(stderr_write);
        let process = OwnedProcessHandle::new(information.hProcess)?;
        let thread = OwnedProcessHandle::new(information.hThread)?;
        let mut cleanup = SuspendedProcessCleanup {
            process: process.0,
            armed: true,
        };
        let spawn_identity = inspect_process_handle(information.dwProcessId, process.0)
            .map_err(|error| windows_adapter_from_io(&error))?;
        let inner = JobChildHandles {
            process,
            thread,
            job,
            spawn_identity,
            executable,
            spec,
            command_line_utf16,
            stdout: Some(stdout_read.into_file()),
            stderr: Some(stderr_read.into_file()),
            observer,
            terminal: false,
        };
        cleanup.disarm();
        inner.job.assign_process_handle(inner.process.0)?;
        inner
            .observer
            .capture_pid(inner.spawn_identity.process_id)?;
        if !inner
            .job
            .contains_process(inner.spawn_identity.process_id)?
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let observed_file = file_identity(Path::new(&inner.spawn_identity.image_path))
            .map_err(|error| windows_adapter_from_io(&error))?;
        if observed_file != inner.executable.identity
            || !same_windows_path(
                &inner.spawn_identity.image_path,
                &inner.spec.executable.to_string_lossy(),
            )
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(Self { inner })
    }

    #[must_use]
    pub const fn id(&self) -> u32 {
        self.inner.spawn_identity.process_id
    }

    /// Consumes the unvalidated state and requires caller-owned policy to
    /// return an opaque validation token over fresh P-02 mechanics evidence.
    ///
    /// # Errors
    /// Returns `Mechanics` for failed retained-handle validation or `Rejected`
    /// with the caller's own policy/permit error. Either path kills and reaps
    /// the full Job before the error escapes.
    pub fn validate<V, E, F>(
        mut self,
        validator: F,
    ) -> Result<ValidatedSuspendedJobChild<V>, SuspendedValidationError<E>>
    where
        F: FnOnce(&SuspendedProcessEvidence) -> Result<V, E>,
    {
        let evidence = match self.inner.fresh_evidence() {
            Ok(evidence) => evidence,
            Err(error) => {
                self.inner.best_effort_cleanup();
                return Err(SuspendedValidationError::Mechanics(error));
            }
        };
        let validation = match validator(&evidence) {
            Ok(validation) => validation,
            Err(error) => {
                self.inner.best_effort_cleanup();
                return Err(SuspendedValidationError::Rejected(error));
            }
        };
        Ok(ValidatedSuspendedJobChild {
            inner: self.inner,
            evidence,
            validation,
        })
    }

    /// Consumes and terminates an unvalidated child without resuming it.
    ///
    /// # Errors
    /// Returns a typed adapter error when termination or bounded reap fails.
    pub fn terminate(mut self, exit_code: u32) -> Result<TerminatedJobChild, WindowsAdapterError> {
        terminalize(&mut self.inner, exit_code)
    }
}

#[cfg(windows)]
impl<V> ValidatedSuspendedJobChild<V> {
    #[must_use]
    pub fn evidence(&self) -> &SuspendedProcessEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn validation(&self) -> &V {
        &self.validation
    }

    /// Consumes the validated suspended state and resumes exactly once.
    ///
    /// # Errors
    /// Returns a typed adapter error when Windows rejects `ResumeThread`; the
    /// error path kills and reaps the full Job.
    pub fn resume(mut self) -> Result<RunningJobChild<V>, WindowsAdapterError> {
        use windows_sys::Win32::System::Threading::ResumeThread;
        if unsafe { ResumeThread(self.inner.thread.0) } == u32::MAX {
            let error = last_windows_adapter_error();
            self.inner.best_effort_cleanup();
            return Err(error);
        }
        Ok(RunningJobChild {
            inner: self.inner,
            evidence: self.evidence,
            validation: self.validation,
        })
    }

    /// Consumes and terminates a validated child without resuming it.
    ///
    /// # Errors
    /// Returns a typed adapter error when termination or bounded reap fails.
    pub fn terminate(mut self, exit_code: u32) -> Result<TerminatedJobChild, WindowsAdapterError> {
        terminalize(&mut self.inner, exit_code)
    }
}

#[cfg(windows)]
impl<V> RunningJobChild<V> {
    #[must_use]
    pub fn evidence(&self) -> &SuspendedProcessEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn validation(&self) -> &V {
        &self.validation
    }

    /// Returns the exact owner-scoped Job Object identity.
    #[must_use]
    pub const fn job_identity(&self) -> &JobObjectIdentity {
        self.inner.job.identity()
    }

    /// Transfers ownership of the process stdout read handle exactly once.
    #[must_use]
    pub fn take_stdout(&mut self) -> Option<std::fs::File> {
        self.inner.stdout.take()
    }

    /// Transfers ownership of the process stderr read handle exactly once.
    #[must_use]
    pub fn take_stderr(&mut self) -> Option<std::fs::File> {
        self.inner.stderr.take()
    }

    /// Returns an idempotent observation without changing typestate.
    ///
    /// # Errors
    /// Returns a typed adapter error when process or Job state cannot be read.
    pub fn observe(&self) -> Result<RunningJobObservation, WindowsAdapterError> {
        let active_processes = self.inner.active_process_count()?;
        match self.inner.root_exit_code()? {
            None => Ok(RunningJobObservation::Running { active_processes }),
            Some(exit_code) if active_processes == 0 => {
                Ok(RunningJobObservation::Exited { exit_code })
            }
            Some(exit_code) => Ok(RunningJobObservation::RootExited {
                exit_code,
                active_processes,
            }),
        }
    }

    /// Returns identities observed in the Job so far, including exited members.
    ///
    /// # Errors
    /// Returns a typed adapter error when membership or identity cannot be read.
    pub fn job_processes(&self) -> Result<Vec<ProcessIdentity>, WindowsAdapterError> {
        Ok(self
            .inner
            .history()?
            .processes()
            .iter()
            .map(|process| process.process().clone())
            .collect())
    }

    /// Returns the current number of live Job members.
    ///
    /// # Errors
    /// Returns a typed adapter error when Job state cannot be queried.
    pub fn active_process_count(&self) -> Result<u32, WindowsAdapterError> {
        self.inner.active_process_count()
    }

    /// Returns historical membership observed so far.
    ///
    /// While the Job is active, `complete` is necessarily false because more
    /// descendants may still be created.
    ///
    /// # Errors
    /// Returns a typed adapter error when current Job membership cannot be read.
    pub fn process_history(&self) -> Result<JobProcessHistory, WindowsAdapterError> {
        self.inner.history()
    }

    /// Waits for the Job to become empty and returns the final history.
    ///
    /// A timed-out or identity-gap result is returned with `complete == false`;
    /// callers must project that as UNKNOWN rather than tree closure.
    ///
    /// # Errors
    /// Returns a typed adapter error when Job membership cannot be observed.
    pub fn wait_for_empty_history(
        &self,
        timeout: std::time::Duration,
    ) -> Result<JobProcessHistory, WindowsAdapterError> {
        self.inner.wait_for_empty_history(timeout)
    }

    /// Terminates and reaps the complete Job without consuming this owner.
    ///
    /// A failed termination or bounded wait leaves the process and Job
    /// handles attached to this value so the owning executor can retry and
    /// retain exact cleanup evidence.
    ///
    /// # Errors
    ///
    /// Returns a typed adapter error when Job termination, bounded reap, or
    /// final process evidence capture fails.
    pub fn terminate_in_place(
        &mut self,
        exit_code: u32,
    ) -> Result<TerminatedJobChild, WindowsAdapterError> {
        terminalize(&mut self.inner, exit_code)
    }

    /// Consumes and terminates the complete Job exactly once.
    ///
    /// # Errors
    /// Returns a typed adapter error when termination or bounded reap fails.
    pub fn terminate(mut self, exit_code: u32) -> Result<TerminatedJobChild, WindowsAdapterError> {
        self.terminate_in_place(exit_code)
    }
}

/// Cancels one synchronous read issued by a capture reader thread.
///
/// `Ok(false)` means that the thread had no pending synchronous I/O when the
/// cancellation was requested; callers still need to use their bounded wait
/// policy before joining it.
///
/// # Errors
///
/// Returns a typed adapter error when Windows rejects the cancellation for a
/// reason other than there being no pending synchronous I/O.
#[cfg(windows)]
pub fn cancel_capture_thread_io(
    thread: &std::thread::JoinHandle<()>,
) -> Result<bool, WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
    use windows_sys::Win32::System::IO::CancelSynchronousIo;

    if unsafe { CancelSynchronousIo(thread.as_raw_handle()) } != 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_NOT_FOUND.cast_signed()) {
        Ok(false)
    } else {
        Err(windows_adapter_from_io(&error))
    }
}

#[cfg(windows)]
fn terminalize(
    inner: &mut JobChildHandles,
    requested_exit_code: u32,
) -> Result<TerminatedJobChild, WindowsAdapterError> {
    let process = inner.spawn_identity.clone();
    let (observed_exit_code, history) = inner.terminate_and_reap(requested_exit_code)?;
    Ok(TerminatedJobChild {
        process,
        job: inner.job.identity().clone(),
        history,
        requested_exit_code,
        observed_exit_code,
        job_empty: true,
        root_reaped: true,
    })
}

/// Windows implementation of the P-01 ports.
pub struct WindowsPlatform {
    root: PathBuf,
    #[cfg(windows)]
    _root_pin: std::fs::File,
}

/// Retained no-follow launch proof for an executable and its working scope.
///
/// The open handles and ancestor pins remain owned by this value through the
/// suspended `CreateProcess` validation and resume boundary. Reopening a path
/// is only a comparison against these retained identities; it is never the
/// sole proof of containment.
pub struct RetainedProcessPathLease {
    root: PathBuf,
    executable_path: PathBuf,
    working_directory: PathBuf,
    executable_identity: FileIdentity,
    working_directory_identity: FileIdentity,
    #[cfg(windows)]
    executable: std::fs::File,
    #[cfg(windows)]
    working_directory_handle: std::fs::File,
    #[cfg(windows)]
    ancestor_pins: Vec<std::fs::File>,
    #[cfg(windows)]
    ancestor_identities: Vec<(PathBuf, FileIdentity)>,
}

impl std::fmt::Debug for RetainedProcessPathLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedProcessPathLease")
            .field("root", &self.root)
            .field("executable_path", &self.executable_path)
            .field("working_directory", &self.working_directory)
            .field("executable_identity", &self.executable_identity)
            .field(
                "working_directory_identity",
                &self.working_directory_identity,
            )
            .finish_non_exhaustive()
    }
}

impl WindowsPlatform {
    /// Retains exact no-follow handles and ancestor identities for a launch.
    ///
    /// # Errors
    ///
    /// Returns a typed path/provider error when containment, identity, or
    /// digest validation cannot be established.
    pub fn retain_process_path_lease(
        &self,
        executable: &Path,
        working_directory: &Path,
        expected_sha256: &str,
    ) -> Result<RetainedProcessPathLease, PortError> {
        if !executable.is_absolute()
            || !working_directory.is_absolute()
            || !valid_sha256_hex(expected_sha256)
        {
            return Err(PortError::InvalidPath);
        }
        validate_containment(&self.root, executable)?;
        validate_containment(&self.root, working_directory)?;
        #[cfg(windows)]
        {
            use std::io::Read;
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            let mut executable_options = std::fs::OpenOptions::new();
            executable_options
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            let mut executable_handle = executable_options
                .open(executable)
                .map_err(|_| PortError::InvalidPath)?;
            let executable_metadata = executable_handle
                .metadata()
                .map_err(|_| PortError::InvalidPath)?;
            if !executable_metadata.is_file() || is_reparse_point(&executable_metadata) {
                return Err(PortError::InvalidPath);
            }
            let executable_identity = file_identity_from_handle(&executable_handle)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            let mut bytes = Vec::with_capacity(executable_metadata.len().try_into().unwrap_or(0));
            executable_handle
                .read_to_end(&mut bytes)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            if sha256_hex(&bytes) != expected_sha256.to_ascii_lowercase() {
                return Err(PortError::InvalidPath);
            }
            let mut directory_options = std::fs::OpenOptions::new();
            directory_options
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(
                    windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS
                        | FILE_FLAG_OPEN_REPARSE_POINT,
                );
            let working_handle = directory_options
                .open(working_directory)
                .map_err(|_| PortError::InvalidPath)?;
            let working_metadata = working_handle
                .metadata()
                .map_err(|_| PortError::InvalidPath)?;
            if !working_metadata.is_dir() || is_reparse_point(&working_metadata) {
                return Err(PortError::InvalidPath);
            }
            let working_directory_identity = file_identity_from_handle(&working_handle)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            let parent = executable.parent().ok_or(PortError::InvalidPath)?;
            let mut ancestor_pins = pin_ancestors(&self.root, parent)?;
            ancestor_pins.extend(pin_ancestors(&self.root, working_directory)?);
            let mut ancestor_identities = Vec::new();
            for path in executable
                .ancestors()
                .take_while(|path| *path != self.root)
                .chain(
                    working_directory
                        .ancestors()
                        .take_while(|path| *path != self.root),
                )
            {
                if path.is_dir() {
                    let handle = pin_directory(path).map_err(|_| PortError::InvalidPath)?;
                    let identity = file_identity_from_handle(&handle)
                        .map_err(|_| PortError::Provider(provider_failed()))?;
                    ancestor_identities.push((path.to_path_buf(), identity));
                }
            }
            Ok(RetainedProcessPathLease {
                root: self.root.clone(),
                executable_path: executable.to_path_buf(),
                working_directory: working_directory.to_path_buf(),
                executable_identity,
                working_directory_identity,
                executable: executable_handle,
                working_directory_handle: working_handle,
                ancestor_pins,
                ancestor_identities,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (executable, working_directory, expected_sha256);
            Err(PortError::Provider(provider_failed()))
        }
    }
}

impl RetainedProcessPathLease {
    /// Returns the identity retained for the executable handle.
    pub const fn executable_identity(&self) -> FileIdentity {
        self.executable_identity
    }

    /// Validates current path projections against retained handles and pins.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPath` or a provider error when an identity, digest,
    /// ancestor, or no-follow check cannot be proven.
    pub fn validate(
        &self,
        executable: &Path,
        working_directory: &Path,
        expected_sha256: &str,
    ) -> Result<(), PortError> {
        if executable != self.executable_path || working_directory != self.working_directory {
            return Err(PortError::InvalidPath);
        }
        #[cfg(windows)]
        {
            use std::io::Read;
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
                FILE_SHARE_WRITE,
            };
            let mut executable_options = std::fs::OpenOptions::new();
            executable_options
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            let mut current_executable = executable_options
                .open(executable)
                .map_err(|_| PortError::InvalidPath)?;
            let metadata = current_executable
                .metadata()
                .map_err(|_| PortError::InvalidPath)?;
            if !metadata.is_file() || is_reparse_point(&metadata) {
                return Err(PortError::InvalidPath);
            }
            if file_identity_from_handle(&current_executable)
                .map_err(|_| PortError::Provider(provider_failed()))?
                != self.executable_identity
            {
                return Err(PortError::InvalidPath);
            }
            let mut bytes = Vec::new();
            current_executable
                .read_to_end(&mut bytes)
                .map_err(|_| PortError::Provider(provider_failed()))?;
            if sha256_hex(&bytes) != expected_sha256.to_ascii_lowercase() {
                return Err(PortError::InvalidPath);
            }
            let mut directory_options = std::fs::OpenOptions::new();
            directory_options
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
            let current_working = directory_options
                .open(working_directory)
                .map_err(|_| PortError::InvalidPath)?;
            let metadata = current_working
                .metadata()
                .map_err(|_| PortError::InvalidPath)?;
            if !metadata.is_dir() || is_reparse_point(&metadata) {
                return Err(PortError::InvalidPath);
            }
            if file_identity_from_handle(&current_working)
                .map_err(|_| PortError::Provider(provider_failed()))?
                != self.working_directory_identity
            {
                return Err(PortError::InvalidPath);
            }
            for (path, identity) in &self.ancestor_identities {
                let handle = pin_directory(path).map_err(|_| PortError::InvalidPath)?;
                if file_identity_from_handle(&handle)
                    .map_err(|_| PortError::Provider(provider_failed()))?
                    != *identity
                {
                    return Err(PortError::InvalidPath);
                }
            }
            let _ = (
                &self.executable,
                &self.working_directory_handle,
                &self.ancestor_pins,
            );
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = (executable, working_directory, expected_sha256);
            Err(PortError::Provider(provider_failed()))
        }
    }

    /// Revalidates the retained executable/work-root/digest proof and observes
    /// the exact live process identity for one child PID.
    ///
    /// The observed image path and file identity must still project to the
    /// retained executable. Callers must compare the complete returned value
    /// across security-sensitive observations so PID reuse and image changes
    /// fail closed.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPath` or a typed provider failure when the retained
    /// path proof, process query, image path, or image file identity cannot be
    /// proven.
    pub fn validate_process_identity(
        &self,
        process_id: u32,
        executable: &Path,
        working_directory: &Path,
        expected_sha256: &str,
    ) -> Result<ProcessIdentity, PortError> {
        self.validate(executable, working_directory, expected_sha256)?;
        if process_id == 0 {
            return Err(PortError::InvalidPath);
        }
        #[cfg(windows)]
        {
            let identity = inspect_process_identity(process_id)
                .map_err(|error| PortError::Provider(provider_from_io(&error)))?;
            if !same_windows_path(&identity.image_path, &executable.to_string_lossy())
                || file_identity(Path::new(&identity.image_path))
                    .map_err(|error| PortError::Provider(provider_from_io(&error)))?
                    != self.executable_identity
            {
                return Err(PortError::InvalidPath);
            }
            Ok(identity)
        }
        #[cfg(not(windows))]
        {
            let _ = process_id;
            Err(PortError::Provider(provider_failed()))
        }
    }
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

    /// Protects secret bytes for the current Windows user through DPAPI.
    ///
    /// # Errors
    /// Returns a typed adapter error for empty input or DPAPI failure.
    pub fn protect_secret(&self, secret: &[u8]) -> Result<ProtectedSecret, WindowsAdapterError> {
        if secret.is_empty() {
            return Err(WindowsAdapterError::InvalidInput);
        }
        dpapi_protect(secret)
    }

    /// Decrypts bytes previously protected for this Windows user.
    ///
    /// # Errors
    /// Returns a typed adapter error when ciphertext is invalid or unavailable.
    pub fn unprotect_secret(
        &self,
        protected: &ProtectedSecret,
    ) -> Result<CredentialSecret, WindowsAdapterError> {
        dpapi_unprotect(protected.as_bytes())
    }

    /// Writes an opaque generic credential through Windows Credential Manager.
    ///
    /// # Errors
    /// Returns a typed adapter error for invalid keys, size or provider failure.
    pub fn write_credential(&self, key: &str, secret: &[u8]) -> Result<(), WindowsAdapterError> {
        if installer_credential_target(key) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        credential_write(key, secret)
    }

    /// Reads the exact opaque bytes stored in Windows Credential Manager.
    ///
    /// # Errors
    /// Returns a typed adapter error when the key is invalid, absent or inaccessible.
    pub fn read_credential(&self, key: &str) -> Result<CredentialSecret, WindowsAdapterError> {
        if installer_credential_target(key) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        credential_read(key)
    }

    /// Deletes a generic credential. Missing credentials remain explicitly
    /// unavailable rather than being reported as a successful deletion.
    ///
    /// # Errors
    /// Returns a typed adapter error when the key is invalid, absent or inaccessible.
    pub fn delete_credential(&self, key: &str) -> Result<(), WindowsAdapterError> {
        if installer_credential_target(key) {
            return Err(WindowsAdapterError::InvalidInput);
        }
        credential_delete(key)
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

fn admit_named_pipe_peer_process(
    observed: &ProcessIdentity,
    expectation: &NamedPipePeerExpectation,
) -> Result<(), WindowsAdapterError> {
    if let Some(approved) = expectation.approved_process_binding()
        && !same_process_identity(observed, approved.identity())
    {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    if let Some(approved) = expectation.approved_process_job_binding() {
        if !same_process_identity(observed, approved.process_binding().identity()) {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let current =
            observe_named_pipe_peer_process_in_job(approved.job_name(), observed.process_id)?;
        if !same_process_identity(
            current.process_binding().identity(),
            approved.process_binding().identity(),
        ) {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
    }
    Ok(())
}

fn same_process_identity(observed: &ProcessIdentity, approved: &ProcessIdentity) -> bool {
    if observed.process_id != approved.process_id
        || observed.start_time_100ns != approved.start_time_100ns
        || !valid_process_image_path(&observed.image_path)
        || !valid_process_image_path(&approved.image_path)
    {
        return false;
    }

    #[cfg(windows)]
    {
        same_windows_path(&observed.image_path, &approved.image_path)
    }
    #[cfg(not(windows))]
    {
        observed.image_path == approved.image_path
    }
}

/// Authenticates the server bound to a connected client-end named-pipe handle.
///
/// # Errors
/// Returns a typed adapter error when DACL, process identity, SID or session
/// proof fails.
#[cfg(windows)]
pub fn authenticate_named_pipe_server(
    pipe: std::os::windows::io::BorrowedHandle<'_>,
    expectation: &NamedPipePeerExpectation,
) -> Result<NamedPipePeerEvidence, WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let pipe_handle: windows_sys::Win32::Foundation::HANDLE = pipe.as_raw_handle().cast();
    if pipe_handle.is_null() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    validate_pipe_dacl(pipe_handle, &expectation.expected_sid)?;
    let mut process_id = 0_u32;
    if unsafe { GetNamedPipeServerProcessId(pipe_handle, &raw mut process_id) } == 0
        || process_id == 0
    {
        return Err(last_windows_adapter_error());
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(last_windows_adapter_error());
    }
    let observed = (|| {
        let identity = inspect_process_handle(process_id, process)
            .map_err(|error| windows_adapter_from_io(&error))?;
        admit_named_pipe_peer_process(&identity, expectation)?;
        let (sid, session_id) = process_token_identity(process)?;
        if sid != expectation.expected_sid || session_id != expectation.expected_session_id {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(NamedPipePeerEvidence {
            process: identity,
            sid,
            session_id,
        })
    })();
    unsafe { CloseHandle(process) };
    observed
}

/// Authenticates the client bound to a connected server-end named-pipe handle.
///
/// The process identity and process token are read from one retained process
/// handle. The connected client is then impersonated only long enough to bind
/// its thread token to the same SID/session, and an RAII guard calls
/// `RevertToSelf` on every return path.
///
/// # Errors
/// Returns a typed adapter error when PID, process, token, impersonation,
/// exact process identity, SID/session expectation or reversion cannot be
/// established.
#[cfg(windows)]
pub fn authenticate_named_pipe_client(
    pipe: std::os::windows::io::BorrowedHandle<'_>,
    expectation: &NamedPipePeerExpectation,
) -> Result<NamedPipePeerEvidence, WindowsAdapterError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let pipe_handle: windows_sys::Win32::Foundation::HANDLE = pipe.as_raw_handle().cast();
    if pipe_handle.is_null() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    validate_pipe_dacl(pipe_handle, &expectation.expected_sid)?;
    let mut process_id = 0_u32;
    if unsafe { GetNamedPipeClientProcessId(pipe_handle, &raw mut process_id) } == 0
        || process_id == 0
    {
        return Err(last_windows_adapter_error());
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(last_windows_adapter_error());
    }
    let observed = (|| {
        let identity = inspect_process_handle(process_id, process)
            .map_err(|error| windows_adapter_from_io(&error))?;
        admit_named_pipe_peer_process(&identity, expectation)?;
        let process_token = process_token_identity(process)?;
        let principal_matches = match expectation.auth_discriminator() {
            NamedPipeAuthDiscriminator::Ordinary => {
                // Ordinary peers are admitted by the identity observed from
                // the retained process handle. Do not compare that primary
                // token with an impersonation token: they are distinct token
                // objects even when they represent the same client.
                process_token.0 == expectation.expected_sid
                    && process_token.1 == expectation.expected_session_id
            }
            NamedPipeAuthDiscriminator::BuiltinAdministrators => {
                let process_is_admin = process_token_is_builtin_administrator(process)?;
                let impersonation = ImpersonationGuard::begin(pipe_handle)?;
                let thread_is_admin = thread_token_is_builtin_administrator()?;
                impersonation.revert()?;
                // The process token and the impersonated token are checked
                // independently through TokenGroups. Never pass a primary
                // process token to CheckTokenMembership.
                process_is_admin && thread_is_admin && process_token.0 != "S-1-5-18"
            }
        };
        if !principal_matches {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(NamedPipePeerEvidence {
            process: identity,
            sid: process_token.0,
            session_id: process_token.1,
        })
    })();
    unsafe { CloseHandle(process) };
    observed
}

/// Observes the current process token for use as an inert named-pipe server
/// expectation. This does not authenticate any pipe or issue a peer result.
///
/// # Errors
/// Returns a typed adapter error when the current token cannot be observed.
#[cfg(windows)]
pub fn current_process_named_pipe_expectation()
-> Result<NamedPipePeerExpectation, WindowsAdapterError> {
    let process = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
    let (sid, session_id) = process_token_identity(process)?;
    NamedPipePeerExpectation::new(sid, session_id)
}

#[cfg(not(windows))]
pub fn current_process_named_pipe_expectation()
-> Result<NamedPipePeerExpectation, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
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

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut value = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

#[cfg(windows)]
pub(crate) fn fill_system_random(bytes: &mut [u8]) -> Result<(), WindowsAdapterError> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };

    let length = u32::try_from(bytes.len()).map_err(|_| WindowsAdapterError::InvalidInput)?;
    let status = unsafe {
        // SAFETY: `bytes` is a live writable slice and `length` exactly matches it.
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(WindowsAdapterError::Failed)
    }
}

#[cfg(not(windows))]
pub(crate) fn fill_system_random(_bytes: &mut [u8]) -> Result<(), WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

/// Issues an unpredictable public nonce for one durable SCM registration
/// intent.  The value is not a secret; it is bound into the service command
/// line and the protected installer ownership marker.
///
/// # Errors
/// Returns `Unavailable` when the Windows system CSPRNG cannot issue a nonce.
#[must_use = "the nonce must be durably bound before SCM mutation"]
pub fn fresh_service_registration_nonce() -> Result<PlatformHandle, WindowsAdapterError> {
    let mut random = [0_u8; 32];
    fill_system_random(&mut random)?;
    let value = hex_lower(&random);
    random.fill(0);
    PlatformHandle::new(value).map_err(|_| WindowsAdapterError::InvalidInput)
}

const ACTIVATION_NONCE_PREFIX: &str = "eliot-activation-";
const ACTIVATION_NONCE_RANDOM_BYTES: usize = 32;
const ACTIVATION_NONCE_HEX_BYTES: usize = ACTIVATION_NONCE_RANDOM_BYTES * 2;

/// Issues fresh OS-random material exclusively for Kernel activation.
///
/// The nonce deliberately has no lineage, time, process, or other caller
/// input.  Any `BCrypt` failure is terminal for this issuance attempt; callers
/// must not substitute a deterministic or weak fallback. Composition must wrap
/// the returned handle in the canonical `eliot_platform::KernelActivationNonce`
/// and must never substitute a Host installation-epoch nonce.
///
/// # Errors
///
/// Returns [`WindowsAdapterError::Failed`] when the system RNG rejects the
/// request, or [`WindowsAdapterError::InvalidInput`] if the resulting handle
/// cannot satisfy the bounded nonce shape.
#[cfg(windows)]
pub fn fresh_activation_nonce_material() -> Result<PlatformHandle, WindowsAdapterError> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };

    let mut random = [0_u8; ACTIVATION_NONCE_RANDOM_BYTES];
    let status = unsafe {
        // SAFETY: `random` is an initialized, writable fixed-size buffer and
        // its length is within BCryptGenRandom's u32 parameter range.
        BCryptGenRandom(
            std::ptr::null_mut(),
            random.as_mut_ptr(),
            u32::try_from(random.len()).map_err(|_| WindowsAdapterError::InvalidInput)?,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(WindowsAdapterError::Failed);
    }

    let mut value = String::with_capacity(ACTIVATION_NONCE_HEX_BYTES);
    for byte in random {
        use std::fmt::Write;
        write!(&mut value, "{byte:02x}").map_err(|_| WindowsAdapterError::Failed)?;
    }

    let handle = PlatformHandle::new(value).map_err(|_| WindowsAdapterError::InvalidInput)?;
    if handle.as_str().len() != ACTIVATION_NONCE_HEX_BYTES
        || !handle
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(WindowsAdapterError::InvalidInput);
    }
    Ok(handle)
}

#[cfg(not(windows))]
pub fn fresh_activation_nonce_material() -> Result<PlatformHandle, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

/// Issues the canonical typed one-use Kernel activation permit from Windows OS RNG material.
///
/// This is the production composition seam. It cannot accept a Host-process
/// nonce and its formatting remains redacted by [`KernelActivationNonce`].
///
/// # Errors
///
/// Returns the classified OS RNG failure, or [`WindowsAdapterError::InvalidInput`]
/// if the generated material violates the canonical 256-bit nonce contract.
pub fn fresh_kernel_activation_nonce() -> Result<KernelActivationNonce, WindowsAdapterError> {
    KernelActivationNonce::new(fresh_activation_nonce_material()?)
        .map_err(|_| WindowsAdapterError::InvalidInput)
}

/// Compatibility wrapper retaining the historical prefixed handle shape.
/// New Kernel activation code must call [`fresh_kernel_activation_nonce`].
///
/// # Errors
///
/// Returns the classified OS RNG failure, or [`WindowsAdapterError::InvalidInput`]
/// if the compatibility handle cannot be constructed from the generated material.
pub fn fresh_activation_nonce() -> Result<PlatformHandle, WindowsAdapterError> {
    let material = fresh_activation_nonce_material()?;
    PlatformHandle::new(format!("{ACTIVATION_NONCE_PREFIX}{}", material.as_str()))
        .map_err(|_| WindowsAdapterError::InvalidInput)
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
                    let _protected = open_protected_file(&path, false)
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
struct DirectoryPublicationContour {
    entries: Vec<(PathBuf, FileIdentity, std::fs::File)>,
    canonical_parent: PathBuf,
    parent_identity: FileIdentity,
}

#[cfg(windows)]
fn validate_directory_publication_absolute(path: &Path) -> Result<(), DirectoryPublicationError> {
    if !path.is_absolute() {
        return Err(DirectoryPublicationError::InvalidPath);
    }
    let raw = path
        .to_str()
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("\\\\?\\")
        || lower.starts_with("\\\\.\\")
        || lower.starts_with("\\??\\")
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(DirectoryPublicationError::InvalidPath);
    }
    Ok(())
}

#[cfg(windows)]
fn publication_path_text(path: &Path) -> Result<String, DirectoryPublicationError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or(DirectoryPublicationError::InvalidPath)
}

#[cfg(windows)]
fn validate_owned_temporary_name(
    temporary: &Path,
    destination: &Path,
) -> Result<(), DirectoryPublicationError> {
    validate_directory_publication_absolute(temporary)?;
    validate_directory_publication_absolute(destination)?;
    let temporary_parent = temporary
        .parent()
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    let destination_parent = destination
        .parent()
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    if !windows_paths_equal(temporary_parent, destination_parent) {
        return Err(DirectoryPublicationError::InvalidPath);
    }
    let destination_name = destination
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    let temporary_name = temporary
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    validate_package_relative_path(Path::new(destination_name))
        .map_err(|_| DirectoryPublicationError::InvalidPath)?;
    validate_package_relative_path(Path::new(temporary_name))
        .map_err(|_| DirectoryPublicationError::InvalidPath)?;
    let prefix = format!(".{destination_name}.tmp.{}.", std::process::id());
    let Some(index) = temporary_name.strip_prefix(&prefix) else {
        return Err(DirectoryPublicationError::InvalidPath);
    };
    if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DirectoryPublicationError::InvalidPath);
    }
    Ok(())
}

#[cfg(windows)]
fn open_publication_directory(
    path: &Path,
    share_delete: bool,
) -> Result<std::fs::File, DirectoryPublicationError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let share_mode =
        FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ)
        .share_mode(share_mode)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            DirectoryPublicationError::InvalidPath
        } else {
            DirectoryPublicationError::Io
        }
    })?;
    let metadata = file.metadata().map_err(|_| DirectoryPublicationError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DirectoryPublicationError::ReparsePoint);
    }
    if !metadata.is_dir() {
        return Err(DirectoryPublicationError::InvalidPath);
    }
    Ok(file)
}

#[cfg(windows)]
fn open_movable_publication_directory(
    path: &Path,
) -> Result<std::fs::File, DirectoryPublicationError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        // The retained directory is an identity/readback authority, not a
        // deletion handle.  Sharing delete lets the materializer's existing
        // no-follow directory sync handle open while this source remains
        // retained; publication itself still uses the create-new move.
        .access_mode(FILE_GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|_| DirectoryPublicationError::Io)?;
    let metadata = file.metadata().map_err(|_| DirectoryPublicationError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DirectoryPublicationError::ReparsePoint);
    }
    if !metadata.is_dir() {
        return Err(DirectoryPublicationError::InvalidPath);
    }
    Ok(file)
}

#[cfg(windows)]
fn retain_directory_publication_contour(
    parent: &Path,
) -> Result<DirectoryPublicationContour, DirectoryPublicationError> {
    let mut ancestors = parent
        .ancestors()
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    ancestors.reverse();
    if ancestors.is_empty() {
        return Err(DirectoryPublicationError::InvalidPath);
    }
    let mut entries = Vec::with_capacity(ancestors.len());
    for expected_path in ancestors {
        let handle = open_publication_directory(&expected_path, false)?;
        let observed_path =
            final_windows_path_from_handle(&handle).map_err(|_| DirectoryPublicationError::Io)?;
        if !windows_paths_equal(&observed_path, &expected_path) {
            return Err(DirectoryPublicationError::IdentityMismatch);
        }
        let identity =
            file_identity_from_handle(&handle).map_err(|_| DirectoryPublicationError::Io)?;
        if identity.volume_serial_number == 0 || identity.file_index == 0 {
            return Err(DirectoryPublicationError::IdentityMismatch);
        }
        entries.push((observed_path, identity, handle));
    }
    let (canonical_parent, parent_identity, _) = entries
        .last()
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    Ok(DirectoryPublicationContour {
        canonical_parent: canonical_parent.clone(),
        parent_identity: *parent_identity,
        entries,
    })
}

#[cfg(windows)]
fn verify_directory_publication_contour(
    contour: &DirectoryPublicationContour,
) -> Result<(), DirectoryPublicationError> {
    for (expected_path, expected_identity, handle) in &contour.entries {
        let observed_path =
            final_windows_path_from_handle(handle).map_err(|_| DirectoryPublicationError::Io)?;
        let observed_identity =
            file_identity_from_handle(handle).map_err(|_| DirectoryPublicationError::Io)?;
        if !windows_paths_equal(&observed_path, expected_path)
            || observed_identity != *expected_identity
        {
            return Err(DirectoryPublicationError::IdentityMismatch);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn require_directory_publication_absent(
    destination: &Path,
) -> Result<(), DirectoryPublicationError> {
    match std::fs::symlink_metadata(destination) {
        Ok(_) => Err(DirectoryPublicationError::AlreadyExists),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(DirectoryPublicationError::Io),
    }
}

#[cfg(windows)]
fn move_directory_create_new_durable(
    temporary: &Path,
    destination: &Path,
) -> Result<(), DirectoryPublicationError> {
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
    let temporary_wide = wide(temporary);
    let destination_wide = wide(destination);
    let moved = unsafe {
        // SAFETY: both path buffers are NUL-terminated and live for the call.
        // Omitting MOVEFILE_REPLACE_EXISTING is the atomic fail-if-exists
        // contract; WRITE_THROUGH makes the metadata move durable before
        // success is returned.
        MoveFileExW(
            temporary_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved != 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(code)
            if code == ERROR_ALREADY_EXISTS.cast_signed()
                || code == ERROR_FILE_EXISTS.cast_signed()
    ) || std::fs::symlink_metadata(destination).is_ok()
    {
        return Err(DirectoryPublicationError::AlreadyExists);
    }
    Err(DirectoryPublicationError::Io)
}

#[cfg(windows)]
fn prepare_owned_directory_publication(
    destination: &Path,
) -> Result<OwnedDirectoryPublication, DirectoryPublicationError> {
    validate_directory_publication_absolute(destination)?;
    let destination_name = destination
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    validate_package_relative_path(Path::new(destination_name))
        .map_err(|_| DirectoryPublicationError::InvalidPath)?;
    let parent = destination
        .parent()
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    let contour = retain_directory_publication_contour(parent)?;
    verify_directory_publication_contour(&contour)?;
    let canonical_destination = contour.canonical_parent.join(destination_name);
    require_directory_publication_absent(&canonical_destination)?;

    for index in 0_u32..64 {
        let temporary = contour.canonical_parent.join(format!(
            ".{destination_name}.tmp.{}.{}",
            std::process::id(),
            index
        ));
        match std::fs::create_dir(&temporary) {
            Ok(()) => {
                let prepared = (|| {
                    validate_owned_temporary_name(&temporary, &canonical_destination)?;
                    verify_directory_publication_contour(&contour)?;
                    require_directory_publication_absent(&canonical_destination)?;
                    let source = open_movable_publication_directory(&temporary)?;
                    let source_path = final_windows_path_from_handle(&source)
                        .map_err(|_| DirectoryPublicationError::Io)?;
                    let source_identity = file_identity_from_handle(&source)
                        .map_err(|_| DirectoryPublicationError::Io)?;
                    if !windows_paths_equal(&source_path, &temporary)
                        || source_identity.volume_serial_number == 0
                        || source_identity.file_index == 0
                    {
                        return Err(DirectoryPublicationError::IdentityMismatch);
                    }
                    Ok(OwnedDirectoryPublication {
                        temporary: source_path,
                        destination: canonical_destination.clone(),
                        initial_temporary_identity: source_identity,
                        contour,
                        temporary_handle: Some(source),
                        committed: false,
                    })
                })();
                return prepared;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(DirectoryPublicationError::Io),
        }
    }
    Err(DirectoryPublicationError::Io)
}

#[cfg(windows)]
impl OwnedDirectoryPublication {
    #[allow(
        clippy::too_many_lines,
        reason = "the commit boundary and every post-commit no-overclaim discriminator stay in one auditable sequence"
    )]
    fn publish_inner<BeforeMove>(
        &mut self,
        precommit_temporary_identity: FileIdentity,
        before_move: BeforeMove,
        injected_postcommit_unknown: Option<DirectoryPublicationUnknown>,
    ) -> Result<DirectoryPublicationOutcome, DirectoryPublicationError>
    where
        BeforeMove: FnOnce(),
    {
        validate_owned_temporary_name(&self.temporary, &self.destination)?;
        if precommit_temporary_identity != self.initial_temporary_identity
            || precommit_temporary_identity.volume_serial_number == 0
            || precommit_temporary_identity.file_index == 0
        {
            return Err(DirectoryPublicationError::IdentityMismatch);
        }
        verify_directory_publication_contour(&self.contour)?;
        let canonical_parent_path = publication_path_text(&self.contour.canonical_parent)?;
        let destination_path = publication_path_text(&self.destination)?;
        let source = self
            .temporary_handle
            .as_ref()
            .ok_or(DirectoryPublicationError::IdentityMismatch)?;
        let source_path =
            final_windows_path_from_handle(source).map_err(|_| DirectoryPublicationError::Io)?;
        let source_identity =
            file_identity_from_handle(source).map_err(|_| DirectoryPublicationError::Io)?;
        if !windows_paths_equal(&source_path, &self.temporary)
            || source_identity != precommit_temporary_identity
        {
            return Err(DirectoryPublicationError::IdentityMismatch);
        }
        require_directory_publication_absent(&self.destination)?;
        verify_directory_publication_contour(&self.contour)?;
        let source_path =
            final_windows_path_from_handle(source).map_err(|_| DirectoryPublicationError::Io)?;
        let source_identity =
            file_identity_from_handle(source).map_err(|_| DirectoryPublicationError::Io)?;
        if !windows_paths_equal(&source_path, &self.temporary)
            || source_identity != precommit_temporary_identity
        {
            return Err(DirectoryPublicationError::IdentityMismatch);
        }
        before_move();
        let source = self
            .temporary_handle
            .take()
            .ok_or(DirectoryPublicationError::IdentityMismatch)?;
        move_directory_create_new_durable(&self.temporary, &self.destination)?;
        self.committed = true;

        let unknown = |reason| {
            DirectoryPublicationOutcome::CommittedUnknown(DirectoryPublicationUnknownReceipt {
                reason,
                destination_path: destination_path.clone(),
                canonical_parent_path: canonical_parent_path.clone(),
                parent_identity: self.contour.parent_identity,
                source_identity,
            })
        };
        if let Some(reason) = injected_postcommit_unknown {
            return Ok(unknown(reason));
        }
        let Ok(moved_path) = final_windows_path_from_handle(&source) else {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitReadbackUnavailable,
            ));
        };
        if !windows_paths_equal(&moved_path, &self.destination) {
            return Ok(unknown(DirectoryPublicationUnknown::PostCommitPathChanged));
        }
        let Ok(moved_identity) = file_identity_from_handle(&source) else {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitIdentityUnavailable,
            ));
        };
        if moved_identity != source_identity {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitIdentityChanged,
            ));
        }
        let Ok(observer) = open_publication_directory(&self.destination, true) else {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitReadbackUnavailable,
            ));
        };
        let Ok(observer_path) = final_windows_path_from_handle(&observer) else {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitReadbackUnavailable,
            ));
        };
        let Ok(observer_identity) = file_identity_from_handle(&observer) else {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitIdentityUnavailable,
            ));
        };
        if !windows_paths_equal(&observer_path, &self.destination) {
            return Ok(unknown(DirectoryPublicationUnknown::PostCommitPathChanged));
        }
        if observer_identity != source_identity {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitIdentityChanged,
            ));
        }
        let Ok(destination_pin) = open_publication_directory(&self.destination, false) else {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitReadbackUnavailable,
            ));
        };
        let Ok(destination_pinned_path) = final_windows_path_from_handle(&destination_pin) else {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitReadbackUnavailable,
            ));
        };
        let Ok(destination_identity) = file_identity_from_handle(&destination_pin) else {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitIdentityUnavailable,
            ));
        };
        if !windows_paths_equal(&destination_pinned_path, &self.destination) {
            return Ok(unknown(DirectoryPublicationUnknown::PostCommitPathChanged));
        }
        if destination_identity != source_identity || destination_identity != observer_identity {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitIdentityChanged,
            ));
        }
        if verify_directory_publication_contour(&self.contour).is_err() {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitIdentityChanged,
            ));
        }
        if let Some((_, _, parent)) = self.contour.entries.last() {
            // MoveFileExW WRITE_THROUGH is the durable commit boundary. Some
            // Windows filesystems reject directory FlushFileBuffers, so this
            // is best-effort reinforcement, not a second fallible commit.
            let _ = parent.sync_all();
        }
        Ok(DirectoryPublicationOutcome::Published(
            DirectoryPublicationReceipt {
                destination_path,
                canonical_parent_path,
                parent_identity: self.contour.parent_identity,
                source_identity,
                destination_identity,
            },
        ))
    }
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
        return Err(ProtectedPathError::Io);
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
    if written == 0 || usize::try_from(written).map_err(|_| ProtectedPathError::Io)? >= buffer.len()
    {
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
fn file_identity(path: &Path) -> std::io::Result<FileIdentity> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other(
            "identity target is not a regular file",
        ));
    }
    file_identity_from_handle(&file)
}

#[cfg(windows)]
fn file_identity_from_handle(file: &std::fs::File) -> std::io::Result<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is live and the output points to initialized storage.
    let ok =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &raw mut information) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(not(windows))]
fn file_identity(_path: &Path) -> std::io::Result<FileIdentity> {
    Err(std::io::Error::other("Windows identity unavailable"))
}

#[cfg(windows)]
fn acquire_owned_runtime_receipt_publication_lock(
    parent: &Path,
) -> Result<std::fs::File, PortError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let lock_path = parent.join(OWNED_RUNTIME_RECEIPT_PUBLICATION_LOCK);
    for attempt in 0..=400 {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .access_mode(legacy_protected_file_access_mode())
            // A live handle is the inter-process ownership token. No read,
            // write, or delete sharing is permitted until publication has
            // been classified through exact post-commit readback.
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        match options.open(&lock_path) {
            Ok(file) => {
                let metadata = file
                    .metadata()
                    .map_err(|_| PortError::Provider(provider_failed()))?;
                if !metadata.is_file()
                    || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    return Err(PortError::InvalidPath);
                }
                protect_opened_handle(&file, false)
                    .map_err(|_| PortError::Provider(provider_failed()))?;
                return Ok(file);
            }
            Err(error)
                if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION.cast_signed())
                    && attempt < 400 =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(PortError::Provider(provider_from_io(&error))),
        }
    }
    unreachable!("bounded publication-lock loop always returns")
}

#[cfg(windows)]
fn move_file_create_new(source: &Path, destination: &Path) -> Result<(), PortError> {
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let source_wide = wide(source);
    let destination_wide = wide(destination);
    // SAFETY: both strings are NUL-terminated and remain live for the call.
    // Omitting REPLACE_EXISTING is the atomic no-replace commit contract.
    let ok = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok != 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(code)
            if code == ERROR_ALREADY_EXISTS.cast_signed()
                || code == ERROR_FILE_EXISTS.cast_signed()
    ) || std::fs::symlink_metadata(destination).is_ok()
    {
        return Err(PortError::IdentityConflict);
    }
    Err(PortError::Provider(provider_from_io(&error)))
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
    value.strip_prefix("S-1-").is_some_and(|tail| {
        !tail.is_empty()
            && tail.len() <= 180
            && tail
                .chars()
                .all(|character| character.is_ascii_digit() || character == '-')
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

fn valid_service_sid_text(value: &str) -> bool {
    let Some(tail) = value.strip_prefix("S-1-5-80-") else {
        return false;
    };
    let parts = tail.split('-').collect::<Vec<_>>();
    parts.len() == 5
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u32>().is_ok()
        })
}

#[cfg(windows)]
fn process_token_identity(
    process: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(String, u32), WindowsAdapterError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(last_windows_adapter_error());
    }
    let result = token_identity(token);
    unsafe { CloseHandle(token) };
    result
}

/// Returns whether the current process token has enabled membership in the
/// built-in Administrators group.
///
/// This is an observation only. It does not grant authority and callers that
/// cross an administrative mutation boundary must independently require an
/// elevated token and the operation-specific typed request.
///
/// # Errors
///
/// Returns a typed adapter error when the current process token or its group
/// membership cannot be observed, or when called off Windows.
pub fn is_process_builtin_administrator() -> Result<bool, WindowsAdapterError> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        process_token_is_builtin_administrator(unsafe { GetCurrentProcess() })
    }
    #[cfg(not(windows))]
    {
        Err(WindowsAdapterError::Unavailable)
    }
}

#[cfg(windows)]
fn process_token_is_builtin_administrator(
    process: windows_sys::Win32::Foundation::HANDLE,
) -> Result<bool, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(last_windows_adapter_error());
    }
    let result = token_is_builtin_administrator(token);
    unsafe { CloseHandle(token) };
    result
}

#[cfg(windows)]
fn thread_token_is_builtin_administrator() -> Result<bool, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
    let mut token = std::ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) } == 0 {
        return Err(last_windows_adapter_error());
    }
    let result = token_is_builtin_administrator(token);
    unsafe { CloseHandle(token) };
    result
}

#[cfg(windows)]
fn token_is_builtin_administrator(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> Result<bool, WindowsAdapterError> {
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, EqualSid, GetTokenInformation, SECURITY_MAX_SID_SIZE,
        SID_AND_ATTRIBUTES, TOKEN_GROUPS, TokenGroups, WinBuiltinAdministratorsSid,
    };
    use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;
    let mut sid = [0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_bytes = u32::try_from(sid.len()).map_err(|_| WindowsAdapterError::Failed)?;
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &raw mut sid_bytes,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }

    let mut required = 0_u32;
    let _ = unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            std::ptr::null_mut(),
            0,
            &raw mut required,
        )
    };
    if required == 0 {
        return Err(last_windows_adapter_error());
    }
    let required_bytes = usize::try_from(required).map_err(|_| WindowsAdapterError::Failed)?;
    let words = required_bytes
        .checked_add(std::mem::size_of::<usize>() - 1)
        .ok_or(WindowsAdapterError::Failed)?
        / std::mem::size_of::<usize>();
    let mut buffer = vec![0_usize; words];
    if unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            buffer.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }

    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    let group_count =
        usize::try_from(groups.GroupCount).map_err(|_| WindowsAdapterError::Failed)?;
    let groups_offset = std::mem::size_of::<TOKEN_GROUPS>()
        .checked_sub(std::mem::size_of::<SID_AND_ATTRIBUTES>())
        .ok_or(WindowsAdapterError::Failed)?;
    let max_group_count = required_bytes
        .checked_sub(groups_offset)
        .ok_or(WindowsAdapterError::Failed)?
        / std::mem::size_of::<SID_AND_ATTRIBUTES>();
    if group_count > max_group_count {
        return Err(WindowsAdapterError::Failed);
    }
    let groups = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), group_count) };
    Ok(groups.iter().any(|group| {
        group.Attributes & (SE_GROUP_ENABLED as u32) != 0
            && unsafe { EqualSid(group.Sid, sid.as_ptr().cast_mut().cast()) != 0 }
    }))
}

#[cfg(windows)]
fn token_identity(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(String, u32), WindowsAdapterError> {
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_USER, TokenSessionId, TokenUser,
    };
    let mut required = 0_u32;
    let _ = unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &raw mut required)
    };
    if required == 0 {
        return Err(last_windows_adapter_error());
    }
    let required_bytes = usize::try_from(required).map_err(|_| WindowsAdapterError::Failed)?;
    let words = required_bytes
        .checked_add(std::mem::size_of::<usize>() - 1)
        .ok_or(WindowsAdapterError::Failed)?
        / std::mem::size_of::<usize>();
    let mut buffer = vec![0_usize; words];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let sid = sid_to_string(token_user.User.Sid)?;
    let mut session_id = 0_u32;
    let mut session_length =
        u32::try_from(std::mem::size_of::<u32>()).map_err(|_| WindowsAdapterError::Failed)?;
    if unsafe {
        GetTokenInformation(
            token,
            TokenSessionId,
            (&raw mut session_id).cast(),
            session_length,
            &raw mut session_length,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    Ok((sid, session_id))
}

#[cfg(windows)]
struct ImpersonationGuard {
    active: bool,
}

#[cfg(windows)]
impl ImpersonationGuard {
    fn begin(pipe: windows_sys::Win32::Foundation::HANDLE) -> Result<Self, WindowsAdapterError> {
        use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
        if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
            return Err(last_windows_adapter_error());
        }
        Ok(Self { active: true })
    }

    fn revert(mut self) -> Result<(), WindowsAdapterError> {
        if unsafe { windows_sys::Win32::Security::RevertToSelf() } == 0 {
            return Err(last_windows_adapter_error());
        }
        self.active = false;
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active && unsafe { windows_sys::Win32::Security::RevertToSelf() } == 0 {
            // Continuing a privileged server thread under an untrusted client
            // token is less safe than terminating the process. The explicit
            // `revert` path normally disarms this guard; this is its fail-stop.
            std::process::abort();
        }
    }
}

#[cfg(windows)]
fn validate_pipe_dacl(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    expected_sid: &str,
) -> Result<(), WindowsAdapterError> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, GetAce, PSECURITY_DESCRIPTOR,
    };
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || dacl.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(WindowsAdapterError::AclMismatch);
    }
    let result = (|| {
        let ace_count = unsafe { (*dacl).AceCount };
        if ace_count == 0 || ace_count > 16 {
            return Err(WindowsAdapterError::AclMismatch);
        }
        let mut expected_present = false;
        for index in 0..u32::from(ace_count) {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 || ace.is_null() {
                return Err(WindowsAdapterError::AclMismatch);
            }
            let header = unsafe { &*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
            if header.AceType != 0 {
                continue;
            }
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = (&raw const allowed.SidStart).cast_mut().cast();
            let text = sid_to_string(sid)?;
            if text == expected_sid {
                expected_present = true;
            } else if !pipe_dacl_principal_allowed(expected_sid, &text) {
                return Err(WindowsAdapterError::AclMismatch);
            }
        }
        expected_present
            .then_some(())
            .ok_or(WindowsAdapterError::AclMismatch)
    })();
    unsafe { LocalFree(descriptor.cast()) };
    result
}

fn pipe_dacl_principal_allowed(expected_sid: &str, observed_sid: &str) -> bool {
    observed_sid == "S-1-5-18"
        || observed_sid == "S-1-5-32-544"
        || (matches!(expected_sid, "S-1-5-19" | "S-1-5-32-544") && observed_sid == "S-1-5-19")
}

#[cfg(windows)]
fn dpapi_protect(secret: &[u8]) -> Result<ProtectedSecret, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };
    let input_len = u32::try_from(secret.len()).map_err(|_| WindowsAdapterError::InvalidInput)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_len,
        pbData: secret.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    if unsafe {
        CryptProtectData(
            &raw const input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(output.pbData, usize::try_from(output.cbData).unwrap_or(0))
    }
    .to_vec();
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(ProtectedSecret(bytes))
}

#[cfg(not(windows))]
fn dpapi_protect(_secret: &[u8]) -> Result<ProtectedSecret, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn dpapi_unprotect(protected: &[u8]) -> Result<CredentialSecret, WindowsAdapterError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };
    if protected.is_empty() {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(protected.len()).map_err(|_| WindowsAdapterError::InvalidInput)?,
        pbData: protected.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    if unsafe {
        CryptUnprotectData(
            &raw const input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    } == 0
    {
        return Err(last_windows_adapter_error());
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(output.pbData, usize::try_from(output.cbData).unwrap_or(0))
    }
    .to_vec();
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(CredentialSecret(bytes))
}

#[cfg(not(windows))]
fn dpapi_unprotect(_protected: &[u8]) -> Result<CredentialSecret, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
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
fn inspect_process_identity(process_id: u32) -> std::io::Result<ProcessIdentity> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // The handle is the authority for all three fields below.  A second PID
    // lookup is never used to build the durable identity.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let result = inspect_process_handle(process_id, process);
    // SAFETY: process is the live handle returned by OpenProcess.
    unsafe { CloseHandle(process) };
    result
}

#[cfg(windows)]
fn job_process_ids(job: windows_sys::Win32::Foundation::HANDLE) -> std::io::Result<Vec<u32>> {
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
fn same_windows_path(left: &str, right: &str) -> bool {
    fn normalized(value: &str) -> String {
        value
            .strip_prefix(r"\\?\")
            .unwrap_or(value)
            .replace('/', "\\")
            .to_uppercase()
    }
    normalized(left) == normalized(right)
}

#[cfg(windows)]
fn valid_process_image_path(value: &str) -> bool {
    if value.is_empty() || value.chars().any(char::is_control) {
        return false;
    }
    let normalized = value.replace('/', "\\");
    let uppercase = normalized.to_uppercase();
    if uppercase.starts_with(r"\\.\")
        || uppercase.starts_with(r"\DEVICE\")
        || uppercase.starts_with(r"\\?\GLOBALROOT\")
    {
        return false;
    }
    let bytes = normalized.as_bytes();
    let drive_absolute =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    let unc_absolute = normalized.starts_with(r"\\");
    drive_absolute || unc_absolute
}

#[cfg(not(windows))]
fn valid_process_image_path(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
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
fn inspect_process_handle(
    process_id: u32,
    process: windows_sys::Win32::Foundation::HANDLE,
) -> std::io::Result<ProcessIdentity> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, PROCESS_NAME_WIN32, QueryFullProcessImageNameW,
    };
    (|| {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: process is a live query handle and all FILETIME pointers are writable.
        let ok = unsafe {
            GetProcessTimes(
                process,
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let start_time_100ns =
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        if start_time_100ns == 0 {
            return Err(std::io::Error::other("process start time unavailable"));
        }
        let mut buffer = vec![0_u16; 32_768];
        let mut length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: buffer is writable and length is its capacity in UTF-16 units.
        let ok = unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                buffer.as_mut_ptr(),
                &raw mut length,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let image_path =
            std::ffi::OsString::from_wide(&buffer[..usize::try_from(length).unwrap_or(0)])
                .to_string_lossy()
                .into_owned();
        if image_path.is_empty() {
            return Err(std::io::Error::other("process image unavailable"));
        }
        Ok(ProcessIdentity {
            process_id,
            start_time_100ns,
            image_path,
        })
    })()
}

#[cfg(not(windows))]
fn inspect_process_identity(_process_id: u32) -> std::io::Result<ProcessIdentity> {
    Err(std::io::Error::other(
        "Windows process identity unavailable",
    ))
}

/// Observes one live process for use as a named-pipe admission binding.
///
/// The process identifier is only a lookup key. Windows opens the live
/// process and captures PID, creation time, and image path from that handle;
/// callers cannot construct the returned binding from request data.
///
/// # Errors
/// Returns a typed adapter error when the PID is invalid, the process cannot
/// be opened, or its identity cannot be observed and validated.
#[cfg(windows)]
pub fn observe_named_pipe_peer_process(
    process_id: u32,
) -> Result<NamedPipePeerProcessBinding, WindowsAdapterError> {
    if process_id == 0 {
        return Err(WindowsAdapterError::InvalidInput);
    }
    inspect_process_identity(process_id)
        .map_err(|error| windows_adapter_from_io(&error))
        .and_then(NamedPipePeerProcessBinding::from_observed)
}

#[cfg(not(windows))]
pub fn observe_named_pipe_peer_process(
    _process_id: u32,
) -> Result<NamedPipePeerProcessBinding, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

fn valid_named_job_identity(value: &str) -> bool {
    let length = value.encode_utf16().count();
    length != 0 && length <= 240 && !value.chars().any(char::is_control)
}

/// Observes one process and proves that the same PID is currently a member of
/// the named owner Job.  The returned value is sealed evidence, not a caller
/// constructed process or Job authority token.
///
/// # Errors
/// Returns a typed adapter error when the process, Job, or current membership
/// cannot be observed and validated.
#[cfg(windows)]
pub fn observe_named_pipe_peer_process_in_job(
    job_name: &str,
    process_id: u32,
) -> Result<NamedPipePeerJobBinding, WindowsAdapterError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::JobObjects::OpenJobObjectW;
    const JOB_OBJECT_QUERY_ACCESS: u32 = 0x0004;

    if process_id == 0 || !valid_named_job_identity(job_name) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    let mut wide = std::ffi::OsStr::new(job_name)
        .encode_wide()
        .collect::<Vec<_>>();
    wide.push(0);
    // SAFETY: `wide` is NUL terminated and the returned handle is owned below.
    let handle = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY_ACCESS, 0, wide.as_ptr()) };
    if handle.is_null() {
        return Err(windows_adapter_from_io(&std::io::Error::last_os_error()));
    }
    let member = job_process_ids(handle)
        .map_err(|error| windows_adapter_from_io(&error))?
        .into_iter()
        .any(|member| member == process_id);
    // SAFETY: `handle` is the live Job handle returned by OpenJobObjectW.
    unsafe { CloseHandle(handle) };
    if !member {
        return Err(WindowsAdapterError::IdentityMismatch);
    }
    let process = observe_named_pipe_peer_process(process_id)?;
    NamedPipePeerJobBinding::from_observed(process, job_name)
}

#[cfg(not(windows))]
pub fn observe_named_pipe_peer_process_in_job(
    _job_name: &str,
    _process_id: u32,
) -> Result<NamedPipePeerJobBinding, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

/// Queries the canonical `EliotHost` service and retains its live PID, process
/// creation time and image identity for subsequent named-pipe admission.
/// Request data cannot supply any of those identity fields.
///
/// # Errors
///
/// Returns a typed adapter error when the service cannot be queried, is not
/// running, or its live process identity cannot be observed.
#[cfg(windows)]
pub fn observe_running_eliot_host_process()
-> Result<NamedPipePeerProcessBinding, WindowsAdapterError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
    };
    let name = std::ffi::OsStr::new(ELIOT_HOST_SERVICE_NAME)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(last_windows_adapter_error());
    }
    let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        unsafe { CloseServiceHandle(manager) };
        return Err(last_windows_adapter_error());
    }
    let result = (|| {
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0;
        let status_bytes = u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>())
            .map_err(|_| WindowsAdapterError::Failed)?;
        if unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (&raw mut status).cast(),
                status_bytes,
                &raw mut needed,
            )
        } == 0
        {
            return Err(last_windows_adapter_error());
        }
        if status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0 {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let binding = observe_named_pipe_peer_process(status.dwProcessId)?;
        let mut confirmed_status = SERVICE_STATUS_PROCESS::default();
        let mut confirmed_needed = 0;
        if unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (&raw mut confirmed_status).cast(),
                status_bytes,
                &raw mut confirmed_needed,
            )
        } == 0
        {
            return Err(last_windows_adapter_error());
        }
        if confirmed_status.dwCurrentState != SERVICE_RUNNING
            || !service_runtime_sample_is_stable(
                status.dwCurrentState,
                status.dwProcessId,
                confirmed_status.dwCurrentState,
                confirmed_status.dwProcessId,
            )
        {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        let confirmed_binding = observe_named_pipe_peer_process(confirmed_status.dwProcessId)?;
        if confirmed_binding != binding {
            return Err(WindowsAdapterError::IdentityMismatch);
        }
        Ok(binding)
    })();
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    result
}

#[cfg(not(windows))]
pub fn observe_running_eliot_host_process()
-> Result<NamedPipePeerProcessBinding, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
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

fn valid_credential_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '/')
        })
}

const INSTALLER_CREDENTIAL_TARGET_PREFIX: &str = "eliot/installer-root/v1/";
const STORE_CREDENTIAL_TARGET_PREFIX: &str = "eliot/store/v1/";

fn installer_credential_target(value: &str) -> bool {
    value.starts_with(INSTALLER_CREDENTIAL_TARGET_PREFIX)
}

fn valid_installer_credential_target(value: &str) -> bool {
    value
        .strip_prefix(INSTALLER_CREDENTIAL_TARGET_PREFIX)
        .is_some_and(|token| {
            token.len() == 32
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

#[cfg(windows)]
fn credential_write(key: &str, secret: &[u8]) -> Result<(), WindowsAdapterError> {
    if !valid_credential_key(key) || secret.is_empty() || secret.len() > 2560 {
        return Err(WindowsAdapterError::InvalidInput);
    }
    eliot_windows_ipc::credential_write_current_user(key, secret)
        .map_err(|error| windows_adapter_from_io(&error))
}

#[cfg(not(windows))]
fn credential_write(_key: &str, _secret: &[u8]) -> Result<(), WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn credential_read(key: &str) -> Result<CredentialSecret, WindowsAdapterError> {
    if !valid_credential_key(key) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    match eliot_windows_ipc::credential_read_current_user(key)
        .map_err(|error| windows_adapter_from_io(&error))?
    {
        Some(value) => Ok(CredentialSecret(value)),
        None => Err(WindowsAdapterError::Unavailable),
    }
}

#[cfg(windows)]
fn credential_read_optional(key: &str) -> Result<Option<CredentialSecret>, WindowsAdapterError> {
    if !valid_credential_key(key) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    eliot_windows_ipc::credential_read_current_user(key)
        .map(|secret| secret.map(CredentialSecret))
        .map_err(|error| windows_adapter_from_io(&error))
}

#[cfg(not(windows))]
fn credential_read_optional(_key: &str) -> Result<Option<CredentialSecret>, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(not(windows))]
fn credential_read(_key: &str) -> Result<CredentialSecret, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn credential_delete(key: &str) -> Result<(), WindowsAdapterError> {
    if !valid_credential_key(key) {
        return Err(WindowsAdapterError::InvalidInput);
    }
    if eliot_windows_ipc::credential_delete_current_user(key)
        .map_err(|error| windows_adapter_from_io(&error))?
    {
        Ok(())
    } else {
        Err(WindowsAdapterError::Unavailable)
    }
}

#[cfg(not(windows))]
fn credential_delete(_key: &str) -> Result<(), WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
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
mod tests {
    use super::*;

    #[cfg(windows)]
    static PROCESS_JOB_SPAWN_TEST_LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();

    #[cfg(windows)]
    fn process_job_spawn_test_guard() -> std::sync::MutexGuard<'static, ()> {
        PROCESS_JOB_SPAWN_TEST_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(windows)]
    fn test_lease(
        root: &Path,
        relative: &Path,
        create: bool,
    ) -> Result<ProtectedPathLease, ProtectedPathError> {
        let components = protected_components(relative)?;
        let parent = components[..components.len() - 1].iter().fold(
            PathBuf::new(),
            |mut path, component| {
                path.push(component);
                path
            },
        );
        let mut current = root.to_path_buf();
        let mut directories = vec![pin_directory(root).map_err(|_| ProtectedPathError::Io)?];
        for component in parent.components() {
            current.push(component.as_os_str());
            let directory = match pin_directory(&current) {
                Ok(directory) => directory,
                Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::create_dir(&current).map_err(|_| ProtectedPathError::Io)?;
                    pin_directory(&current).map_err(|_| ProtectedPathError::Io)?
                }
                Err(_) => return Err(ProtectedPathError::Io),
            };
            directories.push(directory);
        }
        let file_path = root.join(relative);
        let file = open_protected_file(&file_path, create)?;
        let identity = file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)?;
        Ok(ProtectedPathLease {
            path: file_path,
            identity,
            _directories: directories,
            file,
        })
    }

    #[cfg(windows)]
    fn test_root_lease(
        root: &Path,
        relative: &Path,
    ) -> Result<ProtectedRootLease, ProtectedPathError> {
        let mut current = root.to_path_buf();
        let mut directories = vec![pin_directory(root).map_err(|_| ProtectedPathError::Io)?];
        for component in relative.components() {
            current.push(component.as_os_str());
            directories.push(pin_directory(&current).map_err(|_| ProtectedPathError::Io)?);
        }
        let retained = directories.last().ok_or(ProtectedPathError::InvalidPath)?;
        let identity = file_identity_from_handle(retained).map_err(|_| ProtectedPathError::Io)?;
        Ok(ProtectedRootLease {
            path: current,
            identity,
            directories,
        })
    }

    #[cfg(windows)]
    fn directory_security_descriptor_bytes(path: &Path) -> Vec<u8> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
        use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorLength, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        };

        let handle = pin_directory(path).unwrap_or_else(|error| panic!("directory open: {error}"));
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = unsafe {
            // SAFETY: retained handle is live and descriptor output is a valid local.
            GetSecurityInfo(
                handle.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        assert!(!descriptor.is_null());
        let length = unsafe {
            // SAFETY: descriptor was returned by GetSecurityInfo and is live.
            GetSecurityDescriptorLength(descriptor)
        };
        let length = usize::try_from(length).unwrap_or_else(|_| unreachable!());
        let bytes = unsafe {
            // SAFETY: the reported descriptor length bounds this copied slice.
            std::slice::from_raw_parts(descriptor.cast::<u8>(), length).to_vec()
        };
        unsafe {
            // SAFETY: descriptor is released exactly once after copying.
            LocalFree(descriptor.cast());
        }
        bytes
    }

    #[test]
    fn rejects_relative_and_reparse_roots() {
        assert!(validate_root(Path::new("relative")).is_err());
    }

    #[test]
    fn atomic_suffix_is_nonempty_and_not_secret_derived() {
        assert!(!unique_suffix().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn activation_nonce_has_256_bit_lowercase_hex_shape() {
        let nonce =
            fresh_activation_nonce().unwrap_or_else(|error| panic!("nonce failed: {error}"));
        let value = nonce.as_str();
        assert!(value.starts_with(ACTIVATION_NONCE_PREFIX));
        assert_eq!(
            value.len(),
            ACTIVATION_NONCE_PREFIX.len() + ACTIVATION_NONCE_HEX_BYTES
        );
        assert_eq!(ACTIVATION_NONCE_RANDOM_BYTES * 8, 256);
        assert!(
            value[ACTIVATION_NONCE_PREFIX.len()..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }

    #[cfg(windows)]
    #[test]
    fn activation_nonce_material_is_exact_canonical_64_hex() {
        let first = fresh_activation_nonce_material()
            .unwrap_or_else(|error| panic!("raw nonce failed: {error}"));
        let second = fresh_activation_nonce_material()
            .unwrap_or_else(|error| panic!("raw nonce failed: {error}"));
        assert_eq!(first.as_str().len(), 64);
        assert!(
            first
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_ne!(first, second);
    }

    #[cfg(windows)]
    #[test]
    fn typed_activation_nonce_has_canonical_shape_and_redacted_formatting() {
        let nonce = fresh_kernel_activation_nonce()
            .unwrap_or_else(|error| panic!("typed nonce failed: {error}"));
        let material = nonce.as_handle().as_str();
        assert_eq!(material.len(), 64);
        assert!(
            material
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );

        let debug = format!("{nonce:?}");
        let display = format!("{nonce}");
        assert_eq!(debug, "KernelActivationNonce(<redacted>)");
        assert_eq!(display, "<redacted>");
        assert!(!debug.contains(material));
        assert!(!display.contains(material));
    }

    #[cfg(windows)]
    #[test]
    fn final_handle_paths_drop_verbatim_prefixes_before_contract_comparison() {
        assert_eq!(
            normalize_final_windows_path_text(r"\\?\C:\ProgramData\Eliot")
                .unwrap_or_else(|error| panic!("DOS path normalization failed: {error}")),
            PathBuf::from(r"C:\ProgramData\Eliot")
        );
        assert_eq!(
            normalize_final_windows_path_text(r"\\?\UNC\server\share\Eliot")
                .unwrap_or_else(|error| panic!("UNC path normalization failed: {error}")),
            PathBuf::from(r"\\server\share\Eliot")
        );

        let directory = std::env::temp_dir().join("eliot-canonical-contract-path-test");
        std::fs::create_dir_all(&directory)
            .unwrap_or_else(|error| panic!("fixture creation failed: {error}"));
        let canonical = canonical_windows_path(&directory)
            .unwrap_or_else(|error| panic!("canonicalization failed: {error}"));
        assert!(canonical.is_absolute());
        assert!(!canonical.to_string_lossy().starts_with(r"\\?\"));
    }

    #[cfg(windows)]
    #[test]
    fn known_folder_anchors_ignore_environment_substitution() {
        let original_program_data = std::env::var_os("ProgramData");
        let original_local_app_data = std::env::var_os("LOCALAPPDATA");
        unsafe {
            // SAFETY: the values are restored before assertions or panics.
            std::env::set_var("ProgramData", r"C:\attacker-selected-program-data");
            std::env::set_var("LOCALAPPDATA", r"C:\attacker-selected-local-app-data");
        }
        let observed_program_data = protected_program_data_root();
        let observed_local_app_data = current_user_local_app_data_root();
        unsafe {
            // SAFETY: restore this process's exact pre-test environment state.
            match original_program_data {
                Some(value) => std::env::set_var("ProgramData", value),
                None => std::env::remove_var("ProgramData"),
            }
            match original_local_app_data {
                Some(value) => std::env::set_var("LOCALAPPDATA", value),
                None => std::env::remove_var("LOCALAPPDATA"),
            }
        }
        let observed_program_data = observed_program_data
            .unwrap_or_else(|error| panic!("ProgramData known-folder lookup failed: {error}"));
        let observed_local_app_data = observed_local_app_data
            .unwrap_or_else(|error| panic!("LocalAppData known-folder lookup failed: {error}"));
        assert_ne!(
            observed_program_data,
            PathBuf::from(r"C:\attacker-selected-program-data")
        );
        assert_ne!(
            observed_local_app_data,
            PathBuf::from(r"C:\attacker-selected-local-app-data")
        );
    }

    #[cfg(windows)]
    #[test]
    fn sequential_activation_nonces_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let nonce = fresh_activation_nonce()
                .unwrap_or_else(|error| panic!("nonce issuance failed: {error}"));
            assert!(seen.insert(nonce.as_str().to_owned()));
        }
    }

    #[cfg(windows)]
    #[test]
    fn store_targets_have_exact_shape_and_distinctness() {
        let generator = WindowsStoreCredentialTargetGenerator::new();
        let installer = WindowsInstallerSecretProvider::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let target = generator
                .fresh_target()
                .unwrap_or_else(|error| panic!("Store target issuance failed: {error}"));
            assert!(target.as_str().starts_with(STORE_CREDENTIAL_TARGET_PREFIX));
            let token = target
                .as_str()
                .strip_prefix(STORE_CREDENTIAL_TARGET_PREFIX)
                .unwrap_or_else(|| unreachable!());
            assert_eq!(token.len(), 32);
            assert!(
                token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
            assert!(seen.insert(target.as_str().to_owned()));
        }

        let installer_target = installer
            .fresh_reference()
            .unwrap_or_else(|error| panic!("installer target issuance failed: {error}"));
        assert!(
            installer_target
                .as_str()
                .starts_with(INSTALLER_CREDENTIAL_TARGET_PREFIX)
        );
        assert_ne!(
            installer_target.as_str(),
            generator
                .fresh_target()
                .unwrap_or_else(|error| panic!("Store target issuance failed: {error}"))
                .as_str()
        );
        let activation_target = fresh_activation_nonce()
            .unwrap_or_else(|error| panic!("activation target issuance failed: {error}"));
        assert!(activation_target.as_str().starts_with("eliot-activation-"));
        assert_ne!(
            activation_target.as_str(),
            generator
                .fresh_target()
                .unwrap_or_else(|error| panic!("Store target issuance failed: {error}"))
                .as_str()
        );
    }

    #[test]
    fn rejects_component_traversal_and_control() {
        assert!(validate_component("../outside").is_err());
        assert!(validate_component("state\0.bin").is_err());
        assert!(valid_credential_key("nested/ok-key"));
        assert!(!valid_credential_key("../outside"));
        assert!(installer_credential_target(
            "eliot/installer-root/v1/0123456789abcdef"
        ));
        assert!(valid_installer_credential_target(
            "eliot/installer-root/v1/0123456789abcdef0123456789abcdef"
        ));
        assert!(!valid_installer_credential_target(
            "eliot/installer-root/v1/0123456789ABCDEF0123456789ABCDEF"
        ));
        assert!(!valid_installer_credential_target(
            "eliot/installer-root/v1/short"
        ));
        assert!(!installer_credential_target("runtime/dispatch-key"));
    }

    #[test]
    fn free_space_observation_rejects_relative_path_as_unknown_input() {
        assert_eq!(
            observe_volume_free_space(Path::new("relative")),
            Err(WindowsAdapterError::InvalidInput)
        );
    }

    #[cfg(windows)]
    #[test]
    fn free_space_observation_reads_real_current_volume() {
        let current = std::env::current_dir().unwrap_or_else(|_| unreachable!());
        let available = observe_volume_free_space(&current)
            .unwrap_or_else(|error| panic!("free-space observation failed: {error}"));
        assert!(available > 0);
    }

    #[test]
    fn protected_program_data_path_rejects_substitution_inputs() {
        assert_eq!(
            protected_program_data_path(Path::new("../outside")),
            Err(ProtectedPathError::InvalidPath)
        );
        assert_eq!(
            protected_program_data_path(Path::new("C:/outside")),
            Err(ProtectedPathError::InvalidPath)
        );
    }

    #[cfg(windows)]
    #[test]
    fn retained_process_lease_rejects_identity_or_digest_substitution() {
        let root = std::env::temp_dir().join(format!("eliot-process-lease-{}", unique_suffix()));
        let working = root.join("work");
        let executable = root.join("worker.bin");
        std::fs::create_dir_all(&working).expect("working directory");
        let original = b"original executable bytes";
        std::fs::write(&executable, original).expect("executable");
        let platform = WindowsPlatform::new(&root).expect("platform");
        let digest = sha256_hex(original);
        let lease = platform
            .retain_process_path_lease(&executable, &working, &digest)
            .expect("retained launch lease");

        assert!(std::fs::write(&executable, b"substituted executable bytes").is_err());
        assert!(lease.validate(&executable, &working, &digest).is_ok());
        assert!(
            lease
                .validate(
                    &executable,
                    &working,
                    &sha256_hex(b"substituted executable bytes")
                )
                .is_err()
        );
        assert!(
            lease
                .validate(&executable, &root.join("other"), &digest)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn permission_denied_is_explicit_and_not_retryable() {
        let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let provider = provider_from_io(&error);
        assert_eq!(
            provider.code,
            eliot_platform::ProviderErrorCode::PermissionDenied
        );
        assert!(!provider.retryable);
    }

    #[test]
    fn containment_is_component_wise_not_prefix_wise() {
        let root = Path::new("C:/work/root");
        assert!(validate_containment(root, Path::new("C:/work/root/file")).is_ok());
        assert!(validate_containment(root, Path::new("C:/work/root-sibling/file")).is_err());
    }

    #[test]
    fn wrong_session_is_not_observed() {
        assert!(!session_matches(7, 8));
        assert!(session_matches(7, 7));
    }

    #[test]
    fn notification_text_is_bounded_and_nul_terminated() {
        let mut buffer = [0_u16; 8];
        fill_utf16(&mut buffer, "Eliot notification text");
        assert_eq!(buffer[7], 0);
        assert_eq!(String::from_utf16_lossy(&buffer[..7]), "Eliot n");
    }

    #[cfg(windows)]
    #[test]
    fn watchdog_task_readback_rejects_structural_substitution() {
        let registration = WatchdogTaskRegistration::new(
            WATCHDOG_FALLBACK_TASK_NAME,
            r"C:\Eliot\eliot-notify.exe",
            r"C:\ProgramData\Eliot\watchdog-verifier.json",
            r"C:\ProgramData\Eliot\watchdog-envelope.json",
            "S-1-5-21-1",
            7,
            "00".repeat(32),
            "11".repeat(32),
        )
        .unwrap_or_else(|_| unreachable!());
        let xml = watchdog_task_xml(&registration);
        assert!(watchdog_task_readback_matches(&registration, &xml));

        let extra_action = xml.replace(
            "</Actions>",
            "<Exec><Command>evil.exe</Command></Exec></Actions>",
        );
        assert!(!watchdog_task_readback_matches(
            &registration,
            &extra_action
        ));

        let extra_trigger = xml.replace(
            "</Triggers>",
            "<TimeTrigger><Enabled>true</Enabled></TimeTrigger></Triggers>",
        );
        assert!(!watchdog_task_readback_matches(
            &registration,
            &extra_trigger
        ));

        let extra_principal = xml.replace(
            "</Principals>",
            "<Principal id=\"Substitute\"><UserId>S-1-5-21-9</UserId></Principal></Principals>",
        );
        assert!(!watchdog_task_readback_matches(
            &registration,
            &extra_principal
        ));

        let extra_setting = xml.replace(
            "</Settings>",
            "<UnknownSetting>true</UnknownSetting></Settings>",
        );
        assert!(!watchdog_task_readback_matches(
            &registration,
            &extra_setting
        ));

        let changed_action = xml.replace(
            "<Arguments>--watchdog-fallback</Arguments>",
            "<Arguments>--changed</Arguments>",
        );
        assert!(!watchdog_task_readback_matches(
            &registration,
            &changed_action
        ));
    }

    #[test]
    fn post_commit_identity_failure_is_typed_unknown() {
        let unknown = PublicationUnknownReceipt {
            reason: PublicationUnknown::PostCommitIdentityUnavailable,
            expected_identity: FileIdentity {
                volume_serial_number: 1,
                file_index: 2,
            },
        };
        assert_eq!(
            PublicationOutcome::Unknown(unknown.clone()),
            PublicationOutcome::Unknown(unknown)
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_support_unknown_publication_retains_exact_reopen_identity() {
        let root = std::env::temp_dir().join(format!(
            "eliot-platform-receipt-root-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::create_dir_all(&root).expect("test root");
        let root_override = test_support::override_protected_root(&root);
        let host = root.join("host");
        prepare_protected_directory(&host).expect("protected host root");
        let path = host.join("eliotd-receipt.json");
        test_support::force_next_owned_runtime_receipt_unknown();
        let PublicationOutcome::Unknown(unknown) =
            publish_atomic_owned_runtime_receipt(&path, b"receipt", None).expect("publication")
        else {
            panic!("failpoint must preserve unknown outcome");
        };
        let lease = ProtectedRuntimePathLease::open_existing_absolute(&path)
            .expect("exact post-commit lease");
        assert_eq!(lease.identity(), unknown.expected_identity);
        assert_eq!(lease.read_bounded(64).expect("readback"), b"receipt");
        drop(lease);
        drop(root_override);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn production_owned_receipt_publication_enforces_identity_and_content_fence() {
        let root = std::env::temp_dir().join(format!(
            "eliot-platform-receipt-cas-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::create_dir_all(&root).expect("test root");
        let root_override = test_support::override_protected_root(&root);
        let host = root.join("host");
        prepare_protected_directory(&host).expect("protected host root");
        let path = host.join("eliotd-receipt.json");

        let PublicationOutcome::Published(first) =
            publish_atomic_owned_runtime_receipt(&path, b"receipt-v1", None).expect("first")
        else {
            panic!("first publication must be classified");
        };
        let first_lease =
            ProtectedRuntimePathLease::open_existing_absolute(&path).expect("first receipt lease");
        assert_eq!(first_lease.identity(), first.identity);
        let first_bytes = first_lease.read_bounded(64).expect("first readback");
        let precondition = PublicationPrecondition::from_bytes(first.identity, &first_bytes);
        drop(first_lease);

        let PublicationOutcome::Published(second) =
            publish_atomic_owned_runtime_receipt(&path, b"receipt-v2", Some(&precondition))
                .expect("compare-and-swap publication")
        else {
            panic!("compare-and-swap publication must be classified");
        };
        assert_ne!(second.identity, first.identity);
        let second_lease =
            ProtectedRuntimePathLease::open_existing_absolute(&path).expect("second receipt lease");
        assert_eq!(second_lease.identity(), second.identity);
        assert_eq!(
            second_lease.read_bounded(64).expect("second readback"),
            b"receipt-v2"
        );
        drop(second_lease);

        assert_eq!(
            publish_atomic_owned_runtime_receipt(&path, b"receipt-v3", Some(&precondition))
                .expect_err("stale compare-and-swap must fail closed"),
            PortError::IdentityConflict
        );
        let final_lease =
            ProtectedRuntimePathLease::open_existing_absolute(&path).expect("final receipt lease");
        assert_eq!(
            final_lease.read_bounded(64).expect("final readback"),
            b"receipt-v2"
        );
        drop(final_lease);
        drop(root_override);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn concurrent_owned_receipt_create_is_atomic_no_replace() {
        let root = std::env::temp_dir().join(format!(
            "eliot-platform-receipt-create-race-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::create_dir_all(&root).expect("test root");
        let root_override = test_support::override_protected_root(&root);
        let host = root.join("host");
        prepare_protected_directory(&host).expect("protected host root");
        drop(root_override);

        let path = host.join("eliotd-receipt.json");
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for bytes in [b"create-race-a".as_slice(), b"create-race-b".as_slice()] {
            let root = root.clone();
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            let bytes = bytes.to_vec();
            threads.push(std::thread::spawn(move || {
                let _root_override = test_support::override_protected_root(&root);
                barrier.wait();
                let outcome = publish_atomic_owned_runtime_receipt(&path, &bytes, None);
                (bytes, outcome)
            }));
        }
        barrier.wait();

        let mut published = 0;
        let mut conflicts = 0;
        let mut published_bytes = None;
        for thread in threads {
            let (bytes, outcome) = thread.join().expect("publisher thread");
            match outcome {
                Ok(PublicationOutcome::Published(_)) => {
                    published += 1;
                    published_bytes = Some(bytes);
                }
                Err(PortError::IdentityConflict) => conflicts += 1,
                other => panic!("unexpected create-race outcome: {other:?}"),
            }
        }
        assert_eq!(published, 1);
        assert_eq!(conflicts, 1);
        assert_eq!(
            std::fs::read(&path).expect("committed receipt"),
            published_bytes.expect("one published value")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn concurrent_owned_receipt_substitution_preserves_exact_predecessor_cas() {
        let root = std::env::temp_dir().join(format!(
            "eliot-platform-receipt-replace-race-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        std::fs::create_dir_all(&root).expect("test root");
        let root_override = test_support::override_protected_root(&root);
        let host = root.join("host");
        prepare_protected_directory(&host).expect("protected host root");
        let path = host.join("eliotd-receipt.json");
        let PublicationOutcome::Published(initial) =
            publish_atomic_owned_runtime_receipt(&path, b"predecessor", None)
                .expect("initial publication")
        else {
            panic!("initial publication must be known");
        };
        let initial_lease =
            ProtectedRuntimePathLease::open_existing_absolute(&path).expect("initial lease");
        let initial_bytes = initial_lease.read_bounded(64).expect("initial bytes");
        let precondition = PublicationPrecondition::from_bytes(initial.identity, &initial_bytes);
        drop(initial_lease);
        drop(root_override);

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for bytes in [b"replace-race-a".as_slice(), b"replace-race-b".as_slice()] {
            let root = root.clone();
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            let precondition = precondition.clone();
            let bytes = bytes.to_vec();
            threads.push(std::thread::spawn(move || {
                let _root_override = test_support::override_protected_root(&root);
                barrier.wait();
                let outcome =
                    publish_atomic_owned_runtime_receipt(&path, &bytes, Some(&precondition));
                (bytes, outcome)
            }));
        }
        barrier.wait();

        let mut published = 0;
        let mut conflicts = 0;
        let mut published_bytes = None;
        for thread in threads {
            let (bytes, outcome) = thread.join().expect("publisher thread");
            match outcome {
                Ok(PublicationOutcome::Published(_)) => {
                    published += 1;
                    published_bytes = Some(bytes);
                }
                Err(PortError::IdentityConflict) => conflicts += 1,
                other => panic!("unexpected replacement-race outcome: {other:?}"),
            }
        }
        assert_eq!(published, 1);
        assert_eq!(conflicts, 1);
        assert_eq!(
            std::fs::read(&path).expect("committed receipt"),
            published_bytes.expect("one published value")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn durable_identity_types_reject_unknown_fields() {
        let result = serde_json::from_str::<FileIdentity>(
            r#"{"volume_serial_number":1,"file_index":2,"extra":3}"#,
        );
        assert!(result.is_err());
        let result = serde_json::from_str::<ProcessIdentity>(
            r#"{"process_id":1,"start_time_100ns":2,"image_path":"x","extra":3}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn unsupported_secret_provider_never_routes_to_credential_manager() {
        assert!(!is_windows_secret_provider("arbitrary-provider"));
        assert!(is_windows_secret_provider("windows-credential-manager"));
    }

    #[test]
    fn pipe_expectation_rejects_caller_shaped_non_sid_values() {
        assert_eq!(
            NamedPipePeerExpectation::new("current-user", 1),
            Err(WindowsAdapterError::InvalidInput)
        );
    }

    #[test]
    fn named_pipe_expectations_select_ordinary_or_admin_auth_discriminator() {
        let ordinary =
            NamedPipePeerExpectation::new("S-1-5-19", 1).unwrap_or_else(|_| unreachable!());
        let admin = NamedPipePeerExpectation::new_for_builtin_administrators()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            ordinary.auth_discriminator(),
            NamedPipeAuthDiscriminator::Ordinary
        );
        assert_eq!(
            admin.auth_discriminator(),
            NamedPipeAuthDiscriminator::BuiltinAdministrators
        );
    }

    #[cfg(windows)]
    #[test]
    fn current_process_builtin_administrator_membership_is_read_only_observable() {
        assert!(is_process_builtin_administrator().is_ok());
    }

    #[test]
    fn installer_control_pipe_dacl_allows_only_system_admin_and_local_service() {
        for expected in ["S-1-5-19", "S-1-5-32-544"] {
            for observed in ["S-1-5-18", "S-1-5-32-544", "S-1-5-19"] {
                assert!(pipe_dacl_principal_allowed(expected, observed));
            }
            assert!(!pipe_dacl_principal_allowed(expected, "S-1-5-20"));
            assert!(!pipe_dacl_principal_allowed(expected, "S-1-5-21-1000"));
        }
        assert!(!pipe_dacl_principal_allowed("S-1-5-21-1000", "S-1-5-19"));
    }

    #[cfg(windows)]
    fn test_process_binding() -> NamedPipePeerProcessBinding {
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;

        observe_named_pipe_peer_process(unsafe { GetCurrentProcessId() })
            .unwrap_or_else(|_| unreachable!())
    }

    #[cfg(windows)]
    fn test_process_expectation(binding: NamedPipePeerProcessBinding) -> NamedPipePeerExpectation {
        current_process_named_pipe_expectation()
            .unwrap_or_else(|_| unreachable!())
            .with_process_binding(binding)
            .unwrap_or_else(|_| unreachable!())
    }

    #[cfg(windows)]
    #[test]
    fn pipe_expectation_admits_only_sealed_live_process_binding() {
        let binding = test_process_binding();
        let observed = binding.identity().clone();
        let expectation = test_process_expectation(binding.clone());
        assert_eq!(expectation.approved_process_binding(), Some(&binding));
        assert_eq!(
            admit_named_pipe_peer_process(&observed, &expectation),
            Ok(())
        );
    }

    #[cfg(windows)]
    #[test]
    fn pipe_job_binding_rejects_process_substitution_and_stale_job() {
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;

        let process = test_process_binding();
        let job =
            observe_named_pipe_peer_process_in_job(r"Local\Eliot-Missing-Store-Job", unsafe {
                GetCurrentProcessId()
            });
        assert!(job.is_err());

        let sealed = NamedPipePeerJobBinding::from_observed(
            process.clone(),
            r"Local\Eliot-Missing-Store-Job",
        )
        .unwrap_or_else(|_| unreachable!());
        let expectation = current_process_named_pipe_expectation()
            .unwrap_or_else(|_| unreachable!())
            .with_process_and_job_binding(sealed)
            .unwrap_or_else(|_| unreachable!());
        let mut wrong_start = process.identity().clone();
        wrong_start.start_time_100ns = wrong_start.start_time_100ns.saturating_add(1);
        assert_eq!(
            admit_named_pipe_peer_process(&wrong_start, &expectation),
            Err(WindowsAdapterError::IdentityMismatch)
        );
        assert!(admit_named_pipe_peer_process(process.identity(), &expectation).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn pipe_expectation_rejects_wrong_pid() {
        let binding = test_process_binding();
        let approved = binding.identity().clone();
        let observed = ProcessIdentity {
            process_id: approved.process_id + 1,
            ..approved.clone()
        };
        let expectation = test_process_expectation(binding);
        assert_eq!(
            admit_named_pipe_peer_process(&observed, &expectation),
            Err(WindowsAdapterError::IdentityMismatch)
        );
    }

    #[cfg(windows)]
    #[test]
    fn pipe_expectation_rejects_pid_reuse_by_start_time() {
        let binding = test_process_binding();
        let approved = binding.identity().clone();
        let observed = ProcessIdentity {
            start_time_100ns: approved.start_time_100ns + 1,
            ..approved.clone()
        };
        let expectation = test_process_expectation(binding);
        assert_eq!(
            admit_named_pipe_peer_process(&observed, &expectation),
            Err(WindowsAdapterError::IdentityMismatch)
        );
    }

    #[cfg(windows)]
    #[test]
    fn pipe_expectation_rejects_wrong_image_identity() {
        let binding = test_process_binding();
        let approved = binding.identity().clone();
        let observed = ProcessIdentity {
            image_path: r"C:\Windows\System32\other.exe".to_owned(),
            ..approved.clone()
        };
        let expectation = test_process_expectation(binding);
        assert_eq!(
            admit_named_pipe_peer_process(&observed, &expectation),
            Err(WindowsAdapterError::IdentityMismatch)
        );
    }

    #[cfg(windows)]
    #[test]
    fn pipe_identity_accepts_only_equivalent_normalized_windows_paths() {
        let binding = test_process_binding();
        let approved = binding.identity().clone();
        let expectation = test_process_expectation(binding);
        for image_path in [
            approved.image_path.to_ascii_lowercase(),
            approved.image_path.replace('\\', "/"),
        ] {
            let observed = ProcessIdentity {
                image_path,
                ..approved.clone()
            };
            assert!(same_process_identity(&observed, &approved));
            assert_eq!(
                admit_named_pipe_peer_process(&observed, &expectation),
                Ok(())
            );
        }
        if approved.image_path.as_bytes().get(1) == Some(&b':') {
            let observed = ProcessIdentity {
                image_path: format!(r"\\?\{}", approved.image_path),
                ..approved.clone()
            };
            assert!(same_process_identity(&observed, &approved));
        }
    }

    #[cfg(windows)]
    #[test]
    fn pipe_identity_rejects_malformed_image_paths() {
        let binding = test_process_binding();
        let approved = binding.identity().clone();
        let expectation = test_process_expectation(binding);
        for image_path in ["relative.exe", r"\\.\C:\Windows\System32\device.exe"] {
            let observed = ProcessIdentity {
                image_path: image_path.to_owned(),
                ..approved.clone()
            };
            assert_eq!(
                admit_named_pipe_peer_process(&observed, &expectation),
                Err(WindowsAdapterError::IdentityMismatch)
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn pipe_expectation_preserves_sid_session_only_legacy_behavior() {
        let expectation =
            current_process_named_pipe_expectation().unwrap_or_else(|_| unreachable!());
        let observed = test_process_binding().identity().clone();
        assert!(expectation.approved_process_binding().is_none());
        assert_eq!(
            admit_named_pipe_peer_process(&observed, &expectation),
            Ok(())
        );
    }

    #[test]
    fn service_registration_request_rejects_untrusted_shape() {
        let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
        assert_eq!(
            ServiceRegistrationRequest::new(
                "bad/service",
                "ELIOT test",
                &image,
                ServiceStartMode::Demand,
                ServiceAccount::LocalSystem,
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            ServiceRegistrationRequest::new(
                "EliotTest",
                "\n",
                &image,
                ServiceStartMode::Demand,
                ServiceAccount::LocalSystem,
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            ServiceRegistrationRequest::new(
                "EliotTest",
                "ELIOT test",
                PathBuf::from("relative.exe"),
                ServiceStartMode::Demand,
                ServiceAccount::LocalSystem,
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
    }

    #[test]
    fn service_registration_plan_accepts_local_service_account() {
        let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
        let request = ServiceRegistrationRequest::new(
            ELIOT_HOST_SERVICE_NAME,
            "Eliot Host",
            image,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        )
        .unwrap_or_else(|error| panic!("LocalService plan failed: {error}"));
        assert_eq!(request.account(), ServiceAccount::LocalService);
        assert_eq!(request.service_sid_type(), ServiceSidType::Unrestricted);

        let watchdog = ServiceRegistrationRequest::new(
            ELIOT_WATCHDOG_SERVICE_NAME,
            ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing")),
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        )
        .unwrap_or_else(|error| panic!("Watchdog LocalService plan failed: {error}"));
        assert_eq!(watchdog.service_sid_type(), ServiceSidType::None);
        assert!(!request.requires_host_service_control_grant());
        assert!(watchdog.requires_host_service_control_grant());
    }

    #[test]
    fn watchdog_host_control_grant_rejects_rights_escalation_and_shape_substitution() {
        let required = 0x0000_0001 | 0x0000_0004 | 0x0000_0010 | 0x0000_0020 | 0x0002_0000;
        let forbidden = 0x0000_0002 | 0x0000_0040 | 0x0000_0100 | 0x0001_0000 | 0x000C_0000;
        assert_eq!(ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK, required);
        assert_eq!(ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK & forbidden, 0);

        let descriptor_digest = watchdog_service_security_descriptor_digest("S-1-5-80-1-2-3-4-5")
            .unwrap_or_else(|error| panic!("descriptor digest failed: {error}"));
        let receipt = ServiceControlGrantReadback::new(
            ELIOT_HOST_SERVICE_NAME,
            "S-1-5-80-1-2-3-4-5",
            ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
            descriptor_digest.clone(),
        )
        .unwrap_or_else(|error| panic!("grant receipt failed: {error}"));
        assert!(receipt.validate().is_ok());
        for (principal, sid, mask, digest) in [
            (
                ELIOT_WATCHDOG_SERVICE_NAME,
                "S-1-5-80-1-2-3-4-5",
                ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
                descriptor_digest.clone(),
            ),
            (
                ELIOT_HOST_SERVICE_NAME,
                "S-1-5-80-1-2-3-4",
                ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
                descriptor_digest.clone(),
            ),
            (
                ELIOT_HOST_SERVICE_NAME,
                "S-1-5-80-1-2-3-4-5",
                ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK | 0x0004_0000,
                descriptor_digest,
            ),
            (
                ELIOT_HOST_SERVICE_NAME,
                "S-1-5-80-1-2-3-4-5",
                ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
                "not-a-digest".to_owned(),
            ),
        ] {
            assert!(ServiceControlGrantReadback::new(principal, sid, mask, digest).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn watchdog_installer_mutation_handle_retains_exact_dacl_readback_authority() {
        use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};
        use windows_sys::Win32::System::Services::{
            SERVICE_CHANGE_CONFIG, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
        };

        let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
        let host = ServiceRegistrationRequest::new(
            ELIOT_HOST_SERVICE_NAME,
            ELIOT_HOST_SERVICE_DISPLAY_NAME,
            image.clone(),
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        )
        .unwrap_or_else(|error| panic!("Host request failed: {error}"));
        let watchdog = ServiceRegistrationRequest::new(
            ELIOT_WATCHDOG_SERVICE_NAME,
            ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
            image,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        )
        .unwrap_or_else(|error| panic!("Watchdog request failed: {error}"));

        let readback = SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL;
        let host_access = service_registration_mutation_access(&host);
        assert_eq!(host_access & readback, readback);
        assert_ne!(host_access & SERVICE_CHANGE_CONFIG, 0);
        assert_eq!(host_access & WRITE_DAC, 0);

        let watchdog_access = service_registration_mutation_access(&watchdog);
        assert_eq!(watchdog_access & readback, readback);
        assert_ne!(watchdog_access & SERVICE_CHANGE_CONFIG, 0);
        assert_eq!(watchdog_access & WRITE_DAC, WRITE_DAC);
    }

    #[cfg(windows)]
    #[test]
    fn watchdog_service_dacl_is_protected_exact_and_sid_bound_without_scm_mutation() {
        use windows_sys::Win32::Security::{ACCESS_ALLOWED_ACE, GetAce};
        use windows_sys::Win32::System::Services::SERVICE_ALL_ACCESS;

        let host_sid = "S-1-5-80-1-2-3-4-5";
        let descriptor = OwnedSecurityDescriptor::for_watchdog_host_control(host_sid)
            .unwrap_or_else(|error| panic!("descriptor failed: {error}"));
        let dacl = descriptor
            .dacl()
            .unwrap_or_else(|error| panic!("DACL failed: {error}"));
        assert_eq!(unsafe { (*dacl).AceCount }, 3);
        let mut observed = Vec::new();
        for index in 0..3_u32 {
            let mut ace = std::ptr::null_mut();
            assert_ne!(unsafe { GetAce(dacl, index, &raw mut ace) }, 0);
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = (&raw const allowed.SidStart).cast_mut().cast();
            observed.push((
                sid_to_string(sid).unwrap_or_else(|error| panic!("SID failed: {error}")),
                allowed.Mask,
            ));
        }
        assert_eq!(
            observed,
            vec![
                ("S-1-5-18".to_owned(), SERVICE_ALL_ACCESS),
                ("S-1-5-32-544".to_owned(), SERVICE_ALL_ACCESS),
                (host_sid.to_owned(), ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,),
            ]
        );
        let digest = watchdog_service_security_descriptor_digest(host_sid)
            .unwrap_or_else(|error| panic!("digest failed: {error}"));
        let substituted = OwnedSecurityDescriptor::for_watchdog_host_control("S-1-5-80-6-7-8-9-10")
            .unwrap_or_else(|error| panic!("substituted descriptor failed: {error}"));
        assert!(substituted.dacl().is_ok());
        assert_ne!(
            digest,
            watchdog_service_security_descriptor_digest("S-1-5-80-6-7-8-9-10")
                .unwrap_or_else(|error| panic!("substituted digest failed: {error}"))
        );
    }

    #[test]
    fn service_registration_plan_rejects_non_runtime_shape() {
        let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
        for (name, start_mode, account) in [
            (
                "eliot-host",
                ServiceStartMode::Automatic,
                ServiceAccount::LocalService,
            ),
            (
                ELIOT_HOST_SERVICE_NAME,
                ServiceStartMode::Demand,
                ServiceAccount::LocalService,
            ),
            (
                ELIOT_HOST_SERVICE_NAME,
                ServiceStartMode::Automatic,
                ServiceAccount::LocalSystem,
            ),
        ] {
            assert_eq!(
                ServiceRegistrationRequest::new(name, "Eliot Host", &image, start_mode, account,),
                Err(WindowsAdapterError::InvalidInput)
            );
        }
        assert_eq!(
            ServiceRegistrationRequest::new(
                ELIOT_HOST_SERVICE_NAME,
                ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
                &image,
                ServiceStartMode::Automatic,
                ServiceAccount::LocalService,
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
    }

    #[test]
    fn service_bootstrap_arguments_preserve_typed_order_and_substitution() {
        let bootstrap = ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\ProgramData\Eliot\generation 7\runtime.json"),
            "a".repeat(64),
            "installation-7",
            7,
            ["--extra".to_owned(), "value with spaces".to_owned()],
        )
        .unwrap_or_else(|error| panic!("bootstrap failed: {error}"));
        assert_eq!(
            bootstrap.argv(),
            vec![
                "--config-descriptor".to_owned(),
                r"C:\ProgramData\Eliot\generation 7\runtime.json".to_owned(),
                "--config-descriptor-sha256".to_owned(),
                "a".repeat(64),
                "--installation-id".to_owned(),
                "installation-7".to_owned(),
                "--tx-plan-generation".to_owned(),
                "7".to_owned(),
                "--extra".to_owned(),
                "value with spaces".to_owned(),
            ]
        );
        let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
        let request = ServiceRegistrationRequest::with_bootstrap(
            ELIOT_HOST_SERVICE_NAME,
            ELIOT_HOST_SERVICE_DISPLAY_NAME,
            &image,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
            bootstrap,
        )
        .unwrap_or_else(|error| panic!("request failed: {error}"));
        let command = request.binary_command();
        assert!(command.starts_with('"'));
        assert!(command.contains("--config-descriptor"));
        assert!(command.contains("\"value with spaces\""));
        assert!(command.contains("--tx-plan-generation 7"));
    }

    #[test]
    fn service_bootstrap_arguments_reject_substitution_and_reserved_flags() {
        assert_eq!(
            ServiceBootstrapArguments::new(
                PathBuf::from(r"C:\runtime.json"),
                "A".repeat(64),
                "installation",
                1,
                Vec::<String>::new(),
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            ServiceBootstrapArguments::new(
                PathBuf::from(r"C:\runtime.json"),
                "a".repeat(64),
                "installation",
                1,
                vec!["--installation-id".to_owned()],
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            ServiceBootstrapArguments::new(
                PathBuf::from(r"C:\runtime.json"),
                "a".repeat(64),
                "installation",
                1,
                vec!["--host-state-root".to_owned()],
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
    }

    #[test]
    fn host_bootstrap_root_is_typed_and_ordered_before_effect_nonce() {
        let host_root = PathBuf::from(
            r"C:\ProgramData\Eliot\installations\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\host",
        );
        let bootstrap = ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\ProgramData\Eliot\authority.json"),
            "a".repeat(64),
            "installation",
            7,
            Vec::<String>::new(),
        )
        .and_then(|value| value.with_host_state_root(&host_root))
        .and_then(|value| value.with_registration_nonce("b".repeat(64)))
        .unwrap_or_else(|error| panic!("bootstrap failed: {error}"));
        assert_eq!(bootstrap.host_state_root(), Some(host_root.as_path()));
        assert_eq!(
            &bootstrap.argv()[8..],
            [
                "--host-state-root",
                host_root.to_str().unwrap_or_else(|| unreachable!()),
                "--registration-nonce",
                &"b".repeat(64),
            ]
        );
        assert_eq!(
            ServiceBootstrapArguments::new(
                PathBuf::from(r"C:\ProgramData\Eliot\authority.json"),
                "a".repeat(64),
                "installation",
                7,
                Vec::<String>::new(),
            )
            .and_then(|value| value.with_host_state_root("relative\\host")),
            Err(WindowsAdapterError::InvalidInput)
        );
    }

    #[cfg(windows)]
    #[test]
    fn service_bootstrap_command_preserves_unicode_quotes_and_trailing_slashes() {
        let bootstrap = ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\ProgramData\Eliot\Δ generation\config.json"),
            "b".repeat(64),
            "installation-unicode",
            9,
            [
                "--label=quoted\"value".to_owned(),
                r"C:\ProgramData\Eliot\tail\".to_owned(),
            ],
        )
        .unwrap_or_else(|error| panic!("bootstrap failed: {error}"));
        let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
        let request = ServiceRegistrationRequest::with_bootstrap(
            ELIOT_HOST_SERVICE_NAME,
            ELIOT_HOST_SERVICE_DISPLAY_NAME,
            image,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
            bootstrap,
        )
        .unwrap_or_else(|error| panic!("request failed: {error}"));
        let command = request.binary_command();
        assert!(command.contains("Δ generation"));
        assert!(command.contains("--label=quoted"));
        assert!(command.contains("\\\"value"));
        assert!(command.contains(r"C:\ProgramData\Eliot\tail\"));
        assert_eq!(
            service_configuration_digest(
                &request.binary_command_wide(),
                &utf16_text(request.display_name()),
                &utf16_text("NT AUTHORITY\\LocalService"),
                0x0000_0010,
                0x0000_0002,
                0x0000_0001,
                0,
                &[],
                &[],
                request.service_sid_type().raw(),
            ),
            request.expected_configuration_digest()
        );
    }

    #[test]
    fn service_bootstrap_rejects_nul_and_mutations_require_bootstrap() {
        assert_eq!(
            ServiceBootstrapArguments::new(
                PathBuf::from(r"C:\runtime.json"),
                "a".repeat(64),
                "installation",
                1,
                vec!["bad\0arg".to_owned()],
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            ServiceBootstrapArguments::new(
                PathBuf::from("C:\\runtime\0.json"),
                "a".repeat(64),
                "installation",
                1,
                Vec::<String>::new(),
            ),
            Err(WindowsAdapterError::InvalidInput)
        );

        #[cfg(windows)]
        {
            let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
            let request = ServiceRegistrationRequest::new(
                ELIOT_HOST_SERVICE_NAME,
                ELIOT_HOST_SERVICE_DISPLAY_NAME,
                image,
                ServiceStartMode::Automatic,
                ServiceAccount::LocalService,
            )
            .unwrap_or_else(|error| panic!("request failed: {error}"));
            assert_eq!(
                register_service(&request),
                Err(WindowsAdapterError::InvalidInput)
            );
            assert_eq!(
                update_service_registration(&request),
                Err(WindowsAdapterError::InvalidInput)
            );
            assert_eq!(
                delete_service_registration(&request),
                Err(WindowsAdapterError::InvalidInput)
            );
            assert_eq!(
                start_service_registration(&request),
                Err(WindowsAdapterError::InvalidInput)
            );
            assert_eq!(
                stop_service_registration(&request),
                Err(WindowsAdapterError::InvalidInput)
            );

            let adapter = WindowsPlatform::new(std::env::temp_dir())
                .unwrap_or_else(|error| panic!("temp root failed: {error}"));
            // The public methods repeat the admission guard.  These calls must
            // return before any SCM inspection or mutation can be attempted.
            assert_eq!(
                adapter.start_service_registration(&request),
                Err(WindowsAdapterError::InvalidInput)
            );
            assert_eq!(
                adapter.stop_service_registration(&request),
                Err(WindowsAdapterError::InvalidInput)
            );
        }
    }

    #[test]
    fn service_bootstrap_nonce_is_typed_and_part_of_canonical_argv() {
        let bootstrap = ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\ProgramData\Eliot\authority.json"),
            "a".repeat(64),
            "installation",
            7,
            Vec::<String>::new(),
        )
        .and_then(|bootstrap| bootstrap.with_registration_nonce("b".repeat(64)))
        .unwrap_or_else(|error| panic!("bootstrap failed: {error}"));
        assert_eq!(
            bootstrap.registration_nonce(),
            Some("b".repeat(64).as_str())
        );
        assert_eq!(
            bootstrap.argv(),
            vec![
                "--config-descriptor",
                r"C:\ProgramData\Eliot\authority.json",
                "--config-descriptor-sha256",
                &"a".repeat(64),
                "--installation-id",
                "installation",
                "--tx-plan-generation",
                "7",
                "--registration-nonce",
                &"b".repeat(64),
            ]
        );
        assert_eq!(
            ServiceBootstrapArguments::new(
                PathBuf::from(r"C:\ProgramData\Eliot\authority.json"),
                "a".repeat(64),
                "installation",
                7,
                Vec::<String>::new(),
            )
            .and_then(|bootstrap| bootstrap.with_registration_nonce("not-a-digest")),
            Err(WindowsAdapterError::InvalidInput)
        );
    }

    #[cfg(windows)]
    #[test]
    fn service_mutation_requires_expected_current_and_rejects_substitution() {
        let bootstrap = ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\ProgramData\Eliot\config.json"),
            "c".repeat(64),
            "installation",
            1,
            Vec::<String>::new(),
        )
        .unwrap_or_else(|error| panic!("bootstrap failed: {error}"));
        let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
        let request = ServiceRegistrationRequest::with_bootstrap(
            ELIOT_HOST_SERVICE_NAME,
            ELIOT_HOST_SERVICE_DISPLAY_NAME,
            image,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
            bootstrap,
        )
        .unwrap_or_else(|error| panic!("request failed: {error}"));
        assert_eq!(
            update_service_registration(&request),
            Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation)
        );
        assert_eq!(
            delete_service_registration(&request),
            Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation)
        );

        let matching = ServiceConfigurationReadback {
            binary: request.binary_command_wide(),
            display: utf16_text(request.display_name()),
            account: utf16_text("NT AUTHORITY\\LocalService"),
            load_order_group: Vec::new(),
            dependencies: Vec::new(),
            service_type: 0x0000_0010,
            start_type: 0x0000_0002,
            error_control: 0x0000_0001,
            tag_id: 0,
            service_sid_type: request.service_sid_type().raw(),
        };
        let expected = ServiceRegistrationCurrent::new(
            ELIOT_HOST_SERVICE_NAME,
            service_configuration_digest(
                &matching.binary,
                &matching.display,
                &matching.account,
                matching.service_type,
                matching.start_type,
                matching.error_control,
                matching.tag_id,
                &matching.load_order_group,
                &matching.dependencies,
                matching.service_sid_type,
            ),
        )
        .unwrap_or_else(|error| panic!("current failed: {error}"));
        assert!(service_current_matches(&request, &expected, &matching));
        let substituted = ServiceConfigurationReadback {
            binary: utf16_text(r#""C:\wrong\eliot-host.exe""#),
            ..matching.clone()
        };
        assert!(!service_current_matches(&request, &expected, &substituted));
        let mut substituted_error_control = matching.clone();
        substituted_error_control.error_control = 0x0000_0002;
        assert!(!service_current_matches(
            &request,
            &expected,
            &substituted_error_control
        ));
        let mut substituted_tag = matching.clone();
        substituted_tag.tag_id = 3;
        assert!(!service_current_matches(
            &request,
            &expected,
            &substituted_tag
        ));
        let mut substituted_load_order_group = matching.clone();
        substituted_load_order_group.load_order_group = utf16_text("EliotGroup");
        assert!(!service_current_matches(
            &request,
            &expected,
            &substituted_load_order_group
        ));
        let mut substituted_dependencies = matching;
        substituted_dependencies.dependencies = vec![utf16_text("Tcpip")];
        assert!(!service_current_matches(
            &request,
            &expected,
            &substituted_dependencies
        ));
    }

    #[test]
    fn service_configuration_mismatch_is_not_acceptable() {
        let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
        let request = ServiceRegistrationRequest::new(
            ELIOT_HOST_SERVICE_NAME,
            "Eliot Host",
            &image,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        )
        .unwrap_or_else(|error| panic!("request failed: {error}"));
        let matching = ServiceConfigurationReadback {
            binary: request.binary_command_wide(),
            display: utf16_text("Eliot Host"),
            account: utf16_text("NT AUTHORITY\\LocalService"),
            load_order_group: Vec::new(),
            dependencies: Vec::new(),
            service_type: 0x0000_0010,
            start_type: 0x0000_0002,
            error_control: 0x0000_0001,
            tag_id: 0,
            service_sid_type: request.service_sid_type().raw(),
        };
        assert!(exact_service_configuration_matches(&request, &matching));
        let mut wrong_binary = matching.clone();
        wrong_binary.binary = utf16_text("\"C:\\wrong\\eliot-host.exe\"");
        assert!(!exact_service_configuration_matches(
            &request,
            &wrong_binary
        ));
        let mut wrong_account = matching.clone();
        wrong_account.account = utf16_text("LocalSystem");
        assert!(!exact_service_configuration_matches(
            &request,
            &wrong_account
        ));
        let mut wrong_type = matching.clone();
        wrong_type.service_type = 0x0000_0011;
        assert!(!exact_service_configuration_matches(&request, &wrong_type));
        let mut wrong_start = matching.clone();
        wrong_start.start_type = 0x0000_0003;
        assert!(!exact_service_configuration_matches(&request, &wrong_start));
        let mut wrong_error_control = matching.clone();
        wrong_error_control.error_control = 0x0000_0002;
        assert!(!exact_service_configuration_matches(
            &request,
            &wrong_error_control
        ));
        let mut wrong_tag = matching.clone();
        wrong_tag.tag_id = 7;
        assert!(!exact_service_configuration_matches(&request, &wrong_tag));
        let mut wrong_sid_type = matching.clone();
        wrong_sid_type.service_sid_type = 0;
        assert!(!exact_service_configuration_matches(
            &request,
            &wrong_sid_type
        ));
        let mut wrong_load_order_group = matching.clone();
        wrong_load_order_group.load_order_group = utf16_text("EliotGroup");
        assert!(!exact_service_configuration_matches(
            &request,
            &wrong_load_order_group
        ));
        let mut wrong_dependencies = matching;
        wrong_dependencies.dependencies = vec![utf16_text("Tcpip")];
        assert!(!exact_service_configuration_matches(
            &request,
            &wrong_dependencies
        ));
    }

    #[cfg(windows)]
    #[test]
    fn service_dependency_multisz_readback_is_ordered_and_canonical() {
        let raw = [
            u16::from(b'T'),
            u16::from(b'c'),
            u16::from(b'p'),
            u16::from(b'i'),
            u16::from(b'p'),
            0,
            u16::from(b'D'),
            u16::from(b'n'),
            u16::from(b's'),
            0,
            0,
        ];
        assert_eq!(
            service_config_multi_sz(
                raw.as_ptr(),
                raw.as_ptr().cast(),
                std::mem::size_of_val(&raw),
            ),
            Some(vec![utf16_text("Tcpip"), utf16_text("Dns")])
        );
        assert_eq!(
            service_config_multi_sz(std::ptr::null(), raw.as_ptr().cast(), 0),
            Some(Vec::new())
        );
    }

    #[cfg(windows)]
    #[test]
    fn service_configuration_strings_fail_closed_at_query_buffer_boundary() {
        let unterminated = [u16::from(b'E'), u16::from(b'l')];
        let start = unterminated.as_ptr().cast::<u8>();
        let bytes = std::mem::size_of_val(&unterminated);
        assert_eq!(
            service_config_wide(unterminated.as_ptr(), start, bytes),
            None
        );
        assert_eq!(
            service_config_multi_sz(unterminated.as_ptr(), start, bytes),
            None
        );

        let single_terminated = [u16::from(b'E'), 0];
        assert_eq!(
            service_config_multi_sz(
                single_terminated.as_ptr(),
                single_terminated.as_ptr().cast(),
                std::mem::size_of_val(&single_terminated),
            ),
            None
        );

        let empty_multi_sz = [0_u16, 0];
        assert_eq!(
            service_config_multi_sz(
                empty_multi_sz.as_ptr(),
                empty_multi_sz.as_ptr().cast(),
                std::mem::size_of_val(&empty_multi_sz),
            ),
            Some(Vec::new())
        );

        let outside = unsafe { unterminated.as_ptr().add(unterminated.len()) };
        assert_eq!(service_config_wide(outside, start, bytes), None);
    }

    #[test]
    fn post_create_readback_failure_cannot_report_success() {
        let observation = ServiceObservation {
            service: handle(ELIOT_HOST_SERVICE_NAME),
            state: ServiceState::Stopped,
            generation: None,
            process: None,
        };
        assert!(!service_readback_is_acceptable(
            &ServiceRegistrationInspection::Mismatched
        ));
        assert!(!service_readback_is_acceptable(
            &ServiceRegistrationInspection::Unknown
        ));
        assert!(service_readback_is_acceptable(
            &ServiceRegistrationInspection::Matching {
                observation,
                control_grant: None,
            }
        ));
        assert_eq!(
            ServiceRegistrationOutcome::ExistingRequiresReconciliation,
            ServiceRegistrationOutcome::ExistingRequiresReconciliation
        );
    }

    #[test]
    fn scm_post_effect_failure_is_reconciliation_unknown() {
        let failure = PortOutcome::Error(PortError::Provider(provider_failed()));
        assert_eq!(
            reconcile_service_effect(failure),
            PortOutcome::Unknown(UnknownReason::Indeterminate)
        );
        assert_eq!(
            reconcile_service_effect(PortOutcome::Unknown(UnknownReason::NotObserved)),
            PortOutcome::Unknown(UnknownReason::Indeterminate)
        );
    }

    #[test]
    fn partial_service_status_never_maps_to_matching() {
        let observation = ServiceObservation {
            service: handle(ELIOT_HOST_SERVICE_NAME),
            state: ServiceState::Running,
            generation: None,
            process: None,
        };
        assert_eq!(
            service_registration_inspection_from_status(
                PortOutcome::Partial {
                    value: observation,
                    missing: vec![handle("authority")],
                },
                None
            ),
            ServiceRegistrationInspection::Unknown
        );
    }

    #[cfg(windows)]
    #[test]
    fn exact_runtime_service_observation_requires_handle_bound_live_identity() {
        let image = std::env::current_exe().unwrap_or_else(|_| unreachable!());
        let request = ServiceRegistrationRequest::new(
            ELIOT_HOST_SERVICE_NAME,
            ELIOT_HOST_SERVICE_DISPLAY_NAME,
            &image,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        )
        .unwrap_or_else(|_| unreachable!());
        let running = ProcessIdentity {
            process_id: 41,
            start_time_100ns: 99,
            image_path: image.to_string_lossy().into_owned(),
        };

        let ServiceRegistrationRuntimeInspection::Matching { observation } =
            classify_service_runtime_observation(&request, ServiceState::Stopped, 0, 0, 0, None)
        else {
            unreachable!();
        };
        assert_eq!(observation.state(), ServiceState::Stopped);
        assert!(observation.process().is_none());
        assert_eq!(
            observation.configuration_digest(),
            request.expected_configuration_digest()
        );

        let ServiceRegistrationRuntimeInspection::Matching { observation } =
            classify_service_runtime_observation(
                &request,
                ServiceState::Starting,
                3,
                250,
                running.process_id,
                Some(running.clone()),
            )
        else {
            unreachable!();
        };
        assert_eq!(observation.checkpoint(), 3);
        assert_eq!(observation.wait_hint_ms(), 250);
        assert_eq!(observation.process(), Some(&running));

        assert!(matches!(
            classify_service_runtime_observation(
                &request,
                ServiceState::Running,
                0,
                0,
                running.process_id,
                Some(running),
            ),
            ServiceRegistrationRuntimeInspection::Matching { .. }
        ));
        assert_eq!(
            classify_service_runtime_observation(&request, ServiceState::Running, 0, 0, 41, None,),
            ServiceRegistrationRuntimeInspection::Unknown
        );
        assert_eq!(
            classify_service_runtime_observation(
                &request,
                ServiceState::Stopped,
                0,
                0,
                41,
                Some(ProcessIdentity {
                    process_id: 41,
                    start_time_100ns: 99,
                    image_path: image.to_string_lossy().into_owned(),
                }),
            ),
            ServiceRegistrationRuntimeInspection::Unknown
        );
        assert_eq!(
            classify_service_runtime_observation(
                &request,
                ServiceState::Running,
                0,
                0,
                41,
                Some(ProcessIdentity {
                    process_id: 41,
                    start_time_100ns: 99,
                    image_path: image
                        .with_file_name("substituted.exe")
                        .to_string_lossy()
                        .into_owned(),
                }),
            ),
            ServiceRegistrationRuntimeInspection::Mismatched
        );
        assert!(service_runtime_sample_is_stable(4, 41, 4, 41));
        assert!(!service_runtime_sample_is_stable(4, 41, 1, 0));
        assert!(!service_runtime_sample_is_stable(2, 41, 2, 42));
    }

    #[test]
    fn runtime_identity_digest_binds_configuration_pid_start_time_and_image() {
        let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
        let request = ServiceRegistrationRequest::new(
            ELIOT_HOST_SERVICE_NAME,
            ELIOT_HOST_SERVICE_DISPLAY_NAME,
            &image,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        )
        .unwrap_or_else(|error| panic!("request failed: {error}"));
        let process = ProcessIdentity {
            process_id: 41,
            start_time_100ns: 99,
            image_path: image.to_string_lossy().into_owned(),
        };
        let observation = ServiceRuntimeObservation {
            service_name: request.service_name().to_owned(),
            configuration_digest: request.expected_configuration_digest(),
            state: ServiceState::Running,
            checkpoint: 0,
            wait_hint_ms: 0,
            process: Some(process.clone()),
        };
        let digest = observation
            .runtime_identity_digest()
            .unwrap_or_else(|| unreachable!());
        assert!(valid_sha256_hex(&digest));
        assert_eq!(
            digest,
            runtime_identity_digest_from_configuration(
                observation.configuration_digest(),
                &process,
            )
        );
        assert_eq!(
            request
                .clone()
                .with_expected_runtime_identity_digest(digest.clone())
                .unwrap_or_else(|error| panic!("digest binding failed: {error}"))
                .expected_runtime_identity_digest(),
            Some(digest.as_str())
        );
        assert_eq!(
            request
                .clone()
                .with_expected_runtime_identity_digest("A".repeat(64)),
            Err(WindowsAdapterError::InvalidInput)
        );
        let mut changed = process;
        changed.start_time_100ns += 1;
        assert_ne!(
            digest,
            runtime_identity_digest_from_configuration(
                observation.configuration_digest(),
                &changed,
            )
        );
    }

    #[test]
    fn scm_mutation_outcomes_never_promote_unknown_readback() {
        let observation = |state| ServiceRuntimeObservation {
            service_name: ELIOT_HOST_SERVICE_NAME.to_owned(),
            configuration_digest: "a".repeat(64),
            state,
            checkpoint: 0,
            wait_hint_ms: 0,
            process: None,
        };
        assert!(matches!(
            start_outcome_from_inspection(
                ServiceRegistrationRuntimeInspection::Matching {
                    observation: observation(ServiceState::Running),
                },
                false,
            ),
            ServiceStartOutcome::AlreadyRunning { .. }
        ));
        assert!(matches!(
            start_outcome_from_inspection(
                ServiceRegistrationRuntimeInspection::Matching {
                    observation: observation(ServiceState::Starting),
                },
                true,
            ),
            ServiceStartOutcome::Started { .. }
        ));
        assert_eq!(
            start_outcome_from_inspection(ServiceRegistrationRuntimeInspection::Unknown, true,),
            ServiceStartOutcome::EffectUnknown
        );
        assert!(matches!(
            stop_outcome_from_inspection(
                ServiceRegistrationRuntimeInspection::Matching {
                    observation: observation(ServiceState::Stopped),
                },
                false,
            ),
            ServiceStopOutcome::AlreadyStopped { .. }
        ));
        assert!(matches!(
            stop_outcome_from_inspection(
                ServiceRegistrationRuntimeInspection::Matching {
                    observation: observation(ServiceState::Stopping),
                },
                true,
            ),
            ServiceStopOutcome::Stopped { .. }
        ));
        assert_eq!(
            stop_outcome_from_inspection(ServiceRegistrationRuntimeInspection::Mismatched, true,),
            ServiceStopOutcome::EffectUnknown
        );
    }

    #[cfg(windows)]
    #[test]
    fn stopping_runtime_requires_the_expected_identity_digest() {
        let process = ProcessIdentity {
            process_id: 41,
            start_time_100ns: 99,
            image_path: std::env::current_exe()
                .unwrap_or_else(|_| unreachable!())
                .to_string_lossy()
                .into_owned(),
        };
        let observation = ServiceRuntimeObservation {
            service_name: ELIOT_HOST_SERVICE_NAME.to_owned(),
            configuration_digest: "a".repeat(64),
            state: ServiceState::Stopping,
            checkpoint: 1,
            wait_hint_ms: 250,
            process: Some(process.clone()),
        };
        let expected_digest = observation
            .runtime_identity_digest()
            .unwrap_or_else(|| unreachable!());
        assert!(matches!(
            admit_stop_runtime_observation(
                ServiceRegistrationRuntimeInspection::Matching {
                    observation: observation.clone(),
                },
                &expected_digest,
            ),
            Err(ServiceStopOutcome::AlreadyStopping { .. })
        ));

        let mismatched = ServiceRuntimeObservation {
            process: Some(ProcessIdentity {
                start_time_100ns: process.start_time_100ns + 1,
                ..process
            }),
            ..observation
        };
        assert_eq!(
            admit_stop_runtime_observation(
                ServiceRegistrationRuntimeInspection::Matching {
                    observation: mismatched,
                },
                &expected_digest,
            ),
            Err(ServiceStopOutcome::EffectUnknown)
        );
    }

    #[test]
    fn create_new_does_not_truncate_existing_entry() {
        let root = std::env::temp_dir().join(format!("eliot-p02-create-new-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let path = root.join("entry");
        std::fs::write(&path, b"original").unwrap_or_else(|_| unreachable!());
        let error = create_new_file(&path, b"replacement").expect_err("must not truncate");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap_or_default(), b"original");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_service_is_typed_unsupported() {
        assert!(matches!(
            inspect_service("Eliot"),
            PortOutcome::Unknown(UnknownReason::Unsupported)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn real_windows_identity_and_atomic_publication_are_safe_and_reproducible() {
        let root = std::env::temp_dir().join(format!("eliot-p02-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        std::fs::create_dir(root.join("state")).unwrap_or_else(|_| unreachable!());
        let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
        let path = WorkScopePath::new("state/current.bin").unwrap_or_else(|_| unreachable!());
        let first = adapter
            .publish_atomic_receipt(&path, b"first")
            .unwrap_or_else(|_| unreachable!());
        let second = adapter
            .publish_atomic_receipt(&path, b"second")
            .unwrap_or_else(|_| unreachable!());
        assert_ne!(
            first.identity,
            FileIdentity {
                volume_serial_number: 0,
                file_index: 0
            }
        );
        assert_eq!(
            adapter
                .file_identity(&path)
                .unwrap_or_else(|_| unreachable!()),
            second.identity
        );
        assert_eq!(
            std::fs::read(root.join("state/current.bin")).unwrap_or_default(),
            b"second"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn real_windows_dpapi_and_job_object_primitives_are_available() {
        let root = std::env::temp_dir().join(format!("eliot-p02-crypto-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
        let protected = adapter
            .protect_secret(b"p02-dpapi-roundtrip")
            .unwrap_or_else(|_| unreachable!());
        assert_ne!(protected.as_bytes(), b"p02-dpapi-roundtrip");
        let clear = adapter
            .unprotect_secret(&protected)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(clear.expose(), b"p02-dpapi-roundtrip");
        let _job = JobObject::new_kill_on_close().unwrap_or_else(|_| unreachable!());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn job_child_process() {
        if std::env::var_os("ELIOT_P02_JOB_CHILD").is_some() {
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    }

    #[cfg(windows)]
    fn wait_for_child_exit(child: &mut std::process::Child) -> bool {
        for _ in 0..100 {
            if child.try_wait().ok().flatten().is_some() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    }

    #[cfg(windows)]
    fn spawn_job_child() -> std::process::Child {
        std::process::Command::new(std::env::current_exe().unwrap_or_else(|_| unreachable!()))
            .arg("--exact")
            .arg("tests::job_child_process")
            .arg("--nocapture")
            .env("ELIOT_P02_JOB_CHILD", "1")
            .spawn()
            .unwrap_or_else(|_| unreachable!())
    }

    #[cfg(windows)]
    #[test]
    fn suspended_child_process() {
        if let Some(marker) = std::env::var_os("ELIOT_P02_SUSPENDED_MARKER") {
            let _descendant = std::env::var_os("ELIOT_P02_SPAWN_DESCENDANT").map(|_| {
                std::process::Command::new(
                    std::env::current_exe().unwrap_or_else(|_| unreachable!()),
                )
                .arg("--exact")
                .arg("tests::job_child_process")
                .arg("--nocapture")
                .env("ELIOT_P02_JOB_CHILD", "1")
                .spawn()
                .unwrap_or_else(|_| unreachable!())
            });
            let body = format!(
                "cwd={}\nenv={}",
                std::env::current_dir()
                    .unwrap_or_else(|_| unreachable!())
                    .display(),
                std::env::var("ELIOT_P02_EXACT_ENV").unwrap_or_default()
            );
            std::fs::write(marker, body).unwrap_or_else(|_| unreachable!());
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    }

    #[cfg(windows)]
    fn complete_test_environment(
        marker: &Path,
        spawn_descendant: bool,
    ) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        let mut environment = std::env::vars_os().collect::<Vec<_>>();
        for name in [
            "ELIOT_P02_SUSPENDED_MARKER",
            "ELIOT_P02_EXACT_ENV",
            "ELIOT_P02_SPAWN_DESCENDANT",
        ] {
            environment.retain(|(key, _)| !key.to_string_lossy().eq_ignore_ascii_case(name));
        }
        environment.push((
            "ELIOT_P02_SUSPENDED_MARKER".into(),
            marker.as_os_str().to_owned(),
        ));
        environment.push(("ELIOT_P02_EXACT_ENV".into(), "exact-value".into()));
        if spawn_descendant {
            environment.push(("ELIOT_P02_SPAWN_DESCENDANT".into(), "1".into()));
        }
        environment
    }

    #[cfg(windows)]
    fn suspended_spec(
        marker: &Path,
        working_directory: &Path,
        spawn_descendant: bool,
    ) -> SuspendedLaunchSpec {
        SuspendedLaunchSpec::new(
            std::env::current_exe().unwrap_or_else(|_| unreachable!()),
            vec![
                "--exact".into(),
                "tests::suspended_child_process".into(),
                "--nocapture".into(),
            ],
            working_directory,
            complete_test_environment(marker, spawn_descendant),
        )
        .unwrap_or_else(|error| panic!("spec failed: {error}"))
    }

    #[cfg(windows)]
    fn spawn_suspended_child(
        marker: &Path,
        working_directory: &Path,
        spawn_descendant: bool,
    ) -> SuspendedJobChild {
        SuspendedJobChild::spawn(suspended_spec(marker, working_directory, spawn_descendant))
            .unwrap_or_else(|error| panic!("spawn failed: {error}"))
    }

    #[cfg(windows)]
    fn wait_for_process_gone(pid: u32) -> bool {
        for _ in 0..100 {
            if inspect_process_identity(pid).is_err() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    }

    #[cfg(windows)]
    #[test]
    fn suspended_launch_does_not_start_before_consuming_validation() {
        let _spawn_guard = process_job_spawn_test_guard();
        let root = std::env::temp_dir().join(format!("eliot-p02-suspended-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let marker = root.join("started");
        let child = spawn_suspended_child(&marker, &root, true);
        let pid = child.id();
        assert!(!marker.exists(), "child must not run before ResumeThread");
        let terminal = child.terminate(0xE1_05).unwrap_or_else(|_| unreachable!());
        assert_eq!(terminal.process().process_id, pid);
        assert_eq!(terminal.requested_exit_code(), 0xE1_05);
        assert!(terminal.job_empty());
        assert!(terminal.root_reaped());
        assert!(wait_for_process_gone(pid));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn consuming_validation_binds_exact_launch_evidence_before_resume() {
        let _spawn_guard = process_job_spawn_test_guard();
        let root = std::env::temp_dir().join(format!("eliot-p02-evidence-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let marker = root.join("started");
        let expected_image = std::env::current_exe().unwrap_or_else(|_| unreachable!());
        let child = spawn_suspended_child(&marker, &root, false);
        let expected_pid = child.id();
        let validated = child
            .validate::<&'static str, &'static str, _>(|evidence| {
                assert_eq!(evidence.process().process_id, expected_pid);
                assert_ne!(evidence.executable_file_identity().file_index, 0);
                assert_eq!(evidence.job_process_count(), 1);
                assert!(same_windows_path(
                    &evidence.process().image_path,
                    &expected_image.to_string_lossy()
                ));
                assert_eq!(evidence.requested_executable(), expected_image);
                assert_eq!(evidence.working_directory(), root);
                assert_eq!(
                    evidence.arguments(),
                    [
                        std::ffi::OsString::from("--exact"),
                        std::ffi::OsString::from("tests::suspended_child_process"),
                        std::ffi::OsString::from("--nocapture"),
                    ]
                );
                assert!(evidence.environment().iter().any(|(name, value)| {
                    name == "ELIOT_P02_EXACT_ENV" && value == "exact-value"
                }));
                Ok("validated-by-test-policy")
            })
            .unwrap_or_else(|error| panic!("evidence validation failed: {error:?}"));
        assert!(!marker.exists(), "validation must not resume the child");
        assert_eq!(*validated.validation(), "validated-by-test-policy");
        let running = validated.resume().unwrap_or_else(|_| unreachable!());
        for _ in 0..100 {
            if marker.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(marker.exists(), "child must run after validated resume");
        let marker_body = std::fs::read_to_string(&marker).unwrap_or_default();
        assert!(marker_body.contains(&format!("cwd={}", root.display())));
        assert!(marker_body.contains("env=exact-value"));
        let first = running.observe().unwrap_or_else(|_| unreachable!());
        let second = running.observe().unwrap_or_else(|_| unreachable!());
        assert_eq!(first, second, "observation is idempotent");
        running
            .terminate(0xE1_05)
            .unwrap_or_else(|_| unreachable!());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn caller_pid_image_mismatch_rejection_kills_and_reaps_job() {
        let _spawn_guard = process_job_spawn_test_guard();
        let root = std::env::temp_dir().join(format!("eliot-p02-reject-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let marker = root.join("started");
        let child = spawn_suspended_child(&marker, &root, false);
        let pid = child.id();
        let result = child.validate::<(), &'static str, _>(|evidence| {
            if evidence.process().process_id != pid + 1
                || evidence.process().image_path != "C:\\wrong\\image.exe"
            {
                Err("pid-image-mismatch")
            } else {
                Ok(())
            }
        });
        assert_eq!(
            result.err(),
            Some(SuspendedValidationError::Rejected("pid-image-mismatch"))
        );
        assert!(wait_for_process_gone(pid), "rejected child must not leak");
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn stale_validation_cannot_validate_a_new_process_generation() {
        let _spawn_guard = process_job_spawn_test_guard();
        let root = std::env::temp_dir().join(format!("eliot-p02-stale-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let first_marker = root.join("first");
        let first = spawn_suspended_child(&first_marker, &root, false);
        let mut old_key = String::new();
        let first = first
            .validate::<(), &'static str, _>(|evidence| {
                old_key = evidence.process().stable_key();
                Ok(())
            })
            .unwrap_or_else(|_| unreachable!());
        first.terminate(0xE1_06).unwrap_or_else(|_| unreachable!());

        let second_marker = root.join("second");
        let second = spawn_suspended_child(&second_marker, &root, false);
        let second_pid = second.id();
        let result = second.validate::<(), &'static str, _>(|evidence| {
            if evidence.process().stable_key() == old_key {
                Ok(())
            } else {
                Err("stale-validation")
            }
        });
        assert_eq!(
            result.err(),
            Some(SuspendedValidationError::Rejected("stale-validation"))
        );
        assert!(wait_for_process_gone(second_pid));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn validator_panic_still_kills_and_reaps_suspended_job() {
        let _spawn_guard = process_job_spawn_test_guard();
        let root = std::env::temp_dir().join(format!("eliot-p02-panic-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let marker = root.join("started");
        let child = spawn_suspended_child(&marker, &root, false);
        let pid = child.id();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = child.validate::<(), (), _>(|_| panic!("test validator panic"));
        }));
        assert!(panic.is_err());
        assert!(wait_for_process_gone(pid));
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn resumed_tree_termination_is_consuming_and_reaps_every_member() {
        let _spawn_guard = process_job_spawn_test_guard();
        let root = std::env::temp_dir().join(format!("eliot-p02-tree-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let marker = root.join("started");
        let child = spawn_suspended_child(&marker, &root, true);
        let validated = child
            .validate::<(), &'static str, _>(|_| Ok(()))
            .unwrap_or_else(|_| unreachable!());
        let running = validated.resume().unwrap_or_else(|_| unreachable!());
        for _ in 0..100 {
            if marker.exists()
                && running
                    .job_processes()
                    .is_ok_and(|processes| processes.len() >= 2)
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let members = running
            .job_processes()
            .unwrap_or_else(|error| panic!("membership failed: {error}"));
        assert!(members.len() >= 2);
        let pids = members
            .iter()
            .map(|process| process.process_id)
            .collect::<Vec<_>>();
        let terminal = running
            .terminate(0xE1_07)
            .unwrap_or_else(|error| panic!("termination failed: {error}"));
        assert_eq!(terminal.requested_exit_code(), 0xE1_07);
        assert!(terminal.job_empty());
        assert!(terminal.root_reaped());
        assert!(pids.into_iter().all(wait_for_process_gone));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn windows_argument_quoting_covers_quotes_and_trailing_backslashes() {
        use std::os::windows::ffi::OsStringExt;
        let quote = |value: &str| {
            let units = quote_windows_argument(std::ffi::OsStr::new(value))
                .unwrap_or_else(|_| unreachable!());
            std::ffi::OsString::from_wide(&units)
                .to_string_lossy()
                .into_owned()
        };
        assert_eq!(quote(""), r#""""#);
        assert_eq!(quote("plain"), r#""plain""#);
        assert_eq!(quote(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote("a\\"), "\"a\\\\\"");
        assert_eq!(quote(r#"a\"b"#), r#""a\\\"b""#);
    }

    #[cfg(windows)]
    #[test]
    fn launch_spec_rejects_ambiguous_environment_and_nul_arguments() {
        let executable = std::env::current_exe().unwrap_or_else(|_| unreachable!());
        let root = std::env::temp_dir();
        assert_eq!(
            SuspendedLaunchSpec::new(
                &executable,
                Vec::new(),
                &root,
                vec![("Path".into(), "a".into()), ("PATH".into(), "b".into())],
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            SuspendedLaunchSpec::new(
                executable,
                vec![std::ffi::OsString::from("bad\0argument")],
                root,
                Vec::new(),
            ),
            Err(WindowsAdapterError::InvalidInput)
        );
    }

    #[cfg(windows)]
    #[test]
    fn job_assignment_identity_termination_and_kill_on_close_are_real() {
        let _spawn_guard = process_job_spawn_test_guard();
        let job = JobObject::new_kill_on_close().unwrap_or_else(|_| unreachable!());
        let mut child = spawn_job_child();
        let identity = match job.assign_process(child.id()) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("job assignment failed: {error}");
            }
        };
        assert_eq!(identity.process_id, child.id());
        assert!(identity.start_time_100ns > 0);
        assert!(!identity.image_path.is_empty());
        job.terminate(0xE102).unwrap_or_else(|_| unreachable!());
        assert!(wait_for_child_exit(&mut child));

        let job = JobObject::new_kill_on_close().unwrap_or_else(|_| unreachable!());
        let mut child = spawn_job_child();
        let identity = match job.assign_process(child.id()) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("job assignment failed: {error}");
            }
        };
        assert_eq!(identity.process_id, child.id());
        drop(job);
        assert!(wait_for_child_exit(&mut child));
    }

    #[cfg(windows)]
    #[test]
    fn dropping_host_owned_running_job_kills_children_and_removes_reopen_path() {
        let _spawn_guard = process_job_spawn_test_guard();
        let root = std::env::temp_dir().join(format!(
            "eliot-host-crash-kill-on-close-{}",
            unique_suffix()
        ));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let marker = root.join("started");
        let child = spawn_suspended_child(&marker, &root, false);
        let pid = child.id();
        let running = child
            .validate::<(), &'static str, _>(|_| Ok(()))
            .unwrap_or_else(|_| unreachable!())
            .resume()
            .unwrap_or_else(|_| unreachable!());
        wait_for_marker(&marker);
        let binding = running.evidence().recoverable_job_binding();
        let mut pids = Vec::new();
        for _ in 0..100 {
            if running.active_process_count().is_ok_and(|count| count >= 2) {
                pids = running
                    .job_processes()
                    .unwrap_or_else(|_| unreachable!())
                    .into_iter()
                    .map(|process| process.process_id)
                    .collect::<Vec<_>>();
                if pids.len() >= 2 {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(pids.len() >= 2, "crash contour must include the descendant");

        // This is the Host crash boundary: dropping the process-owned
        // RunningJobChild closes its KILL_ON_JOB_CLOSE Job handle.  A restart
        // must therefore treat the durable binding as historical evidence,
        // not as a live contour it may commit without a fresh launch proof.
        drop(running);
        assert!(pids.into_iter().all(wait_for_process_gone));
        assert!(wait_for_process_gone(pid));
        assert!(matches!(
            RecoverableJobObject::open(binding),
            Err(WindowsAdapterError::NotFound)
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn real_windows_credential_manager_roundtrip_cleans_up() {
        let root = std::env::temp_dir().join(format!("eliot-p02-cred-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
        let key = format!("eliot/p02/test/{}", unique_suffix());
        adapter
            .write_credential(&key, b"credential-roundtrip")
            .unwrap_or_else(|_| unreachable!());
        let read = adapter.read_credential(&key);
        let delete = adapter.delete_credential(&key);
        assert_eq!(
            read.unwrap_or_else(|_| unreachable!()).expose(),
            b"credential-roundtrip"
        );
        assert!(delete.is_ok());
        assert_eq!(
            adapter.read_credential(&key).err(),
            Some(WindowsAdapterError::Unavailable)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn generic_credential_api_cannot_access_installer_authority_namespace() {
        let root = std::env::temp_dir().join(format!("eliot-p02-cred-guard-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
        let target = format!("{INSTALLER_CREDENTIAL_TARGET_PREFIX}{}", unique_suffix());

        assert_eq!(
            adapter.write_credential(&target, &[0x5a; 32]),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            adapter.read_credential(&target).err(),
            Some(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            adapter.delete_credential(&target),
            Err(WindowsAdapterError::InvalidInput)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn installer_secret_provider_rejects_missing_and_malformed_keys() {
        let provider = WindowsInstallerSecretProvider::new();
        let missing = provider
            .fresh_reference()
            .unwrap_or_else(|error| panic!("reference issuance failed: {error}"));
        assert_eq!(
            provider
                .inspect(&missing)
                .unwrap_or_else(|error| panic!("missing inspect failed: {error}")),
            InstallerSecretObservation::Absent
        );
        assert_eq!(
            provider.read(&missing).err(),
            Some(WindowsAdapterError::Unavailable)
        );

        let malformed = provider
            .fresh_reference()
            .unwrap_or_else(|error| panic!("reference issuance failed: {error}"));
        credential_write(malformed.as_str(), b"not-a-256-bit-key")
            .unwrap_or_else(|error| panic!("malformed fixture write failed: {error}"));
        assert_eq!(
            provider.inspect(&malformed),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            provider.read(&malformed).err(),
            Some(WindowsAdapterError::InvalidInput)
        );
        credential_delete(malformed.as_str())
            .unwrap_or_else(|error| panic!("malformed credential cleanup failed: {error}"));
    }

    #[cfg(windows)]
    #[test]
    fn concurrent_publication_is_collision_free_and_cleans_failed_staging() {
        use std::sync::Arc;
        let root = std::env::temp_dir().join(format!("eliot-p02-concurrent-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        std::fs::create_dir(root.join("state")).unwrap_or_else(|_| unreachable!());
        let adapter = Arc::new(WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!()));
        let path = WorkScopePath::new("state/current.bin").unwrap_or_else(|_| unreachable!());
        let workers = (0..8)
            .map(|index| {
                let adapter = Arc::clone(&adapter);
                let path = path.clone();
                std::thread::spawn(move || {
                    adapter.publish_atomic(&path, format!("value-{index}").as_bytes())
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            let outcome = worker
                .join()
                .unwrap_or_else(|_| unreachable!())
                .unwrap_or_else(|_| unreachable!());
            assert!(matches!(
                outcome,
                PublicationOutcome::Published(_) | PublicationOutcome::Unknown(_)
            ));
        }
        assert!(
            matches!(std::fs::read(root.join("state/current.bin")), Ok(bytes) if bytes.starts_with(b"value-"))
        );
        let entries = std::fs::read_dir(root.join("state"))
            .unwrap_or_else(|_| unreachable!())
            .count();
        assert_eq!(
            entries, 1,
            "failed publications must not leave staging files"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn directory_publication_concurrent_destination_race_never_replaces() {
        let root = std::env::temp_dir().join(format!(
            "eliot-directory-publication-race-{}",
            unique_suffix()
        ));
        std::fs::create_dir(&root).unwrap_or_else(|error| panic!("create fixture: {error}"));
        let destination = root.join("bundle");
        let mut publication = OwnedDirectoryPublication::create(&destination)
            .unwrap_or_else(|error| panic!("prepare publication: {error}"));
        let temporary = publication.temporary_path().to_path_buf();
        std::fs::write(temporary.join("role.bin"), b"candidate")
            .unwrap_or_else(|error| panic!("write candidate: {error}"));
        let identity = publication.temporary_identity();
        let racing_destination = destination.clone();
        let outcome = publication.publish_inner(
            identity,
            move || {
                std::thread::spawn(move || {
                    std::fs::create_dir(&racing_destination)
                        .unwrap_or_else(|error| panic!("racing create: {error}"));
                    std::fs::write(racing_destination.join("owner.txt"), b"concurrent-owner")
                        .unwrap_or_else(|error| panic!("racing marker: {error}"));
                })
                .join()
                .unwrap_or_else(|_| panic!("racing creator panicked"));
            },
            None,
        );
        assert_eq!(outcome, Err(DirectoryPublicationError::AlreadyExists));
        assert_eq!(
            std::fs::read(destination.join("owner.txt"))
                .unwrap_or_else(|error| panic!("read racing marker: {error}")),
            b"concurrent-owner"
        );
        assert!(temporary.exists(), "pre-commit failure retains owned temp");
        drop(publication);
        assert!(
            temporary.exists(),
            "uncommitted temp is quarantined; Drop must not delete by pathname"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn directory_publication_drop_never_deletes_a_substituted_tree() {
        let root = std::env::temp_dir().join(format!(
            "eliot-directory-publication-drop-substitution-{}",
            unique_suffix()
        ));
        std::fs::create_dir(&root).unwrap_or_else(|error| panic!("create fixture: {error}"));
        let destination = root.join("bundle");
        let publication = OwnedDirectoryPublication::create(&destination)
            .unwrap_or_else(|error| panic!("prepare publication: {error}"));
        let temporary = publication.temporary_path().to_path_buf();
        let retired = root.join("retired");
        std::fs::rename(&temporary, &retired)
            .unwrap_or_else(|error| panic!("substitute source name: {error}"));
        std::fs::create_dir(&temporary)
            .unwrap_or_else(|error| panic!("create foreign substitute: {error}"));
        std::fs::write(temporary.join("foreign.txt"), b"foreign-owner")
            .unwrap_or_else(|error| panic!("write foreign substitute: {error}"));

        drop(publication);

        assert_eq!(
            std::fs::read(temporary.join("foreign.txt"))
                .unwrap_or_else(|error| panic!("foreign tree was deleted: {error}")),
            b"foreign-owner"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn directory_publication_pins_ancestor_and_rejects_junction_substitution() {
        let root = std::env::temp_dir().join(format!(
            "eliot-directory-publication-contour-{}",
            unique_suffix()
        ));
        let parent = root.join("parent");
        let moved_parent = root.join("parent-moved");
        let outside = root.join("outside");
        std::fs::create_dir_all(&parent)
            .unwrap_or_else(|error| panic!("create retained parent: {error}"));
        std::fs::create_dir(&outside)
            .unwrap_or_else(|error| panic!("create junction target: {error}"));
        let publication = OwnedDirectoryPublication::create(&parent.join("bundle"))
            .unwrap_or_else(|error| panic!("prepare retained publication: {error}"));
        assert!(
            std::fs::rename(&parent, &moved_parent).is_err(),
            "retained no-delete-sharing contour must block ancestor rename"
        );
        drop(publication);
        std::fs::rename(&parent, &moved_parent)
            .unwrap_or_else(|error| panic!("rename after lease drop: {error}"));
        let output = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&parent)
            .arg(&outside)
            .output()
            .unwrap_or_else(|error| panic!("launch mklink: {error}"));
        assert!(
            output.status.success(),
            "mklink /J was not exercised: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(matches!(
            OwnedDirectoryPublication::create(&parent.join("bundle")),
            Err(DirectoryPublicationError::ReparsePoint)
        ));
        assert!(!outside.join("bundle").exists());
        std::fs::remove_dir(&parent).unwrap_or_else(|error| panic!("remove junction: {error}"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn directory_publication_postcommit_failure_is_reconcilable_not_error() {
        let root = std::env::temp_dir().join(format!(
            "eliot-directory-publication-unknown-{}",
            unique_suffix()
        ));
        std::fs::create_dir(&root).unwrap_or_else(|error| panic!("create fixture: {error}"));
        let destination = root.join("bundle");
        let mut publication = OwnedDirectoryPublication::create(&destination)
            .unwrap_or_else(|error| panic!("prepare publication: {error}"));
        let temporary = publication.temporary_path().to_path_buf();
        std::fs::write(temporary.join("role.bin"), b"candidate")
            .unwrap_or_else(|error| panic!("write candidate: {error}"));
        let identity = publication.temporary_identity();
        let outcome = publication
            .publish_inner(
                identity,
                || {},
                Some(DirectoryPublicationUnknown::PostCommitReadbackUnavailable),
            )
            .unwrap_or_else(|error| panic!("post-commit outcome returned Err: {error}"));
        let DirectoryPublicationOutcome::CommittedUnknown(receipt) = outcome else {
            panic!("injected post-commit discriminator must withhold receipt");
        };
        assert_eq!(
            receipt.reason,
            DirectoryPublicationUnknown::PostCommitReadbackUnavailable
        );
        assert_eq!(receipt.source_identity, identity);
        assert!(destination.exists());
        assert!(!temporary.exists());
        assert_eq!(
            std::fs::read(destination.join("role.bin"))
                .unwrap_or_else(|error| panic!("read committed role: {error}")),
            b"candidate"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn live_process_identity_binds_pid_to_start_and_image() {
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;
        let identity = inspect_process_identity(unsafe { GetCurrentProcessId() })
            .unwrap_or_else(|_| unreachable!());
        assert!(identity.start_time_100ns > 0);
        assert!(!identity.image_path.is_empty());
        let reused = ProcessIdentity {
            start_time_100ns: identity.start_time_100ns.saturating_add(1),
            ..identity.clone()
        };
        assert_ne!(identity.stable_key(), reused.stable_key());
    }

    #[cfg(windows)]
    #[test]
    fn reparse_ancestor_is_rejected_without_touching_target() {
        use std::os::windows::fs::symlink_dir;
        let root = std::env::temp_dir().join(format!("eliot-p02-reparse-{}", unique_suffix()));
        let outside = std::env::temp_dir().join(format!("eliot-p02-outside-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        std::fs::create_dir(&outside).unwrap_or_else(|_| unreachable!());
        if symlink_dir(&outside, root.join("link")).is_err() {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            return;
        }
        let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
        let path = WorkScopePath::new("link/target.bin").unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            adapter.publish_atomic(&path, b"must-not-write"),
            Err(PortError::InvalidPath)
        ));
        assert!(!outside.join("target.bin").exists());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(windows)]
    #[test]
    fn reparse_destination_is_rejected_and_staging_is_removed() {
        use std::os::windows::fs::symlink_file;
        let root = std::env::temp_dir().join(format!("eliot-p02-destination-{}", unique_suffix()));
        let outside =
            std::env::temp_dir().join(format!("eliot-p02-destination-outside-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        std::fs::create_dir(&outside).unwrap_or_else(|_| unreachable!());
        std::fs::write(outside.join("target.bin"), b"original").unwrap_or_else(|_| unreachable!());
        if symlink_file(outside.join("target.bin"), root.join("current.bin")).is_err() {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            return;
        }
        let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
        let path = WorkScopePath::new("current.bin").unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            adapter.publish_atomic(&path, b"must-not-write"),
            Err(PortError::InvalidPath)
        ));
        assert_eq!(
            std::fs::read(outside.join("target.bin")).unwrap_or_default(),
            b"original"
        );
        assert_eq!(
            std::fs::read_dir(&root)
                .unwrap_or_else(|_| unreachable!())
                .count(),
            1
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(windows)]
    #[test]
    fn protected_path_lease_retains_components_and_reopens_by_identity() {
        let root = std::env::temp_dir().join(format!("eliot-protected-lease-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let relative = Path::new("Eliot/host/lease.redb");
        let path = root.join(relative);
        let lease = test_lease(&root, relative, true)
            .unwrap_or_else(|error| panic!("protected lease open failed: {error}"));
        std::fs::write(&path, b"retained-by-handle").unwrap_or_else(|_| unreachable!());
        lease
            .verify_stable_identity()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            lease.read_bounded(1024).unwrap_or_default(),
            b"retained-by-handle"
        );
        assert!(std::fs::remove_file(&path).is_err());
        assert!(std::fs::rename(root.join("Eliot"), root.join("Eliot-renamed")).is_err());
        let identity = lease.identity();
        drop(lease);
        let reopened = test_lease(&root, relative, false)
            .unwrap_or_else(|error| panic!("protected lease reopen failed: {error}"));
        assert_eq!(reopened.identity(), identity);
        assert_eq!(
            reopened.read_bounded(1024).unwrap_or_default(),
            b"retained-by-handle"
        );
        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn protected_root_lease_blocks_parent_substitution_until_drop() {
        let root = std::env::temp_dir().join(format!("eliot-protected-root-{}", unique_suffix()));
        let relative = Path::new("Eliot/installations/fixture/host");
        let retained = root.join(relative);
        let substituted = retained.with_file_name("host-substituted");
        std::fs::create_dir_all(&retained).unwrap_or_else(|_| unreachable!());

        let lease = test_root_lease(&root, relative)
            .unwrap_or_else(|error| panic!("protected root lease open failed: {error}"));
        lease
            .verify_stable_identity()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            lease.canonical_path().unwrap_or_else(|_| unreachable!()),
            retained
        );
        assert!(
            std::fs::rename(&retained, &substituted).is_err(),
            "the retained root must reject path substitution"
        );

        drop(lease);
        std::fs::rename(&retained, &substituted)
            .unwrap_or_else(|error| panic!("rename after lease drop failed: {error}"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn runtime_file_access_is_ba_ls_sy_verify_only_while_legacy_keeps_write_dac() {
        use windows_sys::Win32::Security::{ACCESS_ALLOWED_ACE, GetAce};
        use windows_sys::Win32::Storage::FileSystem::{WRITE_DAC, WRITE_OWNER};

        assert_ne!(legacy_protected_file_access_mode() & WRITE_DAC, 0);
        for access in [
            runtime_file_access_mode(false),
            runtime_file_access_mode(true),
        ] {
            assert_eq!(access & (WRITE_DAC | WRITE_OWNER), 0);
        }

        let descriptor = OwnedSecurityDescriptor::for_installer_system_object(false)
            .unwrap_or_else(|error| panic!("runtime descriptor failed: {error}"));
        assert_eq!(
            sid_to_string(descriptor.owner().unwrap_or_else(|_| unreachable!()))
                .unwrap_or_else(|_| unreachable!()),
            "S-1-5-18"
        );
        let dacl = descriptor.dacl().unwrap_or_else(|_| unreachable!());
        let mut principals = std::collections::BTreeSet::new();
        let ace_count = unsafe { (*dacl).AceCount };
        for index in 0..u32::from(ace_count) {
            let mut ace = std::ptr::null_mut();
            assert_ne!(unsafe { GetAce(dacl, index, &raw mut ace) }, 0);
            assert!(!ace.is_null());
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = (&raw const allowed.SidStart).cast_mut().cast();
            principals.insert(sid_to_string(sid).unwrap_or_else(|_| unreachable!()));
        }
        assert_eq!(
            principals,
            ["S-1-5-18", "S-1-5-19", "S-1-5-32-544"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
    }

    #[cfg(windows)]
    #[test]
    fn protected_path_lease_rejects_directory_and_file_reparse_substitution() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let root =
            std::env::temp_dir().join(format!("eliot-protected-reparse-{}", unique_suffix()));
        let outside = std::env::temp_dir().join(format!(
            "eliot-protected-reparse-outside-{}",
            unique_suffix()
        ));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        std::fs::create_dir(&outside).unwrap_or_else(|_| unreachable!());
        let relative = Path::new("Eliot/host/lease.redb");
        if symlink_dir(&outside, root.join("Eliot")).is_err() {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            return;
        }
        assert!(matches!(
            test_lease(&root, relative, true),
            Err(ProtectedPathError::ReparsePoint | ProtectedPathError::Io)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        std::fs::create_dir_all(root.join("Eliot/host")).unwrap_or_else(|_| unreachable!());
        std::fs::write(outside.join("lease.redb"), b"outside").unwrap_or_else(|_| unreachable!());
        if symlink_file(outside.join("lease.redb"), root.join(relative)).is_err() {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            return;
        }
        assert!(matches!(
            test_lease(&root, relative, false),
            Err(ProtectedPathError::ReparsePoint | ProtectedPathError::Io)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(windows)]
    #[test]
    fn user_owned_portable_dev_root_and_path_roundtrip() {
        let root = std::env::temp_dir().join(format!("eliot-user-owned-{}", unique_suffix()));
        let path = root.join("nested/state.bin");
        std::fs::create_dir_all(path.parent().unwrap_or_else(|| unreachable!()))
            .unwrap_or_else(|_| unreachable!());
        std::fs::write(&path, b"portable-dev").unwrap_or_else(|_| unreachable!());

        let root_lease = UserOwnedRootLease::open_existing(&root)
            .unwrap_or_else(|error| panic!("root lease failed: {error}"));
        let file_lease = UserOwnedPathLease::open_existing(&root_lease, &path)
            .unwrap_or_else(|error| panic!("path lease failed: {error}"));
        assert_eq!(
            file_lease.read_bounded(1024).unwrap_or_default(),
            b"portable-dev"
        );
        root_lease
            .verify_stable_identity()
            .unwrap_or_else(|_| unreachable!());
        file_lease
            .verify_stable_identity()
            .unwrap_or_else(|_| unreachable!());
        file_lease
            .verify_path_identity()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(file_lease.current_user_sid(), root_lease.current_user_sid());

        drop(file_lease);
        drop(root_lease);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn read_only_user_root_lease_fails_closed_without_rewriting_security() {
        let root =
            std::env::temp_dir().join(format!("eliot-user-owned-read-only-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());

        let invalid_before = directory_security_descriptor_bytes(&root);
        assert!(UserOwnedRootReadLease::open_existing(&root).is_err());
        assert_eq!(invalid_before, directory_security_descriptor_bytes(&root));

        drop(
            UserOwnedRootLease::open_existing(&root)
                .unwrap_or_else(|error| panic!("fixture ACL provisioning failed: {error}")),
        );
        let valid_before = directory_security_descriptor_bytes(&root);
        let lease = UserOwnedRootReadLease::open_existing(&root)
            .unwrap_or_else(|error| panic!("read-only lease failed: {error}"));
        assert_eq!(valid_before, directory_security_descriptor_bytes(&root));
        lease
            .verify_stable_identity()
            .unwrap_or_else(|_| unreachable!());

        drop(lease);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn user_owned_portable_dev_rejects_outside_root() {
        let root = std::env::temp_dir().join(format!("eliot-user-owned-root-{}", unique_suffix()));
        let outside =
            std::env::temp_dir().join(format!("eliot-user-owned-outside-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        std::fs::create_dir(&outside).unwrap_or_else(|_| unreachable!());
        let outside_file = outside.join("outside.bin");
        std::fs::write(&outside_file, b"outside").unwrap_or_else(|_| unreachable!());
        let root_lease = UserOwnedRootLease::open_existing(&root)
            .unwrap_or_else(|error| panic!("root lease failed: {error}"));
        assert_eq!(
            UserOwnedPathLease::open_existing(&root_lease, &outside_file).err(),
            Some(ProtectedPathError::InvalidPath)
        );
        drop(root_lease);
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[cfg(windows)]
    #[test]
    fn user_owned_portable_dev_rejects_reparse_path_when_available() {
        use std::os::windows::fs::symlink_dir;

        let root =
            std::env::temp_dir().join(format!("eliot-user-owned-reparse-{}", unique_suffix()));
        let outside = std::env::temp_dir().join(format!(
            "eliot-user-owned-reparse-outside-{}",
            unique_suffix()
        ));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        std::fs::create_dir(&outside).unwrap_or_else(|_| unreachable!());
        if symlink_dir(&outside, root.join("link")).is_err() {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            return;
        }
        let target = root.join("link/state.bin");
        std::fs::write(outside.join("state.bin"), b"must-not-open")
            .unwrap_or_else(|_| unreachable!());
        let root_lease = UserOwnedRootLease::open_existing(&root)
            .unwrap_or_else(|error| panic!("root lease failed: {error}"));
        assert!(matches!(
            UserOwnedPathLease::open_existing(&root_lease, &target),
            Err(ProtectedPathError::ReparsePoint | ProtectedPathError::Io)
        ));
        drop(root_lease);
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[cfg(windows)]
    #[test]
    fn user_owned_portable_dev_bounded_read_rejects_oversize() {
        let root = std::env::temp_dir().join(format!("eliot-user-owned-limit-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let path = root.join("state.bin");
        std::fs::write(&path, b"1234").unwrap_or_else(|_| unreachable!());
        let root_lease = UserOwnedRootLease::open_existing(&root)
            .unwrap_or_else(|error| panic!("root lease failed: {error}"));
        let file_lease = UserOwnedPathLease::open_existing(&root_lease, &path)
            .unwrap_or_else(|error| panic!("path lease failed: {error}"));
        assert_eq!(
            file_lease.read_bounded(3).err(),
            Some(ProtectedPathError::SizeExceeded)
        );
        drop(file_lease);
        drop(root_lease);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    fn wait_for_marker(marker: &Path) {
        for _ in 0..100 {
            if marker.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("child marker did not appear: {}", marker.display());
    }

    #[cfg(windows)]
    #[test]
    fn reopened_job_member_uses_exact_job_and_member_termination_preserves_root() {
        let _spawn_guard = process_job_spawn_test_guard();
        let root =
            std::env::temp_dir().join(format!("eliot-existing-job-member-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let root_marker = root.join("root");
        let member_marker = root.join("member");
        let root_child = spawn_suspended_child(&root_marker, &root, false);
        let running_root = root_child
            .validate::<(), &'static str, _>(|_| Ok(()))
            .unwrap_or_else(|_| unreachable!())
            .resume()
            .unwrap_or_else(|_| unreachable!());
        wait_for_marker(&root_marker);
        let binding = running_root.evidence().recoverable_job_binding();
        let recovered = RecoverableJobObject::open(binding)
            .unwrap_or_else(|error| panic!("exact Job reopen failed: {error}"));
        let root_job = running_root.job_identity().clone();
        let member = recovered
            .spawn_member(suspended_spec(&member_marker, &root, false))
            .unwrap_or_else(|error| panic!("member spawn failed: {error}"));
        let member_pid = member.id();
        let validated = member
            .validate::<(), &'static str, _>(|evidence| {
                assert_eq!(evidence.job_identity(), &root_job);
                assert!(evidence.job_process_count() >= 2);
                assert_ne!(
                    evidence.process().process_id,
                    running_root.evidence().process().process_id
                );
                assert_ne!(evidence.executable_file_identity().file_index, 0);
                Ok(())
            })
            .unwrap_or_else(|_| unreachable!());
        let running_member = validated
            .resume()
            .unwrap_or_else(|error| panic!("member resume failed: {error}"));
        wait_for_marker(&member_marker);
        assert_eq!(running_member.job_identity(), &root_job);
        assert!(matches!(
            running_root.observe().unwrap_or_else(|_| unreachable!()),
            RunningJobObservation::Running { active_processes } if active_processes >= 2
        ));
        let terminal = running_member
            .terminate(0xE1_31)
            .unwrap_or_else(|error| panic!("member termination failed: {error}"));
        assert_eq!(terminal.process().process_id, member_pid);
        assert_eq!(terminal.requested_exit_code(), 0xE1_31);
        assert!(terminal.remaining_job_members() >= 1);
        assert!(wait_for_process_gone(member_pid));
        assert!(matches!(
            running_root.observe().unwrap_or_else(|_| unreachable!()),
            RunningJobObservation::Running { active_processes } if active_processes >= 1
        ));
        running_root
            .terminate(0xE132)
            .unwrap_or_else(|error| panic!("root termination failed: {error}"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn existing_job_member_rejection_and_validator_panic_preserve_root() {
        let _spawn_guard = process_job_spawn_test_guard();
        let root =
            std::env::temp_dir().join(format!("eliot-existing-job-reject-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let root_marker = root.join("root");
        let root_child = spawn_suspended_child(&root_marker, &root, false);
        let running_root = root_child
            .validate::<(), &'static str, _>(|_| Ok(()))
            .unwrap_or_else(|_| unreachable!())
            .resume()
            .unwrap_or_else(|_| unreachable!());
        wait_for_marker(&root_marker);
        let recovered =
            RecoverableJobObject::open(running_root.evidence().recoverable_job_binding())
                .unwrap_or_else(|_| unreachable!());

        let rejected_marker = root.join("rejected");
        let rejected = recovered
            .spawn_member(suspended_spec(&rejected_marker, &root, false))
            .unwrap_or_else(|_| unreachable!());
        let rejected_pid = rejected.id();
        let result = rejected.validate::<(), &'static str, _>(|evidence| {
            assert!(evidence.process().start_time_100ns != 0);
            Err("wrong-image-or-policy")
        });
        assert_eq!(
            result.err(),
            Some(SuspendedValidationError::Rejected("wrong-image-or-policy"))
        );
        assert!(wait_for_process_gone(rejected_pid));
        assert!(
            running_root
                .active_process_count()
                .unwrap_or_else(|_| unreachable!())
                >= 1
        );

        let panic_marker = root.join("panic");
        let panicking = recovered
            .spawn_member(suspended_spec(&panic_marker, &root, false))
            .unwrap_or_else(|_| unreachable!());
        let panic_pid = panicking.id();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = panicking.validate::<(), (), _>(|_| panic!("member validator panic"));
        }));
        assert!(panic.is_err());
        assert!(wait_for_process_gone(panic_pid));
        assert!(
            running_root
                .active_process_count()
                .unwrap_or_else(|_| unreachable!())
                >= 1
        );
        assert!(matches!(
            running_root.observe().unwrap_or_else(|_| unreachable!()),
            RunningJobObservation::Running { active_processes } if active_processes >= 1
        ));
        running_root
            .terminate(0xE1_33)
            .unwrap_or_else(|_| unreachable!());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn whole_job_termination_reaps_reopened_member_and_reopen_can_launch_again() {
        let _spawn_guard = process_job_spawn_test_guard();
        let root =
            std::env::temp_dir().join(format!("eliot-existing-job-reap-{}", unique_suffix()));
        std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
        let root_marker = root.join("root");
        let first_marker = root.join("first");
        let second_marker = root.join("second");
        let root_child = spawn_suspended_child(&root_marker, &root, false);
        let running_root = root_child
            .validate::<(), &'static str, _>(|_| Ok(()))
            .unwrap_or_else(|_| unreachable!())
            .resume()
            .unwrap_or_else(|_| unreachable!());
        wait_for_marker(&root_marker);
        let binding = running_root.evidence().recoverable_job_binding();
        let recovered =
            RecoverableJobObject::open(binding.clone()).unwrap_or_else(|_| unreachable!());
        let first = recovered
            .spawn_member(suspended_spec(&first_marker, &root, false))
            .unwrap_or_else(|_| unreachable!())
            .validate::<(), &'static str, _>(|_| Ok(()))
            .unwrap_or_else(|_| unreachable!())
            .resume()
            .unwrap_or_else(|_| unreachable!());
        let first_pid = first.process().process_id;
        wait_for_marker(&first_marker);
        running_root
            .terminate(0xE1_34)
            .unwrap_or_else(|error| panic!("whole Job termination failed: {error}"));
        assert!(wait_for_process_gone(first_pid));
        assert!(matches!(
            first.observe().unwrap_or_else(|_| unreachable!()),
            ExistingJobMemberObservation::Exited {
                active_processes: 0,
                ..
            }
        ));

        let root_child = spawn_suspended_child(&root_marker, &root, false);
        let replacement_root = root_child
            .validate::<(), &'static str, _>(|_| Ok(()))
            .unwrap_or_else(|_| unreachable!())
            .resume()
            .unwrap_or_else(|_| unreachable!());
        wait_for_marker(&root_marker);
        let replacement_recovered =
            RecoverableJobObject::open(replacement_root.evidence().recoverable_job_binding())
                .unwrap_or_else(|_| unreachable!());
        let replacement = replacement_recovered
            .spawn_member(suspended_spec(&second_marker, &root, false))
            .unwrap_or_else(|_| unreachable!())
            .validate::<(), &'static str, _>(|_| Ok(()))
            .unwrap_or_else(|_| unreachable!())
            .resume()
            .unwrap_or_else(|_| unreachable!());
        wait_for_marker(&second_marker);
        replacement
            .terminate(0xE1_35)
            .unwrap_or_else(|_| unreachable!());
        replacement_root
            .terminate(0xE1_36)
            .unwrap_or_else(|_| unreachable!());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    fn test_owner_lease(authority: Arc<HostLeaseAuthority>) -> HostOwnerLease {
        HostOwnerLease {
            handle: std::ptr::null_mut(),
            owns: true,
            name: "test-host-owner".to_owned(),
            authority,
        }
    }

    #[cfg(windows)]
    #[test]
    fn host_epoch_capability_is_revoked_by_release_and_drop() {
        let authority = Arc::new(HostLeaseAuthority::default());
        let mut lease = test_owner_lease(Arc::clone(&authority));
        let capability = lease.activation_capability();
        let guard = capability.live_guard().unwrap_or_else(|_| unreachable!());
        drop(guard);
        lease.release().unwrap_or_else(|_| unreachable!());
        assert_eq!(
            capability.live_guard().err(),
            Some(WindowsAdapterError::IdentityMismatch)
        );
    }

    #[cfg(windows)]
    #[test]
    fn credential_capability_is_revoked_by_release_and_drop() {
        let authority = Arc::new(HostLeaseAuthority::default());
        let mut lease = test_owner_lease(Arc::clone(&authority));
        let capability = lease
            .credential_mutation_capability()
            .unwrap_or_else(|_| unreachable!());
        capability
            .with_authority(|| Ok::<_, WindowsAdapterError>(()))
            .unwrap_or_else(|_| unreachable!());
        lease.release().unwrap_or_else(|_| unreachable!());
        assert_eq!(
            capability.with_authority(|| Ok::<_, WindowsAdapterError>(())),
            Err(WindowsAdapterError::IdentityMismatch)
        );
    }

    #[cfg(windows)]
    #[test]
    fn host_epoch_release_waits_for_in_flight_mutation_guard() {
        use std::sync::Barrier;

        let authority = Arc::new(HostLeaseAuthority::default());
        let mut lease = test_owner_lease(Arc::clone(&authority));
        let capability = lease.activation_capability();
        let entered = Arc::new(Barrier::new(2));
        let entered_worker = Arc::clone(&entered);
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let _guard = capability.live_guard().unwrap_or_else(|_| unreachable!());
                entered_worker.wait();
                std::thread::sleep(std::time::Duration::from_millis(100));
            });
            entered.wait();
            let started = std::time::Instant::now();
            lease.release().unwrap_or_else(|_| unreachable!());
            assert!(started.elapsed() >= std::time::Duration::from_millis(75));
        });
    }

    #[cfg(windows)]
    #[test]
    fn credential_release_waits_for_in_flight_authority_operation() {
        use std::sync::Barrier;

        let authority = Arc::new(HostLeaseAuthority::default());
        let mut lease = test_owner_lease(Arc::clone(&authority));
        let capability = lease
            .credential_mutation_capability()
            .unwrap_or_else(|_| unreachable!());
        let entered = Arc::new(Barrier::new(2));
        let entered_worker = Arc::clone(&entered);
        std::thread::scope(|scope| {
            scope.spawn(move || {
                capability
                    .with_authority(|| {
                        entered_worker.wait();
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        Ok::<_, WindowsAdapterError>(())
                    })
                    .unwrap_or_else(|_| unreachable!());
            });
            entered.wait();
            let started = std::time::Instant::now();
            lease.release().unwrap_or_else(|_| unreachable!());
            assert!(started.elapsed() >= std::time::Duration::from_millis(75));
        });
    }
}
