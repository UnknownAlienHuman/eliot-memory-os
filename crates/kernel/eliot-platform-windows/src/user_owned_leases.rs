//! User-owned filesystem lease closure for handle-derived identity and containment.
//!
//! This private child owns only physical Windows handle-derived
//! identity/containment/no-follow/DACL-protected user-owned lease mechanics.
//! It owns no semantic acceptance, SCM, process lifecycle, secret, retry/default,
//! installation, durable-write, policy, or canonical-authority decisions; the
//! facade/control plane remains outside this module.
//!
//! Normative anchors (verified in this worktree):
//! - Architecture `A2.3`, `A12.2`, `ARCH-MOD-01`, `ARCH-MOD-02`, and
//!   `ARCH-PORT-01` in `docs/normative/ELIOT_ARCHITECTURE.md`.
//! - Implementation `I2.2`, `I2.23`, and `I6.15` in
//!   `docs/normative/ELIOT_IMPLEMENTATION.md`.

#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::process_identity::FileIdentity;
use crate::protected_path::ProtectedPathError;

/// A user-owned `portable_dev` root lease.
///
/// This contour is intentionally separate from [`crate::ProtectedPathLease`]: it is
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
            let path = crate::protected_path::canonical_windows_path(&declared)?;
            if !path.is_absolute() {
                return Err(ProtectedPathError::InvalidRoot);
            }
            crate::reject_reparse_chain(&path, true)?;
            let sid = current_process_sid()?;
            let handle = open_user_owned_directory_read_only(&path, &sid)?;
            let identity = crate::process_identity::file_identity_from_handle(&handle)
                .map_err(|_| ProtectedPathError::Io)?;
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
            crate::final_windows_path_from_handle(&self.handle)
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
            let identity = crate::process_identity::file_identity_from_handle(&self.handle)
                .map_err(|_| ProtectedPathError::Io)?;
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

    #[cfg(windows)]
    pub(super) fn into_handle(self) -> std::fs::File {
        self.handle
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
            let identity = crate::process_identity::file_identity_from_handle(&handle)
                .map_err(|_| ProtectedPathError::Io)?;
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
            crate::final_windows_path_from_handle(&self.handle)
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
            let identity = crate::process_identity::file_identity_from_handle(&self.handle)
                .map_err(|_| ProtectedPathError::Io)?;
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
/// The file must already exist. The retained root, every parent directory,
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
            let identity = crate::process_identity::file_identity_from_handle(&file)
                .map_err(|_| ProtectedPathError::Io)?;
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
            let identity = crate::process_identity::file_identity_from_handle(&self.file)
                .map_err(|_| ProtectedPathError::Io)?;
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
            let identity = crate::process_identity::file_identity_from_handle(&file)
                .map_err(|_| ProtectedPathError::Io)?;
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
    crate::reject_reparse_chain(root, true)?;
    crate::validate_directory_no_reparse(root)?;
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
pub(crate) fn current_process_sid() -> Result<String, ProtectedPathError> {
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(ProtectedPathError::AclMismatch);
    }
    let result = crate::process_identity::token_identity(token)
        .map(|(sid, _)| sid)
        .map_err(|_| ProtectedPathError::AclMismatch);
    unsafe { windows_sys::Win32::Foundation::CloseHandle(token) };
    result
}

#[cfg(not(windows))]
pub(crate) fn current_process_sid() -> Result<String, ProtectedPathError> {
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
pub(super) fn open_user_owned_directory_read_only_contour(
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
pub(super) fn open_user_owned_file_read_only(
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
pub(crate) fn protect_user_owned_opened_handle(
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
    if !crate::valid_sid_text(sid) {
        return Err(ProtectedPathError::AclMismatch);
    }
    let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    if directory != metadata.is_dir() {
        return Err(ProtectedPathError::InvalidPath);
    }
    let expected = crate::OwnedSecurityDescriptor::for_user_owned_storage(sid, directory)
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
    let owner_matches = crate::sid_to_string(observed_owner).is_ok_and(|observed| observed == sid);
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

    if !crate::valid_sid_text(sid) {
        return Err(ProtectedPathError::AclMismatch);
    }
    let expected = crate::OwnedSecurityDescriptor::for_user_owned_storage(sid, true)
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
    let owner_matches = crate::sid_to_string(owner).is_ok_and(|observed| observed == sid);
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
