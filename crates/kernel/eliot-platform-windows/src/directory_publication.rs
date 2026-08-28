//! Handle-bound create-new directory publication for the Windows platform contour.
//!
//! Architecture anchors (eliot-architecture-docs-fa941135): A2.3,
//! ARCH-MOD-02, A12.1, ARCH-SEC-01, A13.1, ARCH-RES-01, A13.6, A13.9,
//! and ARCH-ORD-01. This module owns one independently understandable
//! physical publication capability: retained no-follow parent handles,
//! create-new staging, identity fences, handle-relative no-replace rename,
//! and typed post-commit reconciliation.
//!
//! Implementation anchors (eliot-architecture-docs-fa941135): I2.2, I2.15,
//! I2.23, I3.15, and I5.23. The implementation remains a normal Rust module
//! because its public contract is part of this crate and its native contour
//! is tightly coupled to shared platform identity/path primitives.
//!
//! The module does not own installer authority, package manifest or inventory
//! policy, process/job lifecycle, protected-path ACL policy, service/pipe ACL,
//! secret storage, canonical state, or semantic transitions. The
//! `trusted_source_bundle` method is only a narrow delegated bridge to the
//! package-staging owner for retained source observation; it does not transfer
//! package-staging authority here. Unknown post-commit outcomes remain typed
//! and reconcilable rather than being converted into success or pre-commit
//! errors.

use std::path::{Path, PathBuf};

use crate::package_staging;
use crate::{
    FileIdentity, OwnedSecurityDescriptor, PackageStagingError, TrustedSourceBundle,
    file_identity_from_handle, final_windows_path_from_handle, validate_package_relative_path,
    windows_paths_equal,
};

#[path = "directory_publication_models.rs"]
mod directory_publication_models;
pub use directory_publication_models::{
    DirectoryPublicationError, DirectoryPublicationOutcome, DirectoryPublicationReceipt,
    DirectoryPublicationUnknown, DirectoryPublicationUnknownReceipt,
};

/// Prepared process-owned create-new directory publication.
///
/// Construction retains the complete destination-parent contour through
/// no-follow, no-delete-sharing handles *before* it creates the same-parent
/// temporary directory. The contour remains live while the caller fills and
/// reads back the temporary tree, and until publication or rollback finishes.
pub struct OwnedDirectoryPublication {
    temporary: PathBuf,
    temporary_name: String,
    destination: PathBuf,
    canonical_parent: PathBuf,
    parent_identity: FileIdentity,
    initial_temporary_identity: FileIdentity,
    #[cfg(windows)]
    contour: DirectoryPublicationContour,
    /// The source directory object is retained from native create through the
    /// handle-relative rename.  It is opened no-follow without delete
    /// sharing, so same-token pathname rename/delete attempts cannot replace
    /// the object while the materializer writes and observes it.
    #[cfg(windows)]
    temporary_handle: Option<std::fs::File>,
    committed: bool,
}

impl std::fmt::Debug for OwnedDirectoryPublication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedDirectoryPublication")
            .field("temporary", &self.temporary)
            .field("temporary_name", &self.temporary_name)
            .field("destination", &self.destination)
            .field("canonical_parent", &self.canonical_parent)
            .field("parent_identity", &self.parent_identity)
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

    /// Reopen the exact previously prepared temporary directory recorded by
    /// a durable publication intent.
    ///
    /// The retained destination-parent contour is opened first. The temporary
    /// child is then opened relative to that retained parent with `DELETE`
    /// authority and without delete sharing, so a successful retry can issue
    /// the same handle-relative, no-replace move as a fresh publication.
    ///
    /// # Errors
    ///
    /// Returns a typed error when any path, name, parent identity, temporary
    /// identity, reparse, same-parent, or destination-absence invariant is not
    /// exactly satisfied, or on a non-Windows platform.
    pub fn resume(
        destination: &Path,
        temporary: &Path,
        temporary_name: &str,
        expected_parent_identity: FileIdentity,
        expected_temporary_identity: FileIdentity,
    ) -> Result<Self, DirectoryPublicationError> {
        #[cfg(windows)]
        {
            resume_owned_directory_publication(
                destination,
                temporary,
                temporary_name,
                expected_parent_identity,
                expected_temporary_identity,
            )
        }
        #[cfg(not(windows))]
        {
            let _ = (
                destination,
                temporary,
                temporary_name,
                expected_parent_identity,
                expected_temporary_identity,
            );
            Err(DirectoryPublicationError::UnsupportedPlatform)
        }
    }

    /// Exact absolute temporary directory held below the retained parent.
    #[must_use]
    pub fn temporary_path(&self) -> &Path {
        &self.temporary
    }

    /// Exact same-parent temporary leaf retained by the publication.
    #[must_use]
    pub fn temporary_name(&self) -> &str {
        &self.temporary_name
    }

    /// Canonical retained destination-parent path.
    #[must_use]
    pub fn canonical_parent_path(&self) -> &Path {
        &self.canonical_parent
    }

    /// Identity of the retained destination parent.
    #[must_use]
    pub const fn parent_identity(&self) -> FileIdentity {
        self.parent_identity
    }

    /// Identity captured immediately after create-new temporary allocation.
    #[must_use]
    pub const fn temporary_identity(&self) -> FileIdentity {
        self.initial_temporary_identity
    }

    /// Reuse the retained temporary-root handle for a trusted pre-commit
    /// source observation without reopening the mutable pathname.  The
    /// publication root carries DELETE access for the eventual native rename;
    /// cloning this handle preserves its no-delete-sharing fence.
    ///
    /// # Errors
    ///
    /// Returns a typed staging error when the retained handle cannot be
    /// cloned, revalidated, or bound to the exact source-root contour.
    pub fn trusted_source_bundle(&self) -> Result<TrustedSourceBundle, PackageStagingError> {
        #[cfg(windows)]
        {
            let root = self
                .temporary_handle
                .as_ref()
                .ok_or(PackageStagingError::IdentityMismatch)?;
            package_staging::retain_source_directory_with_retained_root(&self.temporary, root)
        }
        #[cfg(not(windows))]
        {
            Err(PackageStagingError::UnsupportedPlatform)
        }
    }

    /// Atomically rename the completely materialized temporary directory to
    /// the absent destination through the retained handles, with no
    /// replacement semantics.
    ///
    /// The supplied identity must be independently measured by the caller's
    /// complete pre-commit readback. A successful Windows rename is never
    /// reported as `Err`; uncertain post-commit readback returns a typed
    /// reconcilable outcome.
    ///
    /// # Errors
    ///
    /// Returns only pre-commit path, destination-race, identity or I/O errors.
    pub fn publish(
        self,
        precommit_temporary_identity: FileIdentity,
    ) -> Result<DirectoryPublicationOutcome, DirectoryPublicationError> {
        #[cfg(windows)]
        {
            let mut publication = self;
            publication.publish_inner(precommit_temporary_identity, || {}, None)
        }
        #[cfg(not(windows))]
        {
            let _ = (self, precommit_temporary_identity);
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

#[cfg(windows)]
pub(crate) struct DirectoryPublicationContour {
    entries: Vec<(PathBuf, FileIdentity, std::fs::File)>,
    pub(crate) canonical_parent: PathBuf,
    parent_identity: FileIdentity,
}

#[cfg(windows)]
pub(crate) fn validate_directory_publication_absolute(
    path: &Path,
) -> Result<(), DirectoryPublicationError> {
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
    let prefix = format!(".{destination_name}.tmp.");
    let Some(suffix) = temporary_name.strip_prefix(&prefix) else {
        return Err(DirectoryPublicationError::InvalidPath);
    };
    let Some((pid, index)) = suffix.split_once('.') else {
        return Err(DirectoryPublicationError::InvalidPath);
    };
    let Ok(pid_value) = pid.parse::<u32>() else {
        return Err(DirectoryPublicationError::InvalidPath);
    };
    let Ok(index_value) = index.parse::<u32>() else {
        return Err(DirectoryPublicationError::InvalidPath);
    };
    if pid_value == 0
        || index_value >= 64
        || pid != pid_value.to_string()
        || index != index_value.to_string()
    {
        return Err(DirectoryPublicationError::InvalidPath);
    }
    Ok(())
}

#[cfg(windows)]
fn open_publication_directory(
    path: &Path,
    share_delete: bool,
) -> Result<std::fs::File, DirectoryPublicationError> {
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
    open_publication_directory_with_access(path, share_delete, FILE_GENERIC_READ)
}

#[cfg(windows)]
fn open_publication_directory_for_create(
    path: &Path,
) -> Result<std::fs::File, DirectoryPublicationError> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_ADD_SUBDIRECTORY, FILE_GENERIC_READ};
    open_publication_directory_with_access(path, false, FILE_GENERIC_READ | FILE_ADD_SUBDIRECTORY)
}

#[cfg(windows)]
fn open_publication_directory_with_access(
    path: &Path,
    share_delete: bool,
    access: u32,
) -> Result<std::fs::File, DirectoryPublicationError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let share_mode =
        FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(access)
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
#[repr(C)]
struct NativeUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[cfg(windows)]
#[repr(C)]
struct NativeObjectAttributes {
    length: u32,
    root_directory: windows_sys::Win32::Foundation::HANDLE,
    object_name: *mut NativeUnicodeString,
    attributes: u32,
    security_descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    security_quality_of_service: *mut std::ffi::c_void,
}

#[cfg(windows)]
#[repr(C)]
struct NativeIoStatusBlock {
    status: i32,
    information: usize,
}

#[cfg(windows)]
#[repr(C)]
struct NativeFileRenameInformation {
    replace_if_exists: u8,
    padding: [u8; 7],
    root_directory: windows_sys::Win32::Foundation::HANDLE,
    file_name_length: u32,
    file_name: [u16; 1],
}

#[cfg(windows)]
const NATIVE_STATUS_OBJECT_NAME_COLLISION: i32 = -0x3FFF_FFCB;

#[cfg(windows)]
const NATIVE_STATUS_OBJECT_NAME_EXISTS: i32 = 0x4000_0000;

#[cfg(windows)]
const NATIVE_FILE_CREATE: u32 = 2;

#[cfg(windows)]
const NATIVE_FILE_OPEN: u32 = 1;

#[cfg(windows)]
const NATIVE_FILE_DIRECTORY_FILE: u32 = 0x0000_0001;

#[cfg(windows)]
const NATIVE_FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;

#[cfg(windows)]
const NATIVE_FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

#[cfg(windows)]
const NATIVE_OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;

#[cfg(windows)]
const NATIVE_FILE_RENAME_INFORMATION: i32 = 10;

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut windows_sys::Win32::Foundation::HANDLE,
        desired_access: u32,
        object_attributes: *mut NativeObjectAttributes,
        io_status_block: *mut NativeIoStatusBlock,
        allocation_size: *mut i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut std::ffi::c_void,
        ea_length: u32,
    ) -> i32;

    fn NtSetInformationFile(
        file_handle: windows_sys::Win32::Foundation::HANDLE,
        io_status_block: *mut NativeIoStatusBlock,
        file_information: *mut std::ffi::c_void,
        length: u32,
        file_information_class: i32,
    ) -> i32;
}

#[cfg(windows)]
fn native_status_is_success(status: i32) -> bool {
    status >= 0
}

#[cfg(windows)]
fn native_directory_name(name: &str) -> Result<Vec<u16>, DirectoryPublicationError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.encode_utf16().count() > usize::from(u16::MAX / 2)
    {
        return Err(DirectoryPublicationError::InvalidPath);
    }
    if name
        .chars()
        .any(|character| character == '\0' || character == '/' || character == '\\')
    {
        return Err(DirectoryPublicationError::InvalidPath);
    }
    Ok(name.encode_utf16().collect())
}

#[cfg(windows)]
pub(crate) fn create_owned_directory_relative(
    parent: &std::fs::File,
    name: &str,
    security_descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> Result<std::fs::File, DirectoryPublicationError> {
    use std::os::windows::{fs::MetadataExt, io::FromRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let name = native_directory_name(name)?;
    let length = u16::try_from(name.len().saturating_mul(2))
        .map_err(|_| DirectoryPublicationError::InvalidPath)?;
    let mut unicode = NativeUnicodeString {
        length,
        maximum_length: length,
        buffer: name.as_ptr().cast_mut(),
    };
    let mut attributes = NativeObjectAttributes {
        length: u32::try_from(std::mem::size_of::<NativeObjectAttributes>())
            .map_err(|_| DirectoryPublicationError::Io)?,
        root_directory: {
            use std::os::windows::io::AsRawHandle;
            parent.as_raw_handle().cast()
        },
        object_name: &raw mut unicode,
        attributes: NATIVE_OBJ_CASE_INSENSITIVE,
        // Native create does not accept every caller-owned absolute owner
        // descriptor through OBJECT_ATTRIBUTES (STATUS_INVALID_OWNER on
        // ordinary developer tokens).  Apply the exact descriptor to the
        // returned handle immediately below, before exposing it to callers.
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut io_status = NativeIoStatusBlock {
        status: 0,
        information: 0,
    };
    let mut raw = std::ptr::null_mut();
    let mut desired_access = FILE_GENERIC_READ | FILE_ADD_SUBDIRECTORY | DELETE;
    if !security_descriptor.is_null() {
        desired_access |= windows_sys::Win32::Storage::FileSystem::WRITE_DAC
            | windows_sys::Win32::Storage::FileSystem::WRITE_OWNER;
    }
    let status = unsafe {
        // SAFETY: all native structures and UTF-16 storage remain live for
        // the synchronous call; RootDirectory is a retained no-follow
        // parent handle and FILE_CREATE forbids adoption.
        NtCreateFile(
            &raw mut raw,
            desired_access,
            &raw mut attributes,
            &raw mut io_status,
            std::ptr::null_mut(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NATIVE_FILE_CREATE,
            NATIVE_FILE_DIRECTORY_FILE
                | NATIVE_FILE_OPEN_REPARSE_POINT
                | NATIVE_FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null_mut(),
            0,
        )
    };
    if !native_status_is_success(status) {
        if status == NATIVE_STATUS_OBJECT_NAME_COLLISION
            || status == NATIVE_STATUS_OBJECT_NAME_EXISTS
        {
            return Err(DirectoryPublicationError::AlreadyExists);
        }
        return Err(DirectoryPublicationError::Io);
    }
    if raw.is_null() {
        return Err(DirectoryPublicationError::Io);
    }
    let file = unsafe {
        // SAFETY: NtCreateFile returned a unique owned handle.
        std::fs::File::from_raw_handle(raw.cast())
    };
    let result = (|| {
        apply_owned_directory_security(&file, security_descriptor)?;
        let metadata = file.metadata().map_err(|_| DirectoryPublicationError::Io)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(DirectoryPublicationError::ReparsePoint);
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok(file),
        Err(error) => {
            // The native create was create-only and returned the exact child
            // handle.  If post-create ACL/identity validation fails, make a
            // best-effort handle-bound disposition before dropping it; never
            // resolve the pathname for cleanup or adopt the failed directory.
            let _ = delete_created_directory_handle(&file);
            Err(error)
        }
    }
}

#[cfg(windows)]
pub(crate) fn open_owned_directory_relative(
    parent: &std::fs::File,
    name: &str,
) -> Result<std::fs::File, DirectoryPublicationError> {
    use std::os::windows::{fs::MetadataExt, io::FromRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let name = native_directory_name(name)?;
    let length = u16::try_from(name.len().saturating_mul(2))
        .map_err(|_| DirectoryPublicationError::InvalidPath)?;
    let mut unicode = NativeUnicodeString {
        length,
        maximum_length: length,
        buffer: name.as_ptr().cast_mut(),
    };
    let mut attributes = NativeObjectAttributes {
        length: u32::try_from(std::mem::size_of::<NativeObjectAttributes>())
            .map_err(|_| DirectoryPublicationError::Io)?,
        root_directory: {
            use std::os::windows::io::AsRawHandle;
            parent.as_raw_handle().cast()
        },
        object_name: &raw mut unicode,
        attributes: NATIVE_OBJ_CASE_INSENSITIVE,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut io_status = NativeIoStatusBlock {
        status: 0,
        information: 0,
    };
    let mut raw = std::ptr::null_mut();
    let status = unsafe {
        // SAFETY: all native buffers remain live for the synchronous call;
        // RootDirectory is the retained destination parent and FILE_OPEN
        // forbids creating or adopting a different child.
        NtCreateFile(
            &raw mut raw,
            FILE_GENERIC_READ | DELETE,
            &raw mut attributes,
            &raw mut io_status,
            std::ptr::null_mut(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NATIVE_FILE_OPEN,
            NATIVE_FILE_DIRECTORY_FILE
                | NATIVE_FILE_OPEN_REPARSE_POINT
                | NATIVE_FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null_mut(),
            0,
        )
    };
    if !native_status_is_success(status) || raw.is_null() {
        return Err(DirectoryPublicationError::Io);
    }
    let file = unsafe {
        // SAFETY: NtCreateFile returned a unique owned handle.
        std::fs::File::from_raw_handle(raw.cast())
    };
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
fn apply_owned_directory_security(
    file: &std::fs::File,
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> Result<(), DirectoryPublicationError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    if descriptor.is_null() {
        return Ok(());
    }
    let descriptor = std::mem::ManuallyDrop::new(OwnedSecurityDescriptor { raw: descriptor });
    let owner = descriptor
        .owner()
        .map_err(|_| DirectoryPublicationError::Io)?;
    let dacl = descriptor
        .dacl()
        .map_err(|_| DirectoryPublicationError::Io)?;
    let status = unsafe {
        // SAFETY: `file` is a live handle opened with WRITE_DAC/WRITE_OWNER;
        // owner and DACL point into the caller-owned descriptor and remain
        // live for this synchronous operation.
        SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(DirectoryPublicationError::Win32 { code: status })
    }
}

#[cfg(windows)]
fn delete_created_directory_handle(file: &std::fs::File) -> Result<(), DirectoryPublicationError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let ok = unsafe {
        // SAFETY: `file` is the exact create-only directory handle and was
        // opened with DELETE; the disposition buffer has the documented size.
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                .map_err(|_| DirectoryPublicationError::Io)?,
        )
    };
    if ok == 0 {
        Err(DirectoryPublicationError::Io)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn retain_directory_publication_contour(
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
    let parent_path = entries
        .last()
        .map(|(path, _, _)| path.clone())
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    let parent_handle = open_publication_directory_for_create(&parent_path)?;
    if let Some((_, _, handle)) = entries.last_mut() {
        *handle = parent_handle;
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
pub(crate) fn verify_directory_publication_contour(
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
pub(crate) fn rename_directory_from_handle(
    source: &std::fs::File,
    destination_parent: &std::fs::File,
    destination_name: &str,
) -> Result<(), DirectoryPublicationError> {
    use std::os::windows::io::AsRawHandle;

    let name = native_directory_name(destination_name)?;
    let name_bytes = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    let header_bytes = std::mem::size_of::<NativeFileRenameInformation>()
        .checked_sub(std::mem::size_of::<u16>())
        .ok_or(DirectoryPublicationError::Io)?;
    let total_bytes = header_bytes
        .checked_add(name_bytes)
        .ok_or(DirectoryPublicationError::Io)?;
    let word_count = total_bytes
        .checked_add(std::mem::size_of::<usize>() - 1)
        .ok_or(DirectoryPublicationError::Io)?
        / std::mem::size_of::<usize>();
    let mut storage = vec![0_usize; word_count];
    let info = storage.as_mut_ptr().cast::<NativeFileRenameInformation>();
    unsafe {
        // SAFETY: `storage` is allocator-aligned for the repr(C) header and
        // has enough initialized capacity for the header plus UTF-16 name.
        (*info).replace_if_exists = 0;
        (*info).padding = [0; 7];
        (*info).root_directory = destination_parent.as_raw_handle().cast();
        (*info).file_name_length =
            u32::try_from(name_bytes).map_err(|_| DirectoryPublicationError::InvalidPath)?;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).file_name.as_mut_ptr(), name.len());
    }
    let mut io_status = NativeIoStatusBlock {
        status: 0,
        information: 0,
    };
    let status = unsafe {
        // SAFETY: source and destination parent are retained live handles;
        // the rename buffer is valid for the synchronous native call.
        NtSetInformationFile(
            source.as_raw_handle().cast(),
            &raw mut io_status,
            info.cast(),
            u32::try_from(total_bytes).map_err(|_| DirectoryPublicationError::Io)?,
            NATIVE_FILE_RENAME_INFORMATION,
        )
    };
    if native_status_is_success(status) {
        return Ok(());
    }
    if status == NATIVE_STATUS_OBJECT_NAME_COLLISION || status == NATIVE_STATUS_OBJECT_NAME_EXISTS {
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

    let parent = contour
        .entries
        .last()
        .map(|(_, _, handle)| handle)
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    for index in 0_u32..64 {
        let temporary_name = format!(".{destination_name}.tmp.{}.{}", std::process::id(), index);
        let temporary = contour.canonical_parent.join(&temporary_name);
        let source =
            match create_owned_directory_relative(parent, &temporary_name, std::ptr::null_mut()) {
                Ok(source) => source,
                Err(DirectoryPublicationError::AlreadyExists) => continue,
                Err(error) => return Err(error),
            };
        let prepared = (|| {
            validate_owned_temporary_name(&temporary, &canonical_destination)?;
            verify_directory_publication_contour(&contour)?;
            require_directory_publication_absent(&canonical_destination)?;
            let source_path = final_windows_path_from_handle(&source)
                .map_err(|_| DirectoryPublicationError::Io)?;
            let source_identity =
                file_identity_from_handle(&source).map_err(|_| DirectoryPublicationError::Io)?;
            if !windows_paths_equal(&source_path, &temporary)
                || source_identity.volume_serial_number == 0
                || source_identity.file_index == 0
            {
                return Err(DirectoryPublicationError::IdentityMismatch);
            }
            Ok(OwnedDirectoryPublication {
                temporary: source_path,
                temporary_name,
                destination: canonical_destination.clone(),
                canonical_parent: contour.canonical_parent.clone(),
                parent_identity: contour.parent_identity,
                initial_temporary_identity: source_identity,
                contour,
                temporary_handle: Some(source),
                committed: false,
            })
        })();
        return prepared;
    }
    Err(DirectoryPublicationError::Io)
}

#[cfg(windows)]
fn resume_owned_directory_publication(
    destination: &Path,
    temporary: &Path,
    temporary_name: &str,
    expected_parent_identity: FileIdentity,
    expected_temporary_identity: FileIdentity,
) -> Result<OwnedDirectoryPublication, DirectoryPublicationError> {
    validate_directory_publication_absolute(destination)?;
    validate_directory_publication_absolute(temporary)?;
    if expected_parent_identity.volume_serial_number == 0
        || expected_parent_identity.file_index == 0
        || expected_temporary_identity.volume_serial_number == 0
        || expected_temporary_identity.file_index == 0
    {
        return Err(DirectoryPublicationError::IdentityMismatch);
    }
    let destination_name = destination
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    validate_package_relative_path(Path::new(destination_name))
        .map_err(|_| DirectoryPublicationError::InvalidPath)?;
    if temporary.file_name().and_then(std::ffi::OsStr::to_str) != Some(temporary_name) {
        return Err(DirectoryPublicationError::InvalidPath);
    }
    validate_owned_temporary_name(temporary, destination)?;

    let destination_parent = destination
        .parent()
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    let contour = retain_directory_publication_contour(destination_parent)?;
    if contour.parent_identity != expected_parent_identity {
        return Err(DirectoryPublicationError::IdentityMismatch);
    }
    verify_directory_publication_contour(&contour)?;
    let canonical_destination = contour.canonical_parent.join(destination_name);
    let canonical_temporary = contour.canonical_parent.join(temporary_name);
    if !windows_paths_equal(destination, &canonical_destination)
        || !windows_paths_equal(temporary, &canonical_temporary)
    {
        return Err(DirectoryPublicationError::IdentityMismatch);
    }
    require_directory_publication_absent(&canonical_destination)?;
    let parent = contour
        .entries
        .last()
        .map(|(_, _, handle)| handle)
        .ok_or(DirectoryPublicationError::InvalidPath)?;
    let source = open_owned_directory_relative(parent, temporary_name)?;
    let source_path =
        final_windows_path_from_handle(&source).map_err(|_| DirectoryPublicationError::Io)?;
    let source_identity =
        file_identity_from_handle(&source).map_err(|_| DirectoryPublicationError::Io)?;
    if !windows_paths_equal(&source_path, &canonical_temporary)
        || source_identity != expected_temporary_identity
    {
        return Err(DirectoryPublicationError::IdentityMismatch);
    }
    verify_directory_publication_contour(&contour)?;
    require_directory_publication_absent(&canonical_destination)?;
    Ok(OwnedDirectoryPublication {
        temporary: source_path,
        temporary_name: temporary_name.to_owned(),
        destination: canonical_destination,
        canonical_parent: contour.canonical_parent.clone(),
        parent_identity: contour.parent_identity,
        initial_temporary_identity: source_identity,
        contour,
        temporary_handle: Some(source),
        committed: false,
    })
}

#[cfg(windows)]
impl OwnedDirectoryPublication {
    #[allow(
        clippy::too_many_lines,
        reason = "the commit boundary and every post-commit no-overclaim discriminator stay in one auditable sequence"
    )]
    pub(crate) fn publish_inner<BeforeMove>(
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
        let destination_name = self
            .destination
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or(DirectoryPublicationError::InvalidPath)?;
        let destination_parent = self
            .contour
            .entries
            .last()
            .map(|(_, _, handle)| handle)
            .ok_or(DirectoryPublicationError::InvalidPath)?;
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
        // The retained source handle is the object being renamed.  The
        // retained destination-parent handle and relative leaf make this a
        // no-follow, no-replace operation with no path-source lookup between
        // the final identity check and the commit boundary.
        rename_directory_from_handle(source, destination_parent, destination_name)?;
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
        let Ok(moved_path) = final_windows_path_from_handle(source) else {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitReadbackUnavailable,
            ));
        };
        if !windows_paths_equal(&moved_path, &self.destination) {
            return Ok(unknown(DirectoryPublicationUnknown::PostCommitPathChanged));
        }
        let Ok(moved_identity) = file_identity_from_handle(source) else {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitIdentityUnavailable,
            ));
        };
        if moved_identity != source_identity {
            return Ok(unknown(
                DirectoryPublicationUnknown::PostCommitIdentityChanged,
            ));
        }
        // The retained source handle intentionally denies FILE_SHARE_DELETE;
        // readback handles must request only the shares that the owner grants.
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
        let Ok(destination_pin) = open_publication_directory(&self.destination, true) else {
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
            // NtSetInformationFile is the handle-relative commit boundary.
            // Some Windows filesystems reject directory FlushFileBuffers, so
            // this is best-effort reinforcement, not a second fallible commit.
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
