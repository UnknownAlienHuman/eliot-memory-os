//! Physical protected `ProgramData` path proof.
//!
//! Physical containment only. Proves that a caller-supplied path remains below
//! the OS-resolved `ProgramData` contour with retained no-follow directory/file
//! handles, reparse rejection, and identity verification. No semantic authority,
//! no durable recovery proof, and no secret or pipe DACL ownership.
//!
//! Architecture: A12 Security, provenance и bounded influence; A12.1 Security assumes breach; A8.5 Security supervision
//! Implementation: I1.6 Windows isolation; I15 Security and bypass resistance; I15.16 Security testing; Execution identity boundary on Windows
//! Forbidden authority: must not mint authority, must not decide semantics, must not own secret or IPC ACLs.

#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[cfg(not(windows))]
use std::path::{Path, PathBuf};

use crate::FileIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedPathStage {
    KnownFolderPath,
    CanonicalizePath,
    SymlinkMetadata,
    CreateFileW,
    FileMetadata,
    GetFileInformationByHandle,
    GetFinalPathNameByHandleW,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedPathError {
    InvalidRoot,
    InvalidPath,
    ReparsePoint,
    AclMismatch,
    Io,
    IdentityMismatch,
    Win32 {
        stage: ProtectedPathStage,
        code: u32,
    },
    SizeExceeded,
    UnsupportedPlatform,
}

impl std::fmt::Display for ProtectedPathError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Self::Win32 { stage, code } = self {
            return write!(
                formatter,
                "protected path {stage:?} failed with status {code:#010x}"
            );
        }
        formatter.write_str(match self {
            Self::InvalidRoot => "ProgramData protected root is invalid",
            Self::InvalidPath => "path is outside the protected ProgramData contour",
            Self::ReparsePoint => "protected path contains a reparse point",
            Self::AclMismatch => "protected path ACL does not match service/admin policy",
            Self::Io => "protected path I/O failed",
            Self::IdentityMismatch => "protected path identity changed",
            Self::Win32 { .. } => unreachable!(),
            Self::SizeExceeded => "protected file exceeds its bounded read limit",
            Self::UnsupportedPlatform => "protected ProgramData storage requires Windows",
        })
    }
}

impl std::error::Error for ProtectedPathError {}

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

pub fn protected_program_data_root() -> Result<PathBuf, ProtectedPathError> {
    let raw = known_folder_path(KnownFolder::ProgramData)?;
    reject_reparse_chain(&raw, true)?;
    let canonical = canonical_windows_path(&raw)?;
    validate_directory_no_reparse(&canonical)?;
    Ok(canonical)
}

#[derive(Clone, Copy)]
enum KnownFolder {
    ProgramData,
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
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

    let folder_id = match folder {
        KnownFolder::ProgramData => &FOLDERID_ProgramData,
    };
    let mut path = std::ptr::null_mut();
    let status = unsafe { SHGetKnownFolderPath(folder_id, 0, std::ptr::null_mut(), &raw mut path) };
    if status != S_OK {
        unsafe { CoTaskMemFree(path.cast()) };
        return Err(known_folder_hresult_error(status));
    }
    if path.is_null() {
        unsafe { CoTaskMemFree(path.cast()) };
        return Err(ProtectedPathError::InvalidRoot);
    }
    let mut length = 0_usize;
    while length <= 32_767 {
        let terminated = unsafe { *path.add(length) == 0 };
        if terminated {
            break;
        }
        length += 1;
    }
    if length > 32_767 {
        unsafe { CoTaskMemFree(path.cast()) };
        return Err(ProtectedPathError::InvalidRoot);
    }
    let value = unsafe { OsString::from_wide(std::slice::from_raw_parts(path, length)) };
    unsafe { CoTaskMemFree(path.cast()) };
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

pub fn canonical_windows_path(path: &Path) -> Result<PathBuf, ProtectedPathError> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| protected_path_io_error(ProtectedPathStage::CanonicalizePath, &error))?;
    #[cfg(windows)]
    {
        normalize_final_windows_path_text(&canonical.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        Ok(canonical)
    }
}

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

pub struct ProtectedPathLease {
    pub(crate) path: PathBuf,
    pub(crate) identity: FileIdentity,
    #[cfg(windows)]
    pub(crate) _directories: Vec<std::fs::File>,
    #[cfg(windows)]
    pub(crate) file: std::fs::File,
}

pub struct ProtectedRootLease {
    pub(crate) path: PathBuf,
    pub(crate) identity: FileIdentity,
    #[cfg(windows)]
    pub(crate) directories: Vec<std::fs::File>,
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
            let identity = file_identity_from_handle(retained).map_err(|error| {
                protected_path_io_error(ProtectedPathStage::GetFileInformationByHandle, &error)
            })?;
            let observed = final_windows_path_from_handle(retained)?;
            if !crate::windows_paths_equal(&observed, &canonical) {
                return Err(ProtectedPathError::IdentityMismatch);
            }
            Ok(Self {
                path: observed,
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

    pub fn canonical_path(&self) -> Result<PathBuf, ProtectedPathError> {
        #[cfg(windows)]
        {
            let observed = final_windows_path_from_handle(
                self.directories
                    .last()
                    .ok_or(ProtectedPathError::InvalidPath)?,
            )?;
            if !crate::windows_paths_equal(&observed, &self.path) {
                return Err(ProtectedPathError::IdentityMismatch);
            }
            Ok(observed)
        }
        #[cfg(not(windows))]
        {
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    pub fn verify_stable_identity(&self) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            let retained = self
                .directories
                .last()
                .ok_or(ProtectedPathError::InvalidPath)?;
            let identity = file_identity_from_handle(retained).map_err(|error| {
                protected_path_io_error(ProtectedPathStage::GetFileInformationByHandle, &error)
            })?;
            if identity != self.identity {
                return Err(ProtectedPathError::IdentityMismatch);
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
    pub fn open_or_create(relative: impl AsRef<Path>) -> Result<Self, ProtectedPathError> {
        Self::open_relative(relative.as_ref(), true)
    }

    pub fn open_existing(relative: impl AsRef<Path>) -> Result<Self, ProtectedPathError> {
        Self::open_relative(relative.as_ref(), false)
    }

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

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

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
            let _ = (create, path, components);
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

pub fn validate_protected_file(path: &Path) -> Result<(), ProtectedPathError> {
    let _lease = ProtectedPathLease::open_existing_absolute(path)?;
    Ok(())
}

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
    crate::TEST_PROTECTED_ROOT.with(|slot| slot.borrow().clone())
}

#[cfg(not(any(test, feature = "test-support")))]
fn test_protected_root() -> Option<PathBuf> {
    None
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
pub(crate) fn pin_protected_directory_contour(
    root: &Path,
    relative: &Path,
) -> Result<Vec<std::fs::File>, ProtectedPathError> {
    let components = protected_components(relative)?;
    let mut current = root.to_path_buf();
    let mut directories = vec![pin_protected_directory(root)?];
    for component in components {
        current.push(component);
        directories.push(pin_protected_directory(&current)?);
    }
    Ok(directories)
}

#[cfg(windows)]
pub(crate) fn pin_protected_directory(path: &Path) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| protected_path_io_error(ProtectedPathStage::CreateFileW, &error))?;
    let metadata = file
        .metadata()
        .map_err(|error| protected_path_io_error(ProtectedPathStage::FileMetadata, &error))?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    Ok(file)
}

#[cfg(windows)]
fn pin_directory(path: &Path) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| ProtectedPathError::Io)?;
    let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    Ok(file)
}

#[cfg(windows)]
fn open_protected_directory(path: &Path) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    #[cfg(any(test, feature = "test-support"))]
    use windows_sys::Win32::Storage::FileSystem::WRITE_OWNER;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, WRITE_DAC,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    let access = FILE_GENERIC_READ | WRITE_DAC;
    #[cfg(any(test, feature = "test-support"))]
    let access = if test_protected_root().is_some() {
        access | WRITE_OWNER
    } else {
        access
    };
    options.access_mode(access);
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
pub(crate) fn open_protected_file(
    path: &Path,
    create: bool,
) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true);
    options.access_mode(legacy_protected_file_access_mode());
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
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    if !metadata.is_file() {
        return Err(ProtectedPathError::InvalidPath);
    }
    Ok(file)
}

#[cfg(windows)]
pub(crate) fn legacy_protected_file_access_mode() -> u32 {
    #[cfg(any(test, feature = "test-support"))]
    use windows_sys::Win32::Storage::FileSystem::WRITE_OWNER;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, WRITE_DAC,
    };
    let access = FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC;
    #[cfg(any(test, feature = "test-support"))]
    let access = if test_protected_root().is_some() {
        access | WRITE_OWNER
    } else {
        access
    };
    access
}

#[cfg(windows)]
pub(crate) fn protect_opened_handle(
    file: &std::fs::File,
    directory: bool,
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
    #[cfg(any(test, feature = "test-support"))]
    if test_protected_root().is_some() {
        return crate::protect_user_owned_opened_handle(
            file,
            directory,
            &crate::current_process_sid()?,
        );
    }
    let metadata = file.metadata().map_err(|_| ProtectedPathError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ProtectedPathError::ReparsePoint);
    }
    if directory != metadata.is_dir() {
        return Err(ProtectedPathError::InvalidPath);
    }
    let descriptor = crate::OwnedSecurityDescriptor::for_protected_storage()
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
fn final_windows_path_from_handle(file: &std::fs::File) -> Result<PathBuf, ProtectedPathError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    let handle = file.as_raw_handle().cast();
    let required = unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, 0) };
    if required == 0 {
        return Err(protected_path_io_error(
            ProtectedPathStage::GetFinalPathNameByHandleW,
            &std::io::Error::last_os_error(),
        ));
    }
    let mut buffer =
        vec![0_u16; usize::try_from(required).map_err(|_| ProtectedPathError::Io)? + 1];
    let written = unsafe {
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
fn file_identity_from_handle(file: &std::fs::File) -> std::io::Result<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
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
fn file_identity_from_handle(_file: &std::fs::File) -> std::io::Result<FileIdentity> {
    Err(std::io::Error::other("Windows identity unavailable"))
}
