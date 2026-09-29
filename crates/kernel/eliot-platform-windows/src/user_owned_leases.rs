//! User-owned filesystem lease closure for handle-derived identity and containment.
//!
//! This private child owns only physical Windows handle-derived
//! identity/containment/no-follow/DACL-protected user-owned lease mechanics.
//! It owns no semantic acceptance, SCM, process lifecycle, secret, retry/default,
//! installation, durable-write, policy, or canonical-authority decisions; the
//! facade/control plane remains outside this module.
//!
//! Normative anchors:
//! - Architecture `A2.3`
//!   (`docs/architecture/A02-03-modular-architecture.md`) and `A12.2`
//!   (`docs/architecture/A12-02-principal-session-and-visibility.md`).
//! - Implementation `I2.3`
//!   (`docs/architecture/I02-03-workspace-topology-and-dependency-direction.md`),
//!   `I2.23`
//!   (`docs/architecture/I02-23-capability-family-topology-and-crate-extraction-decisions.md`),
//!   and `I6.15`
//!   (`docs/architecture/I06-15-capability-grant-lineage-introductions-and-resource-facets.md`).
//! - Authority and precedence: `docs/ARCHITECTURE_CONTRACT.md`.

#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom, Write};
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

/// The physical kind of one node in an Operator-selected resource contour.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserSelectedResourceKind {
    /// A regular file opened without following a reparse point.
    File,
    /// A directory opened without following a reparse point.
    Directory,
}

/// Handle-derived identity and kind for one node from the local volume root
/// through the selected object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserSelectedResourceNodeMeasurement {
    /// Identity queried from the retained handle.
    pub identity: FileIdentity,
    /// Kind queried from the retained handle.
    pub kind: UserSelectedResourceKind,
}

/// Physical facts measured for one selected root and object.
///
/// This value contains no path or authority. The Broker computes any
/// canonical digests and obtains the State Fence from the Kernel grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserSelectedResourceMeasurement {
    /// Identity of the selected directory root.
    pub root_identity: FileIdentity,
    /// Identity of the selected object.
    pub object_identity: FileIdentity,
    /// Position of `root_identity` in `ancestor_contour`.
    pub root_contour_index: usize,
    /// Full retained contour from the local volume root through the object.
    pub ancestor_contour: Vec<UserSelectedResourceNodeMeasurement>,
    /// Handle-derived object kind.
    pub object_kind: UserSelectedResourceKind,
    /// File byte length; absent for directories.
    pub file_size_bytes: Option<u64>,
    /// File last-write FILETIME in 100 ns ticks; absent for directories.
    pub last_write_filetime_100ns: Option<u64>,
    /// Handle-derived metadata `ChangeTime` in 100 ns ticks. This is not a
    /// directory generation counter.
    pub metadata_change_time_filetime_100ns: Option<u64>,
    /// A true directory-generation source is unavailable on this owner.
    pub directory_generation: Option<u64>,
    /// Successful measurements are confined to a local fixed drive.
    pub network: bool,
    /// Successful measurements exclude device namespace and device objects.
    pub device: bool,
    /// Every opened contour node was checked as non-reparse.
    pub reparse_free: bool,
    /// Owner wall-clock sample after handle measurements; absent if the
    /// system clock was before the Unix epoch or could not be represented.
    pub measured_at_unix_ms: Option<u64>,
}

/// Failure to prove one read-only physical selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserSelectedResourceError {
    /// A path was relative, escaped its selected root, or used an unsupported
    /// Windows namespace form.
    InvalidPath,
    /// The selected path resolves to a remote/network drive.
    NetworkPath,
    /// The selected path names a device namespace, device object, or a
    /// non-fixed/unknown drive class.
    DevicePath,
    /// A path component or selected object is a reparse point.
    ReparsePoint,
    /// A retained handle no longer reports its acquisition identity or kind.
    IdentityMismatch,
    /// A required handle-derived metadata query failed.
    Io,
    /// The one-shot at-use remeasurement has already been attempted.
    AlreadyRemeasured,
    /// The physical owner is available only on Windows.
    UnsupportedPlatform,
}

impl std::fmt::Display for UserSelectedResourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "selected resource path is invalid or outside its root",
            Self::NetworkPath => "selected resource is on a network drive",
            Self::DevicePath => "selected resource is a device or unsupported drive",
            Self::ReparsePoint => "selected resource contour contains a reparse point",
            Self::IdentityMismatch => "selected resource identity changed",
            Self::Io => "selected resource handle measurement failed",
            Self::AlreadyRemeasured => "selected resource at-use remeasurement was consumed",
            Self::UnsupportedPlatform => "selected resource leases require Windows",
        })
    }
}

impl std::error::Error for UserSelectedResourceError {}

/// One read-only, no-follow physical proof for an Operator-selected root and
/// object. Every directory handle from the volume root through the object
/// parent is retained with delete sharing disabled; a directory object is
/// itself retained in that contour. A file object is retained separately.
///
/// The lease does not authorize a later child to reopen the pathname. Broker
/// must perform `remeasure_for_use` at its use boundary and keep this lease
/// alive through the one operation it protects.
pub struct UserSelectedResourceLease {
    #[cfg(windows)]
    directories: Vec<std::fs::File>,
    #[cfg(windows)]
    object_file: Option<std::fs::File>,
    #[cfg(windows)]
    expected_contour: Vec<UserSelectedResourceNodeMeasurement>,
    #[cfg(windows)]
    root_contour_index: usize,
    #[cfg(windows)]
    object_kind: UserSelectedResourceKind,
    #[cfg(windows)]
    volume_root: PathBuf,
    #[cfg(windows)]
    remeasure_consumed: bool,
}

impl std::fmt::Debug for UserSelectedResourceLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(windows)]
        {
            formatter
                .debug_struct("UserSelectedResourceLease")
                .field("retained_directory_count", &self.directories.len())
                .field("object_kind", &self.object_kind)
                .field("remeasure_consumed", &self.remeasure_consumed)
                .finish_non_exhaustive()
        }
        #[cfg(not(windows))]
        {
            formatter
                .debug_struct("UserSelectedResourceLease")
                .finish_non_exhaustive()
        }
    }
}

impl UserSelectedResourceLease {
    /// Opens one Operator-selected directory root and one existing object.
    ///
    /// Acquisition rejects network/device paths, requires the object to be
    /// beneath the selected root, and retains each directory handle from the
    /// local drive root through the object. It never changes a DACL.
    ///
    /// # Errors
    ///
    /// Returns an error when either path is invalid, remote, a device or
    /// reparse point, outside the selected root, or cannot be measured from
    /// retained handles. Non-Windows targets return
    /// [`UserSelectedResourceError::UnsupportedPlatform`].
    pub fn open(
        root: &Path,
        object: &Path,
    ) -> Result<(Self, UserSelectedResourceMeasurement), UserSelectedResourceError> {
        #[cfg(windows)]
        {
            open_user_selected_resource(root, object)
        }
        #[cfg(not(windows))]
        {
            let _ = (root, object);
            Err(UserSelectedResourceError::UnsupportedPlatform)
        }
    }

    /// Consumes the one at-use remeasurement for this selection.
    ///
    /// The measurement is read from the original retained handles. The caller
    /// must invoke this immediately before its one operation and keep `self`
    /// alive until that operation returns. This does not authorize a child to
    /// reopen the selected pathname.
    ///
    /// # Errors
    ///
    /// Returns an error if the one-shot call was already attempted or a
    /// retained identity, kind, network/device policy fact, or metadata query
    /// cannot be re-established.
    pub fn remeasure_for_use(
        &mut self,
    ) -> Result<UserSelectedResourceMeasurement, UserSelectedResourceError> {
        #[cfg(windows)]
        {
            if self.remeasure_consumed {
                return Err(UserSelectedResourceError::AlreadyRemeasured);
            }
            self.remeasure_consumed = true;
            measure_user_selected_resource(self)
        }
        #[cfg(not(windows))]
        {
            Err(UserSelectedResourceError::UnsupportedPlatform)
        }
    }
}

#[cfg(windows)]
fn open_user_selected_resource(
    root: &Path,
    object: &Path,
) -> Result<(UserSelectedResourceLease, UserSelectedResourceMeasurement), UserSelectedResourceError>
{
    let selected_root = normalize_user_selected_path(root)?;
    let selected_object = normalize_user_selected_path(object)?;
    if !selected_object.path.starts_with(&selected_root.path)
        || selected_root.components.len() > selected_object.components.len()
    {
        return Err(UserSelectedResourceError::InvalidPath);
    }
    if !selected_root
        .drive
        .eq_ignore_ascii_case(&selected_object.drive)
    {
        return Err(UserSelectedResourceError::InvalidPath);
    }

    let mut contour = open_user_selected_directory_contour(&selected_root, &selected_object)?;

    let (object_kind, object_file) = if selected_object.components.is_empty() {
        // The local volume root is already retained as contour node zero.
        (UserSelectedResourceKind::Directory, None)
    } else {
        match crate::open_no_follow_directory(&selected_object.path) {
            Ok((identity, handle)) => {
                if identity.volume_serial_number != contour.volume_identity.volume_serial_number {
                    return Err(UserSelectedResourceError::IdentityMismatch);
                }
                require_non_device_directory(&handle)?;
                contour
                    .expected_contour
                    .push(UserSelectedResourceNodeMeasurement {
                        identity,
                        kind: UserSelectedResourceKind::Directory,
                    });
                contour.directories.push(handle);
                (UserSelectedResourceKind::Directory, None)
            }
            Err(ProtectedPathError::InvalidPath) => {
                let (identity, handle) = crate::open_no_follow_file(&selected_object.path)
                    .map_err(map_selected_resource_path_error)?;
                if identity.volume_serial_number != contour.volume_identity.volume_serial_number {
                    return Err(UserSelectedResourceError::IdentityMismatch);
                }
                require_non_device_file(&handle)?;
                contour
                    .expected_contour
                    .push(UserSelectedResourceNodeMeasurement {
                        identity,
                        kind: UserSelectedResourceKind::File,
                    });
                (UserSelectedResourceKind::File, Some(handle))
            }
            Err(error) => return Err(map_selected_resource_path_error(error)),
        }
    };

    if object_kind == UserSelectedResourceKind::File
        && contour.root_contour_index >= contour.expected_contour.len().saturating_sub(1)
    {
        return Err(UserSelectedResourceError::InvalidPath);
    }

    let lease = UserSelectedResourceLease {
        directories: contour.directories,
        object_file,
        expected_contour: contour.expected_contour,
        root_contour_index: contour.root_contour_index,
        object_kind,
        volume_root: contour.volume_root,
        remeasure_consumed: false,
    };
    let measurement = measure_user_selected_resource(&lease)?;
    Ok((lease, measurement))
}

#[cfg(windows)]
struct SelectedDirectoryContour {
    directories: Vec<std::fs::File>,
    expected_contour: Vec<UserSelectedResourceNodeMeasurement>,
    root_contour_index: usize,
    volume_identity: FileIdentity,
    volume_root: PathBuf,
}

#[cfg(windows)]
fn open_user_selected_directory_contour(
    root: &NormalizedUserSelectedPath,
    object: &NormalizedUserSelectedPath,
) -> Result<SelectedDirectoryContour, UserSelectedResourceError> {
    let volume_root = PathBuf::from(format!("{}:\\", root.drive));
    require_local_fixed_drive(&volume_root)?;
    let parent_component_count = object.components.len().saturating_sub(1);
    if root.components.len() > parent_component_count && !object.components.is_empty() {
        return Err(UserSelectedResourceError::InvalidPath);
    }

    let mut directories = Vec::with_capacity(parent_component_count + 2);
    let mut expected_contour = Vec::with_capacity(object.components.len() + 1);
    let (volume_identity, volume_handle) =
        crate::open_no_follow_directory(&volume_root).map_err(map_selected_resource_path_error)?;
    require_non_device_directory(&volume_handle)?;
    require_actual_volume_root(&volume_handle, root.drive)?;
    directories.push(volume_handle);
    expected_contour.push(UserSelectedResourceNodeMeasurement {
        identity: volume_identity,
        kind: UserSelectedResourceKind::Directory,
    });

    let mut current = volume_root.clone();
    for component in object.components.iter().take(parent_component_count) {
        current.push(component);
        let (identity, handle) =
            crate::open_no_follow_directory(&current).map_err(map_selected_resource_path_error)?;
        if identity.volume_serial_number != volume_identity.volume_serial_number {
            return Err(UserSelectedResourceError::IdentityMismatch);
        }
        require_non_device_directory(&handle)?;
        directories.push(handle);
        expected_contour.push(UserSelectedResourceNodeMeasurement {
            identity,
            kind: UserSelectedResourceKind::Directory,
        });
    }

    let root_contour_index = root.components.len();
    if root_contour_index >= expected_contour.len()
        || expected_contour[root_contour_index].kind != UserSelectedResourceKind::Directory
    {
        return Err(UserSelectedResourceError::InvalidPath);
    }
    Ok(SelectedDirectoryContour {
        directories,
        expected_contour,
        root_contour_index,
        volume_identity,
        volume_root,
    })
}

#[cfg(not(windows))]
fn map_selected_resource_path_error(error: ProtectedPathError) -> UserSelectedResourceError {
    let _ = error;
    UserSelectedResourceError::UnsupportedPlatform
}

#[cfg(windows)]
struct NormalizedUserSelectedPath {
    path: PathBuf,
    drive: char,
    components: Vec<std::ffi::OsString>,
}

#[cfg(windows)]
fn normalize_user_selected_path(
    path: &Path,
) -> Result<NormalizedUserSelectedPath, UserSelectedResourceError> {
    use std::path::{Component, Prefix};

    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(UserSelectedResourceError::InvalidPath);
    };
    let drive_byte = match prefix.kind() {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
        Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _) => {
            return Err(UserSelectedResourceError::NetworkPath);
        }
        Prefix::DeviceNS(_) | Prefix::Verbatim(_) => {
            return Err(UserSelectedResourceError::DevicePath);
        }
    };
    if !drive_byte.is_ascii_alphabetic() || !matches!(components.next(), Some(Component::RootDir)) {
        return Err(UserSelectedResourceError::InvalidPath);
    }
    let drive = char::from(drive_byte);
    let mut normal_components = Vec::new();
    for component in components {
        match component {
            Component::Normal(normal) => {
                let text = normal.to_string_lossy();
                if text.contains(':') || text.ends_with('.') || text.ends_with(' ') {
                    return Err(UserSelectedResourceError::InvalidPath);
                }
                normal_components.push(normal.to_os_string());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                return Err(UserSelectedResourceError::InvalidPath);
            }
        }
    }

    let mut normalized = PathBuf::from(format!("{drive}:\\"));
    for component in &normal_components {
        normalized.push(component);
    }
    Ok(NormalizedUserSelectedPath {
        path: normalized,
        drive,
        components: normal_components,
    })
}

#[cfg(windows)]
fn require_local_fixed_drive(path: &Path) -> Result<(), UserSelectedResourceError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    use windows_sys::Win32::System::WindowsProgramming::{DRIVE_FIXED, DRIVE_REMOTE};

    let wide_path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let drive_type = unsafe {
        // SAFETY: `wide_path` is NUL-terminated and remains live for the call.
        GetDriveTypeW(wide_path.as_ptr())
    };
    if drive_type == DRIVE_REMOTE {
        return Err(UserSelectedResourceError::NetworkPath);
    }
    if drive_type != DRIVE_FIXED {
        return Err(UserSelectedResourceError::DevicePath);
    }
    Ok(())
}

#[cfg(windows)]
fn require_actual_volume_root(
    handle: &std::fs::File,
    expected_drive: char,
) -> Result<(), UserSelectedResourceError> {
    let final_path =
        crate::final_windows_path_from_handle(handle).map_err(|_| UserSelectedResourceError::Io)?;
    let resolved = normalize_user_selected_path(&final_path)?;
    if !resolved.components.is_empty() || !resolved.drive.eq_ignore_ascii_case(&expected_drive) {
        return Err(UserSelectedResourceError::InvalidPath);
    }
    Ok(())
}

#[cfg(windows)]
fn map_selected_resource_path_error(error: ProtectedPathError) -> UserSelectedResourceError {
    match error {
        ProtectedPathError::InvalidPath | ProtectedPathError::InvalidRoot => {
            UserSelectedResourceError::InvalidPath
        }
        ProtectedPathError::ReparsePoint => UserSelectedResourceError::ReparsePoint,
        ProtectedPathError::IdentityMismatch => UserSelectedResourceError::IdentityMismatch,
        ProtectedPathError::UnsupportedPlatform => UserSelectedResourceError::UnsupportedPlatform,
        ProtectedPathError::AclMismatch
        | ProtectedPathError::Io
        | ProtectedPathError::Win32 { .. }
        | ProtectedPathError::SizeExceeded => UserSelectedResourceError::Io,
    }
}

#[cfg(windows)]
fn require_non_device_directory(file: &std::fs::File) -> Result<(), UserSelectedResourceError> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let metadata = file.metadata().map_err(|_| UserSelectedResourceError::Io)?;
    let attributes = metadata.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(UserSelectedResourceError::ReparsePoint);
    }
    if attributes & FILE_ATTRIBUTE_DEVICE != 0 || !metadata.is_dir() {
        return Err(UserSelectedResourceError::DevicePath);
    }
    Ok(())
}

#[cfg(windows)]
fn require_non_device_file(file: &std::fs::File) -> Result<(), UserSelectedResourceError> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let metadata = file.metadata().map_err(|_| UserSelectedResourceError::Io)?;
    let attributes = metadata.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(UserSelectedResourceError::ReparsePoint);
    }
    if attributes & FILE_ATTRIBUTE_DEVICE != 0 {
        return Err(UserSelectedResourceError::DevicePath);
    }
    if !metadata.is_file() {
        return Err(UserSelectedResourceError::InvalidPath);
    }
    Ok(())
}

#[cfg(windows)]
fn measure_user_selected_contour(
    lease: &UserSelectedResourceLease,
) -> Result<Vec<UserSelectedResourceNodeMeasurement>, UserSelectedResourceError> {
    require_local_fixed_drive(&lease.volume_root)?;
    if lease.expected_contour.is_empty() || lease.root_contour_index >= lease.expected_contour.len()
    {
        return Err(UserSelectedResourceError::IdentityMismatch);
    }
    let expected_directory_count = match lease.object_kind {
        UserSelectedResourceKind::Directory => lease.expected_contour.len(),
        UserSelectedResourceKind::File => lease.expected_contour.len().saturating_sub(1),
    };
    if lease.directories.len() != expected_directory_count {
        return Err(UserSelectedResourceError::IdentityMismatch);
    }

    let mut observed = Vec::with_capacity(lease.expected_contour.len());
    for (index, handle) in lease.directories.iter().enumerate() {
        require_non_device_directory(handle)?;
        let identity = crate::process_identity::file_identity_from_handle(handle)
            .map_err(|_| UserSelectedResourceError::Io)?;
        let node = UserSelectedResourceNodeMeasurement {
            identity,
            kind: UserSelectedResourceKind::Directory,
        };
        if lease.expected_contour.get(index) != Some(&node) {
            return Err(UserSelectedResourceError::IdentityMismatch);
        }
        observed.push(node);
    }

    let object_handle = match lease.object_kind {
        UserSelectedResourceKind::Directory => lease
            .directories
            .last()
            .ok_or(UserSelectedResourceError::IdentityMismatch)?,
        UserSelectedResourceKind::File => lease
            .object_file
            .as_ref()
            .ok_or(UserSelectedResourceError::IdentityMismatch)?,
    };
    let object_node = UserSelectedResourceNodeMeasurement {
        identity: crate::process_identity::file_identity_from_handle(object_handle)
            .map_err(|_| UserSelectedResourceError::Io)?,
        kind: lease.object_kind,
    };
    if lease.expected_contour.last() != Some(&object_node) {
        return Err(UserSelectedResourceError::IdentityMismatch);
    }
    if lease.object_kind == UserSelectedResourceKind::File {
        observed.push(object_node);
    } else if observed.last() != Some(&object_node) {
        return Err(UserSelectedResourceError::IdentityMismatch);
    }
    Ok(observed)
}

#[cfg(windows)]
struct SelectedObjectMetadata {
    file_size_bytes: Option<u64>,
    last_write_filetime_100ns: Option<u64>,
    metadata_change_time_filetime_100ns: Option<u64>,
}

#[cfg(windows)]
fn measure_selected_object_metadata(
    file: &std::fs::File,
    kind: UserSelectedResourceKind,
) -> Result<SelectedObjectMetadata, UserSelectedResourceError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
    };

    match kind {
        UserSelectedResourceKind::File => require_non_device_file(file)?,
        UserSelectedResourceKind::Directory => require_non_device_directory(file)?,
    }
    let handle = file.as_raw_handle() as HANDLE;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let info_ok = unsafe {
        // SAFETY: the retained handle is live and the initialized information
        // structure is writable for the duration of the call.
        GetFileInformationByHandle(handle, &raw mut information)
    };
    if info_ok == 0 {
        return Err(UserSelectedResourceError::Io);
    }

    let mut basic = FILE_BASIC_INFO::default();
    let basic_size = u32::try_from(std::mem::size_of::<FILE_BASIC_INFO>())
        .map_err(|_| UserSelectedResourceError::Io)?;
    let basic_ok = unsafe {
        // SAFETY: the retained handle is live and `basic` has the documented
        // output size for `FileBasicInfo`.
        GetFileInformationByHandleEx(handle, FileBasicInfo, (&raw mut basic).cast(), basic_size)
    };
    if basic_ok == 0
        || basic.FileAttributes & (FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(UserSelectedResourceError::Io);
    }

    let file_size_bytes = (kind == UserSelectedResourceKind::File).then(|| {
        (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow)
    });
    let last_write_filetime_100ns = (kind == UserSelectedResourceKind::File).then(|| {
        (u64::from(information.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(information.ftLastWriteTime.dwLowDateTime)
    });
    Ok(SelectedObjectMetadata {
        file_size_bytes,
        last_write_filetime_100ns,
        metadata_change_time_filetime_100ns: u64::try_from(basic.ChangeTime).ok(),
    })
}

#[cfg(windows)]
fn measure_user_selected_resource(
    lease: &UserSelectedResourceLease,
) -> Result<UserSelectedResourceMeasurement, UserSelectedResourceError> {
    let observed = measure_user_selected_contour(lease)?;
    let object_node = observed
        .last()
        .copied()
        .ok_or(UserSelectedResourceError::IdentityMismatch)?;
    let object_handle = match lease.object_kind {
        UserSelectedResourceKind::Directory => lease
            .directories
            .last()
            .ok_or(UserSelectedResourceError::IdentityMismatch)?,
        UserSelectedResourceKind::File => lease
            .object_file
            .as_ref()
            .ok_or(UserSelectedResourceError::IdentityMismatch)?,
    };
    let metadata = measure_selected_object_metadata(object_handle, lease.object_kind)?;
    let measured_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok());

    Ok(UserSelectedResourceMeasurement {
        root_identity: lease.expected_contour[lease.root_contour_index].identity,
        object_identity: object_node.identity,
        root_contour_index: lease.root_contour_index,
        ancestor_contour: observed,
        object_kind: lease.object_kind,
        file_size_bytes: metadata.file_size_bytes,
        last_write_filetime_100ns: metadata.last_write_filetime_100ns,
        metadata_change_time_filetime_100ns: metadata.metadata_change_time_filetime_100ns,
        directory_generation: None,
        network: false,
        device: false,
        reparse_free: true,
        measured_at_unix_ms,
    })
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

    /// Reopens the declared path without following reparse points and proves
    /// it still names the retained root object.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is substituted, its ownership proof
    /// fails, or the operation is unsupported on the current platform.
    pub fn verify_path_identity(&self) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            let directory = open_user_owned_directory_read_only(&self.path, &self.sid)?;
            let identity = crate::process_identity::file_identity_from_handle(&directory)
                .map_err(|_| ProtectedPathError::Io)?;
            (identity == self.identity)
                .then_some(())
                .ok_or(ProtectedPathError::IdentityMismatch)
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

    /// Reopens the declared path without following reparse points and proves
    /// it still names the retained root object.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is substituted, its ownership proof
    /// fails, or the operation is unsupported on the current platform.
    pub fn verify_path_identity(&self) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            let directory = open_user_owned_directory_read_only(&self.path, &self.sid)?;
            let identity = crate::process_identity::file_identity_from_handle(&directory)
                .map_err(|_| ProtectedPathError::Io)?;
            (identity == self.identity)
                .then_some(())
                .ok_or(ProtectedPathError::IdentityMismatch)
        }
        #[cfg(not(windows))]
        {
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Opens or creates one exact current-user-protected child directory.
    ///
    /// This is limited to one ordinary path component below the retained root.
    /// Creation is flushed through the retained parent handle before the child
    /// is returned; an existing child is accepted only after the normal
    /// no-follow owner and DACL checks.
    ///
    /// # Errors
    ///
    /// Returns an error when the child name is not one normal component, the
    /// directory cannot be created or opened safely, or either retained path
    /// changes identity.
    pub(crate) fn open_or_create_child_directory(
        &self,
        child_name: &str,
    ) -> Result<Self, ProtectedPathError> {
        #[cfg(windows)]
        {
            let child_component = Path::new(child_name);
            let mut components = child_component.components();
            if !matches!(components.next(), Some(std::path::Component::Normal(_)))
                || components.next().is_some()
                || child_name.is_empty()
                || child_name.contains(['/', '\\'])
            {
                return Err(ProtectedPathError::InvalidPath);
            }
            self.verify_stable_identity()?;
            self.verify_path_identity()?;
            let path = self.path.join(child_component);
            let created = match std::fs::create_dir(&path) {
                Ok(()) => true,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
                Err(_) => return Err(ProtectedPathError::Io),
            };
            let child = Self::open_existing(&path)?;
            if created {
                crate::sync_directory_handle(&self.handle).map_err(|_| ProtectedPathError::Io)?;
            }
            self.verify_stable_identity()?;
            self.verify_path_identity()?;
            child.verify_stable_identity()?;
            child.verify_path_identity()?;
            Ok(child)
        }
        #[cfg(not(windows))]
        {
            let _ = child_name;
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
    /// No-follow handles for every retained parent directory, outermost first.
    /// They are kept alive for the lease lifetime and the last entry is the
    /// immediate parent synced after a durable write.
    #[cfg(windows)]
    retained_parent_directories: Vec<std::fs::File>,
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
    /// Creates one new, current-user-protected file below a retained root.
    ///
    /// This is create-only: an existing object is never opened or adopted.
    /// Parent directories must already exist and are retained with no-follow
    /// handles for the lifetime of the returned lease.
    ///
    /// # Errors
    ///
    /// Returns an error when the destination already exists, a parent is
    /// missing or substituted, the file cannot be protected, or the platform
    /// is unsupported.
    pub fn create_new(root: &UserOwnedRootLease, path: &Path) -> Result<Self, ProtectedPathError> {
        #[cfg(windows)]
        {
            if !path.is_absolute() {
                return Err(ProtectedPathError::InvalidPath);
            }
            root.verify_stable_identity()?;
            root.verify_path_identity()?;
            ensure_user_owned_containment(&root.path, path)?;
            let parent = path.parent().ok_or(ProtectedPathError::InvalidPath)?;
            let relative_parent = parent
                .strip_prefix(&root.path)
                .map_err(|_| ProtectedPathError::InvalidPath)?;
            let directories =
                open_user_owned_directory_contour(&root.path, relative_parent, &root.sid)?;
            let file = create_user_owned_file(path, &root.sid)?;
            let identity = crate::process_identity::file_identity_from_handle(&file)
                .map_err(|_| ProtectedPathError::Io)?;
            let root_handle = root
                .handle
                .try_clone()
                .map_err(|_| ProtectedPathError::Io)?;
            let lease = Self {
                path: path.to_path_buf(),
                identity,
                sid: root.sid.clone(),
                _root: root_handle,
                retained_parent_directories: directories,
                file,
            };
            lease.verify_path_identity()?;
            root.verify_stable_identity()?;
            root.verify_path_identity()?;
            Ok(lease)
        }
        #[cfg(not(windows))]
        {
            let _ = (root, path);
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

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
                retained_parent_directories: directories,
                file,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (root, path);
            Err(ProtectedPathError::UnsupportedPlatform)
        }
    }

    /// Opens one existing file below `root`, or creates that exact file with
    /// create-new semantics when it is absent. The returned handle is
    /// no-follow, single-link, current-user protected, and retained together
    /// with the root and every directory in its parent contour.
    ///
    /// Parent directories are never synthesized here. A concurrent creator
    /// wins only by creating the same ordinary file first; the winner is then
    /// reopened and proved through the same current-user handle checks.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is outside the retained root, a parent
    /// is absent or substituted, the final object is not a regular file, or
    /// its current-user ACL and file identity cannot be proved.
    pub fn open_or_create(
        root: &UserOwnedRootLease,
        path: &Path,
    ) -> Result<Self, ProtectedPathError> {
        #[cfg(windows)]
        {
            if !path.is_absolute() {
                return Err(ProtectedPathError::InvalidPath);
            }
            root.verify_stable_identity()?;
            ensure_user_owned_containment(&root.path, path)?;
            let parent = path.parent().ok_or(ProtectedPathError::InvalidPath)?;
            let relative_parent = parent
                .strip_prefix(&root.path)
                .map_err(|_| ProtectedPathError::InvalidPath)?;
            let directories =
                open_user_owned_directory_contour(&root.path, relative_parent, &root.sid)?;
            let file = match std::fs::symlink_metadata(path) {
                Ok(_) => open_user_owned_file(path, &root.sid)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    match create_user_owned_file(path, &root.sid) {
                        Ok(file) => file,
                        Err(ProtectedPathError::Io) if std::fs::symlink_metadata(path).is_ok() => {
                            open_user_owned_file(path, &root.sid)?
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(_) => return Err(ProtectedPathError::Io),
            };
            let identity = crate::process_identity::file_identity_from_handle(&file)
                .map_err(|_| ProtectedPathError::Io)?;
            let root_handle = root
                .handle
                .try_clone()
                .map_err(|_| ProtectedPathError::Io)?;
            let lease = Self {
                path: path.to_path_buf(),
                identity,
                sid: root.sid.clone(),
                _root: root_handle,
                retained_parent_directories: directories,
                file,
            };
            lease.verify_path_identity()?;
            root.verify_stable_identity()?;
            Ok(lease)
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

    /// Writes bytes only to a newly created empty file, flushes the file and
    /// its retained parent directory, then reads the exact bytes back.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is not empty, write or durability flush
    /// fails, readback differs, or the platform is unsupported.
    pub fn write_new_bytes(&mut self, bytes: &[u8]) -> Result<(), ProtectedPathError> {
        #[cfg(windows)]
        {
            if self
                .file
                .metadata()
                .map_err(|_| ProtectedPathError::Io)?
                .len()
                != 0
            {
                return Err(ProtectedPathError::IdentityMismatch);
            }
            self.file
                .write_all(bytes)
                .map_err(|_| ProtectedPathError::Io)?;
            self.file.sync_all().map_err(|_| ProtectedPathError::Io)?;
            let parent = self
                .retained_parent_directories
                .last()
                .ok_or(ProtectedPathError::IdentityMismatch)?;
            crate::sync_directory_handle(parent).map_err(|_| ProtectedPathError::Io)?;
            if self.read_bounded(bytes.len() as u64)? != bytes {
                return Err(ProtectedPathError::IdentityMismatch);
            }
            self.verify_stable_identity()?;
            self.verify_path_identity()?;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = bytes;
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
    ensure_single_user_file_link(&file)?;
    protect_user_owned_opened_handle(&file, false, sid)?;
    Ok(file)
}

#[cfg(windows)]
fn create_user_owned_file(path: &Path, sid: &str) -> Result<std::fs::File, ProtectedPathError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_SHARE_READ, FILE_SHARE_WRITE, WRITE_DAC, WRITE_OWNER,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .access_mode(FILE_GENERIC_READ | WRITE_DAC | WRITE_OWNER)
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
    ensure_single_user_file_link(&file)?;
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
