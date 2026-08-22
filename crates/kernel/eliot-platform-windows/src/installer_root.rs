//! No-follow Windows runtime-root effects used by the durable installer.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    FileIdentity, OwnedSecurityDescriptor, ProtectedPathError, current_process_sid,
    current_user_local_app_data_root, file_identity_from_handle, final_windows_path_from_handle,
    protected_program_data_root, sid_to_string,
};

const RECEIPT_LIMIT: u64 = 16 * 1024;

#[cfg(windows)]
const INSTALLER_SECURITY_QUERY_MASK: u32 = windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION
    | windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

/// ACL and root-contour policy selected by the installation profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerRootProfile {
    /// Elevated machine-wide roots below the OS `ProgramData` known folder.
    SystemService,
    /// Current-user roots below the OS `LocalAppData` known folder.
    UserMode,
    /// Explicit absolute development root, protected for the current user.
    PortableDev,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct InstallerRootRequest {
    root: PathBuf,
    installation_root: PathBuf,
    profile_anchor: PathBuf,
    profile: InstallerRootProfile,
}

/// One pinned Windows object bound by canonical path, identity and security.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallerRootObjectSnapshot {
    pub canonical_path_digest: String,
    pub volume_serial_number: u32,
    pub file_index: u64,
    pub security_descriptor_digest: String,
}

/// Typed proof that the target was absent while its contour handles were retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallerRootAbsentSnapshot {
    pub target_path_digest: String,
    pub profile_anchor: InstallerRootObjectSnapshot,
    pub ancestors: Vec<InstallerRootObjectSnapshot>,
    pub parent: InstallerRootObjectSnapshot,
    pub root_absent: bool,
}

impl InstallerRootAbsentSnapshot {
    #[must_use]
    pub fn digest(&self) -> String {
        serde_json::to_vec(self).map_or_else(
            |_| digest_text("absent-snapshot-serialization-failed"),
            |bytes| digest(&bytes),
        )
    }
}

/// Exact result returned by the Windows directory creation call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerRootCreateDisposition {
    Created,
    AlreadyExists,
}

/// Fail-closed error from the Windows root executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerRootError {
    /// The request path is outside the exact profile contour.
    InvalidPath,
    /// A required parent is absent; parents are never created implicitly.
    MissingParent,
    /// A symlink, junction or other reparse substitution was observed.
    ReparsePoint,
    /// The exact protected DACL or current-user owner did not match.
    SecurityMismatch,
    /// A receipt was missing, conflicting or unreadable after intent execution.
    ReceiptMismatch,
    /// The observed file identity or canonical path changed.
    IdentityMismatch,
    /// `SystemService` was requested without an elevated token observation.
    NotElevated,
    /// An OS result could not be classified safely.
    Indeterminate,
    /// This executor is intentionally unavailable off Windows.
    UnsupportedPlatform,
}

impl std::fmt::Display for InstallerRootError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Windows installer root effect failed: {self:?}")
    }
}

impl std::error::Error for InstallerRootError {}

#[derive(Clone, Debug)]
struct RootPolicyOverride {
    system_known_folder: PathBuf,
    user_known_folder: PathBuf,
    portable_root: PathBuf,
    elevated: bool,
}

#[derive(Debug, Default)]
struct WindowsInstallerRootExecutor {
    policy_override: Option<RootPolicyOverride>,
}

impl WindowsInstallerRootExecutor {
    const fn new() -> Self {
        Self {
            policy_override: None,
        }
    }

    fn readback(request: &InstallerRootRequest) -> Result<Readback, InstallerRootError> {
        match std::fs::symlink_metadata(&request.root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Readback::Absent),
            Err(_) => Err(InstallerRootError::Indeterminate),
            Ok(metadata) if metadata.file_type().is_symlink() => Ok(Readback::Mismatch),
            Ok(metadata) if !metadata.is_dir() => Ok(Readback::Mismatch),
            Ok(_) => match open_and_readback(&request.root, request.profile, true, false) {
                Ok(root) => Ok(Readback::Matching(root)),
                Err(
                    InstallerRootError::ReparsePoint
                    | InstallerRootError::SecurityMismatch
                    | InstallerRootError::IdentityMismatch,
                ) => Ok(Readback::Mismatch),
                Err(error) => Err(error),
            },
        }
    }

    fn validate_request(&self, request: &InstallerRootRequest) -> Result<(), InstallerRootError> {
        if !request.root.is_absolute()
            || !request.installation_root.is_absolute()
            || !request.profile_anchor.is_absolute()
        {
            return Err(InstallerRootError::InvalidPath);
        }
        if request.profile == InstallerRootProfile::SystemService && !self.is_elevated()? {
            return Err(InstallerRootError::NotElevated);
        }
        self.validate_profile_path(request)
    }

    fn validate_read_request(
        &self,
        request: &InstallerRootRequest,
    ) -> Result<(), InstallerRootError> {
        if !request.root.is_absolute()
            || !request.installation_root.is_absolute()
            || !request.profile_anchor.is_absolute()
        {
            return Err(InstallerRootError::InvalidPath);
        }
        // Reading an already protected object is intentionally available to
        // the EliotHost service SID. Elevation is required only for mutating
        // installer effects; the same exact profile/root/reparse contour is
        // still enforced here with Windows ordinal path comparison.
        self.validate_profile_path(request)
    }

    fn validate_profile_path(
        &self,
        request: &InstallerRootRequest,
    ) -> Result<(), InstallerRootError> {
        if request.root.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) || request.installation_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) || request.profile_anchor.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) {
            return Err(InstallerRootError::InvalidPath);
        }
        let expected_contour = match request.profile {
            InstallerRootProfile::SystemService | InstallerRootProfile::UserMode => {
                let profile_base = self.profile_base(request.profile)?;
                if !windows_paths_equal(&request.profile_anchor, &profile_base) {
                    return Err(InstallerRootError::InvalidPath);
                }
                let expected = profile_base.join("Eliot");
                if !windows_paths_equal(&request.installation_root, &expected) {
                    return Err(InstallerRootError::InvalidPath);
                }
                expected
            }
            InstallerRootProfile::PortableDev => {
                if !windows_path_is_within(&request.installation_root, &request.profile_anchor) {
                    return Err(InstallerRootError::InvalidPath);
                }
                request.installation_root.clone()
            }
        };
        if !windows_path_is_within(&request.root, &expected_contour) {
            return Err(InstallerRootError::InvalidPath);
        }
        validate_existing_ancestors(&request.root)?;
        validate_existing_ancestors(&request.installation_root)
    }

    fn profile_base(&self, profile: InstallerRootProfile) -> Result<PathBuf, InstallerRootError> {
        if let Some(policy) = &self.policy_override {
            return Ok(match profile {
                InstallerRootProfile::SystemService => policy.system_known_folder.clone(),
                InstallerRootProfile::UserMode => policy.user_known_folder.clone(),
                InstallerRootProfile::PortableDev => policy.portable_root.clone(),
            });
        }
        match profile {
            InstallerRootProfile::SystemService => protected_program_data_root(),
            InstallerRootProfile::UserMode => current_user_local_app_data_root(),
            InstallerRootProfile::PortableDev => Err(ProtectedPathError::InvalidRoot),
        }
        .map_err(map_protected_error)
    }

    fn is_elevated(&self) -> Result<bool, InstallerRootError> {
        if let Some(policy) = &self.policy_override {
            return Ok(policy.elevated);
        }
        token_is_elevated()
    }
}

/// Receipt-agnostic specification for one bounded root primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallerRootPrimitiveSpec {
    pub root: PathBuf,
    pub installation_root: PathBuf,
    pub profile_anchor: PathBuf,
    pub profile: InstallerRootProfile,
}

/// Receipt-agnostic readback of one protected root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstallerRootPrimitiveObservation {
    Absent(InstallerRootAbsentSnapshot),
    Matching(InstallerRootObjectSnapshot),
    Mismatch,
}

/// Exact result of an atomic protected-directory create.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallerRootPrimitiveCreate {
    pub disposition: InstallerRootCreateDisposition,
    pub root: Option<InstallerRootObjectSnapshot>,
}

/// Bounded protected-file readback used by the sealed installation adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallerProtectedFileReadback {
    pub object: InstallerRootObjectSnapshot,
    pub bytes: Vec<u8>,
}

/// Receipt-agnostic Windows filesystem primitive.
///
/// It knows only profile contours, atomic ACL creation, handles and identities.
/// Transaction receipts, Credential Manager references and ownership decisions
/// remain entirely in the installation coordinator adapter. In particular,
/// `Created` is only the raw `CreateDirectoryW` disposition: it is never
/// `CreatedByTransaction`, durable evidence, or installation authority.
#[derive(Debug, Default)]
pub struct WindowsInstallerRootPrimitive {
    executor: WindowsInstallerRootExecutor,
}

impl WindowsInstallerRootPrimitive {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            executor: WindowsInstallerRootExecutor::new(),
        }
    }

    /// # Errors
    ///
    /// Fails closed when the profile contour, security, identity or OS state
    /// cannot be observed exactly.
    pub fn inspect(
        &self,
        spec: &InstallerRootPrimitiveSpec,
    ) -> Result<InstallerRootPrimitiveObservation, InstallerRootError> {
        let request = primitive_request(spec);
        self.executor.validate_read_request(&request)?;
        match WindowsInstallerRootExecutor::readback(&request)? {
            Readback::Absent => Ok(InstallerRootPrimitiveObservation::Absent(
                observe_absence(&request)?.snapshot,
            )),
            Readback::Matching(root) => Ok(InstallerRootPrimitiveObservation::Matching(
                root.object_snapshot(),
            )),
            Readback::Mismatch => Ok(InstallerRootPrimitiveObservation::Mismatch),
        }
    }

    /// # Errors
    ///
    /// Rejects a changed absence snapshot, invalid contour, reparse point,
    /// wrong security descriptor or indeterminate OS result.
    pub fn create(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        expected: &InstallerRootAbsentSnapshot,
    ) -> Result<InstallerRootPrimitiveCreate, InstallerRootError> {
        let request = primitive_request(spec);
        self.executor.validate_request(&request)?;
        let pinned = observe_absence(&request)?;
        if &pinned.snapshot != expected {
            return Err(InstallerRootError::IdentityMismatch);
        }
        if !create_directory_atomic(spec.profile, &spec.root)? {
            return Ok(InstallerRootPrimitiveCreate {
                disposition: InstallerRootCreateDisposition::AlreadyExists,
                root: None,
            });
        }
        let root = open_and_readback(&spec.root, spec.profile, true, false)?;
        Ok(InstallerRootPrimitiveCreate {
            disposition: InstallerRootCreateDisposition::Created,
            root: Some(root.object_snapshot()),
        })
    }

    /// # Errors
    ///
    /// Rejects collisions, invalid security/path readback, oversized content
    /// or an indeterminate create/write/flush result.
    pub fn create_protected_file<F>(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        path: &Path,
        build: F,
    ) -> Result<InstallerRootObjectSnapshot, InstallerRootError>
    where
        F: FnOnce(&InstallerRootObjectSnapshot) -> Result<Vec<u8>, InstallerRootError>,
    {
        create_protected_file(
            ProtectedFileSecurity::Installation(spec.profile),
            path,
            build,
        )
    }

    /// Creates a raw protected marker owned by the calling `LocalService` host.
    ///
    /// This primitive returns only OS identity/security readback. It does not
    /// confer installation ownership or mint an installation receipt.
    ///
    /// # Errors
    /// Rejects non-system contours, collisions, wrong security/path readback,
    /// oversized content or an indeterminate create/write/flush result.
    pub fn create_local_service_protected_file<F>(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        path: &Path,
        build: F,
    ) -> Result<InstallerRootObjectSnapshot, InstallerRootError>
    where
        F: FnOnce(&InstallerRootObjectSnapshot) -> Result<Vec<u8>, InstallerRootError>,
    {
        ensure_system_service_spec(spec)?;
        create_protected_file(ProtectedFileSecurity::LocalServiceHostMarker, path, build)
    }

    /// # Errors
    ///
    /// Rejects missing, reparse, oversized, wrong-owner, wrong-DACL or
    /// indeterminate protected-file observations.
    pub fn read_protected_file(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        path: &Path,
        limit: u64,
    ) -> Result<InstallerProtectedFileReadback, InstallerRootError> {
        self.validate_protected_file_request(spec, path)?;
        read_protected_file(
            ProtectedFileSecurity::Installation(spec.profile),
            path,
            limit,
        )
    }

    /// Reads a raw LocalService-owned protected marker without following a
    /// reparse point and verifies its exact owner and protected DACL.
    ///
    /// # Errors
    /// Rejects non-system contours, missing/reparse/oversized files, wrong
    /// owner or DACL, and indeterminate observations.
    pub fn read_local_service_protected_file(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        path: &Path,
        limit: u64,
    ) -> Result<InstallerProtectedFileReadback, InstallerRootError> {
        ensure_system_service_spec(spec)?;
        self.validate_protected_file_request(spec, path)?;
        read_protected_file(ProtectedFileSecurity::LocalServiceHostMarker, path, limit)
    }

    fn validate_protected_file_request(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        path: &Path,
    ) -> Result<(), InstallerRootError> {
        let request = primitive_request(spec);
        self.executor.validate_read_request(&request)?;
        if !path.is_absolute()
            || windows_paths_equal(path, &spec.root)
            || !windows_path_is_within(path, &spec.root)
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(InstallerRootError::InvalidPath);
        }
        validate_existing_ancestors(path)
    }

    /// Replaces a protected marker's bytes while retaining and re-verifying
    /// its exact file identity, canonical path, owner, DACL and flush result.
    ///
    /// # Errors
    /// Rejects substitution, reparse, wrong security, oversized bytes or an
    /// indeterminate write/flush/readback.
    pub fn rewrite_protected_file(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        path: &Path,
        expected: &InstallerRootObjectSnapshot,
        bytes: &[u8],
    ) -> Result<InstallerProtectedFileReadback, InstallerRootError> {
        rewrite_protected_file(
            ProtectedFileSecurity::Installation(spec.profile),
            path,
            expected,
            bytes,
        )
    }

    /// Rewrites a raw LocalService-owned marker while retaining and verifying
    /// its exact file identity, owner, protected DACL and flush readback.
    ///
    /// # Errors
    /// Rejects non-system contours, substitution, reparse, wrong security,
    /// oversized bytes or an indeterminate write/flush/readback.
    pub fn rewrite_local_service_protected_file(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        path: &Path,
        expected: &InstallerRootObjectSnapshot,
        bytes: &[u8],
    ) -> Result<InstallerProtectedFileReadback, InstallerRootError> {
        ensure_system_service_spec(spec)?;
        rewrite_protected_file(
            ProtectedFileSecurity::LocalServiceHostMarker,
            path,
            expected,
            bytes,
        )
    }

    /// # Errors
    ///
    /// Rejects an empty root, foreign entry, multiple entries or an
    /// indeterminate directory enumeration.
    pub fn ensure_only_path(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        expected: &Path,
    ) -> Result<(), InstallerRootError> {
        ensure_only_path(&spec.root, expected)
    }

    /// # Errors
    ///
    /// Rejects identity substitution or an indeterminate exact-handle delete.
    pub fn delete_file(
        &self,
        path: &Path,
        expected: &InstallerRootObjectSnapshot,
    ) -> Result<(), InstallerRootError> {
        delete_exact_path(path, false, Some(snapshot_identity(expected)))
    }

    /// # Errors
    ///
    /// Rejects security/path/identity substitution or an indeterminate
    /// exact-handle directory delete.
    pub fn delete_root(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        expected: &InstallerRootObjectSnapshot,
    ) -> Result<(), InstallerRootError> {
        let root = open_and_readback(&spec.root, spec.profile, true, true)?;
        if root.object_snapshot() != *expected {
            return Err(InstallerRootError::IdentityMismatch);
        }
        delete_open_handle(root.file, root.identity)
    }
}

fn primitive_request(spec: &InstallerRootPrimitiveSpec) -> InstallerRootRequest {
    InstallerRootRequest {
        root: spec.root.clone(),
        installation_root: spec.installation_root.clone(),
        profile_anchor: spec.profile_anchor.clone(),
        profile: spec.profile,
    }
}

fn ensure_system_service_spec(spec: &InstallerRootPrimitiveSpec) -> Result<(), InstallerRootError> {
    if spec.profile == InstallerRootProfile::SystemService {
        Ok(())
    } else {
        Err(InstallerRootError::InvalidPath)
    }
}

#[derive(Clone, Copy)]
enum ProtectedFileSecurity {
    Installation(InstallerRootProfile),
    LocalServiceHostMarker,
}

fn snapshot_identity(snapshot: &InstallerRootObjectSnapshot) -> FileIdentity {
    FileIdentity {
        volume_serial_number: snapshot.volume_serial_number,
        file_index: snapshot.file_index,
    }
}

#[derive(Debug)]
enum Readback {
    Absent,
    Matching(RootReadback),
    Mismatch,
}

#[derive(Debug)]
struct RootReadback {
    file: std::fs::File,
    canonical_path: PathBuf,
    identity: FileIdentity,
    security_descriptor_digest: String,
}

#[derive(Debug)]
struct PinnedAbsentSnapshot {
    snapshot: InstallerRootAbsentSnapshot,
    _pins: Vec<std::fs::File>,
}

fn observe_absence(
    request: &InstallerRootRequest,
) -> Result<PinnedAbsentSnapshot, InstallerRootError> {
    match std::fs::symlink_metadata(&request.root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err(InstallerRootError::IdentityMismatch),
        Err(_) => return Err(InstallerRootError::Indeterminate),
    }
    let parent = request
        .root
        .parent()
        .ok_or(InstallerRootError::MissingParent)?;
    let mut paths: Vec<PathBuf> = parent.ancestors().map(Path::to_path_buf).collect();
    paths.reverse();
    let mut pins = Vec::with_capacity(paths.len());
    let mut snapshots = Vec::with_capacity(paths.len());
    let mut profile_anchor = None;
    for path in paths {
        let pin = open_no_follow(&path, true, false).map_err(|error| match error {
            InstallerRootError::Indeterminate => InstallerRootError::MissingParent,
            other => other,
        })?;
        let canonical = final_windows_path_from_handle(&pin).map_err(map_protected_error)?;
        if !windows_paths_equal(&canonical, &path) {
            return Err(InstallerRootError::IdentityMismatch);
        }
        let identity =
            file_identity_from_handle(&pin).map_err(|_| InstallerRootError::Indeterminate)?;
        let snapshot = InstallerRootObjectSnapshot {
            canonical_path_digest: windows_path_digest(&canonical),
            volume_serial_number: identity.volume_serial_number,
            file_index: identity.file_index,
            security_descriptor_digest: observe_security_descriptor_digest(&pin)?,
        };
        if windows_paths_equal(&canonical, &request.profile_anchor) {
            profile_anchor = Some(snapshot.clone());
        }
        pins.push(pin);
        snapshots.push(snapshot);
    }
    let parent_snapshot = snapshots
        .last()
        .cloned()
        .ok_or(InstallerRootError::MissingParent)?;
    let profile_anchor = profile_anchor.ok_or(InstallerRootError::InvalidPath)?;
    match std::fs::symlink_metadata(&request.root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err(InstallerRootError::IdentityMismatch),
        Err(_) => return Err(InstallerRootError::Indeterminate),
    }
    Ok(PinnedAbsentSnapshot {
        snapshot: InstallerRootAbsentSnapshot {
            target_path_digest: windows_path_digest(&request.root),
            profile_anchor,
            ancestors: snapshots,
            parent: parent_snapshot,
            root_absent: true,
        },
        _pins: pins,
    })
}

impl RootReadback {
    fn object_snapshot(&self) -> InstallerRootObjectSnapshot {
        InstallerRootObjectSnapshot {
            canonical_path_digest: windows_path_digest(&self.canonical_path),
            volume_serial_number: self.identity.volume_serial_number,
            file_index: self.identity.file_index,
            security_descriptor_digest: self.security_descriptor_digest.clone(),
        }
    }
}

#[cfg(windows)]
fn create_protected_file<F>(
    security: ProtectedFileSecurity,
    path: &Path,
    build: F,
) -> Result<InstallerRootObjectSnapshot, InstallerRootError>
where
    F: FnOnce(&InstallerRootObjectSnapshot) -> Result<Vec<u8>, InstallerRootError>,
{
    use std::io::Write as _;
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_HIDDEN, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };

    let descriptor = expected_protected_file_descriptor(security)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| InstallerRootError::Indeterminate)?,
        lpSecurityDescriptor: descriptor.raw,
        bInheritHandle: 0,
    };
    let wide = super::wide(path);
    let handle = unsafe {
        // SAFETY: path and descriptor are live; valid returned handle is adopted once.
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            0,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_HIDDEN,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            Err(InstallerRootError::ReceiptMismatch)
        } else {
            Err(InstallerRootError::Indeterminate)
        };
    }
    let mut file = unsafe {
        // SAFETY: handle is newly created and uniquely owned.
        std::fs::File::from_raw_handle(handle.cast())
    };
    let canonical = final_windows_path_from_handle(&file).map_err(map_protected_error)?;
    if !windows_paths_equal(&canonical, path) {
        return Err(InstallerRootError::IdentityMismatch);
    }
    let identity =
        file_identity_from_handle(&file).map_err(|_| InstallerRootError::Indeterminate)?;
    let object = InstallerRootObjectSnapshot {
        canonical_path_digest: windows_path_digest(&canonical),
        volume_serial_number: identity.volume_serial_number,
        file_index: identity.file_index,
        security_descriptor_digest: verify_protected_file_security(&file, security)?,
    };
    let bytes = build(&object)?;
    if bytes.len() as u64 > RECEIPT_LIMIT {
        return Err(InstallerRootError::ReceiptMismatch);
    }
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| InstallerRootError::Indeterminate)?;
    let final_digest = verify_protected_file_security(&file, security)?;
    if final_digest != object.security_descriptor_digest {
        return Err(InstallerRootError::SecurityMismatch);
    }
    Ok(object)
}

#[cfg(not(windows))]
fn create_protected_file<F>(
    _security: ProtectedFileSecurity,
    _path: &Path,
    _build: F,
) -> Result<InstallerRootObjectSnapshot, InstallerRootError>
where
    F: FnOnce(&InstallerRootObjectSnapshot) -> Result<Vec<u8>, InstallerRootError>,
{
    Err(InstallerRootError::UnsupportedPlatform)
}

fn read_protected_file(
    security: ProtectedFileSecurity,
    path: &Path,
    limit: u64,
) -> Result<InstallerProtectedFileReadback, InstallerRootError> {
    use std::io::Read as _;

    let file = open_no_follow(path, false, false)?;
    let canonical = final_windows_path_from_handle(&file).map_err(map_protected_error)?;
    if !windows_paths_equal(&canonical, path) {
        return Err(InstallerRootError::IdentityMismatch);
    }
    let identity =
        file_identity_from_handle(&file).map_err(|_| InstallerRootError::Indeterminate)?;
    let metadata = file
        .metadata()
        .map_err(|_| InstallerRootError::Indeterminate)?;
    if metadata.len() > limit {
        return Err(InstallerRootError::ReceiptMismatch);
    }
    let object = InstallerRootObjectSnapshot {
        canonical_path_digest: windows_path_digest(&canonical),
        volume_serial_number: identity.volume_serial_number,
        file_index: identity.file_index,
        security_descriptor_digest: verify_protected_file_security(&file, security)?,
    };
    let mut bytes = Vec::with_capacity(metadata.len().try_into().unwrap_or(0));
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| InstallerRootError::Indeterminate)?;
    if bytes.len() as u64 > limit {
        return Err(InstallerRootError::ReceiptMismatch);
    }
    Ok(InstallerProtectedFileReadback { object, bytes })
}

#[cfg(windows)]
fn rewrite_protected_file(
    security: ProtectedFileSecurity,
    path: &Path,
    expected: &InstallerRootObjectSnapshot,
    bytes: &[u8],
) -> Result<InstallerProtectedFileReadback, InstallerRootError> {
    use std::io::{Seek as _, Write as _};
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE,
    };

    if bytes.len() as u64 > RECEIPT_LIMIT {
        return Err(InstallerRootError::ReceiptMismatch);
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = options
        .open(path)
        .map_err(|_| InstallerRootError::Indeterminate)?;
    let metadata = file
        .metadata()
        .map_err(|_| InstallerRootError::Indeterminate)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || metadata.is_dir() {
        return Err(InstallerRootError::ReparsePoint);
    }
    let canonical = final_windows_path_from_handle(&file).map_err(map_protected_error)?;
    if !windows_paths_equal(&canonical, path) {
        return Err(InstallerRootError::IdentityMismatch);
    }
    let identity =
        file_identity_from_handle(&file).map_err(|_| InstallerRootError::Indeterminate)?;
    let actual = InstallerRootObjectSnapshot {
        canonical_path_digest: windows_path_digest(&canonical),
        volume_serial_number: identity.volume_serial_number,
        file_index: identity.file_index,
        security_descriptor_digest: verify_protected_file_security(&file, security)?,
    };
    if &actual != expected {
        return Err(InstallerRootError::IdentityMismatch);
    }
    file.set_len(0)
        .and_then(|()| file.rewind())
        .and_then(|()| file.write_all(bytes))
        .and_then(|()| file.sync_all())
        .map_err(|_| InstallerRootError::Indeterminate)?;
    drop(file);
    let readback = read_protected_file(security, path, RECEIPT_LIMIT)?;
    if readback.object != *expected || readback.bytes != bytes {
        return Err(InstallerRootError::IdentityMismatch);
    }
    Ok(readback)
}

#[cfg(not(windows))]
fn rewrite_protected_file(
    _security: ProtectedFileSecurity,
    _path: &Path,
    _expected: &InstallerRootObjectSnapshot,
    _bytes: &[u8],
) -> Result<InstallerProtectedFileReadback, InstallerRootError> {
    Err(InstallerRootError::UnsupportedPlatform)
}

#[cfg(windows)]
fn create_directory_atomic(
    profile: InstallerRootProfile,
    path: &Path,
) -> Result<bool, InstallerRootError> {
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    let parent = path.parent().ok_or(InstallerRootError::MissingParent)?;
    let _parent = open_no_follow(parent, true, false).map_err(|error| match error {
        InstallerRootError::Indeterminate => InstallerRootError::MissingParent,
        other => other,
    })?;
    let descriptor = expected_descriptor(profile, true)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| InstallerRootError::Indeterminate)?,
        lpSecurityDescriptor: descriptor.raw,
        bInheritHandle: 0,
    };
    let wide = super::wide(path);
    if unsafe {
        // SAFETY: the path and protected descriptor remain live for the call.
        CreateDirectoryW(wide.as_ptr(), &raw const attributes)
    } != 0
    {
        return Ok(true);
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        Ok(false)
    } else {
        Err(InstallerRootError::Indeterminate)
    }
}

#[cfg(not(windows))]
fn create_directory_atomic(
    _profile: InstallerRootProfile,
    _path: &Path,
) -> Result<bool, InstallerRootError> {
    Err(InstallerRootError::UnsupportedPlatform)
}

#[cfg(windows)]
fn open_no_follow(
    path: &Path,
    directory: bool,
    delete: bool,
) -> Result<std::fs::File, InstallerRootError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.access_mode(FILE_GENERIC_READ | if delete { DELETE } else { 0 });
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    options.custom_flags(
        FILE_FLAG_OPEN_REPARSE_POINT
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            },
    );
    let file = options
        .open(path)
        .map_err(|_| InstallerRootError::Indeterminate)?;
    let metadata = file
        .metadata()
        .map_err(|_| InstallerRootError::Indeterminate)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(InstallerRootError::ReparsePoint);
    }
    if metadata.is_dir() != directory {
        return Err(InstallerRootError::IdentityMismatch);
    }
    Ok(file)
}

#[cfg(not(windows))]
fn open_no_follow(
    _path: &Path,
    _directory: bool,
    _delete: bool,
) -> Result<std::fs::File, InstallerRootError> {
    Err(InstallerRootError::UnsupportedPlatform)
}

fn open_and_readback(
    path: &Path,
    profile: InstallerRootProfile,
    directory: bool,
    delete: bool,
) -> Result<RootReadback, InstallerRootError> {
    let file = open_no_follow(path, directory, delete)?;
    let canonical_path = final_windows_path_from_handle(&file).map_err(map_protected_error)?;
    if !windows_paths_equal(&canonical_path, path) {
        return Err(InstallerRootError::IdentityMismatch);
    }
    let identity =
        file_identity_from_handle(&file).map_err(|_| InstallerRootError::Indeterminate)?;
    let security_descriptor_digest = verify_security(&file, profile, directory)?;
    Ok(RootReadback {
        file,
        canonical_path,
        identity,
        security_descriptor_digest,
    })
}

#[cfg(windows)]
fn expected_descriptor(
    profile: InstallerRootProfile,
    directory: bool,
) -> Result<OwnedSecurityDescriptor, InstallerRootError> {
    match profile {
        InstallerRootProfile::SystemService => {
            OwnedSecurityDescriptor::for_installer_system_object(directory)
        }
        InstallerRootProfile::UserMode | InstallerRootProfile::PortableDev => {
            let sid = current_process_sid().map_err(map_protected_error)?;
            OwnedSecurityDescriptor::for_user_owned_storage(&sid, directory)
        }
    }
    .map_err(|_| InstallerRootError::SecurityMismatch)
}

#[cfg(windows)]
fn expected_protected_file_descriptor(
    security: ProtectedFileSecurity,
) -> Result<OwnedSecurityDescriptor, InstallerRootError> {
    match security {
        ProtectedFileSecurity::Installation(profile) => expected_descriptor(profile, false),
        ProtectedFileSecurity::LocalServiceHostMarker => {
            OwnedSecurityDescriptor::for_local_service_host_marker()
                .map_err(|_| InstallerRootError::SecurityMismatch)
        }
    }
}

#[cfg(not(windows))]
fn expected_protected_file_descriptor(
    _security: ProtectedFileSecurity,
) -> Result<OwnedSecurityDescriptor, InstallerRootError> {
    Err(InstallerRootError::UnsupportedPlatform)
}

#[cfg(not(windows))]
fn expected_descriptor(
    _profile: InstallerRootProfile,
    _directory: bool,
) -> Result<OwnedSecurityDescriptor, InstallerRootError> {
    Err(InstallerRootError::UnsupportedPlatform)
}

#[cfg(windows)]
fn verify_security(
    file: &std::fs::File,
    profile: InstallerRootProfile,
    directory: bool,
) -> Result<String, InstallerRootError> {
    let expected = expected_descriptor(profile, directory)?;
    let expected_owner = match profile {
        InstallerRootProfile::SystemService => "S-1-5-18".to_owned(),
        InstallerRootProfile::UserMode | InstallerRootProfile::PortableDev => {
            current_process_sid().map_err(map_protected_error)?
        }
    };
    verify_security_exact(file, &expected, &expected_owner)
}

#[cfg(windows)]
fn verify_protected_file_security(
    file: &std::fs::File,
    security: ProtectedFileSecurity,
) -> Result<String, InstallerRootError> {
    let expected = expected_protected_file_descriptor(security)?;
    let expected_owner = match security {
        ProtectedFileSecurity::Installation(InstallerRootProfile::SystemService) => {
            "S-1-5-18".to_owned()
        }
        ProtectedFileSecurity::Installation(
            InstallerRootProfile::UserMode | InstallerRootProfile::PortableDev,
        ) => current_process_sid().map_err(map_protected_error)?,
        ProtectedFileSecurity::LocalServiceHostMarker => "S-1-5-19".to_owned(),
    };
    verify_security_exact(file, &expected, &expected_owner)
}

#[cfg(windows)]
fn verify_security_exact(
    file: &std::fs::File,
    expected: &OwnedSecurityDescriptor,
    expected_owner: &str,
) -> Result<String, InstallerRootError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorLength,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    };

    let expected_dacl = expected
        .dacl()
        .map_err(|_| InstallerRootError::SecurityMismatch)?;
    let security = INSTALLER_SECURITY_QUERY_MASK;
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        // SAFETY: the file handle is live and outputs point to valid locals.
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
    if status != ERROR_SUCCESS || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(InstallerRootError::Indeterminate);
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
    let observed_owner = (!owner.is_null())
        .then(|| sid_to_string(owner).ok())
        .flatten();
    let owner_matches = observed_owner.as_deref() == Some(expected_owner);
    let length = unsafe {
        // SAFETY: descriptor is live and self-relative descriptor length is bounded by Windows.
        GetSecurityDescriptorLength(descriptor)
    } as usize;
    let descriptor_digest = if length == 0 {
        None
    } else {
        Some(unsafe {
            // SAFETY: Windows reported the exact byte length for this live descriptor.
            digest(std::slice::from_raw_parts(descriptor.cast::<u8>(), length))
        })
    };
    unsafe { LocalFree(descriptor.cast()) };
    if !dacl_matches || !protected || !owner_matches {
        return Err(InstallerRootError::SecurityMismatch);
    }
    descriptor_digest.ok_or(InstallerRootError::Indeterminate)
}

#[cfg(windows)]
fn observe_security_descriptor_digest(file: &std::fs::File) -> Result<String, InstallerRootError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorControl, GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR,
    };

    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        // SAFETY: the handle is live and the descriptor output points to a valid local.
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            INSTALLER_SECURITY_QUERY_MASK,
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
        return Err(InstallerRootError::Indeterminate);
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    let control_ok = unsafe {
        // SAFETY: descriptor is live and output locals are valid.
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) != 0
    };
    let length = unsafe {
        // SAFETY: descriptor is live and Windows returns its bounded byte length.
        GetSecurityDescriptorLength(descriptor)
    } as usize;
    let digest_value = if control_ok && length != 0 {
        Some(unsafe {
            // SAFETY: Windows reported `length` for this live descriptor.
            digest(std::slice::from_raw_parts(descriptor.cast::<u8>(), length))
        })
    } else {
        None
    };
    unsafe { LocalFree(descriptor.cast()) };
    digest_value.ok_or(InstallerRootError::Indeterminate)
}

#[cfg(not(windows))]
fn observe_security_descriptor_digest(_file: &std::fs::File) -> Result<String, InstallerRootError> {
    Err(InstallerRootError::UnsupportedPlatform)
}

#[cfg(test)]
fn owner_sid_matches(
    profile: InstallerRootProfile,
    observed_owner: Option<&str>,
    current_owner: Option<&str>,
) -> bool {
    match profile {
        InstallerRootProfile::SystemService => observed_owner == Some("S-1-5-18"),
        InstallerRootProfile::UserMode | InstallerRootProfile::PortableDev => {
            observed_owner.is_some() && observed_owner == current_owner
        }
    }
}

#[cfg(not(windows))]
fn verify_security(
    _file: &std::fs::File,
    _profile: InstallerRootProfile,
    _directory: bool,
) -> Result<String, InstallerRootError> {
    Err(InstallerRootError::UnsupportedPlatform)
}

#[cfg(not(windows))]
fn verify_protected_file_security(
    _file: &std::fs::File,
    _security: ProtectedFileSecurity,
) -> Result<String, InstallerRootError> {
    Err(InstallerRootError::UnsupportedPlatform)
}

#[cfg(windows)]
fn delete_exact_path(
    path: &Path,
    directory: bool,
    expected_identity: Option<FileIdentity>,
) -> Result<(), InstallerRootError> {
    let file = open_no_follow(path, directory, true)?;
    let actual = file_identity_from_handle(&file).map_err(|_| InstallerRootError::Indeterminate)?;
    let expected = expected_identity.unwrap_or(actual);
    delete_open_handle(file, expected)
}

#[cfg(windows)]
fn delete_open_handle(
    file: std::fs::File,
    expected_identity: FileIdentity,
) -> Result<(), InstallerRootError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };

    let actual = file_identity_from_handle(&file).map_err(|_| InstallerRootError::Indeterminate)?;
    if actual != expected_identity {
        return Err(InstallerRootError::IdentityMismatch);
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        // SAFETY: the handle was opened with DELETE, the buffer has the exact
        // FILE_DISPOSITION_INFO layout, and deletion targets this handle identity.
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                .map_err(|_| InstallerRootError::Indeterminate)?,
        )
    } == 0
    {
        return Err(InstallerRootError::Indeterminate);
    }
    drop(file);
    Ok(())
}

fn ensure_only_path(root: &Path, expected: &Path) -> Result<(), InstallerRootError> {
    let mut entries = std::fs::read_dir(root).map_err(|_| InstallerRootError::Indeterminate)?;
    let Some(entry) = entries.next() else {
        return Err(InstallerRootError::ReceiptMismatch);
    };
    let entry = entry.map_err(|_| InstallerRootError::Indeterminate)?;
    if !windows_paths_equal(&entry.path(), expected) {
        return Err(InstallerRootError::ReceiptMismatch);
    }
    if entries.next().is_some() {
        return Err(InstallerRootError::ReceiptMismatch);
    }
    Ok(())
}

#[cfg(not(windows))]
fn delete_exact_path(
    _path: &Path,
    _directory: bool,
    _expected_identity: Option<FileIdentity>,
) -> Result<(), InstallerRootError> {
    Err(InstallerRootError::UnsupportedPlatform)
}

#[cfg(not(windows))]
fn delete_open_handle(
    _file: std::fs::File,
    _expected_identity: FileIdentity,
) -> Result<(), InstallerRootError> {
    Err(InstallerRootError::UnsupportedPlatform)
}

#[cfg(windows)]
fn token_is_elevated() -> Result<bool, InstallerRootError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(InstallerRootError::Indeterminate);
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0_u32;
    let ok = unsafe {
        // SAFETY: token is live and the fixed-size output buffer is valid.
        GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>())
                .map_err(|_| InstallerRootError::Indeterminate)?,
            &raw mut returned,
        )
    };
    unsafe { CloseHandle(token) };
    if ok == 0
        || returned
            != u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>())
                .map_err(|_| InstallerRootError::Indeterminate)?
    {
        return Err(InstallerRootError::Indeterminate);
    }
    Ok(elevation.TokenIsElevated != 0)
}

/// Observes whether the current process token is elevated without
/// mutating installer state.
///
/// This is a read-only probe. It does not create or widen installer
/// mutation authority; all durable effects remain behind
/// `WindowsInstallerRootPrimitive` and `WindowsInstallationCoordinator`.
///
/// # Errors
///
/// Returns `InstallerRootError::Indeterminate` when the token cannot be
/// classified, `UnsupportedPlatform` off Windows, or `InvalidPath` on
/// malformed input. `NotElevated` is never returned here; the caller
/// interprets `Ok(false)` explicitly.
pub fn is_process_elevated() -> Result<bool, InstallerRootError> {
    token_is_elevated()
}

#[cfg(not(windows))]
fn token_is_elevated() -> Result<bool, InstallerRootError> {
    Err(InstallerRootError::UnsupportedPlatform)
}

fn validate_existing_ancestors(path: &Path) -> Result<(), InstallerRootError> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(InstallerRootError::ReparsePoint);
            }
            Ok(metadata) => {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt as _;
                    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
                    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                        return Err(InstallerRootError::ReparsePoint);
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(InstallerRootError::Indeterminate),
        }
    }
    Ok(())
}

fn windows_path_is_within(path: &Path, contour: &Path) -> bool {
    let path_components: Vec<_> = path.components().collect();
    let contour_components: Vec<_> = contour.components().collect();
    path_components.len() >= contour_components.len()
        && path_components
            .iter()
            .zip(contour_components.iter())
            .all(|(left, right)| windows_os_strings_equal(left.as_os_str(), right.as_os_str()))
}

/// Compares canonicalized paths with Windows ordinal Unicode case semantics.
#[must_use]
pub fn windows_paths_equal(left: &Path, right: &Path) -> bool {
    windows_os_strings_equal(left.as_os_str(), right.as_os_str())
}

#[cfg(windows)]
fn windows_os_strings_equal(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

    let left: Vec<u16> = left.encode_wide().collect();
    let right: Vec<u16> = right.encode_wide().collect();
    let Ok(left_len) = i32::try_from(left.len()) else {
        return false;
    };
    let Ok(right_len) = i32::try_from(right.len()) else {
        return false;
    };
    unsafe {
        // SAFETY: both UTF-16 slices remain live for their exact lengths.
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}

#[cfg(not(windows))]
fn windows_os_strings_equal(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    left == right
}

#[cfg(windows)]
fn windows_path_digest(path: &Path) -> String {
    use std::os::windows::ffi::OsStrExt as _;

    let mut bytes = Vec::new();
    for unit in path.as_os_str().encode_wide() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    digest(&bytes)
}

/// Digests an exact Windows path as UTF-16 code units for receipt binding.
#[must_use]
pub fn windows_path_identity_digest(path: &Path) -> String {
    windows_path_digest(path)
}

#[cfg(not(windows))]
fn windows_path_digest(path: &Path) -> String {
    digest(path.as_os_str().as_encoded_bytes())
}

fn map_protected_error(error: ProtectedPathError) -> InstallerRootError {
    match error {
        ProtectedPathError::InvalidRoot | ProtectedPathError::InvalidPath => {
            InstallerRootError::InvalidPath
        }
        ProtectedPathError::ReparsePoint => InstallerRootError::ReparsePoint,
        ProtectedPathError::AclMismatch => InstallerRootError::SecurityMismatch,
        ProtectedPathError::UnsupportedPlatform => InstallerRootError::UnsupportedPlatform,
        ProtectedPathError::Io | ProtectedPathError::SizeExceeded => {
            InstallerRootError::Indeterminate
        }
    }
}

fn digest_text(value: &str) -> String {
    digest(value.as_bytes())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(all(test, windows))]
mod primitive_tests {
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        system: PathBuf,
        user: PathBuf,
        portable: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |value| value.as_nanos())
                ^ u128::from(NEXT.fetch_add(1, Ordering::Relaxed));
            let root = std::env::temp_dir().join(format!("eliot-installer-primitive-{unique:x}"));
            let system = root.join("program-data");
            let user = root.join("local-app-data");
            let portable = root.join("portable");
            for path in [&system, &user, &portable] {
                std::fs::create_dir_all(path).unwrap_or_else(|error| {
                    panic!("failed to create test contour {}: {error}", path.display())
                });
            }
            Self {
                root,
                system,
                user,
                portable,
            }
        }

        fn primitive(&self, elevated: bool) -> WindowsInstallerRootPrimitive {
            WindowsInstallerRootPrimitive {
                executor: WindowsInstallerRootExecutor {
                    policy_override: Some(RootPolicyOverride {
                        system_known_folder: self.system.clone(),
                        user_known_folder: self.user.clone(),
                        portable_root: self.portable.clone(),
                        elevated,
                    }),
                },
            }
        }

        fn user_spec(&self, leaf: &str) -> InstallerRootPrimitiveSpec {
            InstallerRootPrimitiveSpec {
                root: self.user.join("Eliot").join(leaf),
                installation_root: self.user.join("Eliot"),
                profile_anchor: self.user.clone(),
                profile: InstallerRootProfile::UserMode,
            }
        }

        fn system_spec(&self, leaf: &str) -> InstallerRootPrimitiveSpec {
            InstallerRootPrimitiveSpec {
                root: self.system.join("Eliot").join(leaf),
                installation_root: self.system.join("Eliot"),
                profile_anchor: self.system.clone(),
                profile: InstallerRootProfile::SystemService,
            }
        }

        fn ensure_user_parent(&self) {
            let created =
                create_directory_atomic(InstallerRootProfile::UserMode, &self.user.join("Eliot"))
                    .unwrap_or_else(|error| panic!("failed to create user parent: {error}"));
            assert!(created);
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn absent(
        primitive: &WindowsInstallerRootPrimitive,
        spec: &InstallerRootPrimitiveSpec,
    ) -> InstallerRootAbsentSnapshot {
        let InstallerRootPrimitiveObservation::Absent(snapshot) = primitive
            .inspect(spec)
            .unwrap_or_else(|error| panic!("absence inspect failed: {error}"))
        else {
            panic!("expected absent root")
        };
        snapshot
    }

    #[test]
    fn absent_snapshot_is_independent_and_tampering_is_rejected() {
        let fixture = Fixture::new();
        fixture.ensure_user_parent();
        let primitive = fixture.primitive(true);
        let spec = fixture.user_spec("independent");
        let observed = absent(&primitive, &spec);
        let mut forged = observed.clone();
        forged.target_path_digest = "f".repeat(64);

        assert_ne!(observed, forged);
        assert_eq!(
            primitive.create(&spec, &forged),
            Err(InstallerRootError::IdentityMismatch)
        );
        assert!(!spec.root.exists());
    }

    #[test]
    fn retained_parent_identity_substitution_is_rejected_before_create() {
        let fixture = Fixture::new();
        fixture.ensure_user_parent();
        let primitive = fixture.primitive(true);
        let spec = fixture.user_spec("parent-substitution");
        let observed = absent(&primitive, &spec);
        let parent = spec.root.parent().unwrap_or_else(|| unreachable!());
        let moved = fixture.user.join("Eliot-original");
        std::fs::rename(parent, &moved)
            .unwrap_or_else(|error| panic!("failed to substitute parent: {error}"));
        assert!(
            create_directory_atomic(InstallerRootProfile::UserMode, parent)
                .unwrap_or_else(|error| panic!("failed to create replacement parent: {error}"))
        );

        assert_eq!(
            primitive.create(&spec, &observed),
            Err(InstallerRootError::IdentityMismatch)
        );
        assert!(!spec.root.exists());
    }

    #[test]
    fn junction_substitution_is_actually_exercised_and_rejected() {
        let fixture = Fixture::new();
        fixture.ensure_user_parent();
        let primitive = fixture.primitive(true);
        let spec = fixture.user_spec("junction");
        let outside = fixture.root.join("outside");
        std::fs::create_dir(&outside)
            .unwrap_or_else(|error| panic!("failed to create junction target: {error}"));
        let output = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&spec.root)
            .arg(&outside)
            .output()
            .unwrap_or_else(|error| panic!("failed to launch mklink: {error}"));
        assert!(
            output.status.success(),
            "mklink /J was not exercised: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        {
            use std::os::windows::fs::MetadataExt as _;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

            let metadata = std::fs::symlink_metadata(&spec.root)
                .unwrap_or_else(|error| panic!("junction readback failed: {error}"));
            assert_ne!(
                metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
                0,
                "mklink succeeded without creating a reparse point"
            );
        }

        assert!(matches!(
            primitive.inspect(&spec),
            Ok(InstallerRootPrimitiveObservation::Mismatch) | Err(InstallerRootError::ReparsePoint)
        ));
        std::fs::remove_dir(&spec.root)
            .unwrap_or_else(|error| panic!("failed to remove junction: {error}"));
    }

    #[test]
    fn inherited_or_wrong_acl_is_never_matching_and_apply_is_verify_only() {
        let fixture = Fixture::new();
        fixture.ensure_user_parent();
        let primitive = fixture.primitive(true);
        let spec = fixture.user_spec("wrong-acl");
        std::fs::create_dir(&spec.root)
            .unwrap_or_else(|error| panic!("failed to create inherited-ACL root: {error}"));

        assert_eq!(
            primitive.inspect(&spec),
            Ok(InstallerRootPrimitiveObservation::Mismatch)
        );
        assert!(spec.root.exists(), "inspection must never repair the ACL");
    }

    #[test]
    fn protected_marker_create_new_flush_rewrite_and_identity_delete_are_exercised() {
        let fixture = Fixture::new();
        fixture.ensure_user_parent();
        let primitive = fixture.primitive(true);
        let spec = fixture.user_spec("marker-lifecycle");
        let snapshot = absent(&primitive, &spec);
        let created = primitive
            .create(&spec, &snapshot)
            .unwrap_or_else(|error| panic!("root create: {error}"));
        assert_eq!(created.disposition, InstallerRootCreateDisposition::Created);
        let marker_path = spec.root.join(".credential.owner");
        let marker = primitive
            .create_protected_file(&spec, &marker_path, |_| Ok(b"reserved".to_vec()))
            .unwrap_or_else(|error| panic!("marker create-new: {error}"));
        let readback = primitive
            .read_protected_file(&spec, &marker_path, 64)
            .unwrap_or_else(|error| panic!("marker readback: {error}"));
        assert_eq!(readback.object, marker);
        assert_eq!(readback.bytes, b"reserved");
        let rewritten = primitive
            .rewrite_protected_file(&spec, &marker_path, &marker, b"finalized")
            .unwrap_or_else(|error| panic!("marker rewrite: {error}"));
        assert_eq!(rewritten.object, marker);
        assert_eq!(rewritten.bytes, b"finalized");
        primitive
            .delete_file(&marker_path, &marker)
            .unwrap_or_else(|error| panic!("marker identity delete: {error}"));
        assert!(matches!(
            std::fs::symlink_metadata(&marker_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn protected_file_read_rejects_every_path_outside_the_validated_root_contour() {
        let fixture = Fixture::new();
        fixture.ensure_user_parent();
        let primitive = fixture.primitive(true);
        let spec = fixture.user_spec("read-contour");
        let snapshot = absent(&primitive, &spec);
        primitive
            .create(&spec, &snapshot)
            .unwrap_or_else(|error| panic!("root create: {error}"));
        let inside = spec.root.join("authority.json");
        primitive
            .create_protected_file(&spec, &inside, |_| Ok(b"inside".to_vec()))
            .unwrap_or_else(|error| panic!("inside create: {error}"));
        assert!(primitive.read_protected_file(&spec, &inside, 64).is_ok());

        let foreign_spec = fixture.user_spec("foreign-read-contour");
        let foreign_snapshot = absent(&primitive, &foreign_spec);
        primitive
            .create(&foreign_spec, &foreign_snapshot)
            .unwrap_or_else(|error| panic!("foreign root create: {error}"));
        let foreign = foreign_spec.root.join("authority.json");
        primitive
            .create_protected_file(&foreign_spec, &foreign, |_| Ok(b"foreign".to_vec()))
            .unwrap_or_else(|error| panic!("foreign create: {error}"));

        assert_eq!(
            primitive.read_protected_file(&spec, &foreign, 64),
            Err(InstallerRootError::InvalidPath)
        );
        let unicode_confusable = fixture
            .user
            .join("Eli\u{43e}t")
            .join("read-contour")
            .join("authority.json");
        assert_eq!(
            primitive.read_protected_file(&spec, &unicode_confusable, 64),
            Err(InstallerRootError::InvalidPath)
        );
        assert_eq!(
            primitive.read_protected_file(&spec, &spec.root, 64),
            Err(InstallerRootError::InvalidPath)
        );
        assert_eq!(
            primitive.read_protected_file(
                &spec,
                &spec
                    .root
                    .join("..")
                    .join("foreign-read-contour")
                    .join("authority.json"),
                64
            ),
            Err(InstallerRootError::InvalidPath)
        );

        let junction_root = fixture.user.join("Eliot").join("read-junction");
        let junction_target = fixture.root.join("read-junction-target");
        std::fs::create_dir(&junction_target)
            .unwrap_or_else(|error| panic!("junction target create: {error}"));
        let output = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction_root)
            .arg(&junction_target)
            .output()
            .unwrap_or_else(|error| panic!("junction command: {error}"));
        assert!(output.status.success(), "mklink /J failed: {output:?}");
        let junction_spec = fixture.user_spec("read-junction");
        assert_eq!(
            primitive.read_protected_file(
                &junction_spec,
                &junction_root.join("authority.json"),
                64,
            ),
            Err(InstallerRootError::ReparsePoint)
        );
        std::fs::remove_dir(&junction_root)
            .unwrap_or_else(|error| panic!("junction cleanup: {error}"));
    }

    #[test]
    fn non_elevated_system_read_contour_accepts_exact_path_before_acl_readback() {
        let fixture = Fixture::new();
        let spec = fixture.system_spec("kernel-work");
        std::fs::create_dir_all(&spec.root)
            .unwrap_or_else(|error| panic!("system contour fixture: {error}"));
        let path = spec.root.join("supervision-authority.json");
        std::fs::write(&path, b"sealed")
            .unwrap_or_else(|error| panic!("system file fixture: {error}"));

        let non_elevated_reader = fixture.primitive(false);
        assert_eq!(
            non_elevated_reader.validate_protected_file_request(&spec, &path),
            Ok(())
        );
        assert_ne!(
            non_elevated_reader.read_protected_file(&spec, &path, 64),
            Err(InstallerRootError::NotElevated),
            "read-only contour validation must reach exact ACL/identity readback without elevation"
        );
        assert_eq!(
            non_elevated_reader.validate_protected_file_request(
                &spec,
                &fixture.system.join("Eliot-other").join("sealed.json"),
            ),
            Err(InstallerRootError::InvalidPath)
        );
    }

    #[test]
    fn non_elevated_system_mutation_is_rejected_before_os_observation() {
        let fixture = Fixture::new();
        let primitive = fixture.primitive(false);
        let spec = fixture.system_spec("state");
        let request = primitive_request(&spec);

        assert_eq!(
            primitive.executor.validate_request(&request),
            Err(InstallerRootError::NotElevated)
        );
        assert_ne!(
            primitive.inspect(&spec),
            Err(InstallerRootError::NotElevated),
            "read-only inspection must not inherit the installer mutation elevation gate"
        );
    }

    #[test]
    fn system_root_receipt_and_host_marker_descriptors_declare_exact_owners() {
        use windows_sys::Win32::Security::{
            GetSecurityDescriptorOwner, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
        };

        assert_eq!(
            INSTALLER_SECURITY_QUERY_MASK & PROTECTED_DACL_SECURITY_INFORMATION,
            0,
            "protection is read only through GetSecurityDescriptorControl"
        );
        assert!(owner_sid_matches(
            InstallerRootProfile::SystemService,
            Some("S-1-5-18"),
            Some("S-1-5-21-1000")
        ));
        assert!(!owner_sid_matches(
            InstallerRootProfile::SystemService,
            Some("S-1-5-21-1000"),
            Some("S-1-5-21-1000")
        ));
        assert!(owner_sid_matches(
            InstallerRootProfile::UserMode,
            Some("S-1-5-21-1000"),
            Some("S-1-5-21-1000")
        ));
        assert!(!owner_sid_matches(
            InstallerRootProfile::UserMode,
            Some("S-1-5-18"),
            Some("S-1-5-21-1000")
        ));

        for directory in [true, false] {
            let descriptor = OwnedSecurityDescriptor::for_installer_system_object(directory)
                .unwrap_or_else(|error| panic!("system descriptor creation failed: {error}"));
            let mut owner: PSID = std::ptr::null_mut();
            let mut defaulted = 0;
            let ok = unsafe {
                // SAFETY: the descriptor and output locals remain live for the call.
                GetSecurityDescriptorOwner(descriptor.raw, &raw mut owner, &raw mut defaulted)
            };
            assert_ne!(ok, 0);
            assert!(!owner.is_null());
            assert_eq!(
                sid_to_string(owner).unwrap_or_else(|error| panic!("owner SID failed: {error}")),
                "S-1-5-18"
            );
        }

        let marker = OwnedSecurityDescriptor::for_local_service_host_marker()
            .unwrap_or_else(|error| panic!("marker descriptor creation failed: {error}"));
        let mut marker_owner: PSID = std::ptr::null_mut();
        let mut marker_defaulted = 0;
        let marker_ok = unsafe {
            // SAFETY: the descriptor and output locals remain live for the call.
            GetSecurityDescriptorOwner(marker.raw, &raw mut marker_owner, &raw mut marker_defaulted)
        };
        assert_ne!(marker_ok, 0);
        assert_eq!(
            sid_to_string(marker_owner)
                .unwrap_or_else(|error| panic!("marker owner SID failed: {error}")),
            "S-1-5-19"
        );

        let fixture = Fixture::new();
        assert_eq!(
            ensure_system_service_spec(&fixture.user_spec("not-system")),
            Err(InstallerRootError::InvalidPath)
        );
    }

    #[test]
    fn is_process_elevated_is_observable_without_mutation() {
        let first = is_process_elevated()
            .unwrap_or_else(|error| panic!("is_process_elevated must be observable: {error}"));
        let second = is_process_elevated().unwrap_or_else(|error| {
            panic!("second is_process_elevated probe must be observable: {error}")
        });
        assert_eq!(
            first, second,
            "elevation probe must be stable without mutation"
        );
    }
}
