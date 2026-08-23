//! No-follow Windows runtime-root effects used by the durable installer.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    FileIdentity, OwnedSecurityDescriptor, ProtectedPathError, current_process_sid,
    current_user_local_app_data_root, file_identity_from_handle, protected_program_data_root,
    sid_to_string,
};

#[cfg(not(windows))]
use super::final_windows_path_from_handle;

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

/// Bounded stage at which a raw Win32 result was observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerRootStage {
    OpenThreadToken,
    OpenProcessToken,
    DuplicateToken,
    QueryPrivilege,
    EnablePrivilege,
    BindThreadToken,
    RestorePrivilege,
    RestoreThreadToken,
    CreateDirectory,
    OpenReadback,
    Readback,
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
    /// A raw Win32 failure observed at a bounded operation stage.
    Win32 {
        stage: InstallerRootStage,
        code: u32,
    },
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
            Err(error) => Err(map_io_error(InstallerRootStage::Readback, &error)),
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
                let installations = expected.join("installations");
                let installation_parent = request.installation_root.parent();
                let installation_key = request
                    .installation_root
                    .file_name()
                    .and_then(|name| name.to_str());
                if installation_parent
                    .is_none_or(|parent| !windows_paths_equal(parent, &installations))
                    || installation_key.is_none_or(|key| {
                        key.len() != 64
                            || !key
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                    })
                    || !windows_path_is_within(&request.root, &expected)
                {
                    return Err(InstallerRootError::InvalidPath);
                }
                let root_is_profile = windows_paths_equal(&request.root, &expected);
                let root_is_installations = windows_paths_equal(&request.root, &installations);
                let packages = expected.join("packages");
                let root_is_packages = windows_paths_equal(&request.root, &packages);
                if !root_is_profile
                    && !root_is_installations
                    && !root_is_packages
                    && !windows_path_is_within(&request.root, &request.installation_root)
                {
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

/// Outcome of a root create attempt, retaining the OS create disposition when
/// post-create readback fails.
#[derive(Debug)]
pub enum InstallerRootCreateAttempt {
    /// The create call and complete identity/security readback succeeded.
    Complete(InstallerRootPrimitiveCreate),
    /// The directory was created, but bounded post-create readback failed.
    Failed {
        disposition: InstallerRootCreateDisposition,
        error: InstallerRootError,
    },
    /// The target appeared while the pinned absence precondition was being
    /// established; no create call was issued.
    PreconditionRace {
        /// Stable semantic reference for the known target-appearance race.
        pending_ref: &'static str,
    },
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
                observe_absence(&request)
                    .map_err(|error| map_absence_observation_error(&error))?
                    .snapshot,
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
        match self.create_attempt(spec, expected)? {
            InstallerRootCreateAttempt::Complete(value) => Ok(value),
            InstallerRootCreateAttempt::Failed { error, .. } => Err(error),
            InstallerRootCreateAttempt::PreconditionRace { .. } => {
                Err(InstallerRootError::IdentityMismatch)
            }
        }
    }

    /// Performs a create while retaining the raw create disposition if
    /// post-create identity/security readback fails.
    ///
    /// # Errors
    ///
    /// Returns a validation, precondition, privilege or create-call error
    /// before a disposition can be retained.
    pub fn create_attempt(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        expected: &InstallerRootAbsentSnapshot,
    ) -> Result<InstallerRootCreateAttempt, InstallerRootError> {
        let request = primitive_request(spec);
        self.executor.validate_request(&request)?;
        let pinned = match observe_absence(&request) {
            Ok(pinned) => pinned,
            Err(AbsenceObservationError::RootAppeared) => {
                return Ok(InstallerRootCreateAttempt::PreconditionRace {
                    pending_ref: "installer-root-absence-race-v1:precondition",
                });
            }
            Err(AbsenceObservationError::Installer(error)) => return Err(error),
        };
        if &pinned.snapshot != expected {
            return Err(InstallerRootError::IdentityMismatch);
        }
        with_system_restore_privilege(spec.profile, || {
            if !create_directory_atomic(spec.profile, &spec.root)? {
                return Ok(InstallerRootCreateAttempt::Complete(
                    InstallerRootPrimitiveCreate {
                        disposition: InstallerRootCreateDisposition::AlreadyExists,
                        root: None,
                    },
                ));
            }
            let root = match open_and_readback(&spec.root, spec.profile, true, false) {
                Ok(root) => root,
                Err(error) => {
                    return Ok(InstallerRootCreateAttempt::Failed {
                        disposition: InstallerRootCreateDisposition::Created,
                        error,
                    });
                }
            };
            Ok(InstallerRootCreateAttempt::Complete(
                InstallerRootPrimitiveCreate {
                    disposition: InstallerRootCreateDisposition::Created,
                    root: Some(root.object_snapshot()),
                },
            ))
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

/// Distinguishes a target that appeared during a stable absence observation
/// from a semantic contour/identity failure.  The distinction is important:
/// only the former is safe to expose as the typed absence-race reference.
#[derive(Debug)]
enum AbsenceObservationError {
    RootAppeared,
    Installer(InstallerRootError),
}

fn map_absence_observation_error(error: &AbsenceObservationError) -> InstallerRootError {
    match error {
        AbsenceObservationError::RootAppeared => InstallerRootError::IdentityMismatch,
        AbsenceObservationError::Installer(error) => *error,
    }
}

fn observe_absence(
    request: &InstallerRootRequest,
) -> Result<PinnedAbsentSnapshot, AbsenceObservationError> {
    match std::fs::symlink_metadata(&request.root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(AbsenceObservationError::Installer(
                InstallerRootError::IdentityMismatch,
            ));
        }
        Err(error) => {
            return Err(AbsenceObservationError::Installer(map_io_error(
                InstallerRootStage::Readback,
                &error,
            )));
        }
    }
    let parent = request
        .root
        .parent()
        .ok_or(AbsenceObservationError::Installer(
            InstallerRootError::MissingParent,
        ))?;
    let mut paths: Vec<PathBuf> = parent.ancestors().map(Path::to_path_buf).collect();
    paths.reverse();
    let mut pins = Vec::with_capacity(paths.len());
    let mut snapshots = Vec::with_capacity(paths.len());
    let mut profile_anchor = None;
    for path in paths {
        let pin = open_no_follow(&path, true, false)
            .map_err(|error| match error {
                InstallerRootError::Indeterminate => InstallerRootError::MissingParent,
                other => other,
            })
            .map_err(AbsenceObservationError::Installer)?;
        let canonical = canonical_path_from_handle(&pin, InstallerRootStage::Readback)
            .map_err(AbsenceObservationError::Installer)?;
        if !windows_paths_equal(&canonical, &path) {
            return Err(AbsenceObservationError::Installer(
                InstallerRootError::IdentityMismatch,
            ));
        }
        let identity = file_identity_from_handle_staged(&pin, InstallerRootStage::Readback)
            .map_err(AbsenceObservationError::Installer)?;
        let snapshot = InstallerRootObjectSnapshot {
            canonical_path_digest: windows_path_digest(&canonical),
            volume_serial_number: identity.volume_serial_number,
            file_index: identity.file_index,
            security_descriptor_digest: observe_security_descriptor_digest(&pin)
                .map_err(AbsenceObservationError::Installer)?,
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
        .ok_or(AbsenceObservationError::Installer(
            InstallerRootError::MissingParent,
        ))?;
    let profile_anchor = profile_anchor.ok_or(AbsenceObservationError::Installer(
        InstallerRootError::InvalidPath,
    ))?;
    match std::fs::symlink_metadata(&request.root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            if !absence_contour_matches(request, &snapshots)
                .map_err(AbsenceObservationError::Installer)?
            {
                return Err(AbsenceObservationError::Installer(
                    InstallerRootError::IdentityMismatch,
                ));
            }
            return Err(AbsenceObservationError::RootAppeared);
        }
        Err(error) => {
            return Err(AbsenceObservationError::Installer(map_io_error(
                InstallerRootStage::Readback,
                &error,
            )));
        }
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

/// Re-checks the retained parent contour before classifying a target
/// appearance as the semantic absence race.  A replacement parent (or any
/// replaced ancestor) is an identity mismatch, never an absence race.
fn absence_contour_matches(
    request: &InstallerRootRequest,
    snapshots: &[InstallerRootObjectSnapshot],
) -> Result<bool, InstallerRootError> {
    let parent = request
        .root
        .parent()
        .ok_or(InstallerRootError::MissingParent)?;
    let mut paths: Vec<PathBuf> = parent.ancestors().map(Path::to_path_buf).collect();
    paths.reverse();
    if paths.len() != snapshots.len() {
        return Err(InstallerRootError::Indeterminate);
    }
    for (path, expected) in paths.iter().zip(snapshots) {
        let pin = open_no_follow(path, true, false).map_err(|error| match error {
            InstallerRootError::Indeterminate => InstallerRootError::MissingParent,
            other => other,
        })?;
        let canonical = canonical_path_from_handle(&pin, InstallerRootStage::Readback)?;
        if !windows_paths_equal(&canonical, path) {
            return Ok(false);
        }
        let identity = file_identity_from_handle_staged(&pin, InstallerRootStage::Readback)?;
        if identity != snapshot_identity(expected) {
            return Ok(false);
        }
    }
    Ok(true)
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
    let canonical = canonical_path_from_handle(&file, InstallerRootStage::Readback)?;
    if !windows_paths_equal(&canonical, path) {
        return Err(InstallerRootError::IdentityMismatch);
    }
    let identity = file_identity_from_handle_staged(&file, InstallerRootStage::Readback)?;
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
        .map_err(|error| map_io_error(InstallerRootStage::Readback, &error))?;
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

    #[cfg(windows)]
    let file = open_no_follow_staged(path, false, false, true)?;
    #[cfg(not(windows))]
    let file = open_no_follow(path, false, false)?;
    let canonical = canonical_path_from_handle(&file, InstallerRootStage::Readback)?;
    if !windows_paths_equal(&canonical, path) {
        return Err(InstallerRootError::IdentityMismatch);
    }
    let identity = file_identity_from_handle_staged(&file, InstallerRootStage::Readback)?;
    let metadata = file
        .metadata()
        .map_err(|error| map_io_error(InstallerRootStage::Readback, &error))?;
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
        .map_err(|error| map_io_error(InstallerRootStage::Readback, &error))?;
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
        .map_err(|error| map_io_error(InstallerRootStage::OpenReadback, &error))?;
    let metadata = file
        .metadata()
        .map_err(|error| map_io_error(InstallerRootStage::Readback, &error))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || metadata.is_dir() {
        return Err(InstallerRootError::ReparsePoint);
    }
    let canonical = canonical_path_from_handle(&file, InstallerRootStage::Readback)?;
    if !windows_paths_equal(&canonical, path) {
        return Err(InstallerRootError::IdentityMismatch);
    }
    let identity = file_identity_from_handle_staged(&file, InstallerRootStage::Readback)?;
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
        .map_err(|error| map_io_error(InstallerRootStage::Readback, &error))?;
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivilegeState {
    luid: u64,
    attributes: u32,
}

#[cfg(windows)]
trait PrivilegeApi {
    fn open_thread_token(&mut self) -> Result<usize, u32>;
    fn open_process_token(&mut self) -> Result<usize, u32>;
    fn duplicate_token(&mut self, source: usize) -> Result<usize, u32>;
    fn query_restore_privilege(&mut self, token: usize) -> Result<PrivilegeState, u32>;
    fn enable_restore_privilege(&mut self, token: usize, luid: u64) -> Result<(), u32>;
    fn restore_restore_privilege(&mut self, token: usize, state: PrivilegeState)
    -> Result<(), u32>;
    fn bind_thread_token(&mut self, token: Option<usize>) -> Result<(), u32>;
    fn close_token(&mut self, token: usize);
}

#[cfg(windows)]
struct NativePrivilegeApi;

#[cfg(windows)]
impl PrivilegeApi for NativePrivilegeApi {
    fn open_thread_token(&mut self) -> Result<usize, u32> {
        use windows_sys::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY};
        use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
        let mut token = std::ptr::null_mut();
        if unsafe {
            // SAFETY: the current thread pseudo-handle and output pointer are valid.
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                1,
                &raw mut token,
            )
        } == 0
        {
            Err(unsafe {
                // SAFETY: called immediately after the failed Win32 call.
                windows_sys::Win32::Foundation::GetLastError()
            })
        } else {
            Ok(token as usize)
        }
    }

    fn open_process_token(&mut self) -> Result<usize, u32> {
        use windows_sys::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let mut token = std::ptr::null_mut();
        if unsafe {
            // SAFETY: the current process pseudo-handle and output pointer are valid.
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &raw mut token,
            )
        } == 0
        {
            Err(unsafe {
                // SAFETY: called immediately after the failed Win32 call.
                windows_sys::Win32::Foundation::GetLastError()
            })
        } else {
            Ok(token as usize)
        }
    }

    fn duplicate_token(&mut self, source: usize) -> Result<usize, u32> {
        use windows_sys::Win32::Security::{
            DuplicateTokenEx, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES, TOKEN_IMPERSONATE,
            TOKEN_QUERY, TokenImpersonation,
        };
        let mut duplicate = std::ptr::null_mut();
        if unsafe {
            // SAFETY: source is a live token handle and duplicate is a valid output pointer.
            DuplicateTokenEx(
                source as windows_sys::Win32::Foundation::HANDLE,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE | TOKEN_QUERY,
                std::ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &raw mut duplicate,
            )
        } == 0
        {
            Err(unsafe {
                // SAFETY: called immediately after the failed Win32 call.
                windows_sys::Win32::Foundation::GetLastError()
            })
        } else {
            Ok(duplicate as usize)
        }
    }

    fn query_restore_privilege(&mut self, token: usize) -> Result<PrivilegeState, u32> {
        use windows_sys::Win32::Security::{
            GetTokenInformation, TOKEN_PRIVILEGES, TokenPrivileges,
        };
        let mut required = 0_u32;
        let _ = unsafe {
            // SAFETY: the zero-length probe has no output buffer.
            GetTokenInformation(
                token as windows_sys::Win32::Foundation::HANDLE,
                TokenPrivileges,
                std::ptr::null_mut(),
                0,
                &raw mut required,
            )
        };
        if required == 0 {
            return Err(unsafe {
                // SAFETY: called immediately after the failed size probe.
                windows_sys::Win32::Foundation::GetLastError()
            });
        }
        let words = usize::try_from(required)
            .ok()
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<usize>() - 1))
            .map(|bytes| bytes / std::mem::size_of::<usize>())
            .ok_or(windows_sys::Win32::Foundation::ERROR_ARITHMETIC_OVERFLOW)?;
        let mut buffer = vec![0_usize; words];
        if unsafe {
            // SAFETY: buffer is aligned and at least `required` bytes long.
            GetTokenInformation(
                token as windows_sys::Win32::Foundation::HANDLE,
                TokenPrivileges,
                buffer.as_mut_ptr().cast(),
                required,
                &raw mut required,
            )
        } == 0
        {
            return Err(unsafe {
                // SAFETY: called immediately after the failed Win32 call.
                windows_sys::Win32::Foundation::GetLastError()
            });
        }
        let returned_bytes = usize::try_from(required)
            .map_err(|_| windows_sys::Win32::Foundation::ERROR_ARITHMETIC_OVERFLOW)?;
        let allocated_bytes = buffer
            .len()
            .checked_mul(std::mem::size_of::<usize>())
            .ok_or(windows_sys::Win32::Foundation::ERROR_ARITHMETIC_OVERFLOW)?;
        let privilege_count_end = std::mem::offset_of!(TOKEN_PRIVILEGES, PrivilegeCount)
            .checked_add(std::mem::size_of::<u32>())
            .ok_or(windows_sys::Win32::Foundation::ERROR_ARITHMETIC_OVERFLOW)?;
        let privileges_offset = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
        if returned_bytes > allocated_bytes || returned_bytes < privilege_count_end {
            return Err(windows_sys::Win32::Foundation::ERROR_BAD_LENGTH);
        }
        let privileges = buffer.as_ptr().cast::<TOKEN_PRIVILEGES>();
        let count = unsafe {
            // SAFETY: GetTokenInformation filled the TOKEN_PRIVILEGES header.
            (*privileges).PrivilegeCount
        };
        let count = usize::try_from(count)
            .map_err(|_| windows_sys::Win32::Foundation::ERROR_ARITHMETIC_OVERFLOW)?;
        let entries_bytes = count
            .checked_mul(std::mem::size_of::<
                windows_sys::Win32::Security::LUID_AND_ATTRIBUTES,
            >())
            .ok_or(windows_sys::Win32::Foundation::ERROR_ARITHMETIC_OVERFLOW)?;
        let entries_end = privileges_offset
            .checked_add(entries_bytes)
            .ok_or(windows_sys::Win32::Foundation::ERROR_ARITHMETIC_OVERFLOW)?;
        if entries_end > returned_bytes {
            return Err(windows_sys::Win32::Foundation::ERROR_BAD_LENGTH);
        }
        let mut luid = windows_sys::Win32::Foundation::LUID::default();
        let lookup_ok = unsafe {
            // SAFETY: the output LUID is valid and the constant name is NUL-terminated.
            windows_sys::Win32::Security::LookupPrivilegeValueW(
                std::ptr::null(),
                windows_sys::Win32::Security::SE_RESTORE_NAME,
                &raw mut luid,
            )
        };
        if lookup_ok == 0 {
            return Err(unsafe {
                // SAFETY: called immediately after the failed Win32 call.
                windows_sys::Win32::Foundation::GetLastError()
            });
        }
        let entries = unsafe {
            // SAFETY: the validated returned buffer contains `count` entries.
            std::slice::from_raw_parts::<windows_sys::Win32::Security::LUID_AND_ATTRIBUTES>(
                buffer.as_ptr().cast::<u8>().add(privileges_offset).cast(),
                count,
            )
        };
        entries
            .iter()
            .find(|entry| {
                entry.Luid.LowPart == luid.LowPart && entry.Luid.HighPart == luid.HighPart
            })
            .map(|entry| PrivilegeState {
                luid: u64::from(entry.Luid.LowPart)
                    | (u64::from(u32::from_ne_bytes(entry.Luid.HighPart.to_ne_bytes())) << 32),
                attributes: entry.Attributes,
            })
            .ok_or(windows_sys::Win32::Foundation::ERROR_NOT_ALL_ASSIGNED)
    }

    fn enable_restore_privilege(&mut self, token: usize, luid: u64) -> Result<(), u32> {
        use windows_sys::Win32::Security::{
            AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES,
        };
        let low = u32::try_from(luid & u64::from(u32::MAX))
            .map_err(|_| windows_sys::Win32::Foundation::ERROR_ARITHMETIC_OVERFLOW)?;
        let high = u32::try_from(luid >> 32)
            .map_err(|_| windows_sys::Win32::Foundation::ERROR_ARITHMETIC_OVERFLOW)?;
        let state = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: windows_sys::Win32::Foundation::LUID {
                    LowPart: low,
                    HighPart: i32::from_ne_bytes(high.to_ne_bytes()),
                },
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let ok = unsafe {
            // SAFETY: token is a live duplicate with TOKEN_ADJUST_PRIVILEGES and state is valid.
            AdjustTokenPrivileges(
                token as windows_sys::Win32::Foundation::HANDLE,
                0,
                &raw const state,
                u32::try_from(std::mem::size_of::<TOKEN_PRIVILEGES>())
                    .map_err(|_| windows_sys::Win32::Foundation::ERROR_ARITHMETIC_OVERFLOW)?,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        let code = unsafe {
            // SAFETY: captured immediately after AdjustTokenPrivileges.
            windows_sys::Win32::Foundation::GetLastError()
        };
        if ok == 0 || code == windows_sys::Win32::Foundation::ERROR_NOT_ALL_ASSIGNED {
            Err(if code == 0 {
                windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED
            } else {
                code
            })
        } else {
            Ok(())
        }
    }

    fn restore_restore_privilege(
        &mut self,
        token: usize,
        state: PrivilegeState,
    ) -> Result<(), u32> {
        use windows_sys::Win32::Security::{
            AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES,
        };
        let low = u32::try_from(state.luid & u64::from(u32::MAX))
            .map_err(|_| windows_sys::Win32::Foundation::ERROR_ARITHMETIC_OVERFLOW)?;
        let high = u32::try_from(state.luid >> 32)
            .map_err(|_| windows_sys::Win32::Foundation::ERROR_ARITHMETIC_OVERFLOW)?;
        let previous = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: windows_sys::Win32::Foundation::LUID {
                    LowPart: low,
                    HighPart: i32::from_ne_bytes(high.to_ne_bytes()),
                },
                Attributes: state.attributes,
            }],
        };
        let ok = unsafe {
            // SAFETY: token is a live duplicate and the restore state is valid.
            AdjustTokenPrivileges(
                token as windows_sys::Win32::Foundation::HANDLE,
                0,
                &raw const previous,
                u32::try_from(std::mem::size_of::<TOKEN_PRIVILEGES>())
                    .map_err(|_| windows_sys::Win32::Foundation::ERROR_ARITHMETIC_OVERFLOW)?,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        let code = unsafe {
            // SAFETY: captured immediately after AdjustTokenPrivileges.
            windows_sys::Win32::Foundation::GetLastError()
        };
        if ok == 0 || code != 0 {
            Err(if code == 0 {
                windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED
            } else {
                code
            })
        } else {
            Ok(())
        }
    }

    fn bind_thread_token(&mut self, token: Option<usize>) -> Result<(), u32> {
        use windows_sys::Win32::System::Threading::SetThreadToken;
        if unsafe {
            // SAFETY: null thread selects the current thread; token is either a live handle or null.
            SetThreadToken(
                std::ptr::null(),
                token.unwrap_or_default() as windows_sys::Win32::Foundation::HANDLE,
            )
        } == 0
        {
            Err(unsafe {
                // SAFETY: called immediately after the failed Win32 call.
                windows_sys::Win32::Foundation::GetLastError()
            })
        } else {
            Ok(())
        }
    }

    fn close_token(&mut self, token: usize) {
        unsafe {
            // SAFETY: each token is closed exactly once by its owner.
            windows_sys::Win32::Foundation::CloseHandle(
                token as windows_sys::Win32::Foundation::HANDLE,
            );
        }
    }
}

#[cfg(windows)]
struct ScopedRestorePrivilege<'a, A: PrivilegeApi + ?Sized> {
    api: &'a mut A,
    duplicate: usize,
    prior_thread: Option<usize>,
    prior_privilege: PrivilegeState,
    adjusted: bool,
    armed: bool,
    _not_send_sync: std::marker::PhantomData<*mut ()>,
}

#[cfg(windows)]
impl<'a, A: PrivilegeApi + ?Sized> ScopedRestorePrivilege<'a, A> {
    fn enter(api: &'a mut A) -> Result<Self, InstallerRootError> {
        use windows_sys::Win32::Foundation::{ERROR_NO_TOKEN, ERROR_NOT_ALL_ASSIGNED};
        let (source, prior_thread) = match api.open_thread_token() {
            Ok(token) => (token, Some(token)),
            Err(code) if code == ERROR_NO_TOKEN => (
                api.open_process_token()
                    .map_err(|code| InstallerRootError::Win32 {
                        stage: InstallerRootStage::OpenProcessToken,
                        code,
                    })?,
                None,
            ),
            Err(code) => {
                return Err(InstallerRootError::Win32 {
                    stage: InstallerRootStage::OpenThreadToken,
                    code,
                });
            }
        };
        let duplicate = match api.duplicate_token(source) {
            Ok(token) => token,
            Err(code) => {
                api.close_token(source);
                return Err(InstallerRootError::Win32 {
                    stage: InstallerRootStage::DuplicateToken,
                    code,
                });
            }
        };
        if prior_thread.is_none() {
            api.close_token(source);
        }
        let prior_privilege = match api.query_restore_privilege(duplicate) {
            Ok(state) => state,
            Err(code) => {
                api.close_token(duplicate);
                if let Some(token) = prior_thread {
                    api.close_token(token);
                }
                return Err(InstallerRootError::Win32 {
                    stage: InstallerRootStage::QueryPrivilege,
                    code: if code == 0 {
                        ERROR_NOT_ALL_ASSIGNED
                    } else {
                        code
                    },
                });
            }
        };
        let adjusted =
            if prior_privilege.attributes & windows_sys::Win32::Security::SE_PRIVILEGE_ENABLED == 0
            {
                if let Err(code) = api.enable_restore_privilege(duplicate, prior_privilege.luid) {
                    api.close_token(duplicate);
                    if let Some(token) = prior_thread {
                        api.close_token(token);
                    }
                    return Err(InstallerRootError::Win32 {
                        stage: InstallerRootStage::EnablePrivilege,
                        code,
                    });
                }
                true
            } else {
                false
            };
        if let Err(code) = api.bind_thread_token(Some(duplicate)) {
            let restore = if adjusted {
                api.restore_restore_privilege(duplicate, prior_privilege)
            } else {
                Ok(())
            };
            api.close_token(duplicate);
            if let Some(token) = prior_thread {
                api.close_token(token);
            }
            if let Err(_restore_code) = restore {
                std::process::abort();
            }
            return Err(InstallerRootError::Win32 {
                stage: InstallerRootStage::BindThreadToken,
                code,
            });
        }
        Ok(Self {
            api,
            duplicate,
            prior_thread,
            prior_privilege,
            adjusted,
            armed: true,
            _not_send_sync: std::marker::PhantomData,
        })
    }

    fn restore(&mut self) {
        if !self.armed {
            return;
        }
        if self.adjusted
            && self
                .api
                .restore_restore_privilege(self.duplicate, self.prior_privilege)
                .is_err()
        {
            std::process::abort();
        }
        if let Err(_code) = self.api.bind_thread_token(self.prior_thread) {
            std::process::abort();
        }
        self.api.close_token(self.duplicate);
        if let Some(token) = self.prior_thread {
            self.api.close_token(token);
        }
        self.armed = false;
    }
}

#[cfg(windows)]
impl<A: PrivilegeApi + ?Sized> Drop for ScopedRestorePrivilege<'_, A> {
    fn drop(&mut self) {
        if self.armed {
            self.restore();
        }
    }
}

#[cfg(windows)]
fn with_native_restore_privilege<F, T>(f: F) -> Result<T, InstallerRootError>
where
    F: FnOnce() -> Result<T, InstallerRootError>,
{
    let mut api = NativePrivilegeApi;
    let mut guard = ScopedRestorePrivilege::enter(&mut api)?;
    let result = f();
    guard.restore();
    result
}

#[allow(clippy::needless_return)]
fn with_system_restore_privilege<F, T>(
    profile: InstallerRootProfile,
    f: F,
) -> Result<T, InstallerRootError>
where
    F: FnOnce() -> Result<T, InstallerRootError>,
{
    if profile != InstallerRootProfile::SystemService {
        return f();
    }
    #[cfg(windows)]
    {
        return with_native_restore_privilege(f);
    }
    #[cfg(not(windows))]
    {
        let _ = f;
        Err(InstallerRootError::UnsupportedPlatform)
    }
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
        InstallerRootError::Indeterminate
        | InstallerRootError::Win32 {
            stage: InstallerRootStage::OpenReadback,
            ..
        } => InstallerRootError::MissingParent,
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
    let code = unsafe {
        // SAFETY: captured immediately after the failed CreateDirectoryW call.
        GetLastError()
    };
    if code == ERROR_ALREADY_EXISTS {
        Ok(false)
    } else {
        Err(InstallerRootError::Win32 {
            stage: InstallerRootStage::CreateDirectory,
            code,
        })
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
    open_no_follow_staged(path, directory, delete, false)
}

#[cfg(windows)]
fn open_no_follow_staged(
    path: &Path,
    directory: bool,
    delete: bool,
    report_win32: bool,
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
    let file = options.open(path).map_err(|error| {
        if report_win32 {
            error
                .raw_os_error()
                .map_or(InstallerRootError::Indeterminate, |code| {
                    u32::try_from(code).map_or(InstallerRootError::Indeterminate, |code| {
                        InstallerRootError::Win32 {
                            stage: InstallerRootStage::OpenReadback,
                            code,
                        }
                    })
                })
        } else {
            InstallerRootError::Indeterminate
        }
    })?;
    let metadata = file.metadata().map_err(|error| {
        if report_win32 {
            map_io_error(InstallerRootStage::OpenReadback, &error)
        } else {
            InstallerRootError::Indeterminate
        }
    })?;
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
    #[cfg(windows)]
    let file = open_no_follow_staged(path, directory, delete, true)?;
    #[cfg(not(windows))]
    let file = open_no_follow(path, directory, delete)?;
    let canonical_path = canonical_path_from_handle(&file, InstallerRootStage::Readback)?;
    if !windows_paths_equal(&canonical_path, path) {
        return Err(InstallerRootError::IdentityMismatch);
    }
    let identity = file_identity_from_handle_staged(&file, InstallerRootStage::Readback)?;
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
#[allow(clippy::too_many_lines)]
fn verify_security_exact(
    file: &std::fs::File,
    expected: &OwnedSecurityDescriptor,
    expected_owner: &str,
) -> Result<String, InstallerRootError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GetLastError, LocalFree};
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
    if status != ERROR_SUCCESS {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(InstallerRootError::Win32 {
            stage: InstallerRootStage::Readback,
            code: status,
        });
    }
    if descriptor.is_null() {
        return Err(InstallerRootError::Indeterminate);
    }
    let mut present = 0;
    let mut actual_dacl = std::ptr::null_mut();
    let mut defaulted = 0;
    let dacl_ok = unsafe {
        // SAFETY: both descriptors remain live for these bounded ACL reads.
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut actual_dacl,
            &raw mut defaulted,
        )
    };
    if dacl_ok == 0 {
        unsafe { LocalFree(descriptor.cast()) };
        return Err(InstallerRootError::Win32 {
            stage: InstallerRootStage::Readback,
            code: unsafe { GetLastError() },
        });
    }
    let dacl_matches = present != 0
        && !actual_dacl.is_null()
        && unsafe {
            (*actual_dacl).AclSize == (*expected_dacl).AclSize
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
    let control_ok = unsafe {
        // SAFETY: descriptor remains live and output locals are valid.
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
    };
    if control_ok == 0 {
        unsafe { LocalFree(descriptor.cast()) };
        return Err(InstallerRootError::Win32 {
            stage: InstallerRootStage::Readback,
            code: unsafe { GetLastError() },
        });
    }
    let protected = control & SE_DACL_PROTECTED != 0;
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
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GetLastError, LocalFree};
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
    if status != ERROR_SUCCESS {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(InstallerRootError::Win32 {
            stage: InstallerRootStage::Readback,
            code: status,
        });
    }
    if descriptor.is_null() {
        return Err(InstallerRootError::Indeterminate);
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    let control_ok = unsafe {
        // SAFETY: descriptor is live and output locals are valid.
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
    };
    if control_ok == 0 {
        unsafe { LocalFree(descriptor.cast()) };
        return Err(InstallerRootError::Win32 {
            stage: InstallerRootStage::Readback,
            code: unsafe { GetLastError() },
        });
    }
    let length = unsafe {
        // SAFETY: descriptor is live and Windows returns its bounded byte length.
        GetSecurityDescriptorLength(descriptor)
    } as usize;
    let digest_value = if length != 0 {
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

#[cfg(windows)]
fn map_io_error(stage: InstallerRootStage, error: &std::io::Error) -> InstallerRootError {
    error
        .raw_os_error()
        .map_or(InstallerRootError::Indeterminate, |code| {
            u32::try_from(code).map_or(InstallerRootError::Indeterminate, |code| {
                InstallerRootError::Win32 { stage, code }
            })
        })
}

#[cfg(not(windows))]
fn map_io_error(_stage: InstallerRootStage, _error: &std::io::Error) -> InstallerRootError {
    // POSIX errno values are not Win32 status values.  Keep them out of the
    // typed Win32 reference wire when this Windows primitive is unavailable.
    InstallerRootError::Indeterminate
}

#[cfg(windows)]
fn canonical_path_from_handle(
    file: &std::fs::File,
    stage: InstallerRootStage,
) -> Result<PathBuf, InstallerRootError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

    let handle = file.as_raw_handle().cast();
    let required = unsafe {
        // SAFETY: query call uses a live retained handle and no output buffer.
        GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, 0)
    };
    if required == 0 {
        return Err(InstallerRootError::Win32 {
            stage,
            code: unsafe { GetLastError() },
        });
    }
    let capacity = usize::try_from(required)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(InstallerRootError::Indeterminate)?;
    let mut buffer = vec![0_u16; capacity];
    let written = unsafe {
        // SAFETY: buffer is writable for the declared length and handle remains live.
        GetFinalPathNameByHandleW(
            handle,
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).map_err(|_| InstallerRootError::Indeterminate)?,
            0,
        )
    };
    let written = usize::try_from(written).map_err(|_| InstallerRootError::Indeterminate)?;
    if written == 0 || written >= buffer.len() {
        return Err(InstallerRootError::Win32 {
            stage,
            code: unsafe { GetLastError() },
        });
    }
    let path =
        String::from_utf16(&buffer[..written]).map_err(|_| InstallerRootError::InvalidPath)?;
    let normalized = if let Some(unc) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(dos) = path.strip_prefix(r"\\?\") {
        dos.to_owned()
    } else {
        path
    };
    let normalized = PathBuf::from(normalized);
    if !normalized.is_absolute() {
        return Err(InstallerRootError::InvalidPath);
    }
    Ok(normalized)
}

#[cfg(not(windows))]
fn canonical_path_from_handle(
    file: &std::fs::File,
    _stage: InstallerRootStage,
) -> Result<PathBuf, InstallerRootError> {
    final_windows_path_from_handle(file).map_err(map_protected_error)
}

#[cfg(windows)]
fn file_identity_from_handle_staged(
    file: &std::fs::File,
    stage: InstallerRootStage,
) -> Result<FileIdentity, InstallerRootError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let ok = unsafe {
        // SAFETY: the handle is live and the output points to initialized storage.
        GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &raw mut information)
    };
    if ok == 0 {
        return Err(InstallerRootError::Win32 {
            stage,
            code: unsafe { GetLastError() },
        });
    }
    Ok(FileIdentity {
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(not(windows))]
fn file_identity_from_handle_staged(
    file: &std::fs::File,
    _stage: InstallerRootStage,
) -> Result<FileIdentity, InstallerRootError> {
    file_identity_from_handle(file).map_err(|_| InstallerRootError::Indeterminate)
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

    #[cfg(windows)]
    struct FakePrivilegeApi {
        thread: Result<usize, u32>,
        process: Result<usize, u32>,
        duplicate: Result<usize, u32>,
        query: Result<PrivilegeState, u32>,
        enable: Result<(), u32>,
        restore: Result<(), u32>,
        bind: Result<(), u32>,
        bound: Vec<Option<usize>>,
        adjusted: usize,
        closed: Vec<usize>,
    }

    #[cfg(windows)]
    impl PrivilegeApi for FakePrivilegeApi {
        fn open_thread_token(&mut self) -> Result<usize, u32> {
            self.thread
        }

        fn open_process_token(&mut self) -> Result<usize, u32> {
            self.process
        }

        fn duplicate_token(&mut self, _source: usize) -> Result<usize, u32> {
            self.duplicate
        }

        fn query_restore_privilege(&mut self, _token: usize) -> Result<PrivilegeState, u32> {
            self.query
        }

        fn enable_restore_privilege(&mut self, _token: usize, _luid: u64) -> Result<(), u32> {
            self.adjusted += 1;
            self.enable
        }

        fn restore_restore_privilege(
            &mut self,
            _token: usize,
            _state: PrivilegeState,
        ) -> Result<(), u32> {
            self.restore
        }

        fn bind_thread_token(&mut self, token: Option<usize>) -> Result<(), u32> {
            self.bound.push(token);
            self.bind
        }

        fn close_token(&mut self, token: usize) {
            self.closed.push(token);
        }
    }

    #[cfg(windows)]
    fn fake_api() -> FakePrivilegeApi {
        FakePrivilegeApi {
            thread: Err(windows_sys::Win32::Foundation::ERROR_NO_TOKEN),
            process: Ok(11),
            duplicate: Ok(22),
            query: Ok(PrivilegeState {
                luid: 7,
                attributes: 0,
            }),
            enable: Ok(()),
            restore: Ok(()),
            bind: Ok(()),
            bound: Vec::new(),
            adjusted: 0,
            closed: Vec::new(),
        }
    }

    #[cfg(windows)]
    #[test]
    fn raw_readback_io_errors_keep_stage_and_win32_status() {
        let error = std::io::Error::from_raw_os_error(5);
        assert_eq!(
            map_io_error(InstallerRootStage::Readback, &error),
            InstallerRootError::Win32 {
                stage: InstallerRootStage::Readback,
                code: 5,
            }
        );
    }

    #[test]
    fn absence_race_mapping_does_not_relabel_identity_substitution() {
        assert_eq!(
            map_absence_observation_error(&AbsenceObservationError::RootAppeared),
            InstallerRootError::IdentityMismatch
        );
        assert_eq!(
            map_absence_observation_error(&AbsenceObservationError::Installer(
                InstallerRootError::IdentityMismatch,
            )),
            InstallerRootError::IdentityMismatch
        );
    }

    #[cfg(windows)]
    #[test]
    fn scoped_restore_privilege_falls_back_only_for_no_token_and_restores_binding() {
        let mut api = fake_api();
        {
            let mut guard = ScopedRestorePrivilege::enter(&mut api).unwrap();
            guard.restore();
        }
        assert_eq!(api.adjusted, 1);
        assert_eq!(api.bound, vec![Some(22), None]);
        assert_eq!(api.closed, vec![11, 22]);
    }

    #[cfg(windows)]
    #[test]
    fn scoped_restore_privilege_restores_an_existing_thread_token_without_process_fallback() {
        let mut api = fake_api();
        api.thread = Ok(33);
        api.process = Err(99);
        {
            let mut guard = ScopedRestorePrivilege::enter(&mut api).unwrap();
            guard.restore();
        }
        assert_eq!(api.bound, vec![Some(22), Some(33)]);
        assert_eq!(api.closed, vec![22, 33]);
    }

    #[cfg(windows)]
    #[test]
    fn scoped_restore_privilege_closes_existing_thread_token_when_duplicate_fails() {
        let mut api = fake_api();
        api.thread = Ok(33);
        api.duplicate = Err(5);
        assert!(matches!(
            ScopedRestorePrivilege::enter(&mut api),
            Err(InstallerRootError::Win32 {
                stage: InstallerRootStage::DuplicateToken,
                code: 5,
            })
        ));
        assert!(api.bound.is_empty());
        assert_eq!(api.closed, vec![33]);
    }

    #[cfg(windows)]
    #[test]
    fn scoped_restore_privilege_does_not_fallback_for_other_thread_token_errors() {
        let mut api = fake_api();
        api.thread = Err(5);
        assert!(matches!(
            ScopedRestorePrivilege::enter(&mut api),
            Err(InstallerRootError::Win32 {
                stage: InstallerRootStage::OpenThreadToken,
                code: 5,
            })
        ));
        assert!(api.bound.is_empty());
        assert!(api.closed.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn scoped_restore_privilege_rejects_missing_privilege_and_never_adjusts_process_token() {
        let mut api = fake_api();
        api.query = Err(windows_sys::Win32::Foundation::ERROR_NOT_ALL_ASSIGNED);
        assert!(matches!(
            ScopedRestorePrivilege::enter(&mut api),
            Err(InstallerRootError::Win32 {
                stage: InstallerRootStage::QueryPrivilege,
                code: windows_sys::Win32::Foundation::ERROR_NOT_ALL_ASSIGNED,
            })
        ));
        assert_eq!(api.adjusted, 0);
        assert!(api.bound.is_empty());
        assert_eq!(api.closed, vec![11, 22]);
    }

    #[cfg(windows)]
    #[test]
    fn scoped_restore_privilege_rolls_back_when_thread_binding_fails() {
        let mut api = fake_api();
        api.bind = Err(5);
        assert!(matches!(
            ScopedRestorePrivilege::enter(&mut api),
            Err(InstallerRootError::Win32 {
                stage: InstallerRootStage::BindThreadToken,
                code: 5,
            })
        ));
        assert_eq!(api.bound, vec![Some(22)]);
        assert_eq!(api.closed, vec![11, 22]);
    }

    #[cfg(windows)]
    #[test]
    fn scoped_restore_privilege_reports_not_all_assigned_when_enable_fails() {
        let mut api = fake_api();
        api.enable = Err(windows_sys::Win32::Foundation::ERROR_NOT_ALL_ASSIGNED);
        assert!(matches!(
            ScopedRestorePrivilege::enter(&mut api),
            Err(InstallerRootError::Win32 {
                stage: InstallerRootStage::EnablePrivilege,
                code: windows_sys::Win32::Foundation::ERROR_NOT_ALL_ASSIGNED,
            })
        ));
        assert_eq!(api.adjusted, 1);
        assert!(api.bound.is_empty());
        assert_eq!(api.closed, vec![11, 22]);
    }

    #[cfg(windows)]
    #[test]
    fn scoped_restore_privilege_drop_restores_after_operation_panic() {
        let mut api = fake_api();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = ScopedRestorePrivilege::enter(&mut api).unwrap();
            panic!("operation failure");
        }));
        assert!(panic.is_err());
        assert_eq!(api.bound, vec![Some(22), None]);
        assert_eq!(api.closed, vec![11, 22]);
    }

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
            let profile_root = self.user.join("Eliot");
            let installation_root = profile_root
                .join("installations")
                .join("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
            InstallerRootPrimitiveSpec {
                root: installation_root.join(leaf),
                installation_root,
                profile_anchor: self.user.clone(),
                profile: InstallerRootProfile::UserMode,
            }
        }

        fn system_spec(&self, leaf: &str) -> InstallerRootPrimitiveSpec {
            let profile_root = self.system.join("Eliot");
            let installation_root = profile_root
                .join("installations")
                .join("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
            InstallerRootPrimitiveSpec {
                root: installation_root.join(leaf),
                installation_root,
                profile_anchor: self.system.clone(),
                profile: InstallerRootProfile::SystemService,
            }
        }

        fn ensure_user_parent(&self) {
            let profile_root = self.user.join("Eliot");
            let installation_root = profile_root
                .join("installations")
                .join("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
            for path in [
                profile_root,
                self.user.join("Eliot").join("installations"),
                installation_root,
            ] {
                let created = create_directory_atomic(InstallerRootProfile::UserMode, &path)
                    .unwrap_or_else(|error| panic!("failed to create user parent: {error}"));
                assert!(created);
            }
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

        let junction_root = fixture.user_spec("read-junction").root;
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
    fn profiled_installation_root_is_one_direct_hex_child_of_installations() {
        let fixture = Fixture::new();
        fixture.ensure_user_parent();
        let primitive = fixture.primitive(true);
        let spec = fixture.user_spec("state");

        let mut nested = spec.clone();
        nested.installation_root = spec.installation_root.join("nested");
        nested.root = nested.installation_root.join("state");
        assert_eq!(
            primitive.inspect(&nested),
            Err(InstallerRootError::InvalidPath)
        );

        let mut short = spec.clone();
        short.installation_root = spec
            .installation_root
            .parent()
            .unwrap_or_else(|| unreachable!())
            .join("abc");
        short.root = short.installation_root.join("state");
        assert_eq!(
            primitive.inspect(&short),
            Err(InstallerRootError::InvalidPath)
        );

        let mut non_hex = spec.clone();
        non_hex.installation_root = spec
            .installation_root
            .parent()
            .unwrap_or_else(|| unreachable!())
            .join(format!("{}g", "a".repeat(63)));
        non_hex.root = non_hex.installation_root.join("state");
        assert_eq!(
            primitive.inspect(&non_hex),
            Err(InstallerRootError::InvalidPath)
        );

        let mut uppercase = spec.clone();
        uppercase.installation_root = spec
            .installation_root
            .parent()
            .unwrap_or_else(|| unreachable!())
            .join("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789");
        uppercase.root = uppercase.installation_root.join("state");
        assert_eq!(
            primitive.inspect(&uppercase),
            Err(InstallerRootError::InvalidPath)
        );

        let mut sibling = spec;
        sibling.installation_root = sibling
            .profile_anchor
            .join("Eliot")
            .join("installations-sibling")
            .join("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        sibling.root = sibling.installation_root.join("state");
        assert_eq!(
            primitive.inspect(&sibling),
            Err(InstallerRootError::InvalidPath)
        );
    }

    #[test]
    fn fresh_user_profile_hierarchy_is_created_leaf_by_leaf_in_parent_order() {
        let fixture = Fixture::new();
        let primitive = fixture.primitive(true);
        let profile_root = fixture.user.join("Eliot");
        let packages_root = profile_root.join("packages");
        let installations_dir = profile_root.join("installations");
        let installation_root = installations_dir
            .join("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let kernel_root = installation_root.join("kernel");
        let store_root = installation_root.join("store");
        let roots = [
            profile_root.clone(),
            packages_root.clone(),
            installations_dir.clone(),
            installation_root.clone(),
            installation_root.join("canary-evidence"),
            installation_root.join("host"),
            kernel_root.clone(),
            kernel_root.join("state"),
            kernel_root.join("work"),
            store_root.clone(),
            store_root.join("data"),
            store_root.join("work"),
            store_root.join("tmp"),
            installation_root.join("watchdog"),
        ];
        let missing_parent_spec = InstallerRootPrimitiveSpec {
            root: packages_root.clone(),
            installation_root: installation_root.clone(),
            profile_anchor: fixture.user.clone(),
            profile: InstallerRootProfile::UserMode,
        };
        assert_eq!(
            primitive.inspect(&missing_parent_spec),
            Err(InstallerRootError::MissingParent),
            "a child must not synthesize its missing profile parent"
        );

        for root in roots {
            let spec = InstallerRootPrimitiveSpec {
                root: root.clone(),
                installation_root: installation_root.clone(),
                profile_anchor: fixture.user.clone(),
                profile: InstallerRootProfile::UserMode,
            };
            let snapshot = absent(&primitive, &spec);
            let created = primitive.create(&spec, &snapshot).unwrap_or_else(|error| {
                panic!("fresh hierarchy create {}: {error}", root.display())
            });
            assert_eq!(created.disposition, InstallerRootCreateDisposition::Created);
            assert!(
                root.is_dir(),
                "one leaf must be created: {}",
                root.display()
            );
            assert!(matches!(
                primitive.inspect(&spec),
                Ok(InstallerRootPrimitiveObservation::Matching(_))
            ));
        }
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
