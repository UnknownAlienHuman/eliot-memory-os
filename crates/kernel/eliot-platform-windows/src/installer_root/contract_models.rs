//! Passive installer-root contracts and local model helpers.
//!
//! Architecture A5.1: bounded observations/models; reality remains external.
//! Implementation I3.15: installation/update transaction; installer/Host owns effects and recovery.
//! Implementation I2.1: module/crate membership transfers no lifecycle, mutable-state, or authority.
//!
//! This child owns passive installer-root DTOs/errors and pure local
//! validation/accessors only. The parent owns OS handles, security/path
//! operations, create/readback effects, lifecycle, and installation authority.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::FileIdentity;

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
pub(super) struct InstallerRootRequest {
    pub(super) root: PathBuf,
    pub(super) installation_root: PathBuf,
    pub(super) profile_anchor: PathBuf,
    pub(super) profile: InstallerRootProfile,
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
    CreateProtectedFile,
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

/// Distinguishes a target that appeared during a stable absence observation
/// from a semantic contour/identity failure. The distinction is important:
/// only the former is safe to expose as the typed absence-race reference.
#[derive(Debug)]
pub(super) enum AbsenceObservationError {
    RootAppeared,
    Installer(InstallerRootError),
}

pub(super) fn map_absence_observation_error(error: &AbsenceObservationError) -> InstallerRootError {
    match error {
        AbsenceObservationError::RootAppeared => InstallerRootError::IdentityMismatch,
        AbsenceObservationError::Installer(error) => *error,
    }
}

pub(super) fn primitive_request(spec: &InstallerRootPrimitiveSpec) -> InstallerRootRequest {
    InstallerRootRequest {
        root: spec.root.clone(),
        installation_root: spec.installation_root.clone(),
        profile_anchor: spec.profile_anchor.clone(),
        profile: spec.profile,
    }
}

pub(super) fn ensure_system_service_spec(
    spec: &InstallerRootPrimitiveSpec,
) -> Result<(), InstallerRootError> {
    if spec.profile == InstallerRootProfile::SystemService {
        Ok(())
    } else {
        Err(InstallerRootError::InvalidPath)
    }
}

pub(super) fn snapshot_identity(snapshot: &InstallerRootObjectSnapshot) -> FileIdentity {
    FileIdentity {
        volume_serial_number: snapshot.volume_serial_number,
        file_index: snapshot.file_index,
    }
}

pub(super) fn windows_path_is_within(path: &Path, contour: &Path) -> bool {
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
pub(super) fn windows_path_digest(path: &Path) -> String {
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
pub(super) fn windows_path_digest(path: &Path) -> String {
    digest(path.as_os_str().as_encoded_bytes())
}

fn digest_text(value: &str) -> String {
    digest(value.as_bytes())
}

pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
