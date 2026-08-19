//! P-08: governed installation, discovery and update transaction contracts.
//!
//! This crate owns installation policy and durable decision state. Platform
//! adapters perform bounded effects through [`InstallationEffectPort`]; they
//! never decide admission, infer success from a path, or turn an unknown
//! external outcome into success. Canonical memory is not used as installer
//! control state.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use eliot_contracts::{
    ContractIdentity, ContractVersion, ResourceGeneration, StateFence,
    contract_identity as make_contract_identity, sha256_hex,
};
use eliot_ipc::{NamedPipeTransport, TransportLimits};
use eliot_platform::{
    InstallationObservation, InstallationPort, InstallationRequest, PlatformHandle, PortError,
    PortOutcome, ProviderError, ProviderErrorCode, UnknownReason,
};
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_NAME, ELIOT_WATCHDOG_SERVICE_NAME, HostOwnerEpochCapability,
    InstallerRootAbsentSnapshot, InstallerRootCreateDisposition, InstallerRootError,
    InstallerRootObjectSnapshot, InstallerRootPrimitiveObservation, InstallerRootPrimitiveSpec,
    InstallerRootProfile, InstallerSecretCreateDisposition, InstallerSecretObservation,
    ProtectedPathError, ProtectedPathLease, ProtectedRootLease, ServiceAccount,
    ServiceBootstrapArguments, ServiceRegistrationCurrent, ServiceRegistrationInspection,
    ServiceRegistrationOutcome, ServiceRegistrationRequest, ServiceStartMode, UserOwnedPathLease,
    UserOwnedRootReadLease, WindowsInstallerRootPrimitive, WindowsInstallerSecretProvider,
    WindowsPlatform, WindowsStoreCredentialTargetGenerator, current_user_local_app_data_root,
    fresh_service_registration_nonce, observe_running_eliot_host_process,
    protected_program_data_root, require_protected_program_data_path,
};
use redb::{Database, ReadOnlyDatabase, ReadableDatabase, TableDefinition};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

mod credential_provision;
mod redb_state;

pub use credential_provision::{
    CredentialAccessReceipt, CredentialOwnershipMarkerIdentity, HOST_CREDENTIAL_CONTROL_PIPE,
    HOST_CREDENTIAL_CONTROL_WIRE, HostCredentialControlIntent, HostCredentialControlOperation,
    HostCredentialControlRequest, HostCredentialControlResponse, LOCAL_SERVICE_SID,
    StoreCredentialAbsentSnapshot, StoreCredentialLifecycle, StoreCredentialProgress,
    StoreCredentialProvider, StoreCredentialProvisionPlan, StoreCredentialScope,
    credential_absent_response_digest, credential_control_request_frame,
    credential_control_response_frame, credential_deleted_response_digest,
    credential_matching_response_digest, decode_credential_control_request_frame,
    decode_credential_control_response_frame, validate_store_credential_target,
};
pub use redb_state::RedbInstallationTransactionStore;

/// Stable wire name for the installation contract.
pub const CONTRACT_NAME: &str = "eliot.kernel.installation";
/// Current installation contract revision.
///
/// Version 3 makes the approved Host executable path and content digest
/// required members of the CandidateManifest/RuntimeLaunchDescriptor wire.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(3, 0, 0);
/// Breaking wire revision for durable [`InstallationTransaction`] records.
///
/// This discriminator is intentionally independent from [`CONTRACT_VERSION`]
/// so durable transaction records fail closed when their nested candidate
/// manifest predates the required Host artifact binding.
pub const INSTALLATION_TRANSACTION_WIRE_VERSION: ContractVersion = ContractVersion::new(7, 0, 0);

/// Returns the stable contract identity for handshakes and provenance.
pub fn contract_identity() -> Result<ContractIdentity, InstallationError> {
    #[derive(Serialize)]
    struct Shape {
        surface: &'static str,
        version: ContractVersion,
        transaction_rule: &'static str,
        unknown_rule: &'static str,
    }

    make_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &Shape {
            surface: "profile_catalogue_runtime_roots_installer_transaction",
            version: CONTRACT_VERSION,
            transaction_rule: "digest_bound_roots_immutable_plan_observed_stage_transition",
            unknown_rule: "rollback_required_until_reconciled",
        },
    )
    .map_err(|_| InstallationError::InvalidField {
        field: "contract_identity".to_owned(),
        reason: "canonical contract shape could not be serialized".to_owned(),
    })
}

/// Typed installation failures. No variant carries secrets or raw provider output.
#[derive(Clone, Debug, Eq, Error, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationError {
    /// A required field is blank, malformed or out of bounds.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Field path rejected by installation validation.
        field: String,
        /// Stable reason for rejecting the field.
        reason: String,
    },
    /// A collection contains the same identity more than once.
    #[error("{kind} contains duplicate identity {identity}")]
    Duplicate {
        /// Collection or identity kind containing a duplicate.
        kind: String,
        /// Duplicate stable identity.
        identity: String,
    },
    /// A state transition is not admitted by the transaction machine.
    #[error("illegal installation transition from {from:?} to {to:?}")]
    IllegalTransition {
        /// Current transaction stage.
        from: InstallationStage,
        /// Requested transaction stage.
        to: InstallationStage,
    },
    /// A caller attempted to use a request for another transaction.
    #[error("installation transaction identity conflict")]
    IdentityConflict,
    /// A provider changed an external object without a durable acknowledgement.
    #[error("installation effect outcome is unknown at stage {stage:?}")]
    UnknownOutcome {
        /// Stage at which the provider outcome became unknown.
        stage: InstallationStage,
    },
    /// A known observation does not prove the requested postcondition.
    #[error("installation postcondition is incomplete: {0}")]
    IncompleteObservation(String),
    /// The selected profile and roots violate isolation policy.
    #[error("installation profile violation: {0}")]
    ProfileViolation(String),
    /// The platform contract rejected the request.
    #[error("platform contract: {0}")]
    Platform(String),
    /// Durable registry bytes are malformed or internally corrupt.
    #[error("installation registry is corrupt: {reason}")]
    CorruptRegistry {
        /// Stable reason for rejecting the registry bytes.
        reason: String,
    },
    /// Existing durable installation state requires an explicit re-stage.
    #[error("installation migration required: {reason}")]
    MigrationRequired {
        /// Why the existing state cannot be admitted as the current schema.
        reason: String,
    },
    /// Durable transaction state changed since it was loaded.
    #[error("installation transaction CAS conflict: expected revision {expected}, actual {actual}")]
    CompareAndSaveConflict {
        /// Revision supplied by the coordinator.
        expected: u64,
        /// Revision currently held by the durable store.
        actual: u64,
    },
    /// The requested durable transaction does not exist.
    #[error("installation transaction was not found: {transaction_id}")]
    TransactionNotFound {
        /// Stable transaction identity that was absent.
        transaction_id: String,
    },
}

fn text(value: &str, field: &str) -> Result<(), InstallationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must be non-blank and free of control characters".to_owned(),
        });
    }
    if value.len() > 4096 {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must not exceed 4096 UTF-8 bytes".to_owned(),
        });
    }
    Ok(())
}

fn handle(value: &PlatformHandle, field: &str) -> Result<(), InstallationError> {
    text(value.as_str(), field)
}

fn sha256_handle(value: &PlatformHandle, field: &str) -> Result<(), InstallationError> {
    handle(value, field)?;
    if value.as_str().len() != 64
        || !value
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must be a lowercase SHA-256 digest".to_owned(),
        });
    }
    Ok(())
}

fn validate_eliotd_launch_nonce(
    value: &PlatformHandle,
    field: &str,
) -> Result<(), InstallationError> {
    let Some(suffix) = value.as_str().strip_prefix("eliotd:") else {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must use the opaque eliotd: correlation-nonce prefix".to_owned(),
        });
    };
    if !(32..=120).contains(&suffix.len())
        || suffix
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
        || value.as_str().contains(['/', '\\'])
    {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must be a bounded opaque non-path correlation nonce".to_owned(),
        });
    }
    Ok(())
}

fn approved_path(value: &PlatformHandle, field: &str) -> Result<(), InstallationError> {
    handle(value, field)?;
    let path = Path::new(value.as_str());
    if !path.is_absolute() {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must be an absolute canonical path".to_owned(),
        });
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must not contain parent-directory traversal".to_owned(),
        });
    }
    if lexical_windows_path(value.as_str()).is_none() {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "unsupported Windows device or NT path prefix".to_owned(),
        });
    }
    Ok(())
}

fn lexical_windows_path(value: &str) -> Option<String> {
    let mut value = value.replace('/', "\\");
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("\\\\?\\unc\\") {
        value = format!("\\\\{}", &value[8..]);
    } else if lower.starts_with("\\\\?\\") {
        let candidate = value.split_off(4);
        if candidate.len() < 3
            || !candidate.as_bytes()[0].is_ascii_alphabetic()
            || candidate.as_bytes()[1] != b':'
            || candidate.as_bytes()[2] != b'\\'
        {
            return None;
        }
        value = candidate;
    } else if lower.starts_with("\\\\.\\")
        || lower.starts_with("\\??\\")
        || lower.starts_with("\\\\??\\")
        || lower.starts_with("\\device\\")
        || lower.starts_with("\\\\device\\")
        || lower.starts_with("\\globalroot\\")
        || lower.starts_with("\\\\globalroot\\")
    {
        return None;
    }
    let (prefix, body) = if let Some(body) = value.strip_prefix("\\\\") {
        ("\\\\".to_owned(), body.to_owned())
    } else if value.len() >= 3 && value.as_bytes()[1] == b':' && value.as_bytes()[2] == b'\\' {
        (format!("{}\\", &value[..2]), value[3..].to_owned())
    } else if let Some(body) = value.strip_prefix('\\') {
        ("\\".to_owned(), body.to_owned())
    } else if value.len() >= 2 && value.as_bytes()[1] == b':' {
        (value[..2].to_owned(), value[2..].to_owned())
    } else {
        (String::new(), value)
    };
    let mut components = Vec::new();
    for component in body.split('\\') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component => components.push(component.to_ascii_lowercase()),
        }
    }
    let mut normalized = prefix.to_ascii_lowercase();
    normalized.push_str(&components.join("\\"));
    Some(normalized)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct WindowsPathIdentity {
    prefix: String,
    components: Vec<String>,
}

impl WindowsPathIdentity {
    fn parse_root(value: &str, field: &str) -> Result<Self, InstallationError> {
        text(value, field)?;
        let value = value.replace('/', "\\");
        let lower = value.to_ascii_lowercase();
        if lower.starts_with("\\\\?\\")
            || lower.starts_with("\\\\.\\")
            || lower.starts_with("\\??\\")
            || lower.starts_with("\\\\??\\")
            || lower.starts_with("\\device\\")
            || lower.starts_with("\\\\device\\")
            || lower.starts_with("\\globalroot\\")
            || lower.starts_with("\\\\globalroot\\")
        {
            return Err(InstallationError::InvalidField {
                field: field.to_owned(),
                reason:
                    "Windows device, NT and verbatim prefixes are not admitted for runtime roots"
                        .to_owned(),
            });
        }

        let (prefix, body) = if let Some(body) = value.strip_prefix("\\\\") {
            let mut parts = body.split('\\');
            let server = parts.next().unwrap_or_default();
            let share = parts.next().unwrap_or_default();
            if server.is_empty() || share.is_empty() {
                return Err(InstallationError::InvalidField {
                    field: field.to_owned(),
                    reason: "UNC runtime root must include server and share components".to_owned(),
                });
            }
            (
                format!(
                    "\\\\{}\\{}",
                    server.to_ascii_lowercase(),
                    share.to_ascii_lowercase()
                ),
                parts.collect::<Vec<_>>(),
            )
        } else if value.len() >= 3
            && value.as_bytes()[0].is_ascii_alphabetic()
            && value.as_bytes()[1] == b':'
            && value.as_bytes()[2] == b'\\'
        {
            (
                value[..2].to_ascii_lowercase(),
                value[3..].split('\\').collect::<Vec<_>>(),
            )
        } else {
            return Err(InstallationError::InvalidField {
                field: field.to_owned(),
                reason: "runtime root must be an absolute drive or UNC path".to_owned(),
            });
        };

        let mut components = Vec::new();
        for component in body {
            if component.is_empty() {
                continue;
            }
            if component == "." || component == ".." {
                return Err(InstallationError::InvalidField {
                    field: field.to_owned(),
                    reason: "runtime root must not contain dot or parent traversal components"
                        .to_owned(),
                });
            }
            if component.ends_with(' ') || component.ends_with('.') || component.contains(':') {
                return Err(InstallationError::InvalidField {
                    field: field.to_owned(),
                    reason: "runtime root contains a Windows lexical alias component".to_owned(),
                });
            }
            components.push(component.to_ascii_lowercase());
        }
        if components.is_empty() {
            return Err(InstallationError::InvalidField {
                field: field.to_owned(),
                reason: "volume roots are not admitted as mutable runtime roots".to_owned(),
            });
        }
        Ok(Self { prefix, components })
    }

    fn contains(&self, candidate: &Self) -> bool {
        self.prefix == candidate.prefix
            && self.components.len() <= candidate.components.len()
            && self
                .components
                .iter()
                .zip(&candidate.components)
                .all(|(left, right)| left == right)
    }

    fn aliases_or_overlaps(&self, other: &Self) -> bool {
        self.contains(other) || other.contains(self)
    }

    fn ends_with(&self, suffix: &[&str]) -> bool {
        self.components.len() >= suffix.len()
            && self.components[self.components.len() - suffix.len()..]
                .iter()
                .map(String::as_str)
                .eq(suffix.iter().copied())
    }
}

fn joined_windows_path(root: &str, suffix: &str) -> String {
    format!("{}\\{}", root.trim_end_matches(['\\', '/']), suffix)
}

fn same_windows_root(left: &str, right: &str) -> Result<bool, InstallationError> {
    Ok(WindowsPathIdentity::parse_root(left, "left_root")?
        == WindowsPathIdentity::parse_root(right, "right_root")?)
}

fn reject_authority_alias(
    authority_path: &PlatformHandle,
    candidate_path: &PlatformHandle,
    candidate_field: &str,
) -> Result<(), InstallationError> {
    let Some(authority) = lexical_windows_path(authority_path.as_str()) else {
        return Err(InstallationError::InvalidField {
            field: "runtime_launch.authority_descriptor_path".to_owned(),
            reason: "unsupported Windows device or NT path prefix".to_owned(),
        });
    };
    let Some(candidate) = lexical_windows_path(candidate_path.as_str()) else {
        return Err(InstallationError::InvalidField {
            field: candidate_field.to_owned(),
            reason: "unsupported Windows device or NT path prefix".to_owned(),
        });
    };
    if authority == candidate {
        return Err(InstallationError::InvalidField {
            field: "runtime_launch.authority_descriptor_path".to_owned(),
            reason: format!("must not alias {candidate_field}"),
        });
    }
    Ok(())
}

fn approved_filename(
    value: &PlatformHandle,
    expected: &str,
    field: &str,
) -> Result<(), InstallationError> {
    if Path::new(value.as_str())
        .file_name()
        .and_then(|name| name.to_str())
        != Some(expected)
    {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: format!("must select the approved {expected} filename"),
        });
    }
    Ok(())
}

const MAX_VERIFIED_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Opens one installation-owned file through the protected no-follow lease,
/// hashes bytes from that retained handle, and verifies the approved digest.
///
/// The returned path is only a locator. Callers that need replacement
/// protection across a launch boundary must retain their own
/// [`ProtectedPathLease`] and use [`verify_file_digest_with_lease`].
pub fn verify_file_digest(
    path: impl AsRef<Path>,
    expected: &PlatformHandle,
    field: &str,
) -> Result<std::path::PathBuf, InstallationError> {
    let lease = ProtectedPathLease::open_existing_absolute(path.as_ref()).map_err(|error| {
        InstallationError::Platform(format!("{field}: protected file open failed: {error}"))
    })?;
    verify_file_digest_with_lease(&lease, expected, field)?;
    Ok(lease.path().to_path_buf())
}

/// Verifies bytes from an already-retained protected file handle.  No path
/// open occurs during hashing, so the caller can keep the same identity pinned
/// through a suspended process resume boundary.
pub fn verify_file_digest_with_lease(
    lease: &ProtectedPathLease,
    expected: &PlatformHandle,
    field: &str,
) -> Result<(), InstallationError> {
    sha256_handle(expected, field)?;
    lease
        .verify_stable_identity()
        .map_err(|error| InstallationError::Platform(format!("{field}: {error}")))?;
    lease
        .verify_path_identity()
        .map_err(|error| InstallationError::Platform(format!("{field}: {error}")))?;
    let bytes = lease
        .read_bounded(MAX_VERIFIED_FILE_BYTES)
        .map_err(|error| InstallationError::Platform(format!("{field}: {error}")))?;
    let actual = sha256_hex(&bytes);
    if actual != expected.as_str() {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: format!("content digest mismatch (actual {actual})"),
        });
    }
    Ok(())
}

/// Verifies bytes from a retained portable-dev file lease.
pub fn verify_file_digest_with_user_lease(
    lease: &UserOwnedPathLease,
    expected: &PlatformHandle,
    field: &str,
) -> Result<(), InstallationError> {
    sha256_handle(expected, field)?;
    lease
        .verify_stable_identity()
        .and_then(|()| lease.verify_path_identity())
        .map_err(|error| InstallationError::Platform(format!("{field}: {error}")))?;
    let bytes = lease
        .read_bounded(MAX_VERIFIED_FILE_BYTES)
        .map_err(|error| InstallationError::Platform(format!("{field}: {error}")))?;
    let actual = sha256_hex(&bytes);
    if actual != expected.as_str() {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: format!("content digest mismatch (actual {actual})"),
        });
    }
    Ok(())
}

/// Verifies that a caller-supplied locator resolves to the exact canonical
/// path recorded by the installation-owned candidate manifest.
pub fn verify_approved_path(
    path: impl AsRef<Path>,
    approved: &PlatformHandle,
    field: &str,
) -> Result<std::path::PathBuf, InstallationError> {
    handle(approved, field)?;
    let approved_path = Path::new(approved.as_str());
    let candidate_path = path.as_ref();
    if !approved_path.is_absolute() || !candidate_path.is_absolute() {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "approved and supplied paths must be absolute".to_owned(),
        });
    }
    let approved_lease = ProtectedPathLease::open_existing_absolute(approved_path)
        .map_err(|error| InstallationError::Platform(format!("{field} approved: {error}")))?;
    let candidate_lease = ProtectedPathLease::open_existing_absolute(candidate_path)
        .map_err(|error| InstallationError::Platform(format!("{field} supplied: {error}")))?;
    approved_lease
        .verify_stable_identity()
        .and_then(|()| approved_lease.verify_path_identity())
        .map_err(|error| InstallationError::Platform(format!("{field} approved: {error}")))?;
    candidate_lease
        .verify_stable_identity()
        .and_then(|()| candidate_lease.verify_path_identity())
        .map_err(|error| InstallationError::Platform(format!("{field} supplied: {error}")))?;
    if candidate_lease.path() != approved_lease.path()
        || candidate_lease.identity() != approved_lease.identity()
    {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "supplied path is not the approved canonical path".to_owned(),
        });
    }
    Ok(approved_lease.path().to_path_buf())
}

fn handles(
    values: &[PlatformHandle],
    field: &str,
    required: bool,
) -> Result<(), InstallationError> {
    if required && values.is_empty() {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must not be empty".to_owned(),
        });
    }
    let mut seen = BTreeSet::new();
    for value in values {
        handle(value, field)?;
        if !seen.insert(value.as_str()) {
            return Err(InstallationError::Duplicate {
                kind: field.to_owned(),
                identity: value.as_str().to_owned(),
            });
        }
    }
    Ok(())
}

/// The supported installation supervision and path profiles.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationProfile {
    /// Elevated SCM-owned service with the strongest isolation guarantees.
    SystemService,
    /// Per-user installation supervised by the current user.
    UserMode,
    /// Repository-local disposable development profile.
    PortableDev,
}

impl InstallationProfile {
    /// Whether this profile requires administrative installation authority.
    #[must_use]
    pub const fn requires_admin(self) -> bool {
        matches!(self, Self::SystemService)
    }

    /// Whether this profile is permitted to share state with production roots.
    #[must_use]
    pub const fn is_disposable(self) -> bool {
        matches!(self, Self::PortableDev)
    }
}

/// Digest-bound mutable runtime roots for one explicitly selected profile.
///
/// `profile_anchor_root` is supplied by the installer after the Windows adapter
/// proves the corresponding protected `ProgramData`, `LocalAppData`, or retained
/// portable contour. The contract never consults process environment variables
/// and therefore cannot silently select a different profile root.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStateRoots {
    /// Profile for which these roots were derived.
    pub profile: InstallationProfile,
    /// Explicit OS-validated profile anchor.
    pub profile_anchor_root: PlatformHandle,
    /// Durable root for this exact installation identity.
    pub installation_root: PlatformHandle,
    /// Host journal and supervision state.
    pub host_state_root: PlatformHandle,
    /// Kernel operational-record state (ORS).
    pub kernel_ors_root: PlatformHandle,
    /// Kernel ephemeral work area.
    pub kernel_work_root: PlatformHandle,
    /// Canonical Store database files.
    pub store_data_root: PlatformHandle,
    /// Canonical Store working directory.
    pub store_work_root: PlatformHandle,
    /// Canonical Store temporary files.
    pub store_temp_root: PlatformHandle,
    /// Watchdog state and bounded spool.
    pub watchdog_state_root: PlatformHandle,
    /// SHA-256 of all preceding fields.
    pub roots_digest: PlatformHandle,
}

/// One retained, no-follow root lease exposed by an OS adapter.
///
/// Implementations must keep the underlying directory and ancestor handles
/// alive for the lifetime of the value. Returning path text without a retained
/// lease violates this contract.
pub trait RuntimeRootLease {
    /// Caller-declared path bound to the retained handle.
    fn declared_path(&self) -> &str;
    /// Canonical path obtained from the retained no-follow handle.
    fn canonical_path(&self) -> &str;
    /// Stable same-file identity (for example volume serial plus file index).
    fn file_identity(&self) -> &str;
    /// Whether every retained component was proven non-reparse.
    fn is_reparse_free(&self) -> bool;
}

/// Adapter hook that acquires retained no-follow leases for runtime roots.
pub trait RuntimeRootLeaseProvider {
    /// Concrete guard kept alive through validation and returned to the caller.
    type Lease: RuntimeRootLease;

    /// Retains one existing root without following a reparse point.
    fn retain_root(&mut self, root: &PlatformHandle) -> Result<Self::Lease, InstallationError>;
}

/// Validated lease guards. Dropping this value releases the retained OS leases.
pub struct ValidatedRuntimeRootLeases<L> {
    leases: Vec<L>,
}

/// Real Windows retained root lease used by production composition.
pub enum WindowsRuntimeRootLease {
    /// `SystemService` lease backed by a retained read-only directory contour.
    Protected {
        /// Contract-declared root path.
        declared_path: String,
        /// OS-resolved DOS/UNC root path.
        canonical_path: String,
        /// Stable retained file-object identity.
        file_identity: String,
        /// Retained no-follow protected contour guard.
        lease: ProtectedRootLease,
    },
    /// UserMode/PortableDev retained directory lease.
    UserOwned {
        /// Contract-declared root path.
        declared_path: String,
        /// OS-resolved DOS/UNC root path.
        canonical_path: String,
        /// Stable retained directory-object identity.
        file_identity: String,
        /// Retained current-user directory guard.
        lease: UserOwnedRootReadLease,
    },
}

impl RuntimeRootLease for WindowsRuntimeRootLease {
    fn declared_path(&self) -> &str {
        match self {
            Self::Protected { declared_path, .. } | Self::UserOwned { declared_path, .. } => {
                declared_path
            }
        }
    }

    fn canonical_path(&self) -> &str {
        match self {
            Self::Protected { canonical_path, .. } | Self::UserOwned { canonical_path, .. } => {
                canonical_path
            }
        }
    }

    fn file_identity(&self) -> &str {
        match self {
            Self::Protected { file_identity, .. } | Self::UserOwned { file_identity, .. } => {
                file_identity
            }
        }
    }

    fn is_reparse_free(&self) -> bool {
        match self {
            Self::Protected { lease, .. } => lease.verify_stable_identity().is_ok(),
            Self::UserOwned { lease, .. } => lease.verify_stable_identity().is_ok(),
        }
    }
}

/// Production Windows adapter for the `RuntimeRootLeaseProvider` hook.
pub struct WindowsRuntimeRootLeaseProvider {
    profile: InstallationProfile,
}

impl WindowsRuntimeRootLeaseProvider {
    /// Validates the OS profile anchor before any runtime root is retained.
    pub fn for_roots(roots: &RuntimeStateRoots) -> Result<Self, InstallationError> {
        roots.validate()?;
        roots.validate_profile_anchor_os()?;
        Ok(Self {
            profile: roots.profile,
        })
    }
}

impl RuntimeRootLeaseProvider for WindowsRuntimeRootLeaseProvider {
    type Lease = WindowsRuntimeRootLease;

    fn retain_root(&mut self, root: &PlatformHandle) -> Result<Self::Lease, InstallationError> {
        let declared_path = root.as_str().to_owned();
        let path = Path::new(root.as_str());
        match self.profile {
            InstallationProfile::SystemService => {
                let lease =
                    ProtectedRootLease::open_existing(path).map_err(protected_path_error)?;
                let canonical_path = lease
                    .canonical_path()
                    .map_err(protected_path_error)?
                    .to_string_lossy()
                    .into_owned();
                let identity = lease.identity();
                Ok(WindowsRuntimeRootLease::Protected {
                    declared_path,
                    canonical_path,
                    file_identity: format!(
                        "volume:{}:file:{}",
                        identity.volume_serial_number, identity.file_index
                    ),
                    lease,
                })
            }
            InstallationProfile::UserMode | InstallationProfile::PortableDev => {
                let lease =
                    UserOwnedRootReadLease::open_existing(path).map_err(protected_path_error)?;
                let canonical_path = lease
                    .canonical_path()
                    .map_err(protected_path_error)?
                    .to_string_lossy()
                    .into_owned();
                let identity = lease.identity();
                Ok(WindowsRuntimeRootLease::UserOwned {
                    declared_path,
                    canonical_path,
                    file_identity: format!(
                        "volume:{}:file:{}",
                        identity.volume_serial_number, identity.file_index
                    ),
                    lease,
                })
            }
        }
    }
}

fn protected_path_error(error: ProtectedPathError) -> InstallationError {
    InstallationError::Platform(error.to_string())
}

impl<L> ValidatedRuntimeRootLeases<L> {
    /// Borrows every retained root lease in contract field order.
    #[must_use]
    pub fn leases(&self) -> &[L] {
        &self.leases
    }
}

impl RuntimeStateRoots {
    const ROOT_SUFFIXES: [(&'static str, &'static str); 7] = [
        ("host_state_root", "host"),
        ("kernel_ors_root", "kernel\\state"),
        ("kernel_work_root", "kernel\\work"),
        ("store_data_root", "store\\data"),
        ("store_work_root", "store\\work"),
        ("store_temp_root", "store\\tmp"),
        ("watchdog_state_root", "watchdog"),
    ];

    /// Derives `SystemService` or `UserMode` roots from an explicit OS-validated
    /// profile anchor and a lowercase SHA-256 installation key.
    pub fn derive_profiled(
        profile: InstallationProfile,
        profile_anchor_root: PlatformHandle,
        installation_key: &str,
    ) -> Result<Self, InstallationError> {
        if profile == InstallationProfile::PortableDev {
            return Err(InstallationError::ProfileViolation(
                "portable_dev requires derive_portable with one retained root".to_owned(),
            ));
        }
        Self::validate_profile_anchor_path_os(profile, &profile_anchor_root)?;
        validate_installation_key(installation_key)?;
        let installation_root = PlatformHandle::new(joined_windows_path(
            profile_anchor_root.as_str(),
            &format!("Eliot\\installations\\{installation_key}"),
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "runtime_state_roots.installation_root".to_owned(),
            reason: error.to_string(),
        })?;
        Self::derived(profile, profile_anchor_root, installation_root)
    }

    /// Derives `PortableDev` roots below one explicit retained disposable root.
    pub fn derive_portable(
        retained_portable_root: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        Self::validate_profile_anchor_path_os(
            InstallationProfile::PortableDev,
            &retained_portable_root,
        )?;
        Self::derived(
            InstallationProfile::PortableDev,
            retained_portable_root.clone(),
            retained_portable_root,
        )
    }

    fn validate_profile_anchor_path_os(
        profile: InstallationProfile,
        anchor: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        let observed = match profile {
            InstallationProfile::SystemService => {
                protected_program_data_root().map_err(protected_path_error)?
            }
            InstallationProfile::UserMode => {
                current_user_local_app_data_root().map_err(protected_path_error)?
            }
            InstallationProfile::PortableDev => {
                let lease = UserOwnedRootReadLease::open_existing(Path::new(anchor.as_str()))
                    .map_err(protected_path_error)?;
                lease.canonical_path().map_err(protected_path_error)?
            }
        };
        if !same_windows_root(anchor.as_str(), &observed.to_string_lossy())? {
            return Err(InstallationError::ProfileViolation(
                "profile anchor does not match the OS-resolved retained contour".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_profile_anchor_os(&self) -> Result<(), InstallationError> {
        Self::validate_profile_anchor_path_os(self.profile, &self.profile_anchor_root)
    }

    fn derived(
        profile: InstallationProfile,
        profile_anchor_root: PlatformHandle,
        installation_root: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        let make = |suffix: &str| {
            PlatformHandle::new(joined_windows_path(installation_root.as_str(), suffix)).map_err(
                |error| InstallationError::InvalidField {
                    field: "runtime_state_roots".to_owned(),
                    reason: error.to_string(),
                },
            )
        };
        let host_state_root = make("host")?;
        let kernel_ors_root = make("kernel\\state")?;
        let kernel_work_root = make("kernel\\work")?;
        let store_data_root = make("store\\data")?;
        let store_work_root = make("store\\work")?;
        let store_temp_root = make("store\\tmp")?;
        let watchdog_state_root = make("watchdog")?;
        let mut roots = Self {
            profile,
            profile_anchor_root,
            installation_root,
            host_state_root,
            kernel_ors_root,
            kernel_work_root,
            store_data_root,
            store_work_root,
            store_temp_root,
            watchdog_state_root,
            roots_digest: PlatformHandle::new("0".repeat(64)).map_err(|error| {
                InstallationError::InvalidField {
                    field: "runtime_state_roots.roots_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?,
        };
        roots.roots_digest =
            PlatformHandle::new(sha256_hex(&roots.unsigned_bytes()?)).map_err(|error| {
                InstallationError::InvalidField {
                    field: "runtime_state_roots.roots_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?;
        roots.validate()?;
        Ok(roots)
    }

    fn root_fields(&self) -> [(&'static str, &PlatformHandle); 7] {
        [
            ("host_state_root", &self.host_state_root),
            ("kernel_ors_root", &self.kernel_ors_root),
            ("kernel_work_root", &self.kernel_work_root),
            ("store_data_root", &self.store_data_root),
            ("store_work_root", &self.store_work_root),
            ("store_temp_root", &self.store_temp_root),
            ("watchdog_state_root", &self.watchdog_state_root),
        ]
    }

    fn reject_mutable_alias(
        &self,
        candidate: &PlatformHandle,
        candidate_field: &str,
    ) -> Result<(), InstallationError> {
        let candidate_path = WindowsPathIdentity::parse_root(candidate.as_str(), candidate_field)?;
        for (root_field, root) in self.root_fields() {
            let mutable_path = WindowsPathIdentity::parse_root(
                root.as_str(),
                &format!("runtime_state_roots.{root_field}"),
            )?;
            if candidate_path.aliases_or_overlaps(&mutable_path) {
                return Err(InstallationError::ProfileViolation(format!(
                    "{candidate_field} aliases mutable runtime root {root_field}"
                )));
            }
        }
        Ok(())
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, InstallationError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            profile: InstallationProfile,
            profile_anchor_root: &'a PlatformHandle,
            installation_root: &'a PlatformHandle,
            host_state_root: &'a PlatformHandle,
            kernel_ors_root: &'a PlatformHandle,
            kernel_work_root: &'a PlatformHandle,
            store_data_root: &'a PlatformHandle,
            store_work_root: &'a PlatformHandle,
            store_temp_root: &'a PlatformHandle,
            watchdog_state_root: &'a PlatformHandle,
        }
        serde_json::to_vec(&Unsigned {
            profile: self.profile,
            profile_anchor_root: &self.profile_anchor_root,
            installation_root: &self.installation_root,
            host_state_root: &self.host_state_root,
            kernel_ors_root: &self.kernel_ors_root,
            kernel_work_root: &self.kernel_work_root,
            store_data_root: &self.store_data_root,
            store_work_root: &self.store_work_root,
            store_temp_root: &self.store_temp_root,
            watchdog_state_root: &self.watchdog_state_root,
        })
        .map_err(|error| InstallationError::InvalidField {
            field: "runtime_state_roots".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates profile binding, fixed topology, whole-component separation,
    /// and the roots digest. OS reparse/file identity proof is performed by
    /// [`Self::retain_and_validate`].
    pub fn validate(&self) -> Result<(), InstallationError> {
        let anchor = WindowsPathIdentity::parse_root(
            self.profile_anchor_root.as_str(),
            "runtime_state_roots.profile_anchor_root",
        )?;
        let installation = WindowsPathIdentity::parse_root(
            self.installation_root.as_str(),
            "runtime_state_roots.installation_root",
        )?;
        match self.profile {
            InstallationProfile::SystemService | InstallationProfile::UserMode => {
                if !anchor.contains(&installation) || anchor == installation {
                    return Err(InstallationError::ProfileViolation(
                        "profiled installation root must be below its explicit profile anchor"
                            .to_owned(),
                    ));
                }
                let Some(key) = installation.components.last() else {
                    return Err(InstallationError::ProfileViolation(
                        "profiled installation root is incomplete".to_owned(),
                    ));
                };
                validate_installation_key(key)?;
                if installation.components.len() < 3
                    || !installation.ends_with(&["eliot", "installations", key])
                {
                    return Err(InstallationError::ProfileViolation(
                        "profiled installation root must end in Eliot/installations/<key>"
                            .to_owned(),
                    ));
                }
            }
            InstallationProfile::PortableDev => {
                if anchor != installation {
                    return Err(InstallationError::ProfileViolation(
                        "portable_dev installation root must equal its retained portable root"
                            .to_owned(),
                    ));
                }
                if installation.components.len() >= 3 {
                    let last = installation.components.last().map_or("", String::as_str);
                    if valid_installation_key(last)
                        && installation.ends_with(&["eliot", "installations", last])
                    {
                        return Err(InstallationError::ProfileViolation(
                            "portable_dev must not alias a profiled durable installation root"
                                .to_owned(),
                        ));
                    }
                }
            }
        }

        let fields = self.root_fields();
        let mut parsed = Vec::with_capacity(fields.len());
        for ((field, root), (expected_field, suffix)) in
            fields.iter().zip(Self::ROOT_SUFFIXES.iter())
        {
            debug_assert_eq!(field, expected_field);
            let path = WindowsPathIdentity::parse_root(
                root.as_str(),
                &format!("runtime_state_roots.{field}"),
            )?;
            if !installation.contains(&path) || installation == path {
                return Err(InstallationError::ProfileViolation(format!(
                    "{field} must be below the installation root"
                )));
            }
            let expected = WindowsPathIdentity::parse_root(
                &joined_windows_path(self.installation_root.as_str(), suffix),
                &format!("runtime_state_roots.{field}"),
            )?;
            if path != expected {
                return Err(InstallationError::ProfileViolation(format!(
                    "{field} does not match the fixed runtime root topology"
                )));
            }
            parsed.push((field, path));
        }
        for left in 0..parsed.len() {
            for right in left + 1..parsed.len() {
                if parsed[left].1.aliases_or_overlaps(&parsed[right].1) {
                    return Err(InstallationError::ProfileViolation(format!(
                        "{} and {} alias or overlap by Windows path components",
                        parsed[left].0, parsed[right].0
                    )));
                }
            }
        }
        sha256_handle(&self.roots_digest, "runtime_state_roots.roots_digest")?;
        if sha256_hex(&self.unsigned_bytes()?) != self.roots_digest.as_str() {
            return Err(InstallationError::InvalidField {
                field: "runtime_state_roots.roots_digest".to_owned(),
                reason: "runtime root digest mismatch".to_owned(),
            });
        }
        Ok(())
    }

    /// Acquires and validates retained no-follow OS leases for all mutable roots.
    /// The returned guards must remain alive across descriptor consumption.
    pub fn retain_and_validate<P>(
        &self,
        provider: &mut P,
    ) -> Result<ValidatedRuntimeRootLeases<P::Lease>, InstallationError>
    where
        P: RuntimeRootLeaseProvider,
    {
        self.validate()?;
        let mut leases = Vec::with_capacity(7);
        let mut identities = BTreeSet::new();
        for (field, root) in self.root_fields() {
            let lease = provider.retain_root(root)?;
            if !lease.is_reparse_free() {
                return Err(InstallationError::ProfileViolation(format!(
                    "{field} retained lease contains a reparse point"
                )));
            }
            if !same_windows_root(lease.declared_path(), root.as_str())?
                || !same_windows_root(lease.canonical_path(), root.as_str())?
            {
                return Err(InstallationError::ProfileViolation(format!(
                    "{field} retained lease does not bind the declared canonical root"
                )));
            }
            text(lease.file_identity(), "runtime_root_lease.file_identity")?;
            if !identities.insert(lease.file_identity().to_owned()) {
                return Err(InstallationError::ProfileViolation(
                    "two runtime roots alias the same retained file object".to_owned(),
                ));
            }
            leases.push(lease);
        }
        Ok(ValidatedRuntimeRootLeases { leases })
    }
}

fn valid_installation_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_installation_key(value: &str) -> Result<(), InstallationError> {
    if valid_installation_key(value) {
        Ok(())
    } else {
        Err(InstallationError::InvalidField {
            field: "installation_key".to_owned(),
            reason: "must be a lowercase SHA-256-derived path key".to_owned(),
        })
    }
}

/// Installation/package roots plus the typed mutable runtime topology.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationRoots {
    /// Immutable, versioned binaries and component artifacts.
    pub immutable_binaries: String,
    /// Durable service/installation state.
    pub durable_data: String,
    /// User configuration and cache.
    pub user_config_cache: String,
    /// Explicit digest-bound runtime state topology.
    pub runtime_state_roots: RuntimeStateRoots,
}

impl InstallationRoots {
    /// Creates and validates a root set for one profile.
    pub fn new(
        profile: InstallationProfile,
        immutable_binaries: impl Into<String>,
        durable_data: impl Into<String>,
        user_config_cache: impl Into<String>,
        runtime_state_roots: RuntimeStateRoots,
    ) -> Result<Self, InstallationError> {
        let roots = Self {
            immutable_binaries: immutable_binaries.into(),
            durable_data: durable_data.into(),
            user_config_cache: user_config_cache.into(),
            runtime_state_roots,
        };
        roots.validate(profile)?;
        Ok(roots)
    }

    /// Validates path separation and rejects traversal or empty roots.
    pub fn validate(&self, profile: InstallationProfile) -> Result<(), InstallationError> {
        let values = [
            (&self.immutable_binaries, "immutable_binaries"),
            (&self.durable_data, "durable_data"),
            (&self.user_config_cache, "user_config_cache"),
        ];
        let mut parsed_roots = Vec::new();
        for (value, field) in values {
            text(value, field)?;
            parsed_roots.push((field, WindowsPathIdentity::parse_root(value, field)?));
        }
        for left in 0..parsed_roots.len() {
            for right in left + 1..parsed_roots.len() {
                if parsed_roots[left]
                    .1
                    .aliases_or_overlaps(&parsed_roots[right].1)
                {
                    return Err(InstallationError::ProfileViolation(format!(
                        "{} and {} alias or overlap by Windows path components",
                        parsed_roots[left].0, parsed_roots[right].0
                    )));
                }
            }
        }
        if !profile.is_disposable()
            && self
                .immutable_binaries
                .eq_ignore_ascii_case(&self.durable_data)
        {
            return Err(InstallationError::ProfileViolation(
                "production binaries may not share the durable data root".to_owned(),
            ));
        }
        self.runtime_state_roots.validate()?;
        if self.runtime_state_roots.profile != profile {
            return Err(InstallationError::ProfileViolation(
                "runtime roots profile must equal the installation profile".to_owned(),
            ));
        }
        if !same_windows_root(
            &self.durable_data,
            self.runtime_state_roots.installation_root.as_str(),
        )? {
            return Err(InstallationError::ProfileViolation(
                "durable installation root must equal RuntimeStateRoots.installation_root"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// One installation lineage; sequence is monotonic only within this lineage.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct InstallationEpoch {
    /// Installation identity.
    pub installation: PlatformHandle,
    /// Stable lineage identity; it changes after restore or reconstitution.
    pub lineage_id: PlatformHandle,
    /// Monotonic sequence within the lineage.
    pub sequence: u64,
}

impl InstallationEpoch {
    /// Validates an installation epoch.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.installation, "installation_epoch.installation")?;
        handle(&self.lineage_id, "installation_epoch.lineage_id")?;
        if self.sequence == 0 {
            return Err(InstallationError::InvalidField {
                field: "installation_epoch.sequence".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        Ok(())
    }
}

/// The governed operation requested by a human/control-plane caller.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedEnvironmentAction {
    /// Install an absent candidate.
    Install,
    /// Replace an active generation side-by-side.
    Update,
    /// Re-apply or repair a known installation.
    Repair,
    /// Remove registrations and immutable artifacts while preserving data by default.
    Remove,
    /// Register an already observed external integration.
    Register,
    /// Change an installation configuration without changing its artifact generation.
    Reconfigure,
}

/// A bounded, evidence-linked request to change the managed environment.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedEnvironmentChangeRequest {
    /// Stable request identity.
    pub request_id: PlatformHandle,
    /// Principal/reason reference; never a secret.
    pub requester_and_reason: PlatformHandle,
    /// Requested operation.
    pub action: ManagedEnvironmentAction,
    /// Catalogue family being changed.
    pub target_family: PlatformHandle,
    /// Exact candidate identity or generation.
    pub exact_candidate: PlatformHandle,
    /// Expected capability/problem delta.
    pub expected_delta: PlatformHandle,
    /// Source, license and dependency-closure evidence.
    pub source_assurance_refs: Vec<PlatformHandle>,
    /// Affected routes, modules, scopes and credential references.
    pub affected_refs: Vec<PlatformHandle>,
    /// Impact classification owned by the caller's governance policy.
    pub impact_class: PlatformHandle,
    /// Required owner for admission.
    pub required_owner: PlatformHandle,
    /// Backup, rollback or forward-repair plan reference.
    pub rollback_plan: PlatformHandle,
    /// Post-change verifier reference.
    pub verifier: PlatformHandle,
    /// Resource/budget policy reference.
    pub budget: PlatformHandle,
    /// Explicit stop condition.
    pub stop_condition: PlatformHandle,
}

impl ManagedEnvironmentChangeRequest {
    /// Validates the request without performing an external effect.
    pub fn validate(&self) -> Result<(), InstallationError> {
        for (value, field) in [
            (&self.request_id, "request_id"),
            (&self.requester_and_reason, "requester_and_reason"),
            (&self.target_family, "target_family"),
            (&self.exact_candidate, "exact_candidate"),
            (&self.expected_delta, "expected_delta"),
            (&self.impact_class, "impact_class"),
            (&self.required_owner, "required_owner"),
            (&self.rollback_plan, "rollback_plan"),
            (&self.verifier, "verifier"),
            (&self.budget, "budget"),
            (&self.stop_condition, "stop_condition"),
        ] {
            handle(value, field)?;
        }
        handles(&self.source_assurance_refs, "source_assurance_refs", true)?;
        handles(&self.affected_refs, "affected_refs", false)
    }
}

/// Broad discovery family used by the catalogue; presence is not admission.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationCategory {
    /// Agent runtime, host or ACP/stdio surface.
    AgentRuntime,
    /// Editor or professional application host.
    EditorHost,
    /// Local model runtime.
    LocalModelRuntime,
    /// MCP server or bridge.
    McpServer,
    /// Code-intelligence provider.
    CodeIntelligence,
    /// Database or store runtime.
    Database,
    /// Compiler, language server or development toolchain.
    Toolchain,
    /// Package manager or installer surface.
    PackageManager,
    /// Browser or professional tool.
    BrowserProfessionalTool,
    /// Cloud CLI or remote integration.
    CloudCli,
}

/// One versioned, detection-first discovery recipe.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationDiscoveryCatalogueEntry {
    /// Stable family identity.
    pub family_id: PlatformHandle,
    /// Discovery category.
    pub category: IntegrationCategory,
    /// Platforms on which the recipe is valid.
    pub supported_platforms: Vec<PlatformHandle>,
    /// Known executable/config/manifest locations.
    pub known_locations: Vec<PlatformHandle>,
    /// Safe discovery or negative-capability probes.
    pub safe_probes: Vec<PlatformHandle>,
    /// Official install/update/remove surfaces.
    pub managed_surfaces: Vec<PlatformHandle>,
    /// Required execution identities or credential references.
    pub credential_refs: Vec<PlatformHandle>,
    /// License, supply-chain and privacy notes.
    pub assurance_refs: Vec<PlatformHandle>,
    /// Candidate adapter/bridge identities.
    pub adapter_candidates: Vec<PlatformHandle>,
    /// Evidence expiry in Unix milliseconds, if bounded.
    pub evidence_expiry_ms: Option<u64>,
}

impl IntegrationDiscoveryCatalogueEntry {
    /// Validates the recipe and requires at least one safe discovery surface.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.family_id, "family_id")?;
        handles(&self.supported_platforms, "supported_platforms", true)?;
        handles(&self.known_locations, "known_locations", true)?;
        handles(&self.safe_probes, "safe_probes", true)?;
        handles(&self.managed_surfaces, "managed_surfaces", false)?;
        handles(&self.credential_refs, "credential_refs", false)?;
        handles(&self.assurance_refs, "assurance_refs", true)?;
        handles(&self.adapter_candidates, "adapter_candidates", false)?;
        if self.evidence_expiry_ms == Some(0) {
            return Err(InstallationError::InvalidField {
                field: "evidence_expiry_ms".to_owned(),
                reason: "must be absent or positive".to_owned(),
            });
        }
        Ok(())
    }
}

/// Immutable ELIOT-owned discovery catalogue, not a capability registry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationDiscoveryCatalogue {
    /// Catalogue origin/provenance reference.
    pub origin: PlatformHandle,
    /// Monotonic catalogue revision.
    pub revision: u64,
    /// Versioned discovery recipes.
    pub entries: Vec<IntegrationDiscoveryCatalogueEntry>,
}

impl IntegrationDiscoveryCatalogue {
    /// Validates all entries and rejects duplicate family identities.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.origin, "catalogue.origin")?;
        if self.revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "catalogue.revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            entry.validate()?;
            if !seen.insert(entry.family_id.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "catalogue family".to_owned(),
                    identity: entry.family_id.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Finds one exact family recipe after validating the catalogue.
    pub fn entry(
        &self,
        family_id: &PlatformHandle,
    ) -> Result<&IntegrationDiscoveryCatalogueEntry, InstallationError> {
        self.validate()?;
        self.entries
            .iter()
            .find(|entry| &entry.family_id == family_id)
            .ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "catalogue family was not found".to_owned(),
                )
            })
    }
}

/// Exact immutable candidate manifest used by a transaction.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateManifest {
    /// Candidate generation identity.
    pub generation: PlatformHandle,
    /// Component identities included in the candidate.
    pub components: Vec<PlatformHandle>,
    /// SHA-256 digest of the approved Kernel image.
    pub kernel_artifact_digest: PlatformHandle,
    /// SHA-256 digest of the approved Store bridge image. The bridge is route
    /// evidence only and is not a Host-owned process.
    pub store_bridge_artifact_digest: PlatformHandle,
    /// SHA-256 digest of the approved canonical Store engine image.
    pub canonical_store_artifact_digest: PlatformHandle,
    /// SHA-256 digest of the approved Host image.
    pub host_artifact_digest: PlatformHandle,
    /// Canonical installation-approved Kernel executable path.
    pub kernel_executable_path: PlatformHandle,
    /// Canonical installation-approved eliot-store-surreal bridge path.
    pub store_bridge_executable_path: PlatformHandle,
    /// Canonical installation-approved Surreal engine path.
    pub canonical_store_executable_path: PlatformHandle,
    /// Canonical installation-approved Host executable path.
    pub host_executable_path: PlatformHandle,
    /// Canonical installation-approved generation configuration path.
    pub config_path: PlatformHandle,
    /// Executable/dependency closure evidence.
    pub dependency_closure_refs: Vec<PlatformHandle>,
    /// License and source assurance evidence.
    pub license_refs: Vec<PlatformHandle>,
    /// Candidate configuration digest.
    pub config_digest: PlatformHandle,
    /// Exact Credential Manager target bound to this candidate generation.
    pub store_credential_target: PlatformHandle,
    /// Installation-approved public-key fingerprint for supervision leases.
    pub supervision_key_fingerprint: PlatformHandle,
    /// Signature/approval evidence reference.
    pub signature_ref: PlatformHandle,
    /// Digest of the exact mutable root topology approved by this manifest.
    pub runtime_state_roots_digest: PlatformHandle,
    /// Exact Host-owned runtime launch contour bound to this approval.
    pub runtime_launch: RuntimeLaunchDescriptor,
}

/// Immutable, digest-bound process launch inputs owned by Host.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLaunchDescriptor {
    /// Installation profile selected for this generation.
    pub profile: InstallationProfile,
    /// Canonical repository root for `portable_dev`, when applicable.
    pub portable_root: Option<PlatformHandle>,
    /// Installation lineage that approved this launch contour.
    pub installation_epoch: InstallationEpoch,
    /// Exact candidate generation that approved this launch contour.
    pub generation: PlatformHandle,
    /// Authority generation copied from the approved handoff descriptor.
    pub authority_generation: ResourceGeneration,
    /// Authority fence copied from the approved handoff descriptor.
    pub authority_state_fence: StateFence,
    /// Absolute, installation-approved `ProcessAuthorityHandoffDescriptor` path.
    pub authority_descriptor_path: PlatformHandle,
    /// Independent lowercase SHA-256 digest of the authority descriptor bytes.
    pub authority_descriptor_digest: PlatformHandle,
    /// Explicit profile-bound mutable runtime root topology.
    pub runtime_state_roots: RuntimeStateRoots,
    /// Explicit Kernel working directory.
    ///
    /// This v1 compatibility field must exactly equal
    /// `runtime_state_roots.kernel_work_root` and can be removed only in a
    /// separately versioned consumer migration.
    pub kernel_work_root: PlatformHandle,
    /// SHA-256 digest of the approved Kernel image.
    pub kernel_artifact_digest: PlatformHandle,
    /// Explicit installation-approved `eliotd.exe` path.
    pub eliotd_executable_path: PlatformHandle,
    /// SHA-256 digest of the approved `eliotd.exe` image.
    pub eliotd_artifact_digest: PlatformHandle,
    /// Explicit protected `GovernorLaunchConfig` path consumed only by
    /// `eliotd`. This is a distinct schema and artifact domain from the
    /// concrete Store configuration.
    pub eliotd_config_path: PlatformHandle,
    /// SHA-256 digest of the exact `GovernorLaunchConfig` bytes.
    pub eliotd_config_digest: PlatformHandle,
    /// Explicit serialized `EliotdLaunchDescriptor` path.
    pub eliotd_descriptor_path: PlatformHandle,
    /// SHA-256 digest of the serialized `EliotdLaunchDescriptor` bytes.
    pub eliotd_descriptor_digest: PlatformHandle,
    /// Public correlation nonce embedded in the serialized eliotd descriptor.
    /// It is not an authority credential; process/Job/pipe evidence is.
    pub eliotd_launch_nonce: PlatformHandle,
    /// Explicit concrete Store bridge configuration path. Its digest is the
    /// parent [`CandidateManifest::config_digest`] binding. It is never
    /// consumed as the daemon's `GovernorLaunchConfig`; that independent
    /// domain is bound by `eliotd_config_path` and `eliotd_config_digest`.
    pub store_config_path: PlatformHandle,
    /// Exact Credential Manager target provisioned for this Store generation.
    ///
    /// This is the same canonical target admitted by
    /// [`StoreCredentialProvisionPlan`]. It is part of the launch descriptor
    /// digest and therefore cannot be changed without re-staging the manifest.
    pub store_credential_target: PlatformHandle,
    /// Approved Store bridge image retained for the later Kernel route.
    pub store_bridge_executable_path: PlatformHandle,
    /// SHA-256 digest of the approved Store bridge image.
    pub store_bridge_artifact_digest: PlatformHandle,
    /// Neutral Store bootstrap descriptor consumed by Kernel.
    pub store_bootstrap_descriptor_path: PlatformHandle,
    /// SHA-256 digest of the neutral Store bootstrap descriptor.
    pub store_bootstrap_descriptor_digest: PlatformHandle,
    /// Approved canonical Surreal engine artifact path.
    pub canonical_store_executable_path: PlatformHandle,
    /// SHA-256 digest of the canonical Surreal engine image.
    pub canonical_store_artifact_digest: PlatformHandle,
    /// Exact Kernel child arguments, excluding argv[0].
    pub kernel_arguments: Vec<PlatformHandle>,
    /// Exact Store bridge arguments, excluding argv[0].
    pub store_bridge_arguments: Vec<PlatformHandle>,
    /// Exact canonical Surreal provider arguments, excluding argv[0].
    pub canonical_store_arguments: Vec<PlatformHandle>,
    /// Canonical SCM Host image and its approved digest.
    pub host_executable_path: PlatformHandle,
    /// SHA-256 digest of the Host image.
    pub host_artifact_digest: PlatformHandle,
    /// Canonical SCM Watchdog image and its approved digest.
    pub watchdog_executable_path: PlatformHandle,
    /// SHA-256 digest of the Watchdog image.
    pub watchdog_artifact_digest: PlatformHandle,
    /// SHA-256 of the descriptor fields excluding this digest.
    pub descriptor_digest: PlatformHandle,
}

impl RuntimeLaunchDescriptor {
    /// Recomputes the descriptor digest after all immutable launch fields have
    /// been materialized.
    ///
    /// The digest deliberately excludes itself, so producers can construct a
    /// descriptor with a zero digest, bind every path and artifact digest, and
    /// then seal the exact bytes consumed by Host and Watchdog. This is the
    /// only public sealing operation; callers must not hand-roll the unsigned
    /// projection.
    pub fn with_computed_digest(mut self) -> Result<Self, InstallationError> {
        self.descriptor_digest =
            PlatformHandle::new(sha256_hex(&self.unsigned_bytes()?)).map_err(|error| {
                InstallationError::InvalidField {
                    field: "runtime_launch.descriptor_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?;
        self.validate()?;
        Ok(self)
    }

    fn expected_store_bridge_arguments(&self, config_path: &PlatformHandle) -> Vec<String> {
        match self.profile {
            InstallationProfile::PortableDev => vec![
                "--portable-dev-root".to_owned(),
                self.portable_root
                    .as_ref()
                    .map_or_else(String::new, |root| root.as_str().to_owned()),
                "--config".to_owned(),
                config_path.as_str().to_owned(),
            ],
            InstallationProfile::SystemService | InstallationProfile::UserMode => {
                vec!["--config".to_owned(), config_path.as_str().to_owned()]
            }
        }
    }

    fn validate_canonical_store_arguments(&self) -> Result<(), InstallationError> {
        let arguments = self
            .canonical_store_arguments
            .iter()
            .map(PlatformHandle::as_str)
            .collect::<Vec<_>>();
        let expected_len = 12;
        if arguments.len() != expected_len
            || arguments[0] != "start"
            || arguments[1] != "--no-banner"
            || arguments[2] != "--bind"
            || arguments[4] != "--temporary-directory"
            || !same_windows_root(
                arguments[5],
                self.runtime_state_roots.store_temp_root.as_str(),
            )?
            || arguments[6] != "--log-file-enabled"
            || arguments[7] != "--log-file-path"
            || !same_windows_root(
                arguments[8],
                self.runtime_state_roots.store_work_root.as_str(),
            )?
            || arguments[9] != "--log-file-name"
            || arguments[10] != "surrealdb.log"
            || arguments[11]
                != format!(
                    "surrealkv://{}",
                    self.runtime_state_roots
                        .store_data_root
                        .as_str()
                        .replace('\\', "/")
                )
        {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.canonical_store_arguments".to_owned(),
                reason: "must exactly bind the canonical Surreal provider launch contour"
                    .to_owned(),
            });
        }
        let bind = arguments[3];
        let valid_bind = bind
            .strip_prefix("127.0.0.1:")
            .or_else(|| bind.strip_prefix("[::1]:"))
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port != 0);
        if !valid_bind {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.canonical_store_arguments".to_owned(),
                reason: "provider --bind must be an exact nonzero loopback socket".to_owned(),
            });
        }
        Ok(())
    }

    fn expected_kernel_arguments(&self, _config_path: &PlatformHandle) -> Vec<String> {
        vec![
            "--work-root".to_owned(),
            self.kernel_work_root.as_str().to_owned(),
            "--store-bootstrap".to_owned(),
            self.store_bootstrap_descriptor_path.as_str().to_owned(),
            "--store-bootstrap-sha256".to_owned(),
            self.store_bootstrap_descriptor_digest.as_str().to_owned(),
            "--authority-descriptor".to_owned(),
            self.authority_descriptor_path.as_str().to_owned(),
            "--authority-descriptor-sha256".to_owned(),
            self.authority_descriptor_digest.as_str().to_owned(),
            "--kernel-artifact-sha256".to_owned(),
            self.kernel_artifact_digest.as_str().to_owned(),
            "--eliotd-descriptor".to_owned(),
            self.eliotd_descriptor_path.as_str().to_owned(),
            "--eliotd-descriptor-sha256".to_owned(),
            self.eliotd_descriptor_digest.as_str().to_owned(),
        ]
    }

    /// Validates the launch contour against the exact approved generation
    /// configuration. Child argv is an authority input, not caller metadata.
    pub fn validate_for_config(
        &self,
        config_path: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        if self.store_config_path != *config_path {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.store_config_path".to_owned(),
                reason: "must exactly equal the approved concrete Store config".to_owned(),
            });
        }
        let expected_store = self.expected_store_bridge_arguments(config_path);
        let expected_kernel = self.expected_kernel_arguments(config_path);
        let actual_store = self
            .store_bridge_arguments
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect::<Vec<_>>();
        let actual_kernel = self
            .kernel_arguments
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect::<Vec<_>>();
        if actual_store != expected_store {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.store_bridge_arguments".to_owned(),
                reason: "must exactly select the approved generation config".to_owned(),
            });
        }
        if actual_kernel != expected_kernel {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.kernel_arguments".to_owned(),
                reason: "must exactly select the approved generation config".to_owned(),
            });
        }
        self.validate_canonical_store_arguments()?;
        Ok(())
    }

    /// Returns the exact approved Host executable path and content digest.
    ///
    /// The descriptor self-digest and all path/digest invariants are checked
    /// before a consumer receives the binding.
    pub fn host_artifact_binding(
        &self,
    ) -> Result<(&PlatformHandle, &PlatformHandle), InstallationError> {
        self.validate()?;
        Ok((&self.host_executable_path, &self.host_artifact_digest))
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, InstallationError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            profile: InstallationProfile,
            portable_root: &'a Option<PlatformHandle>,
            installation_epoch: &'a InstallationEpoch,
            generation: &'a PlatformHandle,
            authority_generation: ResourceGeneration,
            authority_state_fence: &'a StateFence,
            authority_descriptor_path: &'a PlatformHandle,
            authority_descriptor_digest: &'a PlatformHandle,
            runtime_state_roots: &'a RuntimeStateRoots,
            kernel_work_root: &'a PlatformHandle,
            kernel_artifact_digest: &'a PlatformHandle,
            eliotd_executable_path: &'a PlatformHandle,
            eliotd_artifact_digest: &'a PlatformHandle,
            eliotd_config_path: &'a PlatformHandle,
            eliotd_config_digest: &'a PlatformHandle,
            eliotd_descriptor_path: &'a PlatformHandle,
            eliotd_descriptor_digest: &'a PlatformHandle,
            eliotd_launch_nonce: &'a PlatformHandle,
            store_config_path: &'a PlatformHandle,
            store_credential_target: &'a PlatformHandle,
            store_bootstrap_descriptor_path: &'a PlatformHandle,
            store_bootstrap_descriptor_digest: &'a PlatformHandle,
            canonical_store_executable_path: &'a PlatformHandle,
            canonical_store_artifact_digest: &'a PlatformHandle,
            kernel_arguments: &'a [PlatformHandle],
            store_bridge_executable_path: &'a PlatformHandle,
            store_bridge_artifact_digest: &'a PlatformHandle,
            store_bridge_arguments: &'a [PlatformHandle],
            canonical_store_arguments: &'a [PlatformHandle],
            host_executable_path: &'a PlatformHandle,
            host_artifact_digest: &'a PlatformHandle,
            watchdog_executable_path: &'a PlatformHandle,
            watchdog_artifact_digest: &'a PlatformHandle,
        }
        serde_json::to_vec(&Unsigned {
            profile: self.profile,
            portable_root: &self.portable_root,
            installation_epoch: &self.installation_epoch,
            generation: &self.generation,
            authority_generation: self.authority_generation,
            authority_state_fence: &self.authority_state_fence,
            authority_descriptor_path: &self.authority_descriptor_path,
            authority_descriptor_digest: &self.authority_descriptor_digest,
            runtime_state_roots: &self.runtime_state_roots,
            kernel_work_root: &self.kernel_work_root,
            kernel_artifact_digest: &self.kernel_artifact_digest,
            eliotd_executable_path: &self.eliotd_executable_path,
            eliotd_artifact_digest: &self.eliotd_artifact_digest,
            eliotd_config_path: &self.eliotd_config_path,
            eliotd_config_digest: &self.eliotd_config_digest,
            eliotd_descriptor_path: &self.eliotd_descriptor_path,
            eliotd_descriptor_digest: &self.eliotd_descriptor_digest,
            eliotd_launch_nonce: &self.eliotd_launch_nonce,
            store_config_path: &self.store_config_path,
            store_credential_target: &self.store_credential_target,
            store_bootstrap_descriptor_path: &self.store_bootstrap_descriptor_path,
            store_bootstrap_descriptor_digest: &self.store_bootstrap_descriptor_digest,
            canonical_store_executable_path: &self.canonical_store_executable_path,
            canonical_store_artifact_digest: &self.canonical_store_artifact_digest,
            kernel_arguments: &self.kernel_arguments,
            store_bridge_executable_path: &self.store_bridge_executable_path,
            store_bridge_artifact_digest: &self.store_bridge_artifact_digest,
            store_bridge_arguments: &self.store_bridge_arguments,
            canonical_store_arguments: &self.canonical_store_arguments,
            host_executable_path: &self.host_executable_path,
            host_artifact_digest: &self.host_artifact_digest,
            watchdog_executable_path: &self.watchdog_executable_path,
            watchdog_artifact_digest: &self.watchdog_artifact_digest,
        })
        .map_err(|error| InstallationError::InvalidField {
            field: "manifest.runtime_launch".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Computes the canonical self-digest after all explicit launch bindings
    /// have been populated. Installers use this while materializing a new
    /// immutable descriptor; validation never repairs or infers a digest.
    pub fn compute_digest(&self) -> Result<String, InstallationError> {
        Ok(sha256_hex(&self.unsigned_bytes()?))
    }

    /// Validates the explicit launch contour and its self-digest.
    #[allow(
        clippy::too_many_lines,
        reason = "the launch contour is one fail-closed validation boundary"
    )]
    pub fn validate(&self) -> Result<(), InstallationError> {
        self.installation_epoch.validate()?;
        handle(&self.generation, "runtime_launch.generation")?;
        self.authority_state_fence
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "runtime_launch.authority_state_fence".to_owned(),
                reason: error.to_string(),
            })?;
        if self.authority_generation != self.authority_state_fence.resource_generation {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.authority_generation".to_owned(),
                reason: "must exactly equal the authority fence resource generation".to_owned(),
            });
        }
        handle(
            &self.authority_descriptor_path,
            "runtime_launch.authority_descriptor_path",
        )?;
        approved_path(
            &self.authority_descriptor_path,
            "runtime_launch.authority_descriptor_path",
        )?;
        sha256_handle(
            &self.authority_descriptor_digest,
            "runtime_launch.authority_descriptor_digest",
        )?;
        self.runtime_state_roots.validate()?;
        if self.runtime_state_roots.profile != self.profile {
            return Err(InstallationError::ProfileViolation(
                "runtime launch profile must equal RuntimeStateRoots.profile".to_owned(),
            ));
        }
        handle(&self.kernel_work_root, "runtime_launch.kernel_work_root")?;
        approved_path(&self.kernel_work_root, "runtime_launch.kernel_work_root")?;
        if !same_windows_root(
            self.kernel_work_root.as_str(),
            self.runtime_state_roots.kernel_work_root.as_str(),
        )? {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.kernel_work_root".to_owned(),
                reason: "legacy field must equal RuntimeStateRoots.kernel_work_root".to_owned(),
            });
        }
        sha256_handle(
            &self.kernel_artifact_digest,
            "runtime_launch.kernel_artifact_digest",
        )?;
        approved_path(
            &self.eliotd_executable_path,
            "runtime_launch.eliotd_executable_path",
        )?;
        approved_filename(
            &self.eliotd_executable_path,
            "eliotd.exe",
            "runtime_launch.eliotd_executable_path",
        )?;
        sha256_handle(
            &self.eliotd_artifact_digest,
            "runtime_launch.eliotd_artifact_digest",
        )?;
        approved_path(
            &self.eliotd_config_path,
            "runtime_launch.eliotd_config_path",
        )?;
        sha256_handle(
            &self.eliotd_config_digest,
            "runtime_launch.eliotd_config_digest",
        )?;
        approved_path(
            &self.eliotd_descriptor_path,
            "runtime_launch.eliotd_descriptor_path",
        )?;
        sha256_handle(
            &self.eliotd_descriptor_digest,
            "runtime_launch.eliotd_descriptor_digest",
        )?;
        validate_eliotd_launch_nonce(
            &self.eliotd_launch_nonce,
            "runtime_launch.eliotd_launch_nonce",
        )?;
        handle(&self.store_config_path, "runtime_launch.store_config_path")?;
        approved_path(&self.store_config_path, "runtime_launch.store_config_path")?;
        handle(
            &self.store_credential_target,
            "runtime_launch.store_credential_target",
        )?;
        if let Err(reason) = validate_store_credential_target(self.store_credential_target.as_str())
        {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.store_credential_target".to_owned(),
                reason,
            });
        }
        handle(
            &self.store_bootstrap_descriptor_path,
            "runtime_launch.store_bootstrap_descriptor_path",
        )?;
        approved_path(
            &self.store_bootstrap_descriptor_path,
            "runtime_launch.store_bootstrap_descriptor_path",
        )?;
        sha256_handle(
            &self.store_bootstrap_descriptor_digest,
            "runtime_launch.store_bootstrap_descriptor_digest",
        )?;
        handle(
            &self.canonical_store_executable_path,
            "runtime_launch.canonical_store_executable_path",
        )?;
        approved_path(
            &self.canonical_store_executable_path,
            "runtime_launch.canonical_store_executable_path",
        )?;
        approved_filename(
            &self.canonical_store_executable_path,
            "surreal.exe",
            "runtime_launch.canonical_store_executable_path",
        )?;
        sha256_handle(
            &self.canonical_store_artifact_digest,
            "runtime_launch.canonical_store_artifact_digest",
        )?;
        approved_path(
            &self.host_executable_path,
            "runtime_launch.host_executable_path",
        )?;
        approved_filename(
            &self.host_executable_path,
            "eliot-host.exe",
            "runtime_launch.host_executable_path",
        )?;
        sha256_handle(
            &self.host_artifact_digest,
            "runtime_launch.host_artifact_digest",
        )?;
        approved_path(
            &self.store_bridge_executable_path,
            "runtime_launch.store_bridge_executable_path",
        )?;
        approved_filename(
            &self.store_bridge_executable_path,
            "eliot-store-surreal.exe",
            "runtime_launch.store_bridge_executable_path",
        )?;
        sha256_handle(
            &self.store_bridge_artifact_digest,
            "runtime_launch.store_bridge_artifact_digest",
        )?;
        approved_path(
            &self.watchdog_executable_path,
            "runtime_launch.watchdog_executable_path",
        )?;
        approved_filename(
            &self.watchdog_executable_path,
            "eliot-watchdog.exe",
            "runtime_launch.watchdog_executable_path",
        )?;
        sha256_handle(
            &self.watchdog_artifact_digest,
            "runtime_launch.watchdog_artifact_digest",
        )?;
        match (self.profile, &self.portable_root) {
            (InstallationProfile::PortableDev, Some(root)) => {
                approved_path(root, "runtime_launch.portable_root")?;
                if !same_windows_root(
                    root.as_str(),
                    self.runtime_state_roots.installation_root.as_str(),
                )? {
                    return Err(InstallationError::ProfileViolation(
                        "portable root must equal RuntimeStateRoots.installation_root".to_owned(),
                    ));
                }
            }
            (InstallationProfile::PortableDev, None) => {
                return Err(InstallationError::ProfileViolation(
                    "portable_dev requires an explicit portable root".to_owned(),
                ));
            }
            (_, Some(_)) => {
                return Err(InstallationError::ProfileViolation(
                    "portable root is only valid for portable_dev".to_owned(),
                ));
            }
            (_, None) => {}
        }
        for (candidate, field) in [
            (
                &self.store_bridge_executable_path,
                "runtime_launch.store_bridge_executable_path",
            ),
            (
                &self.canonical_store_executable_path,
                "runtime_launch.canonical_store_executable_path",
            ),
            (
                &self.watchdog_executable_path,
                "runtime_launch.watchdog_executable_path",
            ),
            (
                &self.host_executable_path,
                "runtime_launch.host_executable_path",
            ),
            (&self.store_config_path, "runtime_launch.store_config_path"),
            (
                &self.eliotd_config_path,
                "runtime_launch.eliotd_config_path",
            ),
            (
                &self.store_bootstrap_descriptor_path,
                "runtime_launch.store_bootstrap_descriptor_path",
            ),
            (
                &self.eliotd_executable_path,
                "runtime_launch.eliotd_executable_path",
            ),
            (
                &self.eliotd_descriptor_path,
                "runtime_launch.eliotd_descriptor_path",
            ),
            (&self.kernel_work_root, "runtime_launch.kernel_work_root"),
        ] {
            reject_authority_alias(&self.authority_descriptor_path, candidate, field)?;
        }
        if let Some(portable_root) = &self.portable_root {
            reject_authority_alias(
                &self.authority_descriptor_path,
                portable_root,
                "runtime_launch.portable_root",
            )?;
        }
        for (candidate, candidate_field) in [
            (
                &self.authority_descriptor_path,
                "runtime_launch.authority_descriptor_path",
            ),
            (&self.store_config_path, "runtime_launch.store_config_path"),
            (
                &self.eliotd_config_path,
                "runtime_launch.eliotd_config_path",
            ),
            (
                &self.store_bootstrap_descriptor_path,
                "runtime_launch.store_bootstrap_descriptor_path",
            ),
            (
                &self.store_bridge_executable_path,
                "runtime_launch.store_bridge_executable_path",
            ),
            (
                &self.canonical_store_executable_path,
                "runtime_launch.canonical_store_executable_path",
            ),
            (
                &self.watchdog_executable_path,
                "runtime_launch.watchdog_executable_path",
            ),
            (
                &self.eliotd_executable_path,
                "runtime_launch.eliotd_executable_path",
            ),
            (
                &self.eliotd_descriptor_path,
                "runtime_launch.eliotd_descriptor_path",
            ),
            (
                &self.host_executable_path,
                "runtime_launch.host_executable_path",
            ),
        ] {
            self.runtime_state_roots
                .reject_mutable_alias(candidate, candidate_field)?;
        }
        for (arguments, field) in [
            (&self.kernel_arguments, "runtime_launch.kernel_arguments"),
            (
                &self.store_bridge_arguments,
                "runtime_launch.store_bridge_arguments",
            ),
            (
                &self.canonical_store_arguments,
                "runtime_launch.canonical_store_arguments",
            ),
        ] {
            for argument in arguments {
                handle(argument, field)?;
            }
        }
        let expected_store_bridge = self.expected_store_bridge_arguments(&self.store_config_path);
        let actual_store_bridge = self
            .store_bridge_arguments
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect::<Vec<_>>();
        if actual_store_bridge != expected_store_bridge {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.store_bridge_arguments".to_owned(),
                reason: "must exactly select the descriptor-bound Store config".to_owned(),
            });
        }
        self.validate_canonical_store_arguments()?;
        sha256_handle(&self.descriptor_digest, "runtime_launch.descriptor_digest")?;
        if self.compute_digest()? != self.descriptor_digest.as_str() {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.descriptor_digest".to_owned(),
                reason: "descriptor digest mismatch".to_owned(),
            });
        }
        Ok(())
    }
}

impl CandidateManifest {
    /// Validates candidate identity and complete assurance references.
    #[allow(
        clippy::too_many_lines,
        reason = "manifest validation keeps all generation bindings in one boundary"
    )]
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.generation, "manifest.generation")?;
        handles(&self.components, "manifest.components", true)?;
        sha256_handle(
            &self.kernel_artifact_digest,
            "manifest.kernel_artifact_digest",
        )?;
        sha256_handle(
            &self.store_bridge_artifact_digest,
            "manifest.store_bridge_artifact_digest",
        )?;
        sha256_handle(
            &self.canonical_store_artifact_digest,
            "manifest.canonical_store_artifact_digest",
        )?;
        sha256_handle(&self.host_artifact_digest, "manifest.host_artifact_digest")?;
        approved_path(
            &self.kernel_executable_path,
            "manifest.kernel_executable_path",
        )?;
        approved_filename(
            &self.kernel_executable_path,
            "eliot-kernel.exe",
            "manifest.kernel_executable_path",
        )?;
        self.runtime_launch
            .runtime_state_roots
            .reject_mutable_alias(
                &self.kernel_executable_path,
                "manifest.kernel_executable_path",
            )?;
        approved_path(
            &self.store_bridge_executable_path,
            "manifest.store_bridge_executable_path",
        )?;
        approved_filename(
            &self.store_bridge_executable_path,
            "eliot-store-surreal.exe",
            "manifest.store_bridge_executable_path",
        )?;
        approved_path(
            &self.canonical_store_executable_path,
            "manifest.canonical_store_executable_path",
        )?;
        approved_filename(
            &self.canonical_store_executable_path,
            "surreal.exe",
            "manifest.canonical_store_executable_path",
        )?;
        approved_path(&self.host_executable_path, "manifest.host_executable_path")?;
        approved_filename(
            &self.host_executable_path,
            "eliot-host.exe",
            "manifest.host_executable_path",
        )?;
        self.runtime_launch
            .runtime_state_roots
            .reject_mutable_alias(&self.host_executable_path, "manifest.host_executable_path")?;
        if self.kernel_executable_path == self.store_bridge_executable_path
            || self.kernel_executable_path == self.canonical_store_executable_path
            || self.kernel_executable_path == self.host_executable_path
            || self.store_bridge_executable_path == self.canonical_store_executable_path
            || self.store_bridge_executable_path == self.host_executable_path
            || self.canonical_store_executable_path == self.host_executable_path
        {
            return Err(InstallationError::Duplicate {
                kind: "manifest.named_artifact_paths".to_owned(),
                identity: "aliased executable path".to_owned(),
            });
        }
        approved_path(&self.config_path, "manifest.config_path")?;
        if self.runtime_launch.generation != self.generation {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_launch.generation".to_owned(),
                reason: "must exactly equal the approved manifest generation".to_owned(),
            });
        }
        if self.runtime_launch.store_config_path != self.config_path {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_launch.store_config_path".to_owned(),
                reason: "must exactly equal the approved manifest config_path".to_owned(),
            });
        }
        if self.runtime_launch.eliotd_config_path == self.config_path
            || self.runtime_launch.eliotd_config_path
                == self.runtime_launch.authority_descriptor_path
            || self.runtime_launch.eliotd_config_path
                == self.runtime_launch.store_bootstrap_descriptor_path
            || self.runtime_launch.eliotd_config_path == self.runtime_launch.eliotd_descriptor_path
        {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_launch.eliotd_config_path".to_owned(),
                reason: "eliotd Governor config must be distinct from Store config and authority descriptors".to_owned(),
            });
        }
        if self.runtime_launch.eliotd_descriptor_path == self.config_path
            || self.runtime_launch.eliotd_descriptor_path
                == self.runtime_launch.authority_descriptor_path
            || self.runtime_launch.eliotd_descriptor_path
                == self.runtime_launch.store_bootstrap_descriptor_path
        {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_launch.eliotd_descriptor_path".to_owned(),
                reason: "eliotd descriptor must be distinct from approved config and authority descriptors".to_owned(),
            });
        }
        if self.runtime_launch.eliotd_executable_path == self.kernel_executable_path
            || self.runtime_launch.eliotd_executable_path == self.store_bridge_executable_path
            || self.runtime_launch.eliotd_executable_path == self.canonical_store_executable_path
        {
            return Err(InstallationError::Duplicate {
                kind: "manifest.named_artifact_paths".to_owned(),
                identity: "eliotd executable aliases another approved executable".to_owned(),
            });
        }
        handle(
            &self.store_credential_target,
            "manifest.store_credential_target",
        )?;
        if let Err(reason) = validate_store_credential_target(self.store_credential_target.as_str())
        {
            return Err(InstallationError::InvalidField {
                field: "manifest.store_credential_target".to_owned(),
                reason,
            });
        }
        if self.runtime_launch.store_credential_target != self.store_credential_target {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_launch.store_credential_target".to_owned(),
                reason: "must exactly equal the approved manifest credential target".to_owned(),
            });
        }
        if self.runtime_launch.store_bootstrap_descriptor_path == self.config_path {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_launch.store_bootstrap_descriptor_path".to_owned(),
                reason: "neutral descriptor must be distinct from concrete Store config".to_owned(),
            });
        }
        if self.runtime_launch.authority_descriptor_path == self.config_path
            || self.runtime_launch.authority_descriptor_path
                == self.runtime_launch.store_bootstrap_descriptor_path
        {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_launch.authority_descriptor_path".to_owned(),
                reason: "authority descriptor must be distinct from Store descriptors".to_owned(),
            });
        }
        reject_authority_alias(
            &self.runtime_launch.authority_descriptor_path,
            &self.kernel_executable_path,
            "manifest.kernel_executable_path",
        )?;
        reject_authority_alias(
            &self.runtime_launch.authority_descriptor_path,
            &self.host_executable_path,
            "manifest.host_executable_path",
        )?;
        if self.runtime_launch.canonical_store_executable_path
            != self.canonical_store_executable_path
        {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_launch.canonical_store_executable_path".to_owned(),
                reason: "must exactly equal the approved canonical engine path".to_owned(),
            });
        }
        if self.runtime_launch.store_bridge_executable_path != self.store_bridge_executable_path
            || self.runtime_launch.kernel_artifact_digest != self.kernel_artifact_digest
            || self.runtime_launch.store_bridge_artifact_digest != self.store_bridge_artifact_digest
            || self.runtime_launch.canonical_store_artifact_digest
                != self.canonical_store_artifact_digest
            || self.runtime_launch.host_executable_path != self.host_executable_path
            || self.runtime_launch.host_artifact_digest != self.host_artifact_digest
        {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_launch.artifact_bindings".to_owned(),
                reason: "named artifact bindings do not exactly match the manifest".to_owned(),
            });
        }
        handles(
            &self.dependency_closure_refs,
            "manifest.dependency_closure_refs",
            true,
        )?;
        handles(&self.license_refs, "manifest.license_refs", true)?;
        sha256_handle(&self.config_digest, "manifest.config_digest")?;
        sha256_handle(
            &self.supervision_key_fingerprint,
            "manifest.supervision_key_fingerprint",
        )?;
        sha256_handle(
            &self.runtime_state_roots_digest,
            "manifest.runtime_state_roots_digest",
        )?;
        if self.runtime_state_roots_digest != self.runtime_launch.runtime_state_roots.roots_digest {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_state_roots_digest".to_owned(),
                reason: "must exactly bind the launch RuntimeStateRoots digest".to_owned(),
            });
        }
        handle(&self.signature_ref, "manifest.signature_ref")
            .and_then(|()| self.runtime_launch.validate_for_config(&self.config_path))
    }

    /// Returns the named Kernel, canonical Store, and bridge artifact digests.
    pub fn runtime_artifact_digests(
        &self,
    ) -> Result<(&PlatformHandle, &PlatformHandle, &PlatformHandle), InstallationError> {
        self.validate()?;
        Ok((
            &self.kernel_artifact_digest,
            &self.canonical_store_artifact_digest,
            &self.store_bridge_artifact_digest,
        ))
    }

    /// Returns the canonical Kernel, canonical Store engine and configuration paths.
    pub fn runtime_paths(&self) -> (&PlatformHandle, &PlatformHandle, &PlatformHandle) {
        (
            &self.kernel_executable_path,
            &self.canonical_store_executable_path,
            &self.config_path,
        )
    }

    /// Returns the two Host-owned child image digests: Kernel and Store
    /// bridge. The canonical Surreal provider is launched only inside the
    /// validated Store bridge boundary.
    pub fn host_child_artifact_digests(
        &self,
    ) -> Result<(&PlatformHandle, &PlatformHandle), InstallationError> {
        self.validate()?;
        Ok((
            &self.kernel_artifact_digest,
            &self.store_bridge_artifact_digest,
        ))
    }

    /// Returns the exact approved Host executable path and content digest.
    ///
    /// The complete manifest/descriptor chain is validated before any
    /// borrowed binding is exposed, so consumers cannot receive a partial or
    /// defaulted Host identity.
    pub fn host_artifact_binding(
        &self,
    ) -> Result<(&PlatformHandle, &PlatformHandle), InstallationError> {
        self.validate()?;
        Ok((&self.host_executable_path, &self.host_artifact_digest))
    }

    /// Returns the exact Kernel, Store bridge, and Store config paths consumed
    /// by Host. The canonical Surreal provider path never crosses this launch
    /// seam as a direct Host child.
    pub fn host_child_paths(&self) -> (&PlatformHandle, &PlatformHandle, &PlatformHandle) {
        (
            &self.kernel_executable_path,
            &self.store_bridge_executable_path,
            &self.config_path,
        )
    }
}

/// One artifact generation admitted by installation policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedGeneration {
    /// The complete immutable candidate manifest.
    pub manifest: CandidateManifest,
    /// Non-secret approval evidence reference.
    pub approval_ref: PlatformHandle,
    /// Whether this generation is currently active.
    pub active: bool,
    /// Whether this generation is the last-known-good activation.
    pub last_known_good: bool,
}

/// Durable idempotency receipt for the most recent terminal pending
/// activation result.  Keeping the exact transaction and plan bindings lets
/// a retried Host commit/abort return the original terminal result without
/// accepting a different caller after the pending projection is cleared.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingActivationTerminal {
    transaction_id: PlatformHandle,
    plan_digest: PlatformHandle,
    generation: PlatformHandle,
    disposition: PendingActivationTerminalDisposition,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PendingActivationTerminalDisposition {
    Committed,
    Aborted,
}

impl ApprovedGeneration {
    /// Validates the generation and its approval reference.
    pub fn validate(&self) -> Result<(), InstallationError> {
        self.manifest.validate()?;
        handle(&self.approval_ref, "approved_generation.approval_ref")
    }
}

/// Installation-owned approved-generation and last-known-good registry.
///
/// The registry admits only complete [`CandidateManifest`] values. Activation
/// is a bounded state transition: an unknown generation cannot become active,
/// and rollback selects the previously recorded last-known-good generation.
///
/// ```compile_fail
/// use eliot_installation::ApprovedGenerationRegistry;
/// fn forge_active(registry: &mut ApprovedGenerationRegistry) {
///     registry.active_generation = None;
/// }
/// ```
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedGenerationRegistry {
    /// Approved generations keyed by their exact generation identity.
    generations: Vec<ApprovedGeneration>,
    /// Currently active generation identity, when one is active.
    active_generation: Option<PlatformHandle>,
    /// Last-known-good generation identity, when one is available.
    last_known_good_generation: Option<PlatformHandle>,
    /// Installer-owned candidate awaiting Host health proof and commit.
    ///
    /// This field is deliberately required on the wire (rather than given a
    /// serde default).  Registries written before pending activation was
    /// introduced therefore require an explicit migration/re-stage.
    pending_activation: Option<PendingActivation>,
    /// Exact idempotency receipt for the most recent committed or aborted
    /// pending activation.  A new stage supersedes this single terminal
    /// receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_terminal_activation: Option<PendingActivationTerminal>,
}

/// Durable activation candidate handed from the installer coordinator to the
/// Host owner.  Every identity and digest is repeated from the immutable
/// candidate so a stale or substituted pending record fails closed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingActivation {
    /// Sole installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Digest of the transaction's immutable installer effect plan.
    pub plan_digest: PlatformHandle,
    /// Exact candidate generation and launch contour to be started by Host.
    pub manifest: CandidateManifest,
    /// Candidate configuration digest repeated as an activation binding.
    pub config_digest: PlatformHandle,
    /// Candidate Kernel image digest repeated as an activation binding.
    pub kernel_artifact_digest: PlatformHandle,
    /// Candidate Store bridge image digest repeated as an activation binding.
    pub store_bridge_artifact_digest: PlatformHandle,
    /// Candidate canonical Store image digest repeated as an activation binding.
    pub canonical_store_artifact_digest: PlatformHandle,
    /// Candidate Host executable path repeated as an activation binding.
    pub host_executable_path: PlatformHandle,
    /// Candidate Host image digest repeated as an activation binding.
    pub host_artifact_digest: PlatformHandle,
    /// Candidate mutable-root topology digest repeated as an activation binding.
    pub runtime_state_roots_digest: PlatformHandle,
    /// Canonical digest of `manifest` bytes.
    pub manifest_digest: PlatformHandle,
    /// Prior active generation retained until Host commits this candidate.
    pub prior_active_generation: Option<PlatformHandle>,
    /// Installer approval evidence for this candidate.
    pub approval_ref: PlatformHandle,
    /// Durable recovery disposition after an interrupted/failed attempt.
    pub state: PendingActivationState,
}

/// Pending activation disposition.  Recovery-required remains pending and
/// cannot be mistaken for an active generation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum PendingActivationState {
    /// Host may claim and attempt the exact candidate.
    Pending,
    /// A launch or registry outcome is unknown and needs reconciliation.
    RecoveryRequired {
        /// Stable recovery reason without provider secrets.
        reason: String,
    },
}

const REGISTRY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_approved_generations_v1");
const REGISTRY_RELATIVE_PATH: &str = "Eliot/host/installation-registry.redb";

#[allow(
    dead_code,
    reason = "legacy wire mirror is used for strict schema discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRegistryWire {
    generations: Vec<LegacyApprovedGenerationWire>,
    active_generation: Option<PlatformHandle>,
    last_known_good_generation: Option<PlatformHandle>,
}

#[allow(
    dead_code,
    reason = "legacy wire mirror is used for strict schema discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyApprovedGenerationWire {
    manifest: LegacyCandidateManifestWire,
    approval_ref: PlatformHandle,
    active: bool,
    last_known_good: bool,
}

#[allow(
    dead_code,
    reason = "legacy wire mirror is used for strict schema discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCandidateManifestWire {
    generation: PlatformHandle,
    components: Vec<PlatformHandle>,
    kernel_artifact_digest: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_executable_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    config_path: PlatformHandle,
    dependency_closure_refs: Vec<PlatformHandle>,
    license_refs: Vec<PlatformHandle>,
    config_digest: PlatformHandle,
    supervision_key_fingerprint: PlatformHandle,
    signature_ref: PlatformHandle,
    runtime_launch: LegacyRuntimeLaunchDescriptor,
}

#[allow(
    dead_code,
    reason = "legacy wire mirror is used for strict schema discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRuntimeLaunchDescriptor {
    profile: InstallationProfile,
    portable_root: Option<PlatformHandle>,
    kernel_work_root: PlatformHandle,
    kernel_artifact_digest: PlatformHandle,
    store_config_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    store_bootstrap_descriptor_path: PlatformHandle,
    store_bootstrap_descriptor_digest: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_arguments: Vec<PlatformHandle>,
    canonical_store_arguments: Vec<PlatformHandle>,
    watchdog_executable_path: PlatformHandle,
    watchdog_artifact_digest: PlatformHandle,
    descriptor_digest: PlatformHandle,
}

#[allow(
    dead_code,
    reason = "pre-split wire mirror is used for strict argv migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreSplitRegistryWire {
    generations: Vec<PreSplitApprovedGenerationWire>,
    active_generation: Option<PlatformHandle>,
    last_known_good_generation: Option<PlatformHandle>,
}

#[allow(
    dead_code,
    reason = "pre-split wire mirror is used for strict argv migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreSplitApprovedGenerationWire {
    manifest: PreSplitCandidateManifestWire,
    approval_ref: PlatformHandle,
    active: bool,
    last_known_good: bool,
}

#[allow(
    dead_code,
    reason = "pre-split wire mirror is used for strict argv migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreSplitCandidateManifestWire {
    generation: PlatformHandle,
    components: Vec<PlatformHandle>,
    kernel_artifact_digest: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_executable_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    config_path: PlatformHandle,
    dependency_closure_refs: Vec<PlatformHandle>,
    license_refs: Vec<PlatformHandle>,
    config_digest: PlatformHandle,
    supervision_key_fingerprint: PlatformHandle,
    signature_ref: PlatformHandle,
    runtime_state_roots_digest: PlatformHandle,
    runtime_launch: PreSplitRuntimeLaunchDescriptorWire,
}

#[allow(
    dead_code,
    reason = "pre-split wire mirror is used for strict argv migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreSplitRuntimeLaunchDescriptorWire {
    profile: InstallationProfile,
    portable_root: Option<PlatformHandle>,
    installation_epoch: InstallationEpoch,
    generation: PlatformHandle,
    authority_generation: ResourceGeneration,
    authority_state_fence: StateFence,
    authority_descriptor_path: PlatformHandle,
    authority_descriptor_digest: PlatformHandle,
    runtime_state_roots: RuntimeStateRoots,
    kernel_work_root: PlatformHandle,
    kernel_artifact_digest: PlatformHandle,
    store_config_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    store_bootstrap_descriptor_path: PlatformHandle,
    store_bootstrap_descriptor_digest: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_arguments: Vec<PlatformHandle>,
    canonical_store_arguments: Vec<PlatformHandle>,
    watchdog_executable_path: PlatformHandle,
    watchdog_artifact_digest: PlatformHandle,
    descriptor_digest: PlatformHandle,
}

#[allow(
    dead_code,
    reason = "v1 wire mirror is used for strict major-version migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1RegistryWire {
    generations: Vec<V1ApprovedGenerationWire>,
    active_generation: Option<PlatformHandle>,
    last_known_good_generation: Option<PlatformHandle>,
}

#[allow(
    dead_code,
    reason = "v1 wire mirror is used for strict major-version migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1ApprovedGenerationWire {
    manifest: V1CandidateManifestWire,
    approval_ref: PlatformHandle,
    active: bool,
    last_known_good: bool,
}

#[allow(
    dead_code,
    reason = "v1 wire mirror is used for strict major-version migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1CandidateManifestWire {
    generation: PlatformHandle,
    components: Vec<PlatformHandle>,
    kernel_artifact_digest: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_executable_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    config_path: PlatformHandle,
    dependency_closure_refs: Vec<PlatformHandle>,
    license_refs: Vec<PlatformHandle>,
    config_digest: PlatformHandle,
    supervision_key_fingerprint: PlatformHandle,
    signature_ref: PlatformHandle,
    runtime_launch: V1RuntimeLaunchDescriptorWire,
}

#[allow(
    dead_code,
    reason = "v1 wire mirror is used for strict major-version migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1RuntimeLaunchDescriptorWire {
    profile: InstallationProfile,
    portable_root: Option<PlatformHandle>,
    installation_epoch: InstallationEpoch,
    generation: PlatformHandle,
    authority_generation: ResourceGeneration,
    authority_state_fence: StateFence,
    authority_descriptor_path: PlatformHandle,
    authority_descriptor_digest: PlatformHandle,
    kernel_work_root: PlatformHandle,
    kernel_artifact_digest: PlatformHandle,
    store_config_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    store_bootstrap_descriptor_path: PlatformHandle,
    store_bootstrap_descriptor_digest: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_arguments: Vec<PlatformHandle>,
    canonical_store_arguments: Vec<PlatformHandle>,
    watchdog_executable_path: PlatformHandle,
    watchdog_artifact_digest: PlatformHandle,
    descriptor_digest: PlatformHandle,
}

#[allow(
    dead_code,
    reason = "pre-Host-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreHostArtifactBindingRegistryWire {
    generations: Vec<PreHostArtifactBindingApprovedGenerationWire>,
    active_generation: Option<PlatformHandle>,
    last_known_good_generation: Option<PlatformHandle>,
    #[serde(default)]
    pending_activation: Option<serde_json::Value>,
    #[serde(default)]
    last_terminal_activation: Option<serde_json::Value>,
}

#[allow(
    dead_code,
    reason = "pre-Host-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreHostArtifactBindingApprovedGenerationWire {
    manifest: PreHostArtifactBindingCandidateManifestWire,
    approval_ref: PlatformHandle,
    active: bool,
    last_known_good: bool,
}

#[allow(
    dead_code,
    reason = "pre-Host-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreHostArtifactBindingCandidateManifestWire {
    generation: PlatformHandle,
    components: Vec<PlatformHandle>,
    kernel_artifact_digest: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_executable_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    config_path: PlatformHandle,
    dependency_closure_refs: Vec<PlatformHandle>,
    license_refs: Vec<PlatformHandle>,
    config_digest: PlatformHandle,
    store_credential_target: PlatformHandle,
    supervision_key_fingerprint: PlatformHandle,
    signature_ref: PlatformHandle,
    runtime_state_roots_digest: PlatformHandle,
    runtime_launch: PreHostArtifactBindingRuntimeLaunchDescriptorWire,
}

#[allow(
    dead_code,
    reason = "pre-Host-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreHostArtifactBindingRuntimeLaunchDescriptorWire {
    profile: InstallationProfile,
    portable_root: Option<PlatformHandle>,
    installation_epoch: InstallationEpoch,
    generation: PlatformHandle,
    authority_generation: ResourceGeneration,
    authority_state_fence: StateFence,
    authority_descriptor_path: PlatformHandle,
    authority_descriptor_digest: PlatformHandle,
    runtime_state_roots: RuntimeStateRoots,
    kernel_work_root: PlatformHandle,
    kernel_artifact_digest: PlatformHandle,
    eliotd_executable_path: PlatformHandle,
    eliotd_artifact_digest: PlatformHandle,
    eliotd_config_path: PlatformHandle,
    eliotd_config_digest: PlatformHandle,
    eliotd_descriptor_path: PlatformHandle,
    eliotd_descriptor_digest: PlatformHandle,
    eliotd_launch_nonce: PlatformHandle,
    store_config_path: PlatformHandle,
    store_credential_target: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    store_bootstrap_descriptor_path: PlatformHandle,
    store_bootstrap_descriptor_digest: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_arguments: Vec<PlatformHandle>,
    store_bridge_arguments: Vec<PlatformHandle>,
    canonical_store_arguments: Vec<PlatformHandle>,
    watchdog_executable_path: PlatformHandle,
    watchdog_artifact_digest: PlatformHandle,
    descriptor_digest: PlatformHandle,
}

#[allow(
    dead_code,
    reason = "pre-credential-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreCredentialBindingRegistryWire {
    generations: Vec<PreCredentialBindingApprovedGenerationWire>,
    active_generation: Option<PlatformHandle>,
    last_known_good_generation: Option<PlatformHandle>,
    #[serde(default)]
    pending_activation: Option<serde_json::Value>,
    #[serde(default)]
    last_terminal_activation: Option<serde_json::Value>,
}

#[allow(
    dead_code,
    reason = "pre-credential-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreCredentialBindingApprovedGenerationWire {
    manifest: PreCredentialBindingCandidateManifestWire,
    approval_ref: PlatformHandle,
    active: bool,
    last_known_good: bool,
}

#[allow(
    dead_code,
    reason = "pre-credential-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreCredentialBindingCandidateManifestWire {
    generation: PlatformHandle,
    components: Vec<PlatformHandle>,
    kernel_artifact_digest: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_executable_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    config_path: PlatformHandle,
    dependency_closure_refs: Vec<PlatformHandle>,
    license_refs: Vec<PlatformHandle>,
    config_digest: PlatformHandle,
    supervision_key_fingerprint: PlatformHandle,
    signature_ref: PlatformHandle,
    runtime_state_roots_digest: PlatformHandle,
    runtime_launch: PreCredentialBindingRuntimeLaunchDescriptorWire,
}

#[allow(
    dead_code,
    reason = "pre-credential-binding wire mirror is used for strict migration discrimination"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreCredentialBindingRuntimeLaunchDescriptorWire {
    profile: InstallationProfile,
    portable_root: Option<PlatformHandle>,
    installation_epoch: InstallationEpoch,
    generation: PlatformHandle,
    authority_generation: ResourceGeneration,
    authority_state_fence: StateFence,
    authority_descriptor_path: PlatformHandle,
    authority_descriptor_digest: PlatformHandle,
    runtime_state_roots: RuntimeStateRoots,
    kernel_work_root: PlatformHandle,
    kernel_artifact_digest: PlatformHandle,
    store_config_path: PlatformHandle,
    store_bridge_executable_path: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    store_bootstrap_descriptor_path: PlatformHandle,
    store_bootstrap_descriptor_digest: PlatformHandle,
    canonical_store_executable_path: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    kernel_arguments: Vec<PlatformHandle>,
    store_bridge_arguments: Vec<PlatformHandle>,
    canonical_store_arguments: Vec<PlatformHandle>,
    watchdog_executable_path: PlatformHandle,
    watchdog_artifact_digest: PlatformHandle,
    descriptor_digest: PlatformHandle,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrePendingRegistryWire {
    generations: Vec<ApprovedGeneration>,
    active_generation: Option<PlatformHandle>,
    last_known_good_generation: Option<PlatformHandle>,
}

fn is_pre_eliotd_config_registry(bytes: &[u8]) -> bool {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    let Some(generations) = value
        .get_mut("generations")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return false;
    };
    if generations.is_empty() {
        return false;
    }
    for (index, generation) in generations.iter_mut().enumerate() {
        let Some(runtime) = generation
            .get_mut("manifest")
            .and_then(|manifest| manifest.get_mut("runtime_launch"))
            .and_then(serde_json::Value::as_object_mut)
        else {
            return false;
        };
        if runtime.contains_key("eliotd_config_path")
            || runtime.contains_key("eliotd_config_digest")
        {
            return false;
        }
        runtime.insert(
            "eliotd_config_path".to_owned(),
            serde_json::Value::String(format!(
                r"C:\ProgramData\Eliot\Migration\eliotd-governor-{index}.json"
            )),
        );
        runtime.insert(
            "eliotd_config_digest".to_owned(),
            serde_json::Value::String("0".repeat(64)),
        );
    }
    let Ok(mut registry) = serde_json::from_value::<ApprovedGenerationRegistry>(value) else {
        return false;
    };
    for generation in &mut registry.generations {
        let Ok(bytes) = generation.manifest.runtime_launch.unsigned_bytes() else {
            return false;
        };
        let Ok(digest) = PlatformHandle::new(sha256_hex(&bytes)) else {
            return false;
        };
        generation.manifest.runtime_launch.descriptor_digest = digest;
    }
    registry.validate().is_ok()
}

fn decode_registry_bytes(bytes: &[u8]) -> Result<ApprovedGenerationRegistry, InstallationError> {
    match serde_json::from_slice::<ApprovedGenerationRegistry>(bytes) {
        Ok(registry) => {
            registry
                .validate()
                .map_err(|_| InstallationError::CorruptRegistry {
                    reason: "current registry projection failed validation".to_owned(),
                })?;
            Ok(registry)
        }
        Err(_) => {
            if serde_json::from_slice::<PreHostArtifactBindingRegistryWire>(bytes).is_ok() {
                Err(InstallationError::MigrationRequired {
                    reason: "approved-generation registry predates the approved Host executable artifact binding and requires explicit re-stage"
                        .to_owned(),
                })
            } else if is_pre_eliotd_config_registry(bytes) {
                Err(InstallationError::MigrationRequired {
                    reason: "approved-generation registry predates the separate eliotd Governor config binding and requires explicit re-stage"
                        .to_owned(),
                })
            } else if serde_json::from_slice::<PreCredentialBindingRegistryWire>(bytes).is_ok() {
                Err(InstallationError::MigrationRequired {
                    reason: "approved-generation registry predates the descriptor-bound Store credential target and requires explicit re-stage"
                        .to_owned(),
                })
            } else if serde_json::from_slice::<PreSplitRegistryWire>(bytes).is_ok() {
                Err(InstallationError::MigrationRequired {
                    reason: "approved-generation registry predates split Store bridge/provider argv and requires explicit re-stage"
                        .to_owned(),
                })
            } else if serde_json::from_slice::<V1RegistryWire>(bytes).is_ok() {
                Err(InstallationError::MigrationRequired {
                    reason: "approved-generation registry v1 requires explicit re-stage; runtime roots cannot be synthesized"
                        .to_owned(),
                })
            } else if serde_json::from_slice::<LegacyRegistryWire>(bytes).is_ok() {
                Err(InstallationError::MigrationRequired {
                    reason: "approved-generation registry requires re-stage; legacy launch fields cannot be synthesized"
                        .to_owned(),
                })
            } else if let Ok(previous) = serde_json::from_slice::<PrePendingRegistryWire>(bytes) {
                let previous = ApprovedGenerationRegistry {
                    generations: previous.generations,
                    active_generation: previous.active_generation,
                    last_known_good_generation: previous.last_known_good_generation,
                    pending_activation: None,
                    last_terminal_activation: None,
                };
                if previous.validate().is_ok() {
                    Err(InstallationError::MigrationRequired {
                        reason: "approved-generation registry predates durable pending activation and requires explicit re-stage"
                            .to_owned(),
                    })
                } else {
                    Err(InstallationError::CorruptRegistry {
                        reason: "pre-pending registry projection failed validation".to_owned(),
                    })
                }
            } else {
                Err(InstallationError::CorruptRegistry {
                    reason:
                        "registry bytes are neither current nor structurally valid prior-v1 schema"
                            .to_owned(),
                })
            }
        }
    }
}

/// Durable redb owner for approved generations and LKG activation state.
pub struct RedbInstallationRegistry {
    database: Database,
    _path_lease: ProtectedPathLease,
}

impl RedbInstallationRegistry {
    /// Opens or creates the registry database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, InstallationError> {
        let path = path.as_ref();
        require_protected_program_data_path(path, REGISTRY_RELATIVE_PATH)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let path_lease = ProtectedPathLease::open_or_create(REGISTRY_RELATIVE_PATH)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        if path_lease.path() != path {
            return Err(InstallationError::Platform(
                "registry path is not the exact protected ProgramData path".to_owned(),
            ));
        }
        let database = Database::create(path_lease.path())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        path_lease
            .verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Self {
            database,
            _path_lease: path_lease,
        })
    }

    /// Inspects an existing registry without creating a file, database or
    /// table. The retained protected lease covers the complete read so a
    /// deletion or replacement race fails closed before redb is opened.
    pub fn inspect_existing(
        path: impl AsRef<Path>,
    ) -> Result<Option<ApprovedGenerationRegistry>, InstallationError> {
        let path = path.as_ref();
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(_) | Err(_) => {
                return Err(InstallationError::Platform(
                    "registry path is not an existing regular file".to_owned(),
                ));
            }
        }
        require_protected_program_data_path(path, REGISTRY_RELATIVE_PATH)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let path_lease = ProtectedPathLease::open_existing_absolute(path)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        if path_lease.path() != path {
            return Err(InstallationError::Platform(
                "registry path is not the exact protected ProgramData path".to_owned(),
            ));
        }
        path_lease
            .verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let database = ReadOnlyDatabase::open(path_lease.path())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        path_lease
            .verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let read = database
            .begin_read()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let table = match read.open_table(REGISTRY_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Ok(Some(ApprovedGenerationRegistry::new()));
            }
            Err(error) => return Err(InstallationError::Platform(error.to_string())),
        };
        let Some(value) = table
            .get("registry")
            .map_err(|error| InstallationError::Platform(error.to_string()))?
        else {
            return Ok(Some(ApprovedGenerationRegistry::new()));
        };
        let registry = decode_registry_bytes(value.value())?;
        registry.validate()?;
        Ok(Some(registry))
    }

    /// Loads the registry, returning an empty value on first use.
    pub fn load(&self) -> Result<ApprovedGenerationRegistry, InstallationError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let table = match read.open_table(REGISTRY_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Ok(ApprovedGenerationRegistry::new());
            }
            Err(error) => return Err(InstallationError::Platform(error.to_string())),
        };
        let Some(value) = table
            .get("registry")
            .map_err(|error| InstallationError::Platform(error.to_string()))?
        else {
            return Ok(ApprovedGenerationRegistry::new());
        };
        let registry = decode_registry_bytes(value.value())?;
        // A durable registry is an authority projection, not an opaque cache.
        // Never allow malformed or contradictory bytes to become an empty or
        // partially trusted activation decision.
        registry.validate()?;
        Ok(registry)
    }

    /// Durably stores one complete validated registry projection.
    pub fn save(&self, registry: &ApprovedGenerationRegistry) -> Result<(), InstallationError> {
        registry.validate()?;
        let bytes = serde_json::to_vec(registry)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        {
            let mut table = write
                .open_table(REGISTRY_TABLE)
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
            table
                .insert("registry", bytes.as_slice())
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
        }
        write
            .commit()
            .map_err(|error| InstallationError::Platform(error.to_string()))
    }
}

impl ApprovedGenerationRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generations: Vec::new(),
            active_generation: None,
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
        }
    }

    /// Approves one exact candidate generation.
    fn approve(
        &mut self,
        manifest: CandidateManifest,
        approval_ref: PlatformHandle,
    ) -> Result<(), InstallationError> {
        manifest.validate()?;
        handle(&approval_ref, "approved_generation.approval_ref")?;
        if self
            .generations
            .iter()
            .any(|generation| generation.manifest.generation == manifest.generation)
        {
            return Err(InstallationError::Duplicate {
                kind: "approved generation".to_owned(),
                identity: manifest.generation.as_str().to_owned(),
            });
        }
        self.generations.push(ApprovedGeneration {
            manifest,
            approval_ref,
            active: false,
            last_known_good: false,
        });
        self.validate()?;
        Ok(())
    }

    /// Persists an installer-approved candidate as pending.  This is the only
    /// installer admission operation; it never changes `active_generation`.
    pub fn stage_pending_activation(
        &mut self,
        transaction_id: PlatformHandle,
        plan_digest: PlatformHandle,
        manifest: CandidateManifest,
        approval_ref: PlatformHandle,
    ) -> Result<(), InstallationError> {
        handle(&transaction_id, "pending_activation.transaction_id")?;
        sha256_handle(&plan_digest, "pending_activation.plan_digest")?;
        manifest.validate()?;
        handle(&approval_ref, "pending_activation.approval_ref")?;
        let manifest_digest = candidate_manifest_digest(&manifest)?;
        let pending = PendingActivation {
            transaction_id,
            plan_digest,
            config_digest: manifest.config_digest.clone(),
            kernel_artifact_digest: manifest.kernel_artifact_digest.clone(),
            store_bridge_artifact_digest: manifest.store_bridge_artifact_digest.clone(),
            canonical_store_artifact_digest: manifest.canonical_store_artifact_digest.clone(),
            host_executable_path: manifest.host_executable_path.clone(),
            host_artifact_digest: manifest.host_artifact_digest.clone(),
            runtime_state_roots_digest: manifest.runtime_state_roots_digest.clone(),
            manifest,
            manifest_digest,
            prior_active_generation: self.active_generation.clone(),
            approval_ref,
            state: PendingActivationState::Pending,
        };
        if let Some(existing) = &self.pending_activation {
            let mut same_identity = pending.clone();
            same_identity.state = existing.state.clone();
            if existing == &same_identity {
                return Ok(());
            }
            return Err(InstallationError::IdentityConflict);
        }
        if self
            .generations
            .iter()
            .any(|generation| generation.manifest.generation == pending.manifest.generation)
        {
            return Err(InstallationError::Duplicate {
                kind: "approved generation".to_owned(),
                identity: pending.manifest.generation.as_str().to_owned(),
            });
        }
        self.approve(pending.manifest.clone(), pending.approval_ref.clone())?;
        self.pending_activation = Some(pending);
        self.last_terminal_activation = None;
        self.validate()
    }

    /// Returns the pending candidate, if one exists.
    #[must_use]
    pub const fn pending_activation(&self) -> Option<&PendingActivation> {
        self.pending_activation.as_ref()
    }

    fn terminal_matches(
        &self,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: Option<&PlatformHandle>,
        disposition: PendingActivationTerminalDisposition,
    ) -> bool {
        self.last_terminal_activation
            .as_ref()
            .is_some_and(|terminal| {
                terminal.transaction_id == *transaction_id
                    && terminal.plan_digest == *plan_digest
                    && generation.is_none_or(|value| terminal.generation == *value)
                    && terminal.disposition == disposition
            })
    }

    /// Host-only claim/retry transition for one exact pending identity.
    ///
    /// The capability is minted only by the live Host owner lease. An external
    /// installer or plugin cannot call this method without that proof.
    ///
    /// ```compile_fail
    /// # use eliot_installation::ApprovedGenerationRegistry;
    /// # use eliot_platform::PlatformHandle;
    /// # let mut registry = ApprovedGenerationRegistry::new();
    /// # let transaction = PlatformHandle::new("tx").unwrap();
    /// # let plan = PlatformHandle::new("plan").unwrap();
    /// # let generation = PlatformHandle::new("generation").unwrap();
    /// registry.claim_pending_activation(&transaction, &plan, &generation);
    /// ```
    /// Recovery-required records may be retried with the same transaction and
    /// plan digest; substitutions are rejected before any process launch.
    pub fn claim_pending_activation(
        &mut self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
    ) -> Result<PendingActivation, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.validate()?;
        let pending = self.pending_activation.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation("no pending activation exists".to_owned())
        })?;
        if pending.transaction_id != *transaction_id
            || pending.plan_digest != *plan_digest
            || pending.manifest.generation != *generation
        {
            return Err(InstallationError::IdentityConflict);
        }
        pending.state = PendingActivationState::Pending;
        let claimed = pending.clone();
        self.validate()?;
        Ok(claimed)
    }

    /// Returns the immutable approved-generation projection.
    #[must_use]
    pub fn generations(&self) -> &[ApprovedGeneration] {
        &self.generations
    }

    /// Returns the active generation identity, if committed by Host.
    #[must_use]
    pub const fn active_generation(&self) -> Option<&PlatformHandle> {
        self.active_generation.as_ref()
    }

    /// Returns the retained last-known-good identity, if any.
    #[must_use]
    pub const fn last_known_good_generation(&self) -> Option<&PlatformHandle> {
        self.last_known_good_generation.as_ref()
    }

    /// Commits a Host-proven healthy pending candidate and clears pending.
    /// The transaction and plan digest are mandatory idempotency bindings.
    pub fn commit_pending_activation(
        &mut self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.validate()?;
        let Some(pending) = self.pending_activation.as_ref() else {
            if self.terminal_matches(
                transaction_id,
                plan_digest,
                Some(generation),
                PendingActivationTerminalDisposition::Committed,
            ) {
                return Ok(());
            }
            return Err(InstallationError::IncompleteObservation(
                "no pending activation exists".to_owned(),
            ));
        };
        if pending.transaction_id != *transaction_id
            || pending.plan_digest != *plan_digest
            || pending.manifest.generation != *generation
        {
            return Err(InstallationError::IdentityConflict);
        }
        if !matches!(pending.state, PendingActivationState::Pending) {
            return Err(InstallationError::IncompleteObservation(
                "pending activation requires recovery before commit".to_owned(),
            ));
        }
        let pending_record = pending.clone();
        let pending = self.pending_activation.take();
        if let Err(error) = self.activate(generation) {
            self.pending_activation = pending;
            return Err(error);
        }
        self.last_terminal_activation = Some(PendingActivationTerminal {
            transaction_id: pending_record.transaction_id,
            plan_digest: pending_record.plan_digest,
            generation: pending_record.manifest.generation,
            disposition: PendingActivationTerminalDisposition::Committed,
        });
        self.validate()
    }

    /// Records an unknown/failed Host attempt without advertising the candidate.
    pub fn mark_pending_recovery(
        &mut self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        reason: impl Into<String>,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.validate()?;
        let pending = self.pending_activation.as_mut().ok_or_else(|| {
            InstallationError::IncompleteObservation("no pending activation exists".to_owned())
        })?;
        if pending.transaction_id != *transaction_id || pending.plan_digest != *plan_digest {
            return Err(InstallationError::IdentityConflict);
        }
        let reason = reason.into();
        text(&reason, "pending_activation.state.reason")?;
        pending.state = PendingActivationState::RecoveryRequired { reason };
        self.validate()
    }

    /// Aborts a first-install candidate without creating an active/LKG state.
    pub fn abort_pending_activation(
        &mut self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.validate()?;
        let Some(pending) = self.pending_activation.as_ref() else {
            if self.terminal_matches(
                transaction_id,
                plan_digest,
                None,
                PendingActivationTerminalDisposition::Aborted,
            ) {
                return Ok(());
            }
            return Err(InstallationError::IncompleteObservation(
                "no pending activation exists".to_owned(),
            ));
        };
        if pending.transaction_id != *transaction_id || pending.plan_digest != *plan_digest {
            return Err(InstallationError::IdentityConflict);
        }
        if self.active_generation.is_some() || self.last_known_good_generation.is_some() {
            return Err(InstallationError::IncompleteObservation(
                "abort-to-none is only valid for first install".to_owned(),
            ));
        }
        let generation = pending.manifest.generation.clone();
        let terminal = PendingActivationTerminal {
            transaction_id: pending.transaction_id.clone(),
            plan_digest: pending.plan_digest.clone(),
            generation: generation.clone(),
            disposition: PendingActivationTerminalDisposition::Aborted,
        };
        self.generations
            .retain(|item| item.manifest.generation != generation);
        self.pending_activation = None;
        self.last_terminal_activation = Some(terminal);
        self.validate()
    }

    /// Activates an approved generation and records the prior active
    /// generation as last-known-good before crossing the activation boundary.
    fn activate(&mut self, generation: &PlatformHandle) -> Result<(), InstallationError> {
        self.validate()?;
        let selected = self
            .generations
            .iter()
            .position(|item| &item.manifest.generation == generation)
            .ok_or_else(|| {
                InstallationError::IncompleteObservation("generation is not approved".to_owned())
            })?;
        if self.active_generation.as_ref() == Some(generation) {
            // Reactivation is idempotent, but still requires the full
            // projection to be internally consistent.
            return Ok(());
        }
        let previous = self.active_generation.take();
        self.last_known_good_generation.clone_from(&previous);
        for item in &mut self.generations {
            item.active = false;
            // A cutover has exactly one LKG: the generation that was active
            // immediately before this transition.  Clear any stale marker
            // before setting that projection below.
            item.last_known_good = false;
        }
        if let Some(previous) = previous
            && let Some(item) = self
                .generations
                .iter_mut()
                .find(|item| item.manifest.generation == previous)
        {
            item.last_known_good = true;
        }
        self.generations[selected].active = true;
        self.generations[selected].last_known_good = false;
        self.active_generation = Some(generation.clone());
        self.validate()?;
        Ok(())
    }

    /// Returns the currently active approved generation.
    #[must_use]
    pub fn active(&self) -> Option<&ApprovedGeneration> {
        self.active_generation.as_ref().and_then(|generation| {
            self.generations
                .iter()
                .find(|item| &item.manifest.generation == generation && item.active)
        })
    }

    fn validate_terminal_activation(
        &self,
        terminal: &PendingActivationTerminal,
    ) -> Result<(), InstallationError> {
        handle(
            &terminal.transaction_id,
            "last_terminal_activation.transaction_id",
        )?;
        sha256_handle(
            &terminal.plan_digest,
            "last_terminal_activation.plan_digest",
        )?;
        handle(&terminal.generation, "last_terminal_activation.generation")?;
        match terminal.disposition {
            PendingActivationTerminalDisposition::Committed
                if self.active_generation.as_ref() != Some(&terminal.generation) =>
            {
                Err(InstallationError::IncompleteObservation(
                    "committed terminal activation is not the active generation".to_owned(),
                ))
            }
            PendingActivationTerminalDisposition::Aborted
                if self
                    .generations
                    .iter()
                    .any(|item| item.manifest.generation == terminal.generation) =>
            {
                Err(InstallationError::IncompleteObservation(
                    "aborted terminal activation remains approved".to_owned(),
                ))
            }
            _ => Ok(()),
        }
    }

    /// Validates the complete registry projection and all generation entries.
    pub fn validate(&self) -> Result<(), InstallationError> {
        let mut identities = BTreeSet::new();
        let mut active_count = 0_usize;
        let mut lkg_count = 0_usize;
        for generation in &self.generations {
            generation.validate()?;
            if !identities.insert(generation.manifest.generation.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "approved generation".to_owned(),
                    identity: generation.manifest.generation.as_str().to_owned(),
                });
            }
            if generation.active {
                active_count += 1;
            }
            if generation.last_known_good {
                lkg_count += 1;
            }
        }
        if active_count > 1 {
            return Err(InstallationError::IncompleteObservation(
                "registry contains multiple active generations".to_owned(),
            ));
        }
        if lkg_count > 1 {
            return Err(InstallationError::IncompleteObservation(
                "registry contains multiple last-known-good generations".to_owned(),
            ));
        }
        if let Some(active) = &self.active_generation {
            if active_count != 1
                || !self
                    .generations
                    .iter()
                    .any(|item| item.active && item.manifest.generation == *active)
            {
                return Err(InstallationError::IncompleteObservation(
                    "active generation is absent from registry".to_owned(),
                ));
            }
        } else if active_count != 0 {
            return Err(InstallationError::IncompleteObservation(
                "active generation flag has no registry identity".to_owned(),
            ));
        }
        if let Some(lkg) = &self.last_known_good_generation {
            if lkg_count != 1
                || !self
                    .generations
                    .iter()
                    .any(|item| item.last_known_good && item.manifest.generation == *lkg)
            {
                return Err(InstallationError::IncompleteObservation(
                    "last-known-good generation is absent from registry".to_owned(),
                ));
            }
            if self.active_generation.as_ref() == Some(lkg) {
                return Err(InstallationError::IncompleteObservation(
                    "active generation cannot also be last-known-good".to_owned(),
                ));
            }
        } else if lkg_count != 0 {
            return Err(InstallationError::IncompleteObservation(
                "last-known-good flag has no registry identity".to_owned(),
            ));
        }
        if let Some(terminal) = &self.last_terminal_activation {
            self.validate_terminal_activation(terminal)?;
        }
        if let Some(pending) = &self.pending_activation {
            pending.validate(self.active_generation.as_ref())?;
            if !self.generations.iter().any(|item| {
                item.manifest == pending.manifest && item.approval_ref == pending.approval_ref
            }) {
                return Err(InstallationError::IncompleteObservation(
                    "pending activation candidate is absent from registry".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

fn candidate_manifest_digest(
    manifest: &CandidateManifest,
) -> Result<PlatformHandle, InstallationError> {
    let bytes = serde_json::to_vec(manifest).map_err(|error| InstallationError::InvalidField {
        field: "pending_activation.manifest_digest".to_owned(),
        reason: error.to_string(),
    })?;
    PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
        field: "pending_activation.manifest_digest".to_owned(),
        reason: error.to_string(),
    })
}

impl PendingActivation {
    fn validate(
        &self,
        active_generation: Option<&PlatformHandle>,
    ) -> Result<(), InstallationError> {
        handle(&self.transaction_id, "pending_activation.transaction_id")?;
        sha256_handle(&self.plan_digest, "pending_activation.plan_digest")?;
        self.manifest.validate()?;
        sha256_handle(&self.manifest_digest, "pending_activation.manifest_digest")?;
        if candidate_manifest_digest(&self.manifest)? != self.manifest_digest {
            return Err(InstallationError::IdentityConflict);
        }
        for (value, field, expected) in [
            (
                &self.config_digest,
                "config_digest",
                &self.manifest.config_digest,
            ),
            (
                &self.kernel_artifact_digest,
                "kernel_artifact_digest",
                &self.manifest.kernel_artifact_digest,
            ),
            (
                &self.store_bridge_artifact_digest,
                "store_bridge_artifact_digest",
                &self.manifest.store_bridge_artifact_digest,
            ),
            (
                &self.canonical_store_artifact_digest,
                "canonical_store_artifact_digest",
                &self.manifest.canonical_store_artifact_digest,
            ),
            (
                &self.host_artifact_digest,
                "host_artifact_digest",
                &self.manifest.host_artifact_digest,
            ),
            (
                &self.runtime_state_roots_digest,
                "runtime_state_roots_digest",
                &self.manifest.runtime_state_roots_digest,
            ),
        ] {
            sha256_handle(value, &format!("pending_activation.{field}"))?;
            if value != expected {
                return Err(InstallationError::IdentityConflict);
            }
        }
        if self.host_executable_path != self.manifest.host_executable_path {
            return Err(InstallationError::IdentityConflict);
        }
        if let Some(prior) = &self.prior_active_generation {
            handle(prior, "pending_activation.prior_active_generation")?;
        }
        if self.prior_active_generation.as_ref() != active_generation {
            return Err(InstallationError::IdentityConflict);
        }
        handle(&self.approval_ref, "pending_activation.approval_ref")?;
        if let PendingActivationState::RecoveryRequired { reason } = &self.state {
            text(reason, "pending_activation.state.reason")?;
        }
        Ok(())
    }
}

/// A planned immutable change to an OS registration, file or plugin surface.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedChange {
    /// Stable change identity.
    pub change_id: PlatformHandle,
    /// External object/reference affected by the change.
    pub target: PlatformHandle,
    /// Exact precondition evidence.
    pub precondition_refs: Vec<PlatformHandle>,
    /// Expected postcondition evidence.
    pub postcondition_refs: Vec<PlatformHandle>,
}

impl PlannedChange {
    /// Validates one planned external change.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.change_id, "change_id")?;
        handle(&self.target, "change.target")?;
        handles(&self.precondition_refs, "change.precondition_refs", true)?;
        handles(&self.postcondition_refs, "change.postcondition_refs", true)
    }
}

/// Service role owned by the elevated `SystemService` installer.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallerServiceRole {
    /// `eliot-host` service.
    Host,
    /// Sibling `eliot-watchdog` service.
    Watchdog,
}

/// Password-free account admitted for Runtime Live service plans.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallerServiceAccount {
    /// Built-in least-privileged `LocalService` identity.
    LocalService,
}

/// Principals admitted by one protected runtime-root ACL plan.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallerAclPrincipal {
    /// Built-in Administrators group.
    Administrators,
    /// Built-in `LocalService` identity used by Host and Watchdog.
    LocalService,
    /// Built-in `LocalSystem` identity retained for installer/OS ownership.
    LocalSystem,
    /// Current user, valid only for `UserMode` or `PortableDev`.
    CurrentUser,
}

/// One immutable installer effect owned by the enclosing
/// [`InstallationTransaction`]. The elevated adapter reports observations
/// through the existing transaction coordinator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum InstallerEffectPlan {
    /// Create and retain one declared root.
    CreateRoot {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Exact root to create.
        root: PlatformHandle,
    },
    /// Apply and verify one protected ACL.
    ApplyAcl {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Exact root receiving the ACL.
        root: PlatformHandle,
        /// Complete admitted principal set.
        principals: Vec<InstallerAclPrincipal>,
    },
    /// Register one own-process SCM service.
    RegisterService {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Host or Watchdog role.
        role: InstallerServiceRole,
        /// Stable SCM service name.
        service_name: PlatformHandle,
        /// Approved executable path.
        executable_path: PlatformHandle,
        /// Password-free service account.
        account: InstallerServiceAccount,
        /// Whether SCM starts the service automatically.
        automatic_start: bool,
    },
    /// Provision the Store credential inside the exact `LocalService` Host token.
    ProvisionStoreCredential {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Secret-free immutable provision plan.
        provision: StoreCredentialProvisionPlan,
    },
}

impl InstallerEffectPlan {
    fn effect_id(&self) -> &PlatformHandle {
        match self {
            Self::CreateRoot { effect_id, .. }
            | Self::ApplyAcl { effect_id, .. }
            | Self::RegisterService { effect_id, .. }
            | Self::ProvisionStoreCredential { effect_id, .. } => effect_id,
        }
    }

    fn validate(&self) -> Result<(), InstallationError> {
        handle(self.effect_id(), "installer_effect.effect_id")?;
        match self {
            Self::CreateRoot { root, .. } => approved_path(root, "installer_effect.root"),
            Self::ApplyAcl {
                root, principals, ..
            } => {
                approved_path(root, "installer_effect.root")?;
                if principals.is_empty() {
                    return Err(InstallationError::InvalidField {
                        field: "installer_effect.principals".to_owned(),
                        reason: "ACL plan must contain explicit principals".to_owned(),
                    });
                }
                let unique = principals.iter().copied().collect::<BTreeSet<_>>();
                if unique.len() != principals.len() {
                    return Err(InstallationError::Duplicate {
                        kind: "installer ACL principal".to_owned(),
                        identity: self.effect_id().as_str().to_owned(),
                    });
                }
                Ok(())
            }
            Self::RegisterService {
                service_name,
                executable_path,
                automatic_start,
                ..
            } => {
                handle(service_name, "installer_effect.service_name")?;
                approved_path(executable_path, "installer_effect.executable_path")?;
                if !automatic_start {
                    return Err(InstallationError::InvalidField {
                        field: "installer_effect.automatic_start".to_owned(),
                        reason: "Runtime Live Host and Watchdog must use automatic start"
                            .to_owned(),
                    });
                }
                Ok(())
            }
            Self::ProvisionStoreCredential { provision, .. } => provision.validate(),
        }
    }
}

fn validate_effect_profile(
    profile: InstallationProfile,
    plan: &InstallerEffectPlan,
) -> Result<(), InstallationError> {
    match plan {
        InstallerEffectPlan::CreateRoot { .. } => Ok(()),
        InstallerEffectPlan::ApplyAcl { principals, .. } => {
            let expected = match profile {
                InstallationProfile::SystemService => [
                    InstallerAclPrincipal::Administrators,
                    InstallerAclPrincipal::LocalService,
                    InstallerAclPrincipal::LocalSystem,
                ]
                .into_iter()
                .collect::<BTreeSet<_>>(),
                InstallationProfile::UserMode | InstallationProfile::PortableDev => [
                    InstallerAclPrincipal::CurrentUser,
                    InstallerAclPrincipal::LocalSystem,
                ]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            };
            if principals.iter().copied().collect::<BTreeSet<_>>() == expected {
                Ok(())
            } else {
                Err(InstallationError::ProfileViolation(
                    "effect request ACL differs from its exact profile".to_owned(),
                ))
            }
        }
        InstallerEffectPlan::RegisterService { .. }
        | InstallerEffectPlan::ProvisionStoreCredential { .. }
            if profile == InstallationProfile::SystemService =>
        {
            Ok(())
        }
        InstallerEffectPlan::RegisterService { .. } => Err(InstallationError::ProfileViolation(
            "service effect requires SystemService profile".to_owned(),
        )),
        InstallerEffectPlan::ProvisionStoreCredential { .. } => {
            Err(InstallationError::ProfileViolation(
                "Store credential provisioning requires SystemService profile".to_owned(),
            ))
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "ordered fail-closed installer validation is kept in one auditable boundary"
)]
fn validate_installer_effects(
    profile: InstallationProfile,
    roots: &RuntimeStateRoots,
    store_credential_target: &PlatformHandle,
    planned_changes: &[PlannedChange],
    effects: &[InstallerEffectPlan],
) -> Result<(), InstallationError> {
    if effects.is_empty() {
        return Err(InstallationError::InvalidField {
            field: "installer_effects".to_owned(),
            reason: "must contain explicit root, ACL and service work".to_owned(),
        });
    }
    let planned_ids = planned_changes
        .iter()
        .map(|change| change.change_id.as_str())
        .collect::<BTreeSet<_>>();
    if planned_ids.len() != planned_changes.len() {
        return Err(InstallationError::Duplicate {
            kind: "planned change".to_owned(),
            identity: "installer plan contains a repeated change identity".to_owned(),
        });
    }
    let mut effect_ids = BTreeSet::new();
    let mut created_roots = BTreeSet::new();
    let mut acl_roots = BTreeSet::new();
    let mut service_roles = BTreeSet::new();
    let mut host_service_image = None;
    let mut credential_host_image = None;
    for effect in effects {
        effect.validate()?;
        if !effect_ids.insert(effect.effect_id().as_str()) {
            return Err(InstallationError::Duplicate {
                kind: "installer effect".to_owned(),
                identity: effect.effect_id().as_str().to_owned(),
            });
        }
        match effect {
            InstallerEffectPlan::CreateRoot { root, .. } => {
                created_roots.insert(WindowsPathIdentity::parse_root(
                    root.as_str(),
                    "installer_effect.root",
                )?);
            }
            InstallerEffectPlan::ApplyAcl {
                root, principals, ..
            } => {
                let expected_principals = if profile == InstallationProfile::SystemService {
                    [
                        InstallerAclPrincipal::Administrators,
                        InstallerAclPrincipal::LocalService,
                        InstallerAclPrincipal::LocalSystem,
                    ]
                    .into_iter()
                    .collect::<BTreeSet<_>>()
                } else {
                    [
                        InstallerAclPrincipal::CurrentUser,
                        InstallerAclPrincipal::LocalSystem,
                    ]
                    .into_iter()
                    .collect::<BTreeSet<_>>()
                };
                if principals.iter().copied().collect::<BTreeSet<_>>() != expected_principals {
                    return Err(InstallationError::ProfileViolation(
                        "runtime ACL differs from the exact profile principal set".to_owned(),
                    ));
                }
                acl_roots.insert(WindowsPathIdentity::parse_root(
                    root.as_str(),
                    "installer_effect.root",
                )?);
            }
            InstallerEffectPlan::RegisterService {
                role,
                service_name,
                executable_path,
                account,
                ..
            } => {
                if profile != InstallationProfile::SystemService {
                    return Err(InstallationError::ProfileViolation(
                        "SCM effects are admitted only for SystemService".to_owned(),
                    ));
                }
                if *account != InstallerServiceAccount::LocalService {
                    return Err(InstallationError::ProfileViolation(
                        "Host and Watchdog must run as LocalService".to_owned(),
                    ));
                }
                let (expected_name, expected_image) = match role {
                    InstallerServiceRole::Host => (ELIOT_HOST_SERVICE_NAME, "eliot-host.exe"),
                    InstallerServiceRole::Watchdog => {
                        (ELIOT_WATCHDOG_SERVICE_NAME, "eliot-watchdog.exe")
                    }
                };
                let observed_image = executable_path
                    .as_str()
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or_default();
                if service_name.as_str() != expected_name
                    || !observed_image.eq_ignore_ascii_case(expected_image)
                {
                    return Err(InstallationError::ProfileViolation(format!(
                        "{role:?} must register canonical service {expected_name} from {expected_image}"
                    )));
                }
                if !service_roles.insert(*role) {
                    return Err(InstallationError::Duplicate {
                        kind: "installer service role".to_owned(),
                        identity: format!("{role:?}"),
                    });
                }
                if *role == InstallerServiceRole::Host {
                    host_service_image = Some(WindowsPathIdentity::parse_root(
                        executable_path.as_str(),
                        "installer_effect.host_executable",
                    )?);
                }
            }
            InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => {
                if provision.target != *store_credential_target {
                    return Err(InstallationError::InvalidField {
                        field: "installer_effect.provision.target".to_owned(),
                        reason: "must exactly equal the candidate runtime launch credential target"
                            .to_owned(),
                    });
                }
                let host_root = WindowsPathIdentity::parse_root(
                    roots.host_state_root.as_str(),
                    "runtime_roots.host_state_root",
                )?;
                let planned_root = WindowsPathIdentity::parse_root(
                    provision.host_state_root.as_str(),
                    "credential.host_state_root",
                )?;
                if profile != InstallationProfile::SystemService || planned_root != host_root {
                    return Err(InstallationError::ProfileViolation(
                        "credential marker must use the exact SystemService host_state_root"
                            .to_owned(),
                    ));
                }
                if credential_host_image
                    .replace(WindowsPathIdentity::parse_root(
                        provision.expected_host_executable.as_str(),
                        "credential.expected_host_executable",
                    )?)
                    .is_some()
                {
                    return Err(InstallationError::Duplicate {
                        kind: "Store credential effect".to_owned(),
                        identity: provision.target.as_str().to_owned(),
                    });
                }
            }
        }
    }
    if planned_ids != effect_ids {
        return Err(InstallationError::IdentityConflict);
    }
    let required_roots = std::iter::once(&roots.installation_root)
        .chain(roots.root_fields().into_iter().map(|(_, root)| root))
        .map(|root| WindowsPathIdentity::parse_root(root.as_str(), "required_root"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if created_roots != required_roots || acl_roots != required_roots {
        return Err(InstallationError::IncompleteObservation(
            "transaction plan must create and ACL exactly the declared runtime roots".to_owned(),
        ));
    }
    let required_services = [InstallerServiceRole::Host, InstallerServiceRole::Watchdog]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if profile == InstallationProfile::SystemService && service_roles != required_services {
        return Err(InstallationError::IncompleteObservation(
            "SystemService transaction requires exactly Host and Watchdog registrations".to_owned(),
        ));
    }
    if profile == InstallationProfile::SystemService
        && (credential_host_image.is_none() || credential_host_image != host_service_image)
    {
        return Err(InstallationError::IncompleteObservation(
            "SystemService transaction requires one Store credential effect bound to the exact Host image"
                .to_owned(),
        ));
    }
    if profile != InstallationProfile::SystemService && credential_host_image.is_some() {
        return Err(InstallationError::ProfileViolation(
            "non-service profiles must not provision a LocalService Store credential".to_owned(),
        ));
    }
    if profile != InstallationProfile::SystemService && !service_roles.is_empty() {
        return Err(InstallationError::ProfileViolation(
            "non-service profiles must not register SCM services".to_owned(),
        ));
    }
    Ok(())
}

/// Store-volume observation used to evaluate the immutable free-space policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreFreeSpaceObservation {
    /// Windows observed caller-available bytes.
    Known {
        /// Caller-available bytes on the Store data volume.
        available_bytes: u64,
        /// Evidence binding the observation to the volume and instant.
        evidence_refs: Vec<PlatformHandle>,
    },
    /// Windows could not classify the current available space.
    Unknown {
        /// Evidence or failure capsule references for recovery.
        evidence_refs: Vec<PlatformHandle>,
    },
}

/// Durable installer stage. A partial external effect cannot skip recovery.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationStage {
    /// Immutable plan exists but no external effect has started.
    Planned,
    /// Candidate bytes are being copied into an isolated staging root.
    Staging,
    /// Hashes/signatures/dependency closure have been observed.
    StaticVerified,
    /// Candidate registrations are being prepared without authority.
    Registering,
    /// The activation pointer or service configuration is being switched.
    Activating,
    /// Runtime health and conformance have been observed.
    ActiveVerified,
    /// Superseded staging and registrations are being removed.
    Cleaning,
    /// Transaction has completed with an observed disposition.
    Completed,
    /// External outcome is unknown and requires reconciliation or rollback.
    RollbackRequired,
    /// Candidate was rolled back with an observed disposition.
    RolledBack,
    /// Recovery could not safely determine a disposition.
    Quarantined,
}

impl InstallationStage {
    fn can_advance(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Planned, Self::Staging | Self::RollbackRequired)
                | (Self::Staging, Self::StaticVerified | Self::RollbackRequired)
                | (
                    Self::StaticVerified,
                    Self::Registering | Self::RollbackRequired
                )
                | (Self::Registering, Self::Activating | Self::RollbackRequired)
                | (
                    Self::Activating,
                    Self::ActiveVerified | Self::RollbackRequired
                )
                | (Self::ActiveVerified, Self::Cleaning | Self::Completed)
                | (Self::Cleaning, Self::Completed | Self::RollbackRequired)
                | (Self::RollbackRequired, Self::RolledBack | Self::Quarantined)
        )
    }
}

/// Proven ownership of an observed installer effect.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationEffectDisposition {
    /// The exact external object was created by this transaction intent.
    CreatedByTransaction,
    /// The exact requested postcondition already existed before execution.
    PreexistingMatching,
}

/// Exact OS identity and security state observed through one retained handle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationOsObjectSnapshot {
    /// Digest of the canonical UTF-16 path returned by Windows for the handle.
    pub canonical_path_digest: PlatformHandle,
    /// NTFS volume serial number.
    pub volume_serial_number: u32,
    /// Stable file index on that volume.
    pub file_index: u64,
    /// Digest of owner, DACL and descriptor control read from the handle.
    pub security_descriptor_digest: PlatformHandle,
}

impl InstallationOsObjectSnapshot {
    fn validate(&self, field: &str) -> Result<(), InstallationError> {
        sha256_handle(
            &self.canonical_path_digest,
            &format!("{field}.canonical_path_digest"),
        )?;
        if self.file_index == 0 {
            return Err(InstallationError::InvalidField {
                field: format!("{field}.file_index"),
                reason: "must be non-zero".to_owned(),
            });
        }
        sha256_handle(
            &self.security_descriptor_digest,
            &format!("{field}.security_descriptor_digest"),
        )
    }
}

/// Typed Windows proof that an exact target was absent below pinned parents.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationRootAbsentSnapshot {
    /// Digest of the exact requested target path in canonical UTF-16 form.
    pub target_path_digest: PlatformHandle,
    /// OS-known-folder/profile anchor retained during observation.
    pub profile_anchor: InstallationOsObjectSnapshot,
    /// Ordered existing objects from the profile anchor through the parent.
    pub ancestors: Vec<InstallationOsObjectSnapshot>,
    /// Exact retained parent handle used for the absence observation.
    pub parent: InstallationOsObjectSnapshot,
    /// Explicit negative observation; never inferred from an empty identity.
    pub root_absent: bool,
}

impl InstallationRootAbsentSnapshot {
    fn validate(&self) -> Result<(), InstallationError> {
        sha256_handle(
            &self.target_path_digest,
            "effect.precondition.os_snapshot.target_path_digest",
        )?;
        self.profile_anchor
            .validate("effect.precondition.os_snapshot.profile_anchor")?;
        if self.ancestors.is_empty() {
            return Err(InstallationError::InvalidField {
                field: "effect.precondition.os_snapshot.ancestors".to_owned(),
                reason: "must include the retained parent contour".to_owned(),
            });
        }
        for (index, ancestor) in self.ancestors.iter().enumerate() {
            ancestor.validate(&format!(
                "effect.precondition.os_snapshot.ancestors[{index}]"
            ))?;
        }
        self.parent
            .validate("effect.precondition.os_snapshot.parent")?;
        if self.ancestors.last() != Some(&self.parent) || !self.root_absent {
            return Err(InstallationError::InvalidField {
                field: "effect.precondition.os_snapshot".to_owned(),
                reason: "must end at the retained parent and prove exact absence".to_owned(),
            });
        }
        Ok(())
    }
}

/// Durable lifecycle of one Credential Manager ownership-key reference.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationSecretLifecycle {
    /// The committed reference remains required for execute/reconcile/rollback.
    Active,
    /// Deletion intent was committed before the Credential Manager delete.
    DeleteIntentCommitted,
    /// Authoritative readback proved the Credential Manager target absent.
    Deleted,
}

/// Durable OS create classification. Only `Created` can authorize ownership.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationCreateDisposition {
    /// No root create result has been durably recorded.
    NotAttempted,
    /// The exact OS create call reported a newly-created directory.
    Created,
    /// The exact OS create call reported an existing path.
    AlreadyExists,
}

/// Provider scope for one durable installer ownership-key reference.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationSecretScope {
    /// Windows Credential Manager under one exact current-user SID.
    WindowsCredentialManagerCurrentUser,
}

/// Non-secret durable reference issued before Credential Manager mutation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationSecretReference {
    /// Unpredictable provider target.
    pub target: PlatformHandle,
    /// Exact process-token SID that owns the provider scope.
    pub expected_principal_sid: PlatformHandle,
    /// Provider scope; ciphertext alone is never authorization.
    pub scope: InstallationSecretScope,
}

impl InstallationSecretReference {
    fn validate(&self) -> Result<(), InstallationError> {
        handle(
            &self.target,
            "effect_progress.ownership_secret.reference.target",
        )?;
        handle(
            &self.expected_principal_sid,
            "effect_progress.ownership_secret.reference.expected_principal_sid",
        )?;
        let target_token = self
            .target
            .as_str()
            .strip_prefix("eliot/installer-root/v1/");
        if target_token.is_none_or(|token| {
            token.len() != 32
                || !token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) || !self.expected_principal_sid.as_str().starts_with("S-")
        {
            return Err(InstallationError::InvalidField {
                field: "effect_progress.ownership_secret.reference".to_owned(),
                reason: "invalid Credential Manager target or principal SID".to_owned(),
            });
        }
        Ok(())
    }
}

/// Durable reference to an ownership key held only by Credential Manager.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationOwnershipSecret {
    /// Current-user Credential Manager target and exact expected owner SID.
    pub reference: InstallationSecretReference,
    /// Root create disposition durably captured after the OS call.
    pub create_disposition: InstallationCreateDisposition,
    /// Intent-before-delete lifecycle.
    pub lifecycle: InstallationSecretLifecycle,
}

impl InstallationOwnershipSecret {
    fn validate(&self) -> Result<(), InstallationError> {
        self.reference.validate()
    }
}

/// Durable progress for exactly one immutable installer effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum InstallationEffectProgressState {
    /// No effect intent has been committed.
    Pending,
    /// The exact intent was durably committed before the platform call.
    IntentCommitted {
        /// Non-zero execution attempt.
        attempt: u32,
        /// Digest of the exact request authorized for this attempt.
        intent_digest: PlatformHandle,
    },
    /// Authoritative readback proved the exact postcondition.
    Applied {
        /// Whether this transaction created or merely adopted the object.
        disposition: InstallationEffectDisposition,
        /// Exact provider object identity observed after the effect.
        external_identity: PlatformHandle,
        /// Evidence proving the authoritative postcondition.
        evidence: Vec<PlatformHandle>,
        /// Digest of the authoritative postcondition.
        postcondition_digest: PlatformHandle,
    },
    /// Authoritative classification was impossible or mismatched.
    Unknown {
        /// Stable evidence/reference requiring recovery.
        pending_ref: PlatformHandle,
    },
}

/// One-to-one durable progress entry bound to an installer effect identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationEffectProgress {
    /// Immutable effect identity from the installer plan.
    pub effect_id: PlatformHandle,
    /// Typed OS precondition admitted by the coordinator before intent commit.
    pub admitted_precondition: Option<InstallationEffectPrecondition>,
    /// Credential Manager reference retained across restart and recovery.
    pub ownership_secret: Option<InstallationOwnershipSecret>,
    /// Unpredictable public nonce retained for one SCM registration effect.
    #[serde(default)]
    pub registration_nonce: Option<PlatformHandle>,
    /// `LocalService` Store credential lifecycle, present only for its effect.
    pub store_credential: Option<StoreCredentialProgress>,
    /// Current durable effect state.
    pub state: InstallationEffectProgressState,
}

/// Durable installation/update transaction and its recovery projection.
///
/// Mutable durability state is intentionally read-only outside this crate:
///
/// ```compile_fail
/// use eliot_installation::{InstallationStage, InstallationTransaction};
///
/// fn forge_stage(transaction: &mut InstallationTransaction) {
///     transaction.stage = InstallationStage::Completed;
/// }
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationTransaction {
    /// Required breaking discriminator for this transaction projection only.
    pub transaction_wire_version: ContractVersion,
    /// Stable transaction identity.
    pub transaction_id: PlatformHandle,
    /// Installation lineage at transaction creation.
    pub installation_epoch: InstallationEpoch,
    /// Selected path/supervision profile.
    pub profile: InstallationProfile,
    /// Governing request identity.
    pub request: ManagedEnvironmentChangeRequest,
    /// Previously active generation, if one exists.
    pub current_active_manifest: Option<CandidateManifest>,
    /// Immutable candidate generation.
    pub candidate_manifest: CandidateManifest,
    /// Isolated staging root.
    pub staging_root: PlatformHandle,
    /// Planned OS/file/plugin/service changes.
    pub planned_changes: Vec<PlannedChange>,
    /// Typed root/ACL/SCM effects bound one-to-one to `planned_changes`.
    pub installer_effects: Vec<InstallerEffectPlan>,
    /// Minimum caller-available bytes required on the Store data volume.
    pub minimum_store_available_bytes: u64,
    /// Digest binding the sole transaction identity to its immutable installer plan.
    pub installer_plan_digest: PlatformHandle,
    /// One-to-one ordered durable progress for `installer_effects`.
    effect_progress: Vec<InstallationEffectProgress>,
    /// Precondition observations captured before staging.
    pub precondition_evidence: Vec<PlatformHandle>,
    /// Current durable stage.
    stage: InstallationStage,
    /// Evidence references for completed stages.
    pub completed_stage_refs: Vec<PlatformHandle>,
    /// External objects changed but not yet acknowledged.
    pub pending_external_changes: Vec<PlatformHandle>,
    /// Rollback or forward-repair plan.
    pub rollback_plan: PlatformHandle,
    /// Last-known-good manifest/generation reference.
    pub last_known_good: Option<PlatformHandle>,
    /// No-return boundary evidence, when activation crossed it.
    pub no_return_boundary: Option<PlatformHandle>,
    /// Observed postconditions.
    pub observed_postconditions: Vec<PlatformHandle>,
    /// Operator recovery command/reference.
    pub recovery_command: PlatformHandle,
    /// Monotonic state revision.
    revision: u64,
}

impl InstallationTransaction {
    /// Creates a validated immutable plan at `PLANNED`.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "constructor validates the complete immutable installation transaction boundary"
    )]
    pub fn new(
        transaction_id: PlatformHandle,
        installation_epoch: InstallationEpoch,
        profile: InstallationProfile,
        request: ManagedEnvironmentChangeRequest,
        current_active_manifest: Option<CandidateManifest>,
        candidate_manifest: CandidateManifest,
        staging_root: PlatformHandle,
        planned_changes: Vec<PlannedChange>,
        installer_effects: Vec<InstallerEffectPlan>,
        minimum_store_available_bytes: u64,
        precondition_evidence: Vec<PlatformHandle>,
        recovery_command: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        handle(&transaction_id, "transaction_id")?;
        installation_epoch.validate()?;
        request.validate()?;
        candidate_manifest.validate()?;
        if candidate_manifest.runtime_launch.profile != profile {
            return Err(InstallationError::ProfileViolation(
                "transaction profile must equal the candidate runtime launch profile".to_owned(),
            ));
        }
        if candidate_manifest.runtime_launch.installation_epoch != installation_epoch {
            return Err(InstallationError::InvalidField {
                field: "candidate_manifest.runtime_launch.installation_epoch".to_owned(),
                reason: "must exactly equal the transaction installation epoch".to_owned(),
            });
        }
        if let Some(manifest) = &current_active_manifest {
            manifest.validate()?;
        }
        handle(&staging_root, "staging_root")?;
        handle(&recovery_command, "recovery_command")?;
        handles(&precondition_evidence, "precondition_evidence", true)?;
        let mut change_ids = BTreeSet::new();
        for change in &planned_changes {
            change.validate()?;
            if !change_ids.insert(change.change_id.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "planned change".to_owned(),
                    identity: change.change_id.as_str().to_owned(),
                });
            }
        }
        if planned_changes.is_empty() {
            return Err(InstallationError::InvalidField {
                field: "planned_changes".to_owned(),
                reason: "must contain an explicit effect plan".to_owned(),
            });
        }
        if minimum_store_available_bytes == 0 {
            return Err(InstallationError::InvalidField {
                field: "minimum_store_available_bytes".to_owned(),
                reason: "must be a non-zero explicit policy value".to_owned(),
            });
        }
        validate_installer_effects(
            profile,
            &candidate_manifest.runtime_launch.runtime_state_roots,
            &candidate_manifest.store_credential_target,
            &planned_changes,
            &installer_effects,
        )?;
        if profile.is_disposable() && staging_root.as_str().contains("..") {
            return Err(InstallationError::ProfileViolation(
                "portable staging root must remain repository-local".to_owned(),
            ));
        }
        let rollback_plan = request.rollback_plan.clone();
        let installer_plan_digest =
            PlatformHandle::new(sha256_hex(&Self::installer_plan_unsigned_bytes(
                &transaction_id,
                &candidate_manifest.runtime_launch.runtime_state_roots,
                minimum_store_available_bytes,
                &planned_changes,
                &installer_effects,
            )?))
            .map_err(|error| InstallationError::InvalidField {
                field: "installer_plan_digest".to_owned(),
                reason: error.to_string(),
            })?;
        let effect_progress = installer_effects
            .iter()
            .map(|effect| InstallationEffectProgress {
                effect_id: effect.effect_id().clone(),
                admitted_precondition: None,
                ownership_secret: None,
                registration_nonce: None,
                store_credential: None,
                state: InstallationEffectProgressState::Pending,
            })
            .collect();
        Ok(Self {
            transaction_wire_version: INSTALLATION_TRANSACTION_WIRE_VERSION,
            transaction_id,
            installation_epoch,
            profile,
            request,
            current_active_manifest,
            candidate_manifest,
            staging_root,
            planned_changes,
            installer_effects,
            minimum_store_available_bytes,
            installer_plan_digest,
            effect_progress,
            precondition_evidence,
            stage: InstallationStage::Planned,
            completed_stage_refs: Vec::new(),
            pending_external_changes: Vec::new(),
            rollback_plan,
            last_known_good: None,
            no_return_boundary: None,
            observed_postconditions: Vec::new(),
            recovery_command,
            revision: 1,
        })
    }

    /// Returns the current durable stage without exposing a mutation seam.
    #[must_use]
    pub const fn stage(&self) -> InstallationStage {
        self.stage
    }

    /// Returns the ordered effect progress as a read-only projection.
    #[must_use]
    pub fn effect_progress(&self) -> &[InstallationEffectProgress] {
        &self.effect_progress
    }

    /// Returns the monotonic durable revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    fn installer_plan_unsigned_bytes(
        transaction_id: &PlatformHandle,
        runtime_state_roots: &RuntimeStateRoots,
        minimum_store_available_bytes: u64,
        planned_changes: &[PlannedChange],
        installer_effects: &[InstallerEffectPlan],
    ) -> Result<Vec<u8>, InstallationError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            transaction_id: &'a PlatformHandle,
            runtime_state_roots: &'a RuntimeStateRoots,
            minimum_store_available_bytes: u64,
            planned_changes: &'a [PlannedChange],
            installer_effects: &'a [InstallerEffectPlan],
        }
        serde_json::to_vec(&Unsigned {
            transaction_id,
            runtime_state_roots,
            minimum_store_available_bytes,
            planned_changes,
            installer_effects,
        })
        .map_err(|error| InstallationError::InvalidField {
            field: "installer_plan".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates the complete transaction projection.
    #[allow(
        clippy::too_many_lines,
        reason = "the complete transaction invariant is intentionally audited in one boundary"
    )]
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.transaction_wire_version != INSTALLATION_TRANSACTION_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "installation transaction wire {} cannot be read as {}",
                    self.transaction_wire_version, INSTALLATION_TRANSACTION_WIRE_VERSION
                ),
            });
        }
        handle(&self.transaction_id, "transaction_id")?;
        self.installation_epoch.validate()?;
        self.request.validate()?;
        self.candidate_manifest.validate()?;
        if self.profile != self.candidate_manifest.runtime_launch.profile {
            return Err(InstallationError::ProfileViolation(
                "transaction profile must equal the candidate runtime launch profile".to_owned(),
            ));
        }
        if self.candidate_manifest.runtime_launch.installation_epoch != self.installation_epoch {
            return Err(InstallationError::InvalidField {
                field: "candidate_manifest.runtime_launch.installation_epoch".to_owned(),
                reason: "must exactly equal the transaction installation epoch".to_owned(),
            });
        }
        if let Some(manifest) = &self.current_active_manifest {
            manifest.validate()?;
        }
        handle(&self.staging_root, "staging_root")?;
        handle(&self.rollback_plan, "rollback_plan")?;
        handle(&self.recovery_command, "recovery_command")?;
        if self.minimum_store_available_bytes == 0 {
            return Err(InstallationError::InvalidField {
                field: "minimum_store_available_bytes".to_owned(),
                reason: "must be a non-zero explicit policy value".to_owned(),
            });
        }
        for change in &self.planned_changes {
            change.validate()?;
        }
        validate_installer_effects(
            self.profile,
            &self.candidate_manifest.runtime_launch.runtime_state_roots,
            &self.candidate_manifest.store_credential_target,
            &self.planned_changes,
            &self.installer_effects,
        )?;
        sha256_handle(&self.installer_plan_digest, "installer_plan_digest")?;
        if sha256_hex(&Self::installer_plan_unsigned_bytes(
            &self.transaction_id,
            &self.candidate_manifest.runtime_launch.runtime_state_roots,
            self.minimum_store_available_bytes,
            &self.planned_changes,
            &self.installer_effects,
        )?) != self.installer_plan_digest.as_str()
        {
            return Err(InstallationError::InvalidField {
                field: "installer_plan_digest".to_owned(),
                reason: "installer plan digest mismatch".to_owned(),
            });
        }
        self.validate_effect_progress()?;
        if self.revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        handles(&self.precondition_evidence, "precondition_evidence", true)?;
        handles(&self.completed_stage_refs, "completed_stage_refs", false)?;
        handles(
            &self.pending_external_changes,
            "pending_external_changes",
            false,
        )?;
        handles(
            &self.observed_postconditions,
            "observed_postconditions",
            false,
        )?;
        if matches!(
            self.stage,
            InstallationStage::ActiveVerified | InstallationStage::Completed
        ) && self.observed_postconditions.is_empty()
        {
            return Err(InstallationError::IncompleteObservation(
                "active/completed transaction requires postcondition evidence".to_owned(),
            ));
        }
        if matches!(self.stage, InstallationStage::RollbackRequired)
            && self.pending_external_changes.is_empty()
        {
            return Err(InstallationError::IncompleteObservation(
                "rollback-required transaction must name pending external changes".to_owned(),
            ));
        }
        if matches!(
            self.stage,
            InstallationStage::RolledBack | InstallationStage::Quarantined
        ) && self.pending_external_changes.is_empty()
            && self.completed_stage_refs.is_empty()
        {
            return Err(InstallationError::IncompleteObservation(
                "terminal recovery state requires disposition evidence".to_owned(),
            ));
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one audit boundary validates all coupled durable effect-progress invariants"
    )]
    fn validate_effect_progress(&self) -> Result<(), InstallationError> {
        if self.effect_progress.len() != self.installer_effects.len() {
            return Err(InstallationError::IdentityConflict);
        }
        let mut unsettled_seen = false;
        for (effect, progress) in self.installer_effects.iter().zip(&self.effect_progress) {
            if progress.effect_id != *effect.effect_id() {
                return Err(InstallationError::IdentityConflict);
            }
            if let Some(precondition) = &progress.admitted_precondition {
                precondition.validate()?;
                let snapshot_matches = match effect {
                    InstallerEffectPlan::ProvisionStoreCredential { .. } => {
                        precondition.credential_snapshot.is_some()
                            && precondition.os_snapshot.is_none()
                    }
                    _ => {
                        precondition.os_snapshot.is_some()
                            && precondition.credential_snapshot.is_none()
                    }
                };
                if !snapshot_matches {
                    return Err(InstallationError::InvalidField {
                        field: "effect_progress.admitted_precondition".to_owned(),
                        reason: "must contain the typed snapshot for its exact effect".to_owned(),
                    });
                }
            }
            if let Some(ownership) = &progress.ownership_secret {
                ownership.validate()?;
                match ownership.lifecycle {
                    InstallationSecretLifecycle::Active
                        if !matches!(
                            self.stage,
                            InstallationStage::Completed | InstallationStage::RolledBack
                        ) => {}
                    InstallationSecretLifecycle::DeleteIntentCommitted
                        if self.stage == InstallationStage::RollbackRequired => {}
                    InstallationSecretLifecycle::Deleted
                        if matches!(
                            self.stage,
                            InstallationStage::RolledBack | InstallationStage::Completed
                        ) && self
                            .completed_stage_refs
                            .contains(&ownership_secret_absence_evidence(&ownership.reference)) => {
                    }
                    _ => {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.ownership_secret.lifecycle".to_owned(),
                            reason: "secret lifecycle does not match transaction recovery phase"
                                .to_owned(),
                        });
                    }
                }
            }
            if let Some(nonce) = &progress.registration_nonce {
                if !matches!(effect, InstallerEffectPlan::RegisterService { .. }) {
                    return Err(InstallationError::IdentityConflict);
                }
                sha256_handle(nonce, "effect_progress.registration_nonce")?;
            }
            if matches!(
                &progress.state,
                InstallationEffectProgressState::IntentCommitted { .. }
                    | InstallationEffectProgressState::Applied { .. }
            ) && matches!(effect, InstallerEffectPlan::RegisterService { .. })
                && progress.registration_nonce.is_none()
            {
                return Err(InstallationError::InvalidField {
                    field: "effect_progress.registration_nonce".to_owned(),
                    reason: "service intent requires durable nonce".to_owned(),
                });
            }
            if let Some(credential) = &progress.store_credential {
                credential.validate()?;
                let InstallerEffectPlan::ProvisionStoreCredential { provision, .. } = effect else {
                    return Err(InstallationError::InvalidField {
                        field: "effect_progress.store_credential".to_owned(),
                        reason: "credential progress belongs only to its provision effect"
                            .to_owned(),
                    });
                };
                match credential.lifecycle {
                    StoreCredentialLifecycle::Active
                        if !matches!(
                            self.stage,
                            InstallationStage::Completed | InstallationStage::RolledBack
                        ) => {}
                    StoreCredentialLifecycle::DeleteIntentCommitted
                    | StoreCredentialLifecycle::DeleteExecuted
                        if self.stage == InstallationStage::RollbackRequired => {}
                    StoreCredentialLifecycle::Deleted
                        if matches!(
                            self.stage,
                            InstallationStage::RolledBack | InstallationStage::Completed
                        ) => {}
                    _ => {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.store_credential.lifecycle".to_owned(),
                            reason: "credential lifecycle does not match transaction phase"
                                .to_owned(),
                        });
                    }
                }
                if let Some(receipt) = &credential.receipt
                    && (receipt.transaction_id != self.transaction_id
                        || receipt.effect_id != progress.effect_id
                        || receipt.generation != provision.generation
                        || receipt.config_digest != provision.config_digest
                        || receipt.target != provision.target
                        || receipt.provider != provision.provider
                        || receipt.scope != provision.scope
                        || receipt.principal_sid != provision.expected_principal_sid)
                {
                    return Err(InstallationError::IdentityConflict);
                }
            } else if matches!(effect, InstallerEffectPlan::ProvisionStoreCredential { .. })
                && !matches!(progress.state, InstallationEffectProgressState::Pending)
            {
                return Err(InstallationError::InvalidField {
                    field: "effect_progress.store_credential".to_owned(),
                    reason: "committed credential effect requires typed durable progress"
                        .to_owned(),
                });
            }
            match (
                &progress.state,
                effect,
                &progress.admitted_precondition,
                &progress.ownership_secret,
            ) {
                (
                    InstallationEffectProgressState::Pending
                    | InstallationEffectProgressState::Unknown { .. },
                    _,
                    None,
                    None,
                )
                | (
                    InstallationEffectProgressState::IntentCommitted { .. }
                    | InstallationEffectProgressState::Unknown { .. }
                    | InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        ..
                    },
                    InstallerEffectPlan::CreateRoot { .. },
                    Some(_),
                    Some(_),
                )
                | (
                    InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::PreexistingMatching,
                        ..
                    },
                    InstallerEffectPlan::CreateRoot { .. },
                    None,
                    None,
                )
                | (
                    InstallationEffectProgressState::IntentCommitted { .. }
                    | InstallationEffectProgressState::Applied { .. }
                    | InstallationEffectProgressState::Unknown { .. },
                    InstallerEffectPlan::ApplyAcl { .. }
                    | InstallerEffectPlan::RegisterService { .. },
                    _,
                    None,
                ) => {}
                (
                    InstallationEffectProgressState::IntentCommitted { .. }
                    | InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        ..
                    }
                    | InstallationEffectProgressState::Unknown { .. },
                    InstallerEffectPlan::ProvisionStoreCredential { .. },
                    Some(_),
                    Some(_),
                ) if progress.store_credential.is_some() => {}
                _ => {
                    return Err(InstallationError::InvalidField {
                        field: "effect_progress.capability".to_owned(),
                        reason: "precondition and ownership must match the effect phase".to_owned(),
                    });
                }
            }
            match &progress.state {
                InstallationEffectProgressState::Applied {
                    disposition,
                    external_identity,
                    evidence,
                    postcondition_digest,
                    ..
                } if !unsettled_seen => {
                    if *disposition == InstallationEffectDisposition::CreatedByTransaction
                        && !matches!(effect, InstallerEffectPlan::RegisterService { .. })
                        && progress.ownership_secret.as_ref().is_none_or(|ownership| {
                            ownership.create_disposition != InstallationCreateDisposition::Created
                        })
                    {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.disposition".to_owned(),
                            reason: "transaction ownership requires a durable Created result"
                                .to_owned(),
                        });
                    }
                    if progress.ownership_secret.as_ref().is_some_and(|ownership| {
                        ownership.create_disposition == InstallationCreateDisposition::AlreadyExists
                    }) {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.ownership_secret.create_disposition".to_owned(),
                            reason: "AlreadyExists can never enter Applied ownership".to_owned(),
                        });
                    }
                    handle(external_identity, "effect_progress.external_identity")?;
                    handles(evidence, "effect_progress.evidence", true)?;
                    sha256_handle(postcondition_digest, "effect_progress.postcondition_digest")?;
                    if matches!(effect, InstallerEffectPlan::ProvisionStoreCredential { .. })
                        && progress
                            .store_credential
                            .as_ref()
                            .is_none_or(|credential| credential.receipt.is_none())
                    {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.store_credential.receipt".to_owned(),
                            reason: "applied credential ownership requires exact Host receipt"
                                .to_owned(),
                        });
                    }
                }
                InstallationEffectProgressState::Pending => unsettled_seen = true,
                InstallationEffectProgressState::IntentCommitted {
                    attempt,
                    intent_digest,
                } if !unsettled_seen => {
                    if *attempt == 0 {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.attempt".to_owned(),
                            reason: "must be non-zero".to_owned(),
                        });
                    }
                    sha256_handle(intent_digest, "effect_progress.intent_digest")?;
                    unsettled_seen = true;
                }
                InstallationEffectProgressState::Unknown { pending_ref } if !unsettled_seen => {
                    handle(pending_ref, "effect_progress.pending_ref")?;
                    unsettled_seen = true;
                }
                InstallationEffectProgressState::Applied { .. }
                | InstallationEffectProgressState::IntentCommitted { .. }
                | InstallationEffectProgressState::Unknown { .. } => {
                    return Err(InstallationError::InvalidField {
                        field: "effect_progress".to_owned(),
                        reason: "progress must be an applied prefix followed by at most one active state and a pending suffix".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn is_constructor_planned(&self) -> bool {
        self.transaction_wire_version == INSTALLATION_TRANSACTION_WIRE_VERSION
            && self.stage == InstallationStage::Planned
            && self.revision == 1
            && self.completed_stage_refs.is_empty()
            && self.pending_external_changes.is_empty()
            && self.observed_postconditions.is_empty()
            && self.last_known_good.is_none()
            && self.no_return_boundary.is_none()
            && self
                .effect_progress
                .iter()
                .all(|progress| matches!(progress.state, InstallationEffectProgressState::Pending))
    }

    /// Records the real Store-volume observation through this transaction's
    /// existing fail-closed state machine.
    pub fn record_store_free_space(
        &mut self,
        observation: StoreFreeSpaceObservation,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        self.validate()?;
        match observation {
            StoreFreeSpaceObservation::Known {
                available_bytes,
                evidence_refs,
            } => {
                handles(&evidence_refs, "free_space.evidence_refs", true)?;
                if available_bytes < self.minimum_store_available_bytes {
                    return Ok(InstallationStepOutcome::Rejected);
                }
                self.precondition_evidence.extend(evidence_refs.clone());
                self.revision = self.revision.checked_add(1).ok_or_else(|| {
                    InstallationError::InvalidField {
                        field: "revision".to_owned(),
                        reason: "overflow".to_owned(),
                    }
                })?;
                self.validate()?;
                Ok(InstallationStepOutcome::Applied {
                    stage: self.stage,
                    evidence_refs,
                })
            }
            StoreFreeSpaceObservation::Unknown { evidence_refs } => {
                self.mark_unknown(evidence_refs.clone())?;
                Ok(InstallationStepOutcome::RollbackRequired {
                    pending_refs: evidence_refs,
                })
            }
        }
    }

    /// Advances one stage using observed evidence and increments the revision.
    pub fn advance(
        &mut self,
        next: InstallationStage,
        evidence: Vec<PlatformHandle>,
    ) -> Result<(), InstallationError> {
        if !self.stage.can_advance(next) {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: next,
            });
        }
        handles(&evidence, "stage_evidence", true)?;
        self.completed_stage_refs.extend(evidence);
        if next == InstallationStage::ActiveVerified {
            self.observed_postconditions
                .extend(self.completed_stage_refs.clone());
        }
        self.stage = next;
        self.revision =
            self.revision
                .checked_add(1)
                .ok_or_else(|| InstallationError::InvalidField {
                    field: "revision".to_owned(),
                    reason: "overflow".to_owned(),
                })?;
        self.validate()
    }

    /// Records an external effect whose outcome cannot yet be classified.
    pub fn mark_unknown(&mut self, pending: Vec<PlatformHandle>) -> Result<(), InstallationError> {
        handles(&pending, "pending_external_changes", true)?;
        if !self.stage.can_advance(InstallationStage::RollbackRequired) {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: InstallationStage::RollbackRequired,
            });
        }
        self.pending_external_changes = pending;
        self.stage = InstallationStage::RollbackRequired;
        self.revision =
            self.revision
                .checked_add(1)
                .ok_or_else(|| InstallationError::InvalidField {
                    field: "revision".to_owned(),
                    reason: "overflow".to_owned(),
                })?;
        self.validate()
    }

    /// Records a no-return activation boundary after explicit observation.
    pub fn record_no_return_boundary(
        &mut self,
        reference: PlatformHandle,
    ) -> Result<(), InstallationError> {
        handle(&reference, "no_return_boundary")?;
        if !matches!(
            self.stage,
            InstallationStage::Activating | InstallationStage::ActiveVerified
        ) {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: InstallationStage::ActiveVerified,
            });
        }
        self.no_return_boundary = Some(reference);
        self.validate()
    }
}

/// Decodes the canonical transaction JSON and classifies pre-v7 records as an
/// explicit migration requirement rather than synthesizing missing progress.
pub fn decode_installation_transaction_json(
    bytes: &[u8],
) -> Result<InstallationTransaction, InstallationError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| InstallationError::CorruptRegistry {
            reason: error.to_string(),
        })?;
    let version = value.get("transaction_wire_version").ok_or_else(|| {
        InstallationError::MigrationRequired {
            reason: "installation transaction predates the required v7 discriminator".to_owned(),
        }
    })?;
    let version: ContractVersion = serde_json::from_value(version.clone()).map_err(|_| {
        InstallationError::MigrationRequired {
            reason: "installation transaction has an unsupported wire discriminator".to_owned(),
        }
    })?;
    if version != INSTALLATION_TRANSACTION_WIRE_VERSION {
        return Err(InstallationError::MigrationRequired {
            reason: format!(
                "installation transaction wire {version} requires explicit migration to {INSTALLATION_TRANSACTION_WIRE_VERSION}"
            ),
        });
    }
    let transaction: InstallationTransaction =
        serde_json::from_value(value).map_err(|error| InstallationError::CorruptRegistry {
            reason: error.to_string(),
        })?;
    transaction.validate()?;
    Ok(transaction)
}

fn platform_error(error: &PortError) -> InstallationError {
    InstallationError::Platform(error.to_string())
}

/// Whether an exact effect request applies or rolls back one plan entry.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationEffectAction {
    /// Apply the exact immutable effect plan.
    Apply,
    /// Remove only the exact identity previously created by this transaction.
    Rollback,
}

/// Exact precondition bound into an effect intent.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationEffectPrecondition {
    /// Evidence references captured for the matching planned change.
    pub evidence_refs: Vec<PlatformHandle>,
    /// Typed OS snapshot admitted after an authoritative absence observation.
    pub os_snapshot: Option<InstallationRootAbsentSnapshot>,
    /// Typed `LocalService` Host/marker/credential absence observation.
    pub credential_snapshot: Option<StoreCredentialAbsentSnapshot>,
    /// Digest binding the planned references and typed OS snapshot in order.
    pub digest: PlatformHandle,
}

impl InstallationEffectPrecondition {
    fn from_change(change: &PlannedChange) -> Result<Self, InstallationError> {
        Self::new(change.precondition_refs.clone(), None, None)
    }

    fn with_os_snapshot(
        &self,
        snapshot: InstallationRootAbsentSnapshot,
    ) -> Result<Self, InstallationError> {
        Self::new(self.evidence_refs.clone(), Some(snapshot), None)
    }

    fn with_credential_snapshot(
        &self,
        snapshot: StoreCredentialAbsentSnapshot,
    ) -> Result<Self, InstallationError> {
        Self::new(self.evidence_refs.clone(), None, Some(snapshot))
    }

    fn new(
        evidence_refs: Vec<PlatformHandle>,
        os_snapshot: Option<InstallationRootAbsentSnapshot>,
        credential_snapshot: Option<StoreCredentialAbsentSnapshot>,
    ) -> Result<Self, InstallationError> {
        #[derive(Serialize)]
        struct DigestInput<'a> {
            evidence_refs: &'a [PlatformHandle],
            os_snapshot: &'a Option<InstallationRootAbsentSnapshot>,
            credential_snapshot: &'a Option<StoreCredentialAbsentSnapshot>,
        }
        let digest = PlatformHandle::new(sha256_hex(
            &serde_json::to_vec(&DigestInput {
                evidence_refs: &evidence_refs,
                os_snapshot: &os_snapshot,
                credential_snapshot: &credential_snapshot,
            })
            .map_err(|error| InstallationError::InvalidField {
                field: "effect.precondition".to_owned(),
                reason: error.to_string(),
            })?,
        ))
        .map_err(|error| platform_error(&error))?;
        let value = Self {
            evidence_refs,
            os_snapshot,
            credential_snapshot,
            digest,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), InstallationError> {
        #[derive(Serialize)]
        struct DigestInput<'a> {
            evidence_refs: &'a [PlatformHandle],
            os_snapshot: &'a Option<InstallationRootAbsentSnapshot>,
            credential_snapshot: &'a Option<StoreCredentialAbsentSnapshot>,
        }

        handles(
            &self.evidence_refs,
            "effect.precondition.evidence_refs",
            true,
        )?;
        if let Some(snapshot) = &self.os_snapshot {
            snapshot.validate()?;
        }
        if let Some(snapshot) = &self.credential_snapshot {
            snapshot.validate()?;
        }
        if self.os_snapshot.is_some() && self.credential_snapshot.is_some() {
            return Err(InstallationError::InvalidField {
                field: "effect.precondition.snapshot".to_owned(),
                reason: "root and credential snapshots are mutually exclusive".to_owned(),
            });
        }
        sha256_handle(&self.digest, "effect.precondition.digest")?;
        let expected = sha256_hex(
            &serde_json::to_vec(&DigestInput {
                evidence_refs: &self.evidence_refs,
                os_snapshot: &self.os_snapshot,
                credential_snapshot: &self.credential_snapshot,
            })
            .map_err(|error| InstallationError::InvalidField {
                field: "effect.precondition".to_owned(),
                reason: error.to_string(),
            })?,
        );
        if expected != self.digest.as_str() {
            return Err(InstallationError::InvalidField {
                field: "effect.precondition.digest".to_owned(),
                reason: "precondition digest mismatch".to_owned(),
            });
        }
        Ok(())
    }
}

/// Request sent to the effect executor for exactly one immutable plan entry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationServiceBootstrap {
    /// Exact authority descriptor path consumed by Host and Watchdog.
    pub descriptor_path: PlatformHandle,
    /// SHA-256 digest of the descriptor bytes.
    pub descriptor_digest: PlatformHandle,
    /// Installation identity bound to the descriptor.
    pub installation_id: PlatformHandle,
    /// Authority generation bound to this candidate launch.
    pub plan_generation: u64,
}

impl InstallationServiceBootstrap {
    fn validate(&self) -> Result<(), InstallationError> {
        approved_path(&self.descriptor_path, "service_bootstrap.descriptor_path")?;
        sha256_handle(
            &self.descriptor_digest,
            "service_bootstrap.descriptor_digest",
        )?;
        handle(&self.installation_id, "service_bootstrap.installation_id")?;
        if self.plan_generation == 0 {
            return Err(InstallationError::InvalidField {
                field: "service_bootstrap.plan_generation".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        Ok(())
    }
}

/// Request sent to the effect executor for exactly one immutable plan entry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationEffectRequest {
    /// Transaction identity.
    pub transaction_id: PlatformHandle,
    /// Exact immutable effect plan.
    pub plan: InstallerEffectPlan,
    /// Installation profile selecting the exact root contour and DACL.
    pub profile: InstallationProfile,
    /// Exact profile installation root from the durable runtime-root descriptor.
    pub installation_root: PlatformHandle,
    /// Effect identity echoed outside the tagged plan for adapter routing.
    pub effect_id: PlatformHandle,
    /// Non-zero attempt durably committed before execution.
    pub attempt: u32,
    /// Digest of the complete immutable installer plan.
    pub plan_digest: PlatformHandle,
    /// Exact precondition admitted for this attempt.
    pub precondition: InstallationEffectPrecondition,
    /// Durable Credential Manager reference and create classification.
    pub ownership_secret: Option<InstallationOwnershipSecret>,
    /// Typed durable Store credential progress for its exact effect.
    pub store_credential: Option<StoreCredentialProgress>,
    /// Apply or exact-identity rollback.
    pub action: InstallationEffectAction,
    /// Required exact identity for rollback; absent for apply.
    pub expected_external_identity: Option<PlatformHandle>,
    /// Candidate launch authority used to render canonical SCM argv.
    #[serde(default)]
    pub service_bootstrap: Option<InstallationServiceBootstrap>,
    /// Public unpredictable nonce retained by the transaction and marker.
    #[serde(default)]
    pub registration_nonce: Option<PlatformHandle>,
}

impl InstallationEffectRequest {
    /// Validates an exact effect request before it crosses the adapter boundary.
    #[allow(
        clippy::too_many_lines,
        reason = "the request validator keeps all cross-effect identity and lifecycle invariants together"
    )]
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.transaction_id, "effect.transaction_id")?;
        self.plan.validate()?;
        validate_effect_profile(self.profile, &self.plan)?;
        approved_path(&self.installation_root, "effect.installation_root")?;
        handle(&self.effect_id, "effect.effect_id")?;
        if self.effect_id != *self.plan.effect_id() {
            return Err(InstallationError::IdentityConflict);
        }
        if self.attempt == 0 {
            return Err(InstallationError::InvalidField {
                field: "effect.attempt".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        sha256_handle(&self.plan_digest, "effect.plan_digest")?;
        self.precondition.validate()?;
        if let Some(bootstrap) = &self.service_bootstrap {
            bootstrap.validate()?;
        }
        if let Some(nonce) = &self.registration_nonce {
            sha256_handle(nonce, "effect.registration_nonce")?;
        }
        if let Some(ownership) = &self.ownership_secret {
            ownership.validate()?;
        }
        if let Some(credential) = &self.store_credential {
            credential.validate()?;
        }
        match (&self.plan, self.action, &self.ownership_secret) {
            (
                InstallerEffectPlan::CreateRoot { .. },
                InstallationEffectAction::Apply,
                Some(ownership),
            ) if self.precondition.os_snapshot.is_some()
                && ownership.lifecycle == InstallationSecretLifecycle::Active => {}
            (InstallerEffectPlan::CreateRoot { .. }, InstallationEffectAction::Apply, None)
                if self.precondition.os_snapshot.is_none() => {}
            (
                InstallerEffectPlan::CreateRoot { .. },
                InstallationEffectAction::Rollback,
                Some(ownership),
            ) if ownership.lifecycle != InstallationSecretLifecycle::Deleted => {}
            (InstallerEffectPlan::ApplyAcl { .. }, InstallationEffectAction::Apply, None)
            | (InstallerEffectPlan::RegisterService { .. }, _, None) => {
                if matches!(&self.plan, InstallerEffectPlan::RegisterService { .. })
                    && self.service_bootstrap.is_none()
                {
                    return Err(InstallationError::InvalidField {
                        field: "effect.service_bootstrap".to_owned(),
                        reason: "service effects require descriptor and nonce bindings".to_owned(),
                    });
                }
            }
            (
                InstallerEffectPlan::ProvisionStoreCredential { .. },
                InstallationEffectAction::Apply,
                None,
            ) if self.precondition.credential_snapshot.is_none()
                && self.store_credential.is_none() => {}
            (
                InstallerEffectPlan::ProvisionStoreCredential { .. },
                InstallationEffectAction::Apply | InstallationEffectAction::Rollback,
                Some(ownership),
            ) if ownership.lifecycle != InstallationSecretLifecycle::Deleted => {}
            _ => {
                return Err(InstallationError::InvalidField {
                    field: "effect.ownership_secret".to_owned(),
                    reason: "must match the root effect phase and lifecycle".to_owned(),
                });
            }
        }
        match (&self.plan, self.action, &self.store_credential) {
            (
                InstallerEffectPlan::ProvisionStoreCredential { .. },
                InstallationEffectAction::Apply,
                None,
            ) if self.ownership_secret.is_none()
                && self.precondition.credential_snapshot.is_none() => {}
            (
                InstallerEffectPlan::ProvisionStoreCredential { .. },
                InstallationEffectAction::Apply,
                Some(progress),
            ) if progress.lifecycle == StoreCredentialLifecycle::Active
                && self.ownership_secret.is_some()
                && self.precondition.credential_snapshot.is_some() => {}
            (
                InstallerEffectPlan::ProvisionStoreCredential { .. },
                InstallationEffectAction::Rollback,
                Some(progress),
            ) if progress.lifecycle != StoreCredentialLifecycle::Deleted
                && self.ownership_secret.is_some() => {}
            (InstallerEffectPlan::ProvisionStoreCredential { .. }, _, _) => {
                return Err(InstallationError::InvalidField {
                    field: "effect.store_credential".to_owned(),
                    reason: "credential progress must match the durable effect phase".to_owned(),
                });
            }
            (_, _, None) => {}
            _ => return Err(InstallationError::IdentityConflict),
        }
        match (&self.action, &self.expected_external_identity) {
            (InstallationEffectAction::Apply, None) => Ok(()),
            (InstallationEffectAction::Rollback, Some(identity)) => {
                handle(identity, "effect.expected_external_identity")
            }
            _ => Err(InstallationError::InvalidField {
                field: "effect.expected_external_identity".to_owned(),
                reason: "must be absent for apply and present for rollback".to_owned(),
            }),
        }
    }

    fn intent_digest(&self) -> Result<PlatformHandle, InstallationError> {
        let mut intent = self.clone();
        if let Some(ownership) = &mut intent.ownership_secret {
            // Create disposition is an observed result persisted after the OS
            // call; it cannot retroactively change the committed authorization.
            ownership.create_disposition = InstallationCreateDisposition::NotAttempted;
        }
        if let Some(credential) = &mut intent.store_credential {
            credential.receipt = None;
        }
        let bytes =
            serde_json::to_vec(&intent).map_err(|error| InstallationError::InvalidField {
                field: "effect.intent".to_owned(),
                reason: error.to_string(),
            })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| platform_error(&error))
    }
}

/// Authoritative readback for one exact effect request.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum InstallationEffectObservation {
    /// The exact external object is authoritatively absent.
    Absent {
        /// Independently observed typed OS precondition.
        observed_precondition: InstallationEffectPrecondition,
        /// Evidence proving absence.
        evidence: Vec<PlatformHandle>,
    },
    /// The exact requested postcondition is authoritatively present.
    Matching {
        /// Proven ownership of the observed object.
        disposition: InstallationEffectDisposition,
        /// Exact provider object identity.
        external_identity: PlatformHandle,
        /// Evidence proving the postcondition.
        evidence: Vec<PlatformHandle>,
        /// Digest of the authoritative postcondition.
        postcondition_digest: PlatformHandle,
        /// Typed credential receipt, only for the Store credential effect.
        credential_receipt: Option<CredentialAccessReceipt>,
    },
    /// Readback proved a conflicting object or precondition.
    Mismatch {
        /// Stable evidence/reference requiring recovery.
        pending_ref: PlatformHandle,
    },
}

impl InstallationEffectObservation {
    fn validate(&self) -> Result<(), InstallationError> {
        self.validate_with_service_absence(false)
    }

    fn validate_for_effect(&self, effect: &InstallerEffectPlan) -> Result<(), InstallationError> {
        self.validate_with_service_absence(matches!(
            effect,
            InstallerEffectPlan::RegisterService { .. }
        ))
    }

    fn validate_with_service_absence(
        &self,
        allow_service_absence: bool,
    ) -> Result<(), InstallationError> {
        match self {
            Self::Absent {
                observed_precondition,
                evidence,
            } => {
                observed_precondition.validate()?;
                if observed_precondition.os_snapshot.is_none()
                    && observed_precondition.credential_snapshot.is_none()
                    && !allow_service_absence
                {
                    return Err(InstallationError::InvalidField {
                        field: "observation.observed_precondition".to_owned(),
                        reason: "absence must contain an independently observed OS snapshot"
                            .to_owned(),
                    });
                }
                handles(evidence, "observation.evidence", true)
            }
            Self::Matching {
                external_identity,
                evidence,
                postcondition_digest,
                credential_receipt,
                ..
            } => {
                handle(external_identity, "observation.external_identity")?;
                handles(evidence, "observation.evidence", true)?;
                sha256_handle(postcondition_digest, "observation.postcondition_digest")?;
                if let Some(receipt) = credential_receipt {
                    receipt.validate()?;
                }
                Ok(())
            }
            Self::Mismatch { pending_ref } => handle(pending_ref, "observation.pending_ref"),
        }
    }
}

/// Acknowledgement from the mutating call; success is not a postcondition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationEffectExecution {
    /// Non-authoritative evidence emitted by the mutating adapter call.
    pub evidence: Vec<PlatformHandle>,
    /// Exact create result that must be persisted before reconcile can own it.
    pub create_disposition: Option<InstallationCreateDisposition>,
    /// Typed `LocalService` receipt returned only by credential provision/reconcile.
    pub credential_receipt: Option<CredentialAccessReceipt>,
}

/// Object-safe adapter seam for bounded installation effects.
pub trait InstallationEffectPort: Send {
    /// Issues an unpredictable public nonce before an SCM registration intent
    /// is committed. The call must not mutate SCM or the protected state root.
    fn fresh_service_registration_nonce(
        &mut self,
        _request: &InstallationEffectRequest,
    ) -> PortOutcome<PlatformHandle> {
        PortOutcome::Unknown(UnknownReason::Unsupported)
    }

    /// Issues a non-secret unpredictable Credential Manager target.
    ///
    /// This call must not create a credential or mutate the requested root.
    fn fresh_ownership_secret_reference(
        &mut self,
        _request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationSecretReference> {
        PortOutcome::Unknown(UnknownReason::Unsupported)
    }

    /// Creates or reopens the installer-held ownership key only after its
    /// exact reference and effect intent were durably committed.
    fn provision_ownership_secret(
        &mut self,
        _request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationCreateDisposition> {
        PortOutcome::Unknown(UnknownReason::Unsupported)
    }

    /// Executes the exact committed intent. This result never proves success.
    fn execute(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectExecution>;

    /// Executes one service effect after the coordinator committed intent.
    fn execute_service(
        &mut self,
        _request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectExecution> {
        PortOutcome::Unknown(UnknownReason::Unsupported)
    }

    /// Performs authoritative readback before a first execution.
    fn inspect(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectObservation>;

    /// Reconciles a committed intent after execution or process restart.
    fn reconcile(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectObservation>;

    /// Deletes one credential only after the coordinator committed delete intent.
    fn delete_ownership_secret(&mut self, _request: &InstallationEffectRequest) -> PortOutcome<()> {
        PortOutcome::Unknown(UnknownReason::Unsupported)
    }

    /// Authoritatively observes whether the committed credential target is absent.
    fn ownership_secret_absent(
        &mut self,
        _request: &InstallationEffectRequest,
    ) -> PortOutcome<bool> {
        PortOutcome::Unknown(UnknownReason::Unsupported)
    }
}

/// Sealed production Windows adapter. Only [`WindowsInstallationCoordinator`]
/// can construct or mutably use this capability.
#[derive(Debug)]
struct WindowsInstallationEffectPort {
    primitive: WindowsInstallerRootPrimitive,
    secrets: WindowsInstallerSecretProvider,
    store_target_generator: WindowsStoreCredentialTargetGenerator,
}

impl WindowsInstallationEffectPort {
    const fn new() -> Self {
        Self {
            primitive: WindowsInstallerRootPrimitive::new(),
            secrets: WindowsInstallerSecretProvider::new(),
            store_target_generator: WindowsStoreCredentialTargetGenerator::new(),
        }
    }

    fn fresh_store_credential_target(
        &self,
    ) -> Result<PlatformHandle, eliot_platform_windows::WindowsAdapterError> {
        self.store_target_generator.fresh_target()
    }

    fn service_context(
        request: &InstallationEffectRequest,
    ) -> Result<
        (
            WindowsPlatform,
            ServiceRegistrationRequest,
            InstallerRootPrimitiveSpec,
        ),
        PortError,
    > {
        let (role, service_name, executable_path) = match &request.plan {
            InstallerEffectPlan::RegisterService {
                role,
                service_name,
                executable_path,
                ..
            } => (*role, service_name.as_str(), executable_path.as_str()),
            _ => return Err(PortError::InvalidRequestMetadata),
        };
        let expected_name = match role {
            InstallerServiceRole::Host => ELIOT_HOST_SERVICE_NAME,
            InstallerServiceRole::Watchdog => ELIOT_WATCHDOG_SERVICE_NAME,
        };
        if service_name != expected_name {
            return Err(PortError::InvalidRequestMetadata);
        }
        let bootstrap = request
            .service_bootstrap
            .as_ref()
            .ok_or(PortError::InvalidRequestMetadata)?;
        let nonce = request
            .registration_nonce
            .as_ref()
            .ok_or(PortError::InvalidRequestMetadata)?;
        let bootstrap = ServiceBootstrapArguments::new(
            Path::new(bootstrap.descriptor_path.as_str()).to_path_buf(),
            bootstrap.descriptor_digest.as_str(),
            bootstrap.installation_id.as_str(),
            bootstrap.plan_generation,
            Vec::<String>::new(),
        )
        .and_then(|value| value.with_registration_nonce(nonce.as_str()))
        .map_err(|_| PortError::InvalidRequestMetadata)?;
        let mut registration = ServiceRegistrationRequest::with_bootstrap(
            service_name,
            match role {
                InstallerServiceRole::Host => {
                    eliot_platform_windows::ELIOT_HOST_SERVICE_DISPLAY_NAME
                }
                InstallerServiceRole::Watchdog => {
                    eliot_platform_windows::ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME
                }
            },
            Path::new(executable_path).to_path_buf(),
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
            bootstrap,
        )
        .map_err(|_| PortError::InvalidRequestMetadata)?;
        if request.action == InstallationEffectAction::Rollback {
            let expected = request
                .expected_external_identity
                .as_ref()
                .ok_or(PortError::InvalidRequestMetadata)?;
            registration = registration
                .with_expected_current(
                    ServiceRegistrationCurrent::new(service_name, expected.as_str())
                        .map_err(|_| PortError::InvalidRequestMetadata)?,
                )
                .map_err(|_| PortError::InvalidRequestMetadata)?;
        }
        let installation_root = PathBuf::from(request.installation_root.as_str());
        let platform = WindowsPlatform::new(installation_root.clone())
            .map_err(|_| PortError::InvalidRequestMetadata)?;
        let profile = match request.profile {
            InstallationProfile::SystemService => InstallerRootProfile::SystemService,
            InstallationProfile::UserMode => InstallerRootProfile::UserMode,
            InstallationProfile::PortableDev => InstallerRootProfile::PortableDev,
        };
        let profile_anchor = match request.profile {
            InstallationProfile::SystemService => {
                protected_program_data_root().map_err(|_| PortError::InvalidRequestMetadata)?
            }
            InstallationProfile::UserMode => {
                current_user_local_app_data_root().map_err(|_| PortError::InvalidRequestMetadata)?
            }
            InstallationProfile::PortableDev => installation_root
                .parent()
                .ok_or(PortError::InvalidRequestMetadata)?
                .to_path_buf(),
        };
        let spec = InstallerRootPrimitiveSpec {
            root: installation_root.clone(),
            installation_root,
            profile_anchor,
            profile,
        };
        Ok((platform, registration, spec))
    }

    fn secret_target<'a>(
        &self,
        request: &'a InstallationEffectRequest,
    ) -> Result<&'a PlatformHandle, PortError> {
        let ownership = request
            .ownership_secret
            .as_ref()
            .ok_or(PortError::InvalidRequestMetadata)?;
        if ownership.lifecycle == InstallationSecretLifecycle::Deleted {
            return Err(PortError::InvalidRequestMetadata);
        }
        let observed_sid = self.secrets.principal_sid().map_err(secret_port_error)?;
        if ownership.reference.scope != InstallationSecretScope::WindowsCredentialManagerCurrentUser
            || observed_sid != ownership.reference.expected_principal_sid
        {
            return Err(PortError::Provider(ProviderError {
                code: ProviderErrorCode::PermissionDenied,
                retryable: false,
            }));
        }
        Ok(&ownership.reference.target)
    }

    fn ensure_secret(
        &self,
        request: &InstallationEffectRequest,
    ) -> Result<eliot_platform_windows::CredentialSecret, eliot_platform_windows::WindowsAdapterError>
    {
        let reference = self
            .secret_target(request)
            .map_err(|_| eliot_platform_windows::WindowsAdapterError::InvalidInput)?;
        let disposition = request
            .ownership_secret
            .as_ref()
            .ok_or(eliot_platform_windows::WindowsAdapterError::InvalidInput)?
            .create_disposition;
        if disposition == InstallationCreateDisposition::Created {
            return self.secrets.read(reference);
        }
        if disposition != InstallationCreateDisposition::NotAttempted {
            return Err(eliot_platform_windows::WindowsAdapterError::AlreadyExists);
        }
        match self.secrets.inspect(reference)? {
            InstallerSecretObservation::Absent => {}
            // A credential present before this call is indistinguishable from
            // a forged/colliding entry or a crash after CredWrite. It must
            // never be adopted as transaction ownership.
            InstallerSecretObservation::Present => {
                return Err(eliot_platform_windows::WindowsAdapterError::AlreadyExists);
            }
        }
        let disposition = self.secrets.create_at(reference)?;
        if disposition != InstallerSecretCreateDisposition::Created {
            return Err(eliot_platform_windows::WindowsAdapterError::AlreadyExists);
        }
        self.secrets.read(reference)
    }

    #[allow(
        clippy::unused_self,
        reason = "request construction is kept on the Windows effect-port boundary"
    )]
    fn host_credential_request(
        &self,
        request: &InstallationEffectRequest,
        operation: HostCredentialControlOperation,
        ownership_key: Vec<u8>,
    ) -> Result<HostCredentialControlRequest, PortError> {
        let InstallerEffectPlan::ProvisionStoreCredential { provision, .. } = &request.plan else {
            return Err(PortError::InvalidRequestMetadata);
        };
        let intent = HostCredentialControlIntent::new(
            operation,
            request.transaction_id.clone(),
            request.effect_id.clone(),
            provision.clone(),
            request.plan_digest.clone(),
        )
        .map_err(|_| PortError::InvalidRequestMetadata)?;
        let value = HostCredentialControlRequest {
            intent,
            ownership_key,
            expected_receipt: matches!(
                operation,
                HostCredentialControlOperation::Reconcile | HostCredentialControlOperation::Delete
            )
            .then(|| {
                request
                    .store_credential
                    .as_ref()
                    .and_then(|progress| progress.receipt.clone())
            })
            .flatten(),
        };
        value
            .validate()
            .map_err(|_| PortError::InvalidRequestMetadata)?;
        Ok(value)
    }

    #[allow(
        clippy::unused_self,
        reason = "host call is kept on the Windows effect-port boundary"
    )]
    fn call_credential_host(
        &self,
        request: &HostCredentialControlRequest,
    ) -> Result<HostCredentialControlResponse, PortError> {
        let binding = observe_running_eliot_host_process().map_err(secret_port_error)?;
        if !eliot_platform_windows::windows_paths_equal(
            Path::new(request.intent.provision.expected_host_executable.as_str()),
            Path::new(binding.image_path()),
        ) {
            return Err(PortError::IdentityConflict);
        }
        let host_process_digest =
            PlatformHandle::new(sha256_hex(binding.identity().stable_key().as_bytes()))
                .map_err(|_| PortError::InvalidRequestMetadata)?;
        let expectation =
            eliot_platform_windows::NamedPipePeerExpectation::new_with_process_binding(
                LOCAL_SERVICE_SID,
                0,
                binding,
            )
            .map_err(secret_port_error)?;
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_io()
                        .enable_time()
                        .build()
                        .map_err(|_| host_port_error())?;
                    runtime.block_on(async {
                        let timeout = std::time::Duration::from_secs(5);
                        let mut transport = NamedPipeTransport::connect_authenticated(
                            HOST_CREDENTIAL_CONTROL_PIPE,
                            timeout,
                            &expectation,
                        )
                        .await
                        .map_err(|_| host_port_error())?;
                        let frame = credential_control_request_frame(
                            request.intent.request_digest.as_str(),
                            request,
                        )
                        .map_err(|_| PortError::InvalidRequestMetadata)?;
                        transport
                            .send_frame(&frame, TransportLimits::default())
                            .await
                            .map_err(|_| host_port_error())?;
                        let response = transport
                            .receive_frame(TransportLimits::default())
                            .await
                            .map_err(|_| host_port_error())?;
                        if response.connection_id != request.intent.request_digest.as_str() {
                            return Err(PortError::IdentityConflict);
                        }
                        let response = decode_credential_control_response_frame(&response)
                            .map_err(|_| PortError::IdentityConflict)?;
                        let process_matches = match &response {
                            HostCredentialControlResponse::Absent { snapshot, .. } => {
                                snapshot.host_process_identity == host_process_digest
                            }
                            HostCredentialControlResponse::Matching { receipt } => {
                                receipt.host_process_identity == host_process_digest
                            }
                            HostCredentialControlResponse::Deleted { .. } => {
                                request.expected_receipt.as_ref().is_some_and(|receipt| {
                                    receipt.host_process_identity == host_process_digest
                                })
                            }
                            HostCredentialControlResponse::Unknown { .. } => true,
                        };
                        if !process_matches {
                            return Err(PortError::IdentityConflict);
                        }
                        Ok(response)
                    })
                })
                .join()
                .map_err(|_| host_port_error())?
        })
    }

    fn credential_secret(&self, request: &InstallationEffectRequest) -> Result<Vec<u8>, PortError> {
        let ownership = request
            .ownership_secret
            .as_ref()
            .ok_or(PortError::InvalidRequestMetadata)?;
        if ownership.create_disposition != InstallationCreateDisposition::Created
            || ownership.lifecycle == InstallationSecretLifecycle::Deleted
        {
            return Err(PortError::InvalidRequestMetadata);
        }
        self.secrets
            .read(self.secret_target(request)?)
            .map(|secret| secret.expose().to_vec())
            .map_err(secret_port_error)
    }

    fn inspect_primitive(
        &self,
        request: &InstallationEffectRequest,
    ) -> Result<InstallationEffectObservation, PortError> {
        let (spec, operation) = windows_root_spec(request)?;
        match self.primitive.inspect(&spec).map_err(root_port_error)? {
            InstallerRootPrimitiveObservation::Absent(snapshot) => {
                absent_observation(request, snapshot)
            }
            InstallerRootPrimitiveObservation::Mismatch => Ok(root_mismatch("root-readback")),
            InstallerRootPrimitiveObservation::Matching(root) => match operation {
                WindowsRootOperation::ApplyAcl => matching_preexisting(request, &root),
                WindowsRootOperation::Create => {
                    if std::fs::symlink_metadata(ownership_receipt_path(request)).is_ok() {
                        Ok(root_mismatch("unexpected-receipt-before-intent"))
                    } else {
                        matching_preexisting(request, &root)
                    }
                }
                WindowsRootOperation::Rollback => Err(PortError::InvalidRequestMetadata),
            },
        }
    }

    fn reconcile_primitive(
        &self,
        request: &InstallationEffectRequest,
    ) -> Result<InstallationEffectObservation, PortError> {
        let (spec, operation) = windows_root_spec(request)?;
        match self.primitive.inspect(&spec).map_err(root_port_error)? {
            InstallerRootPrimitiveObservation::Absent(snapshot) => {
                absent_observation(request, snapshot)
            }
            InstallerRootPrimitiveObservation::Mismatch => Ok(root_mismatch("root-readback")),
            InstallerRootPrimitiveObservation::Matching(root) => {
                if operation == WindowsRootOperation::ApplyAcl {
                    return matching_preexisting(request, &root);
                }
                let ownership = request
                    .ownership_secret
                    .as_ref()
                    .ok_or(PortError::InvalidRequestMetadata)?;
                if ownership.create_disposition != InstallationCreateDisposition::Created {
                    return Ok(root_mismatch("created-without-durable-disposition"));
                }
                let secret = self
                    .secrets
                    .read(self.secret_target(request)?)
                    .map_err(secret_port_error)?;
                let marker = self
                    .primitive
                    .read_protected_file(&spec, &ownership_receipt_path(request), RECEIPT_LIMIT)
                    .map_err(root_port_error)?;
                let receipt: WindowsRootOwnershipReceipt = serde_json::from_slice(&marker.bytes)
                    .map_err(|_| PortError::InvalidRequestMetadata)?;
                if !receipt.matches(request, &root, &marker.object, secret.expose()) {
                    return Ok(root_mismatch("keyed-receipt-binding"));
                }
                let external_identity = receipt.external_identity()?;
                if operation == WindowsRootOperation::Rollback
                    && request.expected_external_identity.as_ref() != Some(&external_identity)
                {
                    return Ok(root_mismatch("rollback-external-identity"));
                }
                matching_created(request, &root, &marker.object, &receipt, external_identity)
            }
        }
    }

    fn inspect_service(
        &self,
        request: &InstallationEffectRequest,
    ) -> Result<InstallationEffectObservation, PortError> {
        let (platform, registration, spec) = Self::service_context(request)?;
        let service_name = registration.service_name().to_owned();
        match platform.inspect_service_registration(&registration) {
            ServiceRegistrationInspection::Absent => {
                if std::fs::symlink_metadata(service_marker_path(request)).is_ok() {
                    return Ok(root_mismatch("service-marker-before-intent"));
                }
                service_absent_observation(request)
            }
            ServiceRegistrationInspection::Matching { .. } => {
                let digest = registration.expected_configuration_digest();
                match service_marker_read(&self.primitive, &spec, request, &service_name, &digest)?
                {
                    Some(_) => Ok(root_mismatch("service-marker-before-intent")),
                    None => service_matching_observation(
                        request,
                        InstallationEffectDisposition::PreexistingMatching,
                        &digest,
                        &PlatformHandle::new("service-preexisting-marker-absent")
                            .map_err(|_| PortError::InvalidRequestMetadata)?,
                    ),
                }
            }
            ServiceRegistrationInspection::Mismatched => Ok(root_mismatch("service-config")),
            ServiceRegistrationInspection::Unknown => Ok(root_mismatch("service-readback")),
        }
    }

    fn reconcile_service(
        &self,
        request: &InstallationEffectRequest,
    ) -> Result<InstallationEffectObservation, PortError> {
        let (platform, registration, spec) = Self::service_context(request)?;
        let service_name = registration.service_name().to_owned();
        let digest = registration.expected_configuration_digest();
        match platform.inspect_service_registration(&registration) {
            ServiceRegistrationInspection::Absent => service_absent_observation(request),
            ServiceRegistrationInspection::Matching { .. } => {
                let marker = if let Some(marker) =
                    service_marker_read(&self.primitive, &spec, request, &service_name, &digest)?
                {
                    marker
                } else {
                    let marker =
                        WindowsServiceOwnershipMarker::new(request, &service_name, &digest)?;
                    let marker_path = service_marker_path(request);
                    match self
                        .primitive
                        .create_protected_file(&spec, &marker_path, |_| {
                            serde_json::to_vec(&marker)
                                .map_err(|_| InstallerRootError::Indeterminate)
                        }) {
                        Ok(_) | Err(InstallerRootError::ReceiptMismatch) => {}
                        Err(error) => return Err(root_port_error(error)),
                    }
                    service_marker_read(&self.primitive, &spec, request, &service_name, &digest)?
                        .ok_or(PortError::InvalidRequestMetadata)?
                };
                let (_, marker) = marker;
                let marker_digest = marker.digest()?;
                service_matching_observation(
                    request,
                    InstallationEffectDisposition::CreatedByTransaction,
                    &digest,
                    &marker_digest,
                )
            }
            ServiceRegistrationInspection::Mismatched => Ok(root_mismatch("service-config")),
            ServiceRegistrationInspection::Unknown => Ok(root_mismatch("service-readback")),
        }
    }

    fn credential_observation(
        &self,
        request: &InstallationEffectRequest,
        operation: HostCredentialControlOperation,
    ) -> Result<InstallationEffectObservation, PortError> {
        let ownership_key = if operation == HostCredentialControlOperation::Inspect {
            Vec::new()
        } else {
            self.credential_secret(request)?
        };
        let host_request = self.host_credential_request(request, operation, ownership_key)?;
        let response = self.call_credential_host(&host_request)?;
        match response {
            HostCredentialControlResponse::Absent {
                snapshot,
                response_digest,
            } => {
                if response_digest
                    != credential_absent_response_digest(
                        &host_request.intent.request_digest,
                        &snapshot,
                    )
                    .map_err(|_| PortError::IdentityConflict)?
                {
                    return Err(PortError::IdentityConflict);
                }
                Ok(InstallationEffectObservation::Absent {
                    observed_precondition: request
                        .precondition
                        .with_credential_snapshot(snapshot)
                        .map_err(|_| PortError::InvalidRequestMetadata)?,
                    evidence: vec![response_digest],
                })
            }
            HostCredentialControlResponse::Matching { receipt } => {
                if !receipt.matches_intent(&host_request.intent) {
                    return Err(PortError::IdentityConflict);
                }
                let bytes =
                    serde_json::to_vec(&receipt).map_err(|_| PortError::InvalidRequestMetadata)?;
                let digest = PlatformHandle::new(sha256_hex(&bytes))
                    .map_err(|_| PortError::InvalidRequestMetadata)?;
                let external_identity =
                    PlatformHandle::new(format!("store-credential:{}", digest.as_str()))
                        .map_err(|_| PortError::InvalidRequestMetadata)?;
                Ok(InstallationEffectObservation::Matching {
                    disposition: InstallationEffectDisposition::CreatedByTransaction,
                    external_identity,
                    evidence: vec![receipt.response_digest.clone()],
                    postcondition_digest: digest,
                    credential_receipt: Some(receipt),
                })
            }
            HostCredentialControlResponse::Deleted { absence_digest } => {
                let prior = host_request
                    .expected_receipt
                    .as_ref()
                    .ok_or(PortError::IdentityConflict)?;
                let expected = credential_deleted_response_digest(
                    &host_request.intent.request_digest,
                    &prior.host_owner_epoch,
                    &prior.host_process_identity,
                    &prior.marker,
                )
                .map_err(|_| PortError::IdentityConflict)?;
                if expected != absence_digest {
                    return Err(PortError::IdentityConflict);
                }
                Ok(InstallationEffectObservation::Absent {
                    observed_precondition: request.precondition.clone(),
                    evidence: vec![absence_digest],
                })
            }
            HostCredentialControlResponse::Unknown { pending_ref } => {
                Ok(InstallationEffectObservation::Mismatch { pending_ref })
            }
        }
    }

    fn execute_credential(
        &self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectExecution> {
        let operation = match request.action {
            InstallationEffectAction::Apply => HostCredentialControlOperation::Provision,
            InstallationEffectAction::Rollback => HostCredentialControlOperation::Delete,
        };
        let key = match self.credential_secret(request) {
            Ok(key) => key,
            Err(error) => return PortOutcome::Error(error),
        };
        let host_request = match self.host_credential_request(request, operation, key) {
            Ok(request) => request,
            Err(error) => return PortOutcome::Error(error),
        };
        match self.call_credential_host(&host_request) {
            Ok(HostCredentialControlResponse::Matching { receipt })
                if operation == HostCredentialControlOperation::Provision
                    && receipt.matches_intent(&host_request.intent) =>
            {
                PortOutcome::Known(InstallationEffectExecution {
                    evidence: vec![receipt.response_digest.clone()],
                    create_disposition: None,
                    credential_receipt: Some(receipt),
                })
            }
            Ok(HostCredentialControlResponse::Deleted { absence_digest })
                if operation == HostCredentialControlOperation::Delete =>
            {
                let Some(prior) = host_request.expected_receipt.as_ref() else {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                };
                let expected = credential_deleted_response_digest(
                    &host_request.intent.request_digest,
                    &prior.host_owner_epoch,
                    &prior.host_process_identity,
                    &prior.marker,
                );
                if expected.as_ref() != Ok(&absence_digest) {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                }
                PortOutcome::Known(InstallationEffectExecution {
                    evidence: vec![absence_digest],
                    create_disposition: None,
                    credential_receipt: None,
                })
            }
            Ok(HostCredentialControlResponse::Unknown { .. }) => {
                PortOutcome::Unknown(UnknownReason::Indeterminate)
            }
            Ok(_) => PortOutcome::Unknown(UnknownReason::Indeterminate),
            Err(error) => PortOutcome::Error(error),
        }
    }
}

impl InstallationEffectPort for WindowsInstallationEffectPort {
    fn fresh_service_registration_nonce(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<PlatformHandle> {
        if !matches!(&request.plan, InstallerEffectPlan::RegisterService { .. }) {
            return PortOutcome::Error(PortError::InvalidRequestMetadata);
        }
        match fresh_service_registration_nonce() {
            Ok(nonce) => PortOutcome::Known(nonce),
            Err(error) => secret_outcome(error),
        }
    }

    fn fresh_ownership_secret_reference(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationSecretReference> {
        if !matches!(
            request.plan,
            InstallerEffectPlan::CreateRoot { .. }
                | InstallerEffectPlan::ProvisionStoreCredential { .. }
        ) || request.precondition.os_snapshot.is_some()
            || request.precondition.credential_snapshot.is_some()
        {
            return PortOutcome::Error(PortError::InvalidRequestMetadata);
        }
        let target = match self.secrets.fresh_reference() {
            Ok(target) => target,
            Err(error) => return secret_outcome(error),
        };
        let expected_principal_sid = match self.secrets.principal_sid() {
            Ok(sid) => sid,
            Err(error) => return secret_outcome(error),
        };
        PortOutcome::Known(InstallationSecretReference {
            target,
            expected_principal_sid,
            scope: InstallationSecretScope::WindowsCredentialManagerCurrentUser,
        })
    }

    fn provision_ownership_secret(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationCreateDisposition> {
        if !matches!(
            request.plan,
            InstallerEffectPlan::ProvisionStoreCredential { .. }
        ) || request.precondition.credential_snapshot.is_none()
        {
            return PortOutcome::Error(PortError::InvalidRequestMetadata);
        }
        match self.ensure_secret(request) {
            Ok(_) => PortOutcome::Known(InstallationCreateDisposition::Created),
            Err(error) => secret_outcome(error),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the sealed adapter keeps create, receipt, and exact rollback mechanics in one boundary"
    )]
    fn execute(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectExecution> {
        if matches!(&request.plan, InstallerEffectPlan::RegisterService { .. }) {
            return self.execute_service(request);
        }
        if matches!(
            request.plan,
            InstallerEffectPlan::ProvisionStoreCredential { .. }
        ) {
            return self.execute_credential(request);
        }
        let (spec, operation) = match windows_root_spec(request) {
            Ok(value) => value,
            Err(error) => return PortOutcome::Error(error),
        };
        match operation {
            WindowsRootOperation::ApplyAcl => PortOutcome::Known(InstallationEffectExecution {
                evidence: vec![
                    PlatformHandle::new("apply-acl-readback-only")
                        .unwrap_or_else(|_| unreachable!()),
                ],
                create_disposition: None,
                credential_receipt: None,
            }),
            WindowsRootOperation::Create => {
                let Some(expected) = request.precondition.os_snapshot.as_ref() else {
                    return PortOutcome::Error(PortError::InvalidRequestMetadata);
                };
                let expected = platform_absent_snapshot(expected);
                let secret = match self.ensure_secret(request) {
                    Ok(secret) => secret,
                    Err(error) => return secret_outcome(error),
                };
                let created = match self.primitive.create(&spec, &expected) {
                    Ok(created) => created,
                    Err(error) => return root_execution_error(error),
                };
                if created.disposition == InstallerRootCreateDisposition::AlreadyExists {
                    return PortOutcome::Known(InstallationEffectExecution {
                        evidence: vec![
                            PlatformHandle::new("create-raced-existing")
                                .unwrap_or_else(|_| unreachable!()),
                        ],
                        create_disposition: Some(InstallationCreateDisposition::AlreadyExists),
                        credential_receipt: None,
                    });
                }
                let Some(root) = created.root else {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                };
                let marker_path = ownership_receipt_path(request);
                let receipt_result =
                    self.primitive
                        .create_protected_file(&spec, &marker_path, |marker| {
                            let receipt = WindowsRootOwnershipReceipt::new(
                                request,
                                &root,
                                marker,
                                secret.expose(),
                            )?;
                            serde_json::to_vec(&receipt)
                                .map_err(|_| InstallerRootError::Indeterminate)
                        });
                let marker = match receipt_result {
                    Ok(marker) => marker,
                    Err(error) => return root_execution_error(error),
                };
                let evidence = PlatformHandle::new(root_marker_digest(&root, &marker))
                    .unwrap_or_else(|_| unreachable!());
                PortOutcome::Known(InstallationEffectExecution {
                    evidence: vec![evidence],
                    create_disposition: Some(InstallationCreateDisposition::Created),
                    credential_receipt: None,
                })
            }
            WindowsRootOperation::Rollback => {
                let observed = match self.reconcile_primitive(request) {
                    Ok(observed) => observed,
                    Err(error) => return PortOutcome::Error(error),
                };
                let InstallationEffectObservation::Matching {
                    disposition: InstallationEffectDisposition::CreatedByTransaction,
                    external_identity,
                    ..
                } = observed
                else {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                };
                if request.expected_external_identity.as_ref() != Some(&external_identity) {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                }
                let marker_path = ownership_receipt_path(request);
                let marker =
                    match self
                        .primitive
                        .read_protected_file(&spec, &marker_path, RECEIPT_LIMIT)
                    {
                        Ok(marker) => marker,
                        Err(error) => return root_execution_error(error),
                    };
                let root = match self.primitive.inspect(&spec) {
                    Ok(InstallerRootPrimitiveObservation::Matching(root)) => root,
                    Ok(_) => return PortOutcome::Unknown(UnknownReason::Indeterminate),
                    Err(error) => return root_execution_error(error),
                };
                if self
                    .primitive
                    .ensure_only_path(&spec, &marker_path)
                    .is_err()
                    || self
                        .primitive
                        .delete_file(&marker_path, &marker.object)
                        .is_err()
                    || self.primitive.delete_root(&spec, &root).is_err()
                {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                }
                PortOutcome::Known(InstallationEffectExecution {
                    evidence: vec![
                        PlatformHandle::new("rollback-exact-identity-delete")
                            .unwrap_or_else(|_| unreachable!()),
                    ],
                    create_disposition: None,
                    credential_receipt: None,
                })
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn execute_service(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectExecution> {
        let (platform, registration, spec) = match Self::service_context(request) {
            Ok(value) => value,
            Err(error) => return PortOutcome::Error(error),
        };
        if request.action == InstallationEffectAction::Rollback {
            let observed = match self.reconcile_service(request) {
                Ok(observed) => observed,
                Err(error) => return PortOutcome::Error(error),
            };
            let InstallationEffectObservation::Matching {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                external_identity,
                ..
            } = observed
            else {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            };
            if request.expected_external_identity.as_ref() != Some(&external_identity) {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            let marker_path = service_marker_path(request);
            let marker =
                match self
                    .primitive
                    .read_protected_file(&spec, &marker_path, SERVICE_MARKER_LIMIT)
                {
                    Ok(marker) => marker,
                    Err(error) => return root_execution_error(error),
                };
            match platform.delete_service_registration(&registration) {
                Ok(ServiceRegistrationOutcome::Deleted) => {}
                Ok(
                    ServiceRegistrationOutcome::AlreadyAbsent
                    | ServiceRegistrationOutcome::ExistingRequiresReconciliation
                    | ServiceRegistrationOutcome::EffectUnknown
                    | ServiceRegistrationOutcome::CreatedNow { .. }
                    | ServiceRegistrationOutcome::PreexistingMatching { .. }
                    | ServiceRegistrationOutcome::Registered { .. }
                    | ServiceRegistrationOutcome::Updated { .. }
                    | ServiceRegistrationOutcome::Unchanged { .. },
                ) => {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                }
                Err(_) => return PortOutcome::Unknown(UnknownReason::Indeterminate),
            }
            if self
                .primitive
                .delete_file(&marker_path, &marker.object)
                .is_err()
                || std::fs::symlink_metadata(&marker_path).is_ok()
            {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            return PortOutcome::Known(InstallationEffectExecution {
                evidence: vec![
                    PlatformHandle::new("rollback-service-and-marker-exact-identity")
                        .unwrap_or_else(|_| unreachable!()),
                ],
                create_disposition: None,
                credential_receipt: None,
            });
        }
        let configuration_digest = registration.expected_configuration_digest();
        match platform.register_service(&registration) {
            Ok(ServiceRegistrationOutcome::CreatedNow { .. }) => {}
            Ok(
                ServiceRegistrationOutcome::PreexistingMatching { .. }
                | ServiceRegistrationOutcome::Registered { .. }
                | ServiceRegistrationOutcome::ExistingRequiresReconciliation
                | ServiceRegistrationOutcome::EffectUnknown
                | ServiceRegistrationOutcome::Updated { .. }
                | ServiceRegistrationOutcome::Unchanged { .. }
                | ServiceRegistrationOutcome::Deleted
                | ServiceRegistrationOutcome::AlreadyAbsent,
            ) => {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            Err(_) => return PortOutcome::Unknown(UnknownReason::Indeterminate),
        }
        let marker = match WindowsServiceOwnershipMarker::new(
            request,
            registration.service_name(),
            &configuration_digest,
        ) {
            Ok(marker) => marker,
            Err(error) => return PortOutcome::Error(error),
        };
        let marker_path = service_marker_path(request);
        let marker_object = match self
            .primitive
            .create_protected_file(&spec, &marker_path, |_| {
                serde_json::to_vec(&marker).map_err(|_| InstallerRootError::Indeterminate)
            }) {
            Ok(object) => object,
            Err(error) => return root_execution_error(error),
        };
        let marker_digest = match marker.digest() {
            Ok(digest) => digest,
            Err(error) => return PortOutcome::Error(error),
        };
        if self
            .primitive
            .read_protected_file(&spec, &marker_path, SERVICE_MARKER_LIMIT)
            .is_err()
        {
            return PortOutcome::Unknown(UnknownReason::Indeterminate);
        }
        PortOutcome::Known(InstallationEffectExecution {
            evidence: vec![
                marker_digest,
                PlatformHandle::new(format!(
                    "service-marker-object:{}:{}",
                    marker_object.volume_serial_number, marker_object.file_index
                ))
                .unwrap_or_else(|_| unreachable!()),
            ],
            create_disposition: Some(InstallationCreateDisposition::Created),
            credential_receipt: None,
        })
    }

    fn inspect(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectObservation> {
        let result = if matches!(&request.plan, InstallerEffectPlan::RegisterService { .. }) {
            self.inspect_service(request)
        } else if matches!(
            request.plan,
            InstallerEffectPlan::ProvisionStoreCredential { .. }
        ) {
            self.credential_observation(request, HostCredentialControlOperation::Inspect)
        } else {
            self.inspect_primitive(request)
        };
        match result {
            Ok(observation) => PortOutcome::Known(observation),
            Err(error) => PortOutcome::Error(error),
        }
    }

    fn reconcile(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectObservation> {
        let result = if matches!(&request.plan, InstallerEffectPlan::RegisterService { .. }) {
            self.reconcile_service(request)
        } else if matches!(
            request.plan,
            InstallerEffectPlan::ProvisionStoreCredential { .. }
        ) {
            let operation = if request.action == InstallationEffectAction::Rollback
                && request.store_credential.as_ref().is_some_and(|progress| {
                    matches!(
                        progress.lifecycle,
                        StoreCredentialLifecycle::DeleteExecuted
                            | StoreCredentialLifecycle::Deleted
                    )
                }) {
                HostCredentialControlOperation::Inspect
            } else {
                HostCredentialControlOperation::Reconcile
            };
            self.credential_observation(request, operation)
        } else {
            self.reconcile_primitive(request)
        };
        match result {
            Ok(observation) => PortOutcome::Known(observation),
            Err(error) => PortOutcome::Error(error),
        }
    }

    fn delete_ownership_secret(&mut self, request: &InstallationEffectRequest) -> PortOutcome<()> {
        let Some(ownership) = request.ownership_secret.as_ref() else {
            return PortOutcome::Error(PortError::InvalidRequestMetadata);
        };
        if ownership.lifecycle != InstallationSecretLifecycle::DeleteIntentCommitted {
            return PortOutcome::Error(PortError::InvalidRequestMetadata);
        }
        let target = match self.secret_target(request) {
            Ok(target) => target,
            Err(error) => return PortOutcome::Error(error),
        };
        match self.secrets.delete(target) {
            Ok(()) => PortOutcome::Known(()),
            Err(error) => secret_outcome(error),
        }
    }

    fn ownership_secret_absent(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<bool> {
        if request.ownership_secret.is_none() {
            return PortOutcome::Error(PortError::InvalidRequestMetadata);
        }
        let target = match self.secret_target(request) {
            Ok(target) => target,
            Err(error) => return PortOutcome::Error(error),
        };
        match self.secrets.inspect(target) {
            Ok(InstallerSecretObservation::Absent) => PortOutcome::Known(true),
            Ok(InstallerSecretObservation::Present) => PortOutcome::Known(false),
            Err(error) => secret_outcome(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsRootOperation {
    Create,
    ApplyAcl,
    Rollback,
}

fn windows_root_spec(
    request: &InstallationEffectRequest,
) -> Result<(InstallerRootPrimitiveSpec, WindowsRootOperation), PortError> {
    request
        .validate()
        .map_err(|_| PortError::InvalidRequestMetadata)?;
    let (root, operation) = match (&request.plan, request.action) {
        (InstallerEffectPlan::CreateRoot { root, .. }, InstallationEffectAction::Apply) => {
            (root, WindowsRootOperation::Create)
        }
        (InstallerEffectPlan::CreateRoot { root, .. }, InstallationEffectAction::Rollback) => {
            (root, WindowsRootOperation::Rollback)
        }
        (InstallerEffectPlan::ApplyAcl { root, .. }, InstallationEffectAction::Apply) => {
            (root, WindowsRootOperation::ApplyAcl)
        }
        _ => return Err(PortError::InvalidRequestMetadata),
    };
    let profile = match request.profile {
        InstallationProfile::SystemService => InstallerRootProfile::SystemService,
        InstallationProfile::UserMode => InstallerRootProfile::UserMode,
        InstallationProfile::PortableDev => InstallerRootProfile::PortableDev,
    };
    let profile_anchor = match request.profile {
        InstallationProfile::SystemService => {
            protected_program_data_root().map_err(|_| PortError::InvalidRequestMetadata)?
        }
        InstallationProfile::UserMode => {
            current_user_local_app_data_root().map_err(|_| PortError::InvalidRequestMetadata)?
        }
        InstallationProfile::PortableDev => Path::new(request.installation_root.as_str())
            .parent()
            .ok_or(PortError::InvalidRequestMetadata)?
            .to_path_buf(),
    };
    Ok((
        InstallerRootPrimitiveSpec {
            root: root.as_str().into(),
            installation_root: request.installation_root.as_str().into(),
            profile_anchor,
            profile,
        },
        operation,
    ))
}

fn platform_object_snapshot(
    snapshot: &InstallationOsObjectSnapshot,
) -> InstallerRootObjectSnapshot {
    InstallerRootObjectSnapshot {
        canonical_path_digest: snapshot.canonical_path_digest.as_str().to_owned(),
        volume_serial_number: snapshot.volume_serial_number,
        file_index: snapshot.file_index,
        security_descriptor_digest: snapshot.security_descriptor_digest.as_str().to_owned(),
    }
}

fn platform_absent_snapshot(
    snapshot: &InstallationRootAbsentSnapshot,
) -> InstallerRootAbsentSnapshot {
    InstallerRootAbsentSnapshot {
        target_path_digest: snapshot.target_path_digest.as_str().to_owned(),
        profile_anchor: platform_object_snapshot(&snapshot.profile_anchor),
        ancestors: snapshot
            .ancestors
            .iter()
            .map(platform_object_snapshot)
            .collect(),
        parent: platform_object_snapshot(&snapshot.parent),
        root_absent: snapshot.root_absent,
    }
}

fn installation_object_snapshot(
    snapshot: InstallerRootObjectSnapshot,
) -> Result<InstallationOsObjectSnapshot, PortError> {
    Ok(InstallationOsObjectSnapshot {
        canonical_path_digest: PlatformHandle::new(snapshot.canonical_path_digest)
            .map_err(|_| PortError::InvalidRequestMetadata)?,
        volume_serial_number: snapshot.volume_serial_number,
        file_index: snapshot.file_index,
        security_descriptor_digest: PlatformHandle::new(snapshot.security_descriptor_digest)
            .map_err(|_| PortError::InvalidRequestMetadata)?,
    })
}

fn installation_absent_snapshot(
    snapshot: InstallerRootAbsentSnapshot,
) -> Result<InstallationRootAbsentSnapshot, PortError> {
    Ok(InstallationRootAbsentSnapshot {
        target_path_digest: PlatformHandle::new(snapshot.target_path_digest)
            .map_err(|_| PortError::InvalidRequestMetadata)?,
        profile_anchor: installation_object_snapshot(snapshot.profile_anchor)?,
        ancestors: snapshot
            .ancestors
            .into_iter()
            .map(installation_object_snapshot)
            .collect::<Result<_, _>>()?,
        parent: installation_object_snapshot(snapshot.parent)?,
        root_absent: snapshot.root_absent,
    })
}

const RECEIPT_LIMIT: u64 = 16 * 1024;
const OWNERSHIP_RECEIPT_VERSION: u32 = 2;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsRootOwnershipReceipt {
    version: u32,
    transaction_id: String,
    effect_id: String,
    plan_digest: String,
    secret_reference: String,
    root: InstallerRootObjectSnapshot,
    marker: InstallerRootObjectSnapshot,
    mac: String,
}

impl WindowsRootOwnershipReceipt {
    fn new(
        request: &InstallationEffectRequest,
        root: &InstallerRootObjectSnapshot,
        marker: &InstallerRootObjectSnapshot,
        key: &[u8],
    ) -> Result<Self, InstallerRootError> {
        let secret_reference = request
            .ownership_secret
            .as_ref()
            .ok_or(InstallerRootError::ReceiptMismatch)?
            .reference
            .target
            .as_str()
            .to_owned();
        let mut receipt = Self {
            version: OWNERSHIP_RECEIPT_VERSION,
            transaction_id: request.transaction_id.as_str().to_owned(),
            effect_id: request.effect_id.as_str().to_owned(),
            plan_digest: request.plan_digest.as_str().to_owned(),
            secret_reference,
            root: root.clone(),
            marker: marker.clone(),
            mac: String::new(),
        };
        receipt.mac = hmac_sha256_hex(key, &receipt.mac_payload()?);
        Ok(receipt)
    }

    fn mac_payload(&self) -> Result<Vec<u8>, InstallerRootError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            version: u32,
            transaction_id: &'a str,
            effect_id: &'a str,
            plan_digest: &'a str,
            secret_reference: &'a str,
            root: &'a InstallerRootObjectSnapshot,
            marker: &'a InstallerRootObjectSnapshot,
        }
        serde_json::to_vec(&Payload {
            version: self.version,
            transaction_id: &self.transaction_id,
            effect_id: &self.effect_id,
            plan_digest: &self.plan_digest,
            secret_reference: &self.secret_reference,
            root: &self.root,
            marker: &self.marker,
        })
        .map_err(|_| InstallerRootError::Indeterminate)
    }

    fn matches(
        &self,
        request: &InstallationEffectRequest,
        root: &InstallerRootObjectSnapshot,
        marker: &InstallerRootObjectSnapshot,
        key: &[u8],
    ) -> bool {
        let Some(ownership) = request.ownership_secret.as_ref() else {
            return false;
        };
        let Ok(payload) = self.mac_payload() else {
            return false;
        };
        self.version == OWNERSHIP_RECEIPT_VERSION
            && self.transaction_id == request.transaction_id.as_str()
            && self.effect_id == request.effect_id.as_str()
            && self.plan_digest == request.plan_digest.as_str()
            && self.secret_reference == ownership.reference.target.as_str()
            && self.root == *root
            && self.marker == *marker
            && constant_time_equal(
                self.mac.as_bytes(),
                hmac_sha256_hex(key, &payload).as_bytes(),
            )
    }

    fn external_identity(&self) -> Result<PlatformHandle, PortError> {
        PlatformHandle::new(sha256_hex(
            &serde_json::to_vec(&(
                "installer-owned-root-v2",
                &self.root,
                &self.marker,
                &self.mac,
            ))
            .map_err(|_| PortError::InvalidRequestMetadata)?,
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)
    }
}

fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK_BYTES: usize = 64;
    let mut normalized = [0_u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; BLOCK_BYTES];
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    normalized.fill(0);
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    inner_pad.fill(0);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer_pad.fill(0);
    format!("{:x}", outer.finalize())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn ownership_receipt_path(request: &InstallationEffectRequest) -> std::path::PathBuf {
    let root = match &request.plan {
        InstallerEffectPlan::CreateRoot { root, .. }
        | InstallerEffectPlan::ApplyAcl { root, .. } => Path::new(root.as_str()),
        InstallerEffectPlan::RegisterService { .. } => {
            Path::new(request.installation_root.as_str())
        }
        InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => {
            Path::new(provision.host_state_root.as_str())
        }
    };
    let name = sha256_hex(
        format!(
            "{}\0{}\0{}",
            request.transaction_id.as_str(),
            request.effect_id.as_str(),
            request.plan_digest.as_str()
        )
        .as_bytes(),
    );
    root.join(format!(".eliot-install-{name}.receipt"))
}

fn root_marker_digest(
    root: &InstallerRootObjectSnapshot,
    marker: &InstallerRootObjectSnapshot,
) -> String {
    serde_json::to_vec(&("root-marker-v2", root, marker)).map_or_else(
        |_| sha256_hex(b"root-marker-invalid"),
        |bytes| sha256_hex(&bytes),
    )
}

fn absent_observation(
    request: &InstallationEffectRequest,
    snapshot: InstallerRootAbsentSnapshot,
) -> Result<InstallationEffectObservation, PortError> {
    let evidence =
        PlatformHandle::new(snapshot.digest()).map_err(|_| PortError::InvalidRequestMetadata)?;
    let snapshot = installation_absent_snapshot(snapshot)?;
    let observed_precondition = request
        .precondition
        .with_os_snapshot(snapshot)
        .map_err(|_| PortError::InvalidRequestMetadata)?;
    Ok(InstallationEffectObservation::Absent {
        observed_precondition,
        evidence: vec![evidence],
    })
}

fn matching_preexisting(
    request: &InstallationEffectRequest,
    root: &InstallerRootObjectSnapshot,
) -> Result<InstallationEffectObservation, PortError> {
    let root_digest = sha256_hex(
        &serde_json::to_vec(&("preexisting-root-v2", root))
            .map_err(|_| PortError::InvalidRequestMetadata)?,
    );
    let external_identity =
        PlatformHandle::new(root_digest.clone()).map_err(|_| PortError::InvalidRequestMetadata)?;
    let evidence_digest = sha256_hex(
        &serde_json::to_vec(&(
            "root-readback-evidence-v2",
            request.effect_id.as_str(),
            request.plan_digest.as_str(),
            root,
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)?,
    );
    let postcondition_digest = PlatformHandle::new(sha256_hex(
        &serde_json::to_vec(&(
            "root-postcondition-v2",
            request.effect_id.as_str(),
            request.plan_digest.as_str(),
            root,
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)?,
    ))
    .map_err(|_| PortError::InvalidRequestMetadata)?;
    Ok(InstallationEffectObservation::Matching {
        disposition: InstallationEffectDisposition::PreexistingMatching,
        external_identity,
        evidence: vec![
            PlatformHandle::new(evidence_digest).map_err(|_| PortError::InvalidRequestMetadata)?,
        ],
        postcondition_digest,
        credential_receipt: None,
    })
}

fn matching_created(
    request: &InstallationEffectRequest,
    root: &InstallerRootObjectSnapshot,
    marker: &InstallerRootObjectSnapshot,
    receipt: &WindowsRootOwnershipReceipt,
    external_identity: PlatformHandle,
) -> Result<InstallationEffectObservation, PortError> {
    let evidence_digest = sha256_hex(
        &serde_json::to_vec(&(
            "owned-root-evidence-v2",
            request.effect_id.as_str(),
            request.plan_digest.as_str(),
            root,
            marker,
            &receipt.mac,
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)?,
    );
    let postcondition_digest = PlatformHandle::new(sha256_hex(
        &serde_json::to_vec(&(
            "owned-root-postcondition-v2",
            request.effect_id.as_str(),
            request.plan_digest.as_str(),
            root,
            marker,
            &receipt.mac,
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)?,
    ))
    .map_err(|_| PortError::InvalidRequestMetadata)?;
    Ok(InstallationEffectObservation::Matching {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity,
        evidence: vec![
            PlatformHandle::new(evidence_digest).map_err(|_| PortError::InvalidRequestMetadata)?,
        ],
        postcondition_digest,
        credential_receipt: None,
    })
}

fn root_mismatch(reason: &str) -> InstallationEffectObservation {
    InstallationEffectObservation::Mismatch {
        pending_ref: PlatformHandle::new(format!("mismatch:installer-root:{reason}"))
            .unwrap_or_else(|_| unreachable!()),
    }
}

const SERVICE_MARKER_VERSION: u32 = 1;
const SERVICE_MARKER_LIMIT: u64 = 16 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsServiceOwnershipMarker {
    version: u32,
    transaction_id: String,
    effect_id: String,
    plan_digest: String,
    service_name: String,
    registration_nonce: String,
    configuration_digest: String,
}

impl WindowsServiceOwnershipMarker {
    fn new(
        request: &InstallationEffectRequest,
        service_name: &str,
        configuration_digest: &str,
    ) -> Result<Self, PortError> {
        Ok(Self {
            version: SERVICE_MARKER_VERSION,
            transaction_id: request.transaction_id.as_str().to_owned(),
            effect_id: request.effect_id.as_str().to_owned(),
            plan_digest: request.plan_digest.as_str().to_owned(),
            service_name: service_name.to_owned(),
            registration_nonce: request
                .registration_nonce
                .as_ref()
                .ok_or(PortError::InvalidRequestMetadata)?
                .as_str()
                .to_owned(),
            configuration_digest: configuration_digest.to_owned(),
        })
    }

    fn matches(
        &self,
        request: &InstallationEffectRequest,
        service_name: &str,
        digest: &str,
    ) -> bool {
        self.version == SERVICE_MARKER_VERSION
            && self.transaction_id == request.transaction_id.as_str()
            && self.effect_id == request.effect_id.as_str()
            && self.plan_digest == request.plan_digest.as_str()
            && self.service_name == service_name
            && request
                .registration_nonce
                .as_ref()
                .is_some_and(|nonce| self.registration_nonce == nonce.as_str())
            && self.configuration_digest == digest
    }

    fn digest(&self) -> Result<PlatformHandle, PortError> {
        PlatformHandle::new(sha256_hex(
            &serde_json::to_vec(self).map_err(|_| PortError::InvalidRequestMetadata)?,
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)
    }
}

fn service_marker_path(request: &InstallationEffectRequest) -> PathBuf {
    let name = sha256_hex(
        format!(
            "service-marker-v1\0{}\0{}\0{}\0{}",
            request.transaction_id.as_str(),
            request.effect_id.as_str(),
            request.plan_digest.as_str(),
            request
                .registration_nonce
                .as_ref()
                .map_or("", PlatformHandle::as_str),
        )
        .as_bytes(),
    );
    Path::new(request.installation_root.as_str()).join(format!(".eliot-service-{name}.marker"))
}

fn service_marker_read(
    primitive: &WindowsInstallerRootPrimitive,
    spec: &InstallerRootPrimitiveSpec,
    request: &InstallationEffectRequest,
    service_name: &str,
    configuration_digest: &str,
) -> Result<Option<(InstallerRootObjectSnapshot, WindowsServiceOwnershipMarker)>, PortError> {
    let path = service_marker_path(request);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(root_port_error(InstallerRootError::Indeterminate)),
    }
    let readback = primitive
        .read_protected_file(spec, &path, SERVICE_MARKER_LIMIT)
        .map_err(root_port_error)?;
    let marker: WindowsServiceOwnershipMarker =
        serde_json::from_slice(&readback.bytes).map_err(|_| PortError::InvalidRequestMetadata)?;
    if !marker.matches(request, service_name, configuration_digest) {
        return Err(PortError::Provider(ProviderError {
            code: ProviderErrorCode::Failed,
            retryable: false,
        }));
    }
    Ok(Some((readback.object, marker)))
}

fn service_absent_observation(
    request: &InstallationEffectRequest,
) -> Result<InstallationEffectObservation, PortError> {
    Ok(InstallationEffectObservation::Absent {
        observed_precondition: request.precondition.clone(),
        evidence: vec![
            PlatformHandle::new(sha256_hex(
                format!(
                    "service-absent-v1\0{}\0{}",
                    request.effect_id.as_str(),
                    request.plan_digest.as_str()
                )
                .as_bytes(),
            ))
            .map_err(|_| PortError::InvalidRequestMetadata)?,
        ],
    })
}

fn service_matching_observation(
    request: &InstallationEffectRequest,
    disposition: InstallationEffectDisposition,
    configuration_digest: &str,
    marker_digest: &PlatformHandle,
) -> Result<InstallationEffectObservation, PortError> {
    let external_identity =
        PlatformHandle::new(configuration_digest).map_err(|_| PortError::InvalidRequestMetadata)?;
    let evidence = PlatformHandle::new(sha256_hex(
        format!(
            "service-matching-v1\0{}\0{}\0{}\0{}",
            request.effect_id.as_str(),
            request.plan_digest.as_str(),
            configuration_digest,
            marker_digest.as_str(),
        )
        .as_bytes(),
    ))
    .map_err(|_| PortError::InvalidRequestMetadata)?;
    let postcondition_digest = PlatformHandle::new(sha256_hex(
        format!(
            "service-postcondition-v1\0{}\0{}\0{}",
            request.effect_id.as_str(),
            configuration_digest,
            marker_digest.as_str(),
        )
        .as_bytes(),
    ))
    .map_err(|_| PortError::InvalidRequestMetadata)?;
    Ok(InstallationEffectObservation::Matching {
        disposition,
        external_identity,
        evidence: vec![evidence],
        postcondition_digest,
        credential_receipt: None,
    })
}

fn root_port_error(error: InstallerRootError) -> PortError {
    match error {
        InstallerRootError::InvalidPath | InstallerRootError::MissingParent => {
            PortError::InvalidPath
        }
        InstallerRootError::NotElevated => PortError::Provider(ProviderError {
            code: ProviderErrorCode::PermissionDenied,
            retryable: false,
        }),
        _ => PortError::Provider(ProviderError {
            code: ProviderErrorCode::Unavailable,
            retryable: false,
        }),
    }
}

fn secret_port_error(_error: eliot_platform_windows::WindowsAdapterError) -> PortError {
    PortError::Provider(ProviderError {
        code: ProviderErrorCode::Unavailable,
        retryable: false,
    })
}

fn host_port_error() -> PortError {
    PortError::Provider(ProviderError {
        code: ProviderErrorCode::Unavailable,
        retryable: true,
    })
}

fn secret_outcome<T>(error: eliot_platform_windows::WindowsAdapterError) -> PortOutcome<T> {
    PortOutcome::Error(secret_port_error(error))
}

fn root_execution_error<T>(error: InstallerRootError) -> PortOutcome<T> {
    match error {
        InstallerRootError::UnsupportedPlatform => PortOutcome::Unknown(UnknownReason::Unsupported),
        InstallerRootError::ReceiptMismatch
        | InstallerRootError::IdentityMismatch
        | InstallerRootError::Indeterminate => PortOutcome::Unknown(UnknownReason::Indeterminate),
        InstallerRootError::InvalidPath | InstallerRootError::MissingParent => {
            PortOutcome::Error(PortError::InvalidPath)
        }
        InstallerRootError::NotElevated => PortOutcome::Error(PortError::Provider(ProviderError {
            code: ProviderErrorCode::PermissionDenied,
            retryable: false,
        })),
        InstallerRootError::ReparsePoint | InstallerRootError::SecurityMismatch => {
            PortOutcome::Error(PortError::Provider(ProviderError {
                code: ProviderErrorCode::Failed,
                retryable: false,
            }))
        }
    }
}

mod transaction_store_private {
    use super::{InstallationError, InstallationTransaction, sha256_hex};

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct TransactionVersion {
        pub revision: u64,
        pub checksum: String,
    }

    impl TransactionVersion {
        pub fn of(transaction: &InstallationTransaction) -> Result<Self, InstallationError> {
            transaction.validate()?;
            let bytes = serde_json::to_vec(transaction).map_err(|error| {
                InstallationError::CorruptRegistry {
                    reason: error.to_string(),
                }
            })?;
            Ok(Self {
                revision: transaction.revision,
                checksum: sha256_hex(&bytes),
            })
        }
    }

    pub trait Sealed {
        fn compare_and_save(
            &mut self,
            expected: TransactionVersion,
            transaction: &InstallationTransaction,
        ) -> Result<(), InstallationError>;
    }
}

use transaction_store_private::TransactionVersion;

/// Durable read/create boundary for installation transactions.
///
/// The trait is sealed so arbitrary implementations cannot participate in the
/// coordinator's private compare-and-save capability:
///
/// ```compile_fail
/// use eliot_installation::{
///     InstallationError, InstallationTransaction, InstallationTransactionStore,
/// };
/// use eliot_platform::PlatformHandle;
///
/// struct ForgingStore;
/// impl InstallationTransactionStore for ForgingStore {
///     fn create_planned(
///         &mut self,
///         _: &InstallationTransaction,
///     ) -> Result<(), InstallationError> { Ok(()) }
///     fn load(
///         &self,
///         _: &PlatformHandle,
///     ) -> Result<Option<InstallationTransaction>, InstallationError> { Ok(None) }
/// }
/// ```
///
/// ```compile_fail
/// use eliot_installation::{InstallationTransaction, RedbInstallationTransactionStore};
///
/// fn overwrite(
///     store: &mut RedbInstallationTransactionStore,
///     transaction: &InstallationTransaction,
/// ) {
///     store.compare_and_save(1, transaction);
/// }
/// ```
pub trait InstallationTransactionStore: transaction_store_private::Sealed + Send {
    /// Creates a constructor-produced v3 `Planned`/`Pending` transaction.
    fn create_planned(
        &mut self,
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError>;

    /// Loads one exact durable transaction.
    fn load(
        &self,
        transaction_id: &PlatformHandle,
    ) -> Result<Option<InstallationTransaction>, InstallationError>;
}

/// Result of one coordinator step.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationStepOutcome {
    /// The effect was observed and the transaction advanced.
    Applied {
        /// Durable stage reached after the observed effect.
        stage: InstallationStage,
        /// Evidence references proving the effect postcondition.
        evidence_refs: Vec<PlatformHandle>,
    },
    /// The effect changed an object but complete postcondition evidence is absent.
    RollbackRequired {
        /// Evidence references that must be reconciled before rollback.
        pending_refs: Vec<PlatformHandle>,
    },
    /// Rollback itself is indeterminate and the transaction is quarantined.
    Quarantined {
        /// External identities still requiring operator reconciliation.
        pending_refs: Vec<PlatformHandle>,
    },
    /// The effect could not be admitted before changing an external object.
    Rejected,
}

/// Coordinates one durable installation transaction without owning platform mechanics.
pub struct InstallationCoordinator<P, S> {
    port: P,
    store: S,
}

impl<P, S> InstallationCoordinator<P, S>
where
    P: InstallationEffectPort,
    S: InstallationTransactionStore,
{
    /// Creates a coordinator around one platform effect port and durable store.
    #[must_use]
    pub const fn new(port: P, store: S) -> Self {
        Self { port, store }
    }

    /// Borrows the underlying effect port for composition or inspection.
    #[must_use]
    pub const fn port(&self) -> &P {
        &self.port
    }

    /// Borrows the underlying durable store.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Drives exactly one effect through durable intent and authoritative readback.
    #[allow(
        clippy::too_many_lines,
        reason = "ordered crash-window transitions remain in one auditable coordinator boundary"
    )]
    pub fn drive_effect(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        let mut transaction = self.store.load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        transaction.validate()?;
        let Some(index) = transaction.effect_progress.iter().position(|progress| {
            !matches!(
                progress.state,
                InstallationEffectProgressState::Applied { .. }
            )
        }) else {
            return Ok(InstallationStepOutcome::Applied {
                stage: transaction.stage,
                evidence_refs: transaction.observed_postconditions.clone(),
            });
        };
        let attempt = match transaction.effect_progress[index].state {
            InstallationEffectProgressState::Pending => 1,
            InstallationEffectProgressState::IntentCommitted { attempt, .. } => attempt,
            InstallationEffectProgressState::Unknown { ref pending_ref } => {
                return Ok(InstallationStepOutcome::RollbackRequired {
                    pending_refs: vec![pending_ref.clone()],
                });
            }
            InstallationEffectProgressState::Applied { .. } => unreachable!(),
        };
        if matches!(
            transaction.installer_effects[index],
            InstallerEffectPlan::RegisterService { .. }
        ) && transaction.effect_progress[index]
            .registration_nonce
            .is_none()
            && matches!(
                &transaction.effect_progress[index].state,
                InstallationEffectProgressState::Pending
            )
        {
            let expected = TransactionVersion::of(&transaction)?;
            let provisional = effect_request(
                &transaction,
                index,
                attempt,
                InstallationEffectAction::Apply,
                None,
            )?;
            let nonce = match self.port.fresh_service_registration_nonce(&provisional) {
                PortOutcome::Known(nonce) => nonce,
                other => return self.persist_unknown(transaction, index, port_pending(other)),
            };
            sha256_handle(&nonce, "effect.registration_nonce")?;
            transaction.effect_progress[index].registration_nonce = Some(nonce);
            increment_revision(&mut transaction)?;
            transaction.validate()?;
            self.store.compare_and_save(expected, &transaction)?;
        }
        let mut request = effect_request(
            &transaction,
            index,
            attempt,
            InstallationEffectAction::Apply,
            None,
        )?;
        let state = transaction.effect_progress[index].state.clone();
        let was_intent = matches!(
            state,
            InstallationEffectProgressState::IntentCommitted { .. }
        );
        if was_intent
            && matches!(
                transaction.installer_effects[index],
                InstallerEffectPlan::ProvisionStoreCredential { .. }
            )
            && transaction.effect_progress[index]
                .ownership_secret
                .as_ref()
                .is_some_and(|ownership| {
                    ownership.create_disposition == InstallationCreateDisposition::NotAttempted
                })
        {
            let disposition = match self.port.provision_ownership_secret(&request) {
                PortOutcome::Known(disposition) => disposition,
                other => return self.persist_unknown(transaction, index, port_pending(other)),
            };
            if disposition != InstallationCreateDisposition::Created {
                return self.persist_unknown(
                    transaction,
                    index,
                    PlatformHandle::new("mismatch:credential-key-not-created")
                        .map_err(|error| platform_error(&error))?,
                );
            }
            let expected = TransactionVersion::of(&transaction)?;
            transaction.effect_progress[index]
                .ownership_secret
                .as_mut()
                .ok_or(InstallationError::IdentityConflict)?
                .create_disposition = disposition;
            increment_revision(&mut transaction)?;
            transaction.validate()?;
            self.store.compare_and_save(expected, &transaction)?;
            request = effect_request(
                &transaction,
                index,
                attempt,
                InstallationEffectAction::Apply,
                None,
            )?;
        }
        let observation = match state {
            InstallationEffectProgressState::Pending => match self.port.inspect(&request) {
                PortOutcome::Known(observation) => observation,
                other => return self.persist_unknown(transaction, index, port_pending(other)),
            },
            InstallationEffectProgressState::IntentCommitted { intent_digest, .. } => {
                if request.intent_digest()? != intent_digest {
                    return self.persist_unknown(
                        transaction,
                        index,
                        PlatformHandle::new("mismatch:intent-digest")
                            .map_err(|error| platform_error(&error))?,
                    );
                }
                match self.port.reconcile(&request) {
                    PortOutcome::Known(observation) => observation,
                    other => return self.persist_unknown(transaction, index, port_pending(other)),
                }
            }
            _ => unreachable!(),
        };
        observation.validate_for_effect(&transaction.installer_effects[index])?;
        match observation {
            InstallationEffectObservation::Matching {
                disposition,
                external_identity,
                evidence,
                postcondition_digest,
                credential_receipt,
            } => {
                if !was_intent {
                    if disposition != InstallationEffectDisposition::PreexistingMatching {
                        return self.persist_unknown(
                            transaction,
                            index,
                            PlatformHandle::new("mismatch:uncommitted-created-disposition")
                                .map_err(|error| platform_error(&error))?,
                        );
                    }
                } else if disposition == InstallationEffectDisposition::CreatedByTransaction
                    && transaction.effect_progress[index]
                        .ownership_secret
                        .as_ref()
                        .is_none_or(|ownership| {
                            ownership.create_disposition != InstallationCreateDisposition::Created
                        })
                {
                    return self.persist_unknown(
                        transaction,
                        index,
                        PlatformHandle::new("mismatch:created-without-durable-create-disposition")
                            .map_err(|error| platform_error(&error))?,
                    );
                } else if was_intent
                    && disposition == InstallationEffectDisposition::PreexistingMatching
                    && transaction.effect_progress[index]
                        .ownership_secret
                        .is_some()
                {
                    return self.persist_unknown(
                        transaction,
                        index,
                        PlatformHandle::new("mismatch:preexisting-after-intent")
                            .map_err(|error| platform_error(&error))?,
                    );
                }
                self.persist_applied(
                    transaction,
                    index,
                    disposition,
                    external_identity,
                    evidence,
                    postcondition_digest,
                    credential_receipt,
                )
            }
            InstallationEffectObservation::Mismatch { pending_ref } => {
                self.persist_unknown(transaction, index, pending_ref)
            }
            InstallationEffectObservation::Absent {
                observed_precondition,
                evidence: _,
            } => {
                let snapshot_matches_effect = match &transaction.installer_effects[index] {
                    InstallerEffectPlan::ProvisionStoreCredential { .. } => {
                        observed_precondition.credential_snapshot.is_some()
                            && observed_precondition.os_snapshot.is_none()
                    }
                    InstallerEffectPlan::RegisterService { .. } => true,
                    _ => {
                        observed_precondition.os_snapshot.is_some()
                            && observed_precondition.credential_snapshot.is_none()
                    }
                };
                if observed_precondition.evidence_refs != request.precondition.evidence_refs
                    || !snapshot_matches_effect
                    || (was_intent && observed_precondition != request.precondition)
                {
                    return self.persist_unknown(
                        transaction,
                        index,
                        PlatformHandle::new("mismatch:precondition")
                            .map_err(|error| platform_error(&error))?,
                    );
                }
                let next_attempt = if was_intent {
                    attempt
                        .checked_add(1)
                        .ok_or_else(|| InstallationError::InvalidField {
                            field: "effect.attempt".to_owned(),
                            reason: "overflow".to_owned(),
                        })?
                } else {
                    attempt
                };
                let expected = TransactionVersion::of(&transaction)?;
                if !was_intent {
                    transaction.effect_progress[index].admitted_precondition =
                        Some(observed_precondition);
                    if matches!(
                        transaction.installer_effects[index],
                        InstallerEffectPlan::CreateRoot { .. }
                            | InstallerEffectPlan::ProvisionStoreCredential { .. }
                    ) {
                        let reference = match self.port.fresh_ownership_secret_reference(&request) {
                            PortOutcome::Known(reference) => reference,
                            other => {
                                return self.persist_unknown(
                                    transaction,
                                    index,
                                    port_pending(other),
                                );
                            }
                        };
                        transaction.effect_progress[index].ownership_secret =
                            Some(InstallationOwnershipSecret {
                                reference,
                                create_disposition: InstallationCreateDisposition::NotAttempted,
                                lifecycle: InstallationSecretLifecycle::Active,
                            });
                        if matches!(
                            transaction.installer_effects[index],
                            InstallerEffectPlan::ProvisionStoreCredential { .. }
                        ) {
                            transaction.effect_progress[index].store_credential =
                                Some(StoreCredentialProgress {
                                    lifecycle: StoreCredentialLifecycle::Active,
                                    receipt: None,
                                });
                        }
                    }
                }
                let mut request = effect_request(
                    &transaction,
                    index,
                    next_attempt,
                    InstallationEffectAction::Apply,
                    None,
                )?;
                transaction.effect_progress[index].state =
                    InstallationEffectProgressState::IntentCommitted {
                        attempt: next_attempt,
                        intent_digest: request.intent_digest()?,
                    };
                increment_revision(&mut transaction)?;
                transaction.validate()?;
                self.store.compare_and_save(expected, &transaction)?;
                if matches!(
                    transaction.installer_effects[index],
                    InstallerEffectPlan::ProvisionStoreCredential { .. }
                ) && transaction.effect_progress[index]
                    .ownership_secret
                    .as_ref()
                    .is_some_and(|ownership| {
                        ownership.create_disposition == InstallationCreateDisposition::NotAttempted
                    })
                {
                    let disposition = match self.port.provision_ownership_secret(&request) {
                        PortOutcome::Known(disposition) => disposition,
                        other => {
                            return self.persist_unknown(transaction, index, port_pending(other));
                        }
                    };
                    if disposition != InstallationCreateDisposition::Created {
                        return self.persist_unknown(
                            transaction,
                            index,
                            PlatformHandle::new("mismatch:credential-key-not-created")
                                .map_err(|error| platform_error(&error))?,
                        );
                    }
                    let expected = TransactionVersion::of(&transaction)?;
                    transaction.effect_progress[index]
                        .ownership_secret
                        .as_mut()
                        .ok_or(InstallationError::IdentityConflict)?
                        .create_disposition = disposition;
                    increment_revision(&mut transaction)?;
                    transaction.validate()?;
                    self.store.compare_and_save(expected, &transaction)?;
                    request = effect_request(
                        &transaction,
                        index,
                        next_attempt,
                        InstallationEffectAction::Apply,
                        None,
                    )?;
                }
                let execution = match self.port.execute(&request) {
                    PortOutcome::Known(execution) => execution,
                    other => return self.persist_unknown(transaction, index, port_pending(other)),
                };
                handles(&execution.evidence, "effect.execution.evidence", false)?;
                match (
                    &transaction.installer_effects[index],
                    execution.create_disposition,
                ) {
                    (InstallerEffectPlan::CreateRoot { .. }, Some(disposition)) => {
                        let expected = TransactionVersion::of(&transaction)?;
                        let Some(ownership) =
                            transaction.effect_progress[index].ownership_secret.as_mut()
                        else {
                            return self.persist_unknown(
                                transaction,
                                index,
                                PlatformHandle::new("mismatch:missing-ownership-secret")
                                    .map_err(|error| platform_error(&error))?,
                            );
                        };
                        ownership.create_disposition = disposition;
                        increment_revision(&mut transaction)?;
                        transaction.validate()?;
                        self.store.compare_and_save(expected, &transaction)?;
                        request = effect_request(
                            &transaction,
                            index,
                            next_attempt,
                            InstallationEffectAction::Apply,
                            None,
                        )?;
                    }
                    (InstallerEffectPlan::CreateRoot { .. }, None)
                    | (
                        InstallerEffectPlan::ApplyAcl { .. }
                        | InstallerEffectPlan::ProvisionStoreCredential { .. },
                        Some(_),
                    ) => {
                        return self.persist_unknown(
                            transaction,
                            index,
                            PlatformHandle::new("mismatch:create-disposition-shape")
                                .map_err(|error| platform_error(&error))?,
                        );
                    }
                    (
                        InstallerEffectPlan::ApplyAcl { .. }
                        | InstallerEffectPlan::RegisterService { .. }
                        | InstallerEffectPlan::ProvisionStoreCredential { .. },
                        None,
                    )
                    | (InstallerEffectPlan::RegisterService { .. }, Some(_)) => {}
                }
                if matches!(
                    transaction.installer_effects[index],
                    InstallerEffectPlan::ProvisionStoreCredential { .. }
                ) {
                    let Some(receipt) = execution.credential_receipt else {
                        return self.persist_unknown(
                            transaction,
                            index,
                            PlatformHandle::new("mismatch:credential-execution-receipt")
                                .map_err(|error| platform_error(&error))?,
                        );
                    };
                    let expected = TransactionVersion::of(&transaction)?;
                    transaction.effect_progress[index]
                        .store_credential
                        .as_mut()
                        .ok_or(InstallationError::IdentityConflict)?
                        .receipt = Some(receipt);
                    increment_revision(&mut transaction)?;
                    transaction.validate()?;
                    self.store.compare_and_save(expected, &transaction)?;
                    request = effect_request(
                        &transaction,
                        index,
                        next_attempt,
                        InstallationEffectAction::Apply,
                        None,
                    )?;
                } else if execution.credential_receipt.is_some() {
                    return self.persist_unknown(
                        transaction,
                        index,
                        PlatformHandle::new("mismatch:unexpected-credential-receipt")
                            .map_err(|error| platform_error(&error))?,
                    );
                }
                let reconciled = match self.port.reconcile(&request) {
                    PortOutcome::Known(observation) => observation,
                    other => return self.persist_unknown(transaction, index, port_pending(other)),
                };
                reconciled.validate_for_effect(&transaction.installer_effects[index])?;
                match reconciled {
                    InstallationEffectObservation::Matching {
                        disposition,
                        external_identity,
                        evidence,
                        postcondition_digest,
                        credential_receipt,
                    } => {
                        let ownership =
                            transaction.effect_progress[index].ownership_secret.as_ref();
                        let authorized = match disposition {
                            InstallationEffectDisposition::CreatedByTransaction => {
                                ownership.is_some_and(|ownership| {
                                    ownership.create_disposition
                                        == InstallationCreateDisposition::Created
                                }) || (matches!(
                                    transaction.installer_effects[index],
                                    InstallerEffectPlan::RegisterService { .. }
                                ) && transaction.effect_progress[index]
                                    .registration_nonce
                                    .is_some())
                            }
                            InstallationEffectDisposition::PreexistingMatching => {
                                ownership.is_none()
                            }
                        };
                        if authorized {
                            self.persist_applied(
                                transaction,
                                index,
                                disposition,
                                external_identity,
                                evidence,
                                postcondition_digest,
                                credential_receipt,
                            )
                        } else {
                            self.persist_unknown(
                                transaction,
                                index,
                                PlatformHandle::new(
                                    "mismatch:unauthorized-post-execute-disposition",
                                )
                                .map_err(|error| platform_error(&error))?,
                            )
                        }
                    }
                    InstallationEffectObservation::Absent {
                        observed_precondition,
                        ..
                    } if observed_precondition == request.precondition => {
                        // The durable intent remains authoritative. A later
                        // drive must reconcile it again and may retry only
                        // after proving the same absence and precondition.
                        Ok(InstallationStepOutcome::Rejected)
                    }
                    InstallationEffectObservation::Absent { .. } => self.persist_unknown(
                        transaction,
                        index,
                        PlatformHandle::new("mismatch:post-execute-precondition")
                            .map_err(|error| platform_error(&error))?,
                    ),
                    InstallationEffectObservation::Mismatch { pending_ref } => {
                        self.persist_unknown(transaction, index, pending_ref)
                    }
                }
            }
        }
    }

    /// Rolls back only exact identities proven `CreatedByTransaction`.
    #[allow(
        clippy::needless_continue,
        clippy::too_many_lines,
        reason = "one rollback boundary preserves reverse-order root and secret lifecycle proofs"
    )]
    pub fn rollback(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        let mut transaction = self.store.load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        transaction.validate()?;
        if transaction.stage != InstallationStage::RollbackRequired {
            return Err(InstallationError::IllegalTransition {
                from: transaction.stage,
                to: InstallationStage::RolledBack,
            });
        }
        let unreconciled = transaction
            .effect_progress
            .iter()
            .find_map(|progress| match &progress.state {
                InstallationEffectProgressState::Unknown { pending_ref } => {
                    Some(pending_ref.clone())
                }
                InstallationEffectProgressState::IntentCommitted { intent_digest, .. } => {
                    Some(intent_digest.clone())
                }
                InstallationEffectProgressState::Pending
                | InstallationEffectProgressState::Applied { .. } => None,
            });
        if let Some(pending_ref) = unreconciled {
            return self.persist_quarantined(transaction, pending_ref);
        }
        let mut credential_absence_refs = Vec::new();
        for index in (0..transaction.effect_progress.len()).rev() {
            let InstallationEffectProgressState::Applied {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                ref external_identity,
                ..
            } = transaction.effect_progress[index].state
            else {
                continue;
            };
            let mut request = effect_request(
                &transaction,
                index,
                1,
                InstallationEffectAction::Rollback,
                Some(external_identity.clone()),
            )?;
            let observed = match self.port.reconcile(&request) {
                PortOutcome::Known(observed) => {
                    observed.validate()?;
                    observed
                }
                other => return self.persist_quarantined(transaction, port_pending(other)),
            };
            match observed {
                InstallationEffectObservation::Absent { evidence, .. } => {
                    if matches!(
                        transaction.installer_effects[index],
                        InstallerEffectPlan::ProvisionStoreCredential { .. }
                    ) {
                        if transaction.effect_progress[index]
                            .store_credential
                            .as_ref()
                            .is_some_and(|credential| {
                                credential.lifecycle
                                    == StoreCredentialLifecycle::DeleteIntentCommitted
                            })
                        {
                            let expected = TransactionVersion::of(&transaction)?;
                            transaction.effect_progress[index]
                                .store_credential
                                .as_mut()
                                .ok_or(InstallationError::IdentityConflict)?
                                .lifecycle = StoreCredentialLifecycle::DeleteExecuted;
                            increment_revision(&mut transaction)?;
                            transaction.validate()?;
                            self.store.compare_and_save(expected, &transaction)?;
                        }
                        credential_absence_refs.extend(evidence);
                    }
                    continue;
                }
                InstallationEffectObservation::Matching {
                    disposition: InstallationEffectDisposition::CreatedByTransaction,
                    ref external_identity,
                    ..
                } if request.expected_external_identity.as_ref() == Some(external_identity) => {
                    if matches!(
                        transaction.installer_effects[index],
                        InstallerEffectPlan::ProvisionStoreCredential { .. }
                    ) {
                        let expected = TransactionVersion::of(&transaction)?;
                        let credential = transaction.effect_progress[index]
                            .store_credential
                            .as_mut()
                            .ok_or(InstallationError::IdentityConflict)?;
                        match credential.lifecycle {
                            StoreCredentialLifecycle::Active => {
                                if !credential
                                    .lifecycle
                                    .can_transition(StoreCredentialLifecycle::DeleteIntentCommitted)
                                {
                                    return Err(InstallationError::IdentityConflict);
                                }
                                credential.lifecycle =
                                    StoreCredentialLifecycle::DeleteIntentCommitted;
                                increment_revision(&mut transaction)?;
                                transaction.validate()?;
                                self.store.compare_and_save(expected, &transaction)?;
                                request = effect_request(
                                    &transaction,
                                    index,
                                    1,
                                    InstallationEffectAction::Rollback,
                                    Some(external_identity.clone()),
                                )?;
                            }
                            StoreCredentialLifecycle::DeleteIntentCommitted => {}
                            StoreCredentialLifecycle::DeleteExecuted
                            | StoreCredentialLifecycle::Deleted => {
                                return self.persist_quarantined(
                                    transaction,
                                    PlatformHandle::new("mismatch:credential-delete-lifecycle")
                                        .map_err(|error| platform_error(&error))?,
                                );
                            }
                        }
                    }
                    let credential_effect = matches!(
                        transaction.installer_effects[index],
                        InstallerEffectPlan::ProvisionStoreCredential { .. }
                    );
                    match self.port.execute(&request) {
                        PortOutcome::Known(InstallationEffectExecution {
                            create_disposition: None,
                            ..
                        }) => {}
                        PortOutcome::Unknown(reason) if credential_effect => {
                            return Ok(InstallationStepOutcome::RollbackRequired {
                                pending_refs: vec![port_pending(PortOutcome::<()>::Unknown(
                                    reason,
                                ))],
                            });
                        }
                        other => {
                            return self.persist_quarantined(transaction, port_pending(other));
                        }
                    }
                    if matches!(
                        transaction.installer_effects[index],
                        InstallerEffectPlan::ProvisionStoreCredential { .. }
                    ) {
                        let expected = TransactionVersion::of(&transaction)?;
                        let credential = transaction.effect_progress[index]
                            .store_credential
                            .as_mut()
                            .ok_or(InstallationError::IdentityConflict)?;
                        if !credential
                            .lifecycle
                            .can_transition(StoreCredentialLifecycle::DeleteExecuted)
                        {
                            return Err(InstallationError::IdentityConflict);
                        }
                        credential.lifecycle = StoreCredentialLifecycle::DeleteExecuted;
                        increment_revision(&mut transaction)?;
                        transaction.validate()?;
                        self.store.compare_and_save(expected, &transaction)?;
                        request = effect_request(
                            &transaction,
                            index,
                            1,
                            InstallationEffectAction::Rollback,
                            Some(external_identity.clone()),
                        )?;
                    }
                    let reconciled = match self.port.reconcile(&request) {
                        PortOutcome::Known(reconciled) => {
                            reconciled.validate()?;
                            reconciled
                        }
                        other => return self.persist_quarantined(transaction, port_pending(other)),
                    };
                    match reconciled {
                        InstallationEffectObservation::Absent { evidence, .. } => {
                            if matches!(
                                transaction.installer_effects[index],
                                InstallerEffectPlan::ProvisionStoreCredential { .. }
                            ) {
                                credential_absence_refs.extend(evidence);
                            }
                            continue;
                        }
                        other => {
                            return self
                                .persist_quarantined(transaction, observation_pending(&other));
                        }
                    }
                }
                other => {
                    return self.persist_quarantined(transaction, observation_pending(&other));
                }
            }
        }
        let mut secret_absence_refs = Vec::new();
        for index in 0..transaction.effect_progress.len() {
            let Some(ownership) = transaction.effect_progress[index].ownership_secret.as_ref()
            else {
                continue;
            };
            let secret_reference = ownership.reference.clone();
            if ownership.lifecycle == InstallationSecretLifecycle::Active {
                let expected = TransactionVersion::of(&transaction)?;
                transaction.effect_progress[index]
                    .ownership_secret
                    .as_mut()
                    .ok_or(InstallationError::IdentityConflict)?
                    .lifecycle = InstallationSecretLifecycle::DeleteIntentCommitted;
                increment_revision(&mut transaction)?;
                transaction.validate()?;
                self.store.compare_and_save(expected, &transaction)?;
            }
            let external_identity = match &transaction.effect_progress[index].state {
                InstallationEffectProgressState::Applied {
                    disposition: InstallationEffectDisposition::CreatedByTransaction,
                    external_identity,
                    ..
                } => external_identity.clone(),
                _ => {
                    return self.persist_quarantined(
                        transaction,
                        PlatformHandle::new("mismatch:secret-without-created-effect")
                            .map_err(|error| platform_error(&error))?,
                    );
                }
            };
            let request = effect_request(
                &transaction,
                index,
                1,
                InstallationEffectAction::Rollback,
                Some(external_identity),
            )?;
            let absent = match self.port.ownership_secret_absent(&request) {
                PortOutcome::Known(absent) => absent,
                other => {
                    return Ok(InstallationStepOutcome::RollbackRequired {
                        pending_refs: vec![port_pending(other)],
                    });
                }
            };
            if !absent {
                match self.port.delete_ownership_secret(&request) {
                    PortOutcome::Known(()) => {}
                    other => {
                        return Ok(InstallationStepOutcome::RollbackRequired {
                            pending_refs: vec![port_pending(other)],
                        });
                    }
                }
                match self.port.ownership_secret_absent(&request) {
                    PortOutcome::Known(true) => {}
                    other => {
                        return Ok(InstallationStepOutcome::RollbackRequired {
                            pending_refs: vec![port_pending(other)],
                        });
                    }
                }
            }
            secret_absence_refs.push(ownership_secret_absence_evidence(&secret_reference));
        }
        let expected = TransactionVersion::of(&transaction)?;
        transaction.pending_external_changes.clear();
        transaction.stage = InstallationStage::RolledBack;
        for progress in &mut transaction.effect_progress {
            if let Some(ownership) = &mut progress.ownership_secret {
                ownership.lifecycle = InstallationSecretLifecycle::Deleted;
            }
            if let Some(credential) = &mut progress.store_credential {
                if !credential
                    .lifecycle
                    .can_transition(StoreCredentialLifecycle::Deleted)
                {
                    return Err(InstallationError::IdentityConflict);
                }
                credential.lifecycle = StoreCredentialLifecycle::Deleted;
            }
        }
        transaction
            .completed_stage_refs
            .extend(credential_absence_refs);
        transaction.completed_stage_refs.extend(secret_absence_refs);
        transaction.completed_stage_refs.push(
            PlatformHandle::new("rollback:authoritative-absence")
                .map_err(|error| platform_error(&error))?,
        );
        increment_revision(&mut transaction)?;
        transaction.validate()?;
        self.store.compare_and_save(expected, &transaction)?;
        Ok(InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack,
            evidence_refs: transaction.completed_stage_refs,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the persisted applied receipt is one atomic effect record"
    )]
    fn persist_applied(
        &mut self,
        mut transaction: InstallationTransaction,
        index: usize,
        disposition: InstallationEffectDisposition,
        external_identity: PlatformHandle,
        evidence: Vec<PlatformHandle>,
        postcondition_digest: PlatformHandle,
        credential_receipt: Option<CredentialAccessReceipt>,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        let expected = TransactionVersion::of(&transaction)?;
        if let Some(receipt) = credential_receipt {
            transaction.effect_progress[index]
                .store_credential
                .as_mut()
                .ok_or(InstallationError::IdentityConflict)?
                .receipt = Some(receipt);
        }
        transaction.effect_progress[index].state = InstallationEffectProgressState::Applied {
            disposition,
            external_identity,
            evidence: evidence.clone(),
            postcondition_digest,
        };
        transaction.observed_postconditions.extend(evidence.clone());
        increment_revision(&mut transaction)?;
        transaction.validate()?;
        self.store.compare_and_save(expected, &transaction)?;
        Ok(InstallationStepOutcome::Applied {
            stage: transaction.stage,
            evidence_refs: evidence,
        })
    }

    fn persist_unknown(
        &mut self,
        mut transaction: InstallationTransaction,
        index: usize,
        pending_ref: PlatformHandle,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        let expected = TransactionVersion::of(&transaction)?;
        transaction.effect_progress[index].state = InstallationEffectProgressState::Unknown {
            pending_ref: pending_ref.clone(),
        };
        transaction.pending_external_changes = vec![pending_ref.clone()];
        transaction.stage = InstallationStage::RollbackRequired;
        increment_revision(&mut transaction)?;
        transaction.validate()?;
        self.store.compare_and_save(expected, &transaction)?;
        Ok(InstallationStepOutcome::RollbackRequired {
            pending_refs: vec![pending_ref],
        })
    }

    fn persist_quarantined(
        &mut self,
        mut transaction: InstallationTransaction,
        pending_ref: PlatformHandle,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        let expected = TransactionVersion::of(&transaction)?;
        transaction.pending_external_changes = vec![pending_ref.clone()];
        transaction.stage = InstallationStage::Quarantined;
        increment_revision(&mut transaction)?;
        transaction.validate()?;
        self.store.compare_and_save(expected, &transaction)?;
        Ok(InstallationStepOutcome::Quarantined {
            pending_refs: vec![pending_ref],
        })
    }
}

/// Coordinator-owned production Windows installation composition.
///
/// The inner Windows effect port is private and is never exposed, so safe code
/// cannot execute root or Credential Manager mutations outside the durable
/// coordinator transition.
pub struct WindowsInstallationCoordinator<S> {
    inner: InstallationCoordinator<WindowsInstallationEffectPort, S>,
}

impl<S> WindowsInstallationCoordinator<S>
where
    S: InstallationTransactionStore,
{
    /// Constructs the only production Windows root-effect composition.
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self {
            inner: InstallationCoordinator::new(WindowsInstallationEffectPort::new(), store),
        }
    }

    /// Issues the non-secret Store credential target for a new installation
    /// plan.
    ///
    /// This is the normal installation-authority factory seam. The planner
    /// must retain the returned target in both the candidate launch manifest
    /// and its Store credential effect; it must not generate a replacement
    /// target through a Kernel activation or installer-root API.
    pub fn fresh_store_credential_target(&self) -> Result<PlatformHandle, InstallationError> {
        self.inner
            .port()
            .fresh_store_credential_target()
            .map_err(|error| InstallationError::Platform(error.to_string()))
    }

    /// Drives exactly one durable root/ACL effect.
    pub fn drive_effect(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        self.inner.drive_effect(transaction_id)
    }

    /// Rolls back exact transaction-created roots and terminally retires keys.
    pub fn rollback(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        self.inner.rollback(transaction_id)
    }

    /// Borrows only the durable store; the mutating port remains sealed.
    #[must_use]
    pub const fn store(&self) -> &S {
        self.inner.store()
    }
}

fn increment_revision(transaction: &mut InstallationTransaction) -> Result<(), InstallationError> {
    transaction.revision =
        transaction
            .revision
            .checked_add(1)
            .ok_or_else(|| InstallationError::InvalidField {
                field: "revision".to_owned(),
                reason: "overflow".to_owned(),
            })?;
    Ok(())
}

fn effect_request(
    transaction: &InstallationTransaction,
    index: usize,
    attempt: u32,
    action: InstallationEffectAction,
    expected_external_identity: Option<PlatformHandle>,
) -> Result<InstallationEffectRequest, InstallationError> {
    let plan = transaction
        .installer_effects
        .get(index)
        .ok_or(InstallationError::IdentityConflict)?
        .clone();
    let effect_id = plan.effect_id().clone();
    let change = transaction
        .planned_changes
        .iter()
        .find(|change| change.change_id == effect_id)
        .ok_or(InstallationError::IdentityConflict)?;
    let progress = transaction
        .effect_progress
        .get(index)
        .ok_or(InstallationError::IdentityConflict)?;
    let is_service = matches!(&plan, InstallerEffectPlan::RegisterService { .. });
    let request = InstallationEffectRequest {
        transaction_id: transaction.transaction_id.clone(),
        plan,
        profile: transaction.profile,
        installation_root: transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .installation_root
            .clone(),
        effect_id,
        attempt,
        plan_digest: transaction.installer_plan_digest.clone(),
        precondition: match &progress.admitted_precondition {
            Some(precondition) => precondition.clone(),
            None => InstallationEffectPrecondition::from_change(change)?,
        },
        ownership_secret: progress.ownership_secret.clone(),
        store_credential: progress.store_credential.clone(),
        action,
        expected_external_identity,
        service_bootstrap: is_service.then(|| InstallationServiceBootstrap {
            descriptor_path: transaction
                .candidate_manifest
                .runtime_launch
                .authority_descriptor_path
                .clone(),
            descriptor_digest: transaction
                .candidate_manifest
                .runtime_launch
                .authority_descriptor_digest
                .clone(),
            installation_id: transaction
                .candidate_manifest
                .runtime_launch
                .installation_epoch
                .installation
                .clone(),
            plan_generation: transaction
                .candidate_manifest
                .runtime_launch
                .authority_generation
                .value(),
        }),
        registration_nonce: progress.registration_nonce.clone(),
    };
    request.validate()?;
    Ok(request)
}

fn port_pending<T>(outcome: PortOutcome<T>) -> PlatformHandle {
    let value = match outcome {
        PortOutcome::Known(_) => "unknown:unexpected-known".to_owned(),
        PortOutcome::Unknown(reason) => format!("unknown:{reason:?}"),
        PortOutcome::Partial { missing, .. } => missing.first().map_or_else(
            || "unknown:partial".to_owned(),
            |value| value.as_str().to_owned(),
        ),
        PortOutcome::Error(error) => format!("error:{error}"),
    };
    PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
}

fn ownership_secret_absence_evidence(reference: &InstallationSecretReference) -> PlatformHandle {
    PlatformHandle::new(format!(
        "secret-absent:{}",
        sha256_hex(reference.target.as_str().as_bytes())
    ))
    .unwrap_or_else(|_| unreachable!())
}

fn observation_pending(observation: &InstallationEffectObservation) -> PlatformHandle {
    match observation {
        InstallationEffectObservation::Mismatch { pending_ref } => pending_ref.clone(),
        InstallationEffectObservation::Matching {
            external_identity, ..
        } => external_identity.clone(),
        InstallationEffectObservation::Absent { evidence, .. } => {
            evidence.first().cloned().unwrap_or_else(|| unreachable!())
        }
    }
}

/// A read-only adapter-backed inspection helper.
pub struct InstallationInspector<P> {
    port: P,
}

impl<P> InstallationInspector<P>
where
    P: InstallationPort,
{
    /// Creates an inspector around the provider-neutral installation port.
    #[must_use]
    pub const fn new(port: P) -> Self {
        Self { port }
    }

    /// Inspects exact components without treating presence as admission.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the public inspection façade preserves its owned request contract"
    )]
    pub fn inspect(
        &mut self,
        request: InstallationRequest,
    ) -> Result<InstallationObservation, InstallationError> {
        request.validate().map_err(|error| platform_error(&error))?;
        let outcome = self.port.execute(&request);
        match outcome {
            PortOutcome::Known(observation) => Ok(observation),
            PortOutcome::Partial { .. } => Err(InstallationError::IncompleteObservation(
                "installation inspection was partial".to_owned(),
            )),
            PortOutcome::Unknown(_) => Err(InstallationError::UnknownOutcome {
                stage: InstallationStage::Planned,
            }),
            PortOutcome::Error(error) => Err(platform_error(&error)),
        }
    }

    /// Borrows the underlying platform port.
    #[must_use]
    pub const fn port(&self) -> &P {
        &self.port
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    #[cfg(windows)]
    use eliot_platform_windows::UserOwnedRootLease;
    use eliot_platform_windows::{HostOwnerEpochCapability, HostOwnerLease};

    static NEXT_TRANSACTION_ROOT: AtomicU64 = AtomicU64::new(0);
    #[cfg(windows)]
    static PRODUCTION_INSTALLER_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn host_capability() -> HostOwnerEpochCapability {
        #[cfg(not(windows))]
        {
            HostOwnerLease::unsupported_platform_test_capability()
        }
        #[cfg(windows)]
        {
            let installation = test_handle(format!(
                "test-host-owner-{}",
                NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            Box::leak(Box::new(
                HostOwnerLease::acquire(&installation)
                    .unwrap_or_else(|error| panic!("test Host owner lease: {error}")),
            ))
            .activation_capability()
        }
    }

    #[cfg(windows)]
    fn live_host_capability() -> (HostOwnerLease, HostOwnerEpochCapability) {
        let installation = test_handle(format!(
            "test-host-owner-live-{}",
            NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let lease = HostOwnerLease::acquire(&installation)
            .unwrap_or_else(|error| panic!("test Host owner lease: {error}"));
        let capability = lease.activation_capability();
        (lease, capability)
    }

    #[cfg(windows)]
    fn pending_registry_for_owner_gate() -> (ApprovedGenerationRegistry, InstallationTransaction) {
        let transaction = registering_transaction();
        let mut registry = ApprovedGenerationRegistry::new();
        must(registry.stage_pending_activation(
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            transaction.candidate_manifest.clone(),
            test_handle("approval:owner-gate"),
        ));
        (registry, transaction)
    }

    #[cfg(windows)]
    fn assert_registry_mutations_rejected_after_owner_shutdown(
        registry: &mut ApprovedGenerationRegistry,
        transaction: &InstallationTransaction,
        capability: &HostOwnerEpochCapability,
    ) {
        let before = registry.clone();
        assert!(
            registry
                .claim_pending_activation(
                    capability,
                    &transaction.transaction_id,
                    &transaction.installer_plan_digest,
                    &transaction.candidate_manifest.generation,
                )
                .is_err()
        );
        assert_eq!(registry, &before);

        let before = registry.clone();
        assert!(
            registry
                .commit_pending_activation(
                    capability,
                    &transaction.transaction_id,
                    &transaction.installer_plan_digest,
                    &transaction.candidate_manifest.generation,
                )
                .is_err()
        );
        assert_eq!(registry, &before);

        let before = registry.clone();
        assert!(
            registry
                .mark_pending_recovery(
                    capability,
                    &transaction.transaction_id,
                    &transaction.installer_plan_digest,
                    "owner lease is no longer live",
                )
                .is_err()
        );
        assert_eq!(registry, &before);

        let before = registry.clone();
        assert!(
            registry
                .abort_pending_activation(
                    capability,
                    &transaction.transaction_id,
                    &transaction.installer_plan_digest,
                )
                .is_err()
        );
        assert_eq!(registry, &before);
    }

    #[derive(Clone, Default)]
    struct SharedStore {
        state: Arc<Mutex<Option<InstallationTransaction>>>,
        conflict_next: Arc<Mutex<bool>>,
    }

    impl InstallationTransactionStore for SharedStore {
        fn create_planned(
            &mut self,
            transaction: &InstallationTransaction,
        ) -> Result<(), InstallationError> {
            transaction.validate()?;
            if !transaction.is_constructor_planned() {
                return Err(InstallationError::InvalidField {
                    field: "transaction".to_owned(),
                    reason: "not constructor-planned".to_owned(),
                });
            }
            let mut state = self.state.lock().unwrap_or_else(|_| unreachable!());
            if state.is_some() {
                return Err(InstallationError::CompareAndSaveConflict {
                    expected: 0,
                    actual: transaction.revision,
                });
            }
            *state = Some(transaction.clone());
            Ok(())
        }

        fn load(
            &self,
            transaction_id: &PlatformHandle,
        ) -> Result<Option<InstallationTransaction>, InstallationError> {
            Ok(self
                .state
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .as_ref()
                .filter(|transaction| transaction.transaction_id == *transaction_id)
                .cloned())
        }
    }

    impl transaction_store_private::Sealed for SharedStore {
        fn compare_and_save(
            &mut self,
            expected: TransactionVersion,
            transaction: &InstallationTransaction,
        ) -> Result<(), InstallationError> {
            if std::mem::take(&mut *self.conflict_next.lock().unwrap_or_else(|_| unreachable!())) {
                return Err(InstallationError::CompareAndSaveConflict {
                    expected: expected.revision,
                    actual: expected.revision + 1,
                });
            }
            let mut state = self.state.lock().unwrap_or_else(|_| unreachable!());
            let current = state
                .as_ref()
                .ok_or_else(|| InstallationError::TransactionNotFound {
                    transaction_id: transaction.transaction_id.as_str().to_owned(),
                })?;
            let current_version = TransactionVersion::of(current)?;
            if current_version.revision != expected.revision {
                return Err(InstallationError::CompareAndSaveConflict {
                    expected: expected.revision,
                    actual: current_version.revision,
                });
            }
            if current_version.checksum != expected.checksum {
                return Err(InstallationError::IdentityConflict);
            }
            if transaction.revision != expected.revision + 1 {
                return Err(InstallationError::InvalidField {
                    field: "revision".to_owned(),
                    reason: "compare_and_save requires exactly one revision step".to_owned(),
                });
            }
            *state = Some(transaction.clone());
            Ok(())
        }
    }

    #[cfg(windows)]
    #[test]
    fn installation_authority_is_the_store_target_factory_seam() {
        let coordinator = WindowsInstallationCoordinator::new(SharedStore::default());
        let first = must(coordinator.fresh_store_credential_target());
        let second = must(coordinator.fresh_store_credential_target());
        assert!(validate_store_credential_target(first.as_str()).is_ok());
        assert!(validate_store_credential_target(second.as_str()).is_ok());
        assert_ne!(first, second);
    }

    struct FakeEffectPort {
        shared: SharedStore,
        inspections: VecDeque<PortOutcome<InstallationEffectObservation>>,
        reconciliations: VecDeque<PortOutcome<InstallationEffectObservation>>,
        execute_count: Arc<Mutex<usize>>,
        create_disposition: InstallationCreateDisposition,
        secret_absence: VecDeque<PortOutcome<bool>>,
        secret_deletes: VecDeque<PortOutcome<()>>,
        panic_reconcile_once: bool,
    }

    impl InstallationEffectPort for FakeEffectPort {
        fn fresh_ownership_secret_reference(
            &mut self,
            request: &InstallationEffectRequest,
        ) -> PortOutcome<InstallationSecretReference> {
            PortOutcome::Known(InstallationSecretReference {
                target: test_handle(format!(
                    "eliot/installer-root/v1/{}",
                    &sha256_hex(request.effect_id.as_str().as_bytes())[..32]
                )),
                expected_principal_sid: test_handle("S-1-5-21-1000"),
                scope: InstallationSecretScope::WindowsCredentialManagerCurrentUser,
            })
        }

        fn execute(
            &mut self,
            request: &InstallationEffectRequest,
        ) -> PortOutcome<InstallationEffectExecution> {
            let state = self
                .shared
                .load(&request.transaction_id)
                .unwrap_or_else(|_| unreachable!())
                .unwrap_or_else(|| unreachable!());
            assert!(state.effect_progress.iter().any(|progress| {
                if progress.effect_id != request.effect_id {
                    return false;
                }
                match request.action {
                    InstallationEffectAction::Apply => matches!(
                        progress.state,
                        InstallationEffectProgressState::IntentCommitted { attempt, .. }
                            if attempt == request.attempt
                    ),
                    InstallationEffectAction::Rollback => matches!(
                        &progress.state,
                        InstallationEffectProgressState::Applied {
                            disposition: InstallationEffectDisposition::CreatedByTransaction,
                            external_identity,
                            ..
                        } if request.expected_external_identity.as_ref() == Some(external_identity)
                    ),
                }
            }));
            *self.execute_count.lock().unwrap_or_else(|_| unreachable!()) += 1;
            PortOutcome::Known(InstallationEffectExecution {
                evidence: vec![test_handle("evidence:execute-ack")],
                create_disposition: (request.action == InstallationEffectAction::Apply
                    && matches!(request.plan, InstallerEffectPlan::CreateRoot { .. }))
                .then_some(self.create_disposition),
                credential_receipt: None,
            })
        }

        fn inspect(
            &mut self,
            _request: &InstallationEffectRequest,
        ) -> PortOutcome<InstallationEffectObservation> {
            self.inspections.pop_front().unwrap_or(PortOutcome::Unknown(
                eliot_platform::UnknownReason::Indeterminate,
            ))
        }

        fn reconcile(
            &mut self,
            _request: &InstallationEffectRequest,
        ) -> PortOutcome<InstallationEffectObservation> {
            assert!(
                !std::mem::take(&mut self.panic_reconcile_once),
                "simulated crash after external mutation"
            );
            self.reconciliations
                .pop_front()
                .unwrap_or(PortOutcome::Unknown(
                    eliot_platform::UnknownReason::Indeterminate,
                ))
        }

        fn delete_ownership_secret(
            &mut self,
            _request: &InstallationEffectRequest,
        ) -> PortOutcome<()> {
            self.secret_deletes
                .pop_front()
                .unwrap_or(PortOutcome::Unknown(
                    eliot_platform::UnknownReason::Indeterminate,
                ))
        }

        fn ownership_secret_absent(
            &mut self,
            _request: &InstallationEffectRequest,
        ) -> PortOutcome<bool> {
            self.secret_absence
                .pop_front()
                .unwrap_or(PortOutcome::Unknown(
                    eliot_platform::UnknownReason::Indeterminate,
                ))
        }
    }

    fn must<T, E>(result: Result<T, E>) -> T
    where
        E: std::fmt::Display,
    {
        match result {
            Ok(value) => value,
            Err(error) => panic!("invalid installation test fixture: {error}"),
        }
    }

    fn test_handle(value: impl Into<String>) -> PlatformHandle {
        must(PlatformHandle::new(value.into()))
    }

    fn test_path(root: &Path, name: &str) -> PlatformHandle {
        test_handle(root.join(name).to_string_lossy().into_owned())
    }

    #[cfg(windows)]
    fn provision_portable_test_root(path: &Path) {
        std::fs::create_dir_all(path).unwrap_or_else(|_| unreachable!());
        drop(must(UserOwnedRootLease::open_existing(path)));
    }

    fn reseal_roots(roots: &mut RuntimeStateRoots) {
        roots.roots_digest = test_handle(sha256_hex(&must(roots.unsigned_bytes())));
    }

    fn installer_plan_parts(
        roots: &RuntimeStateRoots,
    ) -> (Vec<PlannedChange>, Vec<InstallerEffectPlan>) {
        let mut effects = Vec::new();
        let declared = std::iter::once(&roots.installation_root)
            .chain(roots.root_fields().into_iter().map(|(_, root)| root))
            .cloned()
            .collect::<Vec<_>>();
        for (index, root) in declared.into_iter().enumerate() {
            effects.push(InstallerEffectPlan::CreateRoot {
                effect_id: test_handle(format!("effect:create:{index}")),
                root: root.clone(),
            });
            effects.push(InstallerEffectPlan::ApplyAcl {
                effect_id: test_handle(format!("effect:acl:{index}")),
                root,
                principals: if roots.profile == InstallationProfile::SystemService {
                    vec![
                        InstallerAclPrincipal::Administrators,
                        InstallerAclPrincipal::LocalService,
                        InstallerAclPrincipal::LocalSystem,
                    ]
                } else {
                    vec![
                        InstallerAclPrincipal::CurrentUser,
                        InstallerAclPrincipal::LocalSystem,
                    ]
                },
            });
        }
        if roots.profile == InstallationProfile::SystemService {
            for (role, name, image) in [
                (
                    InstallerServiceRole::Host,
                    "EliotHost",
                    r"C:\ProgramData\Eliot\packages\canary\eliot-host.exe",
                ),
                (
                    InstallerServiceRole::Watchdog,
                    "EliotWatchdog",
                    r"C:\ProgramData\Eliot\packages\canary\eliot-watchdog.exe",
                ),
            ] {
                effects.push(InstallerEffectPlan::RegisterService {
                    effect_id: test_handle(format!("effect:service:{name}")),
                    role,
                    service_name: test_handle(name),
                    executable_path: test_handle(image),
                    account: InstallerServiceAccount::LocalService,
                    automatic_start: true,
                });
            }
            effects.push(InstallerEffectPlan::ProvisionStoreCredential {
                effect_id: test_handle("effect:store-credential"),
                provision: StoreCredentialProvisionPlan {
                    host_state_root: roots.host_state_root.clone(),
                    expected_host_executable: test_handle(
                        r"C:\ProgramData\Eliot\packages\canary\eliot-host.exe",
                    ),
                    target: test_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
                    provider: StoreCredentialProvider::WindowsCredentialManager,
                    scope: StoreCredentialScope::LocalService,
                    expected_principal_sid: test_handle(LOCAL_SERVICE_SID),
                    generation: ResourceGeneration::genesis(),
                    config_digest: test_handle("c".repeat(64)),
                },
            });
        }
        let changes = effects
            .iter()
            .map(|effect| PlannedChange {
                change_id: effect.effect_id().clone(),
                target: match effect {
                    InstallerEffectPlan::CreateRoot { root, .. }
                    | InstallerEffectPlan::ApplyAcl { root, .. } => root.clone(),
                    InstallerEffectPlan::RegisterService { service_name, .. } => {
                        service_name.clone()
                    }
                    InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => {
                        provision.target.clone()
                    }
                },
                precondition_refs: vec![test_handle("evidence:installer-precondition")],
                postcondition_refs: vec![test_handle("evidence:installer-postcondition")],
            })
            .collect();
        (changes, effects)
    }

    struct FakeRuntimeRootLease {
        declared_path: String,
        canonical_path: String,
        identity: String,
        reparse_free: bool,
    }

    impl RuntimeRootLease for FakeRuntimeRootLease {
        fn declared_path(&self) -> &str {
            &self.declared_path
        }

        fn canonical_path(&self) -> &str {
            &self.canonical_path
        }

        fn file_identity(&self) -> &str {
            &self.identity
        }

        fn is_reparse_free(&self) -> bool {
            self.reparse_free
        }
    }

    struct FakeRuntimeRootLeaseProvider {
        next: usize,
        reparse_at: Option<usize>,
        alias_identity: bool,
    }

    impl RuntimeRootLeaseProvider for FakeRuntimeRootLeaseProvider {
        type Lease = FakeRuntimeRootLease;

        fn retain_root(&mut self, root: &PlatformHandle) -> Result<Self::Lease, InstallationError> {
            let index = self.next;
            self.next += 1;
            Ok(FakeRuntimeRootLease {
                declared_path: root.as_str().to_owned(),
                canonical_path: root.as_str().to_ascii_uppercase(),
                identity: if self.alias_identity {
                    "volume:1:file:shared".to_owned()
                } else {
                    format!("volume:1:file:{index}")
                },
                reparse_free: self.reparse_at != Some(index),
            })
        }
    }

    #[allow(clippy::too_many_lines)]
    fn registering_transaction() -> InstallationTransaction {
        let sequence = NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "eliot-installation-activate-regression-{}-{sequence}",
            std::process::id()
        ));
        let portable_directory = root.join("portable");
        provision_portable_test_root(&portable_directory);
        let candidate_generation = test_handle("generation:candidate");
        let rollback_plan = test_handle("rollback:plan");
        let portable_root = test_handle(portable_directory.to_string_lossy().into_owned());
        let runtime_state_roots = must(RuntimeStateRoots::derive_portable(portable_root.clone()));
        let candidate_manifest = CandidateManifest {
            generation: candidate_generation.clone(),
            components: vec![
                test_handle("component:kernel"),
                test_handle("component:store"),
            ],
            kernel_artifact_digest: test_handle("0".repeat(64)),
            store_bridge_artifact_digest: test_handle("1".repeat(64)),
            canonical_store_artifact_digest: test_handle("5".repeat(64)),
            host_artifact_digest: test_handle("8".repeat(64)),
            kernel_executable_path: test_path(&root, "eliot-kernel.exe"),
            store_bridge_executable_path: test_path(&root, "eliot-store-surreal.exe"),
            canonical_store_executable_path: test_path(&root, "surreal.exe"),
            host_executable_path: test_path(&root, "eliot-host.exe"),
            config_path: test_path(&root, "generation.json"),
            dependency_closure_refs: vec![test_handle("evidence:dependency-closure")],
            license_refs: vec![test_handle("evidence:licenses")],
            config_digest: test_handle("2".repeat(64)),
            store_credential_target: test_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            supervision_key_fingerprint: test_handle("3".repeat(64)),
            signature_ref: test_handle("evidence:signature"),
            runtime_state_roots_digest: runtime_state_roots.roots_digest.clone(),
            runtime_launch: {
                let mut descriptor = RuntimeLaunchDescriptor {
                    profile: InstallationProfile::PortableDev,
                    portable_root: Some(portable_root.clone()),
                    installation_epoch: InstallationEpoch {
                        installation: test_handle("installation:test"),
                        lineage_id: test_handle("lineage:test"),
                        sequence: 1,
                    },
                    generation: test_handle("generation:candidate"),
                    authority_generation: ResourceGeneration::genesis(),
                    authority_state_fence: StateFence::new(
                        eliot_contracts::AuthorityEpoch::genesis(),
                        ResourceGeneration::genesis(),
                    ),
                    authority_descriptor_path: test_path(&root, "authority.json"),
                    authority_descriptor_digest: test_handle("7".repeat(64)),
                    runtime_state_roots: runtime_state_roots.clone(),
                    kernel_work_root: runtime_state_roots.kernel_work_root.clone(),
                    kernel_artifact_digest: test_handle("0".repeat(64)),
                    eliotd_executable_path: test_path(&root, "eliotd.exe"),
                    eliotd_artifact_digest: test_handle("8".repeat(64)),
                    eliotd_config_path: test_path(&root, "eliotd-governor.json"),
                    eliotd_config_digest: test_handle("4".repeat(64)),
                    eliotd_descriptor_path: test_path(&root, "eliotd.json"),
                    eliotd_descriptor_digest: test_handle("9".repeat(64)),
                    eliotd_launch_nonce: test_handle(format!("eliotd:{}", "a".repeat(32))),
                    store_config_path: test_path(&root, "generation.json"),
                    store_credential_target: test_handle(
                        "eliot/store/v1/0123456789abcdef0123456789abcdef",
                    ),
                    store_bridge_executable_path: test_path(&root, "eliot-store-surreal.exe"),
                    store_bridge_artifact_digest: test_handle("1".repeat(64)),
                    store_bootstrap_descriptor_path: test_path(&root, "store-bootstrap.json"),
                    store_bootstrap_descriptor_digest: test_handle("6".repeat(64)),
                    canonical_store_executable_path: test_path(&root, "surreal.exe"),
                    canonical_store_artifact_digest: test_handle("5".repeat(64)),
                    kernel_arguments: vec![
                        test_handle("--work-root"),
                        runtime_state_roots.kernel_work_root.clone(),
                        test_handle("--store-bootstrap"),
                        test_path(&root, "store-bootstrap.json"),
                        test_handle("--store-bootstrap-sha256"),
                        test_handle("6".repeat(64)),
                        test_handle("--authority-descriptor"),
                        test_path(&root, "authority.json"),
                        test_handle("--authority-descriptor-sha256"),
                        test_handle("7".repeat(64)),
                        test_handle("--kernel-artifact-sha256"),
                        test_handle("0".repeat(64)),
                        test_handle("--eliotd-descriptor"),
                        test_path(&root, "eliotd.json"),
                        test_handle("--eliotd-descriptor-sha256"),
                        test_handle("9".repeat(64)),
                    ],
                    store_bridge_arguments: vec![
                        test_handle("--portable-dev-root"),
                        portable_root,
                        test_handle("--config"),
                        test_path(&root, "generation.json"),
                    ],
                    canonical_store_arguments: vec![
                        test_handle("start"),
                        test_handle("--no-banner"),
                        test_handle("--bind"),
                        test_handle("127.0.0.1:8000"),
                        test_handle("--temporary-directory"),
                        runtime_state_roots.store_temp_root.clone(),
                        test_handle("--log-file-enabled"),
                        test_handle("--log-file-path"),
                        runtime_state_roots.store_work_root.clone(),
                        test_handle("--log-file-name"),
                        test_handle("surrealdb.log"),
                        test_handle(format!(
                            "surrealkv://{}",
                            runtime_state_roots
                                .store_data_root
                                .as_str()
                                .replace('\\', "/")
                        )),
                    ],
                    host_executable_path: test_path(&root, "eliot-host.exe"),
                    host_artifact_digest: test_handle("8".repeat(64)),
                    watchdog_executable_path: test_path(&root, "eliot-watchdog.exe"),
                    watchdog_artifact_digest: test_handle("4".repeat(64)),
                    descriptor_digest: test_handle("0".repeat(64)),
                };
                descriptor.descriptor_digest =
                    test_handle(sha256_hex(&must(descriptor.unsigned_bytes())));
                descriptor
            },
        };
        let request = ManagedEnvironmentChangeRequest {
            request_id: test_handle("request:install"),
            requester_and_reason: test_handle("requester:test"),
            action: ManagedEnvironmentAction::Install,
            target_family: test_handle("family:eliot"),
            exact_candidate: candidate_generation,
            expected_delta: test_handle("delta:installed"),
            source_assurance_refs: vec![test_handle("evidence:source-assurance")],
            affected_refs: Vec::new(),
            impact_class: test_handle("impact:test"),
            required_owner: test_handle("owner:installation"),
            rollback_plan: rollback_plan.clone(),
            verifier: test_handle("verifier:installation"),
            budget: test_handle("budget:test"),
            stop_condition: test_handle("stop:on-failure"),
        };
        let (planned_changes, installer_effects) = installer_plan_parts(&runtime_state_roots);
        let mut transaction = must(InstallationTransaction::new(
            test_handle("transaction:activate"),
            InstallationEpoch {
                installation: test_handle("installation:test"),
                lineage_id: test_handle("lineage:test"),
                sequence: 1,
            },
            InstallationProfile::PortableDev,
            request,
            None,
            candidate_manifest,
            test_path(&root, "staging"),
            planned_changes,
            installer_effects,
            1,
            vec![test_handle("evidence:plan-precondition")],
            test_handle("recovery:command"),
        ));
        must(transaction.advance(
            InstallationStage::Staging,
            vec![test_handle("evidence:staged")],
        ));
        must(transaction.advance(
            InstallationStage::StaticVerified,
            vec![test_handle("evidence:static-verified")],
        ));
        must(transaction.advance(
            InstallationStage::Registering,
            vec![test_handle("evidence:registered")],
        ));
        transaction
    }

    fn planned_transaction() -> InstallationTransaction {
        let transaction = registering_transaction();
        must(InstallationTransaction::new(
            transaction.transaction_id,
            transaction.installation_epoch,
            transaction.profile,
            transaction.request,
            transaction.current_active_manifest,
            transaction.candidate_manifest,
            transaction.staging_root,
            transaction.planned_changes,
            transaction.installer_effects,
            transaction.minimum_store_available_bytes,
            transaction.precondition_evidence,
            transaction.recovery_command,
        ))
    }

    fn absent_with_file_index(
        transaction: &InstallationTransaction,
        file_index: u64,
    ) -> InstallationEffectObservation {
        let precondition = must(InstallationEffectPrecondition::from_change(
            &transaction.planned_changes[0],
        ));
        let object = InstallationOsObjectSnapshot {
            canonical_path_digest: test_handle("b".repeat(64)),
            volume_serial_number: 1,
            file_index,
            security_descriptor_digest: test_handle("c".repeat(64)),
        };
        let snapshot = InstallationRootAbsentSnapshot {
            target_path_digest: test_handle("d".repeat(64)),
            profile_anchor: object.clone(),
            ancestors: vec![object.clone()],
            parent: object,
            root_absent: true,
        };
        InstallationEffectObservation::Absent {
            observed_precondition: must(precondition.with_os_snapshot(snapshot)),
            evidence: vec![test_handle("evidence:absent")],
        }
    }

    fn absent(transaction: &InstallationTransaction) -> InstallationEffectObservation {
        absent_with_file_index(transaction, 1)
    }

    fn admitted_precondition(
        transaction: &InstallationTransaction,
    ) -> InstallationEffectPrecondition {
        let InstallationEffectObservation::Absent {
            observed_precondition,
            ..
        } = absent(transaction)
        else {
            unreachable!()
        };
        observed_precondition
    }

    fn test_secret_reference(suffix: &str) -> InstallationSecretReference {
        InstallationSecretReference {
            target: test_handle(format!("eliot/installer-root/v1/{suffix}")),
            expected_principal_sid: test_handle("S-1-5-21-1000"),
            scope: InstallationSecretScope::WindowsCredentialManagerCurrentUser,
        }
    }

    fn test_ownership_secret(
        disposition: InstallationCreateDisposition,
        lifecycle: InstallationSecretLifecycle,
    ) -> InstallationOwnershipSecret {
        InstallationOwnershipSecret {
            reference: test_secret_reference("0123456789abcdef0123456789abcdef"),
            create_disposition: disposition,
            lifecycle,
        }
    }

    fn rollback_ready_transaction() -> InstallationTransaction {
        let mut transaction = planned_transaction();
        transaction.effect_progress[0].admitted_precondition =
            Some(admitted_precondition(&transaction));
        transaction.effect_progress[0].ownership_secret = Some(test_ownership_secret(
            InstallationCreateDisposition::Created,
            InstallationSecretLifecycle::Active,
        ));
        transaction.effect_progress[0].state = InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            external_identity: test_handle("external:effect-0"),
            evidence: vec![test_handle("evidence:created-root")],
            postcondition_digest: test_handle("e".repeat(64)),
        };
        transaction.pending_external_changes = vec![test_handle("pending:rollback")];
        transaction.stage = InstallationStage::RollbackRequired;
        transaction.revision = 4;
        must(transaction.validate());
        transaction
    }

    fn matching(disposition: InstallationEffectDisposition) -> InstallationEffectObservation {
        InstallationEffectObservation::Matching {
            disposition,
            external_identity: test_handle("external:effect-0"),
            evidence: vec![test_handle("evidence:matching")],
            postcondition_digest: test_handle("a".repeat(64)),
            credential_receipt: None,
        }
    }

    fn fake_port(
        store: SharedStore,
        inspections: Vec<PortOutcome<InstallationEffectObservation>>,
        reconciliations: Vec<PortOutcome<InstallationEffectObservation>>,
        execute_count: Arc<Mutex<usize>>,
    ) -> FakeEffectPort {
        FakeEffectPort {
            shared: store,
            inspections: inspections.into(),
            reconciliations: reconciliations.into(),
            execute_count,
            create_disposition: InstallationCreateDisposition::Created,
            secret_absence: VecDeque::new(),
            secret_deletes: VecDeque::new(),
            panic_reconcile_once: false,
        }
    }

    #[cfg(windows)]
    fn windows_secret_request(
        reference: InstallationSecretReference,
        disposition: InstallationCreateDisposition,
    ) -> InstallationEffectRequest {
        let transaction = planned_transaction();
        let mut request = must(effect_request(
            &transaction,
            0,
            1,
            InstallationEffectAction::Apply,
            None,
        ));
        request.precondition = admitted_precondition(&transaction);
        request.ownership_secret = Some(InstallationOwnershipSecret {
            reference,
            create_disposition: disposition,
            lifecycle: InstallationSecretLifecycle::Active,
        });
        must(request.validate());
        request
    }

    #[test]
    fn coordinator_rejects_changed_independent_snapshot_after_intent() {
        let transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));
        let execute_count = Arc::new(Mutex::new(0));
        let port = fake_port(
            store.clone(),
            vec![PortOutcome::Known(absent_with_file_index(&transaction, 1))],
            vec![PortOutcome::Known(absent_with_file_index(&transaction, 2))],
            execute_count,
        );
        let mut coordinator = InstallationCoordinator::new(port, store.clone());

        assert!(matches!(
            must(coordinator.drive_effect(&transaction_id)),
            InstallationStepOutcome::RollbackRequired { .. }
        ));
        let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert!(matches!(
            saved.effect_progress[0].state,
            InstallationEffectProgressState::Unknown { .. }
        ));
    }

    #[test]
    fn service_marker_requires_exact_transaction_nonce_and_configuration() {
        let transaction = planned_transaction();
        let mut request = must(effect_request(
            &transaction,
            0,
            1,
            InstallationEffectAction::Apply,
            None,
        ));
        request.registration_nonce = Some(test_handle("a".repeat(64)));
        let marker = must(WindowsServiceOwnershipMarker::new(
            &request,
            ELIOT_HOST_SERVICE_NAME,
            &"b".repeat(64),
        ));
        assert!(marker.matches(&request, ELIOT_HOST_SERVICE_NAME, &"b".repeat(64)));
        assert!(!marker.matches(&request, ELIOT_WATCHDOG_SERVICE_NAME, &"b".repeat(64)));
        assert!(!marker.matches(&request, ELIOT_HOST_SERVICE_NAME, &"c".repeat(64)));
        request.registration_nonce = Some(test_handle("d".repeat(64)));
        assert!(!marker.matches(&request, ELIOT_HOST_SERVICE_NAME, &"b".repeat(64)));
    }

    #[test]
    fn already_exists_can_never_become_transaction_ownership() {
        let transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));
        let execute_count = Arc::new(Mutex::new(0));
        let mut port = fake_port(
            store.clone(),
            vec![PortOutcome::Known(absent(&transaction))],
            vec![PortOutcome::Known(matching(
                InstallationEffectDisposition::CreatedByTransaction,
            ))],
            execute_count,
        );
        port.create_disposition = InstallationCreateDisposition::AlreadyExists;
        let mut coordinator = InstallationCoordinator::new(port, store.clone());

        assert!(matches!(
            must(coordinator.drive_effect(&transaction_id)),
            InstallationStepOutcome::RollbackRequired { .. }
        ));
        let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert_eq!(
            saved.effect_progress[0]
                .ownership_secret
                .as_ref()
                .unwrap_or_else(|| unreachable!())
                .create_disposition,
            InstallationCreateDisposition::AlreadyExists
        );
        assert!(matches!(
            saved.effect_progress[0].state,
            InstallationEffectProgressState::Unknown { .. }
        ));
    }

    #[test]
    fn transaction_admission_enforces_ownership_lifecycle_relations() {
        let mut preexisting = planned_transaction();
        preexisting.effect_progress[0].ownership_secret = Some(test_ownership_secret(
            InstallationCreateDisposition::Created,
            InstallationSecretLifecycle::Active,
        ));
        preexisting.effect_progress[0].admitted_precondition =
            Some(admitted_precondition(&preexisting));
        preexisting.effect_progress[0].state = InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::PreexistingMatching,
            external_identity: test_handle("external:preexisting"),
            evidence: vec![test_handle("evidence:preexisting")],
            postcondition_digest: test_handle("a".repeat(64)),
        };
        assert!(preexisting.validate_effect_progress().is_err());

        for stage in [InstallationStage::Completed, InstallationStage::RolledBack] {
            let mut terminal = planned_transaction();
            terminal.stage = stage;
            terminal.effect_progress[0].ownership_secret = Some(test_ownership_secret(
                InstallationCreateDisposition::Created,
                InstallationSecretLifecycle::Active,
            ));
            terminal.effect_progress[0].admitted_precondition =
                Some(admitted_precondition(&terminal));
            terminal.effect_progress[0].state = InstallationEffectProgressState::Applied {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                external_identity: test_handle("external:created"),
                evidence: vec![test_handle("evidence:created")],
                postcondition_digest: test_handle("b".repeat(64)),
            };
            assert!(terminal.validate_effect_progress().is_err());
        }

        let mut deleted = planned_transaction();
        deleted.stage = InstallationStage::RolledBack;
        deleted.effect_progress[0].ownership_secret = Some(test_ownership_secret(
            InstallationCreateDisposition::Created,
            InstallationSecretLifecycle::Deleted,
        ));
        deleted.effect_progress[0].admitted_precondition = Some(admitted_precondition(&deleted));
        deleted.effect_progress[0].state = InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            external_identity: test_handle("external:deleted"),
            evidence: vec![test_handle("evidence:deleted")],
            postcondition_digest: test_handle("c".repeat(64)),
        };
        assert!(deleted.validate_effect_progress().is_err());
        let reference = deleted.effect_progress[0]
            .ownership_secret
            .as_ref()
            .unwrap_or_else(|| unreachable!())
            .reference
            .clone();
        deleted
            .completed_stage_refs
            .push(ownership_secret_absence_evidence(&reference));
        assert!(deleted.validate_effect_progress().is_ok());
    }

    #[test]
    fn keyed_receipt_rejects_byte_length_key_and_object_substitution() {
        let transaction = planned_transaction();
        let mut request = must(effect_request(
            &transaction,
            0,
            1,
            InstallationEffectAction::Apply,
            None,
        ));
        request.precondition = admitted_precondition(&transaction);
        request.ownership_secret = Some(test_ownership_secret(
            InstallationCreateDisposition::Created,
            InstallationSecretLifecycle::Active,
        ));
        let root = InstallerRootObjectSnapshot {
            canonical_path_digest: "1".repeat(64),
            volume_serial_number: 7,
            file_index: 11,
            security_descriptor_digest: "2".repeat(64),
        };
        let marker = InstallerRootObjectSnapshot {
            canonical_path_digest: "3".repeat(64),
            volume_serial_number: 7,
            file_index: 12,
            security_descriptor_digest: "4".repeat(64),
        };
        let key = [0x5a; 32];
        let mut receipt = WindowsRootOwnershipReceipt::new(&request, &root, &marker, &key)
            .unwrap_or_else(|error| panic!("receipt creation failed: {error}"));
        assert!(receipt.matches(&request, &root, &marker, &key));
        assert!(!receipt.matches(&request, &root, &marker, &[0x6b; 32]));
        let mut substituted_root = root.clone();
        substituted_root.file_index += 1;
        assert!(!receipt.matches(&request, &substituted_root, &marker, &key));
        receipt.mac.push('0');
        assert!(!receipt.matches(&request, &root, &marker, &key));
        receipt.mac.pop();
        receipt.mac.replace_range(
            ..1,
            if receipt.mac.starts_with('0') {
                "1"
            } else {
                "0"
            },
        );
        assert!(!receipt.matches(&request, &root, &marker, &key));
    }

    #[cfg(windows)]
    #[test]
    fn missing_and_other_principal_credential_fail_closed() {
        let port = WindowsInstallationEffectPort::new();
        let reference = InstallationSecretReference {
            target: port
                .secrets
                .fresh_reference()
                .unwrap_or_else(|error| panic!("reference issuance failed: {error}")),
            expected_principal_sid: port
                .secrets
                .principal_sid()
                .unwrap_or_else(|error| panic!("SID observation failed: {error}")),
            scope: InstallationSecretScope::WindowsCredentialManagerCurrentUser,
        };
        let request =
            windows_secret_request(reference.clone(), InstallationCreateDisposition::Created);
        assert!(matches!(
            port.reconcile_primitive(&request),
            Err(PortError::Provider(_))
        ));

        let mut wrong_sid = request;
        wrong_sid
            .ownership_secret
            .as_mut()
            .unwrap_or_else(|| unreachable!())
            .reference
            .expected_principal_sid = test_handle("S-1-5-21-999999");
        assert!(matches!(
            port.secret_target(&wrong_sid),
            Err(PortError::Provider(ProviderError {
                code: ProviderErrorCode::PermissionDenied,
                retryable: false
            }))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn preexisting_valid_credential_is_not_adopted_or_deleted() {
        let port = WindowsInstallationEffectPort::new();
        let target = port
            .secrets
            .fresh_reference()
            .unwrap_or_else(|error| panic!("reference issuance failed: {error}"));
        let reference = InstallationSecretReference {
            target: target.clone(),
            expected_principal_sid: port
                .secrets
                .principal_sid()
                .unwrap_or_else(|error| panic!("SID observation failed: {error}")),
            scope: InstallationSecretScope::WindowsCredentialManagerCurrentUser,
        };
        assert_eq!(
            port.secrets
                .create_at(&target)
                .unwrap_or_else(|error| panic!("credential create failed: {error}")),
            InstallerSecretCreateDisposition::Created
        );
        let request =
            windows_secret_request(reference, InstallationCreateDisposition::NotAttempted);
        assert_eq!(
            port.ensure_secret(&request).err(),
            Some(eliot_platform_windows::WindowsAdapterError::AlreadyExists)
        );
        assert_eq!(
            port.secrets
                .inspect(&target)
                .unwrap_or_else(|error| panic!("credential inspect failed: {error}")),
            InstallerSecretObservation::Present
        );
        port.secrets
            .delete(&target)
            .unwrap_or_else(|error| panic!("credential cleanup failed: {error}"));
    }

    #[test]
    fn crash_before_credential_delete_retains_intent_and_resumes() {
        let transaction = rollback_ready_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let store = SharedStore {
            state: Arc::new(Mutex::new(Some(transaction.clone()))),
            ..SharedStore::default()
        };
        let execute_count = Arc::new(Mutex::new(0));
        let mut crashing = fake_port(
            store.clone(),
            Vec::new(),
            vec![
                PortOutcome::Known(matching(
                    InstallationEffectDisposition::CreatedByTransaction,
                )),
                PortOutcome::Known(absent(&transaction)),
            ],
            execute_count.clone(),
        );
        crashing.secret_absence = vec![PortOutcome::Known(false)].into();
        crashing.secret_deletes = vec![PortOutcome::Unknown(
            eliot_platform::UnknownReason::Indeterminate,
        )]
        .into();
        let mut coordinator = InstallationCoordinator::new(crashing, store.clone());
        assert!(matches!(
            must(coordinator.rollback(&transaction_id)),
            InstallationStepOutcome::RollbackRequired { .. }
        ));
        let retained = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert_eq!(retained.stage, InstallationStage::RollbackRequired);
        assert_eq!(
            retained.effect_progress[0]
                .ownership_secret
                .as_ref()
                .unwrap_or_else(|| unreachable!())
                .lifecycle,
            InstallationSecretLifecycle::DeleteIntentCommitted
        );

        let mut recovering = fake_port(
            store.clone(),
            Vec::new(),
            vec![PortOutcome::Known(absent(&transaction))],
            execute_count,
        );
        recovering.secret_absence =
            vec![PortOutcome::Known(false), PortOutcome::Known(true)].into();
        recovering.secret_deletes = vec![PortOutcome::Known(())].into();
        let mut coordinator = InstallationCoordinator::new(recovering, store.clone());
        assert!(matches!(
            must(coordinator.rollback(&transaction_id)),
            InstallationStepOutcome::Applied {
                stage: InstallationStage::RolledBack,
                ..
            }
        ));
        let terminal = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert_eq!(
            terminal.effect_progress[0]
                .ownership_secret
                .as_ref()
                .unwrap_or_else(|| unreachable!())
                .lifecycle,
            InstallationSecretLifecycle::Deleted
        );
        must(terminal.validate());
    }

    #[test]
    fn crash_after_credential_delete_reobserves_absence_before_terminal_state() {
        let transaction = rollback_ready_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let store = SharedStore {
            state: Arc::new(Mutex::new(Some(transaction.clone()))),
            ..SharedStore::default()
        };
        let execute_count = Arc::new(Mutex::new(0));
        let mut crashing = fake_port(
            store.clone(),
            Vec::new(),
            vec![
                PortOutcome::Known(matching(
                    InstallationEffectDisposition::CreatedByTransaction,
                )),
                PortOutcome::Known(absent(&transaction)),
            ],
            execute_count.clone(),
        );
        crashing.secret_absence = vec![
            PortOutcome::Known(false),
            PortOutcome::Unknown(eliot_platform::UnknownReason::Indeterminate),
        ]
        .into();
        crashing.secret_deletes = vec![PortOutcome::Known(())].into();
        let mut coordinator = InstallationCoordinator::new(crashing, store.clone());
        assert!(matches!(
            must(coordinator.rollback(&transaction_id)),
            InstallationStepOutcome::RollbackRequired { .. }
        ));
        let retained = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert_eq!(retained.stage, InstallationStage::RollbackRequired);
        assert_eq!(
            retained.effect_progress[0]
                .ownership_secret
                .as_ref()
                .unwrap_or_else(|| unreachable!())
                .lifecycle,
            InstallationSecretLifecycle::DeleteIntentCommitted
        );

        let mut recovering = fake_port(
            store.clone(),
            Vec::new(),
            vec![PortOutcome::Known(absent(&transaction))],
            execute_count,
        );
        recovering.secret_absence = vec![PortOutcome::Known(true)].into();
        let mut coordinator = InstallationCoordinator::new(recovering, store.clone());
        assert!(matches!(
            must(coordinator.rollback(&transaction_id)),
            InstallationStepOutcome::Applied {
                stage: InstallationStage::RolledBack,
                ..
            }
        ));
        let terminal = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert_eq!(terminal.stage, InstallationStage::RolledBack);
        must(terminal.validate());
    }

    #[cfg(windows)]
    fn production_created_root(
        store: &SharedStore,
        transaction_id: &PlatformHandle,
    ) -> InstallationTransaction {
        let mut coordinator = WindowsInstallationCoordinator::new(store.clone());
        for _ in 0..3 {
            let outcome = must(coordinator.drive_effect(transaction_id));
            assert!(
                matches!(outcome, InstallationStepOutcome::Applied { .. }),
                "unexpected production drive outcome: {outcome:?}"
            );
        }
        let transaction = must(store.load(transaction_id)).unwrap_or_else(|| unreachable!());
        assert!(matches!(
            transaction.effect_progress[2].state,
            InstallationEffectProgressState::Applied {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                ..
            }
        ));
        transaction
    }

    #[cfg(windows)]
    fn cleanup_production_transaction(transaction: &InstallationTransaction) {
        if let Some(reference) = transaction.effect_progress[2]
            .ownership_secret
            .as_ref()
            .map(|ownership| &ownership.reference.target)
        {
            let _ = WindowsInstallerSecretProvider::new().delete(reference);
        }
        let root = Path::new(
            transaction
                .candidate_manifest
                .runtime_launch
                .runtime_state_roots
                .installation_root
                .as_str(),
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn production_restart_reconciles_hmac_receipt_without_duplicate_creation() {
        let _serial = PRODUCTION_INSTALLER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));
        let mut created = production_created_root(&store, &transaction_id);
        let request = must(effect_request(
            &created,
            2,
            1,
            InstallationEffectAction::Apply,
            None,
        ));
        let (spec, _) = must(windows_root_spec(&request));
        let primitive = WindowsInstallerRootPrimitive::new();
        let InstallerRootPrimitiveObservation::Matching(before) =
            primitive.inspect(&spec).unwrap_or_else(|error| {
                cleanup_production_transaction(&created);
                panic!("created root inspect failed: {error}")
            })
        else {
            cleanup_production_transaction(&created);
            panic!("expected created root")
        };
        let prior_evidence = match &created.effect_progress[2].state {
            InstallationEffectProgressState::Applied { evidence, .. } => evidence.clone(),
            _ => unreachable!(),
        };
        created
            .observed_postconditions
            .retain(|evidence| !prior_evidence.contains(evidence));
        created.effect_progress[2].state = InstallationEffectProgressState::IntentCommitted {
            attempt: 1,
            intent_digest: must(request.intent_digest()),
        };
        created.revision += 1;
        must(created.validate());
        *store.state.lock().unwrap_or_else(|_| unreachable!()) = Some(created.clone());

        let mut restarted = WindowsInstallationCoordinator::new(store.clone());
        let restart_outcome = must(restarted.drive_effect(&transaction_id));
        assert!(
            matches!(restart_outcome, InstallationStepOutcome::Applied { .. }),
            "unexpected restart outcome: {restart_outcome:?}"
        );
        let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        let InstallerRootPrimitiveObservation::Matching(after) =
            primitive.inspect(&spec).unwrap_or_else(|error| {
                cleanup_production_transaction(&saved);
                panic!("reconciled root inspect failed: {error}")
            })
        else {
            cleanup_production_transaction(&saved);
            panic!("expected reconciled root")
        };
        assert_eq!(before, after, "restart must not create a second directory");
        cleanup_production_transaction(&saved);
    }

    #[cfg(windows)]
    #[test]
    fn production_missing_receipt_after_create_is_unknown_not_owned() {
        let _serial = PRODUCTION_INSTALLER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));
        let mut created = production_created_root(&store, &transaction_id);
        let request = must(effect_request(
            &created,
            2,
            1,
            InstallationEffectAction::Apply,
            None,
        ));
        std::fs::remove_file(ownership_receipt_path(&request)).unwrap_or_else(|error| {
            cleanup_production_transaction(&created);
            panic!("receipt removal failed: {error}")
        });
        created.effect_progress[2].state = InstallationEffectProgressState::IntentCommitted {
            attempt: 1,
            intent_digest: must(request.intent_digest()),
        };
        created.revision += 1;
        must(created.validate());
        *store.state.lock().unwrap_or_else(|_| unreachable!()) = Some(created.clone());

        let mut restarted = WindowsInstallationCoordinator::new(store.clone());
        assert!(matches!(
            must(restarted.drive_effect(&transaction_id)),
            InstallationStepOutcome::RollbackRequired { .. }
        ));
        let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert!(matches!(
            saved.effect_progress[2].state,
            InstallationEffectProgressState::Unknown { .. }
        ));
        cleanup_production_transaction(&saved);
    }

    #[cfg(windows)]
    #[test]
    fn production_rollback_rejects_root_identity_substitution() {
        let _serial = PRODUCTION_INSTALLER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));
        let mut created = production_created_root(&store, &transaction_id);
        let request = must(effect_request(
            &created,
            2,
            1,
            InstallationEffectAction::Apply,
            None,
        ));
        let (spec, _) = must(windows_root_spec(&request));
        let moved = spec.root.with_extension("owned-moved");
        std::fs::rename(&spec.root, &moved).unwrap_or_else(|error| {
            cleanup_production_transaction(&created);
            panic!("owned root rename failed: {error}")
        });
        let primitive = WindowsInstallerRootPrimitive::new();
        let InstallerRootPrimitiveObservation::Absent(snapshot) =
            primitive.inspect(&spec).unwrap_or_else(|error| {
                cleanup_production_transaction(&created);
                panic!("replacement absence inspect failed: {error}")
            })
        else {
            cleanup_production_transaction(&created);
            panic!("expected absent replacement path")
        };
        let replacement = primitive.create(&spec, &snapshot).unwrap_or_else(|error| {
            cleanup_production_transaction(&created);
            panic!("replacement create failed: {error}")
        });
        assert_eq!(
            replacement.disposition,
            InstallerRootCreateDisposition::Created
        );
        created.stage = InstallationStage::RollbackRequired;
        created.pending_external_changes = vec![test_handle("pending:identity-substitution")];
        created.revision += 1;
        must(created.validate());
        *store.state.lock().unwrap_or_else(|_| unreachable!()) = Some(created.clone());

        let mut coordinator = WindowsInstallationCoordinator::new(store.clone());
        assert!(matches!(
            must(coordinator.rollback(&transaction_id)),
            InstallationStepOutcome::Quarantined { .. }
        ));
        assert!(spec.root.exists(), "replacement root must never be deleted");
        let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        cleanup_production_transaction(&saved);
        let _ = std::fs::remove_dir_all(moved);
    }

    #[test]
    fn durable_coordinator_commits_intent_before_effect() {
        let transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));
        let execute_count = Arc::new(Mutex::new(0));
        let port = fake_port(
            store.clone(),
            vec![PortOutcome::Known(absent(&transaction))],
            vec![PortOutcome::Known(matching(
                InstallationEffectDisposition::CreatedByTransaction,
            ))],
            execute_count.clone(),
        );
        let mut coordinator = InstallationCoordinator::new(port, store.clone());

        let outcome = must(coordinator.drive_effect(&transaction_id));

        assert!(matches!(outcome, InstallationStepOutcome::Applied { .. }));
        assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
        let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert!(matches!(
            saved.effect_progress[0].state,
            InstallationEffectProgressState::Applied {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                ..
            }
        ));
    }

    #[test]
    fn crash_after_mutation_reconciles_without_replay_and_receipt_never_replays() {
        let transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));
        let execute_count = Arc::new(Mutex::new(0));
        let mut crashing_port = fake_port(
            store.clone(),
            vec![PortOutcome::Known(absent(&transaction))],
            Vec::new(),
            execute_count.clone(),
        );
        crashing_port.panic_reconcile_once = true;
        let mut coordinator = InstallationCoordinator::new(crashing_port, store.clone());
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = coordinator.drive_effect(&transaction_id);
        }));
        assert!(crashed.is_err());
        assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
        let intent = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert!(matches!(
            intent.effect_progress[0].state,
            InstallationEffectProgressState::IntentCommitted { .. }
        ));

        let recovering_port = fake_port(
            store.clone(),
            Vec::new(),
            vec![PortOutcome::Known(matching(
                InstallationEffectDisposition::CreatedByTransaction,
            ))],
            execute_count.clone(),
        );
        let mut recovering = InstallationCoordinator::new(recovering_port, store.clone());
        must(recovering.drive_effect(&transaction_id));
        assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);

        let mut complete = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        for (index, progress) in complete.effect_progress.iter_mut().enumerate().skip(1) {
            progress.state = InstallationEffectProgressState::Applied {
                disposition: InstallationEffectDisposition::PreexistingMatching,
                external_identity: test_handle(format!("external:receipt-{index}")),
                evidence: vec![test_handle(format!("evidence:receipt-{index}"))],
                postcondition_digest: test_handle(format!("{index:064x}")),
            };
        }
        complete.revision += 1;
        must(complete.validate());
        *store.state.lock().unwrap_or_else(|_| unreachable!()) = Some(complete);

        let receipt_port = fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone());
        let mut receipt = InstallationCoordinator::new(receipt_port, store);
        must(receipt.drive_effect(&transaction_id));
        assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
    }

    #[test]
    fn preexisting_matching_is_receipted_without_execution() {
        let transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));
        let execute_count = Arc::new(Mutex::new(0));
        let port = fake_port(
            store.clone(),
            vec![PortOutcome::Known(matching(
                InstallationEffectDisposition::PreexistingMatching,
            ))],
            Vec::new(),
            execute_count.clone(),
        );
        let mut coordinator = InstallationCoordinator::new(port, store.clone());
        must(coordinator.drive_effect(&transaction_id));
        assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
        let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert!(matches!(
            saved.effect_progress[0].state,
            InstallationEffectProgressState::Applied {
                disposition: InstallationEffectDisposition::PreexistingMatching,
                ..
            }
        ));
    }

    #[test]
    fn cas_conflict_happens_before_external_effect() {
        let transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));
        *store
            .conflict_next
            .lock()
            .unwrap_or_else(|_| unreachable!()) = true;
        let execute_count = Arc::new(Mutex::new(0));
        let port = fake_port(
            store.clone(),
            vec![PortOutcome::Known(absent(&transaction))],
            Vec::new(),
            execute_count.clone(),
        );
        let mut coordinator = InstallationCoordinator::new(port, store);
        let result = coordinator.drive_effect(&transaction_id);
        assert!(matches!(
            result,
            Err(InstallationError::CompareAndSaveConflict { .. })
        ));
        assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    }

    #[test]
    fn cas_binds_full_previous_state_at_the_same_revision() {
        let transaction = planned_transaction();
        let expected = must(TransactionVersion::of(&transaction));
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));

        let mut drifted = transaction.clone();
        drifted
            .precondition_evidence
            .push(test_handle("evidence:same-revision-drift"));
        must(drifted.validate());
        *store.state.lock().unwrap_or_else(|_| unreachable!()) = Some(drifted);

        let mut advanced = transaction;
        must(advanced.advance(
            InstallationStage::Staging,
            vec![test_handle("evidence:advance")],
        ));
        assert!(matches!(
            transaction_store_private::Sealed::compare_and_save(&mut store, expected, &advanced),
            Err(InstallationError::IdentityConflict)
        ));
    }

    #[test]
    fn retry_requires_authoritative_absence_and_unchanged_precondition() {
        let transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));
        let execute_count = Arc::new(Mutex::new(0));
        let port = fake_port(
            store.clone(),
            vec![PortOutcome::Known(absent(&transaction))],
            vec![
                PortOutcome::Known(absent(&transaction)),
                PortOutcome::Known(absent(&transaction)),
                PortOutcome::Known(matching(
                    InstallationEffectDisposition::CreatedByTransaction,
                )),
            ],
            execute_count.clone(),
        );
        let mut coordinator = InstallationCoordinator::new(port, store.clone());
        assert_eq!(
            must(coordinator.drive_effect(&transaction_id)),
            InstallationStepOutcome::Rejected
        );
        assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
        must(coordinator.drive_effect(&transaction_id));
        assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 2);
        let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert!(matches!(
            saved.effect_progress[0].state,
            InstallationEffectProgressState::Applied { .. }
        ));
    }

    #[test]
    fn inspect_unknown_entering_rollback_persists_quarantine() {
        let transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));
        let execute_count = Arc::new(Mutex::new(0));
        let port = fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone());
        let mut coordinator = InstallationCoordinator::new(port, store.clone());
        let outcome = must(coordinator.drive_effect(&transaction_id));
        assert!(matches!(
            outcome,
            InstallationStepOutcome::RollbackRequired { .. }
        ));
        let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert_eq!(saved.stage, InstallationStage::RollbackRequired);
        let rollback_port = fake_port(store.clone(), Vec::new(), Vec::new(), execute_count);
        let mut rollback = InstallationCoordinator::new(rollback_port, store.clone());
        let outcome = must(rollback.rollback(&transaction_id));
        assert!(matches!(
            outcome,
            InstallationStepOutcome::Quarantined { .. }
        ));
        let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert_eq!(saved.stage, InstallationStage::Quarantined);
        assert!(matches!(
            saved.effect_progress[0].state,
            InstallationEffectProgressState::Unknown { .. }
        ));
    }

    #[test]
    fn unreconciled_intent_entering_rollback_persists_quarantine() {
        let mut transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        transaction.effect_progress[0].admitted_precondition =
            Some(admitted_precondition(&transaction));
        transaction.effect_progress[0].ownership_secret = Some(test_ownership_secret(
            InstallationCreateDisposition::NotAttempted,
            InstallationSecretLifecycle::Active,
        ));
        let intent_digest = must(effect_request(
            &transaction,
            0,
            1,
            InstallationEffectAction::Apply,
            None,
        ))
        .intent_digest()
        .unwrap_or_else(|error| panic!("intent digest: {error}"));
        transaction.effect_progress[0].state = InstallationEffectProgressState::IntentCommitted {
            attempt: 1,
            intent_digest: intent_digest.clone(),
        };
        transaction.pending_external_changes = vec![intent_digest];
        transaction.stage = InstallationStage::RollbackRequired;
        transaction.revision = 3;
        must(transaction.validate());
        let store = SharedStore {
            state: Arc::new(Mutex::new(Some(transaction))),
            ..SharedStore::default()
        };
        let execute_count = Arc::new(Mutex::new(0));
        let port = fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone());
        let mut coordinator = InstallationCoordinator::new(port, store.clone());

        assert!(matches!(
            must(coordinator.rollback(&transaction_id)),
            InstallationStepOutcome::Quarantined { .. }
        ));
        assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
        let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert_eq!(saved.stage, InstallationStage::Quarantined);
    }

    #[test]
    fn progress_is_exactly_one_to_one_and_plan_digest_is_immutable() {
        let mut transaction = planned_transaction();
        transaction.effect_progress.pop();
        assert!(matches!(
            transaction.validate(),
            Err(InstallationError::IdentityConflict)
        ));

        let mut transaction = planned_transaction();
        transaction.effect_progress[0].effect_id = test_handle("effect:wrong");
        assert!(matches!(
            transaction.validate(),
            Err(InstallationError::IdentityConflict)
        ));

        let mut transaction = planned_transaction();
        transaction.installer_plan_digest = test_handle("c".repeat(64));
        assert!(transaction.validate().is_err());

        let mut transaction = planned_transaction();
        transaction.effect_progress[1].state = InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::PreexistingMatching,
            external_identity: test_handle("external:out-of-order"),
            evidence: vec![test_handle("evidence:out-of-order")],
            postcondition_digest: test_handle("d".repeat(64)),
        };
        assert!(transaction.validate().is_err());
    }

    #[test]
    fn effect_request_carries_exactly_one_plan_and_precondition() {
        let transaction = planned_transaction();
        let request = must(effect_request(
            &transaction,
            0,
            1,
            InstallationEffectAction::Apply,
            None,
        ));
        assert_eq!(
            request.effect_id,
            *transaction.installer_effects[0].effect_id()
        );
        assert_eq!(request.plan_digest, transaction.installer_plan_digest);
        assert_eq!(
            request.installation_root,
            transaction
                .candidate_manifest
                .runtime_launch
                .runtime_state_roots
                .installation_root
        );
        assert_eq!(
            request.precondition.evidence_refs,
            transaction.planned_changes[0].precondition_refs
        );
        let (platform_request, operation) = must(windows_root_spec(&request));
        assert_eq!(
            platform_request.installation_root,
            Path::new(request.installation_root.as_str())
        );
        assert_eq!(platform_request.profile, InstallerRootProfile::PortableDev);
        assert_eq!(operation, WindowsRootOperation::Create);
        let encoded = must(serde_json::to_value(request));
        assert!(encoded.get("plan").is_some());
        assert!(encoded.get("change_refs").is_none());
        assert!(encoded.get("candidate_generation").is_none());
        assert!(encoded.get("installation").is_none());
    }

    #[test]
    fn create_planned_rejects_caller_advanced_state() {
        let mut transaction = planned_transaction();
        transaction.stage = InstallationStage::Staging;
        transaction.completed_stage_refs = vec![test_handle("evidence:advanced")];
        transaction.revision = 2;
        let mut store = SharedStore::default();
        assert!(store.create_planned(&transaction).is_err());
    }

    #[test]
    fn pre_v7_transaction_json_requires_explicit_migration() {
        let mut legacy = must(serde_json::to_value(planned_transaction()));
        let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
        object.remove("transaction_wire_version");
        object.remove("effect_progress");
        let bytes = must(serde_json::to_vec(&legacy));
        assert!(matches!(
            decode_installation_transaction_json(&bytes),
            Err(InstallationError::MigrationRequired { .. })
        ));
    }

    #[test]
    fn v6_transaction_json_requires_explicit_migration_to_v7() {
        let mut legacy = must(serde_json::to_value(planned_transaction()));
        let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
        object.insert(
            "transaction_wire_version".to_owned(),
            must(serde_json::to_value(ContractVersion::new(6, 0, 0))),
        );
        let bytes = must(serde_json::to_vec(&legacy));
        let Err(error) = decode_installation_transaction_json(&bytes) else {
            panic!("v6 transaction must require migration");
        };
        assert!(matches!(
            error,
            InstallationError::MigrationRequired { reason }
                if reason.contains("requires explicit migration to 7.0.0")
        ));
    }

    #[test]
    fn v4_transaction_json_requires_explicit_migration_without_defaults() {
        let mut legacy = must(serde_json::to_value(planned_transaction()));
        let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
        object.insert(
            "transaction_wire_version".to_owned(),
            must(serde_json::to_value(ContractVersion::new(4, 0, 0))),
        );
        let bytes = must(serde_json::to_vec(&legacy));
        assert!(matches!(
            decode_installation_transaction_json(&bytes),
            Err(InstallationError::MigrationRequired { .. })
        ));
    }

    #[test]
    fn malformed_v7_transaction_json_is_corrupt_registry() {
        let bytes = br#"{"transaction_wire_version":{"major":7,"minor":0,"patch":0},"transaction_id":"malformed"}"#;
        assert!(matches!(
            decode_installation_transaction_json(bytes),
            Err(InstallationError::CorruptRegistry { .. })
        ));
    }

    #[test]
    fn redb_transaction_store_round_trips_and_enforces_cas() {
        let path = std::env::temp_dir().join(format!(
            "eliot-installation-transaction-roundtrip-{}.redb",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let transaction = planned_transaction();
        let id = transaction.transaction_id.clone();
        let mut store = must(RedbInstallationTransactionStore::create_at_exact_path(
            &path,
        ));
        must(store.create_planned(&transaction));
        assert_eq!(must(store.load(&id)), Some(transaction.clone()));
        drop(store);
        let mut store = must(RedbInstallationTransactionStore::open_existing_exact_path(
            &path,
        ));

        let mut advanced = transaction;
        must(advanced.advance(
            InstallationStage::Staging,
            vec![test_handle("evidence:redb-cas")],
        ));
        let initial_version = must(TransactionVersion::of(
            &must(store.load(&id)).unwrap_or_else(|| unreachable!()),
        ));
        must(transaction_store_private::Sealed::compare_and_save(
            &mut store,
            initial_version.clone(),
            &advanced,
        ));
        assert!(matches!(
            transaction_store_private::Sealed::compare_and_save(
                &mut store,
                initial_version,
                &advanced,
            ),
            Err(InstallationError::CompareAndSaveConflict {
                expected: 1,
                actual: 2
            })
        ));
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn portable_runtime_roots_accept_distinct_sibling_topology() {
        let directory = std::env::temp_dir().join("eliot-portable-root-siblings");
        provision_portable_test_root(&directory);
        let root = test_handle(directory.to_string_lossy().into_owned());
        let roots = must(RuntimeStateRoots::derive_portable(root));
        assert!(roots.validate().is_ok());
        assert_ne!(roots.kernel_work_root, roots.store_work_root);
        assert_ne!(roots.store_data_root, roots.store_temp_root);
    }

    #[test]
    fn runtime_roots_reject_traversal_and_device_prefixes() {
        assert!(
            RuntimeStateRoots::derive_portable(test_handle(r"C:\portable\..\escaped")).is_err()
        );
        assert!(RuntimeStateRoots::derive_portable(test_handle(r"\\?\C:\portable\eliot")).is_err());
    }

    #[test]
    fn windows_root_overlap_is_case_insensitive_and_component_aware() {
        let parent = must(WindowsPathIdentity::parse_root(
            r"C:\Runtime\Store",
            "parent",
        ));
        let child = must(WindowsPathIdentity::parse_root(
            r"c:/runtime/STORE/data",
            "child",
        ));
        let component_prefix = must(WindowsPathIdentity::parse_root(
            r"C:\Runtime\Storehouse",
            "component_prefix",
        ));
        assert!(parent.aliases_or_overlaps(&child));
        assert!(!parent.aliases_or_overlaps(&component_prefix));
    }

    #[test]
    fn runtime_roots_reject_system_escape_and_portable_system_alias() {
        let program_data = must(protected_program_data_root());
        let unrelated = std::env::temp_dir().join("eliot-wrong-system-anchor");
        std::fs::create_dir_all(&unrelated).unwrap_or_else(|_| unreachable!());
        assert!(
            RuntimeStateRoots::derive_profiled(
                InstallationProfile::SystemService,
                test_handle(unrelated.to_string_lossy().into_owned()),
                &"a".repeat(64),
            )
            .is_err(),
            "SystemService must not silently replace an unproven anchor"
        );
        assert!(
            RuntimeStateRoots::derive_profiled(
                InstallationProfile::UserMode,
                test_handle(program_data.to_string_lossy().into_owned()),
                &"a".repeat(64),
            )
            .is_err(),
            "UserMode must not silently fall back to ProgramData"
        );
        let mut system = must(RuntimeStateRoots::derive_profiled(
            InstallationProfile::SystemService,
            test_handle(program_data.to_string_lossy().into_owned()),
            &"b".repeat(64),
        ));
        system.store_data_root = test_handle(r"C:\outside\store\data");
        reseal_roots(&mut system);
        assert!(system.validate().is_err());

        let profiled = test_handle(format!(
            r"{}\Eliot\installations\{}",
            program_data.to_string_lossy(),
            "c".repeat(64)
        ));
        assert!(
            RuntimeStateRoots::derived(
                InstallationProfile::PortableDev,
                profiled.clone(),
                profiled,
            )
            .is_err(),
            "portable profile must not alias a profiled durable root"
        );
    }

    #[test]
    fn retained_root_hook_rejects_reparse_evidence() {
        let directory = std::env::temp_dir().join("eliot-retained-root-test");
        provision_portable_test_root(&directory);
        let roots = must(RuntimeStateRoots::derive_portable(test_handle(
            directory.to_string_lossy().into_owned(),
        )));
        let mut provider = FakeRuntimeRootLeaseProvider {
            next: 0,
            reparse_at: Some(3),
            alias_identity: false,
        };
        assert!(roots.retain_and_validate(&mut provider).is_err());

        let mut provider = FakeRuntimeRootLeaseProvider {
            next: 0,
            reparse_at: None,
            alias_identity: false,
        };
        let retained = must(roots.retain_and_validate(&mut provider));
        assert_eq!(retained.leases().len(), 7);

        let mut provider = FakeRuntimeRootLeaseProvider {
            next: 0,
            reparse_at: None,
            alias_identity: true,
        };
        assert!(roots.retain_and_validate(&mut provider).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_provider_retains_portable_roots_by_handle() {
        let directory = std::env::temp_dir().join("eliot-production-retained-root-test");
        provision_portable_test_root(&directory);
        let roots = must(RuntimeStateRoots::derive_portable(test_handle(
            directory.to_string_lossy().into_owned(),
        )));
        for (_, root) in roots.root_fields() {
            provision_portable_test_root(Path::new(root.as_str()));
        }
        let mut provider = must(WindowsRuntimeRootLeaseProvider::for_roots(&roots));
        let retained = must(roots.retain_and_validate(&mut provider));
        assert_eq!(retained.leases().len(), 7);
    }

    #[cfg(windows)]
    #[test]
    fn system_retained_validation_does_not_create_missing_roots_or_sentinel() {
        let program_data = must(protected_program_data_root());
        let unique = sha256_hex(
            format!("{}:{:?}", std::process::id(), std::time::SystemTime::now()).as_bytes(),
        );
        let roots = must(RuntimeStateRoots::derive_profiled(
            InstallationProfile::SystemService,
            test_handle(program_data.to_string_lossy().into_owned()),
            &unique,
        ));
        assert!(!Path::new(roots.installation_root.as_str()).exists());
        let mut provider = must(WindowsRuntimeRootLeaseProvider::for_roots(&roots));
        assert!(roots.retain_and_validate(&mut provider).is_err());
        assert!(
            !Path::new(roots.installation_root.as_str()).exists(),
            "retained validation must not create directories or sentinel files"
        );
    }

    #[test]
    fn manifest_rejects_runtime_root_tampering_after_approval() {
        let mut manifest = registering_transaction().candidate_manifest;
        manifest.runtime_launch.runtime_state_roots.store_data_root =
            test_handle(r"C:\Development\scratch\tampered-store-data");
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn installer_plan_binds_local_service_and_unknown_space_requires_recovery() {
        let program_data = must(protected_program_data_root());
        let roots = must(RuntimeStateRoots::derive_profiled(
            InstallationProfile::SystemService,
            test_handle(program_data.to_string_lossy().into_owned()),
            &"d".repeat(64),
        ));
        let (changes, effects) = installer_plan_parts(&roots);
        assert!(
            validate_installer_effects(
                InstallationProfile::SystemService,
                &roots,
                &test_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
                &changes,
                &effects,
            )
            .is_ok()
        );
        let services = effects
            .iter()
            .filter_map(|effect| match effect {
                InstallerEffectPlan::RegisterService {
                    role,
                    service_name,
                    account,
                    automatic_start,
                    ..
                } => Some((*role, service_name.as_str(), *account, *automatic_start)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            services,
            vec![
                (
                    InstallerServiceRole::Host,
                    ELIOT_HOST_SERVICE_NAME,
                    InstallerServiceAccount::LocalService,
                    true,
                ),
                (
                    InstallerServiceRole::Watchdog,
                    ELIOT_WATCHDOG_SERVICE_NAME,
                    InstallerServiceAccount::LocalService,
                    true,
                ),
            ]
        );
        let mut transaction = registering_transaction();
        let outcome = must(transaction.record_store_free_space(
            StoreFreeSpaceObservation::Unknown {
                evidence_refs: vec![test_handle("failure:free-space-unobserved")],
            },
        ));
        assert!(matches!(
            outcome,
            InstallationStepOutcome::RollbackRequired { .. }
        ));
        assert_eq!(transaction.stage, InstallationStage::RollbackRequired);
    }

    #[test]
    fn installer_plan_rejects_credential_target_not_bound_to_candidate_launch() {
        let program_data = must(protected_program_data_root());
        let roots = must(RuntimeStateRoots::derive_profiled(
            InstallationProfile::SystemService,
            test_handle(program_data.to_string_lossy().into_owned()),
            &"f".repeat(64),
        ));
        let (changes, mut effects) = installer_plan_parts(&roots);
        let credential_effect = effects
            .iter_mut()
            .find_map(|effect| match effect {
                InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => Some(provision),
                _ => None,
            })
            .unwrap_or_else(|| unreachable!());
        credential_effect.target = test_handle("eliot/store/v1/fedcba9876543210fedcba9876543210");
        let Err(error) = validate_installer_effects(
            InstallationProfile::SystemService,
            &roots,
            &test_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            &changes,
            &effects,
        ) else {
            panic!("mismatched credential target must fail closed");
        };
        assert!(matches!(
            error,
            InstallationError::InvalidField { field, .. }
                if field == "installer_effect.provision.target"
        ));
    }

    #[test]
    fn installer_rejects_swapped_or_legacy_service_identity() {
        let program_data = must(protected_program_data_root());
        let roots = must(RuntimeStateRoots::derive_profiled(
            InstallationProfile::SystemService,
            test_handle(program_data.to_string_lossy().into_owned()),
            &"e".repeat(64),
        ));
        let (changes, mut effects) = installer_plan_parts(&roots);
        let host = effects
            .iter_mut()
            .find(|effect| {
                matches!(
                    effect,
                    InstallerEffectPlan::RegisterService {
                        role: InstallerServiceRole::Host,
                        ..
                    }
                )
            })
            .unwrap_or_else(|| unreachable!());
        if let InstallerEffectPlan::RegisterService { service_name, .. } = host {
            *service_name = test_handle("eliot-host");
        }

        assert!(
            validate_installer_effects(
                InstallationProfile::SystemService,
                &roots,
                &test_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
                &changes,
                &effects,
            )
            .is_err()
        );
    }

    #[test]
    fn installer_effects_have_no_second_transaction_identity() {
        let mut transaction = registering_transaction();
        let encoded = must(serde_json::to_value(&transaction));
        assert!(encoded.get("transaction_id").is_some());
        let effects = encoded
            .get("installer_effects")
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| unreachable!());
        assert!(effects.iter().all(|effect| {
            effect.get("transaction_id").is_none()
                && effect.get("stage").is_none()
                && effect.get("disposition").is_none()
        }));

        transaction.installer_effects[0] = transaction.installer_effects[1].clone();
        assert!(transaction.validate().is_err());
    }

    #[test]
    fn runtime_launch_descriptor_binds_exact_arguments_and_rejects_tampering() {
        let transaction = registering_transaction();
        let descriptor = &transaction.candidate_manifest.runtime_launch;
        assert_eq!(
            descriptor
                .kernel_arguments
                .iter()
                .map(PlatformHandle::as_str)
                .collect::<Vec<_>>(),
            vec![
                "--work-root",
                descriptor.kernel_work_root.as_str(),
                "--store-bootstrap",
                descriptor.store_bootstrap_descriptor_path.as_str(),
                "--store-bootstrap-sha256",
                descriptor.store_bootstrap_descriptor_digest.as_str(),
                "--authority-descriptor",
                descriptor.authority_descriptor_path.as_str(),
                "--authority-descriptor-sha256",
                descriptor.authority_descriptor_digest.as_str(),
                "--kernel-artifact-sha256",
                descriptor.kernel_artifact_digest.as_str(),
                "--eliotd-descriptor",
                descriptor.eliotd_descriptor_path.as_str(),
                "--eliotd-descriptor-sha256",
                descriptor.eliotd_descriptor_digest.as_str(),
            ]
        );
        assert_eq!(descriptor.store_bridge_arguments[2].as_str(), "--config");
        assert!(descriptor.validate().is_ok());
        let config = &transaction.candidate_manifest.config_path;
        assert!(descriptor.validate_for_config(config).is_ok());

        let mut tampered = descriptor.clone();
        tampered.store_bridge_arguments[0] = test_handle("--outside-root");
        assert!(tampered.validate_for_config(config).is_err());

        let mut missing_config = descriptor.clone();
        missing_config.store_bridge_arguments.truncate(2);
        assert!(missing_config.validate_for_config(config).is_err());

        let mut duplicate_config = descriptor.clone();
        duplicate_config
            .store_bridge_arguments
            .push(test_handle(config.as_str()));
        assert!(duplicate_config.validate_for_config(config).is_err());

        let mut alternate_config = descriptor.clone();
        alternate_config.store_bridge_arguments[3] = test_path(
            &std::env::temp_dir(),
            "eliot-installation-alternate-config.json",
        );
        assert!(alternate_config.validate_for_config(config).is_err());

        let mut missing_root = descriptor.clone();
        missing_root.portable_root = None;
        assert!(missing_root.validate().is_err());

        let mut relative_authority = descriptor.clone();
        relative_authority.authority_descriptor_path = test_handle("authority.json");
        assert!(relative_authority.validate().is_err());

        let mut uppercase_authority_digest = descriptor.clone();
        uppercase_authority_digest.authority_descriptor_digest = test_handle("A".repeat(64));
        assert!(uppercase_authority_digest.validate().is_err());

        let mut missing_authority = descriptor.clone();
        missing_authority.kernel_arguments.truncate(4);
        assert!(missing_authority.validate_for_config(config).is_err());

        let mut missing_store_digest = descriptor.clone();
        missing_store_digest.kernel_arguments.remove(4);
        missing_store_digest.kernel_arguments.remove(4);
        assert!(missing_store_digest.validate_for_config(config).is_err());

        let mut substituted_store_digest = descriptor.clone();
        substituted_store_digest.kernel_arguments[5] = test_handle("9".repeat(64));
        assert!(
            substituted_store_digest
                .validate_for_config(config)
                .is_err()
        );

        let mut duplicate_store_flag = descriptor.clone();
        duplicate_store_flag
            .kernel_arguments
            .insert(4, test_handle("--store-bootstrap"));
        assert!(duplicate_store_flag.validate_for_config(config).is_err());

        let mut unknown_store_flag = descriptor.clone();
        unknown_store_flag.kernel_arguments[4] = test_handle("--unknown-store");
        assert!(unknown_store_flag.validate_for_config(config).is_err());

        let mut wrong_store_order = descriptor.clone();
        wrong_store_order.kernel_arguments.swap(4, 6);
        assert!(wrong_store_order.validate_for_config(config).is_err());

        let mut duplicate_authority = descriptor.clone();
        duplicate_authority
            .kernel_arguments
            .insert(4, test_handle("--authority-descriptor"));
        assert!(duplicate_authority.validate_for_config(config).is_err());

        let mut unknown_authority = descriptor.clone();
        unknown_authority.kernel_arguments[4] = test_handle("--unknown-authority");
        assert!(unknown_authority.validate_for_config(config).is_err());

        let mut wrong_authority_order = descriptor.clone();
        wrong_authority_order.kernel_arguments.swap(6, 8);
        assert!(wrong_authority_order.validate_for_config(config).is_err());
    }

    #[test]
    fn host_child_materialization_selects_bridge_not_provider() {
        let transaction = registering_transaction();
        let manifest = &transaction.candidate_manifest;
        let (_, host_store_path, _) = manifest.host_child_paths();
        let (_, host_store_digest) = must(manifest.host_child_artifact_digests());
        assert_eq!(host_store_path, &manifest.store_bridge_executable_path);
        assert_eq!(host_store_digest, &manifest.store_bridge_artifact_digest);
        assert_ne!(host_store_path, &manifest.canonical_store_executable_path);
    }

    #[test]
    fn split_store_argv_rejects_resealed_semantic_substitution() {
        let descriptor = registering_transaction().candidate_manifest.runtime_launch;
        let mut bridge_tamper = descriptor.clone();
        bridge_tamper.store_bridge_arguments[0] = test_handle("--outside-root");
        bridge_tamper.descriptor_digest =
            test_handle(sha256_hex(&must(bridge_tamper.unsigned_bytes())));
        assert!(bridge_tamper.validate().is_err());

        let mut provider_bind_change = descriptor.clone();
        provider_bind_change.canonical_store_arguments[3] = test_handle("127.0.0.1:9000");
        provider_bind_change.descriptor_digest =
            test_handle(sha256_hex(&must(provider_bind_change.unsigned_bytes())));
        assert!(provider_bind_change.validate().is_ok());

        let mut provider_root_substitution = descriptor;
        provider_root_substitution.canonical_store_arguments[5] = provider_root_substitution
            .runtime_state_roots
            .store_work_root
            .clone();
        provider_root_substitution.descriptor_digest = test_handle(sha256_hex(&must(
            provider_root_substitution.unsigned_bytes(),
        )));
        assert!(provider_root_substitution.validate().is_err());
    }

    #[test]
    fn runtime_launch_digest_covers_store_and_authority_inputs() {
        let transaction = registering_transaction();
        let descriptor = transaction.candidate_manifest.runtime_launch;
        assert!(valid_installation_key(
            descriptor.descriptor_digest.as_str()
        ));
        let original = descriptor.descriptor_digest.clone();

        let mut store_path = descriptor.clone();
        store_path.store_bridge_executable_path =
            test_path(&std::env::temp_dir(), "alternate-eliot-store-surreal.exe");
        assert_ne!(
            sha256_hex(&must(store_path.unsigned_bytes())),
            original.as_str()
        );

        let mut authority_digest = descriptor.clone();
        authority_digest.authority_descriptor_digest = test_handle("8".repeat(64));
        assert_ne!(
            sha256_hex(&must(authority_digest.unsigned_bytes())),
            original.as_str()
        );

        let mut child_digest = descriptor.clone();
        child_digest.eliotd_artifact_digest = test_handle("9".repeat(64));
        assert_ne!(
            sha256_hex(&must(child_digest.unsigned_bytes())),
            original.as_str()
        );

        let mut daemon_config_path = descriptor.clone();
        daemon_config_path.eliotd_config_path =
            test_path(&std::env::temp_dir(), "alternate-eliotd-governor.json");
        assert_ne!(
            sha256_hex(&must(daemon_config_path.unsigned_bytes())),
            original.as_str()
        );

        let mut daemon_config_digest = descriptor.clone();
        daemon_config_digest.eliotd_config_digest = test_handle("6".repeat(64));
        assert_ne!(
            sha256_hex(&must(daemon_config_digest.unsigned_bytes())),
            original.as_str()
        );

        let mut child_argument_swap = descriptor;
        let config_path = transaction.candidate_manifest.config_path;
        child_argument_swap.kernel_arguments[11] = test_handle("9".repeat(64));
        assert!(
            child_argument_swap
                .validate_for_config(&config_path)
                .is_err()
        );
    }

    #[test]
    fn runtime_launch_rejects_binding_mismatches_and_unknown_fields() {
        let transaction = registering_transaction();
        let descriptor = &transaction.candidate_manifest.runtime_launch;

        let mut unknown = must(serde_json::to_value(descriptor));
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RuntimeLaunchDescriptor>(unknown).is_err());

        let mut wrong_generation = transaction.candidate_manifest.clone();
        wrong_generation.runtime_launch.generation = test_handle("generation:other");
        assert!(wrong_generation.validate().is_err());

        let mut wrong_credential_target = transaction.candidate_manifest.clone();
        wrong_credential_target.store_credential_target =
            test_handle("eliot/store/v1/fedcba9876543210fedcba9876543210");
        assert!(wrong_credential_target.validate().is_err());

        let mut invalid_credential_target = transaction.candidate_manifest.clone();
        invalid_credential_target
            .runtime_launch
            .store_credential_target = test_handle("eliot/store");
        assert!(invalid_credential_target.validate().is_err());

        let mut wrong_fence = descriptor.clone();
        wrong_fence.authority_generation = must(ResourceGeneration::new(2));
        assert!(wrong_fence.validate().is_err());

        let mut wrong_installation = transaction;
        wrong_installation
            .candidate_manifest
            .runtime_launch
            .installation_epoch
            .sequence = 2;
        assert!(wrong_installation.validate().is_err());

        let mut wrong_profile = registering_transaction();
        wrong_profile.profile = InstallationProfile::SystemService;
        assert!(wrong_profile.validate().is_err());

        let transaction = registering_transaction();
        let result = InstallationTransaction::new(
            transaction.transaction_id.clone(),
            transaction.installation_epoch.clone(),
            InstallationProfile::SystemService,
            transaction.request.clone(),
            transaction.current_active_manifest.clone(),
            transaction.candidate_manifest.clone(),
            transaction.staging_root.clone(),
            transaction.planned_changes.clone(),
            transaction.installer_effects.clone(),
            transaction.minimum_store_available_bytes,
            transaction.precondition_evidence.clone(),
            transaction.recovery_command.clone(),
        );
        assert!(result.is_err());
    }

    fn authority_alias(path: &PlatformHandle) -> PlatformHandle {
        let path = Path::new(path.as_str());
        let parent = match path.parent() {
            Some(parent) => parent,
            None => panic!("fixture path parent"),
        }
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_uppercase();
        let file = match path.file_name() {
            Some(file) => file,
            None => panic!("fixture path file"),
        }
        .to_string_lossy()
        .to_ascii_uppercase();
        test_handle(format!("{parent}/./{file}/"))
    }

    fn reseal(descriptor: &mut RuntimeLaunchDescriptor) {
        descriptor.descriptor_digest = test_handle(sha256_hex(&must(descriptor.unsigned_bytes())));
    }

    #[test]
    fn authority_path_rejects_windows_lexical_aliases_without_rejecting_prefixes() {
        let transaction = registering_transaction();
        let mut manifest = transaction.candidate_manifest;
        let config = manifest.config_path.clone();
        manifest.runtime_launch.authority_descriptor_path = authority_alias(&config);
        reseal(&mut manifest.runtime_launch);
        assert!(manifest.validate().is_err());

        let mut prefix = registering_transaction().candidate_manifest.runtime_launch;
        let root = Path::new(prefix.authority_descriptor_path.as_str());
        prefix.authority_descriptor_path = test_handle(
            match root.parent() {
                Some(parent) => parent.join("generation.jsonx"),
                None => panic!("authority parent"),
            }
            .to_string_lossy()
            .into_owned(),
        );
        reseal(&mut prefix);
        assert!(prefix.validate().is_ok());

        let valid = registering_transaction().candidate_manifest.runtime_launch;
        assert_eq!(
            valid.portable_root.as_ref(),
            Some(&valid.runtime_state_roots.installation_root)
        );
        assert_ne!(valid.portable_root.as_ref(), Some(&valid.kernel_work_root));
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn lexical_windows_path_unifies_supported_verbatim_aliases_only() {
        assert_eq!(
            lexical_windows_path(r"C:\x").as_deref(),
            lexical_windows_path(r"\\?\C:\x").as_deref()
        );
        assert_eq!(
            lexical_windows_path(r"\\server\share\x").as_deref(),
            lexical_windows_path(r"\\?\UNC\server\share\x").as_deref()
        );
        assert_eq!(
            lexical_windows_path(r"c:/Root/./Child/").as_deref(),
            Some(r"c:\root\child")
        );
        assert_ne!(
            lexical_windows_path(r"C:\x").as_deref(),
            lexical_windows_path(r"C:\x-prefix").as_deref()
        );
        assert!(lexical_windows_path(r"\\.\pipe\eliot").is_none());
        assert!(lexical_windows_path(r"\\?\Volume{abc}\x").is_none());
        assert!(lexical_windows_path(r"\Device\HarddiskVolume1\x").is_none());
    }

    #[cfg(windows)]
    #[test]
    fn approved_path_rejects_unsupported_windows_device_prefixes() {
        assert!(approved_path(&test_handle(r"\\.\pipe\eliot"), "device_path").is_err());
        assert!(approved_path(&test_handle(r"\\?\Volume{abc}\x"), "device_path").is_err());
    }

    fn v1_registry_value() -> serde_json::Value {
        let transaction = registering_transaction();
        let generation = transaction.candidate_manifest.generation.clone();
        let registry = ApprovedGenerationRegistry {
            generations: vec![ApprovedGeneration {
                manifest: transaction.candidate_manifest,
                approval_ref: test_handle("approval:legacy"),
                active: true,
                last_known_good: false,
            }],
            active_generation: Some(generation),
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
        };
        let mut legacy = must(serde_json::to_value(registry));
        let Some(object) = legacy.as_object_mut() else {
            panic!("legacy registry object");
        };
        object.remove("pending_activation");
        let Some(runtime) = legacy["generations"][0]["manifest"]["runtime_launch"].as_object_mut()
        else {
            panic!("legacy fixture runtime launch");
        };
        runtime.remove("host_executable_path");
        runtime.remove("host_artifact_digest");
        runtime.remove("store_credential_target");
        runtime.remove("store_bridge_arguments");
        runtime.remove("runtime_state_roots");
        for field in [
            "eliotd_executable_path",
            "eliotd_artifact_digest",
            "eliotd_config_path",
            "eliotd_config_digest",
            "eliotd_descriptor_path",
            "eliotd_descriptor_digest",
            "eliotd_launch_nonce",
        ] {
            runtime.remove(field);
        }
        let Some(manifest) = legacy["generations"][0]["manifest"].as_object_mut() else {
            panic!("v1 fixture manifest");
        };
        manifest.remove("host_executable_path");
        manifest.remove("host_artifact_digest");
        manifest.remove("store_credential_target");
        manifest.remove("runtime_state_roots_digest");
        legacy
    }

    fn pre_split_registry_value() -> serde_json::Value {
        let transaction = registering_transaction();
        let generation = transaction.candidate_manifest.generation.clone();
        let registry = ApprovedGenerationRegistry {
            generations: vec![ApprovedGeneration {
                manifest: transaction.candidate_manifest,
                approval_ref: test_handle("approval:pre-split"),
                active: true,
                last_known_good: false,
            }],
            active_generation: Some(generation),
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
        };
        let mut value = must(serde_json::to_value(registry));
        let Some(object) = value.as_object_mut() else {
            panic!("pre-split registry object");
        };
        object.remove("pending_activation");
        let Some(manifest) = value["generations"][0]["manifest"].as_object_mut() else {
            panic!("pre-split fixture manifest");
        };
        manifest.remove("host_executable_path");
        manifest.remove("host_artifact_digest");
        manifest.remove("store_credential_target");
        let Some(runtime) = value["generations"][0]["manifest"]["runtime_launch"].as_object_mut()
        else {
            panic!("pre-split fixture runtime launch");
        };
        runtime.remove("host_executable_path");
        runtime.remove("host_artifact_digest");
        runtime.remove("store_credential_target");
        for field in [
            "eliotd_executable_path",
            "eliotd_artifact_digest",
            "eliotd_config_path",
            "eliotd_config_digest",
            "eliotd_descriptor_path",
            "eliotd_descriptor_digest",
            "eliotd_launch_nonce",
        ] {
            runtime.remove(field);
        }
        let bridge_arguments = runtime
            .remove("store_bridge_arguments")
            .unwrap_or_else(|| panic!("pre-split bridge arguments"));
        runtime.insert("canonical_store_arguments".to_owned(), bridge_arguments);
        value
    }

    fn pre_credential_binding_registry_value() -> serde_json::Value {
        let transaction = registering_transaction();
        let generation = transaction.candidate_manifest.generation.clone();
        let registry = ApprovedGenerationRegistry {
            generations: vec![ApprovedGeneration {
                manifest: transaction.candidate_manifest,
                approval_ref: test_handle("approval:pre-credential-binding"),
                active: true,
                last_known_good: false,
            }],
            active_generation: Some(generation),
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
        };
        let mut value = must(serde_json::to_value(registry));
        let Some(manifest) = value["generations"][0]["manifest"].as_object_mut() else {
            panic!("pre-credential-binding fixture manifest");
        };
        manifest.remove("host_executable_path");
        manifest.remove("host_artifact_digest");
        manifest.remove("store_credential_target");
        let Some(runtime) = value["generations"][0]["manifest"]["runtime_launch"].as_object_mut()
        else {
            panic!("pre-credential-binding fixture runtime launch");
        };
        runtime.remove("host_executable_path");
        runtime.remove("host_artifact_digest");
        runtime.remove("store_credential_target");
        for field in [
            "eliotd_executable_path",
            "eliotd_artifact_digest",
            "eliotd_config_path",
            "eliotd_config_digest",
            "eliotd_descriptor_path",
            "eliotd_descriptor_digest",
            "eliotd_launch_nonce",
        ] {
            runtime.remove(field);
        }
        value
    }

    fn pre_eliotd_config_registry_value() -> serde_json::Value {
        let transaction = registering_transaction();
        let generation = transaction.candidate_manifest.generation.clone();
        let registry = ApprovedGenerationRegistry {
            generations: vec![ApprovedGeneration {
                manifest: transaction.candidate_manifest,
                approval_ref: test_handle("approval:pre-eliotd-config"),
                active: true,
                last_known_good: false,
            }],
            active_generation: Some(generation),
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
        };
        let mut value = must(serde_json::to_value(registry));
        let Some(runtime) = value["generations"][0]["manifest"]["runtime_launch"].as_object_mut()
        else {
            panic!("pre-eliotd-config fixture runtime launch");
        };
        runtime.remove("eliotd_config_path");
        runtime.remove("eliotd_config_digest");
        value
    }

    fn pre_host_artifact_binding_registry_value() -> serde_json::Value {
        let transaction = registering_transaction();
        let generation = transaction.candidate_manifest.generation.clone();
        let registry = ApprovedGenerationRegistry {
            generations: vec![ApprovedGeneration {
                manifest: transaction.candidate_manifest,
                approval_ref: test_handle("approval:pre-host-artifact-binding"),
                active: true,
                last_known_good: false,
            }],
            active_generation: Some(generation),
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
        };
        let mut value = must(serde_json::to_value(registry));
        let Some(manifest) = value["generations"][0]["manifest"].as_object_mut() else {
            panic!("pre-host-artifact-binding fixture manifest");
        };
        manifest.remove("host_executable_path");
        manifest.remove("host_artifact_digest");
        let Some(runtime) = value["generations"][0]["manifest"]["runtime_launch"].as_object_mut()
        else {
            panic!("pre-host-artifact-binding fixture runtime launch");
        };
        runtime.remove("host_executable_path");
        runtime.remove("host_artifact_digest");
        value
    }

    #[test]
    fn pre_split_argv_registry_requires_explicit_restage() {
        let bytes = must(serde_json::to_vec(&pre_split_registry_value()));
        assert!(matches!(
            decode_registry_bytes(&bytes),
            Err(InstallationError::MigrationRequired { .. })
        ));
    }

    #[test]
    fn pre_credential_binding_registry_requires_explicit_restage() {
        let bytes = must(serde_json::to_vec(&pre_credential_binding_registry_value()));
        let Err(error) = decode_registry_bytes(&bytes) else {
            panic!("pre-credential-binding registry must require migration");
        };
        assert!(matches!(
            error,
            InstallationError::MigrationRequired { reason }
                if reason.contains("descriptor-bound Store credential target")
        ));
    }

    #[test]
    fn pre_eliotd_config_registry_requires_explicit_restage() {
        let bytes = must(serde_json::to_vec(&pre_eliotd_config_registry_value()));
        let Err(error) = decode_registry_bytes(&bytes) else {
            panic!("pre-eliotd-config registry must require migration");
        };
        assert!(matches!(
            error,
            InstallationError::MigrationRequired { reason }
                if reason.contains("separate eliotd Governor config")
        ));
    }

    #[test]
    fn pre_host_artifact_binding_registry_requires_explicit_restage() {
        let bytes = must(serde_json::to_vec(
            &pre_host_artifact_binding_registry_value(),
        ));
        let Err(error) = decode_registry_bytes(&bytes) else {
            panic!("pre-Host-artifact-binding registry must require migration");
        };
        assert!(matches!(
            error,
            InstallationError::MigrationRequired { reason }
                if reason.contains("approved Host executable artifact binding")
        ));
    }

    #[test]
    fn pending_activation_is_not_active_until_host_commit_and_retries_by_digest() {
        let transaction = registering_transaction();
        let host = host_capability();
        let mut registry = ApprovedGenerationRegistry::new();
        must(registry.stage_pending_activation(
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            transaction.candidate_manifest.clone(),
            test_handle("approval:pending"),
        ));
        assert!(registry.active().is_none());
        assert!(registry.pending_activation().is_some());
        must(registry.stage_pending_activation(
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            transaction.candidate_manifest.clone(),
            test_handle("approval:pending"),
        ));
        must(registry.mark_pending_recovery(
            &host,
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
            "simulated pre-launch crash",
        ));
        must(registry.stage_pending_activation(
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            transaction.candidate_manifest.clone(),
            test_handle("approval:pending"),
        ));
        assert!(matches!(
            registry.pending_activation().map(|pending| &pending.state),
            Some(PendingActivationState::RecoveryRequired { .. })
        ));
        assert!(matches!(
            must(registry.claim_pending_activation(
                &host,
                &transaction.transaction_id,
                &transaction.installer_plan_digest,
                &transaction.candidate_manifest.generation,
            ))
            .state,
            PendingActivationState::Pending
        ));
        assert!(matches!(
            must(registry.claim_pending_activation(
                &host,
                &transaction.transaction_id,
                &transaction.installer_plan_digest,
                &transaction.candidate_manifest.generation,
            ))
            .state,
            PendingActivationState::Pending
        ));
        let wrong_plan = test_handle("f".repeat(64));
        assert!(matches!(
            registry.commit_pending_activation(
                &host,
                &transaction.transaction_id,
                &wrong_plan,
                &transaction.candidate_manifest.generation,
            ),
            Err(InstallationError::IdentityConflict)
        ));
        must(registry.commit_pending_activation(
            &host,
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
            &transaction.candidate_manifest.generation,
        ));
        assert!(registry.pending_activation().is_none());
        assert_eq!(
            registry.active_generation(),
            Some(&transaction.candidate_manifest.generation)
        );
        assert!(registry.last_known_good_generation().is_none());
        let bytes = must(serde_json::to_vec(&registry));
        let mut reloaded = must(decode_registry_bytes(&bytes));
        must(reloaded.commit_pending_activation(
            &host,
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
            &transaction.candidate_manifest.generation,
        ));
    }

    #[cfg(windows)]
    #[test]
    fn registry_mutations_reject_after_owner_release_without_state_change() {
        let (mut registry, transaction) = pending_registry_for_owner_gate();
        let (mut lease, capability) = live_host_capability();
        lease
            .release()
            .unwrap_or_else(|error| panic!("owner release failed: {error}"));
        assert_registry_mutations_rejected_after_owner_shutdown(
            &mut registry,
            &transaction,
            &capability,
        );
    }

    #[cfg(windows)]
    #[test]
    fn registry_mutations_reject_after_owner_drop_without_state_change() {
        let (mut registry, transaction) = pending_registry_for_owner_gate();
        let capability = {
            let (lease, capability) = live_host_capability();
            drop(lease);
            capability
        };
        assert_registry_mutations_rejected_after_owner_shutdown(
            &mut registry,
            &transaction,
            &capability,
        );
    }

    #[test]
    fn upgrade_failure_preserves_prior_active_and_rejects_binding_substitution() {
        let first = registering_transaction();
        let host = host_capability();
        let mut registry = ApprovedGenerationRegistry::new();
        must(registry.stage_pending_activation(
            first.transaction_id.clone(),
            first.installer_plan_digest.clone(),
            first.candidate_manifest.clone(),
            test_handle("approval:first"),
        ));
        must(registry.commit_pending_activation(
            &host,
            &first.transaction_id,
            &first.installer_plan_digest,
            &first.candidate_manifest.generation,
        ));

        let mut upgrade = first.candidate_manifest.clone();
        upgrade.generation = test_handle("generation:upgrade");
        upgrade.runtime_launch.generation = upgrade.generation.clone();
        upgrade.runtime_launch.descriptor_digest =
            test_handle(sha256_hex(&must(upgrade.runtime_launch.unsigned_bytes())));
        must(upgrade.validate());
        let upgrade_tx = test_handle("transaction:upgrade");
        let upgrade_plan = test_handle("a".repeat(64));
        must(registry.stage_pending_activation(
            upgrade_tx.clone(),
            upgrade_plan.clone(),
            upgrade.clone(),
            test_handle("approval:upgrade"),
        ));
        assert_eq!(
            registry.active_generation(),
            Some(&first.candidate_manifest.generation)
        );
        assert_eq!(
            registry
                .pending_activation()
                .and_then(|pending| pending.prior_active_generation.as_ref()),
            Some(&first.candidate_manifest.generation)
        );
        let original_pending = registry
            .pending_activation()
            .cloned()
            .unwrap_or_else(|| unreachable!());
        let wrong_root = {
            let mut pending = original_pending.clone();
            pending.runtime_state_roots_digest = test_handle("b".repeat(64));
            pending
        };
        registry.pending_activation = Some(wrong_root);
        assert!(registry.validate().is_err());
        registry.pending_activation = Some(original_pending);
        must(registry.mark_pending_recovery(
            &host,
            &upgrade_tx,
            &upgrade_plan,
            "journal-active-before-commit",
        ));
        assert_eq!(
            registry.active_generation(),
            Some(&first.candidate_manifest.generation)
        );
        assert_eq!(registry.last_known_good_generation(), None);
    }

    #[test]
    fn first_install_pending_abort_leaves_registry_empty() {
        let transaction = registering_transaction();
        let host = host_capability();
        let mut registry = ApprovedGenerationRegistry::new();
        must(registry.stage_pending_activation(
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            transaction.candidate_manifest,
            test_handle("approval:abort"),
        ));
        must(registry.abort_pending_activation(
            &host,
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
        ));
        must(registry.abort_pending_activation(
            &host,
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
        ));
        let bytes = must(serde_json::to_vec(&registry));
        let mut reloaded = must(decode_registry_bytes(&bytes));
        must(reloaded.abort_pending_activation(
            &host,
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
        ));
        assert!(registry.generations().is_empty());
        assert!(registry.active_generation().is_none());
        assert!(registry.last_known_good_generation().is_none());
        assert!(registry.pending_activation().is_none());
    }

    #[test]
    fn existing_redb_v1_record_requires_migration_instead_of_becoming_empty() {
        let legacy_bytes = must(serde_json::to_vec(&v1_registry_value()));

        let path = std::env::temp_dir().join(format!(
            "eliot-installation-legacy-registry-{}.redb",
            std::process::id()
        ));
        let database = must(Database::create(&path));
        let write = must(database.begin_write());
        {
            let mut table = must(write.open_table(REGISTRY_TABLE));
            must(table.insert("registry", legacy_bytes.as_slice()));
        }
        must(write.commit());
        let read = must(database.begin_read());
        let table = must(read.open_table(REGISTRY_TABLE));
        let Some(value) = must(table.get("registry")) else {
            panic!("legacy registry fixture record");
        };
        let Err(error) = decode_registry_bytes(value.value()) else {
            panic!("migration must be required");
        };
        assert!(matches!(error, InstallationError::MigrationRequired { .. }));
        drop(read);
        drop(database);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn inspect_existing_missing_registry_does_not_create_one() {
        let path = std::env::temp_dir().join(format!(
            "eliot-installation-registry-missing-{}.redb",
            std::process::id()
        ));
        assert!(
            !path.exists(),
            "test registry fixture unexpectedly exists: {}",
            path.display()
        );
        assert_eq!(
            must(RedbInstallationRegistry::inspect_existing(&path)),
            None
        );
        assert!(!path.exists(), "read-only inspection created a registry");
    }

    #[test]
    fn registry_decode_classifies_nonlegacy_bytes_as_corruption() {
        for bytes in [
            b"{\"generations\":[".to_vec(),
            must(serde_json::to_vec(&serde_json::json!([]))),
            must(serde_json::to_vec(&serde_json::json!({
                "generations": "wrong"
            }))),
            must(serde_json::to_vec(&serde_json::json!({
                "unrelated": true
            }))),
        ] {
            let Err(error) = decode_registry_bytes(&bytes) else {
                panic!("corrupt registry must fail closed");
            };
            assert!(matches!(error, InstallationError::CorruptRegistry { .. }));
        }

        let mut current = must(serde_json::to_value(ApprovedGenerationRegistry {
            generations: vec![ApprovedGeneration {
                manifest: registering_transaction().candidate_manifest,
                approval_ref: test_handle("approval:current"),
                active: true,
                last_known_good: false,
            }],
            active_generation: Some(test_handle("generation:missing")),
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
        }));
        let Err(error) = decode_registry_bytes(&must(serde_json::to_vec(&current))) else {
            panic!("current corruption must fail closed");
        };
        assert!(matches!(error, InstallationError::CorruptRegistry { .. }));

        current = v1_registry_value();
        current["unrelated"] = serde_json::json!(true);
        let Err(error) = decode_registry_bytes(&must(serde_json::to_vec(&current))) else {
            panic!("unknown legacy schema must fail closed");
        };
        assert!(matches!(error, InstallationError::CorruptRegistry { .. }));
    }

    #[test]
    fn manifest_rejects_unbound_store_config_alias() {
        let mut manifest = registering_transaction().candidate_manifest;
        manifest.runtime_launch.store_config_path = test_handle(
            std::env::temp_dir()
                .join("eliot-installation-unbound-store.json")
                .to_string_lossy()
                .into_owned(),
        );
        let error = match manifest.validate() {
            Ok(()) => panic!("unbound Store config must fail closed"),
            Err(error) => error,
        };
        assert!(
            matches!(error, InstallationError::InvalidField { field, .. } if field == "manifest.runtime_launch.store_config_path")
        );
    }

    #[test]
    fn manifest_rejects_eliotd_governor_config_domain_substitution() {
        let mut store_alias = registering_transaction().candidate_manifest;
        store_alias.runtime_launch.eliotd_config_path = store_alias.config_path.clone();
        reseal(&mut store_alias.runtime_launch);
        assert!(matches!(
            store_alias.validate(),
            Err(InstallationError::InvalidField { field, .. })
                if field == "manifest.runtime_launch.eliotd_config_path"
        ));

        let mut descriptor_alias = registering_transaction().candidate_manifest;
        descriptor_alias.runtime_launch.eliotd_config_path = descriptor_alias
            .runtime_launch
            .eliotd_descriptor_path
            .clone();
        reseal(&mut descriptor_alias.runtime_launch);
        assert!(matches!(
            descriptor_alias.validate(),
            Err(InstallationError::InvalidField { field, .. })
                if field == "manifest.runtime_launch.eliotd_config_path"
        ));
    }

    #[test]
    fn host_artifact_binding_is_exact_and_self_digest_bound() {
        let manifest = registering_transaction().candidate_manifest;
        let (path, digest) = must(manifest.host_artifact_binding());
        assert_eq!(path, &manifest.runtime_launch.host_executable_path);
        assert_eq!(digest, &manifest.runtime_launch.host_artifact_digest);

        let mut altered = manifest;
        altered.runtime_launch.host_artifact_digest = test_handle("9".repeat(64));
        assert!(altered.host_artifact_binding().is_err());
    }

    #[test]
    fn manifest_rejects_bridge_as_canonical_engine_and_aliased_paths() {
        let mut manifest = registering_transaction().candidate_manifest;
        manifest.canonical_store_executable_path = manifest.store_bridge_executable_path.clone();
        assert!(manifest.validate().is_err());

        let mut swapped = registering_transaction().candidate_manifest;
        swapped.canonical_store_executable_path =
            test_path(&std::env::temp_dir(), "wrong-canonical-engine.exe");
        assert!(swapped.validate().is_err());
    }
}
