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

pub use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
use eliot_contracts::{
    ContractIdentity, ContractVersion, contract_identity as make_contract_identity, sha256_hex,
};
use eliot_ipc::{NamedPipeTransport, TransportLimits};
pub use eliot_platform::PlatformHandle;
use eliot_platform::{
    InstallationObservation, InstallationPort, InstallationRequest, PortError, PortOutcome,
    ProviderError, ProviderErrorCode, UnknownReason,
};
pub use eliot_platform_windows::UserOwnedRootLease;
use eliot_platform_windows::{
    AuthenticodeVerdict, ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME,
    ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME, ELIOT_WATCHDOG_SERVICE_NAME, FileIdentity,
    HostOwnerEpochCapability, InstallerRootAbsentSnapshot, InstallerRootCreateDisposition,
    InstallerRootError, InstallerRootObjectSnapshot, InstallerRootPrimitiveObservation,
    InstallerRootPrimitiveSpec, InstallerRootProfile, InstallerSecretCreateDisposition,
    InstallerSecretObservation, PackageManifest, PackageStager, PackageStagingError,
    PackageStagingObservation, ProtectedPathError, ProtectedPathLease, ProtectedRootLease,
    ProtectedRuntimePathLease, ServiceAccount, ServiceBootstrapArguments,
    ServiceRegistrationCurrent, ServiceRegistrationInspection, ServiceRegistrationOutcome,
    ServiceRegistrationRequest, ServiceStartMode, StagingReceipt, TrustedSourceBundle,
    UserOwnedPathLease, UserOwnedRootReadLease, WindowsInstallerRootPrimitive,
    WindowsInstallerSecretProvider, WindowsPlatform, WindowsStoreCredentialTargetGenerator,
    current_user_local_app_data_root, fresh_service_registration_nonce,
    observe_running_eliot_host_process, protected_program_data_root,
    require_protected_program_data_path,
};
use redb::{
    Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition, TableHandle,
    WriteTransaction,
};
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
/// manifest predates the required Host artifact binding.  Version 9 adds the
/// private, durable activation-receipt binding: a transaction cannot be
/// re-opened as `ActiveVerified` without the exact registry terminal that
/// committed it.
pub const INSTALLATION_TRANSACTION_WIRE_VERSION: ContractVersion = ContractVersion::new(9, 0, 0);

/// Current durable approved-generation registry wire revision.
///
/// Registry wire version 3 makes both the wire discriminator and the
/// monotonic registry revision mandatory.  Older projections are never
/// defaulted into the current activation authority; they require explicit
/// re-stage.
pub const INSTALLATION_REGISTRY_WIRE_VERSION: ContractVersion = ContractVersion::new(4, 0, 0);

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

fn package_plan_error(error: &PackageStagingError) -> InstallationError {
    InstallationError::InvalidField {
        field: "installer_effect.package_manifest".to_owned(),
        reason: error.to_string(),
    }
}

fn validate_package_relative_text(value: &str, field: &str) -> Result<(), InstallationError> {
    eliot_platform_windows::validate_package_relative_path(Path::new(value))
        .map(|_| ())
        .map_err(|error| InstallationError::InvalidField {
            field: field.to_owned(),
            reason: error.to_string(),
        })
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

/// The typed approval binding for one installer-produced activation candidate.
///
/// This is an evidence reference plus the complete identity contour which Host
/// must consume.  It is deliberately not represented by a bare approval string:
/// changing any one of the transaction, manifest, request-owner, runtime
/// descriptor or authority-fence inputs invalidates the approval.
///
/// ```compile_fail
/// use eliot_installation::{InstallationActivationApproval, PlatformHandle};
/// fn forge(approval: &mut InstallationActivationApproval) {
///     approval.approval_ref = PlatformHandle::new("forged").unwrap();
/// }
/// ```
///
/// The approval is also intentionally not deserializable by callers. Only the
/// private registry wire decoder may reconstruct a durable approval record;
/// external JSON must first pass through the signed-authority verification
/// lane.
///
/// ```compile_fail
/// use eliot_installation::InstallationActivationApproval;
///
/// fn forge_from_json(bytes: &str) {
///     let _: InstallationActivationApproval = serde_json::from_str(bytes).unwrap();
/// }
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationActivationApproval {
    /// Non-secret approval evidence reference.  The fields are intentionally
    /// private: installation accepts this value only from an independently
    /// issuing authority that also supplies static-verification proof.
    approval_ref: PlatformHandle,
    /// Sole installation transaction identity.
    transaction_id: PlatformHandle,
    /// Digest of the immutable installer effect plan.
    installer_plan_digest: PlatformHandle,
    /// Candidate generation identity.
    generation: PlatformHandle,
    /// Digest of the exact candidate manifest bytes.
    candidate_manifest_digest: PlatformHandle,
    /// Self-digest of the exact runtime launch descriptor.
    runtime_descriptor_digest: PlatformHandle,
    /// Request owner required for admission.
    required_owner: PlatformHandle,
    /// Candidate signature/approval evidence reference.
    signature_ref: PlatformHandle,
    /// Exact authority handoff descriptor path.
    authority_descriptor_path: PlatformHandle,
    /// SHA-256 digest of the authority descriptor bytes.
    authority_descriptor_digest: PlatformHandle,
    /// Authority resource generation.
    authority_generation: ResourceGeneration,
    /// Exact authority state fence.
    authority_state_fence: StateFence,
}

impl InstallationActivationApproval {
    /// Validates the approval's self-contained typed binding.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.approval_ref, "activation_approval.approval_ref")?;
        handle(&self.transaction_id, "activation_approval.transaction_id")?;
        sha256_handle(
            &self.installer_plan_digest,
            "activation_approval.installer_plan_digest",
        )?;
        handle(&self.generation, "activation_approval.generation")?;
        sha256_handle(
            &self.candidate_manifest_digest,
            "activation_approval.candidate_manifest_digest",
        )?;
        sha256_handle(
            &self.runtime_descriptor_digest,
            "activation_approval.runtime_descriptor_digest",
        )?;
        handle(&self.required_owner, "activation_approval.required_owner")?;
        handle(&self.signature_ref, "activation_approval.signature_ref")?;
        handle(
            &self.authority_descriptor_path,
            "activation_approval.authority_descriptor_path",
        )?;
        sha256_handle(
            &self.authority_descriptor_digest,
            "activation_approval.authority_descriptor_digest",
        )?;
        if self.authority_generation.value() == 0 {
            return Err(InstallationError::InvalidField {
                field: "activation_approval.authority_generation".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        self.authority_state_fence
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "activation_approval.authority_state_fence".to_owned(),
                reason: error.to_string(),
            })?;
        if self.authority_state_fence.resource_generation != self.authority_generation {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    /// Validates every approval binding against the exact transaction.
    ///
    /// The all-effects gate runs first, so a partially applied or unknown
    /// installer transaction can never produce a valid activation approval.
    pub fn validate_against(
        &self,
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError> {
        transaction.require_all_effects_applied()?;
        self.validate()?;
        let manifest = &transaction.candidate_manifest;
        let runtime = &manifest.runtime_launch;
        let expected_manifest_digest = candidate_manifest_digest(manifest)?;
        let matches = [
            self.transaction_id == transaction.transaction_id,
            self.installer_plan_digest == transaction.installer_plan_digest,
            self.generation == manifest.generation,
            self.candidate_manifest_digest == expected_manifest_digest,
            self.runtime_descriptor_digest == runtime.descriptor_digest,
            self.required_owner == transaction.request.required_owner,
            self.signature_ref == manifest.signature_ref,
            self.authority_descriptor_path == runtime.authority_descriptor_path,
            self.authority_descriptor_digest == runtime.authority_descriptor_digest,
            self.authority_generation == runtime.authority_generation,
            self.authority_state_fence == runtime.authority_state_fence,
        ];
        if matches.iter().any(|matches| !matches) {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// One artifact generation admitted by installation policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedGeneration {
    /// The complete immutable candidate manifest.
    pub manifest: CandidateManifest,
    /// Full transaction-bound activation approval.
    pub approval: InstallationActivationApproval,
    /// Whether this generation is currently active.
    pub active: bool,
    /// Whether this generation is the last-known-good activation.
    pub last_known_good: bool,
}

/// Typed readiness fence that Host must present at the pending-to-active CAS.
///
/// The fence is an observation binding, not a claim that process liveness is
/// atomic with the registry write. Host must re-probe the Kernel and Store and
/// append the resulting Kernel-authored observation immediately before the CAS.
/// The journal sequence/checksum make that bounded freshness evidence part of
/// the durable idempotency receipt instead of relying on an in-memory lease.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationCommitFence {
    /// Exact approved candidate generation being committed.
    pub generation: PlatformHandle,
    /// Exact approved configuration digest being committed.
    pub config_digest: PlatformHandle,
    /// Runtime authority resource generation.
    pub authority_generation: ResourceGeneration,
    /// Runtime authority state fence.
    pub authority_state_fence: StateFence,
    /// SHA-256 checksum of the active durable Kernel record observed by Host.
    pub active_kernel_record_checksum: PlatformHandle,
    /// SHA-256 digest of the Kernel `ProbeReady` request.
    pub probe_request_digest: PlatformHandle,
    /// SHA-256 digest of the Kernel-authored ready receipt.
    pub ready_receipt_digest: PlatformHandle,
    /// Exact Store proof fence returned by the authenticated readiness probe.
    pub store_proof_fence: PlatformHandle,
    /// Digest of the exact Kernel candidate binding used by the probe. This
    /// is a dynamic Host/Kernel contour value; the static manifest cannot
    /// derive process and Job identities, so Host authenticates it through
    /// the fresh Kernel-authored journal observation before this CAS.
    pub candidate_binding_digest: PlatformHandle,
    /// Digest of the exact Store bootstrap requirement used by the probe. The
    /// connection and peer-session portions are dynamic and likewise require
    /// Host's fresh authenticated contour check rather than a manifest-only
    /// reconstruction.
    pub store_requirement_digest: PlatformHandle,
    /// Monotonic Host journal sequence of the fresh readiness observation.
    pub readiness_sequence: u64,
    /// SHA-256 checksum of the journal's final frame at observation time.
    pub readiness_journal_checksum: PlatformHandle,
}

impl ActivationCommitFence {
    /// Validates the self-contained typed fence without asserting process
    /// liveness beyond the supplied durable observation.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.generation, "activation_commit_fence.generation")?;
        sha256_handle(&self.config_digest, "activation_commit_fence.config_digest")?;
        if self.authority_generation.value() == 0 {
            return Err(InstallationError::InvalidField {
                field: "activation_commit_fence.authority_generation".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        self.authority_state_fence
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "activation_commit_fence.authority_state_fence".to_owned(),
                reason: error.to_string(),
            })?;
        if self.authority_state_fence.resource_generation != self.authority_generation {
            return Err(InstallationError::IdentityConflict);
        }
        for (value, field) in [
            (
                &self.active_kernel_record_checksum,
                "activation_commit_fence.active_kernel_record_checksum",
            ),
            (
                &self.probe_request_digest,
                "activation_commit_fence.probe_request_digest",
            ),
            (
                &self.ready_receipt_digest,
                "activation_commit_fence.ready_receipt_digest",
            ),
            (
                &self.candidate_binding_digest,
                "activation_commit_fence.candidate_binding_digest",
            ),
            (
                &self.store_requirement_digest,
                "activation_commit_fence.store_requirement_digest",
            ),
            (
                &self.readiness_journal_checksum,
                "activation_commit_fence.readiness_journal_checksum",
            ),
        ] {
            sha256_handle(value, field)?;
        }
        handle(
            &self.store_proof_fence,
            "activation_commit_fence.store_proof_fence",
        )?;
        if self.readiness_sequence == 0 {
            return Err(InstallationError::InvalidField {
                field: "activation_commit_fence.readiness_sequence".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_against_manifest(
        &self,
        manifest: &CandidateManifest,
    ) -> Result<(), InstallationError> {
        // Candidate and Store contour digests are intentionally not compared
        // to a synthetic manifest value: their process, Job, connection, and
        // peer-session identities are minted at runtime. Host remains the
        // observer for those values and supplies this fence only after the
        // Kernel-authored journal proof and current contour agree. The
        // registry still validates their SHA-256 shape and persists them for
        // exact terminal idempotency comparison.
        self.validate()?;
        let runtime = &manifest.runtime_launch;
        if self.generation != manifest.generation
            || self.config_digest != manifest.config_digest
            || self.authority_generation != runtime.authority_generation
            || self.authority_state_fence != runtime.authority_state_fence
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// An opaque proof that the installation registry has durably committed one
/// exact pending activation.
///
/// The fields and constructor are private on purpose.  A caller can obtain a
/// value only by asking a [`RedbInstallationRegistry`] to read its committed
/// terminal projection.  In particular, serializing a Host-authored
/// [`ActivationCommitFence`] is not sufficient to manufacture this proof.
/// The proof is consumed by the transaction-store reconciliation boundary,
/// which is the only owner allowed to advance the durable transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationCommitReceipt {
    transaction_id: PlatformHandle,
    plan_digest: PlatformHandle,
    generation: PlatformHandle,
    candidate_manifest_digest: PlatformHandle,
    commit_fence: ActivationCommitFence,
    registry_revision: u64,
    terminal_digest: PlatformHandle,
}

impl ActivationCommitReceipt {
    fn validate_against_transaction(
        &self,
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError> {
        self.commit_fence
            .validate_against_manifest(&transaction.candidate_manifest)?;
        let expected_manifest_digest = candidate_manifest_digest(&transaction.candidate_manifest)?;
        if self.transaction_id != transaction.transaction_id
            || self.plan_digest != transaction.installer_plan_digest
            || self.generation != transaction.candidate_manifest.generation
            || self.candidate_manifest_digest != expected_manifest_digest
        {
            return Err(InstallationError::IdentityConflict);
        }
        sha256_handle(
            &self.terminal_digest,
            "activation_commit_receipt.terminal_digest",
        )?;
        if self.registry_revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "activation_commit_receipt.registry_revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        Ok(())
    }

    fn binding(self) -> ActiveVerifiedReceiptBinding {
        ActiveVerifiedReceiptBinding {
            transaction_id: self.transaction_id,
            plan_digest: self.plan_digest,
            generation: self.generation,
            candidate_manifest_digest: self.candidate_manifest_digest,
            commit_fence: self.commit_fence,
            registry_revision: self.registry_revision,
            terminal_digest: self.terminal_digest,
        }
    }
}

/// The private durable form of [`ActivationCommitReceipt`] retained after the
/// transaction crosses the activation boundary.  It is deliberately part of
/// the v9 transaction wire so a retry can distinguish the exact original
/// registry terminal from a different fence or a stale epoch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveVerifiedReceiptBinding {
    transaction_id: PlatformHandle,
    plan_digest: PlatformHandle,
    generation: PlatformHandle,
    candidate_manifest_digest: PlatformHandle,
    commit_fence: ActivationCommitFence,
    registry_revision: u64,
    terminal_digest: PlatformHandle,
}

impl ActiveVerifiedReceiptBinding {
    fn validate_against_transaction(
        &self,
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError> {
        let receipt = ActivationCommitReceipt {
            transaction_id: self.transaction_id.clone(),
            plan_digest: self.plan_digest.clone(),
            generation: self.generation.clone(),
            candidate_manifest_digest: self.candidate_manifest_digest.clone(),
            commit_fence: self.commit_fence.clone(),
            registry_revision: self.registry_revision,
            terminal_digest: self.terminal_digest.clone(),
        };
        receipt.validate_against_transaction(transaction)
    }

    fn matches_receipt(&self, receipt: &ActivationCommitReceipt) -> bool {
        self.transaction_id == receipt.transaction_id
            && self.plan_digest == receipt.plan_digest
            && self.generation == receipt.generation
            && self.candidate_manifest_digest == receipt.candidate_manifest_digest
            && self.commit_fence == receipt.commit_fence
            && self.registry_revision == receipt.registry_revision
            && self.terminal_digest == receipt.terminal_digest
    }
}

/// Durable idempotency receipt for the most recent terminal pending
/// activation result.  Keeping the exact transaction and plan bindings lets
/// a retried Host commit/abort return the original terminal result without
/// accepting a different caller after the pending projection is cleared.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingActivationTerminal {
    transaction_id: PlatformHandle,
    plan_digest: PlatformHandle,
    generation: PlatformHandle,
    disposition: PendingActivationTerminalDisposition,
    /// Exact readiness fence used for a committed activation. Aborted
    /// terminals must carry explicit `null` and never a synthetic fence.
    commit_fence: Option<ActivationCommitFence>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PendingActivationTerminalDisposition {
    Committed,
    Aborted,
}

impl ApprovedGeneration {
    /// Validates the generation and its complete approval binding.
    pub fn validate(&self) -> Result<(), InstallationError> {
        self.manifest.validate()?;
        self.approval.validate()?;
        validate_approval_against_manifest(&self.approval, &self.manifest, "approved_generation")
    }
}

fn validate_approval_against_manifest(
    approval: &InstallationActivationApproval,
    manifest: &CandidateManifest,
    field_prefix: &str,
) -> Result<(), InstallationError> {
    let runtime = &manifest.runtime_launch;
    let expected_manifest_digest = candidate_manifest_digest(manifest)?;
    let matches = [
        approval.generation == manifest.generation,
        approval.candidate_manifest_digest == expected_manifest_digest,
        approval.runtime_descriptor_digest == runtime.descriptor_digest,
        approval.signature_ref == manifest.signature_ref,
        approval.authority_descriptor_path == runtime.authority_descriptor_path,
        approval.authority_descriptor_digest == runtime.authority_descriptor_digest,
        approval.authority_generation == runtime.authority_generation,
        approval.authority_state_fence == runtime.authority_state_fence,
    ];
    if matches.iter().any(|matches| !matches) {
        return Err(InstallationError::InvalidField {
            field: field_prefix.to_owned(),
            reason: "activation approval does not bind the exact candidate manifest".to_owned(),
        });
    }
    Ok(())
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
///
/// The public registry type is also intentionally not deserializable.  Only
/// the private v4 wire decoder can reconstruct an authority projection.
///
/// ```compile_fail
/// use eliot_installation::ApprovedGenerationRegistry;
/// fn forge_registry(bytes: &str) {
///     let _: ApprovedGenerationRegistry = serde_json::from_str(bytes).unwrap();
/// }
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedGenerationRegistry {
    /// Mandatory durable wire discriminator.
    registry_wire_version: ContractVersion,
    /// Monotonic CAS revision of this registry projection.
    revision: u64,
    /// Approved generations keyed by their exact generation identity.
    generations: Vec<ApprovedGeneration>,
    /// Installer-owned Host and Watchdog SCM approvals keyed by generation and
    /// role.  This projection is populated only from applied transaction
    /// service effects.
    service_registration_approvals: Vec<InstallerServiceRegistrationApproval>,
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
    last_terminal_activation: Option<PendingActivationTerminal>,
}

impl Default for ApprovedGenerationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Durable activation candidate handed from the installer coordinator to the
/// Host owner.  Every identity and digest is repeated from the immutable
/// candidate so a stale or substituted pending record fails closed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
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
    pub approval: InstallationActivationApproval,
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
    TableDefinition::new("eliot_approved_generations_v2");
const LEGACY_REGISTRY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_approved_generations_v1");
const REGISTRY_RELATIVE_PATH: &str = "Eliot/host/installation-registry.redb";
const INSTALLATION_REGISTRY_FILE_NAME: &str = "installation-registry.redb";

/// Private deserialization mirror for an authority-issued approval.  The
/// public approval type intentionally has no `Deserialize` implementation;
/// only this registry boundary may reconstruct a previously sealed value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationActivationApprovalWire {
    approval_ref: PlatformHandle,
    transaction_id: PlatformHandle,
    installer_plan_digest: PlatformHandle,
    generation: PlatformHandle,
    candidate_manifest_digest: PlatformHandle,
    runtime_descriptor_digest: PlatformHandle,
    required_owner: PlatformHandle,
    signature_ref: PlatformHandle,
    authority_descriptor_path: PlatformHandle,
    authority_descriptor_digest: PlatformHandle,
    authority_generation: ResourceGeneration,
    authority_state_fence: StateFence,
}

impl InstallationActivationApprovalWire {
    fn into_approval(self) -> InstallationActivationApproval {
        InstallationActivationApproval {
            approval_ref: self.approval_ref,
            transaction_id: self.transaction_id,
            installer_plan_digest: self.installer_plan_digest,
            generation: self.generation,
            candidate_manifest_digest: self.candidate_manifest_digest,
            runtime_descriptor_digest: self.runtime_descriptor_digest,
            required_owner: self.required_owner,
            signature_ref: self.signature_ref,
            authority_descriptor_path: self.authority_descriptor_path,
            authority_descriptor_digest: self.authority_descriptor_digest,
            authority_generation: self.authority_generation,
            authority_state_fence: self.authority_state_fence,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedGenerationWire {
    manifest: CandidateManifest,
    approval: InstallationActivationApprovalWire,
    active: bool,
    last_known_good: bool,
}

impl ApprovedGenerationWire {
    fn into_generation(self) -> ApprovedGeneration {
        ApprovedGeneration {
            manifest: self.manifest,
            approval: self.approval.into_approval(),
            active: self.active,
            last_known_good: self.last_known_good,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingActivationWire {
    transaction_id: PlatformHandle,
    plan_digest: PlatformHandle,
    manifest: CandidateManifest,
    config_digest: PlatformHandle,
    kernel_artifact_digest: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    host_executable_path: PlatformHandle,
    host_artifact_digest: PlatformHandle,
    runtime_state_roots_digest: PlatformHandle,
    manifest_digest: PlatformHandle,
    prior_active_generation: Option<PlatformHandle>,
    approval: InstallationActivationApprovalWire,
    state: PendingActivationState,
}

impl PendingActivationWire {
    fn into_pending(self) -> PendingActivation {
        PendingActivation {
            transaction_id: self.transaction_id,
            plan_digest: self.plan_digest,
            manifest: self.manifest,
            config_digest: self.config_digest,
            kernel_artifact_digest: self.kernel_artifact_digest,
            store_bridge_artifact_digest: self.store_bridge_artifact_digest,
            canonical_store_artifact_digest: self.canonical_store_artifact_digest,
            host_executable_path: self.host_executable_path,
            host_artifact_digest: self.host_artifact_digest,
            runtime_state_roots_digest: self.runtime_state_roots_digest,
            manifest_digest: self.manifest_digest,
            prior_active_generation: self.prior_active_generation,
            approval: self.approval.into_approval(),
            state: self.state,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingActivationTerminalWire {
    transaction_id: PlatformHandle,
    plan_digest: PlatformHandle,
    generation: PlatformHandle,
    disposition: PendingActivationTerminalDisposition,
    /// The member is mandatory on the current wire, while explicit `null`
    /// remains the only valid value for an aborted terminal.
    commit_fence: RequiredOption<ActivationCommitFence>,
}

impl PendingActivationTerminalWire {
    fn into_terminal(self) -> PendingActivationTerminal {
        PendingActivationTerminal {
            transaction_id: self.transaction_id,
            plan_digest: self.plan_digest,
            generation: self.generation,
            disposition: self.disposition,
            commit_fence: self.commit_fence.0,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryWireV4 {
    registry_wire_version: ContractVersion,
    revision: u64,
    generations: Vec<ApprovedGenerationWire>,
    service_registration_approvals: Vec<InstallerServiceRegistrationApproval>,
    active_generation: RequiredOption<PlatformHandle>,
    last_known_good_generation: RequiredOption<PlatformHandle>,
    pending_activation: RequiredOption<PendingActivationWire>,
    last_terminal_activation: RequiredOption<PendingActivationTerminalWire>,
}

/// An optional wire member whose presence is mandatory.  Explicit `null` is
/// the only valid empty value; an omitted member is a schema migration rather
/// than an implicit serde default.
struct RequiredOption<T>(Option<T>);

impl<'de, T> Deserialize<'de> for RequiredOption<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Self)
    }
}

impl RegistryWireV4 {
    fn into_registry(self) -> ApprovedGenerationRegistry {
        ApprovedGenerationRegistry {
            registry_wire_version: self.registry_wire_version,
            revision: self.revision,
            generations: self
                .generations
                .into_iter()
                .map(ApprovedGenerationWire::into_generation)
                .collect(),
            service_registration_approvals: self.service_registration_approvals,
            active_generation: self.active_generation.0,
            last_known_good_generation: self.last_known_good_generation.0,
            pending_activation: self
                .pending_activation
                .0
                .map(PendingActivationWire::into_pending),
            last_terminal_activation: self
                .last_terminal_activation
                .0
                .map(PendingActivationTerminalWire::into_terminal),
        }
    }
}

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
    pending_activation: Option<serde_json::Value>,
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
    pending_activation: Option<serde_json::Value>,
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

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreServiceRegistrationApprovalRegistryWire {
    generations: Vec<serde_json::Value>,
    active_generation: Option<PlatformHandle>,
    last_known_good_generation: Option<PlatformHandle>,
    pending_activation: Option<serde_json::Value>,
    last_terminal_activation: Option<serde_json::Value>,
}

fn registry_has_prior_shape(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    [
        "generations",
        "active_generation",
        "last_known_good_generation",
    ]
    .iter()
    .all(|field| object.contains_key(*field))
}

fn registry_runtime_objects(
    value: &serde_json::Value,
) -> impl Iterator<Item = &serde_json::Map<String, serde_json::Value>> {
    value
        .get("generations")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flat_map(|generations| generations.iter())
        .filter_map(serde_json::Value::as_object)
        .filter_map(|generation| generation.get("manifest"))
        .filter_map(serde_json::Value::as_object)
        .filter_map(|manifest| manifest.get("runtime_launch"))
        .filter_map(serde_json::Value::as_object)
}

fn is_pre_eliotd_config_registry(value: &serde_json::Value) -> bool {
    let mut seen = false;
    for runtime in registry_runtime_objects(value) {
        seen = true;
        if runtime.contains_key("eliotd_config_path")
            || runtime.contains_key("eliotd_config_digest")
        {
            return false;
        }
    }
    seen
}

fn current_registry_wire_missing_field(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return true;
    };
    [
        "registry_wire_version",
        "revision",
        "generations",
        "service_registration_approvals",
        "active_generation",
        "last_known_good_generation",
        "pending_activation",
        "last_terminal_activation",
    ]
    .iter()
    .any(|field| !object.contains_key(*field))
}

#[allow(
    clippy::too_many_lines,
    reason = "registry decoding keeps strict current-wire and migration classification together"
)]
fn decode_registry_bytes(bytes: &[u8]) -> Result<ApprovedGenerationRegistry, InstallationError> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).map_err(|error| {
        InstallationError::CorruptRegistry {
            reason: format!("registry bytes are not valid JSON: {error}"),
        }
    })?;

    let declared_major = value
        .get("registry_wire_version")
        .and_then(|version| version.get("major"))
        .and_then(serde_json::Value::as_u64);
    if declared_major == Some(u64::from(INSTALLATION_REGISTRY_WIRE_VERSION.major))
        && current_registry_wire_missing_field(&value)
    {
        return Err(InstallationError::CorruptRegistry {
            reason: "registry wire v4 is missing mandatory fields or contains an invalid field"
                .to_owned(),
        });
    }

    if let Ok(wire) = serde_json::from_value::<RegistryWireV4>(value.clone()) {
        if wire.registry_wire_version != INSTALLATION_REGISTRY_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "approved-generation registry wire {} requires explicit re-stage as {}",
                    wire.registry_wire_version, INSTALLATION_REGISTRY_WIRE_VERSION
                ),
            });
        }
        if wire.revision == 0 {
            return Err(InstallationError::CorruptRegistry {
                reason: "current registry revision must be non-zero".to_owned(),
            });
        }
        let registry = wire.into_registry();
        registry
            .validate()
            .map_err(|_| InstallationError::CorruptRegistry {
                reason: "current registry projection failed validation".to_owned(),
            })?;
        return Ok(registry);
    }

    if let Some(version) = declared_major {
        if version < u64::from(INSTALLATION_REGISTRY_WIRE_VERSION.major) {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "approved-generation registry wire v{version} requires explicit re-stage as v{}",
                    INSTALLATION_REGISTRY_WIRE_VERSION.major
                ),
            });
        }
        return Err(InstallationError::CorruptRegistry {
            reason: "registry wire v4 is missing mandatory fields or contains an invalid field"
                .to_owned(),
        });
    }

    if registry_has_prior_shape(&value) {
        if value.as_object().is_some_and(|object| {
            object.keys().any(|field| {
                !matches!(
                    field.as_str(),
                    "generations"
                        | "active_generation"
                        | "last_known_good_generation"
                        | "service_registration_approvals"
                        | "pending_activation"
                        | "last_terminal_activation"
                        | "registry_wire_version"
                        | "revision"
                )
            })
        }) {
            return Err(InstallationError::CorruptRegistry {
                reason: "prior registry schema contains unknown fields".to_owned(),
            });
        }
        let runtimes = registry_runtime_objects(&value).collect::<Vec<_>>();
        let manifests_missing_store_credential_target = value
            .get("generations")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|generations| {
                generations.iter().any(|generation| {
                    generation
                        .get("manifest")
                        .and_then(serde_json::Value::as_object)
                        .is_some_and(|manifest| !manifest.contains_key("store_credential_target"))
                })
            });
        let has_pending = value.get("pending_activation").is_some();
        if manifests_missing_store_credential_target
            || runtimes
                .iter()
                .any(|runtime| !runtime.contains_key("store_credential_target"))
        {
            return Err(InstallationError::MigrationRequired {
                reason: "approved-generation registry predates the descriptor-bound Store credential target and requires explicit re-stage"
                    .to_owned(),
            });
        }
        if runtimes.iter().any(|runtime| {
            !runtime.contains_key("host_executable_path")
                || !runtime.contains_key("host_artifact_digest")
        }) {
            return Err(InstallationError::MigrationRequired {
                reason: "approved-generation registry predates the approved Host executable artifact binding and requires explicit re-stage"
                    .to_owned(),
            });
        }
        if runtimes
            .iter()
            .any(|runtime| !runtime.contains_key("store_bridge_arguments"))
        {
            return Err(InstallationError::MigrationRequired {
                reason: "approved-generation registry predates split Store bridge/provider argv and requires explicit re-stage"
                    .to_owned(),
            });
        }
        if is_pre_eliotd_config_registry(&value) {
            return Err(InstallationError::MigrationRequired {
                reason: "approved-generation registry predates the separate eliotd Governor config binding and requires explicit re-stage"
                    .to_owned(),
            });
        }
        if value.get("service_registration_approvals").is_none() {
            return Err(InstallationError::MigrationRequired {
                reason: "approved-generation registry predates installer-owned SCM registration approvals and requires explicit re-stage"
                    .to_owned(),
            });
        }
        if !has_pending {
            return Err(InstallationError::MigrationRequired {
                reason: "approved-generation registry predates durable pending activation and requires explicit re-stage"
                    .to_owned(),
            });
        }
        return Err(InstallationError::MigrationRequired {
            reason: "approved-generation registry v2/pre-CAS requires explicit re-stage with a mandatory wire revision"
                .to_owned(),
        });
    }

    Err(InstallationError::CorruptRegistry {
        reason: "registry bytes are neither current nor structurally valid prior schema".to_owned(),
    })
}

/// Durable redb owner for approved generations and LKG activation state.
///
/// There is no public raw `save` operation.  Every production mutation must
/// use a narrow transaction-bound operation with an expected revision and an
/// exact typed approval.
///
/// ```compile_fail
/// use eliot_installation::{ApprovedGenerationRegistry, RedbInstallationRegistry};
/// fn raw_save(store: &RedbInstallationRegistry, registry: &ApprovedGenerationRegistry) {
///     store.save(registry);
/// }
/// ```
pub struct RedbInstallationRegistry {
    database: Database,
    _path_lease: RegistryPathLease,
}

enum RegistryPathLease {
    Legacy {
        _lease: ProtectedPathLease,
    },
    InstallationHost {
        _root: ProtectedRootLease,
        _file: ProtectedRuntimePathLease,
    },
    #[cfg(test)]
    Test,
}

impl RedbInstallationRegistry {
    #[cfg(test)]
    fn from_database_for_test(database: Database) -> Self {
        Self {
            database,
            _path_lease: RegistryPathLease::Test,
        }
    }

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
            _path_lease: RegistryPathLease::Legacy { _lease: path_lease },
        })
    }

    /// Opens or creates the registry below one retained per-installation
    /// Host root.
    ///
    /// The caller transfers ownership of the retained root lease to this
    /// database owner. The registry file is a fixed direct child of that
    /// canonical root; no arbitrary path, legacy system-data location, or
    /// ACL-rewriting lease is accepted. The runtime-file lease proves the
    /// installer-provisioned BA+LS+SY ACL and retains the no-follow contour
    /// for redb's path-based reopen.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the registry owner must retain the caller-provided Host root lease"
    )]
    pub fn open_at(host_root: ProtectedRootLease) -> Result<Self, InstallationError> {
        let path = installation_registry_path(&host_root)?;
        let file = ProtectedRuntimePathLease::open_or_create_absolute(&path)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        if file.path() != path {
            return Err(InstallationError::Platform(
                "installation registry path is not the retained canonical Host child".to_owned(),
            ));
        }
        let database = Database::create(file.path())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        file.verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Self {
            database,
            _path_lease: RegistryPathLease::InstallationHost {
                _root: host_root,
                _file: file,
            },
        })
    }

    /// Opens an existing registry below one retained per-installation Host
    /// root without creating a file or database.
    ///
    /// The returned owner retains both the caller-provided Host root and the
    /// installer-provisioned runtime-file lease while callers validate and
    /// load its durable projection. None means only that the fixed registry
    /// child is absent.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the registry owner must retain the caller-provided Host root lease"
    )]
    pub fn open_existing_at(
        host_root: ProtectedRootLease,
    ) -> Result<Option<Self>, InstallationError> {
        let path = installation_registry_path(&host_root)?;
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(_) | Err(_) => {
                return Err(InstallationError::Platform(
                    "installation registry path is not an existing regular file".to_owned(),
                ));
            }
        }
        let file = ProtectedRuntimePathLease::open_existing_absolute(&path)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        if file.path() != path {
            return Err(InstallationError::Platform(
                "installation registry path is not the retained canonical Host child".to_owned(),
            ));
        }
        file.verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let database = Database::open(file.path())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        file.verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Some(Self {
            database,
            _path_lease: RegistryPathLease::InstallationHost {
                _root: host_root,
                _file: file,
            },
        }))
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
        reject_legacy_registry_table(&read)?;
        let table = match read.open_table(REGISTRY_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                classify_missing_registry_table(&read)?;
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

    /// Inspects an existing registry below one retained per-installation
    /// Host root without creating a file, database, table, or ACL.
    ///
    /// The retained root is consumed for the duration of this read so the
    /// caller cannot drop the containment proof while redb is open. None
    /// means only that the fixed registry child is absent.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the inspection must retain the caller-provided Host root lease during the read"
    )]
    pub fn inspect_existing_at(
        host_root: ProtectedRootLease,
    ) -> Result<Option<ApprovedGenerationRegistry>, InstallationError> {
        let path = installation_registry_path(&host_root)?;
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(_) | Err(_) => {
                return Err(InstallationError::Platform(
                    "installation registry path is not an existing regular file".to_owned(),
                ));
            }
        }
        let file = ProtectedRuntimePathLease::open_existing_absolute(&path)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        if file.path() != path {
            return Err(InstallationError::Platform(
                "installation registry path is not the retained canonical Host child".to_owned(),
            ));
        }
        file.verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let database = ReadOnlyDatabase::open(file.path())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        file.verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        read_existing_registry(&database).map(Some)
    }

    /// Loads the registry, returning an empty value on first use.
    pub fn load(&self) -> Result<ApprovedGenerationRegistry, InstallationError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        reject_legacy_registry_table(&read)?;
        let table = match read.open_table(REGISTRY_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                classify_missing_registry_table(&read)?;
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

    /// Reads one exact committed activation terminal without mutating the
    /// registry. The returned opaque receipt can only be produced from this
    /// read path and binds the transaction, plan, generation, candidate
    /// manifest, commit fence, registry revision and terminal digest.
    pub fn read_committed_activation_receipt(
        &self,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
    ) -> Result<ActivationCommitReceipt, InstallationError> {
        let registry = self.load()?;
        let terminal = registry.last_terminal_activation.as_ref().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "no committed terminal activation exists".to_owned(),
            )
        })?;
        if terminal.disposition != PendingActivationTerminalDisposition::Committed {
            return Err(InstallationError::IncompleteObservation(
                "last terminal activation is not committed".to_owned(),
            ));
        }
        if terminal.transaction_id != *transaction_id
            || terminal.plan_digest != *plan_digest
            || terminal.generation != *generation
        {
            return Err(InstallationError::IdentityConflict);
        }
        if registry.active_generation.as_ref() != Some(generation) {
            return Err(InstallationError::IncompleteObservation(
                "committed terminal is not the active registry generation".to_owned(),
            ));
        }
        let manifest = registry
            .generations
            .iter()
            .find(|item| item.manifest.generation == *generation)
            .ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "committed terminal generation is not approved".to_owned(),
                )
            })?;
        let commit_fence = terminal.commit_fence.clone().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "committed terminal is missing its activation fence".to_owned(),
            )
        })?;
        commit_fence.validate_against_manifest(&manifest.manifest)?;
        let receipt = ActivationCommitReceipt {
            transaction_id: terminal.transaction_id.clone(),
            plan_digest: terminal.plan_digest.clone(),
            generation: terminal.generation.clone(),
            candidate_manifest_digest: candidate_manifest_digest(&manifest.manifest)?,
            commit_fence,
            registry_revision: registry.revision,
            terminal_digest: activation_terminal_digest(terminal)?,
        };
        receipt.commit_fence.validate()?;
        sha256_handle(
            &receipt.terminal_digest,
            "activation_commit_receipt.terminal_digest",
        )?;
        Ok(receipt)
    }

    /// Loads the sealed transaction and atomically stages its exact pending
    /// activation plus installer-owned SCM approvals.
    ///
    /// `approval` must have been issued by the independent authority after
    /// static verification.  This crate deliberately exposes no constructor
    /// or deserializer for that value; until the authority lane supplies the
    /// sealed receipt, initial staging is unavailable and fails closed at the
    /// caller's boundary.
    ///
    /// `expected_revision` is checked against the registry snapshot inside the
    /// same redb write transaction that commits the projection.  An exact retry
    /// is a no-op and does not advance the revision.
    pub fn stage_pending_activation_from_transaction_store<S: InstallationTransactionStore>(
        &self,
        transaction_store: &S,
        transaction_id: &PlatformHandle,
        approval: InstallationActivationApproval,
        expected_revision: u64,
    ) -> Result<(), InstallationError> {
        let transaction = transaction_store.load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        if transaction.transaction_id != *transaction_id {
            return Err(InstallationError::IdentityConflict);
        }
        if approval.transaction_id != *transaction_id {
            return Err(InstallationError::IdentityConflict);
        }
        approval.validate_against(&transaction)?;
        self.mutate_atomic(expected_revision, |registry| {
            registry.stage_pending_activation_from_transaction_with_approval(&transaction, approval)
        })
    }

    fn mutate_atomic<T, F>(&self, expected_revision: u64, mutate: F) -> Result<T, InstallationError>
    where
        F: FnOnce(&mut ApprovedGenerationRegistry) -> Result<T, InstallationError>,
    {
        let write = self
            .database
            .begin_write()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let mut current = read_registry_in_write(&write)?;
        current.validate()?;
        let actual_revision = current.revision();
        if actual_revision != expected_revision {
            return Err(InstallationError::CompareAndSaveConflict {
                expected: expected_revision,
                actual: actual_revision,
            });
        }
        let before = current.clone();
        let result = mutate(&mut current)?;
        current.validate()?;
        if current != before {
            current.revision =
                current
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| InstallationError::InvalidField {
                        field: "registry.revision".to_owned(),
                        reason: "overflow".to_owned(),
                    })?;
            current.validate()?;
            let bytes = serde_json::to_vec(&current)
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
            let mut table = write
                .open_table(REGISTRY_TABLE)
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
            table
                .insert("registry", bytes.as_slice())
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
        }
        write
            .commit()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(result)
    }

    /// Atomically claims one exact pending activation for the live Host owner.
    ///
    /// The registry snapshot, expected revision and complete typed approval
    /// binding are checked inside one redb write transaction.  The returned
    /// pending record is the exact durable value that Host must launch.
    pub fn claim_pending_activation(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
    ) -> Result<PendingActivation, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        let approval = approval.clone();
        self.mutate_atomic(expected_revision, |registry| {
            let pending = registry.pending_activation.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation("no pending activation exists".to_owned())
            })?;
            if pending.approval != approval {
                return Err(InstallationError::IdentityConflict);
            }
            registry.claim_pending_activation_unchecked(
                &approval.transaction_id,
                &approval.installer_plan_digest,
                &approval.generation,
            )
        })
    }

    /// Atomically records a Host recovery disposition for one exact approval.
    pub fn mark_pending_recovery(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
        reason: impl Into<String>,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        let approval = approval.clone();
        let reason = reason.into();
        self.mutate_atomic(expected_revision, |registry| {
            let pending = registry.pending_activation.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation("no pending activation exists".to_owned())
            })?;
            if pending.approval != approval {
                return Err(InstallationError::IdentityConflict);
            }
            registry.mark_pending_recovery_unchecked(
                &approval.transaction_id,
                &approval.installer_plan_digest,
                reason,
            )
        })
    }

    /// Atomically commits one exact Host-proven healthy pending approval.
    pub fn commit_pending_activation(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
        commit_fence: &ActivationCommitFence,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        commit_fence.validate()?;
        let approval = approval.clone();
        let commit_fence = commit_fence.clone();
        self.mutate_atomic(expected_revision, |registry| {
            if let Some(pending) = registry.pending_activation.as_ref()
                && pending.approval != approval
            {
                return Err(InstallationError::IdentityConflict);
            }
            registry.commit_pending_activation_unchecked(
                &approval.transaction_id,
                &approval.installer_plan_digest,
                &approval.generation,
                &commit_fence,
            )
        })
    }

    /// Atomically aborts one exact first-install pending approval.
    pub fn abort_pending_activation(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        let approval = approval.clone();
        self.mutate_atomic(expected_revision, |registry| {
            if let Some(pending) = registry.pending_activation.as_ref()
                && pending.approval != approval
            {
                return Err(InstallationError::IdentityConflict);
            }
            registry.abort_pending_activation_unchecked(
                &approval.transaction_id,
                &approval.installer_plan_digest,
            )
        })
    }
}

fn installation_registry_path(
    host_root: &ProtectedRootLease,
) -> Result<PathBuf, InstallationError> {
    host_root
        .verify_stable_identity()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    let canonical_root = host_root
        .canonical_path()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    validate_installation_host_root(&canonical_root)?;
    Ok(canonical_root.join(INSTALLATION_REGISTRY_FILE_NAME))
}

fn validate_installation_host_root(path: &Path) -> Result<(), InstallationError> {
    let identity = WindowsPathIdentity::parse_root(
        &path.to_string_lossy(),
        "installation_registry.host_root",
    )?;
    let Some(key) = identity
        .components
        .get(identity.components.len().saturating_sub(2))
    else {
        return Err(InstallationError::InvalidField {
            field: "installation_registry.host_root".to_owned(),
            reason: "retained root must be an installation Host root".to_owned(),
        });
    };
    if !valid_installation_key(key) || !identity.ends_with(&["eliot", "installations", key, "host"])
    {
        return Err(InstallationError::InvalidField {
            field: "installation_registry.host_root".to_owned(),
            reason: "retained root must end in Eliot/installations/<sha256-key>/host".to_owned(),
        });
    }
    Ok(())
}

fn read_existing_registry(
    database: &ReadOnlyDatabase,
) -> Result<ApprovedGenerationRegistry, InstallationError> {
    let read = database
        .begin_read()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    reject_legacy_registry_table(&read)?;
    let table = match read.open_table(REGISTRY_TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            classify_missing_registry_table(&read)?;
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
    registry.validate()?;
    Ok(registry)
}

fn reject_legacy_registry_table(read: &redb::ReadTransaction) -> Result<(), InstallationError> {
    match read.open_table(LEGACY_REGISTRY_TABLE) {
        Ok(_) => Err(InstallationError::MigrationRequired {
            reason: "approved-generation registry uses the retired v1 table and requires explicit re-stage"
                .to_owned(),
        }),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(()),
        Err(error) => Err(InstallationError::Platform(error.to_string())),
    }
}

fn classify_missing_registry_table(read: &redb::ReadTransaction) -> Result<(), InstallationError> {
    reject_legacy_registry_table(read)?;
    let has_standard_tables = read
        .list_tables()
        .map_err(|error| InstallationError::Platform(error.to_string()))?
        .next()
        .is_some();
    let has_multimap_tables = read
        .list_multimap_tables()
        .map_err(|error| InstallationError::Platform(error.to_string()))?
        .next()
        .is_some();
    if has_standard_tables || has_multimap_tables {
        return Err(InstallationError::MigrationRequired {
            reason: "existing nonempty registry store has no installation-registry v2 table"
                .to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
fn classify_registry_table(database: &impl ReadableDatabase) -> Result<bool, InstallationError> {
    let read = database
        .begin_read()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    reject_legacy_registry_table(&read)?;
    match read.open_table(REGISTRY_TABLE) {
        Ok(_) => Ok(true),
        Err(redb::TableError::TableDoesNotExist(_)) => {
            classify_missing_registry_table(&read)?;
            Ok(false)
        }
        Err(error) => Err(InstallationError::Platform(error.to_string())),
    }
}

fn read_registry_in_write(
    write: &WriteTransaction,
) -> Result<ApprovedGenerationRegistry, InstallationError> {
    let has_registry_table = write
        .list_tables()
        .map_err(|error| InstallationError::Platform(error.to_string()))?
        .any(|table| table.name() == REGISTRY_TABLE.name());
    let has_legacy_table = write
        .list_tables()
        .map_err(|error| InstallationError::Platform(error.to_string()))?
        .any(|table| table.name() == LEGACY_REGISTRY_TABLE.name());
    if has_legacy_table {
        return Err(InstallationError::MigrationRequired {
            reason: "approved-generation registry uses the retired v1 table and requires explicit re-stage"
                .to_owned(),
        });
    }
    if !has_registry_table {
        let has_standard_tables = write
            .list_tables()
            .map_err(|error| InstallationError::Platform(error.to_string()))?
            .next()
            .is_some();
        let has_multimap_tables = write
            .list_multimap_tables()
            .map_err(|error| InstallationError::Platform(error.to_string()))?
            .next()
            .is_some();
        if has_standard_tables || has_multimap_tables {
            return Err(InstallationError::MigrationRequired {
                reason: "existing nonempty registry store has no installation-registry v3 table"
                    .to_owned(),
            });
        }
        return Ok(ApprovedGenerationRegistry::new());
    }
    let table = write
        .open_table(REGISTRY_TABLE)
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    let Some(value) = table
        .get("registry")
        .map_err(|error| InstallationError::Platform(error.to_string()))?
    else {
        return Ok(ApprovedGenerationRegistry::new());
    };
    decode_registry_bytes(value.value())
}

impl ApprovedGenerationRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            registry_wire_version: INSTALLATION_REGISTRY_WIRE_VERSION,
            revision: 1,
            generations: Vec::new(),
            service_registration_approvals: Vec::new(),
            active_generation: None,
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
        }
    }

    /// Returns the mandatory durable registry wire version.
    #[must_use]
    pub const fn registry_wire_version(&self) -> ContractVersion {
        self.registry_wire_version
    }

    /// Returns the current monotonic registry CAS revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Looks up one exact role approval for a generation without exposing a
    /// mutation seam.
    #[must_use]
    pub fn service_registration_approval(
        &self,
        generation: &PlatformHandle,
        role: InstallerServiceRole,
    ) -> Option<&InstallerServiceRegistrationApproval> {
        self.service_registration_approvals
            .iter()
            .find(|approval| approval.generation == *generation && approval.role == role)
    }

    /// Test-only fixture seam for registry state-machine tests that do not
    /// exercise the production installer transaction. Production admission
    /// is available only through the transaction-bound all-effects gate.
    #[cfg(test)]
    fn stage_pending_activation(
        &mut self,
        transaction_id: PlatformHandle,
        plan_digest: PlatformHandle,
        manifest: CandidateManifest,
        approval_ref: PlatformHandle,
    ) -> Result<(), InstallationError> {
        if manifest.runtime_launch.profile == InstallationProfile::SystemService {
            return Err(InstallationError::ProfileViolation(
                "SystemService activation requires transaction-bound SCM approvals".to_owned(),
            ));
        }
        let runtime = &manifest.runtime_launch;
        let approval = InstallationActivationApproval {
            approval_ref,
            transaction_id,
            installer_plan_digest: plan_digest,
            generation: manifest.generation.clone(),
            candidate_manifest_digest: candidate_manifest_digest(&manifest)?,
            runtime_descriptor_digest: runtime.descriptor_digest.clone(),
            required_owner: PlatformHandle::new("owner:test").map_err(|error| {
                InstallationError::InvalidField {
                    field: "activation_approval.required_owner".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            signature_ref: manifest.signature_ref.clone(),
            authority_descriptor_path: runtime.authority_descriptor_path.clone(),
            authority_descriptor_digest: runtime.authority_descriptor_digest.clone(),
            authority_generation: runtime.authority_generation,
            authority_state_fence: runtime.authority_state_fence.clone(),
        };
        self.stage_pending_activation_unchecked(manifest, approval, &[])
    }

    fn stage_pending_activation_unchecked(
        &mut self,
        manifest: CandidateManifest,
        approval: InstallationActivationApproval,
        service_registration_approvals: &[InstallerServiceRegistrationApproval],
    ) -> Result<(), InstallationError> {
        manifest.validate()?;
        approval.validate()?;
        validate_approval_against_manifest(&approval, &manifest, "pending_activation")?;
        let manifest_digest = candidate_manifest_digest(&manifest)?;
        let pending = PendingActivation {
            transaction_id: approval.transaction_id.clone(),
            plan_digest: approval.installer_plan_digest.clone(),
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
            approval,
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
        self.generations.push(ApprovedGeneration {
            manifest: pending.manifest.clone(),
            approval: pending.approval.clone(),
            active: false,
            last_known_good: false,
        });
        self.pending_activation = Some(pending);
        self.service_registration_approvals
            .extend(service_registration_approvals.iter().cloned());
        self.last_terminal_activation = None;
        self.validate()
    }

    fn stage_pending_activation_from_transaction_with_approval(
        &mut self,
        transaction: &InstallationTransaction,
        approval: InstallationActivationApproval,
    ) -> Result<(), InstallationError> {
        approval.validate_against(transaction)?;
        let approvals = transaction.service_registration_approvals()?;
        if transaction.profile == InstallationProfile::SystemService && approvals.len() != 2 {
            return Err(InstallationError::IncompleteObservation(
                "SystemService transaction requires exactly Host and Watchdog SCM approvals"
                    .to_owned(),
            ));
        }
        if let Some(existing) = self.pending_activation.as_ref()
            && existing.transaction_id == transaction.transaction_id
            && existing.plan_digest == transaction.installer_plan_digest
            && existing.manifest == transaction.candidate_manifest
            && existing.approval == approval
        {
            for approval in &approvals {
                if self.service_registration_approval(&approval.generation, approval.role)
                    != Some(approval)
                {
                    return Err(InstallationError::IdentityConflict);
                }
            }
            return self.validate();
        }
        self.stage_pending_activation_unchecked(
            transaction.candidate_manifest.clone(),
            approval,
            &approvals,
        )?;
        Ok(())
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
        commit_fence: Option<&ActivationCommitFence>,
        disposition: PendingActivationTerminalDisposition,
    ) -> bool {
        self.last_terminal_activation
            .as_ref()
            .is_some_and(|terminal| {
                Self::terminal_identity_matches(
                    terminal,
                    transaction_id,
                    plan_digest,
                    generation,
                    disposition,
                ) && terminal.commit_fence.as_ref() == commit_fence
            })
    }

    fn terminal_identity_matches(
        terminal: &PendingActivationTerminal,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: Option<&PlatformHandle>,
        disposition: PendingActivationTerminalDisposition,
    ) -> bool {
        terminal.transaction_id == *transaction_id
            && terminal.plan_digest == *plan_digest
            && generation.is_none_or(|value| terminal.generation == *value)
            && terminal.disposition == disposition
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
    #[cfg(test)]
    fn claim_pending_activation(
        &mut self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
    ) -> Result<PendingActivation, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.claim_pending_activation_unchecked(transaction_id, plan_digest, generation)
    }

    fn claim_pending_activation_unchecked(
        &mut self,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
    ) -> Result<PendingActivation, InstallationError> {
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
    #[cfg(test)]
    fn commit_pending_activation(
        &mut self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
        commit_fence: &ActivationCommitFence,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.commit_pending_activation_unchecked(
            transaction_id,
            plan_digest,
            generation,
            commit_fence,
        )
    }

    fn commit_pending_activation_unchecked(
        &mut self,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
        commit_fence: &ActivationCommitFence,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        commit_fence.validate()?;
        let Some(pending) = self.pending_activation.as_ref() else {
            if self.terminal_matches(
                transaction_id,
                plan_digest,
                Some(generation),
                Some(commit_fence),
                PendingActivationTerminalDisposition::Committed,
            ) {
                return Ok(());
            }
            if self
                .last_terminal_activation
                .as_ref()
                .is_some_and(|terminal| {
                    Self::terminal_identity_matches(
                        terminal,
                        transaction_id,
                        plan_digest,
                        Some(generation),
                        PendingActivationTerminalDisposition::Committed,
                    )
                })
            {
                return Err(InstallationError::IdentityConflict);
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
        commit_fence.validate_against_manifest(&pending.manifest)?;
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
            commit_fence: Some(commit_fence.clone()),
        });
        self.validate()
    }

    /// Records an unknown/failed Host attempt without advertising the candidate.
    #[cfg(test)]
    fn mark_pending_recovery(
        &mut self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        reason: impl Into<String>,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.mark_pending_recovery_unchecked(transaction_id, plan_digest, reason)
    }

    fn mark_pending_recovery_unchecked(
        &mut self,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        reason: impl Into<String>,
    ) -> Result<(), InstallationError> {
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
    #[cfg(test)]
    fn abort_pending_activation(
        &mut self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.abort_pending_activation_unchecked(transaction_id, plan_digest)
    }

    fn abort_pending_activation_unchecked(
        &mut self,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        let Some(pending) = self.pending_activation.as_ref() else {
            if self.terminal_matches(
                transaction_id,
                plan_digest,
                None,
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
            commit_fence: None,
        };
        self.generations
            .retain(|item| item.manifest.generation != generation);
        self.service_registration_approvals
            .retain(|approval| approval.generation != generation);
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

    /// Returns the exact fence recorded for the most recent committed
    /// activation, if the terminal receipt is a committed disposition.
    #[must_use]
    pub fn last_committed_activation_fence(&self) -> Option<&ActivationCommitFence> {
        self.last_terminal_activation.as_ref().and_then(|terminal| {
            (terminal.disposition == PendingActivationTerminalDisposition::Committed)
                .then_some(terminal.commit_fence.as_ref())
                .flatten()
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
            PendingActivationTerminalDisposition::Committed => {
                if self.active_generation.as_ref() != Some(&terminal.generation) {
                    return Err(InstallationError::IncompleteObservation(
                        "committed terminal activation is not the active generation".to_owned(),
                    ));
                }
                let Some(commit_fence) = terminal.commit_fence.as_ref() else {
                    return Err(InstallationError::IncompleteObservation(
                        "committed terminal activation is missing its readiness fence".to_owned(),
                    ));
                };
                let manifest = self
                    .generations
                    .iter()
                    .find(|item| item.manifest.generation == terminal.generation)
                    .ok_or_else(|| {
                        InstallationError::IncompleteObservation(
                            "committed terminal activation generation is not approved".to_owned(),
                        )
                    })?;
                commit_fence.validate_against_manifest(&manifest.manifest)
            }
            PendingActivationTerminalDisposition::Aborted => {
                if terminal.commit_fence.is_some() {
                    return Err(InstallationError::IncompleteObservation(
                        "aborted terminal activation carries a readiness fence".to_owned(),
                    ));
                }
                if self
                    .generations
                    .iter()
                    .any(|item| item.manifest.generation == terminal.generation)
                {
                    return Err(InstallationError::IncompleteObservation(
                        "aborted terminal activation remains approved".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Validates the complete registry projection and all generation entries.
    #[allow(
        clippy::too_many_lines,
        reason = "registry validation keeps the complete activation authority in one boundary"
    )]
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.registry_wire_version != INSTALLATION_REGISTRY_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "approved-generation registry wire {} cannot be read as {}",
                    self.registry_wire_version, INSTALLATION_REGISTRY_WIRE_VERSION
                ),
            });
        }
        if self.revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "registry.revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        let mut identities = BTreeSet::new();
        let mut service_identities = BTreeSet::new();
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
        for approval in &self.service_registration_approvals {
            approval.validate()?;
            let generation = self
                .generations
                .iter()
                .find(|item| item.manifest.generation == approval.generation)
                .ok_or(InstallationError::IdentityConflict)?;
            if generation.manifest.runtime_launch.profile != InstallationProfile::SystemService {
                return Err(InstallationError::ProfileViolation(
                    "SCM registration approvals require the SystemService profile".to_owned(),
                ));
            }
            if !service_identities.insert((&approval.generation, approval.role)) {
                return Err(InstallationError::Duplicate {
                    kind: "service registration approval".to_owned(),
                    identity: format!("{}:{:?}", approval.generation.as_str(), approval.role),
                });
            }
        }
        for generation in &self.generations {
            if generation.manifest.runtime_launch.profile == InstallationProfile::SystemService {
                let count = self
                    .service_registration_approvals
                    .iter()
                    .filter(|approval| approval.generation == generation.manifest.generation)
                    .count();
                if count != 2 {
                    return Err(InstallationError::IncompleteObservation(
                        "SystemService generation requires exactly Host and Watchdog SCM approvals"
                            .to_owned(),
                    ));
                }
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
            if !self
                .generations
                .iter()
                .any(|item| item.manifest == pending.manifest && item.approval == pending.approval)
            {
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

fn activation_terminal_digest(
    terminal: &PendingActivationTerminal,
) -> Result<PlatformHandle, InstallationError> {
    let bytes =
        serde_json::to_vec(terminal).map_err(|error| InstallationError::CorruptRegistry {
            reason: format!("committed activation terminal could not be canonicalized: {error}"),
        })?;
    PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
        field: "activation_commit_receipt.terminal_digest".to_owned(),
        reason: error.to_string(),
    })
}

fn validate_package_binding(
    candidate_manifest: &CandidateManifest,
    transaction_staging_root: &PlatformHandle,
    effects: &[InstallerEffectPlan],
) -> Result<(), InstallationError> {
    let expected_manifest_digest = candidate_manifest_digest(candidate_manifest)?;
    let mut package_count = 0_u8;
    for effect in effects {
        let InstallerEffectPlan::StagePackage {
            generation,
            manifest,
            staging_root,
            candidate_manifest_digest: bound_manifest_digest,
            ..
        } = effect
        else {
            continue;
        };
        package_count = package_count.saturating_add(1);
        if generation != &candidate_manifest.generation {
            return Err(InstallationError::IdentityConflict);
        }
        if bound_manifest_digest != &expected_manifest_digest {
            return Err(InstallationError::IdentityConflict);
        }
        if !same_windows_root(staging_root.as_str(), transaction_staging_root.as_str())? {
            return Err(InstallationError::IdentityConflict);
        }
        PackageManifest::new(&manifest.generation, manifest.files.clone())
            .map_err(|error| package_plan_error(&error))?;
    }
    if package_count > 1 {
        return Err(InstallationError::Duplicate {
            kind: "package staging effect".to_owned(),
            identity: candidate_manifest.generation.as_str().to_owned(),
        });
    }
    let service_requires_package = effects.iter().any(|effect| {
        matches!(
            effect,
            InstallerEffectPlan::RegisterService { .. }
                | InstallerEffectPlan::ProvisionStoreCredential { .. }
        )
    });
    if service_requires_package && package_count == 0 {
        return Err(InstallationError::IncompleteObservation(
            "service effects require one package/static-verification effect".to_owned(),
        ));
    }
    let package_index = effects
        .iter()
        .position(|effect| matches!(effect, InstallerEffectPlan::StagePackage { .. }));
    if let Some(package_index) = package_index
        && effects[..package_index].iter().any(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::RegisterService { .. }
                    | InstallerEffectPlan::ProvisionStoreCredential { .. }
            )
        })
    {
        return Err(InstallationError::IncompleteObservation(
            "package/static verification must precede service and credential effects".to_owned(),
        ));
    }
    Ok(())
}

fn validate_staging_receipt_for_plan(
    effect: &InstallerEffectPlan,
    receipt: &StagingReceipt,
) -> Result<(), InstallationError> {
    let InstallerEffectPlan::StagePackage {
        manifest,
        staging_root,
        expected_file_digests,
        ..
    } = effect
    else {
        return Err(InstallationError::IdentityConflict);
    };
    if receipt.generation != manifest.generation
        || receipt.manifest_sha256 != manifest.canonical_digest()
        || receipt.root_identity.volume_serial_number == 0
        || receipt.root_identity.file_index == 0
    {
        return Err(InstallationError::IdentityConflict);
    }
    let expected_root = Path::new(staging_root.as_str()).join(&manifest.generation);
    if !eliot_platform_windows::windows_paths_equal(&receipt.root_path, &expected_root) {
        return Err(InstallationError::IdentityConflict);
    }
    if receipt.files.len() != manifest.files.len() {
        return Err(InstallationError::IncompleteObservation(
            "package receipt file count differs from its immutable manifest".to_owned(),
        ));
    }
    for spec in &manifest.files {
        let Some(expected) = expected_file_digests
            .iter()
            .find(|item| item.relative_path.eq_ignore_ascii_case(&spec.relative_path))
        else {
            return Err(InstallationError::IdentityConflict);
        };
        let Some(file) = receipt
            .files
            .iter()
            .find(|item| item.relative_path.eq_ignore_ascii_case(&spec.relative_path))
        else {
            return Err(InstallationError::IncompleteObservation(
                "package receipt is missing a manifest file".to_owned(),
            ));
        };
        sha256_handle(
            &expected.sha256,
            "installer_effect.expected_file_digests.sha256",
        )?;
        if file.sha256 != expected.sha256.as_str()
            || file.size > spec.max_size
            || (spec.executable && (file.pe.is_none() || file.authenticode.is_none()))
            || (!spec.executable && (file.pe.is_some() || file.authenticode.is_some()))
            || file.source_identity.volume_serial_number == 0
            || file.source_identity.file_index == 0
            || file.destination_identity.volume_serial_number == 0
            || file.destination_identity.file_index == 0
        {
            return Err(InstallationError::IdentityConflict);
        }
        if let Some(authenticode) = &file.authenticode
            && authenticode.verdict != AuthenticodeVerdict::Valid
        {
            return Err(InstallationError::IncompleteObservation(
                "package receipt does not contain a valid Authenticode verdict".to_owned(),
            ));
        }
    }
    Ok(())
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
        self.approval.validate()?;
        if self.transaction_id != self.approval.transaction_id
            || self.plan_digest != self.approval.installer_plan_digest
        {
            return Err(InstallationError::IdentityConflict);
        }
        validate_approval_against_manifest(&self.approval, &self.manifest, "pending_activation")?;
        if self.manifest_digest != self.approval.candidate_manifest_digest {
            return Err(InstallationError::IdentityConflict);
        }
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

/// Installer-owned approval for one exact Host or Watchdog SCM registration.
///
/// The approval is a projection of an [`InstallationTransaction`]'s durable
/// service-effect progress.  It is deliberately separate from
/// [`CandidateManifest`] and [`RuntimeLaunchDescriptor`]: the registration
/// nonce is minted only while the installer drives the effect and is retained
/// here only after authoritative SCM readback has produced an `Applied`
/// progress entry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallerServiceRegistrationApproval {
    /// Sole transaction which authorized this registration.
    transaction_id: PlatformHandle,
    /// Candidate generation bound to the transaction.
    generation: PlatformHandle,
    /// Immutable installer effect identity.
    effect_id: PlatformHandle,
    /// Host or Watchdog role.
    role: InstallerServiceRole,
    /// Canonical SCM service name.
    service_name: PlatformHandle,
    /// Exact approved service image path.
    executable_path: PlatformHandle,
    /// Exact service account admitted by the effect plan.
    account: InstallerServiceAccount,
    /// Exact service start policy admitted by the effect plan.
    automatic_start: bool,
    /// Immutable descriptor/installation binding rendered to service argv.
    service_bootstrap: InstallationServiceBootstrap,
    /// Unpredictable nonce rendered only for this role's registration.
    registration_nonce: PlatformHandle,
    /// Authoritative SCM configuration digest returned by readback.
    configuration_digest: PlatformHandle,
}

impl InstallerServiceRegistrationApproval {
    /// Returns the generation bound to this approval.
    #[must_use]
    pub fn generation(&self) -> &PlatformHandle {
        &self.generation
    }

    /// Returns the role bound to this approval.
    #[must_use]
    pub const fn role(&self) -> InstallerServiceRole {
        self.role
    }

    /// Returns the authoritative SCM configuration digest.
    #[must_use]
    pub fn configuration_digest(&self) -> &PlatformHandle {
        &self.configuration_digest
    }

    /// Validates the durable approval without touching the filesystem or SCM.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.transaction_id, "service_registration.transaction_id")?;
        handle(&self.generation, "service_registration.generation")?;
        handle(&self.effect_id, "service_registration.effect_id")?;
        handle(&self.service_name, "service_registration.service_name")?;
        approved_path(
            &self.executable_path,
            "service_registration.executable_path",
        )?;
        self.service_bootstrap.validate()?;
        sha256_handle(
            &self.registration_nonce,
            "service_registration.registration_nonce",
        )?;
        sha256_handle(
            &self.configuration_digest,
            "service_registration.configuration_digest",
        )?;
        let (expected_name, expected_image) = match self.role {
            InstallerServiceRole::Host => (ELIOT_HOST_SERVICE_NAME, "eliot-host.exe"),
            InstallerServiceRole::Watchdog => (ELIOT_WATCHDOG_SERVICE_NAME, "eliot-watchdog.exe"),
        };
        let observed_image = self
            .executable_path
            .as_str()
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or_default();
        if self.service_name.as_str() != expected_name
            || !observed_image.eq_ignore_ascii_case(expected_image)
            || self.account != InstallerServiceAccount::LocalService
            || !self.automatic_start
        {
            return Err(InstallationError::ProfileViolation(
                "service registration approval differs from the canonical Runtime Live service shape"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Reconstructs the exact platform request approved by the installer.
    ///
    /// The returned request is still inert; this helper performs no SCM
    /// mutation.  The platform constructor supplies the final canonical
    /// command line and its configuration digest is checked against the
    /// installer readback before the request is returned.
    pub fn service_registration_request(
        &self,
    ) -> Result<ServiceRegistrationRequest, InstallationError> {
        self.validate()?;
        let bootstrap = ServiceBootstrapArguments::new(
            Path::new(self.service_bootstrap.descriptor_path.as_str()).to_path_buf(),
            self.service_bootstrap.descriptor_digest.as_str(),
            self.service_bootstrap.installation_id.as_str(),
            self.service_bootstrap.plan_generation,
            Vec::<String>::new(),
        )
        .and_then(|value| {
            value.with_host_state_root(Path::new(self.service_bootstrap.host_state_root.as_str()))
        })
        .and_then(|value| value.with_registration_nonce(self.registration_nonce.as_str()))
        .map_err(|_| InstallationError::InvalidField {
            field: "service_registration.service_bootstrap".to_owned(),
            reason: "approved SCM bootstrap could not be reconstructed".to_owned(),
        })?;
        let display_name = match self.role {
            InstallerServiceRole::Host => ELIOT_HOST_SERVICE_DISPLAY_NAME,
            InstallerServiceRole::Watchdog => ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
        };
        let request = ServiceRegistrationRequest::with_bootstrap(
            self.service_name.as_str(),
            display_name,
            Path::new(self.executable_path.as_str()).to_path_buf(),
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
            bootstrap,
        )
        .map_err(|_| InstallationError::InvalidField {
            field: "service_registration.request".to_owned(),
            reason: "approved SCM request could not be reconstructed".to_owned(),
        })?;
        if request.expected_configuration_digest() != self.configuration_digest.as_str() {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(request)
    }
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

/// One expected package-file digest bound to a [`InstallerEffectPlan::StagePackage`] effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageArtifactDigest {
    /// Canonical path relative to the package generation root.
    pub relative_path: String,
    /// Expected SHA-256 digest of the immutable source and staged file.
    pub sha256: PlatformHandle,
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
    /// Stage one immutable source bundle into the transaction staging root and
    /// retain the complete static-verification receipt in effect progress.
    StagePackage {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Absolute retained source bundle directory.
        source_bundle: PlatformHandle,
        /// File identity captured when the plan was admitted.
        source_bundle_identity: FileIdentity,
        /// Candidate generation identity from the immutable manifest.
        generation: PlatformHandle,
        /// Exact package manifest used by the bounded stager.
        manifest: PackageManifest,
        /// Destination root for the immutable generation.
        staging_root: PlatformHandle,
        /// Expected file bytes bound to the candidate artifact set.
        expected_file_digests: Vec<PackageArtifactDigest>,
        /// Digest of the complete candidate manifest, including runtime argv.
        candidate_manifest_digest: PlatformHandle,
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
            | Self::StagePackage { effect_id, .. }
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
            Self::StagePackage {
                source_bundle,
                source_bundle_identity,
                generation,
                manifest,
                staging_root,
                expected_file_digests,
                candidate_manifest_digest,
                ..
            } => {
                approved_path(source_bundle, "installer_effect.source_bundle")?;
                approved_path(staging_root, "installer_effect.staging_root")?;
                handle(generation, "installer_effect.generation")?;
                if source_bundle_identity.volume_serial_number == 0
                    || source_bundle_identity.file_index == 0
                {
                    return Err(InstallationError::InvalidField {
                        field: "installer_effect.source_bundle_identity".to_owned(),
                        reason: "must contain a non-zero retained file identity".to_owned(),
                    });
                }
                let validated = PackageManifest::new(&manifest.generation, manifest.files.clone())
                    .map_err(|error| package_plan_error(&error))?;
                if validated != *manifest {
                    return Err(InstallationError::IdentityConflict);
                }
                sha256_handle(
                    candidate_manifest_digest,
                    "installer_effect.candidate_manifest_digest",
                )?;
                let mut paths = BTreeSet::new();
                for digest in expected_file_digests {
                    validate_package_relative_text(
                        &digest.relative_path,
                        "installer_effect.expected_file_digests.relative_path",
                    )?;
                    if !paths.insert(digest.relative_path.to_ascii_lowercase()) {
                        return Err(InstallationError::Duplicate {
                            kind: "package artifact digest".to_owned(),
                            identity: digest.relative_path.clone(),
                        });
                    }
                    sha256_handle(
                        &digest.sha256,
                        "installer_effect.expected_file_digests.sha256",
                    )?;
                }
                let manifest_paths = manifest
                    .files
                    .iter()
                    .map(|file| file.relative_path.to_ascii_lowercase())
                    .collect::<BTreeSet<_>>();
                if paths != manifest_paths {
                    return Err(InstallationError::IdentityConflict);
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
        InstallerEffectPlan::CreateRoot { .. } | InstallerEffectPlan::StagePackage { .. } => Ok(()),
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
    let mut package_index = None;
    for (index, effect) in effects.iter().enumerate() {
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
            InstallerEffectPlan::StagePackage { .. } => {
                if package_index.replace(index).is_some() {
                    return Err(InstallationError::Duplicate {
                        kind: "package staging effect".to_owned(),
                        identity: effect.effect_id().as_str().to_owned(),
                    });
                }
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
        if package_index.is_some_and(|package| {
            index > package
                && matches!(
                    effect,
                    InstallerEffectPlan::CreateRoot { .. } | InstallerEffectPlan::ApplyAcl { .. }
                )
        }) {
            return Err(InstallationError::IncompleteObservation(
                "root and ACL effects must precede package staging".to_owned(),
            ));
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
    /// Complete immutable package receipt, present only for `StagePackage`.
    pub staging_receipt: Option<StagingReceipt>,
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
///
/// The raw stage transition is crate-private. In particular, callers cannot
/// compile an arbitrary `ActiveVerified` advance; the public replacement
/// requires an opaque [`ActivationCommitReceipt`].
///
/// ```compile_fail
/// use eliot_installation::{InstallationStage, InstallationTransaction};
///
/// fn forge_active(transaction: &mut InstallationTransaction) {
///     transaction.advance(InstallationStage::ActiveVerified, Vec::new());
/// }
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
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
    /// Exact registry terminal that authorized `ActiveVerified`, retained as
    /// a private v9 binding for crash/retry reconciliation.
    active_verified_receipt: Option<ActiveVerifiedReceiptBinding>,
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
        validate_package_binding(&candidate_manifest, &staging_root, &installer_effects)?;
        let rollback_plan = request.rollback_plan.clone();
        let installer_plan_digest =
            PlatformHandle::new(sha256_hex(&Self::installer_plan_unsigned_bytes(
                &transaction_id,
                &candidate_manifest,
                &staging_root,
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
                staging_receipt: None,
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
            active_verified_receipt: None,
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

    /// Requires authoritative readback for every immutable installer effect.
    ///
    /// This is the core admission gate for any registry or approval
    /// projection.  A transaction with a pending intent, unknown outcome, or
    /// merely planned effect must not become an approved generation.
    pub fn require_all_effects_applied(&self) -> Result<(), InstallationError> {
        self.validate()?;
        if self.effect_progress.iter().any(|progress| {
            !matches!(
                progress.state,
                InstallationEffectProgressState::Applied { .. }
            )
        }) {
            return Err(InstallationError::IncompleteObservation(
                "all installer effects require authoritative applied readback before registry staging or approval projection"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Projects the two installer-owned SCM approvals from authoritative
    /// durable service-effect progress.
    ///
    /// Only `Applied` service effects can produce an approval.  A missing
    /// nonce, pending intent, or unknown effect is returned as a stable
    /// fail-closed classification; no nonce is copied into the error.
    pub(crate) fn service_registration_approvals(
        &self,
    ) -> Result<Vec<InstallerServiceRegistrationApproval>, InstallationError> {
        self.validate()?;
        let mut approvals = Vec::new();
        let mut roles = BTreeSet::new();
        let mut nonces = BTreeSet::<PlatformHandle>::new();
        for (effect, progress) in self.installer_effects.iter().zip(&self.effect_progress) {
            let InstallerEffectPlan::RegisterService {
                effect_id,
                role,
                service_name,
                executable_path,
                account,
                automatic_start,
            } = effect
            else {
                continue;
            };
            let registration_nonce = progress.registration_nonce.clone().ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "service registration approval is missing its durable nonce".to_owned(),
                )
            })?;
            let configuration_digest = match &progress.state {
                InstallationEffectProgressState::Applied {
                    external_identity, ..
                } => external_identity.clone(),
                InstallationEffectProgressState::Pending
                | InstallationEffectProgressState::IntentCommitted { .. } => {
                    return Err(InstallationError::IncompleteObservation(
                        "service registration effect is pending authoritative readback".to_owned(),
                    ));
                }
                InstallationEffectProgressState::Unknown { .. } => {
                    return Err(InstallationError::IncompleteObservation(
                        "service registration effect requires reconciliation".to_owned(),
                    ));
                }
            };
            if !roles.insert(*role) {
                return Err(InstallationError::Duplicate {
                    kind: "service registration role".to_owned(),
                    identity: format!("{role:?}"),
                });
            }
            if !nonces.insert(registration_nonce.clone()) {
                return Err(InstallationError::IdentityConflict);
            }
            let approval = InstallerServiceRegistrationApproval {
                transaction_id: self.transaction_id.clone(),
                generation: self.candidate_manifest.generation.clone(),
                effect_id: effect_id.clone(),
                role: *role,
                service_name: service_name.clone(),
                executable_path: executable_path.clone(),
                account: *account,
                automatic_start: *automatic_start,
                service_bootstrap: InstallationServiceBootstrap {
                    descriptor_path: self
                        .candidate_manifest
                        .runtime_launch
                        .authority_descriptor_path
                        .clone(),
                    descriptor_digest: self
                        .candidate_manifest
                        .runtime_launch
                        .authority_descriptor_digest
                        .clone(),
                    installation_id: self
                        .candidate_manifest
                        .runtime_launch
                        .installation_epoch
                        .installation
                        .clone(),
                    plan_generation: self
                        .candidate_manifest
                        .runtime_launch
                        .authority_generation
                        .value(),
                    host_state_root: self
                        .candidate_manifest
                        .runtime_launch
                        .runtime_state_roots
                        .host_state_root
                        .clone(),
                },
                registration_nonce,
                configuration_digest,
            };
            approval.validate()?;
            approvals.push(approval);
        }
        approvals.sort_by_key(|approval| approval.role);
        Ok(approvals)
    }

    /// Returns the monotonic durable revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    fn installer_plan_unsigned_bytes(
        transaction_id: &PlatformHandle,
        candidate_manifest: &CandidateManifest,
        staging_root: &PlatformHandle,
        runtime_state_roots: &RuntimeStateRoots,
        minimum_store_available_bytes: u64,
        planned_changes: &[PlannedChange],
        installer_effects: &[InstallerEffectPlan],
    ) -> Result<Vec<u8>, InstallationError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            transaction_id: &'a PlatformHandle,
            candidate_manifest: &'a CandidateManifest,
            staging_root: &'a PlatformHandle,
            runtime_state_roots: &'a RuntimeStateRoots,
            minimum_store_available_bytes: u64,
            planned_changes: &'a [PlannedChange],
            installer_effects: &'a [InstallerEffectPlan],
        }
        serde_json::to_vec(&Unsigned {
            transaction_id,
            candidate_manifest,
            staging_root,
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
        validate_package_binding(
            &self.candidate_manifest,
            &self.staging_root,
            &self.installer_effects,
        )?;
        sha256_handle(&self.installer_plan_digest, "installer_plan_digest")?;
        if sha256_hex(&Self::installer_plan_unsigned_bytes(
            &self.transaction_id,
            &self.candidate_manifest,
            &self.staging_root,
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
        self.validate_stage_progress()?;
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
        match (&self.stage, &self.active_verified_receipt) {
            (
                InstallationStage::ActiveVerified
                | InstallationStage::Cleaning
                | InstallationStage::Completed,
                Some(receipt),
            ) => receipt.validate_against_transaction(self)?,
            (
                InstallationStage::ActiveVerified
                | InstallationStage::Cleaning
                | InstallationStage::Completed,
                None,
            ) => {
                return Err(InstallationError::IncompleteObservation(
                    "active/completed transaction requires the exact committed activation receipt"
                        .to_owned(),
                ));
            }
            (_, Some(_)) => {
                return Err(InstallationError::IncompleteObservation(
                    "activation receipt cannot exist before ActiveVerified".to_owned(),
                ));
            }
            (_, None) => {}
        }
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
                    InstallerEffectPlan::StagePackage { .. } => {
                        precondition.credential_snapshot.is_none()
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
            if let Some(receipt) = &progress.staging_receipt {
                let InstallerEffectPlan::StagePackage { .. } = effect else {
                    return Err(InstallationError::InvalidField {
                        field: "effect_progress.staging_receipt".to_owned(),
                        reason: "package receipts belong only to the StagePackage effect"
                            .to_owned(),
                    });
                };
                validate_staging_receipt_for_plan(effect, receipt)?;
            } else if matches!(
                (&progress.state, effect),
                (
                    InstallationEffectProgressState::Applied { .. },
                    InstallerEffectPlan::StagePackage { .. }
                )
            ) {
                return Err(InstallationError::InvalidField {
                    field: "effect_progress.staging_receipt".to_owned(),
                    reason: "applied package effect requires its typed staging receipt".to_owned(),
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
                    InstallationEffectProgressState::IntentCommitted { .. }
                    | InstallationEffectProgressState::Unknown { .. }
                    | InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        ..
                    },
                    InstallerEffectPlan::StagePackage { .. },
                    Some(_),
                    None,
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
                        && !matches!(
                            effect,
                            InstallerEffectPlan::RegisterService { .. }
                                | InstallerEffectPlan::StagePackage { .. }
                        )
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
                    if matches!(effect, InstallerEffectPlan::StagePackage { .. })
                        && progress.staging_receipt.is_none()
                    {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.staging_receipt".to_owned(),
                            reason: "applied package effect requires a durable receipt".to_owned(),
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

    fn validate_stage_progress(&self) -> Result<(), InstallationError> {
        let Some(package_index) = self
            .installer_effects
            .iter()
            .position(|effect| matches!(effect, InstallerEffectPlan::StagePackage { .. }))
        else {
            return Ok(());
        };
        let package_applied = matches!(
            self.effect_progress[package_index].state,
            InstallationEffectProgressState::Applied {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                ..
            }
        ) && self.effect_progress[package_index]
            .staging_receipt
            .is_some();
        if matches!(
            self.stage,
            InstallationStage::StaticVerified
                | InstallationStage::Registering
                | InstallationStage::Activating
                | InstallationStage::ActiveVerified
                | InstallationStage::Cleaning
                | InstallationStage::Completed
        ) && !package_applied
        {
            return Err(InstallationError::IncompleteObservation(
                "static verification and later stages require the applied package receipt"
                    .to_owned(),
            ));
        }
        if self.stage == InstallationStage::Staging
            && package_index > 0
            && self.effect_progress[..package_index]
                .iter()
                .any(|progress| {
                    !matches!(
                        progress.state,
                        InstallationEffectProgressState::Applied { .. }
                    )
                })
        {
            return Err(InstallationError::IncompleteObservation(
                "package staging cannot begin before preceding root/ACL effects are applied"
                    .to_owned(),
            ));
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
            && self.active_verified_receipt.is_none()
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

    /// Advances one non-runtime-health stage using observed evidence and
    /// increments the revision.
    ///
    /// This raw transition is crate-private. `ActiveVerified` is never a
    /// value accepted by this path; it requires the opaque receipt produced by
    /// the read-only registry terminal projection below.
    fn advance(
        &mut self,
        next: InstallationStage,
        evidence: Vec<PlatformHandle>,
    ) -> Result<(), InstallationError> {
        if next == InstallationStage::ActiveVerified {
            return Err(InstallationError::IncompleteObservation(
                "ActiveVerified requires the exact committed activation receipt".to_owned(),
            ));
        }
        if !self.stage.can_advance(next) {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: next,
            });
        }
        handles(&evidence, "stage_evidence", true)?;
        self.completed_stage_refs.extend(evidence);
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

    /// Advances from `Activating` to `ActiveVerified` using the exact
    /// read-only registry terminal proof. The proof is consumed and its
    /// complete binding is persisted in the v9 transaction projection.
    pub fn advance_to_active_verified(
        &mut self,
        receipt: ActivationCommitReceipt,
        evidence: Vec<PlatformHandle>,
    ) -> Result<(), InstallationError> {
        if self.stage != InstallationStage::Activating {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: InstallationStage::ActiveVerified,
            });
        }
        self.validate()?;
        handles(&evidence, "stage_evidence", true)?;
        receipt.validate_against_transaction(self)?;
        if self.active_verified_receipt.is_some() {
            return Err(InstallationError::IdentityConflict);
        }
        self.completed_stage_refs.extend(evidence);
        self.observed_postconditions
            .extend(self.completed_stage_refs.clone());
        self.active_verified_receipt = Some(receipt.binding());
        self.stage = InstallationStage::ActiveVerified;
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

/// Private durable decoder shape for [`InstallationTransaction`].  The
/// public transaction intentionally does not implement `Deserialize`: an
/// arbitrary caller-authored JSON record must not be able to manufacture the
/// private v9 activation receipt binding.  Only the version-gated decoder
/// below may reconstruct this shape, and it still runs the full transaction
/// validator before admission.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationTransactionWire {
    transaction_wire_version: ContractVersion,
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
    installer_plan_digest: PlatformHandle,
    effect_progress: Vec<InstallationEffectProgress>,
    precondition_evidence: Vec<PlatformHandle>,
    stage: InstallationStage,
    completed_stage_refs: Vec<PlatformHandle>,
    pending_external_changes: Vec<PlatformHandle>,
    rollback_plan: PlatformHandle,
    last_known_good: Option<PlatformHandle>,
    no_return_boundary: Option<PlatformHandle>,
    observed_postconditions: Vec<PlatformHandle>,
    active_verified_receipt: Option<ActiveVerifiedReceiptBinding>,
    recovery_command: PlatformHandle,
    revision: u64,
}

impl InstallationTransactionWire {
    fn into_transaction(self) -> InstallationTransaction {
        InstallationTransaction {
            transaction_wire_version: self.transaction_wire_version,
            transaction_id: self.transaction_id,
            installation_epoch: self.installation_epoch,
            profile: self.profile,
            request: self.request,
            current_active_manifest: self.current_active_manifest,
            candidate_manifest: self.candidate_manifest,
            staging_root: self.staging_root,
            planned_changes: self.planned_changes,
            installer_effects: self.installer_effects,
            minimum_store_available_bytes: self.minimum_store_available_bytes,
            installer_plan_digest: self.installer_plan_digest,
            effect_progress: self.effect_progress,
            precondition_evidence: self.precondition_evidence,
            stage: self.stage,
            completed_stage_refs: self.completed_stage_refs,
            pending_external_changes: self.pending_external_changes,
            rollback_plan: self.rollback_plan,
            last_known_good: self.last_known_good,
            no_return_boundary: self.no_return_boundary,
            observed_postconditions: self.observed_postconditions,
            active_verified_receipt: self.active_verified_receipt,
            recovery_command: self.recovery_command,
            revision: self.revision,
        }
    }
}

/// Decodes the canonical transaction JSON and classifies pre-v9 records as an
/// explicit migration requirement rather than synthesizing missing progress.
pub fn decode_installation_transaction_json(
    bytes: &[u8],
) -> Result<InstallationTransaction, InstallationError> {
    decode_installation_transaction_json_with_policy(bytes, false)
}

/// Decodes a transaction record from the ACL-protected redb store. This
/// private replay lane may restore an already advanced transaction so the
/// store can compare it with a freshly read registry receipt. Untrusted JSON
/// callers must use [`decode_installation_transaction_json`], which rejects
/// advanced runtime states before any caller can present them as installer
/// authority.
fn decode_installation_transaction_json_from_store(
    bytes: &[u8],
) -> Result<InstallationTransaction, InstallationError> {
    decode_installation_transaction_json_with_policy(bytes, true)
}

fn decode_installation_transaction_json_with_policy(
    bytes: &[u8],
    allow_advanced_state: bool,
) -> Result<InstallationTransaction, InstallationError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| InstallationError::CorruptRegistry {
            reason: error.to_string(),
        })?;
    let version = value.get("transaction_wire_version").ok_or_else(|| {
        InstallationError::MigrationRequired {
            reason: "installation transaction predates the required v9 discriminator".to_owned(),
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
    let transaction: InstallationTransactionWire =
        serde_json::from_value(value).map_err(|error| InstallationError::CorruptRegistry {
            reason: error.to_string(),
        })?;
    let transaction = transaction.into_transaction();
    transaction.validate()?;
    if !allow_advanced_state
        && matches!(
            transaction.stage(),
            InstallationStage::ActiveVerified
                | InstallationStage::Cleaning
                | InstallationStage::Completed
        )
    {
        return Err(InstallationError::MigrationRequired {
            reason: "advanced transaction state requires ACL-protected store replay and an exact registry receipt"
                .to_owned(),
        });
    }
    Ok(transaction)
}

/// Parses the stable identity used to address one durable installation transaction.
///
/// This narrow adapter keeps CLI callers on the installation contract without
/// importing the platform crate or constructing a second transaction identity
/// path. It performs only the same text validation used by the transaction
/// constructor; the durable store remains the authority for existence and CAS.
pub fn parse_installation_transaction_id(
    value: impl Into<String>,
) -> Result<PlatformHandle, InstallationError> {
    PlatformHandle::new(value.into()).map_err(|error| InstallationError::InvalidField {
        field: "transaction_id".to_owned(),
        reason: error.to_string(),
    })
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
    /// Exact per-installation Host state root consumed by Host and Watchdog.
    ///
    /// This is carried in the SCM command line; consumers must not infer it
    /// from `ProgramData`, the current directory, or an ambient environment.
    pub host_state_root: PlatformHandle,
}

impl InstallationServiceBootstrap {
    fn validate(&self) -> Result<(), InstallationError> {
        approved_path(&self.descriptor_path, "service_bootstrap.descriptor_path")?;
        sha256_handle(
            &self.descriptor_digest,
            "service_bootstrap.descriptor_digest",
        )?;
        handle(&self.installation_id, "service_bootstrap.installation_id")?;
        approved_path(&self.host_state_root, "service_bootstrap.host_state_root")?;
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
    /// Typed durable package receipt for a committed stage/recovery request.
    pub staging_receipt: Option<StagingReceipt>,
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
        if let Some(receipt) = &self.staging_receipt {
            validate_staging_receipt_for_plan(&self.plan, receipt)?;
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
            (
                InstallerEffectPlan::ApplyAcl { .. } | InstallerEffectPlan::StagePackage { .. },
                InstallationEffectAction::Apply,
                None,
            )
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
        if matches!(&self.plan, InstallerEffectPlan::StagePackage { .. }) {
            if self.action == InstallationEffectAction::Rollback && self.staging_receipt.is_none() {
                return Err(InstallationError::InvalidField {
                    field: "effect.staging_receipt".to_owned(),
                    reason: "exact package rollback requires the durable staging receipt"
                        .to_owned(),
                });
            }
        } else if self.staging_receipt.is_some() {
            return Err(InstallationError::IdentityConflict);
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
        intent.staging_receipt = None;
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
        /// Typed package receipt, only for the `StagePackage` effect.
        staging_receipt: Option<StagingReceipt>,
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
            InstallerEffectPlan::RegisterService { .. } | InstallerEffectPlan::StagePackage { .. }
        ))?;
        if let Self::Matching {
            staging_receipt: Some(receipt),
            ..
        } = self
        {
            if !matches!(effect, InstallerEffectPlan::StagePackage { .. }) {
                return Err(InstallationError::IdentityConflict);
            }
            validate_staging_receipt_for_plan(effect, receipt)?;
        } else if matches!(effect, InstallerEffectPlan::StagePackage { .. })
            && matches!(self, Self::Matching { .. })
        {
            return Err(InstallationError::IncompleteObservation(
                "package matching readback requires its typed receipt".to_owned(),
            ));
        }
        if !matches!(effect, InstallerEffectPlan::ProvisionStoreCredential { .. })
            && matches!(
                self,
                Self::Matching {
                    credential_receipt: Some(_),
                    ..
                }
            )
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
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
                staging_receipt,
                ..
            } => {
                handle(external_identity, "observation.external_identity")?;
                handles(evidence, "observation.evidence", true)?;
                sha256_handle(postcondition_digest, "observation.postcondition_digest")?;
                if let Some(receipt) = credential_receipt {
                    receipt.validate()?;
                }
                if let Some(receipt) = staging_receipt {
                    if receipt.generation.trim().is_empty() || !receipt.root_path.is_absolute() {
                        return Err(InstallationError::InvalidField {
                            field: "observation.staging_receipt".to_owned(),
                            reason:
                                "package receipt root and generation must be absolute/non-blank"
                                    .to_owned(),
                        });
                    }
                    if receipt.root_identity.volume_serial_number == 0
                        || receipt.root_identity.file_index == 0
                    {
                        return Err(InstallationError::InvalidField {
                            field: "observation.staging_receipt.root_identity".to_owned(),
                            reason: "package receipt root identity must be non-zero".to_owned(),
                        });
                    }
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
    /// Typed package receipt returned only by `StagePackage` execution/readback.
    pub staging_receipt: Option<StagingReceipt>,
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
        let expected_host_state_root =
            joined_windows_path(request.installation_root.as_str(), "host");
        if !same_windows_root(
            bootstrap.host_state_root.as_str(),
            &expected_host_state_root,
        )
        .map_err(|_| PortError::InvalidRequestMetadata)?
        {
            return Err(PortError::InvalidRequestMetadata);
        }
        // `effect_request` has already validated the transaction-bound
        // installation root before this sealed port is reached. Host and its
        // sibling Watchdog must select the same fixed Host-state child; neither
        // service may infer the legacy global contour.
        let installation_root = PathBuf::from(request.installation_root.as_str());
        let bootstrap = ServiceBootstrapArguments::new(
            Path::new(bootstrap.descriptor_path.as_str()).to_path_buf(),
            bootstrap.descriptor_digest.as_str(),
            bootstrap.installation_id.as_str(),
            bootstrap.plan_generation,
            Vec::<String>::new(),
        )
        .and_then(|value| value.with_host_state_root(Path::new(bootstrap.host_state_root.as_str())))
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
                    staging_receipt: None,
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
                    staging_receipt: None,
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
                    staging_receipt: None,
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
        if matches!(&request.plan, InstallerEffectPlan::StagePackage { .. }) {
            return execute_package(request);
        }
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
                staging_receipt: None,
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
                        staging_receipt: None,
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
                    staging_receipt: None,
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
                    staging_receipt: None,
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
                staging_receipt: None,
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
            staging_receipt: None,
        })
    }

    fn inspect(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectObservation> {
        let result = if matches!(&request.plan, InstallerEffectPlan::RegisterService { .. }) {
            self.inspect_service(request)
        } else if matches!(&request.plan, InstallerEffectPlan::StagePackage { .. }) {
            inspect_package(request).map_err(|error| package_port_error(&error))
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
        } else if matches!(&request.plan, InstallerEffectPlan::StagePackage { .. }) {
            reconcile_package(request).map_err(|error| package_port_error(&error))
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
        InstallerEffectPlan::StagePackage { staging_root, .. } => Path::new(staging_root.as_str()),
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
        staging_receipt: None,
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
        staging_receipt: None,
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
        staging_receipt: None,
    })
}

fn package_stager(
    request: &InstallationEffectRequest,
) -> Result<(PackageStager, PackageManifest), PortError> {
    let InstallerEffectPlan::StagePackage {
        source_bundle,
        source_bundle_identity,
        manifest,
        staging_root,
        ..
    } = &request.plan
    else {
        return Err(PortError::InvalidRequestMetadata);
    };
    let source = TrustedSourceBundle::open(Path::new(source_bundle.as_str()))
        .map_err(|error| package_port_error(&error))?;
    if source.identity() != *source_bundle_identity {
        return Err(PortError::IdentityConflict);
    }
    let stager = PackageStager::open(source, Path::new(staging_root.as_str()))
        .map_err(|error| package_port_error(&error))?;
    Ok((stager, manifest.clone()))
}

fn package_port_error(error: &PackageStagingError) -> PortError {
    match error {
        PackageStagingError::InvalidRelativePath
        | PackageStagingError::ManifestCollision
        | PackageStagingError::BoundExceeded
        | PackageStagingError::RootUnavailable => PortError::InvalidRequestMetadata,
        PackageStagingError::UnsupportedPlatform => PortError::Provider(ProviderError {
            code: ProviderErrorCode::Unavailable,
            retryable: false,
        }),
        PackageStagingError::SecurityMismatch => PortError::Provider(ProviderError {
            code: ProviderErrorCode::PermissionDenied,
            retryable: false,
        }),
        _ => PortError::Provider(ProviderError {
            code: ProviderErrorCode::Failed,
            retryable: false,
        }),
    }
}

fn package_staging_outcome<T>(error: &PackageStagingError) -> PortOutcome<T> {
    match error {
        PackageStagingError::UnsupportedPlatform => {
            PortOutcome::Unknown(UnknownReason::Unsupported)
        }
        PackageStagingError::InvalidRelativePath
        | PackageStagingError::ManifestCollision
        | PackageStagingError::BoundExceeded
        | PackageStagingError::RootUnavailable => {
            PortOutcome::Error(PortError::InvalidRequestMetadata)
        }
        _ => PortOutcome::Unknown(UnknownReason::Indeterminate),
    }
}

fn package_pending(error: &PackageStagingError) -> InstallationEffectObservation {
    InstallationEffectObservation::Mismatch {
        pending_ref: PlatformHandle::new(format!("mismatch:package:{error}"))
            .unwrap_or_else(|_| unreachable!()),
    }
}

fn package_receipt_binding(
    request: &InstallationEffectRequest,
    receipt: &StagingReceipt,
) -> Result<(PlatformHandle, PlatformHandle, PlatformHandle), PortError> {
    let receipt_digest =
        PlatformHandle::new(receipt.digest()).map_err(|_| PortError::IdentityConflict)?;
    let external_identity = PlatformHandle::new(sha256_hex(
        &serde_json::to_vec(&(
            "package-receipt-external-v1",
            request.transaction_id.as_str(),
            request.effect_id.as_str(),
            request.plan_digest.as_str(),
            receipt_digest.as_str(),
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)?,
    ))
    .map_err(|_| PortError::InvalidRequestMetadata)?;
    let postcondition_digest = PlatformHandle::new(sha256_hex(
        &serde_json::to_vec(&(
            "package-receipt-postcondition-v1",
            request.plan_digest.as_str(),
            receipt_digest.as_str(),
            receipt,
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)?,
    ))
    .map_err(|_| PortError::InvalidRequestMetadata)?;
    Ok((receipt_digest, external_identity, postcondition_digest))
}

fn package_matching_observation(
    request: &InstallationEffectRequest,
    receipt: StagingReceipt,
) -> Result<InstallationEffectObservation, PortError> {
    validate_staging_receipt_for_plan(&request.plan, &receipt)
        .map_err(|_| PortError::IdentityConflict)?;
    let (receipt_digest, external_identity, postcondition_digest) =
        package_receipt_binding(request, &receipt)?;
    Ok(InstallationEffectObservation::Matching {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity,
        evidence: vec![receipt_digest],
        postcondition_digest,
        credential_receipt: None,
        staging_receipt: Some(receipt),
    })
}

fn package_absent_observation(
    request: &InstallationEffectRequest,
) -> InstallationEffectObservation {
    InstallationEffectObservation::Absent {
        observed_precondition: request.precondition.clone(),
        evidence: vec![
            PlatformHandle::new(sha256_hex(
                format!(
                    "package-absent-v1\0{}\0{}",
                    request.effect_id.as_str(),
                    request.plan_digest.as_str()
                )
                .as_bytes(),
            ))
            .unwrap_or_else(|_| unreachable!()),
        ],
    }
}

fn inspect_package(
    request: &InstallationEffectRequest,
) -> Result<InstallationEffectObservation, PackageStagingError> {
    let (stager, manifest) = package_stager(request).map_err(|_| PackageStagingError::Io)?;
    match stager.inspect(&manifest)? {
        PackageStagingObservation::Absent => Ok(package_absent_observation(request)),
        PackageStagingObservation::Matching(receipt) => {
            package_matching_observation(request, receipt)
                .map_err(|_| PackageStagingError::IdentityMismatch)
        }
        PackageStagingObservation::Mismatch(error) => Ok(package_pending(&error)),
        PackageStagingObservation::Unknown(error) => Err(error),
    }
}

fn reconcile_package(
    request: &InstallationEffectRequest,
) -> Result<InstallationEffectObservation, PackageStagingError> {
    let (stager, manifest) = package_stager(request).map_err(|_| PackageStagingError::Io)?;
    let observation = if let Some(receipt) = &request.staging_receipt {
        stager.reconcile(receipt)?
    } else {
        // A committed intent without a receipt cannot adopt a tree.  Inspect
        // only classifies it; the coordinator will persist rollback-required.
        stager.inspect(&manifest)?
    };
    match observation {
        PackageStagingObservation::Absent => Ok(package_absent_observation(request)),
        PackageStagingObservation::Matching(receipt) => {
            package_matching_observation(request, receipt)
                .map_err(|_| PackageStagingError::IdentityMismatch)
        }
        PackageStagingObservation::Mismatch(error) => Ok(package_pending(&error)),
        PackageStagingObservation::Unknown(error) => Err(error),
    }
}

fn execute_package(
    request: &InstallationEffectRequest,
) -> PortOutcome<InstallationEffectExecution> {
    let (stager, manifest) = match package_stager(request) {
        Ok(value) => value,
        Err(error) => return PortOutcome::Error(error),
    };
    match request.action {
        InstallationEffectAction::Apply => match stager.stage(&manifest) {
            Ok(receipt) => {
                if validate_staging_receipt_for_plan(&request.plan, &receipt).is_err() {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                }
                let Ok(digest) = PlatformHandle::new(receipt.digest()) else {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                };
                PortOutcome::Known(InstallationEffectExecution {
                    evidence: vec![digest],
                    create_disposition: None,
                    credential_receipt: None,
                    staging_receipt: Some(receipt),
                })
            }
            Err(error) => package_staging_outcome(&error),
        },
        InstallationEffectAction::Rollback => {
            let Some(receipt) = request.staging_receipt.as_ref() else {
                return PortOutcome::Error(PortError::InvalidRequestMetadata);
            };
            match stager.rollback(receipt) {
                Ok(()) => PortOutcome::Known(InstallationEffectExecution {
                    evidence: vec![
                        PlatformHandle::new(sha256_hex(
                            format!("package-rollback-v1\0{}", receipt.digest()).as_bytes(),
                        ))
                        .unwrap_or_else(|_| unreachable!()),
                    ],
                    create_disposition: None,
                    credential_receipt: None,
                    staging_receipt: None,
                }),
                Err(error) => package_staging_outcome(&error),
            }
        }
    }
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

    /// Reconciles the exact registry terminal after a crash window between
    /// Host's registry commit and the transaction-store CAS. Implementations
    /// must preserve idempotent retry and fail-closed stage rules; this is
    /// intentionally part of the sealed durable-store boundary.
    fn reconcile_active_verified(
        &mut self,
        receipt: ActivationCommitReceipt,
        evidence: Vec<PlatformHandle>,
    ) -> Result<InstallationStepOutcome, InstallationError>;
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

    /// Reconciles a Host-committed activation terminal into the durable
    /// transaction store. The store remains the sole transaction writer.
    pub fn reconcile_active_verified(
        &mut self,
        receipt: ActivationCommitReceipt,
        evidence: Vec<PlatformHandle>,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        self.store.reconcile_active_verified(receipt, evidence)
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
            InstallerEffectPlan::StagePackage { .. }
        ) && transaction.stage == InstallationStage::Planned
        {
            let expected = TransactionVersion::of(&transaction)?;
            let evidence = PlatformHandle::new(format!(
                "stage:staging-intent:{}",
                transaction.installer_effects[index].effect_id().as_str()
            ))
            .map_err(|error| InstallationError::InvalidField {
                field: "stage_evidence".to_owned(),
                reason: error.to_string(),
            })?;
            transaction.advance(InstallationStage::Staging, vec![evidence])?;
            self.store.compare_and_save(expected, &transaction)?;
        } else if !matches!(
            transaction.installer_effects[index],
            InstallerEffectPlan::StagePackage { .. }
        ) && transaction.stage == InstallationStage::StaticVerified
            && transaction
                .installer_effects
                .iter()
                .any(|effect| matches!(effect, InstallerEffectPlan::StagePackage { .. }))
        {
            let expected = TransactionVersion::of(&transaction)?;
            let evidence = PlatformHandle::new(format!(
                "stage:registering:{}",
                transaction.installer_effects[index].effect_id().as_str()
            ))
            .map_err(|error| InstallationError::InvalidField {
                field: "stage_evidence".to_owned(),
                reason: error.to_string(),
            })?;
            transaction.advance(InstallationStage::Registering, vec![evidence])?;
            self.store.compare_and_save(expected, &transaction)?;
        }
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
                staging_receipt,
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
                    && !matches!(
                        transaction.installer_effects[index],
                        InstallerEffectPlan::StagePackage { .. }
                    )
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
                    staging_receipt,
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
                    InstallerEffectPlan::StagePackage { .. } => {
                        observed_precondition.os_snapshot.is_none()
                            && observed_precondition.credential_snapshot.is_none()
                    }
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
                        | InstallerEffectPlan::ProvisionStoreCredential { .. }
                        | InstallerEffectPlan::StagePackage { .. },
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
                        | InstallerEffectPlan::ProvisionStoreCredential { .. }
                        | InstallerEffectPlan::StagePackage { .. },
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
                if matches!(
                    transaction.installer_effects[index],
                    InstallerEffectPlan::StagePackage { .. }
                ) {
                    let Some(receipt) = execution.staging_receipt else {
                        return self.persist_unknown(
                            transaction,
                            index,
                            PlatformHandle::new("mismatch:package-execution-receipt")
                                .map_err(|error| platform_error(&error))?,
                        );
                    };
                    validate_staging_receipt_for_plan(
                        &transaction.installer_effects[index],
                        &receipt,
                    )?;
                    let expected = TransactionVersion::of(&transaction)?;
                    transaction.effect_progress[index].staging_receipt = Some(receipt);
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
                } else if execution.staging_receipt.is_some() {
                    return self.persist_unknown(
                        transaction,
                        index,
                        PlatformHandle::new("mismatch:unexpected-staging-receipt")
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
                        staging_receipt,
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
                                    || (matches!(
                                        transaction.installer_effects[index],
                                        InstallerEffectPlan::StagePackage { .. }
                                    ) && staging_receipt.is_some())
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
                                staging_receipt,
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

    /// Drives the immutable effect plan until it is complete or reaches a
    /// durable blocked outcome.
    ///
    /// The loop is deliberately finite: at most one call per planned effect
    /// plus one reconciliation pass.  `Rejected`, `RollbackRequired`, and
    /// `Quarantined` are returned immediately, while compare-and-save
    /// conflicts and all other errors are propagated without retry.
    pub fn drive_all_effects_until_blocked(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        let transaction = self.store.load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        transaction.validate()?;
        let max_steps = transaction
            .installer_effects
            .len()
            .checked_add(3)
            .ok_or_else(|| InstallationError::InvalidField {
                field: "installer_effects".to_owned(),
                reason: "bounded drive limit overflow".to_owned(),
            })?;

        for _ in 0..max_steps {
            let outcome = self.drive_effect(transaction_id)?;
            match outcome {
                InstallationStepOutcome::Applied { .. } => {
                    let current = self.store.load(transaction_id)?.ok_or_else(|| {
                        InstallationError::TransactionNotFound {
                            transaction_id: transaction_id.as_str().to_owned(),
                        }
                    })?;
                    if current.effect_progress.iter().all(|progress| {
                        matches!(
                            progress.state,
                            InstallationEffectProgressState::Applied { .. }
                        )
                    }) {
                        current.require_all_effects_applied()?;
                        return Ok(outcome);
                    }
                }
                InstallationStepOutcome::Rejected
                | InstallationStepOutcome::RollbackRequired { .. }
                | InstallationStepOutcome::Quarantined { .. } => return Ok(outcome),
            }
        }

        Err(InstallationError::IncompleteObservation(
            "bounded installation effect drive exhausted before all effects were applied"
                .to_owned(),
        ))
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
        staging_receipt: Option<StagingReceipt>,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        let expected = TransactionVersion::of(&transaction)?;
        if let Some(receipt) = credential_receipt {
            transaction.effect_progress[index]
                .store_credential
                .as_mut()
                .ok_or(InstallationError::IdentityConflict)?
                .receipt = Some(receipt);
        }
        if let Some(receipt) = staging_receipt {
            if !matches!(
                transaction.installer_effects[index],
                InstallerEffectPlan::StagePackage { .. }
            ) || disposition != InstallationEffectDisposition::CreatedByTransaction
            {
                return Err(InstallationError::IdentityConflict);
            }
            validate_staging_receipt_for_plan(&transaction.installer_effects[index], &receipt)?;
            transaction.effect_progress[index].staging_receipt = Some(receipt.clone());
        } else if matches!(
            transaction.installer_effects[index],
            InstallerEffectPlan::StagePackage { .. }
        ) {
            return Err(InstallationError::IncompleteObservation(
                "applied package effect requires its typed staging receipt".to_owned(),
            ));
        }
        transaction.effect_progress[index].state = InstallationEffectProgressState::Applied {
            disposition,
            external_identity,
            evidence: evidence.clone(),
            postcondition_digest,
        };
        transaction.observed_postconditions.extend(evidence.clone());
        if matches!(
            transaction.installer_effects[index],
            InstallerEffectPlan::StagePackage { .. }
        ) {
            let receipt = transaction.effect_progress[index]
                .staging_receipt
                .as_ref()
                .ok_or(InstallationError::IdentityConflict)?;
            let receipt_digest = PlatformHandle::new(receipt.digest()).map_err(|error| {
                InstallationError::InvalidField {
                    field: "effect_progress.staging_receipt".to_owned(),
                    reason: error.to_string(),
                }
            })?;
            if transaction.stage != InstallationStage::Staging {
                return Err(InstallationError::IllegalTransition {
                    from: transaction.stage,
                    to: InstallationStage::StaticVerified,
                });
            }
            transaction.advance(InstallationStage::StaticVerified, vec![receipt_digest])?;
        } else {
            increment_revision(&mut transaction)?;
            transaction.validate()?;
        }
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

    /// Drives all immutable effects through the bounded installer-core loop.
    pub fn drive_all_effects_until_blocked(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        self.inner.drive_all_effects_until_blocked(transaction_id)
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
        staging_receipt: progress.staging_receipt.clone(),
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
            host_state_root: transaction
                .candidate_manifest
                .runtime_launch
                .runtime_state_roots
                .host_state_root
                .clone(),
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
    use std::sync::{Arc, Barrier, Mutex};

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
                    &test_commit_fence(&transaction.candidate_manifest),
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

        fn reconcile_active_verified(
            &mut self,
            receipt: ActivationCommitReceipt,
            evidence: Vec<PlatformHandle>,
        ) -> Result<InstallationStepOutcome, InstallationError> {
            let mut state = self.state.lock().unwrap_or_else(|_| unreachable!());
            let transaction =
                state
                    .as_mut()
                    .ok_or_else(|| InstallationError::TransactionNotFound {
                        transaction_id: receipt.transaction_id.as_str().to_owned(),
                    })?;
            transaction.validate()?;
            match transaction.stage() {
                InstallationStage::Activating => {
                    transaction.advance_to_active_verified(receipt, evidence)?;
                    Ok(InstallationStepOutcome::Applied {
                        stage: transaction.stage(),
                        evidence_refs: transaction.observed_postconditions.clone(),
                    })
                }
                InstallationStage::ActiveVerified
                | InstallationStage::Cleaning
                | InstallationStage::Completed => {
                    let binding =
                        transaction
                            .active_verified_receipt
                            .as_ref()
                            .ok_or_else(|| {
                                InstallationError::IncompleteObservation(
                                "active transaction is missing its committed activation receipt"
                                    .to_owned(),
                            )
                            })?;
                    if !binding.matches_receipt(&receipt) {
                        return Err(InstallationError::IdentityConflict);
                    }
                    Ok(InstallationStepOutcome::Applied {
                        stage: transaction.stage(),
                        evidence_refs: transaction.observed_postconditions.clone(),
                    })
                }
                _ => Err(InstallationError::IncompleteObservation(
                    "test transaction is not in an activation-reconcilable stage".to_owned(),
                )),
            }
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
                staging_receipt: None,
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

    fn test_activation_approval(
        manifest: &CandidateManifest,
        transaction_id: PlatformHandle,
        installer_plan_digest: PlatformHandle,
        approval_ref: PlatformHandle,
    ) -> InstallationActivationApproval {
        let runtime = &manifest.runtime_launch;
        InstallationActivationApproval {
            approval_ref,
            transaction_id,
            installer_plan_digest,
            generation: manifest.generation.clone(),
            candidate_manifest_digest: must(candidate_manifest_digest(manifest)),
            runtime_descriptor_digest: runtime.descriptor_digest.clone(),
            required_owner: test_handle("owner:test"),
            signature_ref: manifest.signature_ref.clone(),
            authority_descriptor_path: runtime.authority_descriptor_path.clone(),
            authority_descriptor_digest: runtime.authority_descriptor_digest.clone(),
            authority_generation: runtime.authority_generation,
            authority_state_fence: runtime.authority_state_fence.clone(),
        }
    }

    fn test_transaction_activation_approval(
        transaction: &InstallationTransaction,
        approval_ref: PlatformHandle,
    ) -> InstallationActivationApproval {
        let mut approval = test_activation_approval(
            &transaction.candidate_manifest,
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            approval_ref,
        );
        approval.required_owner = transaction.request.required_owner.clone();
        approval
    }

    fn test_commit_fence(manifest: &CandidateManifest) -> ActivationCommitFence {
        let runtime = &manifest.runtime_launch;
        ActivationCommitFence {
            generation: manifest.generation.clone(),
            config_digest: manifest.config_digest.clone(),
            authority_generation: runtime.authority_generation,
            authority_state_fence: runtime.authority_state_fence.clone(),
            active_kernel_record_checksum: test_handle("a".repeat(64)),
            probe_request_digest: test_handle("b".repeat(64)),
            ready_receipt_digest: test_handle("c".repeat(64)),
            store_proof_fence: test_handle("store-proof:test"),
            candidate_binding_digest: test_handle("d".repeat(64)),
            store_requirement_digest: test_handle("e".repeat(64)),
            readiness_sequence: 1,
            readiness_journal_checksum: test_handle("f".repeat(64)),
        }
    }

    #[cfg(windows)]
    fn replace_real_redb_transaction(
        store: &mut RedbInstallationTransactionStore,
        current: &mut InstallationTransaction,
        mut replacement: InstallationTransaction,
    ) {
        let expected = must(TransactionVersion::of(current));
        replacement.revision = expected.revision + 1;
        must(
            <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
                store,
                expected,
                &replacement,
            ),
        );
        *current = replacement;
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
                    InstallerEffectPlan::StagePackage { staging_root, .. } => staging_root.clone(),
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

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        clippy::needless_continue,
        reason = "the production-bound fixture exercises the complete SystemService projection"
    )]
    fn system_registration_transaction() -> InstallationTransaction {
        let portable = registering_transaction();
        let program_data = must(protected_program_data_root());
        let roots = must(RuntimeStateRoots::derive_profiled(
            InstallationProfile::SystemService,
            test_handle(program_data.to_string_lossy().into_owned()),
            &"b".repeat(64),
        ));
        let system_path =
            |name: &str| test_handle(format!(r"{}\{name}", roots.installation_root.as_str()));

        let mut descriptor = portable.candidate_manifest.runtime_launch.clone();
        descriptor.profile = InstallationProfile::SystemService;
        descriptor.portable_root = None;
        descriptor.runtime_state_roots = roots.clone();
        descriptor.kernel_work_root = roots.kernel_work_root.clone();
        descriptor.authority_descriptor_path = system_path("authority.json");
        descriptor.eliotd_executable_path = system_path("eliotd.exe");
        descriptor.eliotd_config_path = system_path("eliotd-governor.json");
        descriptor.eliotd_descriptor_path = system_path("eliotd.json");
        descriptor.store_config_path = system_path("generation.json");
        descriptor.store_bridge_executable_path = system_path("eliot-store-surreal.exe");
        descriptor.store_bootstrap_descriptor_path = system_path("store-bootstrap.json");
        descriptor.canonical_store_executable_path = system_path("surreal.exe");
        descriptor.host_executable_path = portable.candidate_manifest.host_executable_path.clone();
        descriptor.watchdog_executable_path = portable
            .candidate_manifest
            .runtime_launch
            .watchdog_executable_path
            .clone();
        for image in [
            &descriptor.host_executable_path,
            &descriptor.watchdog_executable_path,
        ] {
            std::fs::write(image.as_str(), b"test service image")
                .unwrap_or_else(|_| panic!("test service image must be materialized"));
        }
        descriptor.kernel_arguments = descriptor
            .expected_kernel_arguments(&descriptor.store_config_path)
            .into_iter()
            .map(test_handle)
            .collect();
        descriptor.store_bridge_arguments = descriptor
            .expected_store_bridge_arguments(&descriptor.store_config_path)
            .into_iter()
            .map(test_handle)
            .collect();
        descriptor.canonical_store_arguments[5] = roots.store_temp_root.clone();
        descriptor.canonical_store_arguments[8] = roots.store_work_root.clone();
        descriptor.canonical_store_arguments[11] = test_handle(format!(
            "surrealkv://{}",
            roots.store_data_root.as_str().replace('\\', "/")
        ));
        descriptor = must(descriptor.with_computed_digest());

        let mut manifest = portable.candidate_manifest.clone();
        manifest.runtime_state_roots_digest = roots.roots_digest.clone();
        manifest.kernel_executable_path = system_path("eliot-kernel.exe");
        manifest.store_bridge_executable_path = descriptor.store_bridge_executable_path.clone();
        manifest.canonical_store_executable_path =
            descriptor.canonical_store_executable_path.clone();
        manifest.host_executable_path = descriptor.host_executable_path.clone();
        manifest.config_path = descriptor.store_config_path.clone();
        manifest.runtime_launch = descriptor;

        let (mut planned_changes, mut installer_effects) = installer_plan_parts(&roots);
        let package_manifest = must(PackageManifest::new("candidate", Vec::new()));
        let package_effect = InstallerEffectPlan::StagePackage {
            effect_id: test_handle("effect:package-stage"),
            source_bundle: system_path("source-bundle"),
            source_bundle_identity: FileIdentity {
                volume_serial_number: 1,
                file_index: 1,
            },
            generation: manifest.generation.clone(),
            manifest: package_manifest,
            staging_root: system_path("staging"),
            expected_file_digests: Vec::new(),
            candidate_manifest_digest: must(candidate_manifest_digest(&manifest)),
        };
        let package_change = PlannedChange {
            change_id: package_effect.effect_id().clone(),
            target: system_path("staging"),
            precondition_refs: vec![test_handle("evidence:installer-precondition")],
            postcondition_refs: vec![test_handle("evidence:installer-postcondition")],
        };
        let package_index = installer_effects
            .iter()
            .position(|effect| matches!(effect, InstallerEffectPlan::RegisterService { .. }))
            .unwrap_or_else(|| unreachable!());
        installer_effects.insert(package_index, package_effect);
        planned_changes.insert(package_index, package_change);
        for effect in &mut installer_effects {
            match effect {
                InstallerEffectPlan::RegisterService {
                    role,
                    executable_path,
                    ..
                } => {
                    *executable_path = match role {
                        InstallerServiceRole::Host => manifest.host_executable_path.clone(),
                        InstallerServiceRole::Watchdog => {
                            manifest.runtime_launch.watchdog_executable_path.clone()
                        }
                    };
                }
                InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => {
                    provision.expected_host_executable = manifest.host_executable_path.clone();
                }
                InstallerEffectPlan::CreateRoot { .. }
                | InstallerEffectPlan::ApplyAcl { .. }
                | InstallerEffectPlan::StagePackage { .. } => {}
            }
        }
        let mut ordered_effects = installer_effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect,
                    InstallerEffectPlan::CreateRoot { .. }
                        | InstallerEffectPlan::ApplyAcl { .. }
                        | InstallerEffectPlan::StagePackage { .. }
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        ordered_effects.extend(
            installer_effects
                .iter()
                .filter(|effect| matches!(effect, InstallerEffectPlan::RegisterService { .. }))
                .cloned(),
        );
        ordered_effects.extend(installer_effects.into_iter().filter(|effect| {
            matches!(effect, InstallerEffectPlan::ProvisionStoreCredential { .. })
        }));

        let mut transaction = must(InstallationTransaction::new(
            portable.transaction_id,
            portable.installation_epoch,
            InstallationProfile::SystemService,
            portable.request,
            portable.current_active_manifest,
            manifest,
            system_path("staging"),
            planned_changes,
            ordered_effects,
            portable.minimum_store_available_bytes,
            portable.precondition_evidence,
            portable.recovery_command,
        ));

        let bootstrap = transaction.candidate_manifest.runtime_launch.clone();
        for (effect, progress) in transaction
            .installer_effects
            .iter()
            .zip(transaction.effect_progress.iter_mut())
        {
            let InstallerEffectPlan::StagePackage {
                manifest,
                staging_root,
                ..
            } = effect
            else {
                if matches!(
                    effect,
                    InstallerEffectPlan::CreateRoot { .. } | InstallerEffectPlan::ApplyAcl { .. }
                ) {
                    progress.state = InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::PreexistingMatching,
                        external_identity: test_handle(format!(
                            "external:root:{}",
                            progress.effect_id.as_str()
                        )),
                        evidence: vec![test_handle(format!(
                            "evidence:root:{}",
                            progress.effect_id.as_str()
                        ))],
                        postcondition_digest: test_handle("d".repeat(64)),
                    };
                }
                continue;
            };
            progress.admitted_precondition =
                Some(must(InstallationEffectPrecondition::from_change(
                    transaction
                        .planned_changes
                        .iter()
                        .find(|change| change.change_id == progress.effect_id)
                        .unwrap_or_else(|| unreachable!()),
                )));
            let receipt = StagingReceipt {
                generation: manifest.generation.clone(),
                root_path: Path::new(staging_root.as_str()).join(&manifest.generation),
                root_identity: FileIdentity {
                    volume_serial_number: 1,
                    file_index: 2,
                },
                directories: Vec::new(),
                files: Vec::new(),
                manifest_sha256: manifest.canonical_digest(),
            };
            progress.staging_receipt = Some(receipt);
            progress.state = InstallationEffectProgressState::Applied {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                external_identity: test_handle("external:package-stage"),
                evidence: vec![test_handle("evidence:package-stage")],
                postcondition_digest: test_handle("e".repeat(64)),
            };
            continue;
        }
        for (effect, progress) in transaction
            .installer_effects
            .iter()
            .zip(transaction.effect_progress.iter_mut())
        {
            let InstallerEffectPlan::RegisterService {
                role,
                service_name,
                executable_path,
                ..
            } = effect
            else {
                continue;
            };
            let nonce = test_handle(match role {
                InstallerServiceRole::Host => "a".repeat(64),
                InstallerServiceRole::Watchdog => "b".repeat(64),
            });
            let arguments = must(
                ServiceBootstrapArguments::new(
                    Path::new(bootstrap.authority_descriptor_path.as_str()).to_path_buf(),
                    bootstrap.authority_descriptor_digest.as_str(),
                    bootstrap.installation_epoch.installation.as_str(),
                    bootstrap.authority_generation.value(),
                    Vec::<String>::new(),
                )
                .and_then(|value| {
                    value.with_host_state_root(Path::new(
                        bootstrap.runtime_state_roots.host_state_root.as_str(),
                    ))
                })
                .and_then(|value| value.with_registration_nonce(nonce.as_str())),
            );
            let request = must(ServiceRegistrationRequest::with_bootstrap(
                service_name.as_str(),
                match role {
                    InstallerServiceRole::Host => ELIOT_HOST_SERVICE_DISPLAY_NAME,
                    InstallerServiceRole::Watchdog => ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
                },
                Path::new(executable_path.as_str()).to_path_buf(),
                ServiceStartMode::Automatic,
                ServiceAccount::LocalService,
                arguments,
            ));
            let configuration_digest = test_handle(request.expected_configuration_digest());
            progress.registration_nonce = Some(nonce);
            progress.state = InstallationEffectProgressState::Applied {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                external_identity: configuration_digest,
                evidence: vec![test_handle(format!("evidence:service:{role:?}"))],
                postcondition_digest: test_handle("c".repeat(64)),
            };
        }
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
        must(transaction.validate());
        transaction
    }

    #[cfg(windows)]
    fn fully_applied_system_registration_transaction() -> InstallationTransaction {
        let mut transaction = system_registration_transaction();
        for index in 0..transaction.installer_effects.len() {
            let effect = transaction.installer_effects[index].clone();
            match effect {
                InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => {
                    let change = transaction
                        .planned_changes
                        .iter()
                        .find(|change| {
                            change.change_id == transaction.effect_progress[index].effect_id
                        })
                        .cloned()
                        .unwrap_or_else(|| unreachable!());
                    let marker = CredentialOwnershipMarkerIdentity {
                        canonical_path_digest: test_handle("a".repeat(64)),
                        volume_serial_number: 1,
                        file_index: 1,
                        security_descriptor_digest: test_handle("b".repeat(64)),
                    };
                    let host_owner_epoch = test_handle("host-owner:system");
                    let host_process_identity = test_handle("c".repeat(64));
                    let request_digest = test_handle("d".repeat(64));
                    let credential_envelope_digest = test_handle("e".repeat(64));
                    let response_digest = must(credential_matching_response_digest(
                        &request_digest,
                        &host_owner_epoch,
                        &host_process_identity,
                        &marker,
                        &credential_envelope_digest,
                    ));
                    let snapshot = StoreCredentialAbsentSnapshot {
                        host_owner_epoch: host_owner_epoch.clone(),
                        host_process_identity: host_process_identity.clone(),
                        host_state_root: marker.clone(),
                        marker_path_digest: test_handle("f".repeat(64)),
                        marker_absent: true,
                        target_absent: true,
                    };
                    let precondition = must(
                        must(InstallationEffectPrecondition::from_change(&change))
                            .with_credential_snapshot(snapshot),
                    );
                    let reference = InstallationSecretReference {
                        target: test_handle(
                            "eliot/installer-root/v1/0123456789abcdef0123456789abcdef",
                        ),
                        expected_principal_sid: test_handle(LOCAL_SERVICE_SID),
                        scope: InstallationSecretScope::WindowsCredentialManagerCurrentUser,
                    };
                    let receipt = CredentialAccessReceipt {
                        transaction_id: transaction.transaction_id.clone(),
                        effect_id: transaction.effect_progress[index].effect_id.clone(),
                        generation: provision.generation,
                        config_digest: provision.config_digest.clone(),
                        target: provision.target.clone(),
                        provider: provision.provider,
                        scope: provision.scope,
                        principal_sid: provision.expected_principal_sid.clone(),
                        host_owner_epoch,
                        host_process_identity,
                        marker,
                        credential_envelope_digest,
                        request_digest,
                        response_digest,
                    };
                    transaction.effect_progress[index].admitted_precondition = Some(precondition);
                    transaction.effect_progress[index].ownership_secret =
                        Some(InstallationOwnershipSecret {
                            reference,
                            create_disposition: InstallationCreateDisposition::Created,
                            lifecycle: InstallationSecretLifecycle::Active,
                        });
                    transaction.effect_progress[index].store_credential =
                        Some(StoreCredentialProgress {
                            lifecycle: StoreCredentialLifecycle::Active,
                            receipt: Some(receipt),
                        });
                    transaction.effect_progress[index].state =
                        InstallationEffectProgressState::Applied {
                            disposition: InstallationEffectDisposition::CreatedByTransaction,
                            external_identity: test_handle("external:credential"),
                            evidence: vec![test_handle("evidence:credential")],
                            postcondition_digest: test_handle("1".repeat(64)),
                        };
                }
                InstallerEffectPlan::CreateRoot { .. } | InstallerEffectPlan::ApplyAcl { .. } => {
                    transaction.effect_progress[index].state =
                        InstallationEffectProgressState::Applied {
                            disposition: InstallationEffectDisposition::PreexistingMatching,
                            external_identity: test_handle(format!("external:root-{index}")),
                            evidence: vec![test_handle(format!("evidence:root-{index}"))],
                            postcondition_digest: test_handle(format!("{index:064x}")),
                        };
                }
                InstallerEffectPlan::RegisterService { .. }
                | InstallerEffectPlan::StagePackage { .. } => {}
            }
        }
        must(transaction.validate());
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
            staging_receipt: None,
        }
    }

    fn matching_for(
        index: usize,
        disposition: InstallationEffectDisposition,
    ) -> InstallationEffectObservation {
        InstallationEffectObservation::Matching {
            disposition,
            external_identity: test_handle(format!("external:matching-{index}")),
            evidence: vec![test_handle(format!("evidence:matching-{index}"))],
            postcondition_digest: test_handle(format!("{index:064x}")),
            credential_receipt: None,
            staging_receipt: None,
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

    #[cfg(windows)]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table-style regression preserves the complete ordered Host and Watchdog SCM argv"
    )]
    fn service_context_binds_same_host_root_for_host_and_watchdog_argv() {
        let root =
            std::env::temp_dir().join(format!("eliot-service-context-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root)
            .unwrap_or_else(|error| panic!("create service root: {error}"));
        for executable_name in ["eliot-host.exe", "eliot-watchdog.exe"] {
            std::fs::write(root.join(executable_name), [])
                .unwrap_or_else(|error| panic!("create service image: {error}"));
        }
        let installation_root = test_handle(root.to_string_lossy().into_owned());
        let precondition = must(InstallationEffectPrecondition::new(
            vec![test_handle("evidence:service-precondition")],
            None,
            None,
        ));
        let make_request = |role, service_name, executable_name| {
            let effect_id = test_handle(format!("effect:service:{executable_name}"));
            let request = InstallationEffectRequest {
                transaction_id: test_handle(format!("transaction:service:{executable_name}")),
                plan: InstallerEffectPlan::RegisterService {
                    effect_id: effect_id.clone(),
                    role,
                    service_name: test_handle(service_name),
                    executable_path: test_handle(
                        root.join(executable_name).to_string_lossy().into_owned(),
                    ),
                    account: InstallerServiceAccount::LocalService,
                    automatic_start: true,
                },
                profile: InstallationProfile::SystemService,
                installation_root: installation_root.clone(),
                effect_id,
                attempt: 1,
                plan_digest: test_handle("a".repeat(64)),
                precondition: precondition.clone(),
                ownership_secret: None,
                store_credential: None,
                staging_receipt: None,
                action: InstallationEffectAction::Apply,
                expected_external_identity: None,
                service_bootstrap: Some(InstallationServiceBootstrap {
                    descriptor_path: test_handle(r"C:\ProgramData\Eliot\authority.json"),
                    descriptor_digest: test_handle("b".repeat(64)),
                    installation_id: test_handle("installation:service"),
                    plan_generation: 7,
                    host_state_root: test_handle(root.join("host").to_string_lossy().into_owned()),
                }),
                registration_nonce: Some(test_handle("c".repeat(64))),
            };
            must(request.validate());
            let (_, registration, _) =
                must(WindowsInstallationEffectPort::service_context(&request));
            registration
                .bootstrap()
                .unwrap_or_else(|| unreachable!())
                .argv()
        };

        let host_argv = make_request(
            InstallerServiceRole::Host,
            ELIOT_HOST_SERVICE_NAME,
            "eliot-host.exe",
        );
        let host_root = root.join("host").to_string_lossy().into_owned();
        assert_eq!(
            host_argv,
            vec![
                "--config-descriptor".to_owned(),
                r"C:\ProgramData\Eliot\authority.json".to_owned(),
                "--config-descriptor-sha256".to_owned(),
                "b".repeat(64),
                "--installation-id".to_owned(),
                "installation:service".to_owned(),
                "--tx-plan-generation".to_owned(),
                "7".to_owned(),
                "--host-state-root".to_owned(),
                host_root,
                "--registration-nonce".to_owned(),
                "c".repeat(64),
            ]
        );

        let watchdog_argv = make_request(
            InstallerServiceRole::Watchdog,
            ELIOT_WATCHDOG_SERVICE_NAME,
            "eliot-watchdog.exe",
        );
        assert_eq!(
            watchdog_argv,
            vec![
                "--config-descriptor".to_owned(),
                r"C:\ProgramData\Eliot\authority.json".to_owned(),
                "--config-descriptor-sha256".to_owned(),
                "b".repeat(64),
                "--installation-id".to_owned(),
                "installation:service".to_owned(),
                "--tx-plan-generation".to_owned(),
                "7".to_owned(),
                "--host-state-root".to_owned(),
                root.join("host").to_string_lossy().into_owned(),
                "--registration-nonce".to_owned(),
                "c".repeat(64),
            ]
        );
        let _ = std::fs::remove_dir_all(root);
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
    fn all_effects_gate_blocks_registry_projection_until_authoritative_readback() {
        let transaction = planned_transaction();
        assert!(matches!(
            transaction.require_all_effects_applied(),
            Err(InstallationError::IncompleteObservation(_))
        ));

        let mut registry = ApprovedGenerationRegistry::new();
        assert!(matches!(
            registry.stage_pending_activation_from_transaction_with_approval(
                &transaction,
                test_activation_approval(
                    &transaction.candidate_manifest,
                    transaction.transaction_id.clone(),
                    transaction.installer_plan_digest.clone(),
                    test_handle("approval:blocked"),
                ),
            ),
            Err(InstallationError::IncompleteObservation(_))
        ));
        assert!(registry.pending_activation().is_none());
    }

    #[cfg(windows)]
    #[test]
    fn activation_approval_rejects_each_transaction_binding_mismatch() {
        let transaction = fully_applied_system_registration_transaction();
        let approval =
            test_transaction_activation_approval(&transaction, test_handle("approval:issued"));
        must(approval.validate_against(&transaction));

        let mut mismatches = Vec::new();
        let mut value = approval.clone();
        value.transaction_id = test_handle("transaction:other");
        mismatches.push(value);
        let mut value = approval.clone();
        value.installer_plan_digest = test_handle("a".repeat(64));
        mismatches.push(value);
        let mut value = approval.clone();
        value.generation = test_handle("generation:other");
        mismatches.push(value);
        let mut value = approval.clone();
        value.candidate_manifest_digest = test_handle("b".repeat(64));
        mismatches.push(value);
        let mut value = approval.clone();
        value.runtime_descriptor_digest = test_handle("c".repeat(64));
        mismatches.push(value);
        let mut value = approval.clone();
        value.required_owner = test_handle("owner:other");
        mismatches.push(value);
        let mut value = approval.clone();
        value.signature_ref = test_handle("signature:other");
        mismatches.push(value);
        let mut value = approval.clone();
        value.authority_descriptor_path = test_handle("authority:other.json");
        mismatches.push(value);
        let mut value = approval.clone();
        value.authority_descriptor_digest = test_handle("d".repeat(64));
        mismatches.push(value);
        let next_generation = must(ResourceGeneration::new(
            approval.authority_generation.value() + 1,
        ));
        let mut value = approval.clone();
        value.authority_generation = next_generation;
        value.authority_state_fence.resource_generation = next_generation;
        mismatches.push(value);
        let mut value = approval.clone();
        value.authority_state_fence.authority_epoch = must(AuthorityEpoch::new(
            approval.authority_state_fence.authority_epoch.value() + 1,
        ));
        mismatches.push(value);

        assert_eq!(mismatches.len(), 11);
        for mismatch in mismatches {
            assert!(matches!(
                mismatch.validate_against(&transaction),
                Err(InstallationError::IdentityConflict)
            ));
        }

        // `approval_ref` is evidence identity, not a transaction-derived
        // field.  Its authority provenance is sealed by the issuing lane;
        // changing it alone is not a transaction binding mismatch.
        let mut different_evidence = approval;
        different_evidence.approval_ref = test_handle("approval:other");
        must(different_evidence.validate_against(&transaction));
    }

    #[cfg(windows)]
    #[test]
    fn activation_approval_rejects_partial_effects_before_binding_checks() {
        let transaction = planned_transaction();
        let approval = test_activation_approval(
            &transaction.candidate_manifest,
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            test_handle("approval:partial"),
        );
        assert!(matches!(
            approval.validate_against(&transaction),
            Err(InstallationError::IncompleteObservation(_))
        ));
    }

    #[test]
    fn bounded_effect_driver_stops_on_rejected_without_retry() {
        let transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));
        let execute_count = Arc::new(Mutex::new(0));
        let port = fake_port(
            store.clone(),
            vec![PortOutcome::Known(absent(&transaction))],
            vec![PortOutcome::Known(absent(&transaction))],
            execute_count.clone(),
        );
        let mut coordinator = InstallationCoordinator::new(port, store.clone());

        assert_eq!(
            must(coordinator.drive_all_effects_until_blocked(&transaction_id)),
            InstallationStepOutcome::Rejected
        );
        assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
        let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert!(matches!(
            saved.effect_progress[0].state,
            InstallationEffectProgressState::IntentCommitted { .. }
        ));
    }

    #[test]
    fn bounded_effect_driver_completes_all_effects_and_rechecks_authority() {
        let transaction = planned_transaction();
        let transaction_id = transaction.transaction_id.clone();
        let mut store = SharedStore::default();
        must(store.create_planned(&transaction));
        let effect_count = transaction.effect_progress.len();
        let execute_count = Arc::new(Mutex::new(0));
        let port = fake_port(
            store.clone(),
            (0..effect_count)
                .map(|index| {
                    PortOutcome::Known(matching_for(
                        index,
                        InstallationEffectDisposition::PreexistingMatching,
                    ))
                })
                .collect(),
            Vec::new(),
            execute_count.clone(),
        );
        let mut coordinator = InstallationCoordinator::new(port, store.clone());

        assert!(matches!(
            must(coordinator.drive_all_effects_until_blocked(&transaction_id)),
            InstallationStepOutcome::Applied { .. }
        ));
        assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
        let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
        assert!(saved.require_all_effects_applied().is_ok());
    }

    #[test]
    fn bounded_effect_driver_propagates_cas_conflict_without_external_retry() {
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

        let result = coordinator.drive_all_effects_until_blocked(&transaction_id);
        assert!(matches!(
            result,
            Err(InstallationError::CompareAndSaveConflict { .. })
        ));
        assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
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
    fn create_planned_at_exact_path_rejects_advanced_state_before_file_creation() {
        let path = std::env::temp_dir().join(format!(
            "eliot-installation-create-planned-{}.redb",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut transaction = planned_transaction();
        transaction.stage = InstallationStage::Staging;
        transaction.completed_stage_refs = vec![test_handle("evidence:advanced")];
        transaction.revision = 2;

        assert!(
            RedbInstallationTransactionStore::create_planned_at_exact_path(&path, &transaction,)
                .is_err()
        );
        assert!(!path.exists());
    }

    #[test]
    fn create_planned_at_exact_path_publishes_populated_store_without_overwrite() {
        let path = std::env::temp_dir().join(format!(
            "eliot-installation-create-planned-publish-{}.redb",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let transaction = planned_transaction();
        let store = must(
            RedbInstallationTransactionStore::create_planned_at_exact_path(&path, &transaction),
        );
        assert_eq!(
            must(store.load(&transaction.transaction_id))
                .unwrap_or_else(|| unreachable!())
                .revision(),
            transaction.revision()
        );
        drop(store);
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_else(|| unreachable!());
        let temporary_prefix = format!(".{file_name}.eliot-transaction-");
        let temporary_files = std::fs::read_dir(path.parent().unwrap_or_else(|| unreachable!()))
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(&temporary_prefix))
            })
            .collect::<Vec<_>>();
        assert!(temporary_files.is_empty(), "temporary publication leaked");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn create_planned_at_exact_path_never_overwrites_publish_conflict() {
        let path = std::env::temp_dir().join(format!(
            "eliot-installation-create-planned-conflict-{}.redb",
            std::process::id()
        ));
        let original = b"caller-owned-not-a-transaction-store";
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, original).unwrap_or_else(|error| panic!("write conflict: {error}"));
        let transaction = planned_transaction();
        assert!(
            RedbInstallationTransactionStore::create_planned_at_exact_path(&path, &transaction)
                .is_err()
        );
        assert_eq!(
            std::fs::read(&path).unwrap_or_else(|error| panic!("read conflict: {error}")),
            original
        );
        let _ = std::fs::remove_file(&path);
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
    fn v8_transaction_json_requires_explicit_migration_to_v9() {
        let mut legacy = must(serde_json::to_value(planned_transaction()));
        let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
        object.insert(
            "transaction_wire_version".to_owned(),
            must(serde_json::to_value(ContractVersion::new(8, 0, 0))),
        );
        let bytes = must(serde_json::to_vec(&legacy));
        let Err(error) = decode_installation_transaction_json(&bytes) else {
            panic!("v8 transaction must require migration");
        };
        assert!(matches!(
            error,
            InstallationError::MigrationRequired { reason }
                if reason.contains("requires explicit migration to 9.0.0")
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
    fn malformed_v9_transaction_json_is_corrupt_registry() {
        let bytes = br#"{"transaction_wire_version":{"major":9,"minor":0,"patch":0},"transaction_id":"malformed"}"#;
        assert!(matches!(
            decode_installation_transaction_json(bytes),
            Err(InstallationError::CorruptRegistry { .. })
        ));
    }

    #[test]
    fn untrusted_json_cannot_import_active_verified_receipt_state() {
        let transaction = registering_transaction();
        let mut value = must(serde_json::to_value(&transaction));
        let object = value.as_object_mut().unwrap_or_else(|| unreachable!());
        object.insert(
            "stage".to_owned(),
            serde_json::to_value(InstallationStage::ActiveVerified)
                .unwrap_or_else(|_| unreachable!()),
        );
        object.insert(
            "observed_postconditions".to_owned(),
            serde_json::json!(["evidence:forged-active"]),
        );
        object.insert(
            "active_verified_receipt".to_owned(),
            serde_json::json!({
                "transaction_id": transaction.transaction_id.clone(),
                "plan_digest": transaction.installer_plan_digest.clone(),
                "generation": transaction.candidate_manifest.generation.clone(),
                "candidate_manifest_digest": must(candidate_manifest_digest(&transaction.candidate_manifest)),
                "commit_fence": test_commit_fence(&transaction.candidate_manifest),
                "registry_revision": 3,
                "terminal_digest": "a".repeat(64),
            }),
        );
        let bytes = must(serde_json::to_vec(&value));
        assert!(matches!(
            decode_installation_transaction_json(&bytes),
            Err(InstallationError::MigrationRequired { reason })
                if reason.contains("ACL-protected store replay")
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

    #[cfg(windows)]
    #[test]
    fn service_registration_projection_is_durable_and_exact() {
        let transaction = fully_applied_system_registration_transaction();
        let approvals = must(transaction.service_registration_approvals());
        assert_eq!(approvals.len(), 2);
        assert_eq!(approvals[0].role, InstallerServiceRole::Host);
        assert_eq!(approvals[1].role, InstallerServiceRole::Watchdog);
        assert_ne!(
            approvals[0].registration_nonce,
            approvals[1].registration_nonce
        );
        assert_ne!(
            approvals[0].configuration_digest,
            approvals[1].configuration_digest
        );

        let transaction_store = SharedStore::default();
        *transaction_store
            .state
            .lock()
            .unwrap_or_else(|_| unreachable!()) = Some(transaction.clone());
        let path = std::env::temp_dir().join(format!(
            "eliot-installation-scm-projection-{}-{}.redb",
            std::process::id(),
            NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let database = must(Database::create(&path));
        let registry = RedbInstallationRegistry::from_database_for_test(database);
        let approval_ref = test_handle("approval:system-service");
        let approval = test_transaction_activation_approval(&transaction, approval_ref);
        must(registry.stage_pending_activation_from_transaction_store(
            &transaction_store,
            &transaction.transaction_id,
            approval.clone(),
            must(registry.load()).revision(),
        ));

        let loaded = must(registry.load());
        assert_eq!(
            loaded.revision(),
            2,
            "first durable stage advances CAS revision"
        );
        let pending = loaded
            .pending_activation()
            .unwrap_or_else(|| unreachable!());
        assert_eq!(pending.transaction_id, transaction.transaction_id);
        assert_eq!(pending.plan_digest, transaction.installer_plan_digest);
        assert_eq!(pending.approval, approval);
        for role in [InstallerServiceRole::Host, InstallerServiceRole::Watchdog] {
            let approval = loaded
                .service_registration_approval(&transaction.candidate_manifest.generation, role)
                .unwrap_or_else(|| unreachable!());
            let request = must(approval.service_registration_request());
            assert_eq!(
                approval.configuration_digest.as_str(),
                request.expected_configuration_digest()
            );
        }

        let before_retry = loaded.clone();
        must(registry.stage_pending_activation_from_transaction_store(
            &transaction_store,
            &transaction.transaction_id,
            approval.clone(),
            before_retry.revision(),
        ));
        assert_eq!(must(registry.load()), before_retry);

        assert!(matches!(
            registry.stage_pending_activation_from_transaction_store(
                &transaction_store,
                &transaction.transaction_id,
                approval.clone(),
                1,
            ),
            Err(InstallationError::CompareAndSaveConflict {
                expected: 1,
                actual: 2,
            })
        ));
        assert_eq!(must(registry.load()), before_retry);

        assert!(matches!(
            registry.stage_pending_activation_from_transaction_store(
                &transaction_store,
                &transaction.transaction_id,
                {
                    let mut substituted = approval.clone();
                    substituted.approval_ref = test_handle("approval:substituted");
                    substituted
                },
                before_retry.revision(),
            ),
            Err(InstallationError::IdentityConflict)
        ));
        assert_eq!(must(registry.load()), before_retry);
        drop(registry);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(windows)]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "this test exercises the complete real redb crash/retry boundary"
    )]
    fn committed_registry_terminal_reconciles_real_redb_transaction_once() {
        let full = fully_applied_system_registration_transaction();
        let planned = must(InstallationTransaction::new(
            full.transaction_id.clone(),
            full.installation_epoch.clone(),
            full.profile,
            full.request.clone(),
            full.current_active_manifest.clone(),
            full.candidate_manifest.clone(),
            full.staging_root.clone(),
            full.planned_changes.clone(),
            full.installer_effects.clone(),
            full.minimum_store_available_bytes,
            full.precondition_evidence.clone(),
            full.recovery_command.clone(),
        ));
        let mut activating = planned.clone();
        activating.effect_progress = full.effect_progress.clone();
        for (stage, evidence) in [
            (InstallationStage::Staging, "evidence:receipt-staging"),
            (InstallationStage::StaticVerified, "evidence:receipt-static"),
            (
                InstallationStage::Registering,
                "evidence:receipt-registering",
            ),
            (InstallationStage::Activating, "evidence:receipt-activating"),
        ] {
            must(activating.advance(stage, vec![test_handle(evidence)]));
        }
        let transaction_path = std::env::temp_dir().join(format!(
            "eliot-active-verified-receipt-transaction-{}-{}.redb",
            std::process::id(),
            NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&transaction_path);
        let mut transaction_store = must(
            RedbInstallationTransactionStore::create_planned_at_exact_path(
                &transaction_path,
                &planned,
            ),
        );
        let mut current = planned.clone();
        for stage in [
            InstallationStage::Staging,
            InstallationStage::StaticVerified,
            InstallationStage::Registering,
            InstallationStage::Activating,
        ] {
            let expected = must(TransactionVersion::of(&current));
            current = activating.clone();
            current.stage = stage;
            current.revision = expected.revision + 1;
            // Rebuild the durable state one exact CAS step at a time. The
            // in-memory fixture above supplies only authoritative effect
            // progress; redb remains the source under test.
            must(<RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
                &mut transaction_store,
                expected,
                &current,
            ));
            activating = current.clone();
        }
        let transaction = must(
            transaction_store
                .load(&current.transaction_id)
                .map(|value| value.unwrap_or_else(|| unreachable!())),
        );
        assert_eq!(transaction.stage(), InstallationStage::Activating);

        let registry_path = std::env::temp_dir().join(format!(
            "eliot-active-verified-receipt-registry-{}-{}.redb",
            std::process::id(),
            NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&registry_path);
        let registry = RedbInstallationRegistry::from_database_for_test(must(Database::create(
            &registry_path,
        )));
        let approval = test_transaction_activation_approval(
            &transaction,
            test_handle("approval:active-verified-receipt"),
        );
        must(registry.stage_pending_activation_from_transaction_store(
            &transaction_store,
            &transaction.transaction_id,
            approval.clone(),
            must(registry.load()).revision(),
        ));
        let (_owner_lease, host) = live_host_capability();
        let fence = test_commit_fence(&transaction.candidate_manifest);
        must(registry.commit_pending_activation(
            &host,
            must(registry.load()).revision(),
            &approval,
            &fence,
        ));
        let receipt = must(registry.read_committed_activation_receipt(
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
            &transaction.candidate_manifest.generation,
        ));
        let outcome = must(transaction_store.reconcile_active_verified(
            receipt.clone(),
            vec![test_handle("evidence:receipt-ready")],
        ));
        assert!(matches!(
            outcome,
            InstallationStepOutcome::Applied {
                stage: InstallationStage::ActiveVerified,
                ..
            }
        ));
        let committed = must(
            transaction_store
                .load(&transaction.transaction_id)
                .map(|value| value.unwrap_or_else(|| unreachable!())),
        );
        let committed_revision = committed.revision();
        assert_eq!(committed.stage(), InstallationStage::ActiveVerified);

        let retry = must(transaction_store.reconcile_active_verified(
            receipt.clone(),
            vec![test_handle("evidence:retry-is-ignored")],
        ));
        assert!(matches!(
            retry,
            InstallationStepOutcome::Applied {
                stage: InstallationStage::ActiveVerified,
                ..
            }
        ));
        assert_eq!(
            must(
                transaction_store
                    .load(&transaction.transaction_id)
                    .map(|value| value.unwrap_or_else(|| unreachable!())),
            )
            .revision(),
            committed_revision,
            "an exact retry must not advance the transaction revision"
        );

        let mut stale_epoch = receipt.clone();
        stale_epoch
            .commit_fence
            .authority_state_fence
            .authority_epoch = must(AuthorityEpoch::new(
            stale_epoch
                .commit_fence
                .authority_state_fence
                .authority_epoch
                .value()
                .checked_add(1)
                .unwrap_or_else(|| unreachable!()),
        ));
        assert!(matches!(
            transaction_store
                .reconcile_active_verified(stale_epoch, vec![test_handle("evidence:stale-epoch")],),
            Err(InstallationError::IdentityConflict)
        ));

        let mut different_fence = receipt.clone();
        different_fence.commit_fence.readiness_sequence += 1;
        assert!(matches!(
            transaction_store.reconcile_active_verified(
                different_fence,
                vec![test_handle("evidence:different-fence")],
            ),
            Err(InstallationError::IdentityConflict)
        ));

        let mut current = committed;
        let mut pending = planned.clone();
        replace_real_redb_transaction(&mut transaction_store, &mut current, pending);
        assert!(matches!(
            transaction_store.reconcile_active_verified(
                receipt.clone(),
                vec![test_handle("evidence:pending-stage")],
            ),
            Err(InstallationError::IncompleteObservation(reason))
                if reason.contains("before Activating")
        ));

        pending = planned.clone();
        pending.stage = InstallationStage::RollbackRequired;
        pending.pending_external_changes = vec![test_handle("pending:unknown")];
        replace_real_redb_transaction(&mut transaction_store, &mut current, pending);
        assert!(matches!(
            transaction_store.reconcile_active_verified(
                receipt.clone(),
                vec![test_handle("evidence:unknown-stage")],
            ),
            Err(InstallationError::IncompleteObservation(reason))
                if reason.contains("pending, aborted, or unknown")
        ));

        pending = planned.clone();
        pending.stage = InstallationStage::RolledBack;
        pending.completed_stage_refs = vec![test_handle("evidence:aborted")];
        replace_real_redb_transaction(&mut transaction_store, &mut current, pending);
        assert!(matches!(
            transaction_store.reconcile_active_verified(
                receipt.clone(),
                vec![test_handle("evidence:aborted-stage")],
            ),
            Err(InstallationError::IncompleteObservation(reason))
                if reason.contains("pending, aborted, or unknown")
        ));

        pending = planned;
        pending.stage = InstallationStage::Quarantined;
        pending.completed_stage_refs = vec![test_handle("evidence:quarantined")];
        replace_real_redb_transaction(&mut transaction_store, &mut current, pending);
        assert!(matches!(
            transaction_store.reconcile_active_verified(
                receipt,
                vec![test_handle("evidence:quarantined-stage")],
            ),
            Err(InstallationError::IncompleteObservation(reason))
                if reason.contains("pending, aborted, or unknown")
        ));
        let _ = std::fs::remove_file(transaction_path);
        let _ = std::fs::remove_file(registry_path);
    }

    #[cfg(windows)]
    #[test]
    fn concurrent_registry_stages_have_one_revision_winner() {
        let transaction = fully_applied_system_registration_transaction();
        let transaction_store = SharedStore::default();
        *transaction_store
            .state
            .lock()
            .unwrap_or_else(|_| unreachable!()) = Some(transaction.clone());
        let approval =
            test_transaction_activation_approval(&transaction, test_handle("approval:concurrent"));
        let path = std::env::temp_dir().join(format!(
            "eliot-installation-concurrent-stage-{}-{}.redb",
            std::process::id(),
            NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let first = Arc::new(RedbInstallationRegistry::from_database_for_test(must(
            Database::create(&path),
        )));
        let second = first.clone();
        let barrier = Arc::new(Barrier::new(2));
        let first_store = transaction_store.clone();
        let first_barrier = barrier.clone();
        let first_approval = approval.clone();
        let first_transaction_id = transaction.transaction_id.clone();
        let first_registry = first.clone();
        let first_thread = std::thread::spawn(move || {
            first_barrier.wait();
            first_registry.stage_pending_activation_from_transaction_store(
                &first_store,
                &first_transaction_id,
                first_approval,
                1,
            )
        });
        let second_store = transaction_store;
        let second_barrier = barrier;
        let second_transaction_id = transaction.transaction_id.clone();
        let second_registry = second.clone();
        let second_thread = std::thread::spawn(move || {
            second_barrier.wait();
            second_registry.stage_pending_activation_from_transaction_store(
                &second_store,
                &second_transaction_id,
                approval,
                1,
            )
        });
        let first_result = first_thread.join().unwrap_or_else(|_| unreachable!());
        let second_result = second_thread.join().unwrap_or_else(|_| unreachable!());
        let results = [first_result, second_result];
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "exactly one concurrent stage may commit revision 1"
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(InstallationError::CompareAndSaveConflict { .. })
                ))
                .count(),
            1,
            "the losing stage must report a stale revision"
        );
        assert_eq!(must(first.load()).revision(), 2);
        drop(first);
        drop(second);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(windows)]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one test covers each fail-closed service observation class"
    )]
    fn service_registration_projection_rejects_incomplete_or_reused_observations() {
        let mut missing_nonce = system_registration_transaction();
        let host_progress = missing_nonce
            .effect_progress
            .iter_mut()
            .find(|progress| {
                missing_nonce
                    .installer_effects
                    .iter()
                    .find(|effect| effect.effect_id() == &progress.effect_id)
                    .is_some_and(|effect| {
                        matches!(
                            effect,
                            InstallerEffectPlan::RegisterService {
                                role: InstallerServiceRole::Host,
                                ..
                            }
                        )
                    })
            })
            .unwrap_or_else(|| unreachable!());
        host_progress.registration_nonce = None;
        assert!(matches!(
            missing_nonce.service_registration_approvals(),
            Err(InstallationError::InvalidField { field, .. })
                if field == "effect_progress.registration_nonce"
        ));

        let mut pending = system_registration_transaction();
        for (effect, progress) in pending
            .installer_effects
            .iter()
            .zip(pending.effect_progress.iter_mut())
        {
            if matches!(effect, InstallerEffectPlan::RegisterService { .. }) {
                progress.registration_nonce = Some(test_handle("d".repeat(64)));
                progress.state = InstallationEffectProgressState::Pending;
            }
        }
        assert!(matches!(
            pending.service_registration_approvals(),
            Err(InstallationError::IncompleteObservation(reason))
                if reason.contains("pending authoritative readback")
        ));

        let mut unknown = system_registration_transaction();
        for (effect, progress) in unknown
            .installer_effects
            .iter()
            .zip(unknown.effect_progress.iter_mut())
        {
            if let InstallerEffectPlan::RegisterService { role, .. } = effect {
                progress.registration_nonce = Some(test_handle("e".repeat(64)));
                progress.state = if *role == InstallerServiceRole::Host {
                    InstallationEffectProgressState::Unknown {
                        pending_ref: test_handle("reconcile:service"),
                    }
                } else {
                    InstallationEffectProgressState::Pending
                };
            }
        }
        assert!(matches!(
            unknown.service_registration_approvals(),
            Err(InstallationError::IncompleteObservation(reason))
                if reason.contains("requires reconciliation")
        ));

        let mut duplicate_nonce = system_registration_transaction();
        let host_nonce = duplicate_nonce
            .effect_progress
            .iter()
            .find_map(|progress| {
                duplicate_nonce
                    .installer_effects
                    .iter()
                    .find(|effect| effect.effect_id() == &progress.effect_id)
                    .is_some_and(|effect| {
                        matches!(
                            effect,
                            InstallerEffectPlan::RegisterService {
                                role: InstallerServiceRole::Host,
                                ..
                            }
                        )
                    })
                    .then(|| progress.registration_nonce.clone())
                    .flatten()
            })
            .unwrap_or_else(|| unreachable!());
        let watchdog_progress = duplicate_nonce
            .effect_progress
            .iter_mut()
            .find(|progress| {
                duplicate_nonce
                    .installer_effects
                    .iter()
                    .find(|effect| effect.effect_id() == &progress.effect_id)
                    .is_some_and(|effect| {
                        matches!(
                            effect,
                            InstallerEffectPlan::RegisterService {
                                role: InstallerServiceRole::Watchdog,
                                ..
                            }
                        )
                    })
            })
            .unwrap_or_else(|| unreachable!());
        watchdog_progress.registration_nonce = Some(host_nonce);
        assert!(matches!(
            duplicate_nonce.service_registration_approvals(),
            Err(InstallationError::IdentityConflict)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn system_service_registry_wire_rejects_zero_and_partial_approval_pairs() {
        let transaction = system_registration_transaction();
        let approvals = must(transaction.service_registration_approvals());
        for service_registration_approvals in [Vec::new(), vec![approvals[0].clone()]] {
            let registry = ApprovedGenerationRegistry {
                generations: vec![ApprovedGeneration {
                    manifest: transaction.candidate_manifest.clone(),
                    approval: test_activation_approval(
                        &transaction.candidate_manifest,
                        transaction.transaction_id.clone(),
                        transaction.installer_plan_digest.clone(),
                        test_handle("approval:wire"),
                    ),
                    active: false,
                    last_known_good: false,
                }],
                service_registration_approvals,
                active_generation: None,
                last_known_good_generation: None,
                pending_activation: None,
                last_terminal_activation: None,
                ..ApprovedGenerationRegistry::new()
            };
            let bytes = must(serde_json::to_vec(&registry));
            assert!(matches!(
                decode_registry_bytes(&bytes),
                Err(InstallationError::CorruptRegistry { .. })
            ));
        }
    }

    #[test]
    fn legacy_registry_table_requires_explicit_migration() {
        let path = std::env::temp_dir().join(format!(
            "eliot-installation-legacy-table-{}-{}.redb",
            std::process::id(),
            NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let database = must(Database::create(&path));
        let write = must(database.begin_write());
        {
            let mut table = must(write.open_table(LEGACY_REGISTRY_TABLE));
            must(table.insert("registry", b"legacy".as_slice()));
        }
        must(write.commit());
        assert!(matches!(
            classify_registry_table(&database),
            Err(InstallationError::MigrationRequired { .. })
        ));
        drop(database);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn v2_registry_wire_requires_explicit_restage_without_defaults() {
        let mut legacy = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
        let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
        object.remove("registry_wire_version");
        object.remove("revision");
        let bytes = must(serde_json::to_vec(&legacy));
        assert!(matches!(
            decode_registry_bytes(&bytes),
            Err(InstallationError::MigrationRequired { reason })
                if reason.contains("pending activation")
                    || reason.contains("v2/pre-CAS")
        ));
    }

    #[test]
    fn v4_registry_wire_rejects_omitted_optional_members() {
        let mut current = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
        current
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .remove("pending_activation");
        let bytes = must(serde_json::to_vec(&current));
        assert!(matches!(
            decode_registry_bytes(&bytes),
            Err(InstallationError::CorruptRegistry { reason })
                if reason.contains("missing mandatory fields")
        ));
    }

    #[test]
    fn v3_registry_terminal_without_readiness_fence_requires_explicit_restage() {
        let transaction = registering_transaction();
        let host = host_capability();
        let mut registry = ApprovedGenerationRegistry::new();
        must(registry.stage_pending_activation(
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            transaction.candidate_manifest.clone(),
            test_handle("approval:wire-fence"),
        ));
        must(registry.commit_pending_activation(
            &host,
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
            &transaction.candidate_manifest.generation,
            &test_commit_fence(&transaction.candidate_manifest),
        ));
        let mut value = must(serde_json::to_value(registry));
        value["last_terminal_activation"]
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .remove("commit_fence");
        let current_bytes = must(serde_json::to_vec(&value));
        assert!(matches!(
            decode_registry_bytes(&current_bytes),
            Err(InstallationError::CorruptRegistry { .. })
        ));
        value["registry_wire_version"]["major"] = serde_json::json!(3);
        let bytes = must(serde_json::to_vec(&value));
        assert!(matches!(
            decode_registry_bytes(&bytes),
            Err(InstallationError::MigrationRequired { .. })
        ));
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
        let approval = test_activation_approval(
            &transaction.candidate_manifest,
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            test_handle("approval:legacy"),
        );
        let registry = ApprovedGenerationRegistry {
            generations: vec![ApprovedGeneration {
                manifest: transaction.candidate_manifest,
                approval,
                active: true,
                last_known_good: false,
            }],
            service_registration_approvals: Vec::new(),
            active_generation: Some(generation),
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
            ..ApprovedGenerationRegistry::new()
        };
        let mut legacy = must(serde_json::to_value(registry));
        let Some(object) = legacy.as_object_mut() else {
            panic!("legacy registry object");
        };
        object.remove("registry_wire_version");
        object.remove("revision");
        object.remove("service_registration_approvals");
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
        let approval = test_activation_approval(
            &transaction.candidate_manifest,
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            test_handle("approval:pre-split"),
        );
        let registry = ApprovedGenerationRegistry {
            generations: vec![ApprovedGeneration {
                manifest: transaction.candidate_manifest,
                approval,
                active: true,
                last_known_good: false,
            }],
            service_registration_approvals: Vec::new(),
            active_generation: Some(generation),
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
            ..ApprovedGenerationRegistry::new()
        };
        let mut value = must(serde_json::to_value(registry));
        let Some(object) = value.as_object_mut() else {
            panic!("pre-split registry object");
        };
        object.remove("registry_wire_version");
        object.remove("revision");
        object.remove("service_registration_approvals");
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
        let approval = test_activation_approval(
            &transaction.candidate_manifest,
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            test_handle("approval:pre-credential-binding"),
        );
        let registry = ApprovedGenerationRegistry {
            generations: vec![ApprovedGeneration {
                manifest: transaction.candidate_manifest,
                approval,
                active: true,
                last_known_good: false,
            }],
            service_registration_approvals: Vec::new(),
            active_generation: Some(generation),
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
            ..ApprovedGenerationRegistry::new()
        };
        let mut value = must(serde_json::to_value(registry));
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("pre-credential-binding registry object"))
            .remove("registry_wire_version");
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("pre-credential-binding registry object"))
            .remove("revision");
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("pre-credential-binding registry object"))
            .remove("service_registration_approvals");
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
        let approval = test_activation_approval(
            &transaction.candidate_manifest,
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            test_handle("approval:pre-eliotd-config"),
        );
        let registry = ApprovedGenerationRegistry {
            generations: vec![ApprovedGeneration {
                manifest: transaction.candidate_manifest,
                approval,
                active: true,
                last_known_good: false,
            }],
            service_registration_approvals: Vec::new(),
            active_generation: Some(generation),
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
            ..ApprovedGenerationRegistry::new()
        };
        let mut value = must(serde_json::to_value(registry));
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("pre-eliotd-config registry object"))
            .remove("registry_wire_version");
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("pre-eliotd-config registry object"))
            .remove("revision");
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("pre-eliotd-config registry object"))
            .remove("service_registration_approvals");
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
        let approval = test_activation_approval(
            &transaction.candidate_manifest,
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            test_handle("approval:pre-host-artifact-binding"),
        );
        let registry = ApprovedGenerationRegistry {
            generations: vec![ApprovedGeneration {
                manifest: transaction.candidate_manifest,
                approval,
                active: true,
                last_known_good: false,
            }],
            service_registration_approvals: Vec::new(),
            active_generation: Some(generation),
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
            ..ApprovedGenerationRegistry::new()
        };
        let mut value = must(serde_json::to_value(registry));
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("pre-host-artifact-binding registry object"))
            .remove("registry_wire_version");
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("pre-host-artifact-binding registry object"))
            .remove("revision");
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("pre-host-artifact-binding registry object"))
            .remove("service_registration_approvals");
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
    fn pre_service_registration_approval_registry_requires_explicit_restage() {
        let transaction = registering_transaction();
        let mut registry = ApprovedGenerationRegistry::new();
        must(registry.stage_pending_activation(
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            transaction.candidate_manifest,
            test_handle("approval:pre-service-registration"),
        ));
        let mut value = must(serde_json::to_value(registry));
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("pre-service-registration registry object"))
            .remove("registry_wire_version");
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("pre-service-registration registry object"))
            .remove("revision");
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("pre-service-registration registry object"))
            .remove("service_registration_approvals");
        let bytes = must(serde_json::to_vec(&value));
        let Err(error) = decode_registry_bytes(&bytes) else {
            panic!("pre-service-registration registry must require migration");
        };
        assert!(matches!(
            error,
            InstallationError::MigrationRequired { reason }
                if reason.contains("installer-owned SCM registration approvals")
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
                &test_commit_fence(&transaction.candidate_manifest),
            ),
            Err(InstallationError::IdentityConflict)
        ));
        must(registry.commit_pending_activation(
            &host,
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
            &transaction.candidate_manifest.generation,
            &test_commit_fence(&transaction.candidate_manifest),
        ));
        assert!(registry.pending_activation().is_none());
        assert_eq!(
            registry.active_generation(),
            Some(&transaction.candidate_manifest.generation)
        );
        assert!(registry.last_known_good_generation().is_none());
        let bytes = must(serde_json::to_vec(&registry));
        let mut reloaded = must(decode_registry_bytes(&bytes));
        let mut substituted_fence = test_commit_fence(&transaction.candidate_manifest);
        substituted_fence.candidate_binding_digest = test_handle("1".repeat(64));
        assert!(matches!(
            reloaded.commit_pending_activation(
                &host,
                &transaction.transaction_id,
                &transaction.installer_plan_digest,
                &transaction.candidate_manifest.generation,
                &substituted_fence,
            ),
            Err(InstallationError::IdentityConflict)
        ));
        must(reloaded.commit_pending_activation(
            &host,
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
            &transaction.candidate_manifest.generation,
            &test_commit_fence(&transaction.candidate_manifest),
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
            &test_commit_fence(&first.candidate_manifest),
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
            transaction.candidate_manifest.clone(),
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
        let mut malformed = must(serde_json::to_value(&registry));
        malformed["last_terminal_activation"]["commit_fence"] = must(serde_json::to_value(
            test_commit_fence(&transaction.candidate_manifest),
        ));
        let malformed_bytes = must(serde_json::to_vec(&malformed));
        assert!(matches!(
            decode_registry_bytes(&malformed_bytes),
            Err(InstallationError::CorruptRegistry { .. })
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
    fn installation_registry_host_root_shape_is_exact_and_non_reparse_lexical() {
        let key = "a".repeat(64);
        let accepted = PathBuf::from(format!(r"C:\ProgramData\Eliot\installations\{key}\host"));
        assert!(validate_installation_host_root(&accepted).is_ok());

        for rejected in [
            PathBuf::from(r"C:\ProgramData\Eliot\host"),
            PathBuf::from(r"C:\ProgramData\Eliot\installations\not-a-key\host"),
            PathBuf::from(format!(r"C:\ProgramData\Eliot\installations\{key}\wrong")),
            PathBuf::from(format!(
                r"C:\ProgramData\Eliot\installations\{key}\host\..\host"
            )),
            PathBuf::from(format!(
                r"\\?\C:\ProgramData\Eliot\installations\{key}\host"
            )),
        ] {
            assert!(
                validate_installation_host_root(&rejected).is_err(),
                "accepted wrong/reparse-shaped host root {}",
                rejected.display()
            );
        }
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

        let current_transaction = registering_transaction();
        let mut current = must(serde_json::to_value(ApprovedGenerationRegistry {
            generations: vec![ApprovedGeneration {
                manifest: current_transaction.candidate_manifest.clone(),
                approval: test_activation_approval(
                    &current_transaction.candidate_manifest,
                    current_transaction.transaction_id.clone(),
                    current_transaction.installer_plan_digest.clone(),
                    test_handle("approval:current"),
                ),
                active: true,
                last_known_good: false,
            }],
            service_registration_approvals: Vec::new(),
            active_generation: Some(test_handle("generation:missing")),
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
            ..ApprovedGenerationRegistry::new()
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
