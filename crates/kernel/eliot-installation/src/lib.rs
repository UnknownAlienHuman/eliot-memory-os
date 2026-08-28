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
use std::time::{SystemTime, UNIX_EPOCH};

pub use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
use eliot_contracts::{
    ContractIdentity, ContractVersion, canonical_json_bytes,
    contract_identity as make_contract_identity, sha256_hex,
};
use eliot_ipc::{NamedPipeTransport, TransportLimits};
pub use eliot_platform::{HostProcessNonce, PlatformHandle};
use eliot_platform::{
    InstallationObservation, InstallationPort, InstallationRequest, PortError, PortOutcome,
    ProviderError, ProviderErrorCode, UnknownReason,
};
pub use eliot_platform_windows::UserOwnedRootLease;
use eliot_platform_windows::{
    AgentBridgeSecurityConvergenceReceipt as PlatformAgentBridgeSecurityConvergenceReceipt,
    AgentBridgeStagePrepared as PlatformAgentBridgeStagePrepared,
    AgentBridgeStagingReceipt as PlatformAgentBridgeStagingReceipt,
};
#[cfg(test)]
use eliot_platform_windows::{
    AuthenticodeVerdict, PackageManifest, PackageStagingError, PackageStagingStage, PeCoffError,
    TrustedSourceBundle,
};
use eliot_platform_windows::{
    CredentialSecret, ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME,
    ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME, ELIOT_WATCHDOG_SERVICE_NAME, FileIdentity,
    HostOwnerEpochCapability, InstallerRootAbsentSnapshot, InstallerRootCreateAttempt,
    InstallerRootCreateDisposition, InstallerRootError, InstallerRootObjectSnapshot,
    InstallerRootPrimitiveCreate, InstallerRootPrimitiveObservation, InstallerRootPrimitiveSpec,
    InstallerRootProfile, InstallerRootStage, InstallerSecretCreateDisposition,
    InstallerSecretObservation, ProtectedPathLease, ProtectedRootLease, ProtectedRuntimePathLease,
    ServiceAccount, ServiceBootstrapArguments, ServiceRegistrationCurrent,
    ServiceRegistrationInspection, ServiceRegistrationOutcome, ServiceRegistrationRequest,
    ServiceRegistrationRuntimeInspection, ServiceStartMode, ServiceStartOutcome,
    ServiceStopOutcome, StagingReceipt, SupervisionAuthorityKeyError,
    SupervisionAuthorityKeyStoreRequest, UserOwnedPathLease, WindowsInstallerRootPrimitive,
    WindowsInstallerSecretProvider, WindowsPlatform, WindowsStoreCredentialTargetGenerator,
    WindowsSupervisionAuthorityKeyStore, current_user_local_app_data_root,
    fresh_service_registration_nonce, observe_running_eliot_host_process,
    protected_program_data_root, require_protected_program_data_path, resolve_service_sid,
};
#[cfg(test)]
use eliot_platform_windows::{
    ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK, watchdog_service_security_descriptor_digest,
};
pub use eliot_runtime_contracts::ProvisionedSupervisionAuthority;
use eliot_runtime_contracts::{
    SUPERVISION_AUTHORITY_HOST_SERVICE, SUPERVISION_AUTHORITY_SERVICE_SID_TYPE,
};
#[cfg(test)]
use redb::Database;
#[cfg(test)]
use redb::ReadableDatabase;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use thiserror::Error;

#[cfg(test)]
fn test_provisioned_supervision_authority(
    installation_id: &str,
    candidate_generation: &str,
    authority_generation: ResourceGeneration,
) -> ProvisionedSupervisionAuthority {
    let signer = eliot_runtime_contracts::Ed25519SupervisionLeaseSigner::from_secret_key(
        "eliot-kernel",
        "test-supervision-key",
        [0x39; 32],
    )
    .unwrap_or_else(|_| unreachable!());
    let trust_anchor = eliot_runtime_contracts::SupervisionTrustAnchor::new(
        installation_id,
        "eliot-kernel",
        "test-supervision-key",
        signer.public_key().to_vec(),
    )
    .unwrap_or_else(|_| unreachable!());
    let key_reference = eliot_runtime_contracts::SupervisionSealedKeyReference::new(
        "test-supervision-authority.sealed",
        "S-1-5-80-1-2-3-4-5",
        eliot_runtime_contracts::SupervisionSealedKeyFileIdentity {
            canonical_path_digest: "1".repeat(64),
            volume_serial_number: 7,
            file_index: 11,
            security_descriptor_digest: "2".repeat(64),
        },
        "3".repeat(64),
    )
    .unwrap_or_else(|_| unreachable!());
    ProvisionedSupervisionAuthority::new(
        "test-supervision-scope",
        candidate_generation,
        authority_generation,
        key_reference,
        trust_anchor,
    )
    .unwrap_or_else(|_| unreachable!())
}

mod activation;
mod agent_bridge_profile;
mod approved_generation_registry;
mod credential_provision;
mod installation_registry;
mod integration_discovery;
mod package;
mod package_planner;
mod plan;
mod profile_roots;
mod redb_state;
mod registry_wire;
mod runtime_root_contract;
mod scm_approval;
mod signed_activation;
mod transaction;

pub use installation_registry::RedbInstallationRegistry;
#[cfg(test)]
use installation_registry::classify_registry_table;
#[cfg(test)]
use installation_registry::validate_installation_host_root;
use installation_registry::{
    LEGACY_REGISTRY_TABLE, REGISTRY_RELATIVE_PATH, REGISTRY_TABLE, installation_registry_path,
};

pub use approved_generation_registry::{
    ActivationCommitFence, ActivationCommitReceipt, ActivePhaseBRebind, ActivePhaseBRebindIntent,
    ActivePhaseBRebindReceipt, ActivePhaseBRebindRecovery, AgentBridgePhaseBBinding,
    AgentBridgePreparedBinding, AgentBridgeSecurityContour, AgentBridgeStagePrepared,
    ApprovedGeneration, ApprovedGenerationRegistry, HostPhaseBPreparedMaterialization,
    PendingActivation, PendingActivationState, PhaseBDigestState, PhaseBLiveBinding,
    phase_b_digest_state, phase_b_scm_selector,
};
use approved_generation_registry::{
    ActiveVerifiedReceiptBinding, PendingActivationTerminal, PendingActivationTerminalDisposition,
    activation_terminal_digest, candidate_manifest_digest, phase_b_scm_digest,
    registry_projection_identity, validate_approval_against_manifest, validate_phase_b_scm_digest,
};
#[cfg(test)]
use approved_generation_registry::{
    active_phase_b_rebind_intent_digest, active_phase_b_rebind_receipt_digest,
};

pub(crate) use integration_discovery::WindowsPathIdentity;
pub use integration_discovery::{
    IntegrationCategory, IntegrationDiscoveryCatalogue, IntegrationDiscoveryCatalogueEntry,
};

pub use activation::{
    InstallationActivationApproval, InstallationActivationApprovalBinding,
    InstallationActivationProjectionIntent, InstallationActivationRegistryRevisionPolicy,
};
pub use agent_bridge_profile::{
    AGENT_BRIDGE_INSTALLATION_PROFILE_WIRE_ID, AGENT_BRIDGE_INSTALLATION_PROFILE_WIRE_VERSION,
    AGENT_BRIDGE_MAX_FRAME_BYTES, AGENT_BRIDGE_MAX_POLICY_ENTRIES, AGENT_BRIDGE_MODULE_ID,
    AGENT_BRIDGE_SOURCE_MAX_BYTES, AgentBridgeCallerSessionPolicy, AgentBridgeInstallationProfile,
    AgentBridgeProcessPolicy, AgentBridgeProtectedPaths, AgentBridgeSourceMaterializationFactory,
    AgentBridgeSourceMaterializationPlan, AgentBridgeSourceObserverFactory,
    RetainedAgentBridgeArtifact, RetainedAgentBridgeSource, RetainedAgentBridgeSourceObserver,
    agent_bridge_source_plan_from_observed_kernel, derive_agent_bridge_protected_paths,
};
pub use credential_provision::{
    CredentialAccessReceipt, CredentialOwnershipMarkerIdentity, HOST_CREDENTIAL_CONTROL_PIPE,
    HOST_CREDENTIAL_CONTROL_WIRE, HostCredentialControlIntent, HostCredentialControlOperation,
    HostCredentialControlRequest, HostCredentialControlResponse, HostPhaseBMaterializationIntent,
    HostPhaseBMaterializationReceipt, HostPhaseBPreparedReceipt, HostPhaseBStaticTemplate,
    LOCAL_SERVICE_SID, StoreCredentialAbsentSnapshot, StoreCredentialLifecycle,
    StoreCredentialProgress, StoreCredentialProvider, StoreCredentialProvisionPlan,
    StoreCredentialScope, credential_absent_response_digest, credential_control_request_frame,
    credential_control_response_frame, credential_deleted_response_digest,
    credential_matching_response_digest, decode_credential_control_request_frame,
    decode_credential_control_response_frame, dispatch_credential_target_for_store_target,
    phase_b_credential_receipt_digest, phase_b_host_state_root_digest,
    phase_b_static_template_for_candidate, phase_b_watchdog_selector_digest,
    validate_store_credential_target,
};
pub use package::{PackageObservationSnapshot, PackageObservedFile};
use package::{
    execute_package, inspect_package, package_plan_error, package_port_error, reconcile_package,
    validate_package_binding, validate_package_relative_text,
    validate_staging_receipt_for_observation, validate_staging_receipt_for_plan,
};
#[cfg(test)]
use package::{package_absent_with_snapshot, package_manifest_matches, package_staging_reference};
pub use package_planner::{GenerationPackagePlanInput, GenerationPackagePlanner};
pub use plan::{
    InstallerAclPrincipal, InstallerEffectPlan, InstallerServiceAccount, InstallerServiceRole,
    PackageArtifactDigest, PlannedChange, SupervisionAuthorityProvisionPlan,
};
use plan::{validate_effect_profile, validate_installer_effects, validate_phase_b_effect_bindings};
pub use profile_roots::InstallationRoots;
pub use redb_state::{
    RedbInstallationTransactionStore, SOURCE_BUNDLE_PUBLICATION_JOURNAL_WIRE_VERSION,
    SourceBundlePublicationJournal, SourceBundlePublicationJournalState,
    SourceBundlePublicationRole, require_published_source_bundle_journal,
    source_bundle_publication_operation_id,
};
use registry_wire::decode_registry_bytes;
pub use runtime_root_contract::{
    InstallationProfile, RuntimeRootLease, RuntimeRootLeaseProvider, RuntimeStateRoots,
    ValidatedRuntimeRootLeases, WindowsRuntimeRootLease, WindowsRuntimeRootLeaseProvider,
};
pub use scm_approval::{InstallerServiceControlGrantReceipt, InstallerServiceRegistrationApproval};
#[cfg(test)]
use transaction::decode_installation_transaction_json;
use transaction::decode_installation_transaction_json_from_store;
pub use transaction::{
    InstallationCreateDisposition, InstallationEffectDisposition, InstallationEffectProgress,
    InstallationEffectProgressState, InstallationOsObjectSnapshot, InstallationOwnershipSecret,
    InstallationRootAbsentSnapshot, InstallationSecretCreationProof, InstallationSecretLifecycle,
    InstallationSecretProvisionDisposition, InstallationSecretReference, InstallationSecretScope,
    InstallationStage, InstallationTransaction, StoreFreeSpaceObservation,
    parse_installation_transaction_id, validate_installation_transaction_json,
};

/// Stable wire name for the installation contract.
pub const CONTRACT_NAME: &str = "eliot.kernel.installation";
/// Explicit, non-digest Phase-A marker for Host-owned Phase-B physical
/// digests. It is intentionally not SHA-256-shaped: runtime state must never
/// confuse the pending marker with a physical authority or bootstrap digest.
pub const PHASE_B_PENDING_MARKER: &str = "phase-b-pending:v1";
/// Compatibility name for the reserved Phase-A pending state. Despite the
/// historical name, this value is a typed marker and is not a digest.
pub const PHASE_B_PENDING_DIGEST: &str = PHASE_B_PENDING_MARKER;
/// Adapter-only hashed selector emitted in SCM bootstrap argv. This value is
/// never valid in a [`RuntimeLaunchDescriptor`] Phase-B digest field.
pub const PHASE_B_PENDING_SCM_DIGEST: &str =
    "287ddc2779dd75cc92d2dadd6f06b4dba2eefa5d63538db7be11523687f7ba8c";

/// Canonical Phase-A descriptor prefix for the selected supervision slot.
///
/// The slot names the pending lease selected by the immutable plan.  It is
/// deliberately not a public-key fingerprint and cannot authorize a lease;
/// only the Host-owned Phase-B [`ProvisionedSupervisionAuthority`] receipt
/// carries the live trust anchor.
pub const SUPERVISION_KEY_SLOT_PREFIX: &str = "eliot-supervision-slot:v1:";

/// Derives the canonical Phase-A supervision slot from its pending lease ID.
///
/// This value is an intent descriptor only.  It must never be compared with a
/// Phase-B public key or used as an authority digest.
pub fn supervision_key_slot_for_scope_id(
    supervision_lease_scope_id: &str,
) -> Result<PlatformHandle, InstallationError> {
    text(supervision_lease_scope_id, "supervision_lease_scope_id")?;
    PlatformHandle::new(format!(
        "{SUPERVISION_KEY_SLOT_PREFIX}{supervision_lease_scope_id}"
    ))
    .map_err(|error| InstallationError::InvalidField {
        field: "manifest.supervision_key_slot".to_owned(),
        reason: error.to_string(),
    })
}
const LEGACY_PHASE_B_ZERO_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
/// Current installation contract revision.
///
/// Version 4 made the typed pending/provisioned supervision authority a
/// mandatory member of every `RuntimeLaunchDescriptor` projection. Version 5
/// adds the mandatory domain-separated protected snapshot identity.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(5, 0, 0);
/// Breaking wire revision for durable [`InstallationTransaction`] records.
///
/// This discriminator is intentionally independent from [`CONTRACT_VERSION`]
/// so durable transaction records fail closed when their nested candidate
/// manifest predates the required Host artifact binding. Version 9 added the
/// private, durable activation-receipt binding; version 10 added the typed,
/// exact-configuration-bound service-start effects and their durable
/// convergence deadline. Version 11 adds the signed activation projection
/// intent and removes the static Kernel nonce from the activation envelope.
/// Version 13 adds the durable, ordered SCM start effects and their
/// convergence deadline; version 15 is the canonical installer-owned SCM
/// composition with Watchdog then Host Automatic `LocalService` starts and
/// authoritative readback. Version 16 binds the installer-owned service-SID
/// sealed supervision authority plan and Phase-B public provision receipt.
/// Version 18 makes the exact EliotHost-to-EliotWatchdog service-object grant
/// receipt mandatory for every applied Watchdog registration.
/// Version 19 binds the exact profiled root hierarchy, shared immutable
/// package contour, and per-installation canary-evidence root. Version 21
/// makes the durable registration nonce and service-start deadline members
/// mandatory on the current wire; v20 records require explicit migration.
/// Version 22 separates filesystem and Credential Manager create dispositions
/// and requires the keyed non-secret credential creation proof. Version 23
/// adds the optional, digest-bound agent-bridge source materialization plan.
/// Older wires cannot be interpreted as this effect set.
/// Older wires require explicit migration and are never synthesized.
pub const INSTALLATION_TRANSACTION_WIRE_VERSION: ContractVersion = ContractVersion::new(23, 0, 0);

/// Current durable approved-generation registry wire revision.
///
/// Registry wire version 12 binds the provisioned supervision authority into
/// pending Phase-B receipts and committed/rebound live bindings. Version 15
/// binds each Watchdog approval to the exact installer-read SCM control grant.
/// Older projections are never defaulted into current authority.
pub const INSTALLATION_REGISTRY_WIRE_VERSION: ContractVersion = ContractVersion::new(15, 0, 0);

/// Bounded wall-clock window in which one committed SCM start intent must
/// converge to a stable `Running` readback.  The coordinator accepts an
/// injected timestamp in tests and persists the computed deadline before the
/// external start call, so restart cannot silently create a second attempt.
pub const SERVICE_START_CONVERGENCE_TIMEOUT_MS: u64 = 30_000;

/// Version of the durable non-secret Credential Manager creation proof.
pub const INSTALLATION_SECRET_CREATION_PROOF_VERSION: u32 = 1;

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
    if !is_lower_sha256(value.as_str()) {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must be a lowercase SHA-256 digest".to_owned(),
        });
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Validates a digest that belongs to a runtime artifact/config/descriptor
/// domain.  The hashed pending selector is reserved for the SCM adapter and
/// the legacy all-zero value is never a runtime publication proof.
fn runtime_sha256_handle(value: &PlatformHandle, field: &str) -> Result<(), InstallationError> {
    if value.as_str() == PHASE_B_PENDING_SCM_DIGEST {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "the SCM pending selector is adapter-only and cannot be a runtime digest"
                .to_owned(),
        });
    }
    if value.as_str() == LEGACY_PHASE_B_ZERO_DIGEST {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "legacy zero digest cannot be a runtime artifact or publication proof"
                .to_owned(),
        });
    }
    sha256_handle(value, field)
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
    /// Phase-A supervision slot selected by the pending runtime lease.
    ///
    /// The JSON member intentionally retains the historical
    /// `supervision_key_fingerprint` name so current transaction and registry
    /// wires remain readable.  New values use the canonical slot prefix; a
    /// legacy lowercase SHA-256 value is accepted only as an inert projection
    /// and never authorizes a Phase-B trust anchor.
    #[serde(rename = "supervision_key_fingerprint")]
    pub supervision_key_slot: PlatformHandle,
    /// Runtime Live canary artifact-set evidence reference.
    ///
    /// This is a content-addressed, domain-separated SHA-256 over the
    /// canonical generation and exact ordered nine-file Phase-A facts. It is not a
    /// production release signature; production signing remains unclaimed.
    pub signature_ref: PlatformHandle,
    /// Digest of the exact mutable root topology approved by this manifest.
    pub runtime_state_roots_digest: PlatformHandle,
    /// Exact Host-owned runtime launch contour bound to this approval.
    pub runtime_launch: RuntimeLaunchDescriptor,
}

/// Strict Phase-B state for the installer-provisioned supervision authority.
///
/// Phase A retains only the stable lease identity selected by the immutable
/// plan. The Host-owned Phase-B overlay may replace it exactly once with the
/// installer receipt; serde never defaults or synthesizes an absent binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum SupervisionAuthorityBinding {
    /// Immutable Phase-A plan state. This state cannot sign or verify a lease.
    Pending {
        /// Stable lease identity selected by the generation planner.
        supervision_lease_scope_id: PlatformHandle,
    },
    /// Exact public receipt returned by the installer-owned key effect.
    Provisioned {
        /// Public authority binding. Only Kernel consumes `key_reference`.
        authority: Box<ProvisionedSupervisionAuthority>,
    },
}

impl SupervisionAuthorityBinding {
    fn validate_for_launch(
        &self,
        launch: &RuntimeLaunchDescriptor,
    ) -> Result<(), InstallationError> {
        match self {
            Self::Pending {
                supervision_lease_scope_id,
            } => handle(
                supervision_lease_scope_id,
                "runtime_launch.supervision_authority.supervision_lease_scope_id",
            ),
            Self::Provisioned { authority } => {
                authority
                    .validate()
                    .map_err(|error| InstallationError::InvalidField {
                        field: "runtime_launch.supervision_authority".to_owned(),
                        reason: error.to_string(),
                    })?;
                if authority.candidate_generation != launch.generation.as_str()
                    || authority.authority_generation != launch.authority_generation
                    || authority.trust_anchor.installation_id
                        != launch.installation_epoch.installation.as_str()
                {
                    return Err(InstallationError::IdentityConflict);
                }
                Ok(())
            }
        }
    }

    fn scope_id(&self) -> &str {
        match self {
            Self::Pending {
                supervision_lease_scope_id,
            } => supervision_lease_scope_id.as_str(),
            Self::Provisioned { authority } => &authority.supervision_lease_scope_id,
        }
    }
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
    ///
    /// A Phase-A candidate carries [`PHASE_B_PENDING_MARKER`] here. Host
    /// replaces that typed pending state only with the digest of exact
    /// published authority bytes before child admission.
    pub authority_descriptor_digest: PlatformHandle,
    /// Typed pending/provisioned supervision authority state. The immutable
    /// candidate remains Pending; only a transaction-bound Phase-B overlay
    /// carries the provisioned public receipt.
    pub supervision_authority: SupervisionAuthorityBinding,
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
    /// Domain-separated identity of the protected Kernel/eliotd snapshot.
    ///
    /// This is the value materialized inside `GovernorLaunchConfig`; it is
    /// carried independently so consumers cannot substitute a digest of the
    /// configuration bytes for the protected snapshot identity.
    pub protected_snapshot_digest: PlatformHandle,
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
    ///
    /// A Phase-A candidate carries [`PHASE_B_PENDING_MARKER`] here. Host
    /// replaces that typed pending state only with the digest of exact
    /// published Store bootstrap bytes before child admission.
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

    /// Returns the Host Phase-B overlay for one already approved launch
    /// template.
    ///
    /// Phase A intentionally carries only template digests for the authority
    /// and Store bootstrap files. Host calls this method after opening its
    /// real installation epoch and after exact publication/readback of the
    /// live handoff files. The candidate manifest and installer approval are
    /// never rewritten; this is an in-memory launch overlay whose self-digest
    /// is recomputed for the exact bytes consumed by the children.
    pub fn with_phase_b_materialization(
        &self,
        authority_generation: ResourceGeneration,
        authority_state_fence: StateFence,
        authority_descriptor_digest: PlatformHandle,
        store_bootstrap_descriptor_digest: PlatformHandle,
        eliotd_descriptor_digest: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        if self.phase_b_digest_state()? != (PhaseBDigestState::Live, PhaseBDigestState::Pending) {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.phase_b_digest_state".to_owned(),
                reason: "Phase-B finalization must consume the Host live-authority/pending-bootstrap intermediate"
                    .to_owned(),
            });
        }
        self.with_phase_b_overlay(
            authority_generation,
            authority_state_fence,
            authority_descriptor_digest,
            store_bootstrap_descriptor_digest,
            eliotd_descriptor_digest,
            false,
            None,
        )
    }

    /// Returns a non-admissible intermediate overlay used to break the
    /// Store-config/bootstrap self-digest cycle.
    ///
    /// The authority and eliotd descriptor digests must already be live, but
    /// the bootstrap digest remains explicitly [`PhaseBDigestState::Pending`]
    /// until the bootstrap bytes include the final semantic Store hash. The
    /// returned launch must not be used to start a child; callers must finish
    /// with [`Self::with_phase_b_materialization`] and
    /// [`Self::require_phase_b_live`].
    pub fn with_phase_b_pending_bootstrap_overlay(
        &self,
        authority_generation: ResourceGeneration,
        authority_state_fence: StateFence,
        authority_descriptor_digest: PlatformHandle,
        eliotd_descriptor_digest: PlatformHandle,
        provisioned_supervision_authority: ProvisionedSupervisionAuthority,
    ) -> Result<Self, InstallationError> {
        if self.phase_b_digest_state()? != (PhaseBDigestState::Pending, PhaseBDigestState::Pending)
        {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.phase_b_digest_state".to_owned(),
                reason: "Phase-B intermediate overlay must start from an immutable pending pair"
                    .to_owned(),
            });
        }
        let pending_bootstrap = PlatformHandle::new(PHASE_B_PENDING_MARKER).map_err(|error| {
            InstallationError::InvalidField {
                field: "runtime_launch.store_bootstrap_descriptor_digest".to_owned(),
                reason: error.to_string(),
            }
        })?;
        self.with_phase_b_overlay(
            authority_generation,
            authority_state_fence,
            authority_descriptor_digest,
            pending_bootstrap,
            eliotd_descriptor_digest,
            true,
            Some(provisioned_supervision_authority),
        )
    }

    /// Returns the explicit state of the authority and Store bootstrap
    /// physical digest fields.
    pub fn phase_b_digest_state(
        &self,
    ) -> Result<(PhaseBDigestState, PhaseBDigestState), InstallationError> {
        Ok((
            phase_b_digest_state(
                &self.authority_descriptor_digest,
                "runtime_launch.authority_descriptor_digest",
            )?,
            phase_b_digest_state(
                &self.store_bootstrap_descriptor_digest,
                "runtime_launch.store_bootstrap_descriptor_digest",
            )?,
        ))
    }

    /// Requires both Host-owned Phase-B destinations to be live physical
    /// publications before a child process can be admitted.
    pub fn require_phase_b_live(&self) -> Result<(), InstallationError> {
        if self.phase_b_digest_state()? == (PhaseBDigestState::Live, PhaseBDigestState::Live)
            && matches!(
                &self.supervision_authority,
                SupervisionAuthorityBinding::Provisioned { .. }
            )
        {
            return Ok(());
        }
        Err(InstallationError::InvalidField {
            field: "runtime_launch.phase_b_digest_state".to_owned(),
            reason:
                "live child admission requires exact Phase-B authority and Store bootstrap readback"
                    .to_owned(),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the overlay keeps each independent Phase-B digest and fence binding explicit"
    )]
    fn with_phase_b_overlay(
        &self,
        authority_generation: ResourceGeneration,
        authority_state_fence: StateFence,
        authority_descriptor_digest: PlatformHandle,
        store_bootstrap_descriptor_digest: PlatformHandle,
        eliotd_descriptor_digest: PlatformHandle,
        allow_pending_bootstrap: bool,
        provisioned_supervision_authority: Option<ProvisionedSupervisionAuthority>,
    ) -> Result<Self, InstallationError> {
        for (digest, field) in [
            (
                &authority_descriptor_digest,
                "runtime_launch.authority_descriptor_digest",
            ),
            (
                &eliotd_descriptor_digest,
                "runtime_launch.eliotd_descriptor_digest",
            ),
        ] {
            if phase_b_digest_state(digest, field)? == PhaseBDigestState::Pending {
                return Err(InstallationError::InvalidField {
                    field: field.to_owned(),
                    reason:
                        "Phase-B authority and eliotd overlays require observed physical digests"
                            .to_owned(),
                });
            }
        }
        let bootstrap_state = phase_b_digest_state(
            &store_bootstrap_descriptor_digest,
            "runtime_launch.store_bootstrap_descriptor_digest",
        )?;
        if bootstrap_state == PhaseBDigestState::Pending && !allow_pending_bootstrap {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.store_bootstrap_descriptor_digest".to_owned(),
                reason:
                    "live Phase-B materialization requires an observed bootstrap physical digest"
                        .to_owned(),
            });
        }
        let mut overlay = self.clone();
        match (
            &self.supervision_authority,
            provisioned_supervision_authority,
        ) {
            (
                SupervisionAuthorityBinding::Pending {
                    supervision_lease_scope_id,
                },
                Some(authority),
            ) if supervision_lease_scope_id.as_str() == authority.supervision_lease_scope_id => {
                overlay.supervision_authority = SupervisionAuthorityBinding::Provisioned {
                    authority: Box::new(authority),
                };
            }
            (SupervisionAuthorityBinding::Provisioned { .. }, None) => {}
            _ => {
                return Err(InstallationError::InvalidField {
                    field: "runtime_launch.supervision_authority".to_owned(),
                    reason: "Phase-B overlay requires the exact planned lease identity and permits only Pending-to-Provisioned"
                        .to_owned(),
                });
            }
        }
        overlay.authority_generation = authority_generation;
        overlay.authority_state_fence = authority_state_fence;
        overlay.authority_descriptor_digest = authority_descriptor_digest;
        overlay.store_bootstrap_descriptor_digest = store_bootstrap_descriptor_digest;
        overlay.eliotd_descriptor_digest = eliotd_descriptor_digest;
        overlay.kernel_arguments = overlay
            .expected_kernel_arguments(&overlay.store_config_path)
            .into_iter()
            .map(|value| {
                PlatformHandle::new(value).map_err(|error| InstallationError::InvalidField {
                    field: "runtime_launch.kernel_arguments".to_owned(),
                    reason: error.to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        overlay.descriptor_digest = PlatformHandle::new("0".repeat(64)).map_err(|error| {
            InstallationError::InvalidField {
                field: "runtime_launch.descriptor_digest".to_owned(),
                reason: error.to_string(),
            }
        })?;
        overlay.with_computed_digest()
    }

    /// Returns the exact installer-provisioned public authority after all
    /// launch invariants have been checked. Pending candidates fail closed.
    pub fn provisioned_supervision_authority(
        &self,
    ) -> Result<&ProvisionedSupervisionAuthority, InstallationError> {
        self.validate()?;
        match &self.supervision_authority {
            SupervisionAuthorityBinding::Provisioned { authority } => Ok(authority),
            SupervisionAuthorityBinding::Pending { .. } => {
                Err(InstallationError::IncompleteObservation(
                    "supervision authority is not provisioned".to_owned(),
                ))
            }
        }
    }

    /// Returns the stable lease identity in either strict binding state.
    #[must_use]
    pub fn supervision_lease_scope_id(&self) -> &str {
        self.supervision_authority.scope_id()
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
            supervision_authority: &'a SupervisionAuthorityBinding,
            runtime_state_roots: &'a RuntimeStateRoots,
            kernel_work_root: &'a PlatformHandle,
            kernel_artifact_digest: &'a PlatformHandle,
            eliotd_executable_path: &'a PlatformHandle,
            eliotd_artifact_digest: &'a PlatformHandle,
            eliotd_config_path: &'a PlatformHandle,
            eliotd_config_digest: &'a PlatformHandle,
            protected_snapshot_digest: &'a PlatformHandle,
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
            supervision_authority: &self.supervision_authority,
            runtime_state_roots: &self.runtime_state_roots,
            kernel_work_root: &self.kernel_work_root,
            kernel_artifact_digest: &self.kernel_artifact_digest,
            eliotd_executable_path: &self.eliotd_executable_path,
            eliotd_artifact_digest: &self.eliotd_artifact_digest,
            eliotd_config_path: &self.eliotd_config_path,
            eliotd_config_digest: &self.eliotd_config_digest,
            protected_snapshot_digest: &self.protected_snapshot_digest,
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
        phase_b_digest_state(
            &self.authority_descriptor_digest,
            "runtime_launch.authority_descriptor_digest",
        )?;
        self.supervision_authority.validate_for_launch(self)?;
        match self.phase_b_digest_state()? {
            (PhaseBDigestState::Pending, PhaseBDigestState::Pending)
                if matches!(
                    &self.supervision_authority,
                    SupervisionAuthorityBinding::Pending { .. }
                ) => {}
            (PhaseBDigestState::Live, _)
                if matches!(
                    &self.supervision_authority,
                    SupervisionAuthorityBinding::Provisioned { .. }
                ) => {}
            _ => {
                return Err(InstallationError::InvalidField {
                    field: "runtime_launch.supervision_authority".to_owned(),
                    reason: "authority state must be Pending only on the immutable Phase-A pair and Provisioned for every live authority overlay"
                        .to_owned(),
                });
            }
        }
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
        runtime_sha256_handle(
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
        runtime_sha256_handle(
            &self.eliotd_artifact_digest,
            "runtime_launch.eliotd_artifact_digest",
        )?;
        approved_path(
            &self.eliotd_config_path,
            "runtime_launch.eliotd_config_path",
        )?;
        runtime_sha256_handle(
            &self.eliotd_config_digest,
            "runtime_launch.eliotd_config_digest",
        )?;
        runtime_sha256_handle(
            &self.protected_snapshot_digest,
            "runtime_launch.protected_snapshot_digest",
        )?;
        approved_path(
            &self.eliotd_descriptor_path,
            "runtime_launch.eliotd_descriptor_path",
        )?;
        runtime_sha256_handle(
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
        phase_b_digest_state(
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
        runtime_sha256_handle(
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
        runtime_sha256_handle(
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
        runtime_sha256_handle(
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
        runtime_sha256_handle(
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
        runtime_sha256_handle(&self.descriptor_digest, "runtime_launch.descriptor_digest")?;
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
    /// Computes the canonical digest of this immutable candidate manifest.
    ///
    /// The digest covers only manifest bytes. Host materialization receipts,
    /// including destination file identities, are observed after publication
    /// and are never folded into this immutable value.
    pub fn compute_digest(&self) -> Result<PlatformHandle, InstallationError> {
        candidate_manifest_digest(self)
    }

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
        handle(&self.supervision_key_slot, "manifest.supervision_key_slot")?;
        if !is_lower_sha256(self.supervision_key_slot.as_str()) {
            let expected = supervision_key_slot_for_scope_id(
                self.runtime_launch.supervision_lease_scope_id(),
            )?;
            if self.supervision_key_slot != expected {
                return Err(InstallationError::InvalidField {
                    field: "manifest.supervision_key_slot".to_owned(),
                    reason: "must exactly describe the RuntimeLaunchDescriptor pending supervision lease"
                        .to_owned(),
                });
            }
        }
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
    /// Trusted package source observation bound to the exact retained root and manifest.
    pub package_snapshot: Option<PackageObservationSnapshot>,
    /// Digest binding the planned references and typed snapshots in order.
    pub digest: PlatformHandle,
}

impl InstallationEffectPrecondition {
    fn from_change(change: &PlannedChange) -> Result<Self, InstallationError> {
        Self::new(change.precondition_refs.clone(), None, None, None)
    }

    fn with_os_snapshot(
        &self,
        snapshot: InstallationRootAbsentSnapshot,
    ) -> Result<Self, InstallationError> {
        Self::new(self.evidence_refs.clone(), Some(snapshot), None, None)
    }

    fn with_credential_snapshot(
        &self,
        snapshot: StoreCredentialAbsentSnapshot,
    ) -> Result<Self, InstallationError> {
        Self::new(self.evidence_refs.clone(), None, Some(snapshot), None)
    }

    fn with_package_snapshot(
        &self,
        snapshot: PackageObservationSnapshot,
    ) -> Result<Self, InstallationError> {
        Self::new(self.evidence_refs.clone(), None, None, Some(snapshot))
    }

    fn new(
        evidence_refs: Vec<PlatformHandle>,
        os_snapshot: Option<InstallationRootAbsentSnapshot>,
        credential_snapshot: Option<StoreCredentialAbsentSnapshot>,
        package_snapshot: Option<PackageObservationSnapshot>,
    ) -> Result<Self, InstallationError> {
        #[derive(Serialize)]
        struct DigestInput<'a> {
            evidence_refs: &'a [PlatformHandle],
            os_snapshot: &'a Option<InstallationRootAbsentSnapshot>,
            credential_snapshot: &'a Option<StoreCredentialAbsentSnapshot>,
            package_snapshot: &'a Option<PackageObservationSnapshot>,
        }
        let digest = PlatformHandle::new(sha256_hex(
            &serde_json::to_vec(&DigestInput {
                evidence_refs: &evidence_refs,
                os_snapshot: &os_snapshot,
                credential_snapshot: &credential_snapshot,
                package_snapshot: &package_snapshot,
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
            package_snapshot,
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
            package_snapshot: &'a Option<PackageObservationSnapshot>,
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
        if let Some(snapshot) = &self.package_snapshot {
            snapshot.validate()?;
        }
        let snapshot_count = u8::from(self.os_snapshot.is_some())
            + u8::from(self.credential_snapshot.is_some())
            + u8::from(self.package_snapshot.is_some());
        if snapshot_count > 1 {
            return Err(InstallationError::InvalidField {
                field: "effect.precondition.snapshot".to_owned(),
                reason: "snapshots are mutually exclusive".to_owned(),
            });
        }
        sha256_handle(&self.digest, "effect.precondition.digest")?;
        let expected = sha256_hex(
            &serde_json::to_vec(&DigestInput {
                evidence_refs: &self.evidence_refs,
                os_snapshot: &self.os_snapshot,
                credential_snapshot: &self.credential_snapshot,
                package_snapshot: &self.package_snapshot,
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
    /// SHA-256-shaped SCM selector for the descriptor. For a Phase-A pending
    /// runtime marker this is [`PHASE_B_PENDING_SCM_DIGEST`], not a physical
    /// authority readback and never a Phase-B live proof.
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
        // SCM carries only the adapter selector here. A Phase-A runtime
        // pending marker must already have been converted to the distinct
        // hashed selector before this bootstrap crosses the adapter boundary.
        validate_phase_b_scm_digest(
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
        let installation_root = WindowsPathIdentity::parse_root(
            self.installation_root.as_str(),
            "effect.installation_root",
        )?;
        match self.profile {
            InstallationProfile::SystemService | InstallationProfile::UserMode => {
                let Some(key) = installation_root.components.last() else {
                    return Err(InstallationError::ProfileViolation(
                        "profiled effect installation root is incomplete".to_owned(),
                    ));
                };
                validate_installation_key(key)?;
                if !installation_root.ends_with(&["eliot", "installations", key]) {
                    return Err(InstallationError::ProfileViolation(
                        "effect installation_root is not the exact profiled contour".to_owned(),
                    ));
                }
            }
            InstallationProfile::PortableDev => {}
        }
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
            if let Some(snapshot) = &self.precondition.package_snapshot {
                validate_staging_receipt_for_observation(snapshot, receipt)?;
            }
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
                if self.precondition.os_snapshot.is_none()
                    && self.precondition.package_snapshot.is_none() => {}
            (InstallerEffectPlan::StagePackage { .. }, InstallationEffectAction::Apply, None)
                if self.precondition.os_snapshot.is_none()
                    && self.precondition.credential_snapshot.is_none()
                    && self.precondition.package_snapshot.is_none()
                    && self.staging_receipt.is_none()
                    && self.attempt == 1 => {}
            (
                InstallerEffectPlan::StagePackage { .. },
                InstallationEffectAction::Rollback,
                None,
            ) if self.precondition.package_snapshot.is_some() => {}
            (
                InstallerEffectPlan::StagePackage { .. },
                InstallationEffectAction::Rollback,
                Some(ownership),
            ) if self.precondition.package_snapshot.is_some()
                && self.staging_receipt.is_some()
                && ownership.lifecycle != InstallationSecretLifecycle::Deleted => {}
            (InstallerEffectPlan::StagePackage { .. }, InstallationEffectAction::Apply, None)
                if self.precondition.package_snapshot.is_some()
                    && self.precondition.os_snapshot.is_none()
                    && self.precondition.credential_snapshot.is_none() => {}
            (
                InstallerEffectPlan::StagePackage { .. },
                InstallationEffectAction::Apply,
                Some(ownership),
            ) if self.precondition.package_snapshot.is_some()
                && self.precondition.os_snapshot.is_none()
                && self.precondition.credential_snapshot.is_none()
                && ownership.lifecycle != InstallationSecretLifecycle::Deleted
                && matches!(
                    ownership.secret_provision_disposition,
                    InstallationSecretProvisionDisposition::NotAttempted
                        | InstallationSecretProvisionDisposition::Created
                ) => {}
            (
                InstallerEffectPlan::RegisterService { .. }
                | InstallerEffectPlan::StartService { .. },
                _,
                None,
            ) => {
                if matches!(
                    &self.plan,
                    InstallerEffectPlan::RegisterService { .. }
                        | InstallerEffectPlan::StartService { .. }
                ) && (self.service_bootstrap.is_none()
                    || (self.registration_nonce.is_none()
                        && self.action == InstallationEffectAction::Rollback))
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
            (
                InstallerEffectPlan::MaterializePhaseB { .. },
                InstallationEffectAction::Apply,
                Some(ownership),
            ) if self.precondition.credential_snapshot.is_none()
                && self.store_credential.is_some()
                && ownership.lifecycle == InstallationSecretLifecycle::Active
                && ownership.secret_provision_disposition
                    == InstallationSecretProvisionDisposition::Created => {}
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
            (
                InstallerEffectPlan::MaterializePhaseB { .. },
                InstallationEffectAction::Apply,
                Some(progress),
            ) if progress.lifecycle == StoreCredentialLifecycle::Active
                && self.ownership_secret.as_ref().is_some_and(|ownership| {
                    ownership.lifecycle == InstallationSecretLifecycle::Active
                        && ownership.secret_provision_disposition
                            == InstallationSecretProvisionDisposition::Created
                })
                && self.precondition.credential_snapshot.is_none() => {}
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
            ownership.secret_provision_disposition =
                InstallationSecretProvisionDisposition::NotAttempted;
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
        /// Provider-authenticated process lineage observed while a matching
        /// service is still `START_PENDING`.  This is the first continuity
        /// anchor that can survive the PID-0 interval; it is never present
        /// for non-service effects.
        service_runtime_lineage: Option<InstallationServiceProcessLineage>,
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
        /// Exact service-object DACL receipt, present only for the Watchdog
        /// registration effect.
        service_control_grant: Option<Box<InstallerServiceControlGrantReceipt>>,
        /// Typed credential receipt, only for the Store credential effect.
        credential_receipt: Option<CredentialAccessReceipt>,
        /// Typed package receipt, only for the `StagePackage` effect.
        staging_receipt: Option<StagingReceipt>,
        /// Typed Host Phase-B receipt, only for the `MaterializePhaseB` effect.
        /// Box the wire receipt so one large typed observation does not inflate
        /// every provider-neutral observation value in memory.
        phase_b_receipt: Option<Box<HostPhaseBMaterializationReceipt>>,
        /// Provider-authenticated process lineage for a matching `StartService`
        /// readback; absent for all non-service effects.
        service_runtime_lineage: Option<InstallationServiceProcessLineage>,
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

    #[expect(
        clippy::too_many_lines,
        reason = "W3-02 will extract the effect-observation capability cell"
    )]
    fn validate_for_effect(&self, effect: &InstallerEffectPlan) -> Result<(), InstallationError> {
        self.validate_with_service_absence(matches!(
            effect,
            InstallerEffectPlan::RegisterService { .. }
                | InstallerEffectPlan::StartService { .. }
                | InstallerEffectPlan::StagePackage { .. }
                | InstallerEffectPlan::MaterializePhaseB { .. }
        ))?;
        let matching_control_grant = match self {
            Self::Matching {
                service_control_grant,
                ..
            } => service_control_grant.as_deref(),
            Self::Absent { .. } | Self::Mismatch { .. } => None,
        };
        match effect {
            InstallerEffectPlan::RegisterService {
                role: InstallerServiceRole::Watchdog,
                ..
            } if matches!(self, Self::Matching { .. }) => {
                matching_control_grant.ok_or_else(|| {
                    InstallationError::IncompleteObservation(
                        "Watchdog registration requires exact Host service-control grant readback"
                            .to_owned(),
                    )
                })?;
            }
            InstallerEffectPlan::RegisterService {
                role: InstallerServiceRole::Host,
                ..
            } => {
                if matching_control_grant.is_some() {
                    return Err(InstallationError::IdentityConflict);
                }
            }
            _ if matching_control_grant.is_some() => {
                return Err(InstallationError::IdentityConflict);
            }
            _ => {}
        }
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
        if let Self::Matching {
            phase_b_receipt: Some(receipt),
            ..
        } = self
        {
            if !matches!(effect, InstallerEffectPlan::MaterializePhaseB { .. }) {
                return Err(InstallationError::IdentityConflict);
            }
            receipt.validate()?;
        } else if matches!(effect, InstallerEffectPlan::MaterializePhaseB { .. })
            && matches!(self, Self::Matching { .. })
        {
            return Err(InstallationError::IncompleteObservation(
                "Phase-B matching readback requires its typed receipt".to_owned(),
            ));
        }
        if !matches!(effect, InstallerEffectPlan::StartService { .. })
            && matches!(
                self,
                Self::Matching {
                    service_runtime_lineage: Some(_),
                    ..
                }
            )
        {
            return Err(InstallationError::IdentityConflict);
        }
        if !matches!(effect, InstallerEffectPlan::StartService { .. })
            && matches!(
                self,
                Self::Absent {
                    service_runtime_lineage: Some(_),
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
                service_runtime_lineage,
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
                handles(evidence, "observation.evidence", true)?;
                if let Some(lineage) = service_runtime_lineage {
                    lineage.validate()?;
                }
                Ok(())
            }
            Self::Matching {
                external_identity,
                evidence,
                postcondition_digest,
                service_control_grant,
                credential_receipt,
                staging_receipt,
                phase_b_receipt,
                service_runtime_lineage,
                ..
            } => {
                handle(external_identity, "observation.external_identity")?;
                handles(evidence, "observation.evidence", true)?;
                sha256_handle(postcondition_digest, "observation.postcondition_digest")?;
                if let Some(receipt) = service_control_grant {
                    receipt.validate()?;
                }
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
                if let Some(receipt) = phase_b_receipt {
                    receipt.validate()?;
                }
                if let Some(lineage) = service_runtime_lineage {
                    lineage.validate()?;
                }
                Ok(())
            }
            Self::Mismatch { pending_ref } => handle(pending_ref, "observation.pending_ref"),
        }
    }
}

/// Provider disposition for an exact SCM start attempt.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationServiceStartDisposition {
    /// The provider issued the caller's one allowed `StartServiceW` call.
    StartedByCaller,
    /// The provider observed the exact service already running and issued no
    /// start call.
    AlreadyRunning,
    /// The provider observed an in-progress start and issued no start call.
    AlreadyStarting,
}

/// Provider-authenticated identity of the process observed behind one exact
/// SCM service runtime.  PID alone is never sufficient: the provider binds
/// the creation time and image path through the same process query.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationServiceProcessLineage {
    /// Live process identifier used only together with the other fields.
    pub process_id: u32,
    /// Provider-observed process creation time in 100ns units.
    pub start_time_100ns: u64,
    /// Provider-observed executable image path.
    pub image_path: PlatformHandle,
}

impl InstallationServiceProcessLineage {
    fn from_provider(process: &eliot_platform_windows::ProcessIdentity) -> Result<Self, PortError> {
        let image_path = PlatformHandle::new(process.image_path.clone())
            .map_err(|_| PortError::InvalidRequestMetadata)?;
        let lineage = Self {
            process_id: process.process_id,
            start_time_100ns: process.start_time_100ns,
            image_path,
        };
        lineage
            .validate()
            .map_err(|_| PortError::InvalidRequestMetadata)?;
        Ok(lineage)
    }

    fn validate(&self) -> Result<(), InstallationError> {
        if self.process_id == 0 || self.start_time_100ns == 0 {
            return Err(InstallationError::InvalidField {
                field: "service_runtime_lineage".to_owned(),
                reason:
                    "provider-authenticated process identity requires non-zero PID and start time"
                        .to_owned(),
            });
        }
        approved_path(&self.image_path, "service_runtime_lineage.image_path")
    }
}

/// Durable proof that one exact `StartServiceW` mutation was issued by this
/// transaction's provider call.  The proof intentionally has no
/// `AlreadyRunning` or `AlreadyStarting` variant: those dispositions never
/// establish transaction ownership.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationServiceStartProof {
    /// Digest of the exact intent request committed immediately before the
    /// provider issued `StartServiceW`.
    pub intent_digest: PlatformHandle,
    /// Exact provider-authenticated process lineage, once a non-zero PID is
    /// available. `None` is a PID-0 `START_PENDING` proof: it may remain in a
    /// bounded wait, but it can never adopt a later Running readback, even in
    /// the same coordinator.
    pub process_lineage: Option<InstallationServiceProcessLineage>,
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
    /// Typed Host Phase-B receipt returned only by `MaterializePhaseB`.
    pub phase_b_receipt: Option<HostPhaseBMaterializationReceipt>,
    /// Provider-owned disposition for one `StartService` apply call.  This is
    /// deliberately transient: an authoritative running readback alone must
    /// never be used to infer transaction ownership after a response is lost.
    #[serde(skip)]
    pub service_start_disposition: Option<InstallationServiceStartDisposition>,
    /// Provider-authenticated process lineage returned by a caller-issued
    /// `StartService` call when the service is already fully Running.
    #[serde(skip)]
    pub service_runtime_lineage: Option<InstallationServiceProcessLineage>,
}

/// Object-safe adapter seam for bounded installation effects.
pub(crate) trait InstallationEffectPort: Send {
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

    /// Generates and retains one opaque secret while returning only its
    /// non-secret creation proof for durable intent persistence.
    fn prepare_ownership_secret(
        &mut self,
        _request: &InstallationEffectRequest,
        _reference: &InstallationSecretReference,
    ) -> PortOutcome<InstallationSecretCreationProof> {
        PortOutcome::Unknown(UnknownReason::Unsupported)
    }

    /// Creates or reopens the installer-held ownership key only after its
    /// exact reference and effect intent were durably committed.
    fn provision_ownership_secret(
        &mut self,
        _request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationSecretProvisionDisposition> {
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
struct WindowsInstallationEffectPort {
    primitive: WindowsInstallerRootPrimitive,
    secrets: WindowsInstallerSecretProvider,
    prepared_ownership_secret: Option<PreparedOwnershipSecret>,
    store_target_generator: WindowsStoreCredentialTargetGenerator,
    supervision_keys: WindowsSupervisionAuthorityKeyStore,
}

struct PreparedOwnershipSecret {
    reference: InstallationSecretReference,
    proof: InstallationSecretCreationProof,
    secret: CredentialSecret,
}

impl WindowsInstallationEffectPort {
    const fn new() -> Self {
        Self {
            primitive: WindowsInstallerRootPrimitive::new(),
            secrets: WindowsInstallerSecretProvider::new(),
            prepared_ownership_secret: None,
            store_target_generator: WindowsStoreCredentialTargetGenerator::new(),
            supervision_keys: WindowsSupervisionAuthorityKeyStore::new(),
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

    fn service_start_context(
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
            InstallerEffectPlan::StartService {
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
                InstallerServiceRole::Host => ELIOT_HOST_SERVICE_DISPLAY_NAME,
                InstallerServiceRole::Watchdog => ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
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
                .with_expected_runtime_identity_digest(expected.as_str())
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
            .secret_provision_disposition;
        if disposition != InstallationSecretProvisionDisposition::Created {
            return Err(eliot_platform_windows::WindowsAdapterError::InvalidInput);
        }
        let ownership = request
            .ownership_secret
            .as_ref()
            .ok_or(eliot_platform_windows::WindowsAdapterError::InvalidInput)?;
        let secret = self.secrets.read(reference)?;
        if !ownership_secret_creation_proof_matches(request, ownership, secret.expose()) {
            return Err(eliot_platform_windows::WindowsAdapterError::IdentityMismatch);
        }
        Ok(secret)
    }

    fn host_credential_request(
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
            phase_b: None,
            phase_b_final: None,
        };
        value
            .validate()
            .map_err(|_| PortError::InvalidRequestMetadata)?;
        Ok(value)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "W3-02 will extract the Phase-B capability cell"
    )]
    fn phase_b_request(
        &self,
        request: &InstallationEffectRequest,
        operation: HostCredentialControlOperation,
    ) -> Result<HostCredentialControlRequest, PortError> {
        let InstallerEffectPlan::MaterializePhaseB {
            candidate_manifest_digest,
            static_template,
            host_state_root_digest,
            watchdog_selector_digest,
            supervision_authority,
            provision,
            agent_bridge_source,
            ..
        } = &request.plan
        else {
            return Err(PortError::InvalidRequestMetadata);
        };
        let receipt = request
            .store_credential
            .as_ref()
            .and_then(|progress| progress.receipt.as_ref())
            .ok_or(PortError::InvalidRequestMetadata)?;
        receipt
            .validate()
            .map_err(|_| PortError::InvalidRequestMetadata)?;
        let credential_receipt_digest = phase_b_credential_receipt_digest(receipt)
            .map_err(|_| PortError::InvalidRequestMetadata)?;
        let mut ownership_key = self.credential_secret(request)?;
        let host_service_sid =
            resolve_service_sid(supervision_authority.host_service_name.as_str())
                .map_err(secret_port_error)?;
        let profile_anchor =
            protected_program_data_root().map_err(|_| PortError::InvalidRequestMetadata)?;
        let spec = InstallerRootPrimitiveSpec {
            root: PathBuf::from(supervision_authority.kernel_root.as_str()),
            installation_root: PathBuf::from(request.installation_root.as_str()),
            profile_anchor,
            profile: InstallerRootProfile::SystemService,
        };
        let key_request = SupervisionAuthorityKeyStoreRequest {
            transaction_id: request.transaction_id.as_str().to_owned(),
            effect_id: request.effect_id.as_str().to_owned(),
            installation_plan_digest: request.plan_digest.as_str().to_owned(),
            installation_id: supervision_authority.installation_id.as_str().to_owned(),
            candidate_generation: supervision_authority
                .candidate_generation
                .as_str()
                .to_owned(),
            authority_generation: supervision_authority.authority_generation,
            supervision_lease_scope_id: supervision_authority
                .supervision_lease_scope_id
                .as_str()
                .to_owned(),
            signer_id: supervision_authority.signer_id.as_str().to_owned(),
            key_id: supervision_authority.key_id.as_str().to_owned(),
            kernel_root: PathBuf::from(supervision_authority.kernel_root.as_str()),
            relative_path: supervision_authority
                .sealed_key_relative_path
                .as_str()
                .to_owned(),
            expected_host_service_sid: host_service_sid,
        };
        let provisioned_result = match operation {
            HostCredentialControlOperation::MaterializePhaseB => self
                .supervision_keys
                .create_or_reconcile(&spec, &key_request, &ownership_key),
            HostCredentialControlOperation::ReconcilePhaseB => {
                self.supervision_keys
                    .inspect(&spec, &key_request, &ownership_key)
            }
            _ => return Err(PortError::InvalidRequestMetadata),
        };
        ownership_key.fill(0);
        let provisioned_supervision_authority =
            provisioned_result.map_err(supervision_key_port_error)?;
        let phase_b = HostPhaseBMaterializationIntent::new(
            request.transaction_id.clone(),
            request.effect_id.clone(),
            receipt.effect_id.clone(),
            request.plan_digest.clone(),
            candidate_manifest_digest.clone(),
            credential_receipt_digest,
            host_state_root_digest.clone(),
            static_template.clone(),
            watchdog_selector_digest.clone(),
            agent_bridge_source.clone(),
            provisioned_supervision_authority,
        )
        .map_err(|_| PortError::InvalidRequestMetadata)?;
        let intent = HostCredentialControlIntent::new(
            operation,
            request.transaction_id.clone(),
            request.effect_id.clone(),
            provision.as_ref().clone(),
            request.plan_digest.clone(),
        )
        .map_err(|_| PortError::InvalidRequestMetadata)?;
        let value = HostCredentialControlRequest {
            intent,
            ownership_key: Vec::new(),
            expected_receipt: Some(receipt.clone()),
            phase_b: Some(phase_b),
            phase_b_final: None,
        };
        value
            .validate()
            .map_err(|_| PortError::InvalidRequestMetadata)?;
        Ok(value)
    }

    #[allow(
        clippy::manual_let_else,
        clippy::match_same_arms,
        clippy::needless_return,
        clippy::too_many_lines,
        reason = "the two-phase provider handoff keeps validation, convergence and FinalizePhaseB together"
    )]
    fn call_phase_b_host(
        &self,
        request: &InstallationEffectRequest,
        operation: HostCredentialControlOperation,
    ) -> PortOutcome<HostPhaseBMaterializationReceipt> {
        let host_request = match self.phase_b_request(request, operation) {
            Ok(request) => request,
            Err(error) => return PortOutcome::Error(error),
        };
        match self.call_credential_host(&host_request) {
            Ok(HostCredentialControlResponse::PhaseBReady { receipt })
                if operation == HostCredentialControlOperation::ReconcilePhaseB =>
            {
                return if receipt.validate().is_ok() {
                    PortOutcome::Known(*receipt)
                } else {
                    PortOutcome::Unknown(UnknownReason::Indeterminate)
                };
            }
            Ok(HostCredentialControlResponse::PhaseBReady { .. })
                if operation == HostCredentialControlOperation::MaterializePhaseB =>
            {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            Ok(HostCredentialControlResponse::PhaseBPrepared { receipt })
                if matches!(
                    operation,
                    HostCredentialControlOperation::MaterializePhaseB
                        | HostCredentialControlOperation::ReconcilePhaseB
                ) =>
            {
                let Some(intent) = host_request.phase_b.as_ref() else {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                };
                if receipt.validate().is_err()
                    || receipt.transaction_id != intent.transaction_id
                    || receipt.effect_id != intent.effect_id
                    || receipt.candidate_manifest_digest != intent.candidate_manifest_digest
                    || receipt.request_digest != intent.request_digest
                    || receipt.provisioned_supervision_authority
                        != intent.provisioned_supervision_authority
                {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                }
                let mut final_bridge = None;
                if let Some(source) = intent.agent_bridge_source.as_ref() {
                    let Some(binding) = receipt.agent_bridge.as_ref() else {
                        return PortOutcome::Unknown(UnknownReason::Indeterminate);
                    };
                    let Some(bridge_directory) = Path::new(binding.profile_path.as_str()).parent()
                    else {
                        return PortOutcome::Unknown(UnknownReason::Indeterminate);
                    };
                    let Some(host_state_root) = bridge_directory.parent() else {
                        return PortOutcome::Unknown(UnknownReason::Indeterminate);
                    };
                    let acl = eliot_platform_windows::converge_agent_bridge_security(
                        host_state_root,
                        &source.approved_user_sid,
                        Path::new(binding.profile_path.as_str()),
                        Path::new(binding.declaration_path.as_str()),
                    );
                    let Ok(acl) = acl else {
                        return PortOutcome::Unknown(UnknownReason::Indeterminate);
                    };
                    let root_handle = PlatformHandle::new(host_state_root.to_string_lossy());
                    let child_handle = PlatformHandle::new(bridge_directory.to_string_lossy());
                    let (Ok(root_handle), Ok(child_handle)) = (root_handle, child_handle) else {
                        return PortOutcome::Unknown(UnknownReason::Indeterminate);
                    };
                    let Ok(final_binding) = binding.with_final_security(
                        &source.approved_user_sid,
                        root_handle,
                        child_handle,
                        &acl,
                    ) else {
                        return PortOutcome::Unknown(UnknownReason::Indeterminate);
                    };
                    final_bridge = Some(final_binding);
                }
                let mut final_receipt = HostPhaseBMaterializationReceipt {
                    wire: PlatformHandle::new(HostPhaseBMaterializationReceipt::WIRE)
                        .map_err(|_| PortError::InvalidRequestMetadata)
                        .ok()
                        .unwrap_or_else(|| unreachable!()),
                    transaction_id: receipt.transaction_id.clone(),
                    effect_id: receipt.effect_id.clone(),
                    candidate_manifest_digest: receipt.candidate_manifest_digest.clone(),
                    request_digest: receipt.request_digest.clone(),
                    host_owner_epoch: receipt.host_owner_epoch.clone(),
                    host_process_identity: receipt.host_process_identity.clone(),
                    authority_descriptor_digest: receipt.authority_descriptor_digest.clone(),
                    config_file_digest: receipt.config_file_digest.clone(),
                    store_bootstrap_descriptor_digest: receipt
                        .store_bootstrap_descriptor_digest
                        .clone(),
                    eliotd_descriptor_digest: receipt.eliotd_descriptor_digest.clone(),
                    provisioned_supervision_authority: receipt
                        .provisioned_supervision_authority
                        .clone(),
                    agent_bridge: final_bridge,
                    receipt_digest: PlatformHandle::new("pending")
                        .map_err(|_| PortError::InvalidRequestMetadata)
                        .ok()
                        .unwrap_or_else(|| unreachable!()),
                };
                final_receipt.receipt_digest = match final_receipt.computed_digest() {
                    Ok(digest) => digest,
                    Err(_) => return PortOutcome::Unknown(UnknownReason::Indeterminate),
                };
                if final_receipt.validate().is_err() {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                }
                let Some(phase_b) = host_request.phase_b.clone() else {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                };
                let finalize_intent = match HostCredentialControlIntent::new(
                    HostCredentialControlOperation::FinalizePhaseB,
                    host_request.intent.transaction_id.clone(),
                    host_request.intent.effect_id.clone(),
                    host_request.intent.provision.clone(),
                    host_request.intent.installation_plan_digest.clone(),
                ) {
                    Ok(value) => value,
                    Err(_) => return PortOutcome::Unknown(UnknownReason::Indeterminate),
                };
                let finalize_request = HostCredentialControlRequest {
                    intent: finalize_intent,
                    ownership_key: Vec::new(),
                    expected_receipt: host_request.expected_receipt.clone(),
                    phase_b: Some(phase_b),
                    phase_b_final: Some(Box::new(final_receipt)),
                };
                if finalize_request.validate().is_err() {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                }
                match self.call_credential_host(&finalize_request) {
                    Ok(HostCredentialControlResponse::PhaseBReady { receipt })
                        if receipt.validate().is_ok() =>
                    {
                        PortOutcome::Known(*receipt)
                    }
                    Ok(_) | Err(_) => PortOutcome::Unknown(UnknownReason::Indeterminate),
                }
            }
            Ok(HostCredentialControlResponse::Unknown { .. }) => {
                PortOutcome::Unknown(UnknownReason::Indeterminate)
            }
            Ok(_) => PortOutcome::Unknown(UnknownReason::Indeterminate),
            Err(PortError::Provider(provider)) if provider.retryable => {
                PortOutcome::Unknown(UnknownReason::Indeterminate)
            }
            Err(error) => PortOutcome::Error(error),
        }
    }

    fn execute_phase_b(
        &self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectExecution> {
        if request.action != InstallationEffectAction::Apply {
            return PortOutcome::Error(PortError::InvalidRequestMetadata);
        }
        match self.call_phase_b_host(request, HostCredentialControlOperation::MaterializePhaseB) {
            PortOutcome::Known(receipt) => PortOutcome::Known(InstallationEffectExecution {
                evidence: vec![
                    receipt.receipt_digest.clone(),
                    receipt.config_file_digest.clone(),
                    receipt.authority_descriptor_digest.clone(),
                    receipt.store_bootstrap_descriptor_digest.clone(),
                    receipt.eliotd_descriptor_digest.clone(),
                ],
                create_disposition: None,
                credential_receipt: None,
                staging_receipt: None,
                phase_b_receipt: Some(receipt),
                service_start_disposition: None,
                service_runtime_lineage: None,
            }),
            PortOutcome::Unknown(reason) => PortOutcome::Unknown(reason),
            PortOutcome::Partial { .. } => PortOutcome::Unknown(UnknownReason::Indeterminate),
            PortOutcome::Error(error) => PortOutcome::Error(error),
        }
    }

    fn reconcile_phase_b(
        &self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectObservation> {
        match self.call_phase_b_host(request, HostCredentialControlOperation::ReconcilePhaseB) {
            PortOutcome::Known(receipt) => {
                let digest = receipt.receipt_digest.clone();
                let external_identity = PlatformHandle::new(format!("phase-b:{digest}"))
                    .unwrap_or_else(|_| unreachable!());
                PortOutcome::Known(InstallationEffectObservation::Matching {
                    disposition: InstallationEffectDisposition::CreatedByTransaction,
                    external_identity,
                    evidence: vec![
                        digest.clone(),
                        receipt.config_file_digest.clone(),
                        receipt.authority_descriptor_digest.clone(),
                        receipt.store_bootstrap_descriptor_digest.clone(),
                        receipt.eliotd_descriptor_digest.clone(),
                    ],
                    postcondition_digest: digest,
                    service_control_grant: None,
                    credential_receipt: None,
                    staging_receipt: None,
                    phase_b_receipt: Some(Box::new(receipt)),
                    service_runtime_lineage: None,
                })
            }
            PortOutcome::Unknown(reason) => PortOutcome::Unknown(reason),
            PortOutcome::Partial { .. } => PortOutcome::Unknown(UnknownReason::Indeterminate),
            PortOutcome::Error(error) => PortOutcome::Error(error),
        }
    }

    fn inspect_phase_b(
        request: &InstallationEffectRequest,
    ) -> Result<InstallationEffectObservation, PortError> {
        request
            .store_credential
            .as_ref()
            .and_then(|progress| progress.receipt.as_ref())
            .ok_or(PortError::InvalidRequestMetadata)?
            .validate()
            .map_err(|_| PortError::InvalidRequestMetadata)?;
        Ok(InstallationEffectObservation::Absent {
            observed_precondition: request.precondition.clone(),
            evidence: vec![
                PlatformHandle::new(format!("phase-b-pending:{}", request.effect_id.as_str()))
                    .unwrap_or_else(|_| unreachable!()),
            ],
            service_runtime_lineage: None,
        })
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
                            HostCredentialControlResponse::PhaseBPrepared { receipt } => {
                                receipt.host_process_identity == host_process_digest
                            }
                            HostCredentialControlResponse::PhaseBReady { receipt } => {
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
        if ownership.secret_provision_disposition != InstallationSecretProvisionDisposition::Created
            || ownership.lifecycle == InstallationSecretLifecycle::Deleted
        {
            return Err(PortError::InvalidRequestMetadata);
        }
        self.ensure_secret(request)
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
                if ownership.secret_provision_disposition
                    != InstallationSecretProvisionDisposition::Created
                {
                    return Ok(root_mismatch("created-without-durable-secret-proof"));
                }
                let secret = self.ensure_secret(request).map_err(secret_port_error)?;
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
            ServiceRegistrationInspection::Matching { control_grant, .. } => {
                let digest = registration.expected_configuration_digest();
                let control_grant = control_grant
                    .as_ref()
                    .map(InstallerServiceControlGrantReceipt::from_readback)
                    .transpose()
                    .map_err(|_| PortError::InvalidRequestMetadata)?;
                match service_marker_read(
                    &self.primitive,
                    &spec,
                    request,
                    &service_name,
                    &digest,
                    control_grant.as_ref(),
                )? {
                    Some(_) => Ok(root_mismatch("service-marker-before-intent")),
                    None => service_matching_observation(
                        request,
                        InstallationEffectDisposition::PreexistingMatching,
                        &digest,
                        &PlatformHandle::new("service-preexisting-marker-absent")
                            .map_err(|_| PortError::InvalidRequestMetadata)?,
                        control_grant,
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
            ServiceRegistrationInspection::Matching { control_grant, .. } => {
                let control_grant = control_grant
                    .as_ref()
                    .map(InstallerServiceControlGrantReceipt::from_readback)
                    .transpose()
                    .map_err(|_| PortError::InvalidRequestMetadata)?;
                let marker = if let Some(marker) = service_marker_read(
                    &self.primitive,
                    &spec,
                    request,
                    &service_name,
                    &digest,
                    control_grant.as_ref(),
                )? {
                    marker
                } else {
                    let marker = WindowsServiceOwnershipMarker::new(
                        request,
                        &service_name,
                        &digest,
                        control_grant.as_ref(),
                    )?;
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
                    service_marker_read(
                        &self.primitive,
                        &spec,
                        request,
                        &service_name,
                        &digest,
                        control_grant.as_ref(),
                    )?
                    .ok_or(PortError::InvalidRequestMetadata)?
                };
                let (_, marker) = marker;
                let marker_digest = marker.digest()?;
                service_matching_observation(
                    request,
                    InstallationEffectDisposition::CreatedByTransaction,
                    &digest,
                    &marker_digest,
                    control_grant,
                )
            }
            ServiceRegistrationInspection::Mismatched => Ok(root_mismatch("service-config")),
            ServiceRegistrationInspection::Unknown => Ok(root_mismatch("service-readback")),
        }
    }

    fn service_start_running_observation(
        request: &InstallationEffectRequest,
        registration: &ServiceRegistrationRequest,
        observation: &eliot_platform_windows::ServiceRuntimeObservation,
        disposition: InstallationEffectDisposition,
    ) -> Result<InstallationEffectObservation, PortError> {
        if !observation.is_running()
            || observation.configuration_digest() != registration.expected_configuration_digest()
        {
            return Ok(root_mismatch("service-runtime-not-running"));
        }
        let process = observation
            .process()
            .ok_or(PortError::InvalidRequestMetadata)?;
        let service_runtime_lineage =
            Some(InstallationServiceProcessLineage::from_provider(process)?);
        let external_identity = PlatformHandle::new(sha256_hex(
            format!(
                "{}:{}:{}:{}",
                registration.expected_configuration_digest(),
                process.process_id,
                process.start_time_100ns,
                process.image_path
            )
            .as_bytes(),
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)?;
        if request.action == InstallationEffectAction::Rollback
            && request.expected_external_identity.as_ref() != Some(&external_identity)
        {
            return Ok(root_mismatch("service-pid-substituted"));
        }
        let evidence = PlatformHandle::new(sha256_hex(
            format!(
                "service-running:{}:{}:{}:{}",
                registration.service_name(),
                process.process_id,
                process.start_time_100ns,
                process.image_path
            )
            .as_bytes(),
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)?;
        let postcondition_digest = PlatformHandle::new(sha256_hex(
            format!(
                "post:{}:{}:{}:{}",
                registration.expected_configuration_digest(),
                process.process_id,
                process.start_time_100ns,
                process.image_path
            )
            .as_bytes(),
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)?;
        Ok(InstallationEffectObservation::Matching {
            disposition,
            external_identity,
            evidence: vec![evidence],
            postcondition_digest,
            service_control_grant: None,
            credential_receipt: None,
            staging_receipt: None,
            phase_b_receipt: None,
            service_runtime_lineage,
        })
    }

    fn service_start_absent(
        request: &InstallationEffectRequest,
        registration: &ServiceRegistrationRequest,
        reason: &str,
        service_runtime_lineage: Option<InstallationServiceProcessLineage>,
    ) -> Result<InstallationEffectObservation, PortError> {
        let evidence = PlatformHandle::new(format!("{reason}:{}", registration.service_name()))
            .map_err(|_| PortError::InvalidRequestMetadata)?;
        Ok(InstallationEffectObservation::Absent {
            observed_precondition: request.precondition.clone(),
            evidence: vec![evidence],
            service_runtime_lineage,
        })
    }

    fn service_runtime_identity_evidence(
        registration: &ServiceRegistrationRequest,
        observation: &eliot_platform_windows::ServiceRuntimeObservation,
    ) -> Result<PlatformHandle, PortError> {
        let process = observation
            .process()
            .ok_or(PortError::InvalidRequestMetadata)?;
        let identity = sha256_hex(
            format!(
                "{}:{}:{}:{}",
                registration.expected_configuration_digest(),
                process.process_id,
                process.start_time_100ns,
                process.image_path
            )
            .as_bytes(),
        );
        PlatformHandle::new(format!("service-runtime-identity:{identity}"))
            .map_err(|_| PortError::InvalidRequestMetadata)
    }

    #[allow(
        clippy::unused_self,
        reason = "the sealed effect-port receiver keeps StartService context behind one adapter"
    )]
    fn service_start_inspect(
        &self,
        request: &InstallationEffectRequest,
    ) -> Result<InstallationEffectObservation, PortError> {
        let (platform, registration, _) = Self::service_start_context(request)?;
        match platform.inspect_service_registration_runtime(&registration) {
            ServiceRegistrationRuntimeInspection::Matching { observation }
                if observation.is_running() =>
            {
                Self::service_start_running_observation(
                    request,
                    &registration,
                    &observation,
                    InstallationEffectDisposition::PreexistingMatching,
                )
            }
            ServiceRegistrationRuntimeInspection::Matching { observation }
                if observation.is_stopped() =>
            {
                Self::service_start_absent(request, &registration, "service-stopped", None)
            }
            ServiceRegistrationRuntimeInspection::Matching { .. } => {
                Ok(root_mismatch("service-state-indeterminate"))
            }
            ServiceRegistrationRuntimeInspection::Absent => Ok(root_mismatch("service-missing")),
            ServiceRegistrationRuntimeInspection::Mismatched => Ok(root_mismatch("service-config")),
            ServiceRegistrationRuntimeInspection::Unknown => Ok(root_mismatch("service-readback")),
        }
    }

    #[allow(
        clippy::unused_self,
        reason = "the sealed effect-port receiver keeps StartService context behind one adapter"
    )]
    fn service_start_reconcile(
        &self,
        request: &InstallationEffectRequest,
    ) -> Result<InstallationEffectObservation, PortError> {
        let (platform, registration, _) = Self::service_start_context(request)?;
        match platform.inspect_service_registration_runtime(&registration) {
            ServiceRegistrationRuntimeInspection::Matching { observation }
                if observation.is_running() =>
            {
                let running = Self::service_start_running_observation(
                    request,
                    &registration,
                    &observation,
                    InstallationEffectDisposition::CreatedByTransaction,
                )?;
                if let Some(expected) = request.expected_external_identity.as_ref()
                    && !matches!(
                        &running,
                        InstallationEffectObservation::Matching {
                            external_identity,
                            ..
                        } if external_identity == expected
                    )
                {
                    return Ok(root_mismatch("service-pid-substituted"));
                }
                Ok(running)
            }
            ServiceRegistrationRuntimeInspection::Matching { observation }
                if observation.is_starting()
                    && request.action == InstallationEffectAction::Apply =>
            {
                Self::service_start_absent(
                    request,
                    &registration,
                    "service-starting",
                    Self::service_process_lineage_if_available(&observation)?,
                )
            }
            ServiceRegistrationRuntimeInspection::Matching { observation }
                if observation.is_stopped()
                    && request.action == InstallationEffectAction::Rollback =>
            {
                Self::service_start_absent(request, &registration, "service-stopped", None)
            }
            ServiceRegistrationRuntimeInspection::Matching { .. } => {
                Ok(root_mismatch("service-state-indeterminate"))
            }
            ServiceRegistrationRuntimeInspection::Absent => Ok(root_mismatch("service-missing")),
            ServiceRegistrationRuntimeInspection::Mismatched => Ok(root_mismatch("service-config")),
            ServiceRegistrationRuntimeInspection::Unknown => Ok(root_mismatch("service-readback")),
        }
    }

    fn service_process_lineage(
        observation: &eliot_platform_windows::ServiceRuntimeObservation,
    ) -> Result<InstallationServiceProcessLineage, PortError> {
        let process = observation
            .process()
            .ok_or(PortError::InvalidRequestMetadata)?;
        InstallationServiceProcessLineage::from_provider(process)
    }

    fn service_process_lineage_if_available(
        observation: &eliot_platform_windows::ServiceRuntimeObservation,
    ) -> Result<Option<InstallationServiceProcessLineage>, PortError> {
        observation
            .process()
            .map(InstallationServiceProcessLineage::from_provider)
            .transpose()
    }

    #[allow(
        clippy::too_many_lines,
        clippy::unused_self,
        reason = "ordered SCM preflight, one mutation, and authoritative post-readback remain one boundary"
    )]
    fn service_start_execute(
        &self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectExecution> {
        let (platform, registration, _) = match Self::service_start_context(request) {
            Ok(value) => value,
            Err(error) => return PortOutcome::Error(error),
        };
        let inspection = platform.inspect_service_registration_runtime(&registration);
        if request.action == InstallationEffectAction::Apply {
            match inspection {
                ServiceRegistrationRuntimeInspection::Matching { ref observation }
                    if observation.is_running() || observation.is_starting() =>
                {
                    if observation.is_starting() {
                        return PortOutcome::Known(InstallationEffectExecution {
                            evidence: vec![
                                PlatformHandle::new("service-start-already-starting")
                                    .unwrap_or_else(|_| unreachable!()),
                            ],
                            create_disposition: None,
                            credential_receipt: None,
                            staging_receipt: None,
                            phase_b_receipt: None,
                            service_start_disposition: Some(
                                InstallationServiceStartDisposition::AlreadyStarting,
                            ),
                            service_runtime_lineage: None,
                        });
                    }
                    let identity =
                        match Self::service_runtime_identity_evidence(&registration, observation) {
                            Ok(identity) => identity,
                            Err(error) => return PortOutcome::Error(error),
                        };
                    return PortOutcome::Known(InstallationEffectExecution {
                        evidence: vec![
                            PlatformHandle::new(if observation.is_running() {
                                "service-start-already-running"
                            } else {
                                "service-start-already-starting"
                            })
                            .unwrap_or_else(|_| unreachable!()),
                            identity,
                        ],
                        create_disposition: None,
                        credential_receipt: None,
                        staging_receipt: None,
                        phase_b_receipt: None,
                        service_start_disposition: Some(if observation.is_running() {
                            InstallationServiceStartDisposition::AlreadyRunning
                        } else {
                            InstallationServiceStartDisposition::AlreadyStarting
                        }),
                        service_runtime_lineage: if observation.is_running() {
                            Some(match Self::service_process_lineage(observation) {
                                Ok(lineage) => lineage,
                                Err(error) => return PortOutcome::Error(error),
                            })
                        } else {
                            None
                        },
                    });
                }
                ServiceRegistrationRuntimeInspection::Matching { observation }
                    if !observation.is_stopped() =>
                {
                    return PortOutcome::Unknown(UnknownReason::Indeterminate);
                }
                ServiceRegistrationRuntimeInspection::Matching { .. } => {}
                _ => return PortOutcome::Unknown(UnknownReason::Indeterminate),
            }
            return match platform.start_service_registration(&registration) {
                Ok(ServiceStartOutcome::Started { observation }) => {
                    if observation.is_starting() {
                        return PortOutcome::Known(InstallationEffectExecution {
                            evidence: vec![
                                PlatformHandle::new("service-start-ack-starting")
                                    .unwrap_or_else(|_| unreachable!()),
                            ],
                            create_disposition: None,
                            credential_receipt: None,
                            staging_receipt: None,
                            phase_b_receipt: None,
                            service_start_disposition: Some(
                                InstallationServiceStartDisposition::StartedByCaller,
                            ),
                            service_runtime_lineage:
                                match Self::service_process_lineage_if_available(&observation) {
                                    Ok(lineage) => lineage,
                                    Err(error) => return PortOutcome::Error(error),
                                },
                        });
                    }
                    let identity = match Self::service_runtime_identity_evidence(
                        &registration,
                        &observation,
                    ) {
                        Ok(identity) => identity,
                        Err(error) => return PortOutcome::Error(error),
                    };
                    let evidence = if observation.is_running() {
                        "service-start-ack-running"
                    } else {
                        "service-start-ack-starting"
                    };
                    PortOutcome::Known(InstallationEffectExecution {
                        evidence: vec![
                            PlatformHandle::new(evidence).unwrap_or_else(|_| unreachable!()),
                            identity,
                        ],
                        create_disposition: None,
                        credential_receipt: None,
                        staging_receipt: None,
                        phase_b_receipt: None,
                        service_start_disposition: Some(
                            InstallationServiceStartDisposition::StartedByCaller,
                        ),
                        service_runtime_lineage: if observation.is_running() {
                            Some(match Self::service_process_lineage(&observation) {
                                Ok(lineage) => lineage,
                                Err(error) => return PortOutcome::Error(error),
                            })
                        } else {
                            None
                        },
                    })
                }
                Ok(ServiceStartOutcome::AlreadyRunning { observation }) => {
                    let identity = match Self::service_runtime_identity_evidence(
                        &registration,
                        &observation,
                    ) {
                        Ok(identity) => identity,
                        Err(error) => return PortOutcome::Error(error),
                    };
                    PortOutcome::Known(InstallationEffectExecution {
                        evidence: vec![
                            PlatformHandle::new("service-start-race-running")
                                .unwrap_or_else(|_| unreachable!()),
                            identity,
                        ],
                        create_disposition: None,
                        credential_receipt: None,
                        staging_receipt: None,
                        phase_b_receipt: None,
                        service_start_disposition: Some(
                            InstallationServiceStartDisposition::AlreadyRunning,
                        ),
                        service_runtime_lineage: Some(
                            match Self::service_process_lineage(&observation) {
                                Ok(lineage) => lineage,
                                Err(error) => return PortOutcome::Error(error),
                            },
                        ),
                    })
                }
                Ok(ServiceStartOutcome::AlreadyStarting { .. }) => {
                    // A concurrent actor won the stopped->starting race and
                    // this request issued no StartServiceW. Preserve the
                    // typed provider disposition so the coordinator can
                    // durably classify the foreign start as Unknown instead
                    // of treating a generic provider response as a lost call.
                    PortOutcome::Known(InstallationEffectExecution {
                        evidence: vec![
                            PlatformHandle::new("service-start-already-starting")
                                .unwrap_or_else(|_| unreachable!()),
                        ],
                        create_disposition: None,
                        credential_receipt: None,
                        staging_receipt: None,
                        phase_b_receipt: None,
                        service_start_disposition: Some(
                            InstallationServiceStartDisposition::AlreadyStarting,
                        ),
                        service_runtime_lineage: None,
                    })
                }
                Ok(ServiceStartOutcome::EffectUnknown) => {
                    PortOutcome::Unknown(UnknownReason::Indeterminate)
                }
                Err(error) => PortOutcome::Error(PortError::Provider(ProviderError {
                    code: match error {
                        eliot_platform_windows::WindowsAdapterError::PermissionDenied => {
                            ProviderErrorCode::PermissionDenied
                        }
                        eliot_platform_windows::WindowsAdapterError::Timeout => {
                            ProviderErrorCode::Timeout
                        }
                        _ => ProviderErrorCode::Unavailable,
                    },
                    retryable: false,
                })),
            };
        }

        match inspection {
            ServiceRegistrationRuntimeInspection::Matching { ref observation }
                if observation.is_stopped() =>
            {
                return PortOutcome::Known(InstallationEffectExecution {
                    evidence: vec![
                        PlatformHandle::new("service-already-stopped")
                            .unwrap_or_else(|_| unreachable!()),
                    ],
                    create_disposition: None,
                    credential_receipt: None,
                    staging_receipt: None,
                    phase_b_receipt: None,
                    service_start_disposition: None,
                    service_runtime_lineage: None,
                });
            }
            ServiceRegistrationRuntimeInspection::Matching { ref observation }
                if observation.is_starting() || observation.is_stopping() =>
            {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            ServiceRegistrationRuntimeInspection::Matching { ref observation }
                if observation.is_running() => {}
            _ => return PortOutcome::Unknown(UnknownReason::Indeterminate),
        }
        match platform.stop_service_registration(&registration) {
            Ok(
                ServiceStopOutcome::Stopped { .. }
                | ServiceStopOutcome::AlreadyStopped { .. }
                | ServiceStopOutcome::AlreadyStopping { .. },
            ) => PortOutcome::Known(InstallationEffectExecution {
                evidence: vec![
                    PlatformHandle::new("service-stop-ack").unwrap_or_else(|_| unreachable!()),
                ],
                create_disposition: None,
                credential_receipt: None,
                staging_receipt: None,
                phase_b_receipt: None,
                service_start_disposition: None,
                service_runtime_lineage: None,
            }),
            Ok(ServiceStopOutcome::EffectUnknown) => {
                PortOutcome::Unknown(UnknownReason::Indeterminate)
            }
            Err(error) => PortOutcome::Error(PortError::Provider(ProviderError {
                code: match error {
                    eliot_platform_windows::WindowsAdapterError::PermissionDenied => {
                        ProviderErrorCode::PermissionDenied
                    }
                    eliot_platform_windows::WindowsAdapterError::Timeout => {
                        ProviderErrorCode::Timeout
                    }
                    _ => ProviderErrorCode::Unavailable,
                },
                retryable: false,
            })),
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
        let host_request = Self::host_credential_request(request, operation, ownership_key)?;
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
                    service_runtime_lineage: None,
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
                    service_control_grant: None,
                    credential_receipt: Some(receipt),
                    staging_receipt: None,
                    phase_b_receipt: None,
                    service_runtime_lineage: None,
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
                    service_runtime_lineage: None,
                })
            }
            HostCredentialControlResponse::PhaseBReady { .. }
            | HostCredentialControlResponse::PhaseBPrepared { .. } => {
                Err(PortError::IdentityConflict)
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
        let host_request = match Self::host_credential_request(request, operation, key) {
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
                    phase_b_receipt: None,
                    service_start_disposition: None,
                    service_runtime_lineage: None,
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
                    phase_b_receipt: None,
                    service_start_disposition: None,
                    service_runtime_lineage: None,
                })
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
                | InstallerEffectPlan::StagePackage { .. }
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

    fn prepare_ownership_secret(
        &mut self,
        request: &InstallationEffectRequest,
        reference: &InstallationSecretReference,
    ) -> PortOutcome<InstallationSecretCreationProof> {
        if !matches!(
            request.plan,
            InstallerEffectPlan::CreateRoot { .. }
                | InstallerEffectPlan::ProvisionStoreCredential { .. }
                | InstallerEffectPlan::StagePackage { .. }
        ) {
            return PortOutcome::Error(PortError::InvalidRequestMetadata);
        }
        let secret = match self.secrets.generate_secret() {
            Ok(secret) => secret,
            Err(error) => return secret_outcome(error),
        };
        let proof = match ownership_secret_creation_proof(request, reference, secret.expose()) {
            Ok(proof) => proof,
            Err(_error) => return PortOutcome::Error(PortError::InvalidRequestMetadata),
        };
        self.prepared_ownership_secret = Some(PreparedOwnershipSecret {
            reference: reference.clone(),
            proof: proof.clone(),
            secret,
        });
        PortOutcome::Known(proof)
    }

    fn provision_ownership_secret(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationSecretProvisionDisposition> {
        if !matches!(
            request.plan,
            InstallerEffectPlan::CreateRoot { .. }
                | InstallerEffectPlan::ProvisionStoreCredential { .. }
                | InstallerEffectPlan::StagePackage { .. }
        ) {
            return PortOutcome::Error(PortError::InvalidRequestMetadata);
        }
        let Some(ownership) = request.ownership_secret.as_ref() else {
            return PortOutcome::Error(PortError::InvalidRequestMetadata);
        };
        let target = match self.secret_target(request) {
            Ok(target) => target,
            Err(error) => return PortOutcome::Error(error),
        };
        if ownership.secret_provision_disposition
            != InstallationSecretProvisionDisposition::NotAttempted
        {
            return PortOutcome::Error(PortError::InvalidRequestMetadata);
        }
        let result = if let Some(prepared) = self.prepared_ownership_secret.take() {
            if prepared.reference != ownership.reference
                || prepared.proof != ownership.creation_proof
            {
                return PortOutcome::Error(PortError::Provider(ProviderError {
                    code: ProviderErrorCode::Failed,
                    retryable: false,
                }));
            }
            match self.secrets.read_optional(target) {
                Ok(Some(existing)) => {
                    if !ownership_secret_creation_proof_matches(
                        request,
                        ownership,
                        existing.expose(),
                    ) {
                        return PortOutcome::Error(PortError::Provider(ProviderError {
                            code: ProviderErrorCode::Failed,
                            retryable: false,
                        }));
                    }
                    Ok(())
                }
                Ok(None) => {
                    match self.secrets.write_exact_if_absent(target, prepared.secret) {
                        Ok(
                            InstallerSecretCreateDisposition::Created
                            | InstallerSecretCreateDisposition::AlreadyExists,
                        ) => {}
                        Err(error) => return secret_outcome(error),
                    }
                    let readback = match self.secrets.read(target) {
                        Ok(readback) => readback,
                        Err(error) => return secret_outcome(error),
                    };
                    if !ownership_secret_creation_proof_matches(
                        request,
                        ownership,
                        readback.expose(),
                    ) {
                        return PortOutcome::Error(PortError::Provider(ProviderError {
                            code: ProviderErrorCode::Failed,
                            retryable: false,
                        }));
                    }
                    Ok(())
                }
                Err(error) => return secret_outcome(error),
            }
        } else {
            match self.secrets.read_optional(target) {
                Ok(Some(readback))
                    if ownership_secret_creation_proof_matches(
                        request,
                        ownership,
                        readback.expose(),
                    ) =>
                {
                    Ok(())
                }
                Ok(Some(_)) => Err(PortError::Provider(ProviderError {
                    code: ProviderErrorCode::Failed,
                    retryable: false,
                })),
                Ok(None) => return PortOutcome::Unknown(UnknownReason::NotObserved),
                Err(error) => return secret_outcome(error),
            }
        };
        match result {
            Ok(()) => PortOutcome::Known(InstallationSecretProvisionDisposition::Created),
            Err(error) => PortOutcome::Error(error),
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
            let key = match self.credential_secret(request) {
                Ok(key) => key,
                Err(error) => return PortOutcome::Error(error),
            };
            let outcome = execute_package(request, &key);
            return outcome;
        }
        if matches!(&request.plan, InstallerEffectPlan::RegisterService { .. }) {
            return self.execute_service(request);
        }
        if matches!(&request.plan, InstallerEffectPlan::StartService { .. }) {
            return self.service_start_execute(request);
        }
        if matches!(
            request.plan,
            InstallerEffectPlan::ProvisionStoreCredential { .. }
        ) {
            return self.execute_credential(request);
        }
        if matches!(&request.plan, InstallerEffectPlan::MaterializePhaseB { .. }) {
            return self.execute_phase_b(request);
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
                phase_b_receipt: None,
                service_start_disposition: None,
                service_runtime_lineage: None,
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
                let created = match map_root_create_attempt(
                    self.primitive.create_attempt(&spec, &expected),
                ) {
                    Ok(created) => created,
                    Err(outcome) => return *outcome,
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
                        phase_b_receipt: None,
                        service_start_disposition: None,
                        service_runtime_lineage: None,
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
                    Err(error) => {
                        let pending = port_pending(root_execution_error::<()>(error));
                        return PortOutcome::Partial {
                            value: InstallationEffectExecution {
                                evidence: Vec::new(),
                                create_disposition: Some(InstallationCreateDisposition::Created),
                                credential_receipt: None,
                                staging_receipt: None,
                                phase_b_receipt: None,
                                service_start_disposition: None,
                                service_runtime_lineage: None,
                            },
                            missing: vec![pending],
                        };
                    }
                };
                let evidence = PlatformHandle::new(root_marker_digest(&root, &marker))
                    .unwrap_or_else(|_| unreachable!());
                PortOutcome::Known(InstallationEffectExecution {
                    evidence: vec![evidence],
                    create_disposition: Some(InstallationCreateDisposition::Created),
                    credential_receipt: None,
                    staging_receipt: None,
                    phase_b_receipt: None,
                    service_start_disposition: None,
                    service_runtime_lineage: None,
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
                    phase_b_receipt: None,
                    service_start_disposition: None,
                    service_runtime_lineage: None,
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
                phase_b_receipt: None,
                service_start_disposition: None,
                service_runtime_lineage: None,
            });
        }
        let configuration_digest = registration.expected_configuration_digest();
        let control_grant = match platform.register_service(&registration) {
            Ok(ServiceRegistrationOutcome::CreatedNow { control_grant, .. }) => control_grant
                .as_ref()
                .map(InstallerServiceControlGrantReceipt::from_readback)
                .transpose(),
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
        };
        let Ok(control_grant) = control_grant else {
            return PortOutcome::Error(PortError::InvalidRequestMetadata);
        };
        if registration.requires_host_service_control_grant() != control_grant.is_some() {
            return PortOutcome::Unknown(UnknownReason::Indeterminate);
        }
        let marker = match WindowsServiceOwnershipMarker::new(
            request,
            registration.service_name(),
            &configuration_digest,
            control_grant.as_ref(),
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
            phase_b_receipt: None,
            service_start_disposition: None,
            service_runtime_lineage: None,
        })
    }

    fn inspect(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectObservation> {
        let result = if matches!(&request.plan, InstallerEffectPlan::RegisterService { .. }) {
            self.inspect_service(request)
        } else if matches!(&request.plan, InstallerEffectPlan::StartService { .. }) {
            self.service_start_inspect(request)
        } else if matches!(&request.plan, InstallerEffectPlan::StagePackage { .. }) {
            inspect_package(request).map_err(|error| package_port_error(&error))
        } else if matches!(
            request.plan,
            InstallerEffectPlan::ProvisionStoreCredential { .. }
        ) {
            self.credential_observation(request, HostCredentialControlOperation::Inspect)
        } else if matches!(&request.plan, InstallerEffectPlan::MaterializePhaseB { .. }) {
            Self::inspect_phase_b(request)
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
        if matches!(&request.plan, InstallerEffectPlan::MaterializePhaseB { .. }) {
            return self.reconcile_phase_b(request);
        }
        let result = if matches!(&request.plan, InstallerEffectPlan::RegisterService { .. }) {
            self.reconcile_service(request)
        } else if matches!(&request.plan, InstallerEffectPlan::StartService { .. }) {
            self.service_start_reconcile(request)
        } else if matches!(&request.plan, InstallerEffectPlan::StagePackage { .. }) {
            let key = match self.credential_secret(request) {
                Ok(key) => key,
                Err(error) => return PortOutcome::Error(error),
            };
            reconcile_package(request, &key).map_err(|error| package_port_error(&error))
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
        let secret = match self.secrets.read(target) {
            Ok(secret) => secret,
            Err(error) => return secret_outcome(error),
        };
        if !ownership_secret_creation_proof_matches(request, ownership, secret.expose()) {
            return PortOutcome::Error(PortError::Provider(ProviderError {
                code: ProviderErrorCode::Failed,
                retryable: false,
            }));
        }
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

fn ownership_secret_creation_payload(
    request: &InstallationEffectRequest,
    reference: &InstallationSecretReference,
) -> Result<Vec<u8>, InstallationError> {
    serde_json::to_vec(&(
        "eliot.installation.ownership-secret-creation",
        INSTALLATION_SECRET_CREATION_PROOF_VERSION,
        request.transaction_id.as_str(),
        request.effect_id.as_str(),
        request.attempt,
        request.plan_digest.as_str(),
        reference.target.as_str(),
        reference.expected_principal_sid.as_str(),
        reference.scope,
    ))
    .map_err(|error| InstallationError::InvalidField {
        field: "effect_progress.ownership_secret.creation_proof".to_owned(),
        reason: error.to_string(),
    })
}

fn ownership_secret_creation_proof(
    request: &InstallationEffectRequest,
    reference: &InstallationSecretReference,
    secret: &[u8],
) -> Result<InstallationSecretCreationProof, InstallationError> {
    let payload = ownership_secret_creation_payload(request, reference)?;
    let authenticator =
        PlatformHandle::new(hmac_sha256_hex(secret, &payload)).map_err(|error| {
            InstallationError::InvalidField {
                field: "effect_progress.ownership_secret.creation_proof.authenticator".to_owned(),
                reason: error.to_string(),
            }
        })?;
    Ok(InstallationSecretCreationProof {
        version: INSTALLATION_SECRET_CREATION_PROOF_VERSION,
        authenticator,
    })
}

fn ownership_secret_creation_proof_matches(
    request: &InstallationEffectRequest,
    ownership: &InstallationOwnershipSecret,
    secret: &[u8],
) -> bool {
    let Ok(payload) = ownership_secret_creation_payload(request, &ownership.reference) else {
        return false;
    };
    ownership.creation_proof.version == INSTALLATION_SECRET_CREATION_PROOF_VERSION
        && constant_time_equal(
            ownership.creation_proof.authenticator.as_str().as_bytes(),
            hmac_sha256_hex(secret, &payload).as_bytes(),
        )
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
        InstallerEffectPlan::RegisterService { .. }
        | InstallerEffectPlan::MaterializePhaseB { .. } => {
            Path::new(request.installation_root.as_str())
        }
        InstallerEffectPlan::StartService { .. } => Path::new(request.installation_root.as_str()),
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
        service_runtime_lineage: None,
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
        service_control_grant: None,
        credential_receipt: None,
        staging_receipt: None,
        phase_b_receipt: None,
        service_runtime_lineage: None,
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
        service_control_grant: None,
        credential_receipt: None,
        staging_receipt: None,
        phase_b_receipt: None,
        service_runtime_lineage: None,
    })
}

fn root_mismatch(reason: &str) -> InstallationEffectObservation {
    InstallationEffectObservation::Mismatch {
        pending_ref: PlatformHandle::new(format!("mismatch:installer-root:{reason}"))
            .unwrap_or_else(|_| unreachable!()),
    }
}

const SERVICE_MARKER_VERSION: u32 = 2;
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
    service_control_grant_digest: Option<String>,
}

impl WindowsServiceOwnershipMarker {
    fn new(
        request: &InstallationEffectRequest,
        service_name: &str,
        configuration_digest: &str,
        service_control_grant: Option<&InstallerServiceControlGrantReceipt>,
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
            service_control_grant_digest: service_control_grant
                .map(InstallerServiceControlGrantReceipt::canonical_digest)
                .transpose()
                .map_err(|_| PortError::InvalidRequestMetadata)?
                .map(|digest| digest.as_str().to_owned()),
        })
    }

    fn matches(
        &self,
        request: &InstallationEffectRequest,
        service_name: &str,
        digest: &str,
        service_control_grant: Option<&InstallerServiceControlGrantReceipt>,
    ) -> bool {
        let control_grant_digest = service_control_grant
            .map(InstallerServiceControlGrantReceipt::canonical_digest)
            .transpose()
            .ok()
            .flatten()
            .map(|digest| digest.as_str().to_owned());
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
            && self.service_control_grant_digest == control_grant_digest
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
            "service-marker-v2\0{}\0{}\0{}\0{}",
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
    service_control_grant: Option<&InstallerServiceControlGrantReceipt>,
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
    if !marker.matches(
        request,
        service_name,
        configuration_digest,
        service_control_grant,
    ) {
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
        service_runtime_lineage: None,
    })
}

fn service_matching_observation(
    request: &InstallationEffectRequest,
    disposition: InstallationEffectDisposition,
    configuration_digest: &str,
    marker_digest: &PlatformHandle,
    service_control_grant: Option<InstallerServiceControlGrantReceipt>,
) -> Result<InstallationEffectObservation, PortError> {
    let external_identity =
        PlatformHandle::new(configuration_digest).map_err(|_| PortError::InvalidRequestMetadata)?;
    let control_grant_digest = service_control_grant
        .as_ref()
        .map(InstallerServiceControlGrantReceipt::canonical_digest)
        .transpose()
        .map_err(|_| PortError::InvalidRequestMetadata)?;
    let control_grant_digest_text = control_grant_digest
        .as_ref()
        .map_or("none", PlatformHandle::as_str);
    let evidence = PlatformHandle::new(sha256_hex(
        format!(
            "service-matching-v2\0{}\0{}\0{}\0{}\0{}",
            request.effect_id.as_str(),
            request.plan_digest.as_str(),
            configuration_digest,
            marker_digest.as_str(),
            control_grant_digest_text,
        )
        .as_bytes(),
    ))
    .map_err(|_| PortError::InvalidRequestMetadata)?;
    let postcondition_digest = PlatformHandle::new(sha256_hex(
        format!(
            "service-postcondition-v2\0{}\0{}\0{}\0{}",
            request.effect_id.as_str(),
            configuration_digest,
            marker_digest.as_str(),
            control_grant_digest_text,
        )
        .as_bytes(),
    ))
    .map_err(|_| PortError::InvalidRequestMetadata)?;
    Ok(InstallationEffectObservation::Matching {
        disposition,
        external_identity,
        evidence: std::iter::once(evidence)
            .chain(control_grant_digest)
            .collect(),
        postcondition_digest,
        service_control_grant: service_control_grant.map(Box::new),
        credential_receipt: None,
        staging_receipt: None,
        phase_b_receipt: None,
        service_runtime_lineage: None,
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
        InstallerRootError::Win32 { stage, code } => PortError::ProviderReference {
            error: ProviderError {
                code: ProviderErrorCode::Failed,
                retryable: false,
            },
            reference: installer_root_reference(stage, code),
        },
        _ => PortError::Provider(ProviderError {
            code: ProviderErrorCode::Unavailable,
            retryable: false,
        }),
    }
}

fn installer_root_reference(stage: InstallerRootStage, code: u32) -> PlatformHandle {
    PlatformHandle::new(format!(
        "installer-root-win32-v2:{}:{code:08x}",
        installer_root_stage_token(stage),
    ))
    .unwrap_or_else(|_| unreachable!())
}

fn secret_port_error(error: eliot_platform_windows::WindowsAdapterError) -> PortError {
    PortError::Provider(ProviderError {
        code: match error {
            eliot_platform_windows::WindowsAdapterError::InvalidInput => {
                ProviderErrorCode::InvalidRequest
            }
            eliot_platform_windows::WindowsAdapterError::PermissionDenied => {
                ProviderErrorCode::PermissionDenied
            }
            eliot_platform_windows::WindowsAdapterError::Timeout => ProviderErrorCode::Timeout,
            eliot_platform_windows::WindowsAdapterError::IdentityMismatch
            | eliot_platform_windows::WindowsAdapterError::AclMismatch
            | eliot_platform_windows::WindowsAdapterError::AlreadyExists
            | eliot_platform_windows::WindowsAdapterError::Failed => ProviderErrorCode::Failed,
            eliot_platform_windows::WindowsAdapterError::NotFound
            | eliot_platform_windows::WindowsAdapterError::Unavailable => {
                ProviderErrorCode::Unavailable
            }
        },
        retryable: false,
    })
}

fn supervision_key_port_error(error: SupervisionAuthorityKeyError) -> PortError {
    let code = match error {
        SupervisionAuthorityKeyError::InvalidBinding | SupervisionAuthorityKeyError::KeyInvalid => {
            ProviderErrorCode::InvalidRequest
        }
        SupervisionAuthorityKeyError::AccessDenied => ProviderErrorCode::PermissionDenied,
        SupervisionAuthorityKeyError::RandomUnavailable
        | SupervisionAuthorityKeyError::ProviderUnavailable => ProviderErrorCode::Unavailable,
    };
    PortError::Provider(ProviderError {
        code,
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

fn map_root_create_attempt(
    attempt: Result<InstallerRootCreateAttempt, InstallerRootError>,
) -> Result<InstallerRootPrimitiveCreate, Box<PortOutcome<InstallationEffectExecution>>> {
    match attempt {
        Ok(InstallerRootCreateAttempt::Complete(created)) => Ok(created),
        Ok(InstallerRootCreateAttempt::Failed {
            disposition: InstallerRootCreateDisposition::Created,
            error,
        }) => {
            let pending = port_pending(root_execution_error::<()>(error));
            Err(Box::new(PortOutcome::Partial {
                value: InstallationEffectExecution {
                    evidence: Vec::new(),
                    create_disposition: Some(InstallationCreateDisposition::Created),
                    credential_receipt: None,
                    staging_receipt: None,
                    phase_b_receipt: None,
                    service_start_disposition: None,
                    service_runtime_lineage: None,
                },
                missing: vec![pending],
            }))
        }
        Ok(InstallerRootCreateAttempt::Failed { error, .. }) | Err(error) => {
            Err(Box::new(root_execution_error(error)))
        }
        Ok(InstallerRootCreateAttempt::PreconditionRace { pending_ref }) => {
            Err(Box::new(PortOutcome::Error(PortError::ProviderReference {
                error: ProviderError {
                    code: ProviderErrorCode::Failed,
                    retryable: false,
                },
                reference: PlatformHandle::new(pending_ref).unwrap_or_else(|_| unreachable!()),
            })))
        }
    }
}

fn root_execution_error<T>(error: InstallerRootError) -> PortOutcome<T> {
    match error {
        InstallerRootError::UnsupportedPlatform => PortOutcome::Unknown(UnknownReason::Unsupported),
        InstallerRootError::ReceiptMismatch
        | InstallerRootError::IdentityMismatch
        | InstallerRootError::Indeterminate => PortOutcome::Unknown(UnknownReason::Indeterminate),
        InstallerRootError::Win32 { stage, code } => {
            PortOutcome::Error(PortError::ProviderReference {
                error: ProviderError {
                    code: ProviderErrorCode::Failed,
                    retryable: false,
                },
                reference: installer_root_reference(stage, code),
            })
        }
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

fn installer_root_stage_token(stage: InstallerRootStage) -> &'static str {
    match stage {
        InstallerRootStage::OpenThreadToken => "open-thread-token",
        InstallerRootStage::OpenProcessToken => "open-process-token",
        InstallerRootStage::DuplicateToken => "duplicate-token",
        InstallerRootStage::QueryPrivilege => "query-privilege",
        InstallerRootStage::EnablePrivilege => "enable-privilege",
        InstallerRootStage::BindThreadToken => "bind-thread-token",
        InstallerRootStage::RestorePrivilege => "restore-privilege",
        InstallerRootStage::RestoreThreadToken => "restore-thread-token",
        InstallerRootStage::CreateDirectory => "create-directory",
        InstallerRootStage::CreateProtectedFile => "create-protected-file",
        InstallerRootStage::OpenReadback => "open-readback",
        InstallerRootStage::Readback => "readback",
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
pub(crate) struct InstallationCoordinator<P, S> {
    port: P,
    store: S,
}

fn wall_clock_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().try_into().unwrap_or(u64::MAX)
        })
}

impl<P, S> InstallationCoordinator<P, S>
where
    P: InstallationEffectPort,
    S: InstallationTransactionStore,
{
    /// Creates a coordinator around one platform effect port and durable store.
    #[must_use]
    pub(crate) const fn new(port: P, store: S) -> Self {
        Self { port, store }
    }

    /// Borrows the underlying effect port for composition or inspection.
    #[must_use]
    pub(crate) const fn port(&self) -> &P {
        &self.port
    }

    /// Borrows the underlying durable store.
    #[must_use]
    pub(crate) const fn store(&self) -> &S {
        &self.store
    }

    /// Borrows the durable store mutably for the transaction-owned
    /// activation projection boundary.  The platform effect port remains
    /// private; callers can only use this through a sealed coordinator seam.
    pub(crate) fn store_mut(&mut self) -> &mut S {
        &mut self.store
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
        self.drive_effect_at(transaction_id, wall_clock_millis())
    }

    /// Drives one effect using an injected absolute millisecond clock.
    ///
    /// Production callers use [`Self::drive_effect`].  The explicit clock is
    /// retained as a deterministic seam for bounded SCM-start timeout and
    /// restart tests; it does not alter the durable coordinator ownership.
    #[allow(
        clippy::too_many_lines,
        reason = "ordered crash-window transitions remain in one auditable coordinator boundary"
    )]
    pub fn drive_effect_at(
        &mut self,
        transaction_id: &PlatformHandle,
        now_ms: u64,
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
            InstallerEffectPlan::StartService { .. }
        ) {
            let is_registering_bootstrap = transaction.stage == InstallationStage::Registering
                && (|| {
                    let first = transaction.installer_effects.iter().position(|effect| {
                        matches!(effect, InstallerEffectPlan::StartService { .. })
                    })?;
                    let mut cursor = first;
                    let mut roles = Vec::new();
                    while cursor < transaction.installer_effects.len() {
                        match &transaction.installer_effects[cursor] {
                            InstallerEffectPlan::StartService { role, .. } => {
                                roles.push(*role);
                                cursor += 1;
                            }
                            _ => break,
                        }
                    }
                    if roles != [InstallerServiceRole::Watchdog, InstallerServiceRole::Host] {
                        return None;
                    }
                    let suffix = &transaction.installer_effects[cursor..];
                    if suffix.len() == 2
                        && matches!(
                            suffix[0],
                            InstallerEffectPlan::ProvisionStoreCredential { .. }
                        )
                        && matches!(suffix[1], InstallerEffectPlan::MaterializePhaseB { .. })
                    {
                        Some(())
                    } else {
                        None
                    }
                })()
                .is_some();
            if transaction.stage == InstallationStage::Activating || is_registering_bootstrap {
                if transaction.effect_progress[..index].iter().any(|progress| {
                    !matches!(
                        progress.state,
                        InstallationEffectProgressState::Applied { .. }
                    )
                }) {
                    return Ok(InstallationStepOutcome::Rejected);
                }
            } else {
                return Ok(InstallationStepOutcome::Rejected);
            }
        }
        if matches!(
            transaction.installer_effects[index],
            InstallerEffectPlan::RegisterService { .. } | InstallerEffectPlan::StartService { .. }
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
            let nonce = match &transaction.installer_effects[index] {
                InstallerEffectPlan::RegisterService { .. } => {
                    match self.port.fresh_service_registration_nonce(&provisional) {
                        PortOutcome::Known(nonce) => nonce,
                        other => {
                            return self.persist_unknown(transaction, index, port_pending(other));
                        }
                    }
                }
                InstallerEffectPlan::StartService { role, .. } => {
                    // The StartService request must carry the exact nonce
                    // already bound into the corresponding registration
                    // command line. Minting a second nonce would make the
                    // start configuration differ from the installed SCM
                    // configuration and must therefore fail closed.
                    let registration_nonce = transaction
                        .installer_effects
                        .iter()
                        .zip(&transaction.effect_progress)
                        .find_map(|(effect, progress)| match effect {
                            InstallerEffectPlan::RegisterService {
                                role: registered_role,
                                ..
                            } if registered_role == role => progress.registration_nonce.clone(),
                            _ => None,
                        });
                    match registration_nonce {
                        Some(nonce) => nonce,
                        None => {
                            return self.persist_unknown(
                                transaction,
                                index,
                                PlatformHandle::new(
                                    "mismatch:missing-registration-nonce-for-start",
                                )
                                .map_err(|error| platform_error(&error))?,
                            );
                        }
                    }
                }
                _ => unreachable!("service registration nonce only applies to service effects"),
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
                InstallerEffectPlan::StagePackage { .. }
            )
            && request.precondition.package_snapshot.is_none()
        {
            return self.persist_unknown(
                transaction,
                index,
                PlatformHandle::new("mismatch:missing-package-observation")
                    .map_err(|error| platform_error(&error))?,
            );
        }
        if was_intent
            && matches!(
                transaction.installer_effects[index],
                InstallerEffectPlan::StartService { .. }
            )
        {
            let Some(deadline) = transaction.effect_progress[index].service_start_deadline_ms
            else {
                return self.persist_unknown(
                    transaction,
                    index,
                    PlatformHandle::new("mismatch:missing-service-start-deadline")
                        .map_err(|error| platform_error(&error))?,
                );
            };
            if now_ms >= deadline {
                return self.persist_unknown(
                    transaction,
                    index,
                    PlatformHandle::new("timeout:service-start-convergence")
                        .map_err(|error| platform_error(&error))?,
                );
            }
        }
        if was_intent
            && matches!(
                transaction.installer_effects[index],
                InstallerEffectPlan::CreateRoot { .. }
                    | InstallerEffectPlan::ProvisionStoreCredential { .. }
                    | InstallerEffectPlan::StagePackage { .. }
            )
            && transaction.effect_progress[index]
                .ownership_secret
                .as_ref()
                .is_some_and(|ownership| {
                    ownership.secret_provision_disposition
                        == InstallationSecretProvisionDisposition::NotAttempted
                })
        {
            let disposition = match self.port.provision_ownership_secret(&request) {
                PortOutcome::Known(disposition) => disposition,
                other => return self.persist_unknown(transaction, index, port_pending(other)),
            };
            if disposition != InstallationSecretProvisionDisposition::Created {
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
                .secret_provision_disposition = disposition;
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
                service_control_grant,
                credential_receipt,
                staging_receipt,
                phase_b_receipt,
                service_runtime_lineage,
            } => {
                let caller_start_lineage_matches = match transaction.effect_progress[index]
                    .service_start_proof
                    .as_ref()
                {
                    Some(proof) => match proof.process_lineage.as_ref() {
                        Some(expected) => service_runtime_lineage.as_ref() == Some(expected),
                        None => false,
                    },
                    None => false,
                };
                if was_intent
                    && matches!(
                        transaction.installer_effects[index],
                        InstallerEffectPlan::StartService { .. }
                    )
                    && !caller_start_lineage_matches
                {
                    // This is a restart/readback path without the durable
                    // proof that the exact caller issued StartServiceW.
                    // Running alone cannot prove who started SCM.
                    return self.persist_unknown(
                        transaction,
                        index,
                        PlatformHandle::new("mismatch:service-start-provider-disposition-missing")
                            .map_err(|error| platform_error(&error))?,
                    );
                }
                if was_intent
                    && matches!(
                        transaction.installer_effects[index],
                        InstallerEffectPlan::StartService { .. }
                    )
                    && transaction.effect_progress[index]
                        .service_start_proof
                        .as_ref()
                        .is_some_and(|proof| proof.process_lineage.is_none())
                {
                    let Some(lineage) = service_runtime_lineage.clone() else {
                        return self.persist_unknown(
                            transaction,
                            index,
                            PlatformHandle::new("mismatch:service-start-provider-lineage-missing")
                                .map_err(|error| platform_error(&error))?,
                        );
                    };
                    transaction.effect_progress[index]
                        .service_start_proof
                        .as_mut()
                        .ok_or(InstallationError::IdentityConflict)?
                        .process_lineage = Some(lineage);
                }
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
                    && !matches!(
                        transaction.installer_effects[index],
                        InstallerEffectPlan::RegisterService { .. }
                            | InstallerEffectPlan::StartService { .. }
                            | InstallerEffectPlan::MaterializePhaseB { .. }
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
                    service_control_grant.map(|receipt| *receipt),
                    credential_receipt,
                    staging_receipt,
                    phase_b_receipt.map(|receipt| *receipt),
                )
            }
            InstallationEffectObservation::Mismatch { pending_ref } => {
                self.persist_unknown(transaction, index, pending_ref)
            }
            InstallationEffectObservation::Absent {
                observed_precondition,
                evidence,
                service_runtime_lineage,
            } => {
                let snapshot_matches_effect = match &transaction.installer_effects[index] {
                    InstallerEffectPlan::ProvisionStoreCredential { .. } => {
                        observed_precondition.credential_snapshot.is_some()
                            && observed_precondition.os_snapshot.is_none()
                    }
                    InstallerEffectPlan::RegisterService { .. }
                    | InstallerEffectPlan::StartService { .. } => true,
                    InstallerEffectPlan::StagePackage { .. }
                    | InstallerEffectPlan::MaterializePhaseB { .. } => {
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
                if was_intent
                    && matches!(
                        transaction.installer_effects[index],
                        InstallerEffectPlan::StartService { .. }
                    )
                {
                    let starting = evidence
                        .iter()
                        .any(|evidence| evidence.as_str().starts_with("service-starting:"));
                    if starting
                        && transaction.effect_progress[index]
                            .service_start_deadline_ms
                            .is_some_and(|deadline| now_ms < deadline)
                    {
                        if let Some(lineage) = service_runtime_lineage
                            && self
                                .bind_service_start_lineage(&mut transaction, index, lineage)
                                .is_err()
                        {
                            return self.persist_unknown(
                                transaction,
                                index,
                                PlatformHandle::new("mismatch:service-runtime-lineage-substituted")
                                    .map_err(|error| platform_error(&error))?,
                            );
                        }
                        // SCM is still transitioning.  Preserve the exact
                        // intent and return without another external call. A
                        // later Running readback must match any lineage bound
                        // above; PID 0 without such a lineage remains
                        // non-owning.
                        return Ok(InstallationStepOutcome::Rejected);
                    }
                    return self.persist_unknown(
                        transaction,
                        index,
                        PlatformHandle::new("mismatch:service-start-not-running")
                            .map_err(|error| platform_error(&error))?,
                    );
                }
                let preserves_secret_attempt = matches!(
                    transaction.installer_effects[index],
                    InstallerEffectPlan::CreateRoot { .. }
                        | InstallerEffectPlan::ProvisionStoreCredential { .. }
                        | InstallerEffectPlan::StagePackage { .. }
                );
                let next_attempt = if was_intent && !preserves_secret_attempt {
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
                        InstallerEffectPlan::StartService { .. }
                    ) {
                        transaction.effect_progress[index].service_start_deadline_ms =
                            Some(now_ms.saturating_add(SERVICE_START_CONVERGENCE_TIMEOUT_MS));
                    }
                    if matches!(
                        transaction.installer_effects[index],
                        InstallerEffectPlan::CreateRoot { .. }
                            | InstallerEffectPlan::ProvisionStoreCredential { .. }
                            | InstallerEffectPlan::StagePackage { .. }
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
                        let proof = match self.port.prepare_ownership_secret(&request, &reference) {
                            PortOutcome::Known(proof) => proof,
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
                                secret_provision_disposition:
                                    InstallationSecretProvisionDisposition::NotAttempted,
                                creation_proof: proof,
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
                    InstallerEffectPlan::CreateRoot { .. }
                        | InstallerEffectPlan::ProvisionStoreCredential { .. }
                        | InstallerEffectPlan::StagePackage { .. }
                ) && transaction.effect_progress[index]
                    .ownership_secret
                    .as_ref()
                    .is_some_and(|ownership| {
                        ownership.secret_provision_disposition
                            == InstallationSecretProvisionDisposition::NotAttempted
                    })
                {
                    let disposition = match self.port.provision_ownership_secret(&request) {
                        PortOutcome::Known(disposition) => disposition,
                        other => {
                            return self.persist_unknown(transaction, index, port_pending(other));
                        }
                    };
                    if disposition != InstallationSecretProvisionDisposition::Created {
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
                        .secret_provision_disposition = disposition;
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
                if matches!(
                    transaction.installer_effects[index],
                    InstallerEffectPlan::CreateRoot { .. }
                        | InstallerEffectPlan::StagePackage { .. }
                        | InstallerEffectPlan::ProvisionStoreCredential { .. }
                ) && request.action == InstallationEffectAction::Apply
                {
                    // The provider mutation and Created CAS are not enough
                    // to authorize filesystem execution. Reload the exact
                    // store record and bind revision/checksum, intent,
                    // target, and proof before crossing the protected
                    // external-effect boundary.
                    let persisted = self
                        .store
                        .load(transaction_id)?
                        .ok_or(InstallationError::IdentityConflict)?;
                    persisted.validate()?;
                    if TransactionVersion::of(&persisted)? != TransactionVersion::of(&transaction)?
                    {
                        return Err(InstallationError::IdentityConflict);
                    }
                    let (persisted_attempt, persisted_intent_digest) =
                        match &persisted.effect_progress[index].state {
                            InstallationEffectProgressState::IntentCommitted {
                                attempt,
                                intent_digest,
                            } => (*attempt, intent_digest.clone()),
                            _ => return Err(InstallationError::IdentityConflict),
                        };
                    let persisted_request = effect_request(
                        &persisted,
                        index,
                        persisted_attempt,
                        InstallationEffectAction::Apply,
                        None,
                    )?;
                    if persisted_request.intent_digest()? != persisted_intent_digest
                        || persisted_request
                            .ownership_secret
                            .as_ref()
                            .zip(request.ownership_secret.as_ref())
                            .is_none_or(|(persisted, current)| {
                                persisted.reference != current.reference
                                    || persisted.creation_proof != current.creation_proof
                            })
                    {
                        return Err(InstallationError::IdentityConflict);
                    }
                    transaction = persisted;
                    request = persisted_request;
                }
                let execution = match self.port.execute(&request) {
                    PortOutcome::Known(execution) => execution,
                    PortOutcome::Partial { value, missing }
                        if matches!(
                            transaction.installer_effects[index],
                            InstallerEffectPlan::CreateRoot { .. }
                        ) && value.create_disposition
                            == Some(InstallationCreateDisposition::Created) =>
                    {
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
                        ownership.create_disposition = InstallationCreateDisposition::Created;
                        increment_revision(&mut transaction)?;
                        transaction.validate()?;
                        self.store.compare_and_save(expected, &transaction)?;
                        return self.persist_unknown(
                            transaction,
                            index,
                            missing.into_iter().next().unwrap_or_else(|| {
                                PlatformHandle::new("unknown:partial")
                                    .unwrap_or_else(|_| unreachable!())
                            }),
                        );
                    }
                    PortOutcome::Partial { missing, .. } => {
                        return self.persist_unknown(
                            transaction,
                            index,
                            missing.into_iter().next().unwrap_or_else(|| {
                                PlatformHandle::new("unknown:partial")
                                    .unwrap_or_else(|_| unreachable!())
                            }),
                        );
                    }
                    PortOutcome::Unknown(_reason)
                        if matches!(
                            transaction.installer_effects[index],
                            InstallerEffectPlan::StartService { .. }
                        ) && request.action == InstallationEffectAction::Apply =>
                    {
                        // The exact intent is already durable. Preserve it
                        // across a provider response-loss window and force
                        // the next process to reconcile SCM before any new
                        // start call can be considered. Unknown does not
                        // authorize a replay or a rollback stop.
                        return Ok(InstallationStepOutcome::Rejected);
                    }
                    PortOutcome::Unknown(_reason)
                        if matches!(
                            transaction.installer_effects[index],
                            InstallerEffectPlan::MaterializePhaseB { .. }
                        ) && request.action == InstallationEffectAction::Apply =>
                    {
                        // Phase-B intent remains durably committed. A later
                        // drive uses the query-only ReconcilePhaseB operation;
                        // it never republishes the Host overlay blindly.
                        return Ok(InstallationStepOutcome::Rejected);
                    }
                    other => return self.persist_unknown(transaction, index, port_pending(other)),
                };
                let is_start_apply = matches!(
                    transaction.installer_effects[index],
                    InstallerEffectPlan::StartService { .. }
                ) && request.action == InstallationEffectAction::Apply;
                let service_start_disposition = execution.service_start_disposition;
                let service_runtime_lineage = execution.service_runtime_lineage.clone();
                let phase_b_execution_receipt = execution.phase_b_receipt.clone();
                if matches!(
                    transaction.installer_effects[index],
                    InstallerEffectPlan::MaterializePhaseB { .. }
                ) {
                    let Some(receipt) = phase_b_execution_receipt.as_ref() else {
                        return self.persist_unknown(
                            transaction,
                            index,
                            PlatformHandle::new("mismatch:phase-b-execution-receipt")
                                .map_err(|error| platform_error(&error))?,
                        );
                    };
                    receipt.validate()?;
                    if receipt.transaction_id != transaction.transaction_id
                        || receipt.effect_id != *transaction.installer_effects[index].effect_id()
                        || receipt.candidate_manifest_digest
                            != candidate_manifest_digest(&transaction.candidate_manifest)?
                    {
                        return self.persist_unknown(
                            transaction,
                            index,
                            PlatformHandle::new("mismatch:phase-b-execution-binding")
                                .map_err(|error| platform_error(&error))?,
                        );
                    }
                } else if phase_b_execution_receipt.is_some() {
                    return self.persist_unknown(
                        transaction,
                        index,
                        PlatformHandle::new("mismatch:unexpected-phase-b-receipt")
                            .map_err(|error| platform_error(&error))?,
                    );
                }
                if is_start_apply
                    && service_start_disposition
                        == Some(InstallationServiceStartDisposition::StartedByCaller)
                    && transaction.effect_progress[index]
                        .service_start_proof
                        .is_none()
                {
                    let request_intent_digest = request.intent_digest()?;
                    let exact_intent = matches!(
                        &transaction.effect_progress[index].state,
                        InstallationEffectProgressState::IntentCommitted {
                            intent_digest, ..
                        } if *intent_digest == request_intent_digest
                    );
                    if !exact_intent {
                        return self.persist_unknown(
                            transaction,
                            index,
                            PlatformHandle::new("mismatch:service-start-proof-intent")
                                .map_err(|error| platform_error(&error))?,
                        );
                    }
                    let expected = TransactionVersion::of(&transaction)?;
                    transaction.effect_progress[index].service_start_proof =
                        Some(InstallationServiceStartProof {
                            intent_digest: request_intent_digest,
                            process_lineage: service_runtime_lineage.clone(),
                        });
                    increment_revision(&mut transaction)?;
                    transaction.validate()?;
                    self.store.compare_and_save(expected, &transaction)?;
                }
                if is_start_apply {
                    match service_start_disposition {
                        Some(
                            InstallationServiceStartDisposition::StartedByCaller
                            | InstallationServiceStartDisposition::AlreadyRunning,
                        ) => {}
                        Some(InstallationServiceStartDisposition::AlreadyStarting) => {
                            // A foreign actor won the stopped -> starting race.
                            // No later readback may turn that actor into
                            // transaction ownership.
                            return self.persist_unknown(
                                transaction,
                                index,
                                PlatformHandle::new("mismatch:service-start-already-starting")
                                    .map_err(|error| platform_error(&error))?,
                            );
                        }
                        None => {
                            // The provider disposition is the only proof that
                            // the caller issued StartServiceW.  Evidence or a
                            // later Running readback cannot supply ownership.
                            return self.persist_unknown(
                                transaction,
                                index,
                                PlatformHandle::new("mismatch:missing-service-start-disposition")
                                    .map_err(|error| platform_error(&error))?,
                            );
                        }
                    }
                } else if service_start_disposition.is_some() {
                    return self.persist_unknown(
                        transaction,
                        index,
                        PlatformHandle::new("mismatch:unexpected-service-start-disposition")
                            .map_err(|error| platform_error(&error))?,
                    );
                } else if service_runtime_lineage.is_some() {
                    return self.persist_unknown(
                        transaction,
                        index,
                        PlatformHandle::new("mismatch:unexpected-service-runtime-lineage")
                            .map_err(|error| platform_error(&error))?,
                    );
                }
                handles(&execution.evidence, "effect.execution.evidence", false)?;
                let expected_service_runtime_identity = if matches!(
                    transaction.installer_effects[index],
                    InstallerEffectPlan::StartService { .. }
                ) && request.action
                    == InstallationEffectAction::Apply
                {
                    execution.evidence.iter().find_map(|evidence| {
                        evidence
                            .as_str()
                            .strip_prefix("service-runtime-identity:")
                            .map(str::to_owned)
                    })
                } else {
                    None
                };
                let service_start_is_waiting =
                    matches!(
                        transaction.installer_effects[index],
                        InstallerEffectPlan::StartService { .. }
                    ) && request.action == InstallationEffectAction::Apply
                        && service_start_disposition
                            == Some(InstallationServiceStartDisposition::StartedByCaller)
                        && execution.evidence.iter().any(|evidence| {
                            matches!(evidence.as_str(), "service-start-ack-starting")
                        });
                if matches!(
                    transaction.installer_effects[index],
                    InstallerEffectPlan::StartService { .. }
                ) && request.action == InstallationEffectAction::Apply
                    && expected_service_runtime_identity.is_none()
                {
                    if service_start_is_waiting {
                        // START_PENDING is a durable wait/reconcile state. SCM
                        // may report PID 0 until the process is fully
                        // materialized. A provider-authenticated lineage is
                        // captured as soon as START_PENDING exposes one; a
                        // direct PID-0 -> Running transition is never adopted.
                        return Ok(InstallationStepOutcome::Rejected);
                    }
                    return self.persist_unknown(
                        transaction,
                        index,
                        PlatformHandle::new("mismatch:missing-service-runtime-receipt")
                            .map_err(|error| platform_error(&error))?,
                    );
                }
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
                        | InstallerEffectPlan::MaterializePhaseB { .. }
                        | InstallerEffectPlan::StagePackage { .. }
                        | InstallerEffectPlan::StartService { .. },
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
                        | InstallerEffectPlan::StartService { .. }
                        | InstallerEffectPlan::ProvisionStoreCredential { .. }
                        | InstallerEffectPlan::MaterializePhaseB { .. }
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
                    let Some(snapshot) = transaction.effect_progress[index]
                        .admitted_precondition
                        .as_ref()
                        .and_then(|precondition| precondition.package_snapshot.as_ref())
                    else {
                        return self.persist_unknown(
                            transaction,
                            index,
                            PlatformHandle::new("mismatch:missing-package-observation")
                                .map_err(|error| platform_error(&error))?,
                        );
                    };
                    if validate_staging_receipt_for_observation(snapshot, &receipt).is_err() {
                        return self.persist_unknown(
                            transaction,
                            index,
                            PlatformHandle::new("mismatch:package-receipt-observation")
                                .map_err(|error| platform_error(&error))?,
                        );
                    }
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
                        service_control_grant,
                        credential_receipt,
                        staging_receipt,
                        phase_b_receipt,
                        service_runtime_lineage: reconciled_service_runtime_lineage,
                    } => {
                        if let Some(expected_identity) =
                            expected_service_runtime_identity.as_deref()
                            && expected_identity != external_identity.as_str()
                        {
                            return self.persist_unknown(
                                transaction,
                                index,
                                PlatformHandle::new("mismatch:service-pid-substituted")
                                    .map_err(|error| platform_error(&error))?,
                            );
                        }
                        if is_start_apply
                            && service_start_disposition
                                == Some(InstallationServiceStartDisposition::StartedByCaller)
                        {
                            let lineage_matches = match service_runtime_lineage.as_ref() {
                                Some(expected) => {
                                    reconciled_service_runtime_lineage.as_ref() == Some(expected)
                                }
                                None => false,
                            };
                            if !lineage_matches {
                                return self.persist_unknown(
                                    transaction,
                                    index,
                                    PlatformHandle::new(
                                        "mismatch:service-runtime-lineage-substituted",
                                    )
                                    .map_err(|error| platform_error(&error))?,
                                );
                            }
                        }
                        let disposition = if is_start_apply {
                            match service_start_disposition {
                                Some(InstallationServiceStartDisposition::AlreadyRunning) => {
                                    InstallationEffectDisposition::PreexistingMatching
                                }
                                Some(InstallationServiceStartDisposition::StartedByCaller)
                                    if disposition
                                        == InstallationEffectDisposition::CreatedByTransaction =>
                                {
                                    disposition
                                }
                                Some(
                                    InstallationServiceStartDisposition::StartedByCaller
                                    | InstallationServiceStartDisposition::AlreadyStarting,
                                )
                                | None => {
                                    return self.persist_unknown(
                                        transaction,
                                        index,
                                        PlatformHandle::new(
                                            "mismatch:service-start-ownership-disposition",
                                        )
                                        .map_err(|error| platform_error(&error))?,
                                    );
                                }
                            }
                        } else {
                            disposition
                        };
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
                                        | InstallerEffectPlan::StartService { .. }
                                ) && transaction.effect_progress[index]
                                    .registration_nonce
                                    .is_some())
                                    || (matches!(
                                        transaction.installer_effects[index],
                                        InstallerEffectPlan::StagePackage { .. }
                                    ) && staging_receipt.is_some())
                                    || (matches!(
                                        transaction.installer_effects[index],
                                        InstallerEffectPlan::MaterializePhaseB { .. }
                                    ) && phase_b_receipt.is_some())
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
                                service_control_grant.map(|receipt| *receipt),
                                credential_receipt,
                                staging_receipt,
                                phase_b_receipt.map(|receipt| *receipt),
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
                        evidence,
                        service_runtime_lineage,
                    } if observed_precondition == request.precondition => {
                        if is_start_apply
                            && service_start_disposition
                                == Some(InstallationServiceStartDisposition::StartedByCaller)
                            && evidence
                                .iter()
                                .any(|evidence| evidence.as_str().starts_with("service-starting:"))
                            && let Some(lineage) = service_runtime_lineage
                            && self
                                .bind_service_start_lineage(&mut transaction, index, lineage)
                                .is_err()
                        {
                            return self.persist_unknown(
                                transaction,
                                index,
                                PlatformHandle::new("mismatch:service-runtime-lineage-substituted")
                                    .map_err(|error| platform_error(&error))?,
                            );
                        }
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
        self.drive_all_effects_until_blocked_at(transaction_id, wall_clock_millis())
    }

    /// Drives all effects with an injected absolute millisecond clock.
    ///
    /// This preserves the same finite loop and durable state transitions as
    /// [`Self::drive_all_effects_until_blocked`] while allowing deterministic
    /// timeout/restart discrimination tests.
    pub fn drive_all_effects_until_blocked_at(
        &mut self,
        transaction_id: &PlatformHandle,
        now_ms: u64,
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
            let outcome = self.drive_effect_at(transaction_id, now_ms)?;
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
        if transaction.activation_projection_intent.is_some() {
            return Err(InstallationError::IllegalTransition {
                from: transaction.stage,
                to: InstallationStage::RolledBack,
            });
        }
        if transaction.stage != InstallationStage::RollbackRequired {
            if transaction.stage != InstallationStage::Registering {
                return Err(InstallationError::IllegalTransition {
                    from: transaction.stage,
                    to: InstallationStage::RolledBack,
                });
            }
            let has_durable_rejection = !transaction.pending_external_changes.is_empty()
                || transaction.effect_progress.iter().any(|progress| {
                    matches!(
                        progress.state,
                        InstallationEffectProgressState::Unknown { .. }
                            | InstallationEffectProgressState::IntentCommitted { .. }
                    )
                });
            if !has_durable_rejection {
                return Err(InstallationError::IllegalTransition {
                    from: transaction.stage,
                    to: InstallationStage::RolledBack,
                });
            }
            let expected = TransactionVersion::of(&transaction)?;
            let pending = if transaction.pending_external_changes.is_empty() {
                transaction
                    .effect_progress
                    .iter()
                    .filter_map(|progress| match &progress.state {
                        InstallationEffectProgressState::Unknown { pending_ref } => {
                            Some(pending_ref.clone())
                        }
                        InstallationEffectProgressState::IntentCommitted {
                            intent_digest, ..
                        } => Some(intent_digest.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            } else {
                transaction.pending_external_changes.clone()
            };
            if pending.is_empty() {
                return Err(InstallationError::IllegalTransition {
                    from: transaction.stage,
                    to: InstallationStage::RolledBack,
                });
            }
            transaction.pending_external_changes = pending;
            transaction.stage = InstallationStage::RollbackRequired;
            increment_revision(&mut transaction)?;
            transaction.validate()?;
            self.store.compare_and_save(expected, &transaction)?;
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
        let retained_phase_b_effect = transaction
            .installer_effects
            .iter()
            .zip(&transaction.effect_progress)
            .find_map(|(effect, progress)| {
                matches!(effect, InstallerEffectPlan::MaterializePhaseB { .. })
                    .then_some(progress)
                    .filter(|progress| {
                        matches!(
                            progress.state,
                            InstallationEffectProgressState::Applied { .. }
                        )
                    })
                    .map(|progress| progress.effect_id.clone())
            });
        if let Some(effect_id) = retained_phase_b_effect {
            return self.persist_quarantined(
                transaction,
                PlatformHandle::new(format!(
                    "quarantine:phase-b-authority-retained:{}",
                    effect_id.as_str()
                ))
                .map_err(|error| platform_error(&error))?,
            );
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

    /// Captures the first non-zero provider-authenticated lineage observed
    /// while an exact caller-issued start is still `START_PENDING`.  A later
    /// `Running` readback may only use this persisted lineage; coordinator
    /// memory or registration identity cannot substitute for it.
    fn bind_service_start_lineage(
        &mut self,
        transaction: &mut InstallationTransaction,
        index: usize,
        lineage: InstallationServiceProcessLineage,
    ) -> Result<(), InstallationError> {
        let expected = TransactionVersion::of(transaction)?;
        let Some(proof) = transaction.effect_progress[index]
            .service_start_proof
            .as_mut()
        else {
            return Err(InstallationError::IdentityConflict);
        };
        if let Some(existing) = proof.process_lineage.as_ref() {
            if existing != &lineage {
                return Err(InstallationError::IdentityConflict);
            }
            return Ok(());
        }
        proof.process_lineage = Some(lineage);
        increment_revision(transaction)?;
        transaction.validate()?;
        self.store.compare_and_save(expected, transaction)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the persisted applied receipt is one atomic effect record"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "W3-02 will extract transaction persistence"
    )]
    fn persist_applied(
        &mut self,
        mut transaction: InstallationTransaction,
        index: usize,
        disposition: InstallationEffectDisposition,
        external_identity: PlatformHandle,
        evidence: Vec<PlatformHandle>,
        postcondition_digest: PlatformHandle,
        service_control_grant: Option<InstallerServiceControlGrantReceipt>,
        credential_receipt: Option<CredentialAccessReceipt>,
        staging_receipt: Option<StagingReceipt>,
        phase_b_receipt: Option<HostPhaseBMaterializationReceipt>,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        let expected = TransactionVersion::of(&transaction)?;
        match (
            &transaction.installer_effects[index],
            &service_control_grant,
        ) {
            (
                InstallerEffectPlan::RegisterService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                },
                Some(receipt),
            ) => receipt.validate()?,
            (
                InstallerEffectPlan::RegisterService {
                    role: InstallerServiceRole::Host,
                    ..
                },
                None,
            ) => {}
            (InstallerEffectPlan::RegisterService { .. }, _) | (_, Some(_)) => {
                return Err(InstallationError::IdentityConflict);
            }
            (_, None) => {}
        }
        transaction.effect_progress[index].service_control_grant = service_control_grant;
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
        if let Some(receipt) = phase_b_receipt {
            if !matches!(
                transaction.installer_effects[index],
                InstallerEffectPlan::MaterializePhaseB { .. }
            ) || disposition != InstallationEffectDisposition::CreatedByTransaction
            {
                return Err(InstallationError::IdentityConflict);
            }
            receipt.validate()?;
            if receipt.transaction_id != transaction.transaction_id
                || receipt.effect_id != transaction.effect_progress[index].effect_id
                || receipt.candidate_manifest_digest
                    != candidate_manifest_digest(&transaction.candidate_manifest)?
            {
                return Err(InstallationError::IdentityConflict);
            }
            transaction.effect_progress[index].phase_b_receipt = Some(receipt);
        } else if matches!(
            transaction.installer_effects[index],
            InstallerEffectPlan::MaterializePhaseB { .. }
        ) {
            return Err(InstallationError::IncompleteObservation(
                "applied Phase-B effect requires its typed receipt".to_owned(),
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

    /// Drives exactly one effect with an injected clock for deterministic
    /// bounded-start tests.
    pub fn drive_effect_at(
        &mut self,
        transaction_id: &PlatformHandle,
        now_ms: u64,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        self.inner.drive_effect_at(transaction_id, now_ms)
    }

    /// Reconciles an exact Host registry terminal into the sole durable
    /// installation transaction.  This is query/readback driven and does not
    /// issue any platform effect.
    pub fn reconcile_active_verified(
        &mut self,
        receipt: ActivationCommitReceipt,
        evidence: Vec<PlatformHandle>,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        self.inner.reconcile_active_verified(receipt, evidence)
    }

    /// Drives the durable prefix up to, but not through, the first ordered SCM
    /// service start.  Both Watchdog and Host starts must remain pending while
    /// the caller projects the exact signed activation record; no SCM start is
    /// attempted by this prefix method.
    pub fn drive_until_host_bootstrap(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        let transaction = self.inner.store().load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        let max_steps = transaction
            .installer_effects
            .len()
            .checked_add(1)
            .ok_or_else(|| InstallationError::InvalidField {
                field: "installer_effects".to_owned(),
                reason: "bounded prefix limit overflow".to_owned(),
            })?;
        for _ in 0..max_steps {
            let current = self.inner.store().load(transaction_id)?.ok_or_else(|| {
                InstallationError::TransactionNotFound {
                    transaction_id: transaction_id.as_str().to_owned(),
                }
            })?;
            let Some(index) = current.effect_progress.iter().position(|progress| {
                !matches!(
                    progress.state,
                    InstallationEffectProgressState::Applied { .. }
                )
            }) else {
                return Ok(InstallationStepOutcome::Applied {
                    stage: current.stage,
                    evidence_refs: current.observed_postconditions,
                });
            };
            if matches!(
                current.installer_effects[index],
                InstallerEffectPlan::StartService { .. }
            ) {
                return Ok(InstallationStepOutcome::Applied {
                    stage: current.stage,
                    evidence_refs: current.observed_postconditions,
                });
            }
            match self.inner.drive_effect(transaction_id)? {
                applied @ InstallationStepOutcome::Applied { .. } => {
                    if matches!(
                        self.inner.store().load(transaction_id)?.as_ref(),
                        Some(transaction)
                            if transaction.effect_progress.iter().any(|progress| matches!(
                                progress.state,
                                InstallationEffectProgressState::Unknown { .. }
                            ))
                    ) {
                        return Ok(applied);
                    }
                }
                outcome => return Ok(outcome),
            }
        }
        Err(InstallationError::IncompleteObservation(
            "bounded prefix drive exhausted before Host bootstrap".to_owned(),
        ))
    }

    /// Drives all immutable effects through the bounded installer-core loop.
    pub fn drive_all_effects_until_blocked(
        &mut self,
        transaction_id: &PlatformHandle,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        self.inner.drive_all_effects_until_blocked(transaction_id)
    }

    /// Drives all effects with an injected clock for deterministic bounded
    /// SCM-start tests.
    pub fn drive_all_effects_until_blocked_at(
        &mut self,
        transaction_id: &PlatformHandle,
        now_ms: u64,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        self.inner
            .drive_all_effects_until_blocked_at(transaction_id, now_ms)
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

impl WindowsInstallationCoordinator<RedbInstallationTransactionStore> {
    /// Projects bootstrap only after the transaction CAS has retained the
    /// activation projection intent.  The registry remains a projection and
    /// cannot become the first durable owner of this handoff.
    pub fn stage_bootstrap_pending_activation(
        &mut self,
        registry: &RedbInstallationRegistry,
        transaction_id: &PlatformHandle,
        expected_registry_revision: u64,
    ) -> Result<(), InstallationError> {
        registry.stage_pending_activation_bootstrap(
            self.inner.store_mut(),
            transaction_id,
            expected_registry_revision,
        )
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

#[expect(
    clippy::too_many_lines,
    reason = "W3-02 will extract the effect-request capability cell"
)]
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
    let inherited_store_credential = matches!(&plan, InstallerEffectPlan::MaterializePhaseB { .. })
        .then(|| {
            transaction
                .installer_effects
                .iter()
                .zip(&transaction.effect_progress)
                .find_map(|(effect, progress)| {
                    matches!(effect, InstallerEffectPlan::ProvisionStoreCredential { .. })
                        .then(|| progress.store_credential.clone())
                        .flatten()
                })
        })
        .flatten();
    let inherited_ownership_secret = matches!(&plan, InstallerEffectPlan::MaterializePhaseB { .. })
        .then(|| {
            transaction
                .installer_effects
                .iter()
                .zip(&transaction.effect_progress)
                .find_map(|(effect, progress)| {
                    matches!(effect, InstallerEffectPlan::ProvisionStoreCredential { .. })
                        .then(|| progress.ownership_secret.clone())
                        .flatten()
                })
        })
        .flatten();
    let is_service = matches!(
        &plan,
        InstallerEffectPlan::RegisterService { .. } | InstallerEffectPlan::StartService { .. }
    );
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
        ownership_secret: progress
            .ownership_secret
            .clone()
            .or(inherited_ownership_secret),
        store_credential: progress
            .store_credential
            .clone()
            .or(inherited_store_credential),
        staging_receipt: progress.staging_receipt.clone(),
        action,
        expected_external_identity,
        service_bootstrap: is_service
            .then(
                || -> Result<InstallationServiceBootstrap, InstallationError> {
                    Ok(InstallationServiceBootstrap {
                        descriptor_path: transaction
                            .candidate_manifest
                            .runtime_launch
                            .authority_descriptor_path
                            .clone(),
                        descriptor_digest: phase_b_scm_digest(
                            &transaction
                                .candidate_manifest
                                .runtime_launch
                                .authority_descriptor_digest,
                        )?,
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
                    })
                },
            )
            .transpose()?,
        registration_nonce: progress.registration_nonce.clone(),
    };
    request.validate()?;
    Ok(request)
}

const REDACTED_PROVIDER_REFERENCE_PENDING: &str = "pending:provider-reference-redacted";

fn port_pending<T>(outcome: PortOutcome<T>) -> PlatformHandle {
    let value = match outcome {
        PortOutcome::Known(_) => "unknown:unexpected-known".to_owned(),
        PortOutcome::Unknown(reason) => format!("unknown:{reason:?}"),
        PortOutcome::Partial { missing, .. } => missing.first().map_or_else(
            || "unknown:partial".to_owned(),
            |value| value.as_str().to_owned(),
        ),
        PortOutcome::Error(PortError::ProviderReference { reference, .. }) => {
            if is_typed_installer_root_reference(reference.as_str())
                || is_typed_package_staging_reference(reference.as_str())
            {
                return reference;
            }
            REDACTED_PROVIDER_REFERENCE_PENDING.to_owned()
        }
        PortOutcome::Error(error) => format!("error:{error}"),
    };
    PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
}

fn is_typed_package_staging_reference(value: &str) -> bool {
    if let Some(semantic) = value.strip_prefix("stage-package-error-v1:") {
        return matches!(
            semantic,
            "invalid-relative-path"
                | "manifest-collision"
                | "bound-exceeded"
                | "root-unavailable"
                | "reparse-point"
                | "wrong-entry-kind"
                | "identity-mismatch"
                | "hash-mismatch"
                | "size-mismatch"
                | "security-mismatch"
                | "generation-exists"
                | "tree-mismatch"
                | "partial-tree"
                | "pe-parse"
                | "authenticode"
                | "authenticode-rejected"
                | "rollback-refused"
                | "unsupported-platform"
                | "io"
        );
    }
    let Some(rest) = value.strip_prefix("stage-package-win32-v1:") else {
        return false;
    };
    let mut parts = rest.split(':');
    let Some(stage) = parts.next() else {
        return false;
    };
    if !matches!(
        stage,
        "known-folder-path"
            | "canonicalize-path"
            | "symlink-metadata"
            | "set-security-info"
            | "get-security-info"
            | "create-file-w"
            | "file-metadata"
            | "flush-file-buffers"
            | "get-file-information-by-handle"
            | "get-final-path-name-by-handle-w"
            | "duplicate-handle"
            | "set-file-pointer-ex"
            | "read-file"
            | "write-file"
    ) {
        return false;
    }
    let Some(code) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && code.len() == 8
        && code
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_typed_installer_root_reference(value: &str) -> bool {
    if value == "installer-root-absence-race-v1:precondition" {
        return true;
    }
    let Some(rest) = value
        .strip_prefix("installer-root-win32-v2:")
        .or_else(|| value.strip_prefix("installer-root-absence-race-v1:"))
    else {
        return false;
    };
    let mut parts = rest.split(':');
    let Some(stage) = parts.next() else {
        return false;
    };
    if !matches!(
        stage,
        "open-thread-token"
            | "open-process-token"
            | "duplicate-token"
            | "query-privilege"
            | "enable-privilege"
            | "bind-thread-token"
            | "restore-privilege"
            | "restore-thread-token"
            | "create-directory"
            | "create-protected-file"
            | "open-readback"
            | "readback"
    ) {
        return false;
    }
    let Some(code) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && code.len() == 8
        && code
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
mod tests;
