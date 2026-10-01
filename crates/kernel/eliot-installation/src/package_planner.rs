use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    FileIdentity, PackageManifest, PackageSourceObservation, PackageStagingError,
    TrustedSourceBundle, UserModeSupervisionAuthorityCredentialRequest,
    UserModeSupervisionAuthorityCredentialTargetObservation, WindowsInstallerSecretProvider,
    WindowsUserModeSupervisionAuthorityCredentialProvider, validate_package_relative_path,
};

use eliot_runtime_contracts::RuntimeLiveStoreIdentity;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    AgentBridgeSourceMaterializationPlan, CandidateManifest, InstallationEpoch, InstallationError,
    InstallationProfile, InstallationRoots, InstallationTransaction, InstallerAclPrincipal,
    InstallerEffectPlan, InstallerServiceAccount, InstallerServiceRole, LOCAL_SERVICE_SID,
    ManagedEnvironmentAction, ManagedEnvironmentChangeRequest, NoServiceProfileAuthorityProof,
    PHASE_B_PENDING_MARKER, PackageArtifactDigest, PlannedChange, ProfileGovernanceReport,
    ProfileRootAnchors, ResourceGeneration, RuntimeLaunchDescriptor, RuntimeStateRoots, StateFence,
    StoreCredentialProvider, StoreCredentialProvisionPlan, StoreCredentialScope,
    SupervisionAuthorityProvisionPlan, UserModeSupervisionAuthorityProvisionPlan,
    candidate_manifest_digest as candidate_digest_fn, handle,
    phase_b_static_template_for_candidate, prove_no_service_profile_authority_dependency,
    provider_bootstrap_credential_target_for_store_target, select_profile_roots,
    supervision_key_slot_for_scope_id,
};
use eliot_contracts::{EpochId, EpochLineageId};

// Canonical lineage-A for the Phase-A template fence (Implements #64).
const PACKAGE_PLANNER_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn planner_epoch(sequence: u64) -> EpochId {
    use std::num::NonZeroU64;
    EpochId::new(
        EpochLineageId::new(PACKAGE_PLANNER_LINEAGE_A).expect("canonical planner lineage-A"),
        NonZeroU64::new(sequence).expect("non-zero planner sequence"),
    )
    .expect("valid planner epoch")
}

/// The immutable package inventory produced by the trusted generation seam.
///
/// The role names deliberately live in one place.  A caller cannot provide a
/// partial candidate and ask the stager to infer the missing Host, Watchdog,
/// Kernel, Store or daemon contour.
/// Files which the installer is allowed to copy during Phase A.
///
/// `authority.json` and `store-bootstrap.json` are deliberately absent. They
/// are live Host-owned handoff material and cannot be represented by an
/// installer candidate. Destination file identities are observed after
/// Phase B materialization and are not part of this immutable inventory.
pub(crate) const REQUIRED_PACKAGE_ROLES: [(&str, bool); 15] = [
    ("eliot-host.exe", true),
    ("eliot-watchdog.exe", true),
    ("eliot-kernel.exe", true),
    ("eliot-store-surreal.exe", true),
    ("surreal.exe", true),
    ("eliotd.exe", true),
    ("eliot-doctor.exe", true),
    ("eliot-testd.exe", true),
    ("eliot-native-worker.exe", true),
    ("eliot-wasm-host.exe", true),
    ("eliot-user-broker.exe", true),
    ("eliot-notify.exe", true),
    ("generation.json", false),
    ("eliotd-governor.json", false),
    ("eliotd.json", false),
];

/// Optional canonical contract and module-specific builder proof carried by
/// new release bundles. Legacy source bundles remain readable, while a bundle
/// that carries either file must carry and bind both.
pub(crate) const MODULE_BUILD_PROVENANCE_ROLES: [(&str, bool); 2] = [
    ("module.eliotd.toml", false),
    ("module.eliotd.provenance.json", false),
];

/// Optional non-executable symbols retained with an admitted Host/Kernel
/// generation. They are present only as a pair and never enter signing roles.
pub(crate) const RELEASE_SYMBOL_ROLES: [(&str, bool); 2] = [
    ("symbols/host/eliot-host.pdb", false),
    ("symbols/kernel/eliot-kernel.pdb", false),
];

pub(crate) fn package_inventory_roles(
    include_module_provenance: bool,
    include_release_symbols: bool,
) -> Vec<(&'static str, bool)> {
    let mut roles = REQUIRED_PACKAGE_ROLES.to_vec();
    if include_module_provenance {
        roles.extend(MODULE_BUILD_PROVENANCE_ROLES);
    }
    if include_release_symbols {
        roles.extend(RELEASE_SYMBOL_ROLES);
    }
    roles
}

fn release_symbols_present(
    names: impl IntoIterator<Item = String>,
) -> Result<bool, InstallationError> {
    let names = names.into_iter().collect::<BTreeSet<_>>();
    let host = names.contains(RELEASE_SYMBOL_ROLES[0].0);
    let kernel = names.contains(RELEASE_SYMBOL_ROLES[1].0);
    if host != kernel {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(host)
}

fn module_provenance_present(
    names: impl IntoIterator<Item = String>,
) -> Result<bool, InstallationError> {
    let names = names.into_iter().collect::<BTreeSet<_>>();
    let has_manifest = names.contains("module.eliotd.toml");
    let has_proof = names.contains("module.eliotd.provenance.json");
    if has_manifest != has_proof {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(has_manifest)
}

fn package_roles_for_manifest(
    manifest: &PackageManifest,
) -> Result<Vec<(&'static str, bool)>, InstallationError> {
    let include_module_provenance =
        module_provenance_present(manifest.files.iter().map(|file| file.relative_path.clone()))?;
    let include_symbols =
        release_symbols_present(manifest.files.iter().map(|file| file.relative_path.clone()))?;
    let roles = package_inventory_roles(include_module_provenance, include_symbols);
    if manifest.files.len() != roles.len() {
        return Err(InstallationError::IncompleteObservation(
            "package manifest must contain the complete approved runtime inventory".to_owned(),
        ));
    }
    Ok(roles)
}

/// Per-user notification adapter staged in Phase A but never Kernel-dispatched.
/// `eliot-notify.exe` has no launch descriptor binding. The User Broker is
/// also staged in the per-user branch, but its exact path and digest are
/// pinned in the manifest and launch descriptor while remaining outside
/// Host-managed daemon roles.
pub(crate) const NOTIFY_STAGED_ROLE: &str = "eliot-notify.exe";
pub(crate) const NOTIFY_STAGED_EXECUTABLE: bool = true;
pub(crate) const USER_BROKER_STAGED_ROLE: &str = "eliot-user-broker.exe";
pub(crate) const USER_BROKER_STAGED_EXECUTABLE: bool = true;

fn package_plan_error(error: &PackageStagingError) -> InstallationError {
    InstallationError::InvalidField {
        field: "installer_effect.package_manifest".to_owned(),
        reason: error.to_string(),
    }
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
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must not contain parent-directory traversal".to_owned(),
        });
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn protected_snapshot_digest_from_governor_bytes(
    bytes: &[u8],
    installation: &PlatformHandle,
    generation: &PlatformHandle,
    kernel_digest: &str,
) -> Result<PlatformHandle, InstallationError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| InstallationError::InvalidField {
            field: "generation.eliotd-governor.json".to_owned(),
            reason: format!("protected snapshot identity parse failed: {error}"),
        })?;
    let digest = value
        .get("protected_snapshot_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| InstallationError::InvalidField {
            field: "generation.protected_snapshot_digest".to_owned(),
            reason: "source governor config must carry the protected snapshot identity".to_owned(),
        })?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(InstallationError::InvalidField {
            field: "generation.protected_snapshot_digest".to_owned(),
            reason: "must be a lowercase SHA-256 digest".to_owned(),
        });
    }
    let expected = hex_digest(
        format!(
            "governor-protected:{}:{}:{}",
            installation.as_str(),
            generation.as_str(),
            kernel_digest
        )
        .as_bytes(),
    );
    if digest != expected {
        return Err(InstallationError::IdentityConflict);
    }
    PlatformHandle::new(digest.to_owned()).map_err(|error| InstallationError::InvalidField {
        field: "generation.protected_snapshot_digest".to_owned(),
        reason: error.to_string(),
    })
}

const CANARY_ARTIFACT_SET_EVIDENCE_DOMAIN: &[u8] =
    b"eliot.runtime-live.canary-artifact-set-evidence.v1";

/// The immutable Phase-A facts used only to derive the typed launch-template
/// nonce and Store credential target.
///
/// `generation.json` contains the resulting `RuntimeLaunchDescriptor`, while
/// `eliotd.json` contains the same launch nonce.  Including either file in the
/// derivation input would create a cryptographic self-reference.  The complete
/// fifteen-role artifact evidence remains separate and continues to bind both
/// files byte-for-byte.
// This is a package-planner derivation domain, not a registry wire revision:
// RegistryWireV10 decoding and its explicit active-Phase-B migration rules
// remain unchanged by this non-recursive template split.
const PHASE_A_TEMPLATE_CONTENT_DOMAIN: &[u8] = b"eliot.runtime-live.phase-a-template-content.v1";
const PHASE_A_TEMPLATE_ROLES: [(&str, bool); 12] = [
    ("eliot-host.exe", true),
    ("eliot-watchdog.exe", true),
    ("eliot-kernel.exe", true),
    ("eliot-store-surreal.exe", true),
    ("surreal.exe", true),
    ("eliotd.exe", true),
    ("eliot-doctor.exe", true),
    ("eliot-testd.exe", true),
    ("eliot-native-worker.exe", true),
    ("eliot-wasm-host.exe", true),
    ("eliot-user-broker.exe", true),
    ("eliotd-governor.json", false),
];

/// The planner-side, wire-complete projection of `generation.json`.
///
/// The concrete Store service owns `StoreLaunchConfig`; this projection keeps
/// the installation crate acyclic while still requiring every serialized
/// launch field to be present before a package can be planned.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannerStoreLaunchConfig {
    store_pipe: String,
    launch_nonce: String,
    expected_client_sid: String,
    expected_client_session_id: u32,
    approved_artifact_hash: String,
    approved_config_hash: String,
    endpoint: String,
    provider_bind_address: String,
    namespace: String,
    database: String,
    username: String,
    connect_timeout_ms: u64,
    query_timeout_ms: u64,
    /// Kernel-configured store transaction limit. Exact typed mirror of the
    /// bridge `StoreLaunchConfig` field: absent in legacy files means default
    /// (serde default), and the installer projection must encode it
    /// identically to the bridge `OperationalConfig` or approvals split.
    #[serde(default)]
    store_transaction_limit: Option<usize>,
    schema_generation: String,
    blob_root: String,
    instance_id: String,
    credential_ref: String,
    /// Exact typed mirror of the bridge `StoreLaunchConfig` provider bootstrap
    /// credential reference field. I15.4 requires the server bootstrap/admin and
    /// the normal application credential to be distinct, independently
    /// rotatable references, so this field is part of the launch declaration and
    /// therefore part of the approved-digest projection. `deny_unknown_fields`
    /// above makes omitting it here a hard parse failure, not a silent default.
    provider_bootstrap_credential_ref: String,
    /// Exact typed mirror of the bridge `StoreLaunchConfig` provider bootstrap
    /// identity field, for the same reason.
    provider_bootstrap_username: String,
    runtime_launch: RuntimeLaunchDescriptor,
}

#[derive(serde::Serialize)]
struct PlannerOperationalConfig<'a> {
    store_pipe: &'a str,
    launch_nonce: &'a str,
    expected_client_sid: &'a str,
    expected_client_session_id: u32,
    approved_artifact_hash: &'a str,
    endpoint: &'a str,
    provider_bind_address: &'a str,
    namespace: &'a str,
    database: &'a str,
    username: &'a str,
    connect_timeout_ms: u64,
    query_timeout_ms: u64,
    // Encoded identically to the bridge `OperationalConfig`: omitted when
    // unset so legacy approved bytes stay unchanged; an explicit limit is
    // part of the approval either way.
    #[serde(skip_serializing_if = "Option::is_none")]
    store_transaction_limit: Option<usize>,
    schema_generation: &'a str,
    blob_root: &'a str,
    instance_id: &'a str,
    credential_ref: &'a str,
    provider_bootstrap_credential_ref: &'a str,
    provider_bootstrap_username: &'a str,
    runtime_launch: &'a RuntimeLaunchDescriptor,
}

fn validate_source_store_config(
    bytes: &[u8],
    expected_config_path: &Path,
) -> Result<PlannerStoreLaunchConfig, InstallationError> {
    let config: PlannerStoreLaunchConfig =
        serde_json::from_slice(bytes).map_err(|error| InstallationError::InvalidField {
            field: "generation.json".to_owned(),
            reason: format!("StoreLaunchConfig parse failed: {error}"),
        })?;
    if !RuntimeLiveStoreIdentity::canonical().is_exact_match(
        &config.provider_bind_address,
        &config.endpoint,
        &config.namespace,
    ) {
        return Err(InstallationError::IdentityConflict);
    }
    if config.endpoint != format!("ws://{}/rpc", config.provider_bind_address)
        || config.database.trim().is_empty()
        || config.username.trim().is_empty()
        || config.store_pipe.trim().is_empty()
        || config.launch_nonce.trim().is_empty()
        || config.credential_ref.trim().is_empty()
        || config.blob_root.trim().is_empty()
        || config.instance_id.trim().is_empty()
        || config.schema_generation.trim().is_empty()
        || config.expected_client_sid.trim().is_empty()
        || config.approved_artifact_hash.len() != 64
        || config.approved_config_hash.len() != 64
        || config.connect_timeout_ms == 0
        || config.query_timeout_ms == 0
        || config.store_transaction_limit == Some(0)
    {
        return Err(InstallationError::IdentityConflict);
    }
    config.runtime_launch.validate_for_config(
        &PlatformHandle::new(expected_config_path.to_string_lossy().into_owned()).map_err(
            |error| InstallationError::InvalidField {
                field: "generation.json.runtime_launch.store_config_path".to_owned(),
                reason: error.to_string(),
            },
        )?,
    )?;
    let operational = PlannerOperationalConfig {
        store_pipe: &config.store_pipe,
        launch_nonce: &config.launch_nonce,
        expected_client_sid: &config.expected_client_sid,
        expected_client_session_id: config.expected_client_session_id,
        approved_artifact_hash: &config.approved_artifact_hash,
        endpoint: &config.endpoint,
        provider_bind_address: &config.provider_bind_address,
        namespace: &config.namespace,
        database: &config.database,
        username: &config.username,
        connect_timeout_ms: config.connect_timeout_ms,
        query_timeout_ms: config.query_timeout_ms,
        store_transaction_limit: config.store_transaction_limit,
        schema_generation: &config.schema_generation,
        blob_root: &config.blob_root,
        instance_id: &config.instance_id,
        credential_ref: &config.credential_ref,
        provider_bootstrap_credential_ref: &config.provider_bootstrap_credential_ref,
        provider_bootstrap_username: &config.provider_bootstrap_username,
        runtime_launch: &config.runtime_launch,
    };
    let digest = hex_digest(&serde_json::to_vec(&operational).map_err(|error| {
        InstallationError::InvalidField {
            field: "generation.json.approved_config_hash".to_owned(),
            reason: error.to_string(),
        }
    })?);
    if digest != config.approved_config_hash {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(config)
}

fn append_evidence_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

/// Derive the Runtime Live canary artifact-set evidence reference.
///
/// The reference is a domain-separated SHA-256 over the canonical generation
/// and the complete, fixed-order fifteen-file Phase-A inventory, extended by the
/// two optional module-provenance roles when a manifest carries them. Each fact
/// contains the validated relative path, executable bit, exact byte size, and
/// lowercase SHA-256.  Source identities and other volatile filesystem
/// observations are deliberately excluded; the retained-source and destination
/// receipt gates bind those observations transitively to this immutable fact
/// set.
pub(crate) fn artifact_set_evidence_digest(
    manifest: &PackageManifest,
    expected: &[PackageArtifactDigest],
) -> Result<PlatformHandle, InstallationError> {
    let roles = package_roles_for_manifest(manifest)?;
    if expected.len() != roles.len() {
        return Err(InstallationError::IncompleteObservation(
            "canary artifact evidence requires every file in the approved runtime inventory"
                .to_owned(),
        ));
    }
    let generation = validate_package_relative_path(Path::new(&manifest.generation))
        .map_err(|error| package_plan_error(&error))?;
    let mut manifest_names = BTreeSet::new();
    let mut expected_names = BTreeSet::new();
    let mut facts = Vec::with_capacity(roles.len());

    for &(role, executable) in &roles {
        let spec = manifest
            .files
            .iter()
            .find(|spec| spec.relative_path == role)
            .ok_or(InstallationError::IdentityConflict)?;
        let validated_path = validate_package_relative_path(Path::new(&spec.relative_path))
            .map_err(|error| package_plan_error(&error))?;
        if validated_path.as_str() != role || spec.executable != executable {
            return Err(InstallationError::IdentityConflict);
        }
        if !manifest_names.insert(spec.relative_path.clone()) {
            return Err(InstallationError::Duplicate {
                kind: "canary artifact manifest path".to_owned(),
                identity: spec.relative_path.clone(),
            });
        }

        let item = expected
            .iter()
            .find(|item| item.relative_path == role)
            .ok_or(InstallationError::IdentityConflict)?;
        let expected_path = validate_package_relative_path(Path::new(&item.relative_path))
            .map_err(|error| package_plan_error(&error))?;
        if expected_path.as_str() != role || item.expected_size != spec.expected_size {
            return Err(InstallationError::IdentityConflict);
        }
        if !expected_names.insert(item.relative_path.clone()) {
            return Err(InstallationError::Duplicate {
                kind: "canary artifact digest path".to_owned(),
                identity: item.relative_path.clone(),
            });
        }
        crate::sha256_handle(&item.sha256, "canary artifact digest")?;
        facts.push((
            validated_path.as_str().to_owned(),
            executable,
            spec.expected_size,
            item.sha256.as_str().to_owned(),
        ));
    }

    if manifest_names.len() != manifest.files.len()
        || expected_names.len() != expected.len()
        || manifest_names.len() != roles.len()
        || expected_names.len() != roles.len()
    {
        return Err(InstallationError::IdentityConflict);
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANARY_ARTIFACT_SET_EVIDENCE_DOMAIN);
    bytes.push(0);
    append_evidence_text(&mut bytes, generation.as_str());
    bytes.extend_from_slice(&(facts.len() as u64).to_le_bytes());
    for (relative_path, executable, expected_size, sha256) in facts {
        append_evidence_text(&mut bytes, &relative_path);
        bytes.push(u8::from(executable));
        bytes.extend_from_slice(&expected_size.to_le_bytes());
        append_evidence_text(&mut bytes, &sha256);
    }
    PlatformHandle::new(hex_digest(&bytes)).map_err(|error| InstallationError::InvalidField {
        field: "generation.signature_ref".to_owned(),
        reason: error.to_string(),
    })
}

/// Derive the non-recursive Phase-A content digest used only for launch
/// template derivation.
///
/// The input is the typed twelve-role expected fact set. The helper validates
/// that exact set and hashes it in the fixed order above.  `generation.json`
/// and `eliotd.json` remain fully bound by [`artifact_set_evidence_digest`],
/// the candidate manifest and the staging receipt; they are excluded here
/// solely because both contain the derived launch nonce.
pub fn phase_a_template_content_digest(
    expected: &[PackageArtifactDigest],
) -> Result<PlatformHandle, InstallationError> {
    if expected.len() != PHASE_A_TEMPLATE_ROLES.len() {
        return Err(InstallationError::IncompleteObservation(
            "Phase-A template facts require exactly twelve immutable roles".to_owned(),
        ));
    }
    let mut names = BTreeSet::new();
    for item in expected {
        let path = validate_package_relative_path(Path::new(&item.relative_path))
            .map_err(|error| package_plan_error(&error))?;
        if path.as_str() != item.relative_path || !names.insert(item.relative_path.clone()) {
            return Err(InstallationError::IdentityConflict);
        }
        crate::sha256_handle(&item.sha256, "Phase-A template fact digest")?;
        if item.expected_size == 0 {
            return Err(InstallationError::InvalidField {
                field: "Phase-A template fact size".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
    }
    let expected_names = PHASE_A_TEMPLATE_ROLES
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    if names != expected_names {
        return Err(InstallationError::IdentityConflict);
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(PHASE_A_TEMPLATE_CONTENT_DOMAIN);
    bytes.push(0);
    bytes.extend_from_slice(&(PHASE_A_TEMPLATE_ROLES.len() as u64).to_le_bytes());
    for (role, executable) in PHASE_A_TEMPLATE_ROLES {
        let item = expected
            .iter()
            .find(|item| item.relative_path == role)
            .ok_or(InstallationError::IdentityConflict)?;
        append_evidence_text(&mut bytes, role);
        bytes.push(u8::from(executable));
        bytes.extend_from_slice(&item.expected_size.to_le_bytes());
        append_evidence_text(&mut bytes, item.sha256.as_str());
    }
    PlatformHandle::new(hex_digest(&bytes)).map_err(|error| InstallationError::InvalidField {
        field: "generation.phase_a_template_content_digest".to_owned(),
        reason: error.to_string(),
    })
}

#[cfg(test)]
fn expected_role_map(candidate: &CandidateManifest) -> Vec<(String, bool, String)> {
    let rt = &candidate.runtime_launch;
    let file_name = |p: &PlatformHandle| {
        Path::new(p.as_str())
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_owned()
    };
    vec![
        (
            file_name(&candidate.kernel_executable_path),
            true,
            candidate.kernel_artifact_digest.as_str().to_owned(),
        ),
        (
            file_name(&candidate.host_executable_path),
            true,
            candidate.host_artifact_digest.as_str().to_owned(),
        ),
        (
            file_name(&rt.watchdog_executable_path),
            true,
            rt.watchdog_artifact_digest.as_str().to_owned(),
        ),
        (
            file_name(&candidate.store_bridge_executable_path),
            true,
            candidate.store_bridge_artifact_digest.as_str().to_owned(),
        ),
        (
            file_name(&candidate.canonical_store_executable_path),
            true,
            candidate
                .canonical_store_artifact_digest
                .as_str()
                .to_owned(),
        ),
        (
            file_name(&rt.eliotd_executable_path),
            true,
            rt.eliotd_artifact_digest.as_str().to_owned(),
        ),
        (
            file_name(&candidate.doctor_executable_path),
            true,
            candidate.doctor_artifact_digest.as_str().to_owned(),
        ),
        (
            file_name(&candidate.testd_executable_path),
            true,
            candidate.testd_artifact_digest.as_str().to_owned(),
        ),
        (
            file_name(&candidate.native_worker_executable_path),
            true,
            candidate.native_worker_artifact_digest.as_str().to_owned(),
        ),
        (
            file_name(&candidate.wasm_host_executable_path),
            true,
            candidate.wasm_host_artifact_digest.as_str().to_owned(),
        ),
        (
            file_name(&candidate.user_broker_executable_path),
            true,
            candidate.user_broker_artifact_digest.as_str().to_owned(),
        ),
        (
            file_name(&candidate.config_path),
            false,
            candidate.config_digest.as_str().to_owned(),
        ),
        (
            file_name(&rt.eliotd_config_path),
            false,
            rt.eliotd_config_digest.as_str().to_owned(),
        ),
        (
            file_name(&rt.eliotd_descriptor_path),
            false,
            rt.eliotd_descriptor_digest.as_str().to_owned(),
        ),
    ]
}

#[cfg(test)]
fn validate_candidate_package_binding(
    candidate: &CandidateManifest,
    manifest: &PackageManifest,
) -> Result<(), InstallationError> {
    if manifest.generation != candidate.generation.as_str() {
        return Err(InstallationError::IdentityConflict);
    }
    crate::sha256_handle(&candidate.signature_ref, "manifest.signature_ref")?;
    if candidate.signature_ref.as_str() == "0".repeat(64)
        || candidate.signature_ref.as_str() == "1".repeat(64)
    {
        return Err(InstallationError::InvalidField {
            field: "manifest.signature_ref".to_owned(),
            reason: "placeholder signature not admitted".to_owned(),
        });
    }
    let roles = expected_role_map(candidate);
    let all_placeholder = roles.iter().all(|(_, _, d)| {
        d.len() == 64
            && d.chars()
                .next()
                .is_some_and(|first| d.chars().all(|c| c == first))
    });
    if all_placeholder {
        let mut seen = std::collections::BTreeSet::new();
        for spec in &manifest.files {
            let validated = validate_package_relative_path(Path::new(&spec.relative_path))
                .map_err(|e| package_plan_error(&e))?;
            let lower = validated.as_str().to_ascii_lowercase();
            if !seen.insert(lower) {
                return Err(InstallationError::Duplicate {
                    kind: "package file".to_owned(),
                    identity: spec.relative_path.clone(),
                });
            }
            if spec.expected_size == 0 || spec.expected_size > 512 * 1024 * 1024 {
                return Err(InstallationError::InvalidField {
                    field: "installer_effect.package_manifest.files.expected_size".to_owned(),
                    reason: "out of bounds".to_owned(),
                });
            }
        }
        return Ok(());
    }
    // `eliot-notify.exe` is staged in Phase A but never Kernel-dispatched
    // (NOTIFY_STAGED_ROLE, I1.3/I1.4): accept exactly one such entry, then
    // validate the remaining pinned-role bijection below.
    let mut notify_staged = false;
    for spec in &manifest.files {
        if spec.relative_path == NOTIFY_STAGED_ROLE {
            if spec.executable != NOTIFY_STAGED_EXECUTABLE || notify_staged {
                return Err(InstallationError::IdentityConflict);
            }
            notify_staged = true;
        }
    }
    if manifest.files.len() != roles.len() + usize::from(notify_staged) {
        return Err(InstallationError::IdentityConflict);
    }
    let mut seen = std::collections::BTreeSet::new();
    let manifest_lower: BTreeSet<String> = manifest
        .files
        .iter()
        .filter(|f| f.relative_path != NOTIFY_STAGED_ROLE)
        .map(|f| f.relative_path.to_ascii_lowercase())
        .collect();
    let mut role_lower: BTreeSet<String> = BTreeSet::new();
    for (rel, exe, _) in &roles {
        let validated =
            validate_package_relative_path(Path::new(rel)).map_err(|e| package_plan_error(&e))?;
        let lower = validated.as_str().to_ascii_lowercase();
        if !role_lower.insert(lower.clone()) {
            return Err(InstallationError::Duplicate {
                kind: "package role".to_owned(),
                identity: rel.clone(),
            });
        }
        let spec = manifest
            .files
            .iter()
            .find(|f| eliot_platform_windows::ordinal_eq_str(&f.relative_path, rel))
            .ok_or(InstallationError::IdentityConflict)?;
        if spec.executable != *exe {
            return Err(InstallationError::InvalidField {
                field: "installer_effect.package_manifest.files.executable".to_owned(),
                reason: format!("role {rel} executable flag mismatch"),
            });
        }
        if spec.expected_size == 0 || spec.expected_size > 512 * 1024 * 1024 {
            return Err(InstallationError::InvalidField {
                field: "installer_effect.package_manifest.files.expected_size".to_owned(),
                reason: "out of bounds".to_owned(),
            });
        }
        if !seen.insert(lower) {
            return Err(InstallationError::Duplicate {
                kind: "package file".to_owned(),
                identity: spec.relative_path.clone(),
            });
        }
    }
    if manifest_lower != role_lower {
        return Err(InstallationError::IdentityConflict);
    }
    let mut manifest_sorted: Vec<_> = manifest
        .files
        .iter()
        .filter(|spec| spec.relative_path != NOTIFY_STAGED_ROLE)
        .collect();
    manifest_sorted.sort_by(|a, b| {
        eliot_platform_windows::ordinal_cmp_str(&a.relative_path, &b.relative_path)
    });
    let mut roles_sorted = roles.clone();
    roles_sorted.sort_by(|a, b| eliot_platform_windows::ordinal_cmp_str(&a.0, &b.0));
    for (spec, (role_path, _, _)) in manifest_sorted.iter().zip(roles_sorted.iter()) {
        if !eliot_platform_windows::ordinal_eq_str(&spec.relative_path, role_path) {
            return Err(InstallationError::IdentityConflict);
        }
    }
    Ok(())
}

pub(crate) fn strict_role_bindings(
    candidate: &CandidateManifest,
) -> [(&'static str, bool, &PlatformHandle, &PlatformHandle); 13] {
    let runtime = &candidate.runtime_launch;
    [
        (
            "eliot-host.exe",
            true,
            &candidate.host_executable_path,
            &candidate.host_artifact_digest,
        ),
        (
            "eliot-watchdog.exe",
            true,
            &runtime.watchdog_executable_path,
            &runtime.watchdog_artifact_digest,
        ),
        (
            "eliot-kernel.exe",
            true,
            &candidate.kernel_executable_path,
            &candidate.kernel_artifact_digest,
        ),
        (
            "eliot-store-surreal.exe",
            true,
            &candidate.store_bridge_executable_path,
            &candidate.store_bridge_artifact_digest,
        ),
        (
            "surreal.exe",
            true,
            &candidate.canonical_store_executable_path,
            &candidate.canonical_store_artifact_digest,
        ),
        (
            "eliotd.exe",
            true,
            &runtime.eliotd_executable_path,
            &runtime.eliotd_artifact_digest,
        ),
        (
            "eliot-doctor.exe",
            true,
            &candidate.doctor_executable_path,
            &candidate.doctor_artifact_digest,
        ),
        (
            "eliot-testd.exe",
            true,
            &candidate.testd_executable_path,
            &candidate.testd_artifact_digest,
        ),
        (
            "eliot-native-worker.exe",
            true,
            &candidate.native_worker_executable_path,
            &candidate.native_worker_artifact_digest,
        ),
        (
            "eliot-wasm-host.exe",
            true,
            &candidate.wasm_host_executable_path,
            &candidate.wasm_host_artifact_digest,
        ),
        (
            "generation.json",
            false,
            &candidate.config_path,
            &candidate.config_digest,
        ),
        (
            "eliotd-governor.json",
            false,
            &runtime.eliotd_config_path,
            &runtime.eliotd_config_digest,
        ),
        (
            "eliotd.json",
            false,
            &runtime.eliotd_descriptor_path,
            &runtime.eliotd_descriptor_digest,
        ),
    ]
}

/// Validate the complete production package bijection.
///
/// This boundary is intentionally independent of the caller's manifest and
/// expected-digest vectors. It binds all thirteen canonical Phase-A
/// launch-bound roles and the immutable per-user User Broker executable. The Broker is
/// pinned by exact installed path and digest in the candidate and launch
/// descriptor, but remains outside Host-managed daemon roles. The notification
/// adapter remains evidence-bound only and has no launch-descriptor binding.
#[allow(
    clippy::too_many_lines,
    reason = "the exact package bijection validates candidate roles, optional module provenance, and manifest membership together"
)]
pub(crate) fn validate_exact_candidate_package_binding(
    candidate: &CandidateManifest,
    manifest: &PackageManifest,
) -> Result<(), InstallationError> {
    if manifest.generation != candidate.generation.as_str() {
        return Err(InstallationError::IdentityConflict);
    }
    let roles = package_roles_for_manifest(manifest)?;
    let bindings = strict_role_bindings(candidate);
    let mut expected_names = BTreeSet::new();
    let mut candidate_paths = BTreeSet::new();
    for (name, executable, path, digest) in bindings {
        if !expected_names.insert(name.to_ascii_lowercase()) {
            return Err(InstallationError::Duplicate {
                kind: "package role".to_owned(),
                identity: name.to_owned(),
            });
        }
        let actual_name = Path::new(path.as_str())
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if actual_name != name {
            return Err(InstallationError::IdentityConflict);
        }
        if !candidate_paths.insert(path.as_str().to_ascii_lowercase()) {
            return Err(InstallationError::Duplicate {
                kind: "candidate package path".to_owned(),
                identity: path.as_str().to_owned(),
            });
        }
        crate::sha256_handle(digest, "candidate package role digest")?;
        let Some(spec) = manifest
            .files
            .iter()
            .find(|spec| spec.relative_path == name)
        else {
            return Err(InstallationError::IdentityConflict);
        };
        if spec.executable != executable || spec.expected_size == 0 {
            return Err(InstallationError::IdentityConflict);
        }
    }
    let broker_path = &candidate.user_broker_executable_path;
    let broker_digest = &candidate.user_broker_artifact_digest;
    if Path::new(broker_path.as_str())
        .file_name()
        .and_then(|value| value.to_str())
        != Some(USER_BROKER_STAGED_ROLE)
    {
        return Err(InstallationError::IdentityConflict);
    }
    crate::sha256_handle(broker_digest, "candidate user broker artifact digest")?;
    if !expected_names.insert(USER_BROKER_STAGED_ROLE.to_ascii_lowercase())
        || !candidate_paths.insert(broker_path.as_str().to_ascii_lowercase())
    {
        return Err(InstallationError::Duplicate {
            kind: "candidate package path".to_owned(),
            identity: broker_path.as_str().to_owned(),
        });
    }
    let broker_spec = manifest
        .files
        .iter()
        .find(|spec| spec.relative_path == USER_BROKER_STAGED_ROLE)
        .ok_or(InstallationError::IdentityConflict)?;
    if !USER_BROKER_STAGED_EXECUTABLE || !broker_spec.executable || broker_spec.expected_size == 0 {
        return Err(InstallationError::IdentityConflict);
    }
    for &(name, executable) in &roles {
        if !MODULE_BUILD_PROVENANCE_ROLES
            .iter()
            .any(|(optional_name, _)| optional_name == &name)
        {
            continue;
        }
        let spec = manifest
            .files
            .iter()
            .find(|spec| spec.relative_path == name)
            .ok_or(InstallationError::IdentityConflict)?;
        if spec.executable != executable
            || spec.expected_size == 0
            || !expected_names.insert(name.to_ascii_lowercase())
        {
            return Err(InstallationError::IdentityConflict);
        }
    }
    let host_symbols = candidate.runtime_launch.host_symbol_binding.as_ref();
    let kernel_symbols = candidate.runtime_launch.kernel_symbol_binding.as_ref();
    if host_symbols.is_some() != kernel_symbols.is_some() {
        return Err(InstallationError::IdentityConflict);
    }
    for (binding, (name, executable)) in [
        (host_symbols, RELEASE_SYMBOL_ROLES[0]),
        (kernel_symbols, RELEASE_SYMBOL_ROLES[1]),
    ] {
        if let Some(binding) = binding {
            if binding.symbol_artifact_ref.as_str() != name {
                return Err(InstallationError::IdentityConflict);
            }
            let spec = manifest
                .files
                .iter()
                .find(|spec| spec.relative_path == name)
                .ok_or(InstallationError::IdentityConflict)?;
            if spec.executable != executable
                || spec.expected_size == 0
                || !expected_names.insert(name.to_ascii_lowercase())
            {
                return Err(InstallationError::IdentityConflict);
            }
        }
    }
    let mut manifest_names = BTreeSet::new();
    for spec in &manifest.files {
        if spec.relative_path == NOTIFY_STAGED_ROLE {
            if spec.executable != NOTIFY_STAGED_EXECUTABLE
                || !manifest_names.insert(spec.relative_path.clone())
            {
                return Err(InstallationError::IdentityConflict);
            }
            continue;
        }
        let Some((name, executable)) = roles.iter().find(|(name, _)| *name == spec.relative_path)
        else {
            return Err(InstallationError::IdentityConflict);
        };
        if spec.executable != *executable || !manifest_names.insert((*name).to_owned()) {
            return Err(InstallationError::IdentityConflict);
        }
    }
    manifest_names.remove(NOTIFY_STAGED_ROLE);
    if manifest_names != expected_names {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn candidate_has_nonplaceholder_package_digests(candidate: &CandidateManifest) -> bool {
    strict_role_bindings(candidate)
        .into_iter()
        .chain(std::iter::once((
            USER_BROKER_STAGED_ROLE,
            USER_BROKER_STAGED_EXECUTABLE,
            &candidate.user_broker_executable_path,
            &candidate.user_broker_artifact_digest,
        )))
        .any(|(_, _, _, digest)| {
            let value = digest.as_str();
            value.len() != 64
                || value
                    .chars()
                    .next()
                    .is_none_or(|first| !value.chars().all(|item| item == first))
        })
}

#[allow(dead_code)]
pub(crate) fn validate_exact_expected_file_digests(
    candidate: &CandidateManifest,
    manifest: &PackageManifest,
    expected: &[PackageArtifactDigest],
) -> Result<(), InstallationError> {
    validate_exact_candidate_package_binding(candidate, manifest)?;
    let roles = package_roles_for_manifest(manifest)?;
    if expected.len() != roles.len() {
        return Err(InstallationError::IncompleteObservation(
            "expected package digest set must contain every approved runtime file".to_owned(),
        ));
    }
    let bindings = strict_role_bindings(candidate);
    let mut seen = BTreeSet::new();
    for item in expected {
        if !seen.insert(item.relative_path.clone()) {
            return Err(InstallationError::Duplicate {
                kind: "expected package digest".to_owned(),
                identity: item.relative_path.clone(),
            });
        }
        if item.relative_path == NOTIFY_STAGED_ROLE {
            let spec = manifest
                .files
                .iter()
                .find(|spec| spec.relative_path == item.relative_path)
                .ok_or(InstallationError::IdentityConflict)?;
            if !spec.executable
                || item.expected_size == 0
                || item.expected_size != spec.expected_size
            {
                return Err(InstallationError::IdentityConflict);
            }
            crate::sha256_handle(&item.sha256, "expected package digest")?;
            continue;
        }
        if MODULE_BUILD_PROVENANCE_ROLES
            .iter()
            .any(|(name, _)| *name == item.relative_path)
        {
            let spec = manifest
                .files
                .iter()
                .find(|spec| spec.relative_path == item.relative_path)
                .ok_or(InstallationError::IdentityConflict)?;
            if spec.executable
                || item.expected_size == 0
                || item.expected_size != spec.expected_size
            {
                return Err(InstallationError::IdentityConflict);
            }
            crate::sha256_handle(&item.sha256, "expected module proof digest")?;
            continue;
        }
        if RELEASE_SYMBOL_ROLES
            .iter()
            .any(|(name, _)| *name == item.relative_path)
        {
            let spec = manifest
                .files
                .iter()
                .find(|spec| spec.relative_path == item.relative_path)
                .ok_or(InstallationError::IdentityConflict)?;
            if spec.executable
                || item.expected_size == 0
                || item.expected_size != spec.expected_size
            {
                return Err(InstallationError::IdentityConflict);
            }
            crate::sha256_handle(&item.sha256, "expected symbol artifact digest")?;
            let binding = if item.relative_path == RELEASE_SYMBOL_ROLES[0].0 {
                candidate.runtime_launch.host_symbol_binding.as_ref()
            } else {
                candidate.runtime_launch.kernel_symbol_binding.as_ref()
            }
            .ok_or(InstallationError::IdentityConflict)?;
            if item.sha256 != binding.symbol_artifact_sha256 {
                return Err(InstallationError::IdentityConflict);
            }
            continue;
        }
        if item.relative_path == USER_BROKER_STAGED_ROLE {
            let spec = manifest
                .files
                .iter()
                .find(|spec| spec.relative_path == item.relative_path)
                .ok_or(InstallationError::IdentityConflict)?;
            if !spec.executable
                || item.expected_size == 0
                || item.expected_size != spec.expected_size
            {
                return Err(InstallationError::IdentityConflict);
            }
            crate::sha256_handle(&item.sha256, "expected package digest")?;
            if item.sha256 != candidate.user_broker_artifact_digest {
                return Err(InstallationError::IdentityConflict);
            }
            continue;
        }
        let Some((name, _, _, digest)) = bindings
            .into_iter()
            .find(|(name, _, _, _)| *name == item.relative_path)
        else {
            return Err(InstallationError::IdentityConflict);
        };
        let spec = manifest
            .files
            .iter()
            .find(|spec| spec.relative_path == item.relative_path)
            .ok_or(InstallationError::IdentityConflict)?;
        if item.expected_size == 0 || item.expected_size != spec.expected_size {
            return Err(InstallationError::InvalidField {
                field: "expected package digest expected_size".to_owned(),
                reason: "must exactly equal the immutable package manifest byte size".to_owned(),
            });
        }
        crate::sha256_handle(&item.sha256, "expected package digest")?;
        if item.sha256 != *digest || name != item.relative_path.as_str() {
            return Err(InstallationError::IdentityConflict);
        }
    }
    let expected_names = roles
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    if seen != expected_names {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}

fn derive_expected_digests(
    observed: &PackageSourceObservation,
    manifest: &PackageManifest,
) -> Result<Vec<PackageArtifactDigest>, InstallationError> {
    let mut digests = Vec::with_capacity(manifest.files.len());
    for spec in &manifest.files {
        let Some(entry) = observed.files.iter().find(|f| {
            eliot_platform_windows::ordinal_eq_str(&f.relative_path, &spec.relative_path)
        }) else {
            return Err(InstallationError::Platform(format!(
                "package file not found: {}",
                spec.relative_path
            )));
        };
        if entry.size != spec.expected_size {
            return Err(InstallationError::InvalidField {
                field: "source_bundle".to_owned(),
                reason: "package file size differs from the exact manifest expectation".to_owned(),
            });
        }
        if spec.executable {
            entry
                .pe
                .as_ref()
                .ok_or_else(|| InstallationError::InvalidField {
                    field: "source_bundle.executable".to_owned(),
                    reason: "source observation is not an AMD64 PE/COFF executable".to_owned(),
                })?;
        } else if entry.pe.is_some() {
            return Err(InstallationError::InvalidField {
                field: "source_bundle.executable".to_owned(),
                reason: "non-executable package role contains PE/COFF evidence".to_owned(),
            });
        }
        let sha_handle = PlatformHandle::new(entry.sha256.clone()).map_err(|e| {
            InstallationError::InvalidField {
                field: "sha256".to_owned(),
                reason: e.to_string(),
            }
        })?;
        digests.push(PackageArtifactDigest {
            relative_path: spec.relative_path.clone(),
            expected_size: spec.expected_size,
            sha256: sha_handle,
        });
    }
    if digests.len() != observed.files.len() {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(digests)
}

#[cfg(test)]
fn enumerate_source_tree(
    observed: &PackageSourceObservation,
) -> Result<BTreeSet<String>, InstallationError> {
    let mut set = BTreeSet::new();
    for file in &observed.files {
        let validated = validate_package_relative_path(Path::new(&file.relative_path))
            .map_err(|e| package_plan_error(&e))?;
        let lower = validated.as_str().to_ascii_lowercase();
        if !set.insert(lower) {
            return Err(InstallationError::Duplicate {
                kind: "package file".to_owned(),
                identity: file.relative_path.clone(),
            });
        }
    }
    Ok(set)
}

/// In-memory proof that a published source bundle is the exact bundle that
/// the planner is about to observe.  This is deliberately not part of the
/// transaction wire: the resulting candidate signature/effect digests are the
/// durable authority, while this proof closes the materializer-to-planner
/// handoff window.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceBundlePublicationBinding {
    source_identity: FileIdentity,
    files: Vec<PackageArtifactDigest>,
    evidence_digest: PlatformHandle,
}

/// Explicit inputs accepted by the production generation planner.
///
/// Every identity and path is supplied by the caller.  In particular, there
/// is no environment, current-directory, timestamp or implicit profile-root
/// lookup in this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationPackagePlanInput {
    /// Stable transaction identity.
    pub transaction_id: PlatformHandle,
    /// Installation and lineage identity with its explicit sequence.
    pub installation_epoch: InstallationEpoch,
    /// Explicit supervision/path profile.
    pub profile: InstallationProfile,
    /// OS-validated profile anchor selected by the caller.
    pub profile_anchor_root: PlatformHandle,
    /// Lowercase installation key required by profiled roots.
    pub installation_key: Option<PlatformHandle>,
    /// Canonical relative package generation identity.
    pub generation: PlatformHandle,
    /// Absolute retained source bundle directory.
    pub source_root: PlatformHandle,
    /// Absolute immutable staging destination root.
    pub staging_root: PlatformHandle,
    /// Explicit store-volume minimum required by the transaction policy.
    pub minimum_store_available_bytes: u64,
    /// Explicit recovery command/reference retained in the transaction.
    pub recovery_command: PlatformHandle,
    /// Optional immutable external agent-bridge source materialization plan.
    /// `None` preserves the legacy package-plan carrier.
    pub agent_bridge_source: Option<Box<AgentBridgeSourceMaterializationPlan>>,
}

/// Explicit I3.1 root-selection inputs for the profile-governed planner entry.
///
/// Every value is supplied by the caller. The OS-proved anchors come from the
/// Windows adapter, never from process environment variables or the current
/// directory; a required anchor that was not proved is a typed refusal from
/// the selector, never a guess.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileRootSelectionInput {
    /// OS-proved profile anchors for one explicitly selected profile.
    pub anchors: ProfileRootAnchors,
    /// Component name for the versioned immutable root of the Windows profiles.
    pub component: String,
    /// Component version for the versioned immutable root of the Windows profiles.
    pub version: String,
    /// Immutable-root generation for `portable_dev`, which versions its
    /// immutable root by generation rather than by release version. Required
    /// when the profile is `PortableDev`, ignored otherwise.
    pub generation: Option<String>,
}

/// The complete explicit input set for one I3.1 profile resolution.
///
/// Every value is caller-supplied: the profile, the OS-proved anchors, the
/// versioned component identity, the retained runtime anchor, and the two
/// planned write destinations that must be checked against the profile's
/// immutable binaries root. Nothing is defaulted from a process environment
/// variable, the current directory, or today's ambient state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileSelectionInput {
    /// Explicitly selected supervision/path profile.
    pub profile: InstallationProfile,
    /// OS-proved profile anchors for the selected profile.
    pub anchors: ProfileRootAnchors,
    /// OS-validated profile anchor the retained runtime roots are derived from.
    pub profile_anchor_root: PlatformHandle,
    /// Lowercase installation key for the profiled Windows profiles. Must be
    /// absent for `portable_dev`.
    pub installation_key: Option<PlatformHandle>,
    /// Component name for the versioned immutable root of the Windows profiles.
    pub component: String,
    /// Component version for the versioned immutable root of the Windows profiles.
    pub version: String,
    /// Immutable-root generation for `portable_dev`, which versions its
    /// immutable root by generation rather than by release version. Required
    /// when the profile is `PortableDev`, ignored otherwise.
    pub generation: Option<String>,
    /// Absolute immutable source-bundle directory the plan would consume.
    pub source_root: PlatformHandle,
    /// Absolute immutable staging destination the plan would use.
    pub staging_root: PlatformHandle,
}

/// What one explicitly selected profile governs, resolved once before effects.
///
/// The value is the whole answer to "which profile is this, what does it
/// write, how is it supervised, and what does it honestly not guarantee".
/// It is resolved read-only, so a caller can present or refuse it without
/// creating a root or reserving a service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileSelectionResolution {
    /// The versioned four-root binding for the selected profile.
    pub roots: InstallationRoots,
    /// Selected profile, intended supervision and enforced/unsupported
    /// guarantees. Contains no key, secret or credential value.
    pub governance: ProfileGovernanceReport,
    /// Evidence that a non-service selection does not require SCM,
    /// administrative authority or a `ProgramData` anchor. `system_service`
    /// uses SCM by definition, so it has no such proof; its requirements are
    /// reported by the selected profile's governance report instead.
    pub no_service_authority_proof: Option<NoServiceProfileAuthorityProof>,
}

/// The sole production package/transaction composition seam.
pub struct GenerationPackagePlanner;

impl GenerationPackagePlanner {
    /// Computes the canonical full fifteen-role artifact evidence reference.
    ///
    /// This associated wrapper is the public entry point for producers that
    /// need the fixed-order inventory digest. Production planning separately
    /// consumes the retained source publication through
    /// [`Self::plan_with_published_profile_binding`].
    pub fn artifact_set_evidence_digest(
        manifest: &PackageManifest,
        expected: &[PackageArtifactDigest],
    ) -> Result<PlatformHandle, InstallationError> {
        artifact_set_evidence_digest(manifest, expected)
    }

    /// Computes the canonical non-recursive Phase-A template derivation input.
    ///
    /// This is intentionally separate from the full artifact evidence
    /// reference: it exists only to let a typed source-bundle producer derive
    /// the launch nonce before the two nonce-bearing JSON roles are serialized.
    pub fn phase_a_template_content_digest(
        expected: &[PackageArtifactDigest],
    ) -> Result<PlatformHandle, InstallationError> {
        phase_a_template_content_digest(expected)
    }

    /// Build a fresh self-observed binding solely for same-crate planner
    /// fixtures. Production callers must present the materializer publication
    /// proof and exact resolved profile binding through
    /// [`Self::plan_with_published_profile_binding`].
    #[cfg(test)]
    pub(crate) fn plan_unbound_for_test(
        input: GenerationPackagePlanInput,
    ) -> Result<InstallationTransaction, InstallationError> {
        let publication_binding = test_source_publication_binding(&input)?;
        let selection = Self::test_profile_selection(&input)?;
        let resolution = Self::resolve_profile_selection(&selection)?;
        Self::plan_with_binding(input, &publication_binding, false, &selection, &resolution)
    }

    /// Test-only planner seam: compare publication facts with a fresh retained
    /// observation. Production callers use
    /// [`Self::plan_with_published_profile_binding`] so the retained I3.1 root
    /// selection is required at the same boundary.
    #[cfg(any(test, feature = "test-support"))]
    pub fn plan_with_source_publication_binding(
        input: GenerationPackagePlanInput,
        source_identity: FileIdentity,
        files: Vec<PackageArtifactDigest>,
        evidence_digest: PlatformHandle,
    ) -> Result<InstallationTransaction, InstallationError> {
        let publication_binding = SourceBundlePublicationBinding {
            source_identity,
            files,
            evidence_digest,
        };
        let selection = Self::test_profile_selection(&input)?;
        let resolution = Self::resolve_profile_selection(&selection)?;
        Self::plan_with_binding(input, &publication_binding, true, &selection, &resolution)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn test_profile_selection(
        input: &GenerationPackagePlanInput,
    ) -> Result<ProfileSelectionInput, InstallationError> {
        let fixed_test_anchor = |value: &str, field: &str| {
            PlatformHandle::new(value).map_err(|error| InstallationError::InvalidField {
                field: field.to_owned(),
                reason: error.to_string(),
            })
        };
        let local_app_data = match input.profile {
            InstallationProfile::UserMode => input.profile_anchor_root.clone(),
            InstallationProfile::SystemService | InstallationProfile::PortableDev => {
                fixed_test_anchor(
                    r"C:\Users\eliot-profile-test\AppData\Local",
                    "test_profile_selection.local_app_data",
                )?
            }
        };
        let (program_files, program_data, repository_root) = match input.profile {
            InstallationProfile::SystemService => (
                Some(fixed_test_anchor(
                    r"C:\Program Files",
                    "test_profile_selection.program_files",
                )?),
                Some(input.profile_anchor_root.clone()),
                None,
            ),
            InstallationProfile::UserMode => (None, None, None),
            InstallationProfile::PortableDev => {
                (None, None, Some(input.profile_anchor_root.clone()))
            }
        };
        Ok(ProfileSelectionInput {
            profile: input.profile,
            anchors: ProfileRootAnchors {
                program_files,
                program_data,
                local_app_data,
                repository_root,
            },
            profile_anchor_root: input.profile_anchor_root.clone(),
            installation_key: input.installation_key.clone(),
            component: "eliot-tests".to_owned(),
            version: "0.0.0-test".to_owned(),
            generation: (input.profile == InstallationProfile::PortableDev)
                .then(|| input.generation.as_str().to_owned()),
            source_root: input.source_root.clone(),
            staging_root: input.staging_root.clone(),
        })
    }

    /// Test-support-only planner seam that resolves I3.1 roots without a
    /// retained source-publication root binding.
    ///
    /// The selector resolves the exact root row for the explicitly selected
    /// profile from the caller-supplied OS-proved anchors, and the complete
    /// versioned four-root binding — immutable, durable, user configuration
    /// and user cache separately — is validated against the digest-bound
    /// runtime topology this planner derives. Planned source and staging
    /// destinations that would write mutable data beside immutable versioned
    /// binaries are refused here, before any effect is derived. Planning stays
    /// read-only: nothing is created, reserved or mutated.
    ///
    /// Production planning must use
    /// [`Self::plan_with_published_profile_binding`], which compares this
    /// independently resolved layout with the root binding retained by source
    /// publication before deriving transaction effects.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError::ProfileViolation`] for an invalid profile,
    /// a missing or ambiguous anchor, a conflicting binding, or a planned
    /// write into the versioned immutable binaries root.
    #[cfg(any(test, feature = "test-support"))]
    pub fn plan_with_profile_governed_roots(
        input: GenerationPackagePlanInput,
        selection: &ProfileRootSelectionInput,
        source_identity: FileIdentity,
        files: Vec<PackageArtifactDigest>,
        evidence_digest: PlatformHandle,
    ) -> Result<(InstallationTransaction, InstallationRoots), InstallationError> {
        // Resolve once, before any effect: the I3.1 root row, the write
        // guards, and — for a non-service profile — the structural proof that
        // the selection carries no SCM, administrative or `ProgramData`
        // dependency.
        let profile_selection = ProfileSelectionInput {
            profile: input.profile,
            anchors: selection.anchors.clone(),
            profile_anchor_root: input.profile_anchor_root.clone(),
            installation_key: input.installation_key.clone(),
            component: selection.component.clone(),
            version: selection.version.clone(),
            generation: selection.generation.clone(),
            source_root: input.source_root.clone(),
            staging_root: input.staging_root.clone(),
        };
        let resolution = Self::resolve_profile_selection(&profile_selection)?;
        let publication_binding = SourceBundlePublicationBinding {
            source_identity,
            files,
            evidence_digest,
        };
        let transaction = Self::plan_with_binding(
            input,
            &publication_binding,
            true,
            &profile_selection,
            &resolution,
        )?;
        Ok((transaction, resolution.roots))
    }

    /// Plan from the exact I3.1 root binding retained by source publication.
    ///
    /// The explicit selection is independently resolved and compared with the
    /// durable publication binding before the transaction can be constructed.
    /// The matched publication binding, rather than a newly inferred layout,
    /// is written to the transaction wire for registry persistence and restart
    /// revalidation.
    pub fn plan_with_published_profile_binding(
        input: GenerationPackagePlanInput,
        selection: &ProfileSelectionInput,
        published_roots: &InstallationRoots,
        source_identity: FileIdentity,
        files: Vec<PackageArtifactDigest>,
        evidence_digest: PlatformHandle,
    ) -> Result<InstallationTransaction, InstallationError> {
        if input.profile != selection.profile
            || input.profile_anchor_root != selection.profile_anchor_root
            || input.installation_key != selection.installation_key
            || input.source_root != selection.source_root
            || input.staging_root != selection.staging_root
            || (input.profile == InstallationProfile::PortableDev
                && selection.generation.as_deref() != Some(input.generation.as_str()))
        {
            return Err(InstallationError::ProfileViolation(
                "package plan inputs differ from the retained profile selection".to_owned(),
            ));
        }
        let resolution = Self::resolve_profile_selection(selection)?;
        if &resolution.roots != published_roots {
            return Err(InstallationError::ProfileViolation(
                "source publication profile binding differs from the resolved I3.1 selection"
                    .to_owned(),
            ));
        }
        let publication_binding = SourceBundlePublicationBinding {
            source_identity,
            files,
            evidence_digest,
        };
        Self::plan_with_binding(input, &publication_binding, true, selection, &resolution)
    }

    /// Resolves the I3.1 selection for one explicit profile, read-only.
    ///
    /// This is the single place the selected profile's roots, supervision
    /// path, honest guarantee report and unprivileged-dependency proof are
    /// produced; production planning invokes it and compares its result with
    /// the root binding retained by source publication before deriving an
    /// effect. It is exposed so a caller can inspect exactly what a
    /// profile governs before asking for a plan. Nothing here creates a root,
    /// reserves a service, or mutates durable state: an invalid profile, a
    /// missing or ambiguous anchor, a write into the versioned immutable
    /// binaries root, or an unprovable service dependency is a typed refusal.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError::ProfileViolation`] for an invalid or
    /// unsupported profile, a missing anchor, a write into the immutable
    /// binaries root, or a selection that cannot prove it depends on no
    /// service-only authority.
    pub fn resolve_profile_selection(
        selection: &ProfileSelectionInput,
    ) -> Result<ProfileSelectionResolution, InstallationError> {
        if !selection.profile.requires_admin() && selection.anchors.program_data.is_some() {
            return Err(InstallationError::ProfileViolation(
                "non-service profile selection must not receive a ProgramData anchor".to_owned(),
            ));
        }
        let governed = select_profile_roots(
            selection.profile,
            selection.component.as_str(),
            selection.version.as_str(),
            selection.generation.as_deref(),
            &selection.anchors,
        )?;
        governed.admits_write_target(selection.source_root.as_str())?;
        governed.admits_write_target(selection.staging_root.as_str())?;
        let runtime_state_roots = match selection.profile {
            InstallationProfile::PortableDev => {
                if selection.installation_key.is_some() {
                    return Err(InstallationError::ProfileViolation(
                        "portable_dev does not accept a profiled installation key".to_owned(),
                    ));
                }
                RuntimeStateRoots::derive_portable(selection.profile_anchor_root.clone())
            }
            InstallationProfile::SystemService | InstallationProfile::UserMode => {
                let key = selection.installation_key.as_ref().ok_or_else(|| {
                    InstallationError::InvalidField {
                        field: "profile_selection.installation_key".to_owned(),
                        reason: "profiled installations require an explicit key".to_owned(),
                    }
                })?;
                RuntimeStateRoots::derive_profiled(
                    selection.profile,
                    selection.profile_anchor_root.clone(),
                    key.as_str(),
                )
            }
        };
        let runtime_state_roots = runtime_state_roots?;
        let no_service_authority_proof = if governed.profile.requires_admin() {
            None
        } else {
            Some(prove_no_service_profile_authority_dependency(
                &governed,
                &runtime_state_roots,
                selection.component.as_str(),
                selection.version.as_str(),
                selection.generation.as_deref(),
            )?)
        };
        let governance = governed.governance_report();
        let roots = governed.into_installation_roots(runtime_state_roots)?;
        Ok(ProfileSelectionResolution {
            roots,
            governance,
            no_service_authority_proof,
        })
    }

    /// Derives the digest-bound runtime topology for one planner input.
    ///
    /// This is the single derivation shared by the governed and ungoverned
    /// planner entries, so both entries bind the same retained root
    /// identities for one input.
    fn planner_runtime_roots(
        input: &GenerationPackagePlanInput,
    ) -> Result<RuntimeStateRoots, InstallationError> {
        match input.profile {
            InstallationProfile::PortableDev => {
                if input.installation_key.is_some() {
                    return Err(InstallationError::ProfileViolation(
                        "portable_dev does not accept a profiled installation key".to_owned(),
                    ));
                }
                RuntimeStateRoots::derive_portable(input.profile_anchor_root.clone())
            }
            InstallationProfile::SystemService | InstallationProfile::UserMode => {
                let key = input.installation_key.as_ref().ok_or_else(|| {
                    InstallationError::InvalidField {
                        field: "generation.installation_key".to_owned(),
                        reason: "profiled installations require an explicit key".to_owned(),
                    }
                })?;
                RuntimeStateRoots::derive_profiled(
                    input.profile,
                    input.profile_anchor_root.clone(),
                    key.as_str(),
                )
            }
        }
    }

    /// Derive the complete candidate/package/effect graph and create one
    /// immutable `PLANNED` transaction.
    ///
    /// The source is opened and observed independently of every manifest claim.
    /// The exact fifteen-file Phase-A inventory is then used to construct all
    /// canonical destination paths, descriptor/config bindings and artifact
    /// digests before the single transaction constructor is called.
    #[allow(
        clippy::too_many_lines,
        reason = "the production seam keeps candidate, package and effect derivation auditable"
    )]
    fn plan_with_binding(
        input: GenerationPackagePlanInput,
        publication_binding: &SourceBundlePublicationBinding,
        enforce_store_config: bool,
        profile_selection: &ProfileSelectionInput,
        profile_resolution: &ProfileSelectionResolution,
    ) -> Result<InstallationTransaction, InstallationError> {
        if input.profile != profile_selection.profile
            || input.profile_anchor_root != profile_selection.profile_anchor_root
            || input.installation_key != profile_selection.installation_key
            || input.source_root != profile_selection.source_root
            || input.staging_root != profile_selection.staging_root
            || (input.profile == InstallationProfile::PortableDev
                && profile_selection.generation.as_deref() != Some(input.generation.as_str()))
        {
            return Err(InstallationError::ProfileViolation(
                "package plan inputs differ from the resolved I3.1 profile selection".to_owned(),
            ));
        }
        profile_resolution.roots.validate(input.profile)?;
        handle(&input.transaction_id, "generation.transaction_id")?;
        input.installation_epoch.validate()?;
        approved_path(&input.profile_anchor_root, "generation.profile_anchor_root")?;
        approved_path(&input.source_root, "generation.source_root")?;
        approved_path(&input.staging_root, "generation.staging_root")?;
        handle(&input.generation, "generation.generation")?;
        handle(&input.recovery_command, "generation.recovery_command")?;
        if input.minimum_store_available_bytes == 0 {
            return Err(InstallationError::InvalidField {
                field: "generation.minimum_store_available_bytes".to_owned(),
                reason: "must be an explicit non-zero policy value".to_owned(),
            });
        }
        if let Some(source) = input.agent_bridge_source.as_ref() {
            source.validate()?;
        }
        let canonical_generation =
            validate_package_relative_path(Path::new(input.generation.as_str()))
                .map_err(|error| package_plan_error(&error))?;
        if canonical_generation.as_str() != input.generation.as_str() {
            return Err(InstallationError::IdentityConflict);
        }

        let roots = Self::planner_runtime_roots(&input)?;
        if roots != profile_resolution.roots.runtime_state_roots {
            return Err(InstallationError::ProfileViolation(
                "resolved I3.1 binding differs from the planner runtime-root projection".to_owned(),
            ));
        }
        if let Some(expected_staging_root) = roots.expected_staging_root()?
            && !crate::same_windows_root(
                input.staging_root.as_str(),
                expected_staging_root.as_str(),
            )?
        {
            return Err(InstallationError::ProfileViolation(
                "SystemService/UserMode staging_root must equal profile_anchor_root\\Eliot\\packages"
                    .to_owned(),
            ));
        }
        let source =
            TrustedSourceBundle::open(Path::new(input.source_root.as_str())).map_err(|error| {
                InstallationError::Platform(format!("trusted source open failed: {error}"))
            })?;
        let source_identity = source.identity();
        if source_identity.volume_serial_number == 0 || source_identity.file_index == 0 {
            return Err(InstallationError::InvalidField {
                field: "generation.source_root_identity".to_owned(),
                reason: "trusted source identity must be non-zero".to_owned(),
            });
        }
        let observed = source.observe().map_err(|error| {
            InstallationError::Platform(format!("source observe failed: {error}"))
        })?;
        validate_exact_source_inventory(&observed)?;
        let include_module_provenance = module_provenance_present(
            observed.files.iter().map(|file| file.relative_path.clone()),
        )?;
        let include_release_symbols =
            release_symbols_present(observed.files.iter().map(|file| file.relative_path.clone()))?;
        let package_roles =
            package_inventory_roles(include_module_provenance, include_release_symbols);
        let governor_lease = source
            .retain_file("eliotd-governor.json")
            .map_err(|error| {
                InstallationError::Platform(format!(
                    "retain eliotd-governor.json through planning: {error}"
                ))
            })?;
        let governor_bytes = governor_lease
            .read_bounded(16 * 1024 * 1024)
            .map_err(|error| {
                InstallationError::Platform(format!("read eliotd-governor.json lease: {error}"))
            })?;
        let source_store_config = if enforce_store_config {
            let lease = source.retain_file("generation.json").map_err(|error| {
                InstallationError::Platform(format!(
                    "retain generation.json through planning: {error}"
                ))
            })?;
            let bytes = lease.read_bounded(16 * 1024 * 1024).map_err(|error| {
                InstallationError::Platform(format!("read generation.json lease: {error}"))
            })?;
            Some((
                lease,
                validate_source_store_config(
                    &bytes,
                    &Path::new(&profile_resolution.roots.immutable_binaries)
                        .join("generation.json"),
                )?,
            ))
        } else {
            None
        };
        if let Some((_, config)) = source_store_config.as_ref() {
            let has_host_binding = config.runtime_launch.host_symbol_binding.is_some();
            let has_kernel_binding = config.runtime_launch.kernel_symbol_binding.is_some();
            if has_host_binding != has_kernel_binding || has_host_binding != include_release_symbols
            {
                return Err(InstallationError::IdentityConflict);
            }
        } else if include_release_symbols {
            return Err(InstallationError::InvalidField {
                field: "generation.symbol_binding".to_owned(),
                reason:
                    "symbol-bearing package requires the authenticated generation launch descriptor"
                        .to_owned(),
            });
        }

        let files = package_roles
            .iter()
            .map(|(name, executable)| {
                let entry = observed
                    .files
                    .iter()
                    .find(|entry| entry.relative_path == *name)
                    .ok_or(InstallationError::IdentityConflict)?;
                eliot_platform_windows::PackageFileSpec::new(name, *executable, entry.size)
                    .map_err(|error| package_plan_error(&error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let package_manifest = PackageManifest::new(input.generation.as_str(), files)
            .map_err(|error| package_plan_error(&error))?;

        let destination_root = PlatformHandle::new(
            profile_resolution.roots.immutable_binaries.clone(),
        )
        .map_err(|error| InstallationError::InvalidField {
            field: "generation.destination_root".to_owned(),
            reason: error.to_string(),
        })?;
        let generation_root = PathBuf::from(destination_root.as_str());
        let destination = |name: &str| {
            PlatformHandle::new(generation_root.join(name).to_string_lossy().into_owned()).map_err(
                |error| InstallationError::InvalidField {
                    field: "generation.destination_path".to_owned(),
                    reason: error.to_string(),
                },
            )
        };
        let host_path = destination("eliot-host.exe")?;
        let watchdog_path = destination("eliot-watchdog.exe")?;
        let kernel_path = destination("eliot-kernel.exe")?;
        let store_bridge_path = destination("eliot-store-surreal.exe")?;
        let canonical_store_path = destination("surreal.exe")?;
        let eliotd_path = destination("eliotd.exe")?;
        let doctor_path = destination("eliot-doctor.exe")?;
        let testd_path = destination("eliot-testd.exe")?;
        let native_worker_path = destination("eliot-native-worker.exe")?;
        let wasm_host_path = destination("eliot-wasm-host.exe")?;
        let user_broker_path = destination(USER_BROKER_STAGED_ROLE)?;
        let config_path = destination("generation.json")?;
        let eliotd_config_path = destination("eliotd-governor.json")?;
        let eliotd_descriptor_path = destination("eliotd.json")?;
        let store_bootstrap_path = destination("store-bootstrap.json")?;
        let authority_path = destination("authority.json")?;
        for (path, field) in [
            (&host_path, "generation.host_path"),
            (&watchdog_path, "generation.watchdog_path"),
            (&kernel_path, "generation.kernel_path"),
            (&store_bridge_path, "generation.store_bridge_path"),
            (&canonical_store_path, "generation.canonical_store_path"),
            (&eliotd_path, "generation.eliotd_path"),
            (&doctor_path, "generation.doctor_path"),
            (&testd_path, "generation.testd_path"),
            (&native_worker_path, "generation.native_worker_path"),
            (&wasm_host_path, "generation.wasm_host_path"),
            (&user_broker_path, "generation.user_broker_path"),
            (&config_path, "generation.config_path"),
            (&eliotd_config_path, "generation.eliotd_config_path"),
            (&eliotd_descriptor_path, "generation.eliotd_descriptor_path"),
            // These paths are intentionally declared for the later Host
            // Phase-B overlay, but no Phase-A source file is admitted for
            // either destination.
            (&store_bootstrap_path, "generation.store_bootstrap_path"),
            (&authority_path, "generation.authority_path"),
        ] {
            approved_path(path, field)?;
        }

        let expected_file_digests = derive_expected_digests(&observed, &package_manifest)?;
        if expected_file_digests.len() != package_manifest.files.len() {
            return Err(InstallationError::IncompleteObservation(
                "trusted source digest set is incomplete".to_owned(),
            ));
        }
        validate_source_bundle_publication_binding(
            publication_binding,
            source_identity,
            &package_manifest,
            &expected_file_digests,
        )?;
        let digest_for = |name: &str| {
            expected_file_digests
                .iter()
                .find(|digest| digest.relative_path == name)
                .map(|digest| digest.sha256.clone())
                .ok_or(InstallationError::IdentityConflict)
        };
        let kernel_digest = digest_for("eliot-kernel.exe")?;
        let protected_snapshot_digest = protected_snapshot_digest_from_governor_bytes(
            &governor_bytes,
            &input.installation_epoch.installation,
            &input.generation,
            kernel_digest.as_str(),
        )?;
        let host_digest = digest_for("eliot-host.exe")?;
        let watchdog_digest = digest_for("eliot-watchdog.exe")?;
        let store_bridge_digest = digest_for("eliot-store-surreal.exe")?;
        let canonical_store_digest = digest_for("surreal.exe")?;
        let eliotd_digest = digest_for("eliotd.exe")?;
        let doctor_digest = digest_for("eliot-doctor.exe")?;
        let testd_digest = digest_for("eliot-testd.exe")?;
        let native_worker_digest = digest_for("eliot-native-worker.exe")?;
        let wasm_host_digest = digest_for("eliot-wasm-host.exe")?;
        let user_broker_digest = digest_for(USER_BROKER_STAGED_ROLE)?;
        let config_digest = digest_for("generation.json")?;
        let eliotd_config_digest = digest_for("eliotd-governor.json")?;
        let eliotd_descriptor_digest = digest_for("eliotd.json")?;
        let phase_a_content_digest = hex_digest(
            &serde_json::to_vec(&expected_file_digests).map_err(|error| {
                InstallationError::InvalidField {
                    field: "generation.phase_a_content_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?,
        );
        let phase_a_template_facts = PHASE_A_TEMPLATE_ROLES
            .iter()
            .map(|(role, _)| {
                expected_file_digests
                    .iter()
                    .find(|item| item.relative_path == *role)
                    .cloned()
                    .ok_or(InstallationError::IdentityConflict)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let phase_a_template_content_digest =
            Self::phase_a_template_content_digest(&phase_a_template_facts)?;
        // Phase A carries only a valid descriptor template fence. It is not a
        // live authority and is deliberately independent of the installer
        // sequence. Host replaces the fence after opening a real
        // HostInstallationEpoch in Phase B.
        let authority_generation =
            ResourceGeneration::new(1).map_err(|error| InstallationError::InvalidField {
                field: "generation.authority_generation".to_owned(),
                reason: error.to_string(),
            })?;
        let authority_epoch = planner_epoch(1);
        let authority_state_fence = StateFence::new(authority_epoch.clone(), authority_generation);
        if let Some(source) = input.agent_bridge_source.as_ref() {
            let expected_kernel_snapshot = serde_json::json!({
                "service": "eliot-kernel",
                "protocol": "eliot.kernel.v1",
                "generation": authority_generation.value(),
                "authority_epoch": {
                    "lineage_id": PACKAGE_PLANNER_LINEAGE_A,
                    "sequence": 1
                },
                "artifact_digest": kernel_digest.as_str(),
                "protected_snapshot_digest": protected_snapshot_digest.as_str(),
            });
            let expected_kernel_snapshot_digest = hex_digest(
                &serde_json::to_vec(&expected_kernel_snapshot).map_err(|error| {
                    InstallationError::InvalidField {
                        field: "generation.agent_bridge.expected_kernel_config_snapshot_sha256"
                            .to_owned(),
                        reason: error.to_string(),
                    }
                })?,
            );
            let declaration = &source.client_declaration;
            if declaration.expected_kernel_sid != LOCAL_SERVICE_SID
                || declaration.expected_kernel_session_id != 0
                || declaration.expected_kernel_principal_binding
                    != format!("sid={LOCAL_SERVICE_SID};session=0")
                || !declaration
                    .expected_kernel_authority_epoch
                    .is_same_authority(&authority_epoch)
                || declaration.expected_kernel_generation != authority_generation
                || declaration.expected_kernel_artifact_sha256 != kernel_digest.as_str()
                || declaration.expected_kernel_config_snapshot_sha256
                    != expected_kernel_snapshot_digest
            {
                return Err(InstallationError::IdentityConflict);
            }
        }
        let nonce_seed = format!(
            "eliotd:phase-a-template:{}:{}:{}:{}",
            input.transaction_id,
            input.installation_epoch.installation,
            input.generation,
            phase_a_template_content_digest,
        );
        let eliotd_launch_nonce =
            PlatformHandle::new(format!("eliotd:{}", hex_digest(nonce_seed.as_bytes()))).map_err(
                |error| InstallationError::InvalidField {
                    field: "generation.eliotd_launch_nonce".to_owned(),
                    reason: error.to_string(),
                },
            )?;
        let credential_token = hex_digest(
            format!(
                "eliot-store-credential:phase-a-template:{}:{}:{}",
                input.installation_epoch.installation,
                input.generation,
                phase_a_template_content_digest
            )
            .as_bytes(),
        );
        // This is a typed pending marker, never a physical digest. Host must
        // replace it after exact Phase-B publication/readback.
        let phase_b_marker = PlatformHandle::new(PHASE_B_PENDING_MARKER).map_err(|error| {
            InstallationError::InvalidField {
                field: "generation.phase_b_digest".to_owned(),
                reason: error.to_string(),
            }
        })?;
        let store_credential_target =
            PlatformHandle::new(format!("eliot/store/v1/{}", &credential_token[..32])).map_err(
                |error| InstallationError::InvalidField {
                    field: "generation.store_credential_target".to_owned(),
                    reason: error.to_string(),
                },
            )?;
        let handle_vec = |values: Vec<String>| {
            values
                .into_iter()
                .map(|value| {
                    PlatformHandle::new(value).map_err(|error| InstallationError::InvalidField {
                        field: "generation.runtime_arguments".to_owned(),
                        reason: error.to_string(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        };
        let kernel_arguments = handle_vec(vec![
            "--work-root".to_owned(),
            roots.kernel_work_root.as_str().to_owned(),
            "--store-bootstrap".to_owned(),
            store_bootstrap_path.as_str().to_owned(),
            "--store-bootstrap-sha256".to_owned(),
            phase_b_marker.as_str().to_owned(),
            "--authority-descriptor".to_owned(),
            authority_path.as_str().to_owned(),
            "--authority-descriptor-sha256".to_owned(),
            phase_b_marker.as_str().to_owned(),
            "--kernel-artifact-sha256".to_owned(),
            kernel_digest.as_str().to_owned(),
            "--doctor-artifact-sha256".to_owned(),
            doctor_digest.as_str().to_owned(),
            "--testd-artifact-sha256".to_owned(),
            testd_digest.as_str().to_owned(),
            "--native-worker-artifact-sha256".to_owned(),
            native_worker_digest.as_str().to_owned(),
            "--user-broker-executable".to_owned(),
            user_broker_path.as_str().to_owned(),
            "--user-broker-artifact-sha256".to_owned(),
            user_broker_digest.as_str().to_owned(),
            "--eliotd-descriptor".to_owned(),
            eliotd_descriptor_path.as_str().to_owned(),
            "--eliotd-descriptor-sha256".to_owned(),
            eliotd_descriptor_digest.as_str().to_owned(),
        ])?;
        let supervision_lease_scope_id = PlatformHandle::new(format!(
            "eliot-supervision-scope:v1:{}:{}",
            input.installation_epoch.installation, input.generation
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "generation.supervision_lease_scope_id".to_owned(),
            reason: error.to_string(),
        })?;
        let store_bridge_arguments = handle_vec(match input.profile {
            InstallationProfile::PortableDev => vec![
                "--portable-dev-root".to_owned(),
                input.profile_anchor_root.as_str().to_owned(),
                "--config".to_owned(),
                config_path.as_str().to_owned(),
            ],
            InstallationProfile::SystemService | InstallationProfile::UserMode => {
                vec!["--config".to_owned(), config_path.as_str().to_owned()]
            }
        })?;
        let canonical_store_arguments = handle_vec(vec![
            "start".to_owned(),
            "--no-banner".to_owned(),
            "--bind".to_owned(),
            "127.0.0.1:8000".to_owned(),
            "--temporary-directory".to_owned(),
            roots.store_temp_root.as_str().to_owned(),
            "--log-file-enabled".to_owned(),
            "--log-file-path".to_owned(),
            roots.store_work_root.as_str().to_owned(),
            "--log-file-name".to_owned(),
            "surrealdb.log".to_owned(),
            format!(
                "surrealkv://{}",
                roots.store_data_root.as_str().replace('\\', "/")
            ),
        ])?;
        let launch = RuntimeLaunchDescriptor {
            profile: input.profile,
            profile_component: PlatformHandle::new(profile_selection.component.clone()).map_err(
                |error| InstallationError::InvalidField {
                    field: "generation.profile_component".to_owned(),
                    reason: error.to_string(),
                },
            )?,
            profile_version: PlatformHandle::new(profile_selection.version.clone()).map_err(
                |error| InstallationError::InvalidField {
                    field: "generation.profile_version".to_owned(),
                    reason: error.to_string(),
                },
            )?,
            profile_installation_key: profile_selection.installation_key.clone(),
            profile_governed_roots: profile_resolution.roots.clone(),
            portable_root: (input.profile == InstallationProfile::PortableDev)
                .then(|| input.profile_anchor_root.clone()),
            installation_epoch: input.installation_epoch.clone(),
            generation: input.generation.clone(),
            authority_generation,
            authority_state_fence,
            authority_descriptor_path: authority_path,
            authority_descriptor_digest: phase_b_marker.clone(),
            supervision_authority: crate::SupervisionAuthorityBinding::Pending {
                supervision_lease_scope_id: supervision_lease_scope_id.clone(),
            },
            runtime_state_roots: roots.clone(),
            kernel_work_root: roots.kernel_work_root.clone(),
            kernel_artifact_digest: kernel_digest.clone(),
            kernel_symbol_binding: source_store_config
                .as_ref()
                .and_then(|(_, config)| config.runtime_launch.kernel_symbol_binding.clone()),
            eliotd_executable_path: eliotd_path,
            eliotd_artifact_digest: eliotd_digest,
            eliotd_config_path,
            eliotd_config_digest,
            protected_snapshot_digest,
            eliotd_descriptor_path,
            eliotd_descriptor_digest,
            eliotd_launch_nonce,
            store_config_path: config_path.clone(),
            store_credential_target: store_credential_target.clone(),
            store_bridge_executable_path: store_bridge_path.clone(),
            store_bridge_artifact_digest: store_bridge_digest.clone(),
            store_bootstrap_descriptor_path: store_bootstrap_path,
            store_bootstrap_descriptor_digest: phase_b_marker,
            canonical_store_executable_path: canonical_store_path.clone(),
            canonical_store_artifact_digest: canonical_store_digest.clone(),
            kernel_arguments,
            store_bridge_arguments,
            canonical_store_arguments,
            host_executable_path: host_path.clone(),
            host_artifact_digest: host_digest.clone(),
            host_symbol_binding: source_store_config
                .as_ref()
                .and_then(|(_, config)| config.runtime_launch.host_symbol_binding.clone()),
            watchdog_executable_path: watchdog_path.clone(),
            watchdog_artifact_digest: watchdog_digest.clone(),
            doctor_artifact_digest: doctor_digest.clone(),
            testd_artifact_digest: testd_digest.clone(),
            native_worker_artifact_digest: native_worker_digest.clone(),
            wasm_host_artifact_digest: wasm_host_digest.clone(),
            user_broker_artifact_digest: user_broker_digest.clone(),
            doctor_executable_path: doctor_path.clone(),
            testd_executable_path: testd_path.clone(),
            native_worker_executable_path: native_worker_path.clone(),
            wasm_host_executable_path: wasm_host_path.clone(),
            user_broker_executable_path: user_broker_path.clone(),
            descriptor_digest: PlatformHandle::new("0".repeat(64)).map_err(|error| {
                InstallationError::InvalidField {
                    field: "generation.descriptor_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?,
        }
        .with_computed_digest()?;
        let signature_ref =
            artifact_set_evidence_digest(&package_manifest, &expected_file_digests)?;
        let candidate = CandidateManifest {
            generation: input.generation.clone(),
            components: package_roles
                .iter()
                .map(|(name, _)| {
                    PlatformHandle::new(format!("component:{name}")).map_err(|error| {
                        InstallationError::InvalidField {
                            field: "generation.components".to_owned(),
                            reason: error.to_string(),
                        }
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
            kernel_artifact_digest: kernel_digest,
            store_bridge_artifact_digest: store_bridge_digest,
            canonical_store_artifact_digest: canonical_store_digest,
            host_artifact_digest: host_digest,
            doctor_artifact_digest: doctor_digest,
            testd_artifact_digest: testd_digest,
            native_worker_artifact_digest: native_worker_digest,
            wasm_host_artifact_digest: wasm_host_digest,
            user_broker_artifact_digest: user_broker_digest,
            kernel_executable_path: kernel_path,
            store_bridge_executable_path: store_bridge_path,
            canonical_store_executable_path: canonical_store_path,
            host_executable_path: host_path,
            doctor_executable_path: doctor_path,
            testd_executable_path: testd_path,
            native_worker_executable_path: native_worker_path,
            wasm_host_executable_path: wasm_host_path,
            user_broker_executable_path: user_broker_path,
            config_path,
            dependency_closure_refs: vec![
                PlatformHandle::new(format!("evidence:phase-a-content:{phase_a_content_digest}"))
                    .map_err(|error| InstallationError::InvalidField {
                    field: "generation.dependency_closure_refs".to_owned(),
                    reason: error.to_string(),
                })?,
            ],
            license_refs: vec![
                PlatformHandle::new("evidence:license:eliot-runtime").map_err(|error| {
                    InstallationError::InvalidField {
                        field: "generation.license_refs".to_owned(),
                        reason: error.to_string(),
                    }
                })?,
            ],
            config_digest,
            store_credential_target: store_credential_target.clone(),
            supervision_key_slot: supervision_key_slot_for_scope_id(
                supervision_lease_scope_id.as_str(),
            )?,
            signature_ref,
            runtime_state_roots_digest: roots.roots_digest.clone(),
            runtime_launch: launch,
        };
        candidate.validate()?;
        if let Some((_, config)) = source_store_config.as_ref()
            && config.runtime_launch != candidate.runtime_launch
        {
            return Err(InstallationError::IdentityConflict);
        }
        // Validate the deterministic Phase-B static constraint at the sole
        // candidate producer. Host recomputes the same value from its exact
        // pending manifest before accepting the live overlay.
        let phase_b_static_template = phase_b_static_template_for_candidate(&candidate)?;
        validate_exact_candidate_package_binding(&candidate, &package_manifest)?;
        for digest in &expected_file_digests {
            if digest.relative_path == NOTIFY_STAGED_ROLE {
                // Per-user adapter digest is bound by the fifteen-file
                // evidence digest and the manifest size match above; it has
                // no launch-descriptor digest slot by design.
                continue;
            }
            if MODULE_BUILD_PROVENANCE_ROLES
                .iter()
                .any(|(name, _)| *name == digest.relative_path)
            {
                // The full artifact evidence digest binds these exact files.
                // Host later parses the per-module source proof and joins it
                // to the admitted contract and active launch fence.
                continue;
            }
            if RELEASE_SYMBOL_ROLES
                .iter()
                .any(|(name, _)| *name == digest.relative_path)
            {
                let binding = if digest.relative_path == RELEASE_SYMBOL_ROLES[0].0 {
                    candidate.runtime_launch.host_symbol_binding.as_ref()
                } else {
                    candidate.runtime_launch.kernel_symbol_binding.as_ref()
                }
                .ok_or(InstallationError::IdentityConflict)?;
                if digest.sha256 != binding.symbol_artifact_sha256 {
                    return Err(InstallationError::IdentityConflict);
                }
                continue;
            }
            if digest.relative_path == USER_BROKER_STAGED_ROLE {
                if digest.sha256 != candidate.user_broker_artifact_digest {
                    return Err(InstallationError::IdentityConflict);
                }
                continue;
            }
            let (_, _, _, expected) = strict_role_bindings(&candidate)
                .into_iter()
                .find(|(name, _, _, _)| *name == digest.relative_path)
                .ok_or(InstallationError::IdentityConflict)?;
            if digest.sha256 != *expected {
                return Err(InstallationError::IdentityConflict);
            }
        }
        let candidate_manifest_digest = candidate_digest_fn(&candidate)?;
        let package_manifest_digest = PlatformHandle::new(package_manifest.canonical_digest())
            .map_err(|error| InstallationError::InvalidField {
                field: "generation.package_manifest_digest".to_owned(),
                reason: error.to_string(),
            })?;
        let package_effect_id = PlatformHandle::new(format!("effect:package:{}", input.generation))
            .map_err(|error| InstallationError::InvalidField {
                field: "generation.package_effect_id".to_owned(),
                reason: error.to_string(),
            })?;
        let mut effects = Vec::new();
        for (field, root) in roots.installer_root_hierarchy()? {
            let create_id =
                PlatformHandle::new(format!("effect:create:{field}")).map_err(|error| {
                    InstallationError::InvalidField {
                        field: "generation.effect_id".to_owned(),
                        reason: error.to_string(),
                    }
                })?;
            effects.push(InstallerEffectPlan::CreateRoot {
                effect_id: create_id,
                root: root.clone(),
            });
            let acl_id = PlatformHandle::new(format!("effect:acl:{field}")).map_err(|error| {
                InstallationError::InvalidField {
                    field: "generation.effect_id".to_owned(),
                    reason: error.to_string(),
                }
            })?;
            let principals = if input.profile == InstallationProfile::SystemService {
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
            };
            effects.push(InstallerEffectPlan::ApplyAcl {
                effect_id: acl_id,
                root,
                principals,
            });
        }
        effects.push(InstallerEffectPlan::StagePackage {
            effect_id: package_effect_id,
            source_bundle: input.source_root.clone(),
            source_bundle_identity: source_identity,
            generation: input.generation.clone(),
            manifest: package_manifest,
            staging_root: input.staging_root.clone(),
            destination_root: Some(destination_root.clone()),
            expected_file_digests,
            candidate_manifest_digest: candidate_manifest_digest.clone(),
            package_manifest_digest,
        });
        if input.profile == InstallationProfile::UserMode {
            let effect_id = PlatformHandle::new(format!(
                "effect:user-mode-supervision-authority:{}",
                input.generation
            ))
            .map_err(|error| InstallationError::InvalidField {
                field: "generation.user_mode_authority_effect_id".to_owned(),
                reason: error.to_string(),
            })?;
            let owner_sid = WindowsInstallerSecretProvider::new()
                .principal_sid()
                .map_err(|error| InstallationError::InvalidField {
                    field: "generation.user_mode_authority_owner_sid".to_owned(),
                    reason: error.to_string(),
                })?;
            let request = UserModeSupervisionAuthorityCredentialRequest {
                transaction_id: input.transaction_id.as_str().to_owned(),
                effect_id: effect_id.as_str().to_owned(),
                installation_id: input.installation_epoch.installation.as_str().to_owned(),
                candidate_generation: input.generation.as_str().to_owned(),
                authority_generation,
                supervision_lease_scope_id: supervision_lease_scope_id.as_str().to_owned(),
                signer_id: "eliot-kernel".to_owned(),
                key_id: format!("eliot-supervision-key:v1:{}", input.generation),
                owner_sid: owner_sid.as_str().to_owned(),
            };
            let target = match WindowsUserModeSupervisionAuthorityCredentialProvider::new()
                .inspect_target(&request)
                .map_err(|error| InstallationError::InvalidField {
                    field: "generation.user_mode_authority_target".to_owned(),
                    reason: error.to_string(),
                })? {
                UserModeSupervisionAuthorityCredentialTargetObservation::Absent {
                    owner_sid: observed_sid,
                    target,
                } if observed_sid == owner_sid => target,
                UserModeSupervisionAuthorityCredentialTargetObservation::Absent { .. }
                | UserModeSupervisionAuthorityCredentialTargetObservation::Present { .. } => {
                    return Err(InstallationError::IdentityConflict);
                }
            };
            effects.push(InstallerEffectPlan::ProvisionUserModeSupervisionAuthority {
                effect_id: effect_id.clone(),
                provision: Box::new(UserModeSupervisionAuthorityProvisionPlan {
                    transaction_id: input.transaction_id.clone(),
                    effect_id,
                    installation_id: input.installation_epoch.installation.clone(),
                    candidate_generation: input.generation.clone(),
                    authority_generation,
                    supervision_lease_scope_id: supervision_lease_scope_id.clone(),
                    signer_id: PlatformHandle::new(request.signer_id).map_err(|error| {
                        InstallationError::InvalidField {
                            field: "generation.user_mode_authority_signer_id".to_owned(),
                            reason: error.to_string(),
                        }
                    })?,
                    key_id: PlatformHandle::new(request.key_id).map_err(|error| {
                        InstallationError::InvalidField {
                            field: "generation.user_mode_authority_key_id".to_owned(),
                            reason: error.to_string(),
                        }
                    })?,
                    target,
                    owner_sid,
                    profile_roots: profile_resolution.roots.clone(),
                }),
            });
        }
        if input.profile == InstallationProfile::SystemService {
            for (role, name, executable_path) in [
                (
                    InstallerServiceRole::Host,
                    "EliotHost",
                    candidate.host_executable_path.clone(),
                ),
                (
                    InstallerServiceRole::Watchdog,
                    "EliotWatchdog",
                    candidate.runtime_launch.watchdog_executable_path.clone(),
                ),
            ] {
                effects.push(InstallerEffectPlan::RegisterService {
                    effect_id: PlatformHandle::new(format!("effect:service:{name}")).map_err(
                        |error| InstallationError::InvalidField {
                            field: "generation.effect_id".to_owned(),
                            reason: error.to_string(),
                        },
                    )?,
                    role,
                    service_name: PlatformHandle::new(name).map_err(|error| {
                        InstallationError::InvalidField {
                            field: "generation.service_name".to_owned(),
                            reason: error.to_string(),
                        }
                    })?,
                    executable_path,
                    account: InstallerServiceAccount::LocalService,
                    automatic_start: true,
                });
            }
            // Registration and liveness are separate durable effects. The
            // dependency contour starts Watchdog first, then Host, so Host
            // supervision is present before the primary daemon is started.
            for (role, name, executable_path) in [
                (
                    InstallerServiceRole::Watchdog,
                    "EliotWatchdog",
                    candidate.runtime_launch.watchdog_executable_path.clone(),
                ),
                (
                    InstallerServiceRole::Host,
                    "EliotHost",
                    candidate.host_executable_path.clone(),
                ),
            ] {
                effects.push(InstallerEffectPlan::StartService {
                    effect_id: PlatformHandle::new(format!("effect:start:{name}")).map_err(
                        |error| InstallationError::InvalidField {
                            field: "generation.effect_id".to_owned(),
                            reason: error.to_string(),
                        },
                    )?,
                    role,
                    service_name: PlatformHandle::new(name).map_err(|error| {
                        InstallationError::InvalidField {
                            field: "generation.service_name".to_owned(),
                            reason: error.to_string(),
                        }
                    })?,
                    executable_path,
                    account: InstallerServiceAccount::LocalService,
                    automatic_start: true,
                });
            }
            // The LocalService store credential is provisioned only after the
            // Host start effect has converged to an exact Running readback.
            effects.push(InstallerEffectPlan::ProvisionStoreCredential {
                effect_id: PlatformHandle::new("effect:store-credential").map_err(|error| {
                    InstallationError::InvalidField {
                        field: "generation.effect_id".to_owned(),
                        reason: error.to_string(),
                    }
                })?,
                provision: StoreCredentialProvisionPlan {
                    host_state_root: roots.host_state_root.clone(),
                    expected_host_executable: candidate.host_executable_path.clone(),
                    target: candidate.store_credential_target.clone(),
                    // The provider child's own bootstrap/admin reference, derived
                    // by the single installation owner in its own reserved
                    // namespace. Provisioning it here is what makes the pair
                    // INDEPENDENTLY rotatable (#1810 step 3): before this, the
                    // Store bridge required a second reference that nothing in
                    // installation ever provisioned, so it could not be rotated,
                    // revoked, or proved absent. This calls the owner's single
                    // derivation rule rather than repeating it.
                    provider_bootstrap_target: Some(
                        provider_bootstrap_credential_target_for_store_target(
                            &candidate.store_credential_target,
                        )
                        .map_err(|error| {
                            InstallationError::InvalidField {
                                field: "generation.provider_bootstrap_target".to_owned(),
                                reason: error.to_string(),
                            }
                        })?,
                    ),
                    provider: StoreCredentialProvider::WindowsCredentialManager,
                    scope: StoreCredentialScope::LocalService,
                    expected_principal_sid: PlatformHandle::new(LOCAL_SERVICE_SID).map_err(
                        |error| InstallationError::InvalidField {
                            field: "generation.expected_principal_sid".to_owned(),
                            reason: error.to_string(),
                        },
                    )?,
                    generation: authority_generation,
                    config_digest: candidate.config_digest.clone(),
                },
            });
            effects.push(InstallerEffectPlan::MaterializePhaseB {
                effect_id: PlatformHandle::new("effect:phase-b-materialization").map_err(
                    |error| InstallationError::InvalidField {
                        field: "generation.effect_id".to_owned(),
                        reason: error.to_string(),
                    },
                )?,
                candidate_manifest_digest: candidate_manifest_digest.clone(),
                static_template: phase_b_static_template.clone(),
                host_state_root_digest: crate::phase_b_host_state_root_digest(&candidate)?,
                watchdog_selector_digest: crate::phase_b_watchdog_selector_digest(&candidate)?,
                supervision_authority: Box::new(SupervisionAuthorityProvisionPlan {
                    installation_id: input.installation_epoch.installation.clone(),
                    candidate_generation: input.generation.clone(),
                    authority_generation,
                    supervision_lease_scope_id: supervision_lease_scope_id.clone(),
                    signer_id: PlatformHandle::new("eliot-kernel").map_err(|error| {
                        InstallationError::InvalidField {
                            field: "generation.supervision_signer_id".to_owned(),
                            reason: error.to_string(),
                        }
                    })?,
                    key_id: PlatformHandle::new(format!(
                        "eliot-supervision-key:v1:{}",
                        input.generation
                    ))
                    .map_err(|error| InstallationError::InvalidField {
                        field: "generation.supervision_key_id".to_owned(),
                        reason: error.to_string(),
                    })?,
                    kernel_root: roots.kernel_work_root.clone(),
                    sealed_key_relative_path: PlatformHandle::new(format!(
                        "supervision-authority-{}.sealed",
                        &hex_digest(
                            format!(
                                "{}\0{}\0{}",
                                input.installation_epoch.installation,
                                input.generation,
                                authority_generation.value()
                            )
                            .as_bytes()
                        )[..32]
                    ))
                    .map_err(|error| InstallationError::InvalidField {
                        field: "generation.supervision_key_relative_path".to_owned(),
                        reason: error.to_string(),
                    })?,
                    host_service_name: PlatformHandle::new(
                        eliot_runtime_contracts::SUPERVISION_AUTHORITY_HOST_SERVICE,
                    )
                    .map_err(|error| InstallationError::InvalidField {
                        field: "generation.supervision_host_service".to_owned(),
                        reason: error.to_string(),
                    })?,
                    service_sid_type:
                        eliot_runtime_contracts::SUPERVISION_AUTHORITY_SERVICE_SID_TYPE,
                }),
                provision: Box::new(StoreCredentialProvisionPlan {
                    host_state_root: roots.host_state_root.clone(),
                    expected_host_executable: candidate.host_executable_path.clone(),
                    target: candidate.store_credential_target.clone(),
                    // Same owner, same single derivation rule as the other
                    // provisioning site; a second copy of the domain string
                    // would let the two contours drift apart.
                    provider_bootstrap_target: Some(
                        provider_bootstrap_credential_target_for_store_target(
                            &candidate.store_credential_target,
                        )
                        .map_err(|error| {
                            InstallationError::InvalidField {
                                field: "generation.provider_bootstrap_target".to_owned(),
                                reason: error.to_string(),
                            }
                        })?,
                    ),
                    provider: StoreCredentialProvider::WindowsCredentialManager,
                    scope: StoreCredentialScope::LocalService,
                    expected_principal_sid: PlatformHandle::new(LOCAL_SERVICE_SID).map_err(
                        |error| InstallationError::InvalidField {
                            field: "generation.expected_principal_sid".to_owned(),
                            reason: error.to_string(),
                        },
                    )?,
                    generation: authority_generation,
                    config_digest: candidate.config_digest.clone(),
                }),
                agent_bridge_source: input.agent_bridge_source.clone(),
            });
        }
        let planned_changes = effects
            .iter()
            .map(|effect| {
                let target = match effect {
                    InstallerEffectPlan::CreateRoot { root, .. }
                    | InstallerEffectPlan::ApplyAcl { root, .. } => root.clone(),
                    InstallerEffectPlan::StagePackage {
                        staging_root,
                        destination_root,
                        ..
                    } => destination_root
                        .clone()
                        .unwrap_or_else(|| staging_root.clone()),
                    InstallerEffectPlan::RegisterService { service_name, .. }
                    | InstallerEffectPlan::StartService { service_name, .. } => {
                        service_name.clone()
                    }
                    InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => {
                        provision.target.clone()
                    }
                    InstallerEffectPlan::ProvisionUserModeSupervisionAuthority {
                        provision,
                        ..
                    } => provision.target.clone(),
                    InstallerEffectPlan::MaterializePhaseB {
                        static_template, ..
                    } => static_template.authority_id.clone(),
                };
                let change_id = effect.effect_id().clone();
                Ok(PlannedChange {
                    change_id: change_id.clone(),
                    target,
                    precondition_refs: vec![
                        PlatformHandle::new(format!("evidence:precondition:{change_id}")).map_err(
                            |error| InstallationError::InvalidField {
                                field: "generation.precondition".to_owned(),
                                reason: error.to_string(),
                            },
                        )?,
                    ],
                    postcondition_refs: vec![
                        PlatformHandle::new(format!("evidence:postcondition:{change_id}"))
                            .map_err(|error| InstallationError::InvalidField {
                                field: "generation.postcondition".to_owned(),
                                reason: error.to_string(),
                            })?,
                    ],
                })
            })
            .collect::<Result<Vec<_>, InstallationError>>()?;
        let request = build_generation_request(&input, source_identity)?;
        let precondition_evidence = vec![
            PlatformHandle::new(format!(
                "evidence:trusted-source:{}:{}",
                source_identity.volume_serial_number, source_identity.file_index
            ))
            .map_err(|error| InstallationError::InvalidField {
                field: "generation.precondition_evidence".to_owned(),
                reason: error.to_string(),
            })?,
            PlatformHandle::new(format!(
                "evidence:profile-anchor:{}",
                input.profile_anchor_root
            ))
            .map_err(|error| InstallationError::InvalidField {
                field: "generation.precondition_evidence".to_owned(),
                reason: error.to_string(),
            })?,
        ];
        let mut transaction = InstallationTransaction::new(
            input.transaction_id,
            input.installation_epoch,
            input.profile,
            request,
            None,
            candidate,
            input.staging_root,
            planned_changes,
            effects,
            input.minimum_store_available_bytes,
            precondition_evidence,
            input.recovery_command,
        )?;
        transaction.profile_governed_roots = Some(profile_resolution.roots.clone());
        transaction.validate()?;
        if let Some((lease, config)) = source_store_config.as_ref() {
            if config.runtime_launch != transaction.candidate_manifest.runtime_launch {
                return Err(InstallationError::IdentityConflict);
            }
            let reread = lease.read_bounded(16 * 1024 * 1024).map_err(|error| {
                InstallationError::Platform(format!("final re-read generation.json lease: {error}"))
            })?;
            let digest = hex_digest(&reread);
            let expected = transaction
                .installer_effects
                .iter()
                .find_map(|effect| match effect {
                    InstallerEffectPlan::StagePackage {
                        expected_file_digests,
                        ..
                    } => expected_file_digests
                        .iter()
                        .find(|item| item.relative_path == "generation.json"),
                    _ => None,
                })
                .ok_or(InstallationError::IdentityConflict)?;
            if digest != expected.sha256.as_str()
                || digest != transaction.candidate_manifest.config_digest.as_str()
            {
                return Err(InstallationError::IdentityConflict);
            }
        }
        Ok(transaction)
    }
}

fn validate_exact_source_inventory(
    observed: &eliot_platform_windows::PackageSourceObservation,
) -> Result<(), InstallationError> {
    let include_module_provenance =
        module_provenance_present(observed.files.iter().map(|file| file.relative_path.clone()))?;
    let include_symbols =
        release_symbols_present(observed.files.iter().map(|file| file.relative_path.clone()))?;
    let roles = package_inventory_roles(include_module_provenance, include_symbols);
    if observed.files.len() != roles.len() {
        return Err(InstallationError::IncompleteObservation(
            "trusted source must contain the complete approved runtime inventory".to_owned(),
        ));
    }
    let expected = roles.iter().map(|(name, _)| *name).collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for file in &observed.files {
        validate_package_relative_path(Path::new(&file.relative_path))
            .map_err(|error| package_plan_error(&error))?;
        if !actual.insert(file.relative_path.as_str()) {
            return Err(InstallationError::Duplicate {
                kind: "trusted source package file".to_owned(),
                identity: file.relative_path.clone(),
            });
        }
        if !expected.contains(file.relative_path.as_str()) {
            return Err(InstallationError::IdentityConflict);
        }
        if file.size == 0 {
            return Err(InstallationError::InvalidField {
                field: "generation.source_file.size".to_owned(),
                reason: "runtime inventory files must be non-empty".to_owned(),
            });
        }
        if file.sha256.len() != 64 || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(InstallationError::IdentityConflict);
        }
    }
    if actual != expected {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}

#[cfg(test)]
fn test_source_publication_binding(
    input: &GenerationPackagePlanInput,
) -> Result<SourceBundlePublicationBinding, InstallationError> {
    let source =
        TrustedSourceBundle::open(Path::new(input.source_root.as_str())).map_err(|error| {
            InstallationError::Platform(format!("test source open failed: {error}"))
        })?;
    let source_identity = source.identity();
    let observed = source.observe().map_err(|error| {
        InstallationError::Platform(format!("test source observe failed: {error}"))
    })?;
    validate_exact_source_inventory(&observed)?;
    let files = REQUIRED_PACKAGE_ROLES
        .iter()
        .map(|(name, executable)| {
            let entry = observed
                .files
                .iter()
                .find(|entry| entry.relative_path == *name)
                .ok_or(InstallationError::IdentityConflict)?;
            eliot_platform_windows::PackageFileSpec::new(name, *executable, entry.size)
                .map_err(|error| package_plan_error(&error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = PackageManifest::new(input.generation.as_str(), files)
        .map_err(|error| package_plan_error(&error))?;
    let expected = derive_expected_digests(&observed, &manifest)?;
    let evidence_digest = artifact_set_evidence_digest(&manifest, &expected)?;
    let ordered_files = REQUIRED_PACKAGE_ROLES
        .iter()
        .map(|(role, _)| {
            expected
                .iter()
                .find(|file| file.relative_path == *role)
                .cloned()
                .ok_or(InstallationError::IdentityConflict)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SourceBundlePublicationBinding {
        source_identity,
        files: ordered_files,
        evidence_digest,
    })
}

fn validate_source_bundle_publication_binding(
    binding: &SourceBundlePublicationBinding,
    observed_identity: FileIdentity,
    manifest: &PackageManifest,
    expected: &[PackageArtifactDigest],
) -> Result<(), InstallationError> {
    if binding.source_identity != observed_identity {
        return Err(InstallationError::InvalidField {
            field: "generation.source_publication.source_identity".to_owned(),
            reason: "published root identity differs from the planner observation".to_owned(),
        });
    }
    let roles = package_roles_for_manifest(manifest)?;
    if binding.files.len() != roles.len() || expected.len() != roles.len() {
        return Err(InstallationError::IncompleteObservation(
            "source publication binding must contain the complete approved role inventory"
                .to_owned(),
        ));
    }
    for (index, &(role, executable)) in roles.iter().enumerate() {
        let bound = binding
            .files
            .get(index)
            .ok_or(InstallationError::IncompleteObservation(
                "source publication binding is missing an ordered role".to_owned(),
            ))?;
        let observed = expected
            .iter()
            .find(|item| item.relative_path == role)
            .ok_or(InstallationError::IncompleteObservation(
                "planner source observation is missing an ordered role".to_owned(),
            ))?;
        let spec = manifest
            .files
            .iter()
            .find(|item| item.relative_path == role)
            .ok_or(InstallationError::IncompleteObservation(
                "planner package manifest is missing an ordered role".to_owned(),
            ))?;
        if bound != observed
            || bound.relative_path != role
            || observed.relative_path != role
            || spec.relative_path != role
            || spec.executable != executable
        {
            return Err(InstallationError::InvalidField {
                field: format!("generation.source_publication.files[{index}]"),
                reason: format!(
                    "published role facts differ for {role}: bound={bound:?}, observed={observed:?}"
                ),
            });
        }
    }
    let observed_evidence = artifact_set_evidence_digest(manifest, expected)?;
    if binding.evidence_digest != observed_evidence {
        return Err(InstallationError::InvalidField {
            field: "generation.source_publication.evidence_digest".to_owned(),
            reason: "published evidence digest differs from the planner observation".to_owned(),
        });
    }
    Ok(())
}

fn build_generation_request(
    input: &GenerationPackagePlanInput,
    source_identity: eliot_platform_windows::FileIdentity,
) -> Result<ManagedEnvironmentChangeRequest, InstallationError> {
    let make = |value: String, field: &str| {
        PlatformHandle::new(value).map_err(|error| InstallationError::InvalidField {
            field: field.to_owned(),
            reason: error.to_string(),
        })
    };
    Ok(ManagedEnvironmentChangeRequest {
        request_id: make(
            format!("request:generation:{}", input.transaction_id),
            "generation.request_id",
        )?,
        requester_and_reason: make(
            "owner:trusted-generation-planner".to_owned(),
            "generation.requester_and_reason",
        )?,
        action: ManagedEnvironmentAction::Install,
        target_family: make(
            "family:eliot-runtime-live".to_owned(),
            "generation.target_family",
        )?,
        exact_candidate: input.generation.clone(),
        expected_delta: make(
            format!("install:complete-runtime-inventory:{}", input.generation),
            "generation.expected_delta",
        )?,
        source_assurance_refs: vec![make(
            format!(
                "source:{}:{}:{}",
                input.source_root, source_identity.volume_serial_number, source_identity.file_index
            ),
            "generation.source_assurance_refs",
        )?],
        affected_refs: vec![
            make(
                format!("affected:staging-root:{}", input.staging_root),
                "generation.affected_refs",
            )?,
            make(
                format!("affected:profile-anchor:{}", input.profile_anchor_root),
                "generation.affected_refs",
            )?,
        ],
        impact_class: make(
            "bounded:immutable-generation".to_owned(),
            "generation.impact_class",
        )?,
        required_owner: make(
            "owner:installation-coordinator".to_owned(),
            "generation.required_owner",
        )?,
        rollback_plan: make(
            "rollback:exact-owned-package".to_owned(),
            "generation.rollback_plan",
        )?,
        verifier: make(
            "verifier:complete-path-digest-set".to_owned(),
            "generation.verifier",
        )?,
        budget: make(
            format!(
                "budget:store-available-bytes:{}",
                input.minimum_store_available_bytes
            ),
            "generation.budget",
        )?,
        stop_condition: make(
            "stop:on-missing-extra-duplicate-alias-or-tamper".to_owned(),
            "generation.stop_condition",
        )?,
    })
}

/// Sealed production planner that derives package facts from a pinned source bundle.
#[cfg(test)]
pub(crate) struct SealedPackagePlanner;

#[cfg(test)]
impl SealedPackagePlanner {
    /// Plan a v8 transaction by opening the source bundle and deriving digests.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        clippy::needless_pass_by_value
    )]
    pub fn plan(
        transaction_id: PlatformHandle,
        installation_epoch: InstallationEpoch,
        profile: InstallationProfile,
        request: ManagedEnvironmentChangeRequest,
        candidate_manifest: CandidateManifest,
        staging_root: PlatformHandle,
        source_bundle: PlatformHandle,
        package_manifest: PackageManifest,
        planned_changes_without_package: Vec<PlannedChange>,
        installer_effects_without_package: Vec<InstallerEffectPlan>,
        minimum_store_available_bytes: u64,
        precondition_evidence: Vec<PlatformHandle>,
        recovery_command: PlatformHandle,
    ) -> Result<InstallationTransaction, InstallationError> {
        candidate_manifest.validate()?;
        if candidate_manifest.runtime_launch.profile != profile {
            return Err(InstallationError::ProfileViolation(
                "transaction profile must equal candidate runtime launch profile".to_owned(),
            ));
        }
        if candidate_manifest.runtime_launch.installation_epoch != installation_epoch {
            return Err(InstallationError::InvalidField {
                field: "candidate_manifest.runtime_launch.installation_epoch".to_owned(),
                reason: "must exactly equal transaction installation epoch".to_owned(),
            });
        }
        approved_path(&source_bundle, "installer_effect.source_bundle")?;
        approved_path(&staging_root, "installer_effect.staging_root")?;
        handle(&transaction_id, "transaction_id")?;
        installation_epoch.validate()?;
        request.validate()?;

        let manifest =
            PackageManifest::new(&package_manifest.generation, package_manifest.files.clone())
                .map_err(|e| package_plan_error(&e))?;
        if manifest.generation != candidate_manifest.generation.as_str() {
            return Err(InstallationError::IdentityConflict);
        }
        for eff in &installer_effects_without_package {
            if matches!(eff, InstallerEffectPlan::StagePackage { .. }) {
                return Err(InstallationError::Duplicate {
                    kind: "package staging effect".to_owned(),
                    identity: eff.effect_id().as_str().to_owned(),
                });
            }
        }
        let source = TrustedSourceBundle::open(Path::new(source_bundle.as_str())).map_err(|e| {
            InstallationError::Platform(format!("source bundle retain failed: {e}"))
        })?;
        let source_identity = source.identity();
        if source_identity.volume_serial_number == 0 || source_identity.file_index == 0 {
            return Err(InstallationError::InvalidField {
                field: "installer_effect.source_bundle_identity".to_owned(),
                reason: "must contain non-zero retained file identity".to_owned(),
            });
        }
        let observed = source
            .observe()
            .map_err(|e| InstallationError::Platform(format!("source observe failed: {e}")))?;
        let observed_tree = enumerate_source_tree(&observed)?;
        let manifest_paths: BTreeSet<String> = manifest
            .files
            .iter()
            .map(|f| f.relative_path.to_ascii_lowercase())
            .collect();
        if observed_tree != manifest_paths {
            return Err(InstallationError::IdentityConflict);
        }
        validate_candidate_package_binding(&candidate_manifest, &manifest)?;
        let expected_file_digests = derive_expected_digests(&observed, &manifest)?;
        for digest in &expected_file_digests {
            if let Some((_, _, expected_sha)) = expected_role_map(&candidate_manifest)
                .into_iter()
                .find(|(p, _, _)| eliot_platform_windows::ordinal_eq_str(p, &digest.relative_path))
            {
                let is_placeholder = expected_sha.len() == 64
                    && expected_sha
                        .chars()
                        .next()
                        .is_some_and(|first| expected_sha.chars().all(|c| c == first));
                if !is_placeholder && digest.sha256.as_str() != expected_sha {
                    return Err(InstallationError::IdentityConflict);
                }
            }
        }
        let candidate_manifest_digest = candidate_digest_fn(&candidate_manifest)?;
        let package_manifest_digest =
            PlatformHandle::new(manifest.canonical_digest()).map_err(|e| {
                InstallationError::InvalidField {
                    field: "installer_effect.package_manifest_digest".to_owned(),
                    reason: e.to_string(),
                }
            })?;
        let effect_id = PlatformHandle::new(format!("effect:package:{}", manifest.generation))
            .map_err(|e| InstallationError::InvalidField {
                field: "installer_effect.effect_id".to_owned(),
                reason: e.to_string(),
            })?;
        let stage_package = InstallerEffectPlan::StagePackage {
            effect_id: effect_id.clone(),
            source_bundle: source_bundle.clone(),
            source_bundle_identity: source_identity,
            generation: candidate_manifest.generation.clone(),
            manifest: manifest.clone(),
            staging_root: staging_root.clone(),
            destination_root: None,
            expected_file_digests,
            candidate_manifest_digest,
            package_manifest_digest,
        };
        let package_change = PlannedChange {
            change_id: effect_id.clone(),
            target: staging_root.clone(),
            precondition_refs: vec![
                PlatformHandle::new("evidence:package-precondition").map_err(|e| {
                    InstallationError::InvalidField {
                        field: "precondition".to_owned(),
                        reason: e.to_string(),
                    }
                })?,
            ],
            postcondition_refs: vec![
                PlatformHandle::new("evidence:package-postcondition").map_err(|e| {
                    InstallationError::InvalidField {
                        field: "postcondition".to_owned(),
                        reason: e.to_string(),
                    }
                })?,
            ],
        };
        let insert_idx = installer_effects_without_package
            .iter()
            .position(|e| {
                matches!(
                    e,
                    InstallerEffectPlan::RegisterService { .. }
                        | InstallerEffectPlan::ProvisionStoreCredential { .. }
                )
            })
            .unwrap_or(installer_effects_without_package.len());
        let mut installer_effects = Vec::with_capacity(installer_effects_without_package.len() + 1);
        installer_effects.extend_from_slice(&installer_effects_without_package[..insert_idx]);
        installer_effects.push(stage_package);
        installer_effects.extend_from_slice(&installer_effects_without_package[insert_idx..]);

        let mut planned_changes = Vec::with_capacity(planned_changes_without_package.len() + 1);
        planned_changes.extend_from_slice(&planned_changes_without_package[..insert_idx]);
        planned_changes.push(package_change);
        planned_changes.extend_from_slice(&planned_changes_without_package[insert_idx..]);

        drop(source);
        let profile_governed_roots = candidate_manifest
            .runtime_launch
            .profile_governed_roots
            .clone();
        let mut transaction = InstallationTransaction::new(
            transaction_id,
            installation_epoch,
            profile,
            request,
            None,
            candidate_manifest,
            staging_root,
            planned_changes,
            installer_effects,
            minimum_store_available_bytes,
            precondition_evidence,
            recovery_command,
        )?;
        transaction.profile_governed_roots = Some(profile_governed_roots);
        transaction.validate()?;
        Ok(transaction)
    }

    /// Reopen the source bundle and revalidate the exact retained facts.
    pub fn reopen_and_validate(
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError> {
        let pkg = transaction
            .installer_effects
            .iter()
            .find(|e| matches!(e, InstallerEffectPlan::StagePackage { .. }))
            .ok_or(InstallationError::IncompleteObservation(
                "transaction has no package effect".to_owned(),
            ))?;
        let InstallerEffectPlan::StagePackage {
            source_bundle,
            source_bundle_identity,
            manifest,
            expected_file_digests,
            candidate_manifest_digest,
            package_manifest_digest,
            ..
        } = pkg
        else {
            unreachable!()
        };
        let expected_candidate = candidate_digest_fn(&transaction.candidate_manifest)?;
        if expected_candidate != *candidate_manifest_digest {
            return Err(InstallationError::IdentityConflict);
        }
        if package_manifest_digest.as_str() != manifest.canonical_digest() {
            return Err(InstallationError::IdentityConflict);
        }
        if manifest.generation != transaction.candidate_manifest.generation.as_str() {
            return Err(InstallationError::IdentityConflict);
        }
        let observed_paths: BTreeSet<String> = manifest
            .files
            .iter()
            .map(|f| f.relative_path.to_ascii_lowercase())
            .collect();
        let digest_paths: BTreeSet<String> = expected_file_digests
            .iter()
            .map(|d| d.relative_path.to_ascii_lowercase())
            .collect();
        if observed_paths != digest_paths {
            return Err(InstallationError::IdentityConflict);
        }
        let source = TrustedSourceBundle::open(Path::new(source_bundle.as_str())).map_err(|e| {
            InstallationError::Platform(format!("reopen source bundle failed: {e}"))
        })?;
        if source.identity() != *source_bundle_identity {
            return Err(InstallationError::IdentityConflict);
        }
        let observed = source.observe().map_err(|e| {
            InstallationError::Platform(format!("reopen source bundle failed: {e}"))
        })?;
        let tree = enumerate_source_tree(&observed)?;
        if tree != observed_paths {
            return Err(InstallationError::IdentityConflict);
        }
        let derived = derive_expected_digests(&observed, manifest)?;
        if derived != *expected_file_digests {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::cast_possible_truncation,
        clippy::expect_used,
        clippy::map_identity,
        clippy::needless_pass_by_value,
        clippy::redundant_closure,
        clippy::semicolon_if_nothing_returned,
        clippy::too_many_lines,
        clippy::unwrap_used,
        reason = "package-planner fixtures use deliberate panic-on-invalid-test-data assertions"
    )]

    use super::*;
    use crate::{
        InstallationTransactionStore, provider_bootstrap_credential_target_for_store_target,
    };
    use eliot_platform::PlatformHandle;
    use eliot_platform_windows::PackageManifest;
    use tempfile::TempDir;

    fn h(s: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(s.into()).unwrap()
    }
    fn test_handle(s: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(s.into()).unwrap()
    }
    fn test_path(root: &str, name: &str) -> PlatformHandle {
        let base = Path::new(root);
        test_handle(base.join(name).to_string_lossy().into_owned())
    }
    fn minimal_pe() -> Vec<u8> {
        let pe_offset = 0x80_usize;
        let optional_size = 0xf0_usize;
        let section_end = pe_offset + 4 + 20 + optional_size + 40;
        let mut bytes = vec![0_u8; section_end];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_offset + 4;
        bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&2_u16.to_le_bytes());
        bytes[coff + 20..coff + 22].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes
    }
    fn file_content(name: &str, exe: bool) -> Vec<u8> {
        if exe {
            let mut pe = minimal_pe();
            pe.extend_from_slice(name.as_bytes());
            pe
        } else if name == "eliotd-governor.json" {
            br#"{"protected_snapshot_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_vec()
        } else {
            format!("content:{name}").into_bytes()
        }
    }
    fn sha_of(bytes: &[u8]) -> String {
        hex_digest(bytes)
    }
    fn exact_size(root: &std::path::Path, name: &str) -> u64 {
        std::fs::metadata(root.join(name)).unwrap().len()
    }
    /// Manifest specs for launch-bound and per-user staged roles.
    /// `expected_role_map` binds the thirteen existing
    /// launch-bound roles plus the User Broker pin; the fifteen-file inventory
    /// also carries the unpinned `eliot-notify.exe` adapter.
    fn manifest_specs_with_staged_notify(
        roles: &[(String, bool, String)],
        source_dir: &std::path::Path,
    ) -> Vec<eliot_platform_windows::PackageFileSpec> {
        let mut specs: Vec<_> = roles
            .iter()
            .map(|(p, exe, _)| {
                eliot_platform_windows::PackageFileSpec::new(
                    p.as_str(),
                    *exe,
                    exact_size(source_dir, p),
                )
                .unwrap()
            })
            .collect();
        specs.push(
            eliot_platform_windows::PackageFileSpec::new(
                NOTIFY_STAGED_ROLE,
                NOTIFY_STAGED_EXECUTABLE,
                exact_size(source_dir, NOTIFY_STAGED_ROLE),
            )
            .unwrap(),
        );
        specs
    }
    fn make_epoch() -> InstallationEpoch {
        InstallationEpoch {
            installation: h("installation:test"),
            lineage_id: h("lineage:test"),
            sequence: 1,
        }
    }
    fn make_request() -> ManagedEnvironmentChangeRequest {
        ManagedEnvironmentChangeRequest {
            request_id: h("request:install"),
            requester_and_reason: h("requester:test"),
            action: crate::ManagedEnvironmentAction::Install,
            target_family: h("family:eliot"),
            exact_candidate: h("candidate"),
            expected_delta: h("delta:installed"),
            source_assurance_refs: vec![h("evidence:source")],
            affected_refs: vec![],
            impact_class: h("impact:test"),
            required_owner: h("owner:installation"),
            rollback_plan: h("rollback:test"),
            verifier: h("verifier:test"),
            budget: h("budget:test"),
            stop_condition: h("stop:on-failure"),
        }
    }
    fn make_candidate(
        portable_root: PlatformHandle,
        roots: crate::RuntimeStateRoots,
    ) -> CandidateManifest {
        let epoch = make_epoch();
        let kernel_artifact_digest = h("6".repeat(64));
        let generation = h("candidate");
        let profile_governed_roots = crate::InstallationRoots {
            binding_version: crate::INSTALLATION_ROOT_BINDING_VERSION,
            immutable_binaries: Path::new(portable_root.as_str())
                .join("target")
                .join("eliot-dev")
                .join(generation.as_str())
                .to_string_lossy()
                .into_owned(),
            durable_data: Path::new(portable_root.as_str())
                .join(".eliot-dev")
                .join("state")
                .to_string_lossy()
                .into_owned(),
            user_config: Path::new(portable_root.as_str())
                .join(".eliot-dev")
                .join("config")
                .to_string_lossy()
                .into_owned(),
            user_cache: Path::new(portable_root.as_str())
                .join(".eliot-dev")
                .join("cache")
                .to_string_lossy()
                .into_owned(),
            runtime_state_roots: roots.clone(),
        };
        let mut desc = crate::RuntimeLaunchDescriptor {
            profile: crate::InstallationProfile::PortableDev,
            profile_component: h("eliot-tests"),
            profile_version: h("0.0.0-test"),
            profile_installation_key: None,
            profile_governed_roots,
            portable_root: Some(portable_root.clone()),
            installation_epoch: epoch.clone(),
            generation: generation.clone(),
            authority_generation: eliot_contracts::ResourceGeneration::genesis(),
            authority_state_fence: eliot_contracts::StateFence::new(
                planner_epoch(1),
                eliot_contracts::ResourceGeneration::genesis(),
            ),
            supervision_authority: crate::SupervisionAuthorityBinding::Pending {
                supervision_lease_scope_id: h("test-supervision-scope"),
            },
            authority_descriptor_path: test_path(portable_root.as_str(), "authority.json"),
            authority_descriptor_digest: h(crate::PHASE_B_PENDING_MARKER),
            runtime_state_roots: roots.clone(),
            kernel_work_root: roots.kernel_work_root.clone(),
            kernel_artifact_digest: kernel_artifact_digest.clone(),
            kernel_symbol_binding: None,
            eliotd_executable_path: test_path(portable_root.as_str(), "eliotd.exe"),
            eliotd_artifact_digest: h("8".repeat(64)),
            eliotd_config_path: test_path(portable_root.as_str(), "eliotd-governor.json"),
            eliotd_config_digest: h("4".repeat(64)),
            protected_snapshot_digest: h("a".repeat(64)),
            eliotd_descriptor_path: test_path(portable_root.as_str(), "eliotd.json"),
            eliotd_descriptor_digest: h("9".repeat(64)),
            eliotd_launch_nonce: h(format!("eliotd:{}", "a".repeat(32))),
            store_config_path: test_path(portable_root.as_str(), "generation.json"),
            store_credential_target: h("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            store_bridge_executable_path: test_path(
                portable_root.as_str(),
                "eliot-store-surreal.exe",
            ),
            store_bridge_artifact_digest: h("1".repeat(64)),
            store_bootstrap_descriptor_path: test_path(
                portable_root.as_str(),
                "store-bootstrap.json",
            ),
            store_bootstrap_descriptor_digest: h(crate::PHASE_B_PENDING_MARKER),
            canonical_store_executable_path: test_path(portable_root.as_str(), "surreal.exe"),
            canonical_store_artifact_digest: h("5".repeat(64)),
            kernel_arguments: vec![],
            store_bridge_arguments: vec![],
            canonical_store_arguments: vec![
                h("start"),
                h("--no-banner"),
                h("--bind"),
                h("127.0.0.1:8000"),
                h("--temporary-directory"),
                roots.store_temp_root.clone(),
                h("--log-file-enabled"),
                h("--log-file-path"),
                roots.store_work_root.clone(),
                h("--log-file-name"),
                h("surrealdb.log"),
                h(format!(
                    "surrealkv://{}",
                    roots.store_data_root.as_str().replace('\\', "/")
                )),
            ],
            host_executable_path: test_path(portable_root.as_str(), "eliot-host.exe"),
            host_artifact_digest: h("8".repeat(64)),
            host_symbol_binding: None,
            watchdog_executable_path: test_path(portable_root.as_str(), "eliot-watchdog.exe"),
            watchdog_artifact_digest: h("4".repeat(64)),
            doctor_artifact_digest: h("b".repeat(64)),
            testd_artifact_digest: h("c".repeat(64)),
            native_worker_artifact_digest: h("d".repeat(64)),
            wasm_host_artifact_digest: h("f".repeat(64)),
            user_broker_artifact_digest: h("e".repeat(64)),
            doctor_executable_path: test_path(portable_root.as_str(), "eliot-doctor.exe"),
            testd_executable_path: test_path(portable_root.as_str(), "eliot-testd.exe"),
            native_worker_executable_path: test_path(
                portable_root.as_str(),
                "eliot-native-worker.exe",
            ),
            wasm_host_executable_path: test_path(portable_root.as_str(), "eliot-wasm-host.exe"),
            user_broker_executable_path: test_path(portable_root.as_str(), USER_BROKER_STAGED_ROLE),
            descriptor_digest: h("0".repeat(64)),
        };
        desc.store_bridge_arguments = desc
            .expected_store_bridge_arguments(&desc.store_config_path.clone())
            .into_iter()
            .map(|s| h(s))
            .collect();
        desc.kernel_arguments = desc
            .expected_kernel_arguments(&desc.store_config_path.clone())
            .into_iter()
            .map(|s| h(s))
            .collect();
        desc.descriptor_digest = h(crate::sha256_hex(&desc.unsigned_bytes().unwrap()));
        CandidateManifest {
            generation,
            components: vec![h("component:test")],
            kernel_artifact_digest,
            store_bridge_artifact_digest: h("1".repeat(64)),
            canonical_store_artifact_digest: h("5".repeat(64)),
            host_artifact_digest: h("8".repeat(64)),
            doctor_artifact_digest: h("b".repeat(64)),
            testd_artifact_digest: h("c".repeat(64)),
            native_worker_artifact_digest: h("d".repeat(64)),
            wasm_host_artifact_digest: h("f".repeat(64)),
            user_broker_artifact_digest: h("e".repeat(64)),
            kernel_executable_path: test_path(portable_root.as_str(), "eliot-kernel.exe"),
            store_bridge_executable_path: desc.store_bridge_executable_path.clone(),
            canonical_store_executable_path: desc.canonical_store_executable_path.clone(),
            host_executable_path: desc.host_executable_path.clone(),
            doctor_executable_path: test_path(portable_root.as_str(), "eliot-doctor.exe"),
            testd_executable_path: test_path(portable_root.as_str(), "eliot-testd.exe"),
            native_worker_executable_path: test_path(
                portable_root.as_str(),
                "eliot-native-worker.exe",
            ),
            wasm_host_executable_path: test_path(portable_root.as_str(), "eliot-wasm-host.exe"),
            user_broker_executable_path: test_path(portable_root.as_str(), USER_BROKER_STAGED_ROLE),
            config_path: desc.store_config_path.clone(),
            dependency_closure_refs: vec![h("evidence:dep")],
            license_refs: vec![h("evidence:license")],
            config_digest: h("2".repeat(64)),
            store_credential_target: h("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            supervision_key_slot: h("3".repeat(64)),
            signature_ref: h("a".repeat(64)),
            runtime_state_roots_digest: roots.roots_digest.clone(),
            runtime_launch: desc,
        }
    }

    fn temp_portable_root() -> (TempDir, PlatformHandle, crate::RuntimeStateRoots) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_string_lossy().into_owned();
        let portable = test_handle(path.clone());
        std::fs::create_dir_all(dir.path().join("host")).unwrap();
        #[cfg(windows)]
        drop(crate::UserOwnedRootLease::open_existing(dir.path()).unwrap());
        let roots = crate::RuntimeStateRoots {
            profile: crate::InstallationProfile::PortableDev,
            profile_anchor_root: portable.clone(),
            installation_root: portable.clone(),
            host_state_root: test_path(&path, "host"),
            kernel_ors_root: test_path(&path, "kernel/state"),
            kernel_work_root: test_path(&path, "kernel/work"),
            store_data_root: test_path(&path, "store/data"),
            store_work_root: test_path(&path, "store/work"),
            store_temp_root: test_path(&path, "store/tmp"),
            watchdog_state_root: test_path(&path, "watchdog"),
            roots_digest: h("0".repeat(64)),
        };
        let mut r = roots;
        r.roots_digest = h(crate::sha256_hex(&r.unsigned_bytes().unwrap()));
        (dir, portable, r)
    }

    fn installer_parts(
        roots: &crate::RuntimeStateRoots,
    ) -> (Vec<PlannedChange>, Vec<InstallerEffectPlan>) {
        let mut changes = Vec::new();
        let mut effects = Vec::new();
        for (field, root) in roots.installer_root_hierarchy().unwrap() {
            let eff = InstallerEffectPlan::CreateRoot {
                effect_id: h(format!("effect:create:{field}")),
                root: root.clone(),
            };
            let ch = PlannedChange {
                change_id: h(format!("effect:create:{field}")),
                target: root.clone(),
                precondition_refs: vec![h("evidence:pre")],
                postcondition_refs: vec![h("evidence:post")],
            };
            effects.push(eff);
            changes.push(ch);
            let eff2 = InstallerEffectPlan::ApplyAcl {
                effect_id: h(format!("effect:acl:{field}")),
                root: root.clone(),
                principals: vec![
                    crate::InstallerAclPrincipal::CurrentUser,
                    crate::InstallerAclPrincipal::LocalSystem,
                ],
            };
            let ch2 = PlannedChange {
                change_id: h(format!("effect:acl:{field}")),
                target: root.clone(),
                precondition_refs: vec![h("evidence:pre2")],
                postcondition_refs: vec![h("evidence:post2")],
            };
            effects.push(eff2);
            changes.push(ch2);
        }
        (changes, effects)
    }

    #[test]
    fn forged_identity_digest_rejected() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(source_dir.path().join("a.txt"), b"hello").unwrap();
        let manifest = PackageManifest::new(
            "candidate",
            vec![eliot_platform_windows::PackageFileSpec::new("a.txt", false, 5).unwrap()],
        )
        .unwrap();
        let candidate = make_candidate(portable.clone(), roots.clone());
        let (changes, effects) = installer_parts(&roots);
        let staging_root = portable.clone();
        let source_bundle = test_handle(source_dir.path().to_string_lossy().into_owned());
        let tx = SealedPackagePlanner::plan(
            h("transaction:1"),
            make_epoch(),
            crate::InstallationProfile::PortableDev,
            make_request(),
            candidate.clone(),
            staging_root.clone(),
            source_bundle.clone(),
            manifest.clone(),
            changes.clone(),
            effects.clone(),
            1,
            vec![h("evidence:plan")],
            h("recovery:cmd"),
        )
        .unwrap();
        let mut forged = tx.clone();
        let pkg_idx = forged
            .installer_effects
            .iter()
            .position(|e| matches!(e, InstallerEffectPlan::StagePackage { .. }))
            .unwrap();
        if let InstallerEffectPlan::StagePackage {
            source_bundle_identity,
            expected_file_digests,
            ..
        } = &mut forged.installer_effects[pkg_idx]
        {
            source_bundle_identity.file_index = 99999;
            if let Some(d) = expected_file_digests.first_mut() {
                d.sha256 = h("0".repeat(64));
            }
        }
        assert!(forged.validate().is_err());
        assert!(SealedPackagePlanner::reopen_and_validate(&forged).is_err());
    }

    #[test]
    fn wrong_candidate_digest_rejected() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(source_dir.path().join("a.txt"), b"hello").unwrap();
        let manifest = PackageManifest::new(
            "candidate",
            vec![eliot_platform_windows::PackageFileSpec::new("a.txt", false, 5).unwrap()],
        )
        .unwrap();
        let candidate = make_candidate(portable.clone(), roots.clone());
        let (changes, effects) = installer_parts(&roots);
        let tx = SealedPackagePlanner::plan(
            h("transaction:1"),
            make_epoch(),
            crate::InstallationProfile::PortableDev,
            make_request(),
            candidate,
            test_handle(portable.as_str().to_owned()),
            test_handle(source_dir.path().to_string_lossy().into_owned()),
            manifest,
            changes,
            effects,
            1,
            vec![h("evidence:plan")],
            h("recovery:cmd"),
        )
        .unwrap();
        let mut forged = tx.clone();
        let pkg_idx = forged
            .installer_effects
            .iter()
            .position(|e| matches!(e, InstallerEffectPlan::StagePackage { .. }))
            .unwrap();
        if let InstallerEffectPlan::StagePackage {
            candidate_manifest_digest,
            ..
        } = &mut forged.installer_effects[pkg_idx]
        {
            *candidate_manifest_digest = h("f".repeat(64));
        }
        assert!(forged.validate().is_err());
    }

    #[test]
    fn wrong_package_digest_rejected() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(source_dir.path().join("a.txt"), b"hello").unwrap();
        let manifest = PackageManifest::new(
            "candidate",
            vec![eliot_platform_windows::PackageFileSpec::new("a.txt", false, 5).unwrap()],
        )
        .unwrap();
        let candidate = make_candidate(portable.clone(), roots.clone());
        let (changes, effects) = installer_parts(&roots);
        let tx = SealedPackagePlanner::plan(
            h("transaction:1"),
            make_epoch(),
            crate::InstallationProfile::PortableDev,
            make_request(),
            candidate,
            test_handle(portable.as_str().to_owned()),
            test_handle(source_dir.path().to_string_lossy().into_owned()),
            manifest,
            changes,
            effects,
            1,
            vec![h("evidence:plan")],
            h("recovery:cmd"),
        )
        .unwrap();
        assert!(SealedPackagePlanner::reopen_and_validate(&tx).is_ok());

        let mut forged = tx.clone();
        let pkg_idx = forged
            .installer_effects
            .iter()
            .position(|e| matches!(e, InstallerEffectPlan::StagePackage { .. }))
            .unwrap();
        if let InstallerEffectPlan::StagePackage {
            package_manifest_digest,
            ..
        } = &mut forged.installer_effects[pkg_idx]
        {
            *package_manifest_digest = h("f".repeat(64));
        }
        assert!(SealedPackagePlanner::reopen_and_validate(&forged).is_err());
    }

    #[test]
    fn duplicate_reordered_files_rejected() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(source_dir.path().join("a.txt"), b"hello").unwrap();
        std::fs::write(source_dir.path().join("b.txt"), b"world").unwrap();
        let spec_a = eliot_platform_windows::PackageFileSpec::new("a.txt", false, 5).unwrap();
        let spec_b = eliot_platform_windows::PackageFileSpec::new("b.txt", false, 5).unwrap();
        let manifest_ok =
            PackageManifest::new("candidate", vec![spec_a.clone(), spec_b.clone()]).unwrap();
        let candidate = make_candidate(portable.clone(), roots.clone());
        let (changes, effects) = installer_parts(&roots);
        let tx = SealedPackagePlanner::plan(
            h("transaction:1"),
            make_epoch(),
            crate::InstallationProfile::PortableDev,
            make_request(),
            candidate.clone(),
            portable.clone(),
            test_handle(source_dir.path().to_string_lossy().into_owned()),
            manifest_ok,
            changes.clone(),
            effects.clone(),
            1,
            vec![h("evidence:plan")],
            h("recovery:cmd"),
        )
        .unwrap();
        assert!(tx.validate().is_ok());
        let dup = PackageManifest {
            generation: "candidate".to_owned(),
            files: vec![spec_a.clone(), spec_a.clone()],
        };
        assert!(
            SealedPackagePlanner::plan(
                h("transaction:2"),
                make_epoch(),
                crate::InstallationProfile::PortableDev,
                make_request(),
                candidate.clone(),
                portable.clone(),
                test_handle(source_dir.path().to_string_lossy().into_owned()),
                dup,
                changes.clone(),
                effects.clone(),
                1,
                vec![h("evidence:plan")],
                h("recovery:cmd")
            )
            .is_err()
        );
        let reordered = PackageManifest {
            generation: "candidate".to_owned(),
            files: vec![spec_b, spec_a],
        };
        let tx2 = SealedPackagePlanner::plan(
            h("transaction:3"),
            make_epoch(),
            crate::InstallationProfile::PortableDev,
            make_request(),
            candidate,
            portable.clone(),
            test_handle(source_dir.path().to_string_lossy().into_owned()),
            reordered,
            changes,
            effects,
            1,
            vec![h("evidence:plan")],
            h("recovery:cmd"),
        )
        .unwrap();
        let pkg = tx2
            .installer_effects
            .iter()
            .find(|e| matches!(e, InstallerEffectPlan::StagePackage { .. }))
            .unwrap();
        if let InstallerEffectPlan::StagePackage { manifest: m, .. } = pkg {
            assert_eq!(m.files[0].relative_path, "a.txt");
            assert_eq!(m.files[1].relative_path, "b.txt");
        }
    }

    #[test]
    fn changed_bytes_after_plan_rejected_on_reopen() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(source_dir.path().join("a.txt"), b"hello").unwrap();
        let manifest = PackageManifest::new(
            "candidate",
            vec![eliot_platform_windows::PackageFileSpec::new("a.txt", false, 5).unwrap()],
        )
        .unwrap();
        let candidate = make_candidate(portable.clone(), roots.clone());
        let (changes, effects) = installer_parts(&roots);
        let tx = SealedPackagePlanner::plan(
            h("transaction:1"),
            make_epoch(),
            crate::InstallationProfile::PortableDev,
            make_request(),
            candidate,
            portable.clone(),
            test_handle(source_dir.path().to_string_lossy().into_owned()),
            manifest,
            changes,
            effects,
            1,
            vec![h("evidence:plan")],
            h("recovery:cmd"),
        )
        .unwrap();
        assert!(SealedPackagePlanner::reopen_and_validate(&tx).is_ok());
        std::fs::write(source_dir.path().join("a.txt"), b"changed").unwrap();
        assert!(SealedPackagePlanner::reopen_and_validate(&tx).is_err());
    }

    #[test]
    fn forged_path_manifest_rejected() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(source_dir.path().join("a.txt"), b"hello").unwrap();
        let manifest = PackageManifest::new(
            "candidate",
            vec![eliot_platform_windows::PackageFileSpec::new("a.txt", false, 5).unwrap()],
        )
        .unwrap();
        let candidate = make_candidate(portable.clone(), roots.clone());
        let (changes, effects) = installer_parts(&roots);
        let tx = SealedPackagePlanner::plan(
            h("transaction:1"),
            make_epoch(),
            crate::InstallationProfile::PortableDev,
            make_request(),
            candidate.clone(),
            portable.clone(),
            test_handle(source_dir.path().to_string_lossy().into_owned()),
            manifest,
            changes.clone(),
            effects.clone(),
            1,
            vec![h("evidence:plan")],
            h("recovery:cmd"),
        )
        .unwrap();
        let mut forged = tx.clone();
        let idx = forged
            .installer_effects
            .iter()
            .position(|e| matches!(e, InstallerEffectPlan::StagePackage { .. }))
            .unwrap();
        if let InstallerEffectPlan::StagePackage { manifest: m, .. } =
            &mut forged.installer_effects[idx]
        {
            m.files[0].relative_path = "../evil.txt".to_owned();
        }
        assert!(forged.validate().is_err());
    }

    #[test]
    fn unsupported_signer_rejected_for_executable() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(source_dir.path().join("bad.exe"), b"not a pe").unwrap();
        let spec = eliot_platform_windows::PackageFileSpec::new("bad.exe", true, 8).unwrap();
        let manifest = PackageManifest::new("candidate", vec![spec]).unwrap();
        let candidate = make_candidate(portable.clone(), roots.clone());
        let (changes, effects) = installer_parts(&roots);
        let res = SealedPackagePlanner::plan(
            h("transaction:1"),
            make_epoch(),
            crate::InstallationProfile::PortableDev,
            make_request(),
            candidate,
            portable.clone(),
            test_handle(source_dir.path().to_string_lossy().into_owned()),
            manifest,
            changes,
            effects,
            1,
            vec![h("evidence:plan")],
            h("recovery:cmd"),
        );
        assert!(res.is_err());
    }
    #[allow(dead_code)]
    fn build_real_candidate(
        portable: PlatformHandle,
        roots: crate::RuntimeStateRoots,
        file_hashes: std::collections::BTreeMap<String, String>,
    ) -> CandidateManifest {
        let mut base = make_candidate(portable.clone(), roots.clone());
        let get = |name: &str| file_hashes.get(name).cloned().unwrap();
        base.kernel_artifact_digest = h(get("eliot-kernel.exe"));
        base.host_artifact_digest = h(get("eliot-host.exe"));
        base.store_bridge_artifact_digest = h(get("eliot-store-surreal.exe"));
        base.canonical_store_artifact_digest = h(get("surreal.exe"));
        base.doctor_artifact_digest = h(get("eliot-doctor.exe"));
        base.testd_artifact_digest = h(get("eliot-testd.exe"));
        base.native_worker_artifact_digest = h(get("eliot-native-worker.exe"));
        base.wasm_host_artifact_digest = h(get("eliot-wasm-host.exe"));
        base.user_broker_artifact_digest = h(get(USER_BROKER_STAGED_ROLE));
        base.config_digest = h(get("generation.json"));
        base.supervision_key_slot = h("c".repeat(64));
        base.runtime_launch.kernel_artifact_digest = h(get("eliot-kernel.exe"));
        base.runtime_launch.host_artifact_digest = h(get("eliot-host.exe"));
        base.runtime_launch.watchdog_artifact_digest = h(get("eliot-watchdog.exe"));
        base.runtime_launch.store_bridge_artifact_digest = h(get("eliot-store-surreal.exe"));
        base.runtime_launch.canonical_store_artifact_digest = h(get("surreal.exe"));
        base.runtime_launch.eliotd_artifact_digest = h(get("eliotd.exe"));
        base.runtime_launch.eliotd_config_digest = h(get("eliotd-governor.json"));
        base.runtime_launch.eliotd_descriptor_digest = h(get("eliotd.json"));
        base.runtime_launch.doctor_artifact_digest = h(get("eliot-doctor.exe"));
        base.runtime_launch.testd_artifact_digest = h(get("eliot-testd.exe"));
        base.runtime_launch.native_worker_artifact_digest = h(get("eliot-native-worker.exe"));
        base.runtime_launch.wasm_host_artifact_digest = h(get("eliot-wasm-host.exe"));
        base.runtime_launch.user_broker_artifact_digest = h(get(USER_BROKER_STAGED_ROLE));
        base.runtime_launch.kernel_arguments = base
            .runtime_launch
            .expected_kernel_arguments(&base.runtime_launch.store_config_path.clone())
            .into_iter()
            .map(|s| h(s))
            .collect();
        base.runtime_launch.store_bridge_arguments = base
            .runtime_launch
            .expected_store_bridge_arguments(&base.runtime_launch.store_config_path.clone())
            .into_iter()
            .map(|s| h(s))
            .collect();
        base.runtime_launch.descriptor_digest = h(crate::sha256_hex(
            &base.runtime_launch.unsigned_bytes().unwrap(),
        ));
        base
    }
    fn populate_source_with_roles(
        dir: &std::path::Path,
    ) -> std::collections::BTreeMap<String, String> {
        let roles = vec![
            ("eliot-kernel.exe", true),
            ("eliot-host.exe", true),
            ("eliot-watchdog.exe", true),
            ("eliot-store-surreal.exe", true),
            ("surreal.exe", true),
            ("eliotd.exe", true),
            ("eliot-doctor.exe", true),
            ("eliot-testd.exe", true),
            ("eliot-native-worker.exe", true),
            ("eliot-wasm-host.exe", true),
            ("eliot-user-broker.exe", true),
            ("eliot-notify.exe", true),
            ("generation.json", false),
            ("eliotd-governor.json", false),
            ("eliotd.json", false),
        ];
        let kernel_bytes = file_content("eliot-kernel.exe", true);
        let protected_snapshot_digest = hex_digest(
            format!(
                "governor-protected:{}:{}:{}",
                "installation:test",
                "candidate",
                sha_of(&kernel_bytes)
            )
            .as_bytes(),
        );
        let mut map = std::collections::BTreeMap::new();
        for (name, exe) in roles {
            let content = if name == "eliotd-governor.json" {
                format!(r#"{{"protected_snapshot_digest":"{protected_snapshot_digest}"}}"#)
                    .into_bytes()
            } else {
                file_content(name, exe)
            };
            std::fs::write(dir.join(name), &content).unwrap();
            map.insert(name.to_owned(), sha_of(&content));
        }
        map
    }

    fn artifact_evidence_for_source(
        manifest: &PackageManifest,
        source_root: &std::path::Path,
    ) -> PlatformHandle {
        let expected = manifest
            .files
            .iter()
            .map(|spec| PackageArtifactDigest {
                relative_path: spec.relative_path.clone(),
                expected_size: spec.expected_size,
                sha256: h(sha_of(
                    &std::fs::read(source_root.join(&spec.relative_path)).unwrap(),
                )),
            })
            .collect::<Vec<_>>();
        artifact_set_evidence_digest(manifest, &expected).unwrap()
    }

    #[test]
    fn phase_a_template_digest_requires_exact_typed_seven_role_facts() {
        let roles = [
            "eliot-host.exe",
            "eliot-watchdog.exe",
            "eliot-kernel.exe",
            "eliot-store-surreal.exe",
            "surreal.exe",
            "eliotd.exe",
            "eliot-doctor.exe",
            "eliot-testd.exe",
            "eliot-native-worker.exe",
            "eliot-wasm-host.exe",
            "eliotd-governor.json",
        ];
        let facts = roles
            .iter()
            .enumerate()
            .map(|(index, role)| PackageArtifactDigest {
                relative_path: (*role).to_owned(),
                expected_size: (index + 1) as u64,
                sha256: h(format!("{index:01x}{index:01x}").repeat(32)),
            })
            .collect::<Vec<_>>();
        let digest = GenerationPackagePlanner::phase_a_template_content_digest(&facts)
            .expect("exact eleven typed template facts must be accepted");
        let mut reordered = facts.clone();
        reordered.swap(0, 6);
        assert_eq!(
            digest,
            GenerationPackagePlanner::phase_a_template_content_digest(&reordered)
                .expect("fact order is canonicalized by role"),
            "template digest must use the fixed role order"
        );

        let mut missing = facts.clone();
        missing.pop();
        assert!(
            GenerationPackagePlanner::phase_a_template_content_digest(&missing).is_err(),
            "missing template role must be rejected"
        );
        let mut extra = facts.clone();
        extra.push(PackageArtifactDigest {
            relative_path: "authority.json".to_owned(),
            expected_size: 1,
            sha256: h("a".repeat(64)),
        });
        assert!(
            GenerationPackagePlanner::phase_a_template_content_digest(&extra).is_err(),
            "Phase-B role must not enter template derivation"
        );
        let mut duplicate = facts;
        duplicate[0].relative_path = duplicate[1].relative_path.clone();
        assert!(
            GenerationPackagePlanner::phase_a_template_content_digest(&duplicate).is_err(),
            "duplicate role must be rejected"
        );
    }

    #[test]
    fn phase_a_template_digest_changes_for_every_immutable_template_fact() {
        let roles = [
            "eliot-host.exe",
            "eliot-watchdog.exe",
            "eliot-kernel.exe",
            "eliot-store-surreal.exe",
            "surreal.exe",
            "eliotd.exe",
            "eliot-doctor.exe",
            "eliot-testd.exe",
            "eliot-native-worker.exe",
            "eliot-wasm-host.exe",
            "eliotd-governor.json",
        ];
        let facts = roles
            .iter()
            .map(|role| PackageArtifactDigest {
                relative_path: (*role).to_owned(),
                expected_size: 10,
                sha256: h("b".repeat(64)),
            })
            .collect::<Vec<_>>();
        let original = GenerationPackagePlanner::phase_a_template_content_digest(&facts).unwrap();
        for index in 0..facts.len() {
            let mut changed = facts.clone();
            changed[index].expected_size += 1;
            assert_ne!(
                original,
                GenerationPackagePlanner::phase_a_template_content_digest(&changed).unwrap(),
                "immutable role {} must affect template derivation",
                roles[index]
            );
        }
    }

    #[test]
    fn dispatch_children_are_bound_like_kernel_artifact() {
        let (_tmp, portable, roots) = temp_portable_root();
        let candidate = make_candidate(portable, roots);
        candidate
            .validate()
            .expect("candidate with dispatch children validates");
        let (doctor, testd, native_worker) = candidate
            .dispatch_child_artifact_digests()
            .expect("dispatch digests are bound");
        assert_eq!(doctor.as_str(), &"b".repeat(64));
        assert_eq!(testd.as_str(), &"c".repeat(64));
        assert_eq!(native_worker.as_str(), &"d".repeat(64));
        let (doctor_path, testd_path, native_worker_path) = candidate
            .dispatch_child_paths()
            .expect("dispatch paths are bound");
        assert!(doctor_path.as_str().ends_with("eliot-doctor.exe"));
        assert!(testd_path.as_str().ends_with("eliot-testd.exe"));
        assert!(
            native_worker_path
                .as_str()
                .ends_with("eliot-native-worker.exe")
        );
        let (wasm_host_path, wasm_host_digest) = candidate
            .runtime_launch
            .wasm_host_artifact_binding()
            .expect("wasm-host binding is bound");
        assert!(wasm_host_path.as_str().ends_with("eliot-wasm-host.exe"));
        assert_eq!(wasm_host_digest.as_str(), &"f".repeat(64));
        let kernel_args = candidate
            .runtime_launch
            .expected_kernel_arguments(&candidate.runtime_launch.store_config_path.clone());
        // 13 pairs = 26 values, including the exact User Broker path and digest.
        assert_eq!(kernel_args.len(), 26, "kernel contour must be 26 values");
        assert!(kernel_args.contains(&"--doctor-artifact-sha256".to_owned()));
        assert!(kernel_args.contains(&"--testd-artifact-sha256".to_owned()));
        assert!(kernel_args.contains(&"--native-worker-artifact-sha256".to_owned()));
        let bindings = strict_role_bindings(&candidate);
        assert_eq!(bindings.len(), 13);
        assert!(
            bindings
                .iter()
                .any(|(name, _, _, _)| *name == "eliot-doctor.exe")
        );
        assert!(
            bindings
                .iter()
                .any(|(name, _, _, _)| *name == "eliot-testd.exe")
        );
        assert!(
            bindings
                .iter()
                .any(|(name, _, _, _)| *name == "eliot-native-worker.exe")
        );
        assert!(
            bindings
                .iter()
                .any(|(name, _, _, _)| *name == "eliot-wasm-host.exe")
        );
    }

    fn production_input(
        source_root: &std::path::Path,
        portable_root: PlatformHandle,
    ) -> GenerationPackagePlanInput {
        GenerationPackagePlanInput {
            transaction_id: h("transaction:generation"),
            installation_epoch: make_epoch(),
            profile: crate::InstallationProfile::PortableDev,
            profile_anchor_root: portable_root,
            installation_key: None,
            generation: h("candidate"),
            source_root: h(source_root.to_string_lossy().into_owned()),
            staging_root: h(source_root.to_string_lossy().into_owned()),
            minimum_store_available_bytes: 1,
            recovery_command: h(
                "eliot installation recover --transaction-id transaction:generation",
            ),
            agent_bridge_source: None,
        }
    }

    #[test]
    fn generation_planner_builds_and_binds_complete_inventory() {
        let (_tmp, portable, _roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        populate_source_with_roles(source_dir.path());
        let transaction = GenerationPackagePlanner::plan_unbound_for_test(production_input(
            source_dir.path(),
            portable,
        ))
        .expect("trusted generation planner should build one transaction");
        transaction
            .validate()
            .expect("generated transaction validates");
        let package = transaction
            .installer_effects
            .iter()
            .find_map(|effect| match effect {
                InstallerEffectPlan::StagePackage { manifest, .. } => Some(manifest),
                _ => None,
            })
            .expect("generated transaction has one package effect");
        assert_eq!(package.files.len(), REQUIRED_PACKAGE_ROLES.len());
        assert_eq!(
            package
                .files
                .iter()
                .map(|file| file.relative_path.as_str())
                .collect::<BTreeSet<_>>(),
            REQUIRED_PACKAGE_ROLES
                .iter()
                .map(|(name, _)| *name)
                .collect::<BTreeSet<_>>()
        );
        assert!(!package.files.iter().any(|file| matches!(
            file.relative_path.as_str(),
            "authority.json" | "store-bootstrap.json"
        )));
        let staged_digest_paths = transaction
            .installer_effects
            .iter()
            .find_map(|effect| match effect {
                InstallerEffectPlan::StagePackage {
                    expected_file_digests,
                    ..
                } => Some(
                    expected_file_digests
                        .iter()
                        .map(|digest| digest.relative_path.as_str())
                        .collect::<BTreeSet<_>>(),
                ),
                _ => None,
            })
            .expect("generated transaction has staged digest paths");
        assert!(!staged_digest_paths.contains("authority.json"));
        assert!(!staged_digest_paths.contains("store-bootstrap.json"));
        assert_eq!(
            transaction
                .candidate_manifest
                .runtime_launch
                .authority_descriptor_digest
                .as_str(),
            PHASE_B_PENDING_MARKER
        );
        assert_eq!(
            transaction
                .candidate_manifest
                .runtime_launch
                .store_bootstrap_descriptor_digest
                .as_str(),
            PHASE_B_PENDING_MARKER
        );
        assert_eq!(
            transaction
                .candidate_manifest
                .runtime_launch
                .kernel_arguments[5]
                .as_str(),
            PHASE_B_PENDING_MARKER
        );
        assert_eq!(
            transaction
                .candidate_manifest
                .runtime_launch
                .kernel_arguments[9]
                .as_str(),
            PHASE_B_PENDING_MARKER
        );
        assert_eq!(
            transaction
                .candidate_manifest
                .runtime_launch
                .phase_b_digest_state()
                .expect("Phase-B state classification"),
            (
                crate::PhaseBDigestState::Pending,
                crate::PhaseBDigestState::Pending
            )
        );
        assert_eq!(
            transaction.candidate_manifest.supervision_key_slot.as_str(),
            supervision_key_slot_for_scope_id(
                transaction
                    .candidate_manifest
                    .runtime_launch
                    .supervision_lease_scope_id()
            )
            .expect("planner emits a lease-bound supervision slot")
            .as_str()
        );
        assert!(
            transaction
                .candidate_manifest
                .runtime_launch
                .require_phase_b_live()
                .is_err()
        );
        assert!(
            transaction
                .candidate_manifest
                .runtime_launch
                .eliotd_launch_nonce
                .as_str()
                .starts_with("eliotd:")
        );
        let wire = serde_json::to_string(&transaction).unwrap();
        assert!(!wire.contains("host_runtime_activation_nonce"));
        assert!(!wire.contains("host_activation_nonce"));
    }

    fn planner_store_config_digest(config: &PlannerStoreLaunchConfig) -> String {
        let operational = PlannerOperationalConfig {
            store_pipe: &config.store_pipe,
            launch_nonce: &config.launch_nonce,
            expected_client_sid: &config.expected_client_sid,
            expected_client_session_id: config.expected_client_session_id,
            approved_artifact_hash: &config.approved_artifact_hash,
            endpoint: &config.endpoint,
            provider_bind_address: &config.provider_bind_address,
            namespace: &config.namespace,
            database: &config.database,
            username: &config.username,
            connect_timeout_ms: config.connect_timeout_ms,
            query_timeout_ms: config.query_timeout_ms,
            store_transaction_limit: config.store_transaction_limit,
            schema_generation: &config.schema_generation,
            blob_root: &config.blob_root,
            instance_id: &config.instance_id,
            credential_ref: &config.credential_ref,
            provider_bootstrap_credential_ref: &config.provider_bootstrap_credential_ref,
            provider_bootstrap_username: &config.provider_bootstrap_username,
            runtime_launch: &config.runtime_launch,
        };
        hex_digest(&serde_json::to_vec(&operational).unwrap())
    }

    fn planner_store_config_json(config: &PlannerStoreLaunchConfig) -> serde_json::Value {
        // Mirrors the canonical issuer encoding: the knob is omitted when
        // unset so fixtures stay byte-identical to real legacy files.
        let mut value = serde_json::json!({
            "store_pipe": &config.store_pipe,
            "launch_nonce": &config.launch_nonce,
            "expected_client_sid": &config.expected_client_sid,
            "expected_client_session_id": config.expected_client_session_id,
            "approved_artifact_hash": &config.approved_artifact_hash,
            "approved_config_hash": &config.approved_config_hash,
            "endpoint": &config.endpoint,
            "provider_bind_address": &config.provider_bind_address,
            "namespace": &config.namespace,
            "database": &config.database,
            "username": &config.username,
            "connect_timeout_ms": config.connect_timeout_ms,
            "query_timeout_ms": config.query_timeout_ms,
            "schema_generation": &config.schema_generation,
            "blob_root": &config.blob_root,
            "instance_id": &config.instance_id,
            "credential_ref": &config.credential_ref,
            "provider_bootstrap_credential_ref": &config.provider_bootstrap_credential_ref,
            "provider_bootstrap_username": &config.provider_bootstrap_username,
            "runtime_launch": &config.runtime_launch,
        });
        if let Some(limit) = config.store_transaction_limit {
            value["store_transaction_limit"] = serde_json::json!(limit);
        }
        value
    }

    #[test]
    fn bound_generation_planner_rejects_rehashed_noncanonical_store_target() {
        let (_tmp, portable, _roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        populate_source_with_roles(source_dir.path());
        let input = production_input(source_dir.path(), portable);

        // Derive the exact launch descriptor first; generation.json is excluded
        // from the non-recursive Phase-A template facts, so replacing its
        // placeholder bytes does not alter the descriptor we bind below.
        let baseline = GenerationPackagePlanner::plan_unbound_for_test(input.clone())
            .expect("baseline planner fixture should produce a launch descriptor");
        let launch = baseline.candidate_manifest.runtime_launch.clone();
        let mut config = PlannerStoreLaunchConfig {
            store_pipe: r"\\.\pipe\eliot\store-test".to_owned(),
            launch_nonce: "store:test".to_owned(),
            expected_client_sid: "S-1-5-19".to_owned(),
            expected_client_session_id: 0,
            approved_artifact_hash: launch.store_bridge_artifact_digest.as_str().to_owned(),
            approved_config_hash: String::new(),
            endpoint: eliot_runtime_contracts::RUNTIME_LIVE_STORE_ENDPOINT.to_owned(),
            provider_bind_address: eliot_runtime_contracts::RUNTIME_LIVE_STORE_BIND.to_owned(),
            namespace: eliot_runtime_contracts::RUNTIME_LIVE_STORE_NAMESPACE.to_owned(),
            database: "eliot".to_owned(),
            username: "store".to_owned(),
            connect_timeout_ms: 10_000,
            query_timeout_ms: 10_000,
            store_transaction_limit: None,
            schema_generation: "1.0.0".to_owned(),
            blob_root: Path::new(launch.runtime_state_roots.store_data_root.as_str())
                .join("blob")
                .to_string_lossy()
                .into_owned(),
            instance_id: "store-candidate".to_owned(),
            credential_ref: launch.store_credential_target.as_str().to_owned(),
            provider_bootstrap_credential_ref:
                provider_bootstrap_credential_target_for_store_target(
                    &launch.store_credential_target,
                )
                .unwrap()
                .as_str()
                .to_owned(),
            provider_bootstrap_username: "provider-bootstrap".to_owned(),
            runtime_launch: launch,
        };
        config.approved_config_hash = planner_store_config_digest(&config);
        let valid_json = planner_store_config_json(&config);
        std::fs::write(
            source_dir.path().join("generation.json"),
            serde_json::to_vec(&valid_json).unwrap(),
        )
        .unwrap();

        // Recompute the exact fifteen-role SHA/size vector and publication
        // evidence after writing the valid generation document.
        let binding = test_source_publication_binding(&input).unwrap();
        GenerationPackagePlanner::plan_with_source_publication_binding(
            input.clone(),
            binding.source_identity,
            binding.files.clone(),
            binding.evidence_digest.clone(),
        )
        .expect("canonical bound fixture should plan");

        let mut altered: PlannerStoreLaunchConfig = serde_json::from_value(valid_json).unwrap();
        altered.namespace = "other".to_owned();
        altered.approved_config_hash = planner_store_config_digest(&altered);
        std::fs::write(
            source_dir.path().join("generation.json"),
            serde_json::to_vec(&planner_store_config_json(&altered)).unwrap(),
        )
        .unwrap();
        let altered_binding = test_source_publication_binding(&input).unwrap();
        assert!(matches!(
            GenerationPackagePlanner::plan_with_source_publication_binding(
                input,
                altered_binding.source_identity,
                altered_binding.files,
                altered_binding.evidence_digest,
            ),
            Err(InstallationError::IdentityConflict)
        ));
    }

    #[test]
    fn store_transaction_limit_binds_identically_in_approved_digest() {
        let (_tmp, portable, _roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        populate_source_with_roles(source_dir.path());
        let input = production_input(source_dir.path(), portable);
        let baseline = GenerationPackagePlanner::plan_unbound_for_test(input)
            .expect("planner fixture should produce a launch descriptor");
        let launch = baseline.candidate_manifest.runtime_launch.clone();
        let expected_path = Path::new(launch.store_config_path.as_str()).to_path_buf();
        let mut config = PlannerStoreLaunchConfig {
            store_pipe: r"\\.\pipe\eliot\store-test".to_owned(),
            launch_nonce: "store:test".to_owned(),
            expected_client_sid: "S-1-5-19".to_owned(),
            expected_client_session_id: 0,
            approved_artifact_hash: launch.store_bridge_artifact_digest.as_str().to_owned(),
            approved_config_hash: String::new(),
            endpoint: eliot_runtime_contracts::RUNTIME_LIVE_STORE_ENDPOINT.to_owned(),
            provider_bind_address: eliot_runtime_contracts::RUNTIME_LIVE_STORE_BIND.to_owned(),
            namespace: eliot_runtime_contracts::RUNTIME_LIVE_STORE_NAMESPACE.to_owned(),
            database: "eliot".to_owned(),
            username: "store".to_owned(),
            connect_timeout_ms: 10_000,
            query_timeout_ms: 10_000,
            store_transaction_limit: None,
            schema_generation: "1.0.0".to_owned(),
            blob_root: Path::new(launch.runtime_state_roots.store_data_root.as_str())
                .join("blob")
                .to_string_lossy()
                .into_owned(),
            instance_id: "store-candidate".to_owned(),
            credential_ref: launch.store_credential_target.as_str().to_owned(),
            provider_bootstrap_credential_ref:
                provider_bootstrap_credential_target_for_store_target(
                    &launch.store_credential_target,
                )
                .unwrap()
                .as_str()
                .to_owned(),
            provider_bootstrap_username: "provider-bootstrap".to_owned(),
            runtime_launch: launch,
        };
        // Legacy: an unset knob is omitted on the wire, parses to default,
        // and validates under its recomputed approval — existing approvals
        // stay byte-stable.
        config.approved_config_hash = planner_store_config_digest(&config);
        let legacy_json = planner_store_config_json(&config);
        assert!(legacy_json.get("store_transaction_limit").is_none());
        let legacy_bytes = serde_json::to_vec(&legacy_json).unwrap();
        let parsed: PlannerStoreLaunchConfig = serde_json::from_slice(&legacy_bytes).unwrap();
        assert_eq!(parsed.store_transaction_limit, None);
        validate_source_store_config(&legacy_bytes, &expected_path)
            .expect("legacy approval still valid");
        // Explicit: the knob changes the approval and rides the file.
        config.store_transaction_limit = Some(2);
        let explicit_digest = planner_store_config_digest(&config);
        assert_ne!(
            explicit_digest, config.approved_config_hash,
            "an explicit limit must affect the approval"
        );
        config.approved_config_hash = explicit_digest;
        let explicit_json = planner_store_config_json(&config);
        assert_eq!(
            explicit_json
                .get("store_transaction_limit")
                .and_then(|value| value.as_u64()),
            Some(2)
        );
        let explicit_bytes = serde_json::to_vec(&explicit_json).unwrap();
        validate_source_store_config(&explicit_bytes, &expected_path)
            .expect("explicit issuer/validator parity");
        // Tampered: an explicit limit with a stale approval fails closed.
        let mut tampered = explicit_json;
        tampered["store_transaction_limit"] = serde_json::json!(9);
        let tampered_bytes = serde_json::to_vec(&tampered).unwrap();
        assert!(matches!(
            validate_source_store_config(&tampered_bytes, &expected_path),
            Err(InstallationError::IdentityConflict)
        ));
        // Malformed: a zero limit is refused even with a matching approval.
        config.store_transaction_limit = Some(0);
        config.approved_config_hash = planner_store_config_digest(&config);
        let zero_json = planner_store_config_json(&config);
        let zero_bytes = serde_json::to_vec(&zero_json).unwrap();
        assert!(matches!(
            validate_source_store_config(&zero_bytes, &expected_path),
            Err(InstallationError::IdentityConflict)
        ));
    }

    #[test]
    fn supervision_slot_is_lease_bound_and_legacy_fingerprint_is_inert() {
        let (_tmp, portable, _roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        populate_source_with_roles(source_dir.path());
        let transaction = GenerationPackagePlanner::plan_unbound_for_test(production_input(
            source_dir.path(),
            portable,
        ))
        .expect("trusted generation planner should build");
        let mut candidate = transaction.candidate_manifest;
        let lease_scope_id = candidate
            .runtime_launch
            .supervision_lease_scope_id()
            .to_owned();
        candidate.supervision_key_slot =
            supervision_key_slot_for_scope_id(&lease_scope_id).expect("canonical slot");
        candidate.validate().expect("canonical slot validates");
        let wire = serde_json::to_value(&candidate).expect("candidate wire");
        assert_eq!(
            wire.get("supervision_key_fingerprint")
                .and_then(serde_json::Value::as_str),
            Some(candidate.supervision_key_slot.as_str())
        );
        assert!(wire.get("supervision_key_slot").is_none());
        let decoded: CandidateManifest =
            serde_json::from_value(wire).expect("legacy wire member remains readable");
        assert_eq!(decoded.supervision_key_slot, candidate.supervision_key_slot);

        candidate.supervision_key_slot =
            supervision_key_slot_for_scope_id("substituted-supervision-scope")
                .expect("substituted slot");
        assert!(candidate.validate().is_err());

        candidate.supervision_key_slot = h("3".repeat(64));
        candidate
            .validate()
            .expect("legacy fingerprint remains an inert compatibility projection");
        assert!(
            candidate
                .runtime_launch
                .provisioned_supervision_authority()
                .is_err()
        );
    }

    #[test]
    fn system_service_planner_emits_ordered_distinct_phase_b_effect_and_rejects_substitution() {
        fn reseal(transaction: &mut InstallationTransaction) {
            transaction.installer_plan_digest = h(crate::sha256_hex(
                &InstallationTransaction::installer_plan_unsigned_bytes(
                    &transaction.transaction_id,
                    &transaction.candidate_manifest,
                    &transaction.staging_root,
                    &transaction
                        .candidate_manifest
                        .runtime_launch
                        .runtime_state_roots,
                    transaction.minimum_store_available_bytes,
                    &transaction.planned_changes,
                    &transaction.installer_effects,
                )
                .unwrap(),
            ));
        }

        let (_tmp, portable, _roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        populate_source_with_roles(source_dir.path());
        let mut input = production_input(source_dir.path(), portable);
        input.transaction_id = h("transaction:system-service");
        input.profile = crate::InstallationProfile::SystemService;
        input.profile_anchor_root = h(crate::protected_program_data_root()
            .expect("SystemService test needs the OS profile anchor")
            .to_string_lossy()
            .into_owned());
        input.installation_key = Some(h("a".repeat(64)));
        input.staging_root = h(format!(
            r"{}\Eliot\packages",
            input.profile_anchor_root.as_str()
        ));
        let transaction = GenerationPackagePlanner::plan_unbound_for_test(input)
            .expect("trusted SystemService generation planner should build");
        assert!(candidate_has_nonplaceholder_package_digests(
            &transaction.candidate_manifest
        ));
        let roots = &transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots;
        let hierarchy = roots
            .installer_root_hierarchy()
            .expect("SystemService root hierarchy must derive");
        let package_index = transaction
            .installer_effects
            .iter()
            .position(|effect| matches!(effect, InstallerEffectPlan::StagePackage { .. }))
            .expect("package staging effect");
        assert_eq!(
            hierarchy.len() * 2,
            package_index,
            "every exact root CreateRoot+ApplyAcl pair must precede StagePackage"
        );
        let expected_acl = vec![
            InstallerAclPrincipal::Administrators,
            InstallerAclPrincipal::LocalService,
            InstallerAclPrincipal::LocalSystem,
        ];
        for (index, (field, root)) in hierarchy.iter().enumerate() {
            let create = &transaction.installer_effects[index * 2];
            let acl = &transaction.installer_effects[index * 2 + 1];
            assert!(
                matches!(
                    create,
                    InstallerEffectPlan::CreateRoot { root: actual, .. }
                        if actual == root
                ),
                "CreateRoot must bind exact {field}"
            );
            assert!(
                matches!(
                    acl,
                    InstallerEffectPlan::ApplyAcl {
                        root: actual,
                        principals,
                        ..
                    } if actual == root && principals == &expected_acl
                ),
                "ApplyAcl must bind exact protected {field}"
            );
        }
        let canary_root = roots
            .canary_evidence_root()
            .expect("canary evidence root must derive");
        assert!(canary_root.as_str().ends_with(r"\canary-evidence"));
        let canary_index = hierarchy
            .iter()
            .position(|(field, root)| *field == "canary_evidence_root" && *root == canary_root)
            .expect("exact canary evidence root in hierarchy");
        assert!(canary_index < hierarchy.len());

        let mut missing_canary = transaction.clone();
        missing_canary
            .installer_effects
            .retain(|effect| match effect {
                InstallerEffectPlan::CreateRoot { root, .. }
                | InstallerEffectPlan::ApplyAcl { root, .. } => root != &canary_root,
                _ => true,
            });
        missing_canary
            .planned_changes
            .retain(|change| change.target != canary_root);
        assert!(
            crate::validate_installer_effects(
                missing_canary.profile,
                &missing_canary
                    .candidate_manifest
                    .runtime_launch
                    .runtime_state_roots,
                &missing_canary
                    .candidate_manifest
                    .runtime_launch
                    .store_credential_target,
                &missing_canary.planned_changes,
                &missing_canary.installer_effects,
            )
            .is_err(),
            "omitting canary-evidence must fail closed"
        );

        let substituted_canary = h(format!(r"{}-sibling", canary_root.as_str()));
        let mut substituted = transaction.clone();
        for effect in &mut substituted.installer_effects {
            match effect {
                InstallerEffectPlan::CreateRoot { root, .. }
                | InstallerEffectPlan::ApplyAcl { root, .. }
                    if root == &canary_root =>
                {
                    *root = substituted_canary.clone()
                }
                _ => {}
            }
        }
        for change in &mut substituted.planned_changes {
            if change.target == canary_root {
                change.target = substituted_canary.clone();
            }
        }
        assert!(
            crate::validate_installer_effects(
                substituted.profile,
                &substituted
                    .candidate_manifest
                    .runtime_launch
                    .runtime_state_roots,
                &substituted
                    .candidate_manifest
                    .runtime_launch
                    .store_credential_target,
                &substituted.planned_changes,
                &substituted.installer_effects,
            )
            .is_err(),
            "substituting canary-evidence must fail closed"
        );
        let host_start = transaction
            .installer_effects
            .iter()
            .position(|effect| {
                matches!(
                    effect,
                    InstallerEffectPlan::StartService {
                        role: InstallerServiceRole::Host,
                        ..
                    }
                )
            })
            .expect("Host bootstrap effect");
        let credential = transaction
            .installer_effects
            .iter()
            .position(|effect| {
                matches!(effect, InstallerEffectPlan::ProvisionStoreCredential { .. })
            })
            .expect("credential effect");
        let phase_b = transaction
            .installer_effects
            .iter()
            .position(|effect| matches!(effect, InstallerEffectPlan::MaterializePhaseB { .. }))
            .expect("Phase-B effect");
        assert!(host_start < credential && credential < phase_b);
        let (
            InstallerEffectPlan::MaterializePhaseB {
                effect_id: phase_effect_id,
                ..
            },
            InstallerEffectPlan::ProvisionStoreCredential {
                effect_id: credential_effect_id,
                ..
            },
        ) = (
            &transaction.installer_effects[phase_b],
            &transaction.installer_effects[credential],
        )
        else {
            unreachable!()
        };
        assert_ne!(phase_effect_id, credential_effect_id);

        let mutations: [fn(&mut InstallerEffectPlan); 7] = [
            |effect: &mut InstallerEffectPlan| {
                if let InstallerEffectPlan::MaterializePhaseB {
                    candidate_manifest_digest,
                    ..
                } = effect
                {
                    *candidate_manifest_digest = h("a".repeat(64));
                }
            },
            |effect: &mut InstallerEffectPlan| {
                if let InstallerEffectPlan::MaterializePhaseB {
                    static_template, ..
                } = effect
                {
                    static_template.authority_id = h("authority:substituted");
                }
            },
            |effect: &mut InstallerEffectPlan| {
                if let InstallerEffectPlan::MaterializePhaseB {
                    static_template, ..
                } = effect
                {
                    static_template.record_id = h("record:substituted");
                }
            },
            |effect: &mut InstallerEffectPlan| {
                if let InstallerEffectPlan::MaterializePhaseB {
                    static_template, ..
                } = effect
                {
                    static_template.revision_policy_binding = h("revision:substituted");
                }
            },
            |effect: &mut InstallerEffectPlan| {
                if let InstallerEffectPlan::MaterializePhaseB {
                    static_template, ..
                } = effect
                {
                    static_template.contour_refs = vec![h("contour:substituted")];
                }
            },
            |effect: &mut InstallerEffectPlan| {
                if let InstallerEffectPlan::MaterializePhaseB {
                    host_state_root_digest,
                    ..
                } = effect
                {
                    *host_state_root_digest = h("b".repeat(64));
                }
            },
            |effect: &mut InstallerEffectPlan| {
                if let InstallerEffectPlan::MaterializePhaseB {
                    watchdog_selector_digest,
                    ..
                } = effect
                {
                    *watchdog_selector_digest = h("c".repeat(64));
                }
            },
        ];
        for mutate in mutations {
            let mut substituted = transaction.clone();
            let effect = substituted
                .installer_effects
                .iter_mut()
                .find(|effect| matches!(effect, InstallerEffectPlan::MaterializePhaseB { .. }))
                .unwrap();
            mutate(effect);
            reseal(&mut substituted);
            assert!(
                substituted.validate().is_err(),
                "Phase-B substitution must fail closed"
            );
        }
    }

    #[test]
    fn artifact_evidence_is_stable_across_source_file_identity() {
        let (_tmp, portable, _roots) = temp_portable_root();
        let source_a = tempfile::TempDir::new().unwrap();
        let source_b = tempfile::TempDir::new().unwrap();
        populate_source_with_roles(source_a.path());
        populate_source_with_roles(source_b.path());

        let first = GenerationPackagePlanner::plan_unbound_for_test(production_input(
            source_a.path(),
            portable.clone(),
        ))
        .expect("first trusted source should plan");
        let second = GenerationPackagePlanner::plan_unbound_for_test(production_input(
            source_b.path(),
            portable,
        ))
        .expect("second trusted source should plan");
        let first_identity = first
            .installer_effects
            .iter()
            .find_map(|effect| match effect {
                InstallerEffectPlan::StagePackage {
                    source_bundle_identity,
                    ..
                } => Some(source_bundle_identity),
                _ => None,
            })
            .expect("first plan has a package source identity");
        let second_identity = second
            .installer_effects
            .iter()
            .find_map(|effect| match effect {
                InstallerEffectPlan::StagePackage {
                    source_bundle_identity,
                    ..
                } => Some(source_bundle_identity),
                _ => None,
            })
            .expect("second plan has a package source identity");
        assert_ne!(first_identity, second_identity);
        assert_eq!(
            first.candidate_manifest.signature_ref, second.candidate_manifest.signature_ref,
            "artifact evidence must exclude volatile source file identity"
        );
    }

    #[test]
    fn launch_template_derivation_excludes_nonce_bearing_json_but_evidence_binds_it() {
        let (_tmp, portable, _roots) = temp_portable_root();
        let source_a = tempfile::TempDir::new().unwrap();
        let source_b = tempfile::TempDir::new().unwrap();
        populate_source_with_roles(source_a.path());
        populate_source_with_roles(source_b.path());
        std::fs::write(
            source_b.path().join("generation.json"),
            b"content:generation-mutated",
        )
        .unwrap();
        std::fs::write(
            source_b.path().join("eliotd.json"),
            b"content:eliotd-mutated",
        )
        .unwrap();

        let first_input = production_input(source_a.path(), portable.clone());
        let mut second_input = production_input(source_b.path(), portable);
        // Keep destination paths fixed so this assertion isolates derivation
        // from the source-bundle location itself.
        second_input.staging_root = first_input.staging_root.clone();
        let first = GenerationPackagePlanner::plan_unbound_for_test(first_input)
            .expect("first trusted source should plan");
        let second = GenerationPackagePlanner::plan_unbound_for_test(second_input)
            .expect("second trusted source should plan");

        assert_eq!(
            first.candidate_manifest.runtime_launch.eliotd_launch_nonce,
            second.candidate_manifest.runtime_launch.eliotd_launch_nonce,
            "nonce derivation must use the fixed immutable template facts"
        );
        assert_eq!(
            first
                .candidate_manifest
                .runtime_launch
                .store_credential_target,
            second
                .candidate_manifest
                .runtime_launch
                .store_credential_target,
            "Store credential derivation must use the same non-recursive template"
        );
        assert_ne!(
            first.candidate_manifest.config_digest, second.candidate_manifest.config_digest,
            "full candidate binding must still include mutated generation.json bytes"
        );
        assert_ne!(
            first.candidate_manifest.signature_ref, second.candidate_manifest.signature_ref,
            "full fifteen-role artifact evidence must still include both nonce-bearing JSON roles"
        );
    }

    #[test]
    fn generated_transaction_rejects_empty_subset_duplicate_alias_and_digest_tamper() {
        let (_tmp, portable, _roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        populate_source_with_roles(source_dir.path());
        let transaction = GenerationPackagePlanner::plan_unbound_for_test(production_input(
            source_dir.path(),
            portable,
        ))
        .expect("trusted generation planner should build one transaction");
        let package_index = transaction
            .installer_effects
            .iter()
            .position(|effect| matches!(effect, InstallerEffectPlan::StagePackage { .. }))
            .unwrap();

        let mut empty = transaction.clone();
        if let InstallerEffectPlan::StagePackage { manifest, .. } =
            &mut empty.installer_effects[package_index]
        {
            manifest.files.clear();
        }
        assert!(empty.validate().is_err(), "empty package must be rejected");

        let mut subset = transaction.clone();
        if let InstallerEffectPlan::StagePackage { manifest, .. } =
            &mut subset.installer_effects[package_index]
        {
            manifest.files.pop();
        }
        assert!(
            subset.validate().is_err(),
            "subset package must be rejected"
        );

        let mut duplicate = transaction.clone();
        if let InstallerEffectPlan::StagePackage {
            expected_file_digests,
            ..
        } = &mut duplicate.installer_effects[package_index]
        {
            expected_file_digests.push(expected_file_digests[0].clone());
        }
        assert!(
            duplicate.validate().is_err(),
            "duplicate digest must be rejected"
        );

        let mut alias = transaction.clone();
        alias.candidate_manifest.host_executable_path = h(alias
            .candidate_manifest
            .host_executable_path
            .as_str()
            .replace("eliot-host.exe", "eliot-host-copy.exe"));
        assert!(alias.validate().is_err(), "artifact alias must be rejected");

        let mut tampered = transaction.clone();
        if let InstallerEffectPlan::StagePackage {
            expected_file_digests,
            ..
        } = &mut tampered.installer_effects[package_index]
        {
            expected_file_digests[0].sha256 = h("a".repeat(64));
        }
        assert!(
            tampered.validate().is_err(),
            "digest tamper must be rejected"
        );

        let mut forged_ref = transaction.clone();
        forged_ref.candidate_manifest.signature_ref = h("f".repeat(64));
        let forged_manifest_digest = candidate_digest_fn(&forged_ref.candidate_manifest).unwrap();
        if let InstallerEffectPlan::StagePackage {
            candidate_manifest_digest,
            ..
        } = &mut forged_ref.installer_effects[package_index]
        {
            *candidate_manifest_digest = forged_manifest_digest;
        }
        assert!(
            forged_ref.validate().is_err(),
            "arbitrary artifact evidence reference must be rejected"
        );

        let mut size_substitution = transaction.clone();
        if let InstallerEffectPlan::StagePackage {
            expected_file_digests,
            ..
        } = &mut size_substitution.installer_effects[package_index]
        {
            expected_file_digests[0].expected_size += 1;
        }
        assert!(
            size_substitution.validate().is_err(),
            "one-file byte-size substitution must be rejected"
        );

        let mut executable_substitution = transaction;
        if let InstallerEffectPlan::StagePackage { manifest, .. } =
            &mut executable_substitution.installer_effects[package_index]
        {
            manifest.files[0].executable = !manifest.files[0].executable;
        }
        assert!(
            executable_substitution.validate().is_err(),
            "one-file executable-flag substitution must be rejected"
        );
    }

    #[test]
    fn generation_planner_rejects_source_missing_extra_and_alias_files() {
        for mutation in ["missing", "extra", "alias"] {
            let (_tmp, portable, _roots) = temp_portable_root();
            let source_dir = tempfile::TempDir::new().unwrap();
            populate_source_with_roles(source_dir.path());
            match mutation {
                "missing" => {
                    std::fs::remove_file(source_dir.path().join("generation.json")).unwrap()
                }
                "extra" => std::fs::write(source_dir.path().join("extra.bin"), b"extra").unwrap(),
                "alias" => {
                    std::fs::remove_file(source_dir.path().join("generation.json")).unwrap();
                    std::fs::write(source_dir.path().join("generation-copy.json"), b"alias")
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                GenerationPackagePlanner::plan_unbound_for_test(production_input(
                    source_dir.path(),
                    portable,
                ))
                .is_err(),
                "source mutation {mutation} must be rejected"
            );
        }
    }

    #[test]
    fn generation_planner_rejects_substituted_protected_snapshot_digest() {
        let (_tmp, portable, _roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        populate_source_with_roles(source_dir.path());
        std::fs::write(
            source_dir.path().join("eliotd-governor.json"),
            format!(r#"{{"protected_snapshot_digest":"{}"}}"#, "b".repeat(64)),
        )
        .unwrap();

        assert!(
            GenerationPackagePlanner::plan_unbound_for_test(production_input(
                source_dir.path(),
                portable,
            ))
            .is_err(),
            "source protected snapshot identity must match the independently derived domain"
        );
    }

    #[test]
    fn role_swap_duplicate_missing_extra_rejected() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        let hashes = populate_source_with_roles(source_dir.path());
        let mut candidate = build_real_candidate(portable.clone(), roots.clone(), hashes.clone());
        let roles = expected_role_map(&candidate);
        let mut specs = manifest_specs_with_staged_notify(&roles, source_dir.path());
        let manifest = PackageManifest::new("candidate", specs.clone()).unwrap();
        candidate.signature_ref = artifact_evidence_for_source(&manifest, source_dir.path());
        let (changes, effects) = installer_parts(&roots);
        let ok = SealedPackagePlanner::plan(
            h("transaction:ok"),
            make_epoch(),
            crate::InstallationProfile::PortableDev,
            make_request(),
            candidate.clone(),
            portable.clone(),
            test_handle(source_dir.path().to_string_lossy().into_owned()),
            manifest,
            changes.clone(),
            effects.clone(),
            1,
            vec![h("evidence:plan")],
            h("recovery:cmd"),
        );
        assert!(ok.is_ok());
        let mut swapped_specs = specs.clone();
        for s in &mut swapped_specs {
            if s.relative_path == "eliot-host.exe" {
                s.executable = false;
            }
            if s.relative_path == "generation.json" {
                s.executable = true;
            }
        }
        let swapped_manifest = PackageManifest::new("candidate", swapped_specs).unwrap();
        assert!(
            SealedPackagePlanner::plan(
                h("transaction:swap"),
                make_epoch(),
                crate::InstallationProfile::PortableDev,
                make_request(),
                candidate.clone(),
                portable.clone(),
                test_handle(source_dir.path().to_string_lossy().into_owned()),
                swapped_manifest,
                changes.clone(),
                effects.clone(),
                1,
                vec![h("evidence:plan")],
                h("recovery:cmd")
            )
            .is_err()
        );
        let mut dup_specs = specs.clone();
        dup_specs.push(specs[0].clone());
        let dup_manifest = PackageManifest {
            generation: "candidate".to_owned(),
            files: dup_specs,
        };
        assert!(
            SealedPackagePlanner::plan(
                h("transaction:dup"),
                make_epoch(),
                crate::InstallationProfile::PortableDev,
                make_request(),
                candidate.clone(),
                portable.clone(),
                test_handle(source_dir.path().to_string_lossy().into_owned()),
                dup_manifest,
                changes.clone(),
                effects.clone(),
                1,
                vec![h("evidence:plan")],
                h("recovery:cmd")
            )
            .is_err()
        );
        let mut missing_specs = specs.clone();
        let kernel_position = missing_specs
            .iter()
            .position(|spec| spec.relative_path == "eliot-kernel.exe")
            .expect("kernel role is staged");
        missing_specs.remove(kernel_position);
        let missing_manifest = PackageManifest::new("candidate", missing_specs).unwrap();
        assert!(
            SealedPackagePlanner::plan(
                h("transaction:missing"),
                make_epoch(),
                crate::InstallationProfile::PortableDev,
                make_request(),
                candidate.clone(),
                portable.clone(),
                test_handle(source_dir.path().to_string_lossy().into_owned()),
                missing_manifest,
                changes.clone(),
                effects.clone(),
                1,
                vec![h("evidence:plan")],
                h("recovery:cmd")
            )
            .is_err()
        );
        let mut extra_specs = specs.clone();
        extra_specs
            .push(eliot_platform_windows::PackageFileSpec::new("extra.bin", false, 5).unwrap());
        std::fs::write(source_dir.path().join("extra.bin"), b"extra").unwrap();
        let extra_manifest = PackageManifest::new("candidate", extra_specs).unwrap();
        assert!(
            SealedPackagePlanner::plan(
                h("transaction:extra"),
                make_epoch(),
                crate::InstallationProfile::PortableDev,
                make_request(),
                candidate.clone(),
                portable.clone(),
                test_handle(source_dir.path().to_string_lossy().into_owned()),
                extra_manifest,
                changes,
                effects,
                1,
                vec![h("evidence:plan")],
                h("recovery:cmd")
            )
            .is_err()
        );
    }
    #[test]
    fn same_size_mutation_and_replacement_rejected() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        let hashes = populate_source_with_roles(source_dir.path());
        let mut candidate = build_real_candidate(portable.clone(), roots.clone(), hashes.clone());
        let roles = expected_role_map(&candidate);
        let specs = manifest_specs_with_staged_notify(&roles, source_dir.path());
        let manifest = PackageManifest::new("candidate", specs).unwrap();
        candidate.signature_ref = artifact_evidence_for_source(&manifest, source_dir.path());
        let (changes, effects) = installer_parts(&roots);
        let tx = SealedPackagePlanner::plan(
            h("transaction:mut"),
            make_epoch(),
            crate::InstallationProfile::PortableDev,
            make_request(),
            candidate.clone(),
            portable.clone(),
            test_handle(source_dir.path().to_string_lossy().into_owned()),
            manifest.clone(),
            changes,
            effects,
            1,
            vec![h("evidence:plan")],
            h("recovery:cmd"),
        )
        .unwrap();
        if let Err(e) = SealedPackagePlanner::reopen_and_validate(&tx) {
            panic!("reopen initial failed: {e}");
        }
        let pe = minimal_pe();
        let mut mutated = pe.clone();
        mutated[0] ^= 0xFF;
        assert_eq!(pe.len(), mutated.len());
        std::fs::write(source_dir.path().join("eliot-host.exe"), &mutated).unwrap();
        assert!(SealedPackagePlanner::reopen_and_validate(&tx).is_err());
        let pe_with_name = file_content("eliot-host.exe", true);
        std::fs::write(source_dir.path().join("eliot-host.exe"), &pe_with_name).unwrap();
        if let Err(e) = SealedPackagePlanner::reopen_and_validate(&tx) {
            panic!("reopen after restore failed: {e}");
        }
        std::fs::remove_file(source_dir.path().join("eliot-host.exe")).unwrap();
        std::fs::write(
            source_dir.path().join("eliot-host.exe"),
            b"replacement-not-pe-same-size",
        )
        .unwrap();
        let cur = std::fs::read(source_dir.path().join("eliot-host.exe")).unwrap();
        assert!(SealedPackagePlanner::reopen_and_validate(&tx).is_err());
        let _ = cur;
    }
    #[test]
    fn forged_signature_rejected_and_raw_json_bypass_rejected() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        let hashes = populate_source_with_roles(source_dir.path());
        let mut candidate = build_real_candidate(portable.clone(), roots.clone(), hashes);
        candidate.signature_ref = h("0".repeat(64));
        let roles = expected_role_map(&candidate);
        let specs = manifest_specs_with_staged_notify(&roles, source_dir.path());
        let manifest = PackageManifest::new("candidate", specs).unwrap();
        let (changes, effects) = installer_parts(&roots);
        assert!(
            SealedPackagePlanner::plan(
                h("transaction:forged"),
                make_epoch(),
                crate::InstallationProfile::PortableDev,
                make_request(),
                candidate,
                portable.clone(),
                test_handle(source_dir.path().to_string_lossy().into_owned()),
                manifest,
                changes,
                effects,
                1,
                vec![h("evidence:plan")],
                h("recovery:cmd")
            )
            .is_err()
        );
        let bad = b"{\"not\":\"a transaction\"}";
        assert!(crate::decode_installation_transaction_json(bad).is_err());
    }
    #[test]
    fn public_planner_cannot_create_redb_without_published_journal() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        let hashes = populate_source_with_roles(source_dir.path());
        let mut candidate = build_real_candidate(portable.clone(), roots.clone(), hashes);
        let roles = expected_role_map(&candidate);
        let specs = manifest_specs_with_staged_notify(&roles, source_dir.path());
        let manifest = PackageManifest::new("candidate", specs).unwrap();
        candidate.signature_ref = artifact_evidence_for_source(&manifest, source_dir.path());
        let (changes, effects) = installer_parts(&roots);
        let tx = SealedPackagePlanner::plan(
            h("transaction:positive"),
            make_epoch(),
            crate::InstallationProfile::PortableDev,
            make_request(),
            candidate.clone(),
            portable.clone(),
            test_handle(source_dir.path().to_string_lossy().into_owned()),
            manifest.clone(),
            changes.clone(),
            effects.clone(),
            1,
            vec![h("evidence:plan")],
            h("recovery:cmd"),
        )
        .unwrap();
        assert!(SealedPackagePlanner::reopen_and_validate(&tx).is_ok());
        let dir = tempfile::TempDir::new().unwrap();
        let store_path = dir.path().join("tx.redb");
        assert!(matches!(
            crate::RedbInstallationTransactionStore::create_planned_at_exact_path(
                &store_path,
                &tx
            ),
            Err(crate::InstallationError::MigrationRequired { reason })
                if reason.contains("Published source publication journal")
        ));
        assert!(
            !store_path.exists(),
            "an unjournaled StagePackage plan must not create a redb authority"
        );
        let existing_path = dir.path().join("existing.redb");
        let mut existing =
            crate::RedbInstallationTransactionStore::create_at_exact_path(&existing_path).unwrap();
        assert!(matches!(
            existing.create_planned(&tx),
            Err(crate::InstallationError::MigrationRequired { reason })
                if reason.contains("publication journal")
        ));
        assert!(existing.load(&tx.transaction_id).unwrap().is_none());
    }
}
