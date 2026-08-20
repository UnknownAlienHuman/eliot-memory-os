use std::collections::BTreeSet;
use std::path::Path;

use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    PackageManifest, PackageSourceObservation, PackageStagingError, TrustedSourceBundle,
    validate_package_relative_path,
};

use sha2::{Digest, Sha256};

use crate::{
    AuthorityEpoch, CandidateManifest, InstallationEpoch, InstallationError, InstallationProfile,
    InstallationTransaction, InstallerAclPrincipal, InstallerEffectPlan, InstallerServiceAccount,
    InstallerServiceRole, LOCAL_SERVICE_SID, ManagedEnvironmentAction,
    ManagedEnvironmentChangeRequest, PackageArtifactDigest, PlannedChange, ResourceGeneration,
    RuntimeLaunchDescriptor, RuntimeStateRoots, StateFence, StoreCredentialProvider,
    StoreCredentialProvisionPlan, StoreCredentialScope,
    candidate_manifest_digest as candidate_digest_fn, handle,
};

/// The immutable package inventory produced by the trusted generation seam.
///
/// The role names deliberately live in one place.  A caller cannot provide a
/// partial candidate and ask the stager to infer the missing Host, Watchdog,
/// Kernel, Store or daemon contour.
const REQUIRED_PACKAGE_ROLES: [(&str, bool); 11] = [
    ("eliot-host.exe", true),
    ("eliot-watchdog.exe", true),
    ("eliot-kernel.exe", true),
    ("eliot-store-surreal.exe", true),
    ("surreal.exe", true),
    ("eliotd.exe", true),
    ("generation.json", false),
    ("eliotd-governor.json", false),
    ("eliotd.json", false),
    ("store-bootstrap.json", false),
    ("authority.json", false),
];

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

const CANARY_ARTIFACT_SET_EVIDENCE_DOMAIN: &[u8] =
    b"eliot.runtime-live.canary-artifact-set-evidence.v1";

fn append_evidence_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

/// Derive the Runtime Live canary artifact-set evidence reference.
///
/// The reference is a domain-separated SHA-256 over the canonical generation
/// and the complete, fixed-order eleven-file inventory.  Each fact contains
/// the validated relative path, executable bit, exact byte size, and lowercase
/// SHA-256.  Source identities and other volatile filesystem observations are
/// deliberately excluded; the retained-source and destination receipt gates
/// bind those observations transitively to this immutable fact set.
pub(crate) fn artifact_set_evidence_digest(
    manifest: &PackageManifest,
    expected: &[PackageArtifactDigest],
) -> Result<PlatformHandle, InstallationError> {
    if manifest.files.len() != REQUIRED_PACKAGE_ROLES.len()
        || expected.len() != REQUIRED_PACKAGE_ROLES.len()
    {
        return Err(InstallationError::IncompleteObservation(
            "canary artifact evidence requires the complete eleven-file runtime inventory"
                .to_owned(),
        ));
    }
    let generation = validate_package_relative_path(Path::new(&manifest.generation))
        .map_err(|error| package_plan_error(&error))?;
    let mut manifest_names = BTreeSet::new();
    let mut expected_names = BTreeSet::new();
    let mut facts = Vec::with_capacity(REQUIRED_PACKAGE_ROLES.len());

    for (role, executable) in REQUIRED_PACKAGE_ROLES {
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
        || manifest_names.len() != REQUIRED_PACKAGE_ROLES.len()
        || expected_names.len() != REQUIRED_PACKAGE_ROLES.len()
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
            file_name(&rt.authority_descriptor_path),
            false,
            rt.authority_descriptor_digest.as_str().to_owned(),
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
        (
            file_name(&rt.store_bootstrap_descriptor_path),
            false,
            rt.store_bootstrap_descriptor_digest.as_str().to_owned(),
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
    if manifest.files.len() != roles.len() {
        return Err(InstallationError::IdentityConflict);
    }
    let mut seen = std::collections::BTreeSet::new();
    let manifest_lower: BTreeSet<String> = manifest
        .files
        .iter()
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
    let mut manifest_sorted = manifest.files.clone();
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
) -> [(&'static str, bool, &PlatformHandle, &PlatformHandle); 11] {
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
        (
            "store-bootstrap.json",
            false,
            &runtime.store_bootstrap_descriptor_path,
            &runtime.store_bootstrap_descriptor_digest,
        ),
        (
            "authority.json",
            false,
            &runtime.authority_descriptor_path,
            &runtime.authority_descriptor_digest,
        ),
    ]
}

/// Validate the complete production package bijection.
///
/// This boundary is intentionally independent of the caller's manifest and
/// expected-digest vectors.  It binds all eleven canonical role names and
/// requires every `CandidateManifest` path/digest to participate exactly once.
pub(crate) fn validate_exact_candidate_package_binding(
    candidate: &CandidateManifest,
    manifest: &PackageManifest,
) -> Result<(), InstallationError> {
    if manifest.generation != candidate.generation.as_str() {
        return Err(InstallationError::IdentityConflict);
    }
    if manifest.files.len() != REQUIRED_PACKAGE_ROLES.len() {
        return Err(InstallationError::IncompleteObservation(
            "package manifest must contain the complete eleven-file runtime inventory".to_owned(),
        ));
    }
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
    let mut manifest_names = BTreeSet::new();
    for spec in &manifest.files {
        let Some((name, executable)) = REQUIRED_PACKAGE_ROLES
            .iter()
            .find(|(name, _)| *name == spec.relative_path)
        else {
            return Err(InstallationError::IdentityConflict);
        };
        if spec.executable != *executable || !manifest_names.insert((*name).to_owned()) {
            return Err(InstallationError::IdentityConflict);
        }
    }
    if manifest_names != expected_names {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn candidate_has_nonplaceholder_package_digests(candidate: &CandidateManifest) -> bool {
    strict_role_bindings(candidate)
        .into_iter()
        .any(|(_, _, _, digest)| {
            let value = digest.as_str();
            value.len() != 64
                || value
                    .chars()
                    .next()
                    .is_none_or(|first| !value.chars().all(|item| item == first))
        })
}

pub(crate) fn validate_exact_expected_file_digests(
    candidate: &CandidateManifest,
    manifest: &PackageManifest,
    expected: &[PackageArtifactDigest],
) -> Result<(), InstallationError> {
    validate_exact_candidate_package_binding(candidate, manifest)?;
    if expected.len() != REQUIRED_PACKAGE_ROLES.len() {
        return Err(InstallationError::IncompleteObservation(
            "expected package digest set must contain all eleven runtime files".to_owned(),
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
    let expected_names = REQUIRED_PACKAGE_ROLES
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
}

/// The sole production package/transaction composition seam.
pub struct GenerationPackagePlanner;

impl GenerationPackagePlanner {
    /// Derive the complete candidate/package/effect graph and create one
    /// immutable `PLANNED` transaction.
    ///
    /// The source is opened and observed independently of every manifest claim.
    /// The exact eleven-file inventory is then used to construct all canonical
    /// destination paths, descriptor/config bindings, argv and artifact
    /// digests before the single transaction constructor is called.
    #[allow(
        clippy::too_many_lines,
        reason = "the production seam keeps candidate, package and effect derivation auditable"
    )]
    pub fn plan(
        input: GenerationPackagePlanInput,
    ) -> Result<InstallationTransaction, InstallationError> {
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
        let canonical_generation =
            validate_package_relative_path(Path::new(input.generation.as_str()))
                .map_err(|error| package_plan_error(&error))?;
        if canonical_generation.as_str() != input.generation.as_str() {
            return Err(InstallationError::IdentityConflict);
        }

        let roots = match input.profile {
            InstallationProfile::PortableDev => {
                if input.installation_key.is_some() {
                    return Err(InstallationError::ProfileViolation(
                        "portable_dev does not accept a profiled installation key".to_owned(),
                    ));
                }
                RuntimeStateRoots::derive_portable(input.profile_anchor_root.clone())?
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
                )?
            }
        };
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

        let files = observed
            .files
            .iter()
            .map(|entry| {
                let executable = REQUIRED_PACKAGE_ROLES
                    .iter()
                    .find(|(name, _)| *name == entry.relative_path)
                    .map(|(_, executable)| *executable)
                    .ok_or(InstallationError::IdentityConflict)?;
                eliot_platform_windows::PackageFileSpec::new(
                    &entry.relative_path,
                    executable,
                    entry.size,
                )
                .map_err(|error| package_plan_error(&error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let package_manifest = PackageManifest::new(input.generation.as_str(), files)
            .map_err(|error| package_plan_error(&error))?;

        let generation_root =
            Path::new(input.staging_root.as_str()).join(input.generation.as_str());
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
            (&config_path, "generation.config_path"),
            (&eliotd_config_path, "generation.eliotd_config_path"),
            (&eliotd_descriptor_path, "generation.eliotd_descriptor_path"),
            (&store_bootstrap_path, "generation.store_bootstrap_path"),
            (&authority_path, "generation.authority_path"),
        ] {
            approved_path(path, field)?;
        }

        let expected_file_digests = derive_expected_digests(&observed, &package_manifest)?;
        if expected_file_digests.len() != REQUIRED_PACKAGE_ROLES.len() {
            return Err(InstallationError::IncompleteObservation(
                "trusted source digest set is incomplete".to_owned(),
            ));
        }
        let digest_for = |name: &str| {
            expected_file_digests
                .iter()
                .find(|digest| digest.relative_path == name)
                .map(|digest| digest.sha256.clone())
                .ok_or(InstallationError::IdentityConflict)
        };
        let kernel_digest = digest_for("eliot-kernel.exe")?;
        let host_digest = digest_for("eliot-host.exe")?;
        let watchdog_digest = digest_for("eliot-watchdog.exe")?;
        let store_bridge_digest = digest_for("eliot-store-surreal.exe")?;
        let canonical_store_digest = digest_for("surreal.exe")?;
        let eliotd_digest = digest_for("eliotd.exe")?;
        let config_digest = digest_for("generation.json")?;
        let eliotd_config_digest = digest_for("eliotd-governor.json")?;
        let eliotd_descriptor_digest = digest_for("eliotd.json")?;
        let store_bootstrap_digest = digest_for("store-bootstrap.json")?;
        let authority_digest = digest_for("authority.json")?;

        let authority_generation = ResourceGeneration::new(input.installation_epoch.sequence)
            .map_err(|error| InstallationError::InvalidField {
                field: "generation.authority_generation".to_owned(),
                reason: error.to_string(),
            })?;
        let authority_epoch =
            AuthorityEpoch::new(input.installation_epoch.sequence).map_err(|error| {
                InstallationError::InvalidField {
                    field: "generation.authority_epoch".to_owned(),
                    reason: error.to_string(),
                }
            })?;
        let authority_state_fence = StateFence::new(authority_epoch, authority_generation);
        let nonce_seed = format!(
            "eliotd:{}:{}:{}:{}",
            input.transaction_id,
            input.installation_epoch.installation,
            input.generation,
            source_identity.file_index
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
                "eliot-store-credential:{}:{}:{}",
                input.installation_epoch.installation, input.generation, source_identity.file_index
            )
            .as_bytes(),
        );
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
            store_bootstrap_digest.as_str().to_owned(),
            "--authority-descriptor".to_owned(),
            authority_path.as_str().to_owned(),
            "--authority-descriptor-sha256".to_owned(),
            authority_digest.as_str().to_owned(),
            "--kernel-artifact-sha256".to_owned(),
            kernel_digest.as_str().to_owned(),
            "--eliotd-descriptor".to_owned(),
            eliotd_descriptor_path.as_str().to_owned(),
            "--eliotd-descriptor-sha256".to_owned(),
            eliotd_descriptor_digest.as_str().to_owned(),
        ])?;
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
            portable_root: (input.profile == InstallationProfile::PortableDev)
                .then(|| input.profile_anchor_root.clone()),
            installation_epoch: input.installation_epoch.clone(),
            generation: input.generation.clone(),
            authority_generation,
            authority_state_fence,
            authority_descriptor_path: authority_path,
            authority_descriptor_digest: authority_digest,
            runtime_state_roots: roots.clone(),
            kernel_work_root: roots.kernel_work_root.clone(),
            kernel_artifact_digest: kernel_digest.clone(),
            eliotd_executable_path: eliotd_path,
            eliotd_artifact_digest: eliotd_digest,
            eliotd_config_path,
            eliotd_config_digest,
            eliotd_descriptor_path,
            eliotd_descriptor_digest,
            eliotd_launch_nonce,
            store_config_path: config_path.clone(),
            store_credential_target: store_credential_target.clone(),
            store_bridge_executable_path: store_bridge_path.clone(),
            store_bridge_artifact_digest: store_bridge_digest.clone(),
            store_bootstrap_descriptor_path: store_bootstrap_path,
            store_bootstrap_descriptor_digest: store_bootstrap_digest,
            canonical_store_executable_path: canonical_store_path.clone(),
            canonical_store_artifact_digest: canonical_store_digest.clone(),
            kernel_arguments,
            store_bridge_arguments,
            canonical_store_arguments,
            host_executable_path: host_path.clone(),
            host_artifact_digest: host_digest.clone(),
            watchdog_executable_path: watchdog_path.clone(),
            watchdog_artifact_digest: watchdog_digest.clone(),
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
            components: REQUIRED_PACKAGE_ROLES
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
            kernel_executable_path: kernel_path,
            store_bridge_executable_path: store_bridge_path,
            canonical_store_executable_path: canonical_store_path,
            host_executable_path: host_path,
            config_path,
            dependency_closure_refs: vec![
                PlatformHandle::new(format!("evidence:source:{}", source_identity.file_index))
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
            supervision_key_fingerprint: PlatformHandle::new(hex_digest(
                format!(
                    "eliot-supervision-key:{}:{}",
                    input.installation_epoch.installation, input.generation
                )
                .as_bytes(),
            ))
            .map_err(|error| InstallationError::InvalidField {
                field: "generation.supervision_key_fingerprint".to_owned(),
                reason: error.to_string(),
            })?,
            signature_ref,
            runtime_state_roots_digest: roots.roots_digest.clone(),
            runtime_launch: launch,
        };
        candidate.validate()?;
        validate_exact_candidate_package_binding(&candidate, &package_manifest)?;
        for digest in &expected_file_digests {
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
        for (field, root) in std::iter::once(("installation_root", &roots.installation_root))
            .chain(roots.root_fields())
        {
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
                root: root.clone(),
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
            expected_file_digests,
            candidate_manifest_digest,
            package_manifest_digest,
        });
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
        }
        let planned_changes = effects
            .iter()
            .map(|effect| {
                let target = match effect {
                    InstallerEffectPlan::CreateRoot { root, .. }
                    | InstallerEffectPlan::ApplyAcl { root, .. } => root.clone(),
                    InstallerEffectPlan::StagePackage { staging_root, .. } => staging_root.clone(),
                    InstallerEffectPlan::RegisterService { service_name, .. } => {
                        service_name.clone()
                    }
                    InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => {
                        provision.target.clone()
                    }
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
        InstallationTransaction::new(
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
        )
    }
}

fn validate_exact_source_inventory(
    observed: &eliot_platform_windows::PackageSourceObservation,
) -> Result<(), InstallationError> {
    if observed.files.len() != REQUIRED_PACKAGE_ROLES.len() {
        return Err(InstallationError::IncompleteObservation(
            "trusted source must contain exactly eleven runtime files".to_owned(),
        ));
    }
    let expected = REQUIRED_PACKAGE_ROLES
        .iter()
        .map(|(name, _)| *name)
        .collect::<BTreeSet<_>>();
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
        InstallationTransaction::new(
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
        )
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
    use super::*;
    use crate::InstallationTransactionStore;
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
        let mut desc = crate::RuntimeLaunchDescriptor {
            profile: crate::InstallationProfile::PortableDev,
            portable_root: Some(portable_root.clone()),
            installation_epoch: epoch.clone(),
            generation: h("candidate"),
            authority_generation: eliot_contracts::ResourceGeneration::genesis(),
            authority_state_fence: eliot_contracts::StateFence::new(
                eliot_contracts::AuthorityEpoch::genesis(),
                eliot_contracts::ResourceGeneration::genesis(),
            ),
            authority_descriptor_path: test_path(portable_root.as_str(), "authority.json"),
            authority_descriptor_digest: h("7".repeat(64)),
            runtime_state_roots: roots.clone(),
            kernel_work_root: roots.kernel_work_root.clone(),
            kernel_artifact_digest: h("0".repeat(64)),
            eliotd_executable_path: test_path(portable_root.as_str(), "eliotd.exe"),
            eliotd_artifact_digest: h("8".repeat(64)),
            eliotd_config_path: test_path(portable_root.as_str(), "eliotd-governor.json"),
            eliotd_config_digest: h("4".repeat(64)),
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
            store_bootstrap_descriptor_digest: h("6".repeat(64)),
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
            watchdog_executable_path: test_path(portable_root.as_str(), "eliot-watchdog.exe"),
            watchdog_artifact_digest: h("4".repeat(64)),
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
            generation: h("candidate"),
            components: vec![h("component:test")],
            kernel_artifact_digest: h("0".repeat(64)),
            store_bridge_artifact_digest: h("1".repeat(64)),
            canonical_store_artifact_digest: h("5".repeat(64)),
            host_artifact_digest: h("8".repeat(64)),
            kernel_executable_path: test_path(portable_root.as_str(), "eliot-kernel.exe"),
            store_bridge_executable_path: desc.store_bridge_executable_path.clone(),
            canonical_store_executable_path: desc.canonical_store_executable_path.clone(),
            host_executable_path: desc.host_executable_path.clone(),
            config_path: desc.store_config_path.clone(),
            dependency_closure_refs: vec![h("evidence:dep")],
            license_refs: vec![h("evidence:license")],
            config_digest: h("2".repeat(64)),
            store_credential_target: h("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            supervision_key_fingerprint: h("3".repeat(64)),
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
        for (field, root) in std::iter::once(("installation_root", &roots.installation_root))
            .chain(roots.root_fields().into_iter().map(|(f, r)| (f, r)))
        {
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
        base.config_digest = h(get("generation.json"));
        base.supervision_key_fingerprint = h("c".repeat(64));
        base.runtime_launch.kernel_artifact_digest = h(get("eliot-kernel.exe"));
        base.runtime_launch.host_artifact_digest = h(get("eliot-host.exe"));
        base.runtime_launch.watchdog_artifact_digest = h(get("eliot-watchdog.exe"));
        base.runtime_launch.store_bridge_artifact_digest = h(get("eliot-store-surreal.exe"));
        base.runtime_launch.canonical_store_artifact_digest = h(get("surreal.exe"));
        base.runtime_launch.eliotd_artifact_digest = h(get("eliotd.exe"));
        base.runtime_launch.eliotd_config_digest = h(get("eliotd-governor.json"));
        base.runtime_launch.eliotd_descriptor_digest = h(get("eliotd.json"));
        base.runtime_launch.store_bootstrap_descriptor_digest = h(get("store-bootstrap.json"));
        base.runtime_launch.authority_descriptor_digest = h(get("authority.json"));
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
            ("authority.json", false),
            ("generation.json", false),
            ("eliotd-governor.json", false),
            ("eliotd.json", false),
            ("store-bootstrap.json", false),
        ];
        let mut map = std::collections::BTreeMap::new();
        for (name, exe) in roles {
            let content = file_content(name, exe);
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
        }
    }

    #[test]
    fn generation_planner_builds_and_binds_complete_inventory() {
        let (_tmp, portable, _roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        populate_source_with_roles(source_dir.path());
        let transaction =
            GenerationPackagePlanner::plan(production_input(source_dir.path(), portable))
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

    #[test]
    fn artifact_evidence_is_stable_across_source_file_identity() {
        let (_tmp, portable, _roots) = temp_portable_root();
        let source_a = tempfile::TempDir::new().unwrap();
        let source_b = tempfile::TempDir::new().unwrap();
        populate_source_with_roles(source_a.path());
        populate_source_with_roles(source_b.path());

        let first =
            GenerationPackagePlanner::plan(production_input(source_a.path(), portable.clone()))
                .expect("first trusted source should plan");
        let second = GenerationPackagePlanner::plan(production_input(source_b.path(), portable))
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
    fn generated_transaction_rejects_empty_subset_duplicate_alias_and_digest_tamper() {
        let (_tmp, portable, _roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        populate_source_with_roles(source_dir.path());
        let transaction =
            GenerationPackagePlanner::plan(production_input(source_dir.path(), portable))
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
                    std::fs::remove_file(source_dir.path().join("authority.json")).unwrap()
                }
                "extra" => std::fs::write(source_dir.path().join("extra.bin"), b"extra").unwrap(),
                "alias" => {
                    std::fs::remove_file(source_dir.path().join("authority.json")).unwrap();
                    std::fs::write(source_dir.path().join("authority-copy.json"), b"alias")
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                GenerationPackagePlanner::plan(production_input(source_dir.path(), portable))
                    .is_err(),
                "source mutation {mutation} must be rejected"
            );
        }
    }

    #[test]
    fn role_swap_duplicate_missing_extra_rejected() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        let hashes = populate_source_with_roles(source_dir.path());
        let mut candidate = build_real_candidate(portable.clone(), roots.clone(), hashes.clone());
        let roles = expected_role_map(&candidate);
        let specs: Vec<_> = roles
            .iter()
            .map(|(p, exe, _)| {
                eliot_platform_windows::PackageFileSpec::new(
                    p.as_str(),
                    *exe,
                    exact_size(source_dir.path(), p),
                )
                .unwrap()
            })
            .collect();
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
            if s.relative_path == "authority.json" {
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
        missing_specs.pop();
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
        let specs: Vec<_> = roles
            .iter()
            .map(|(p, exe, _)| {
                eliot_platform_windows::PackageFileSpec::new(
                    p.as_str(),
                    *exe,
                    exact_size(source_dir.path(), p),
                )
                .unwrap()
            })
            .collect();
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
        let specs: Vec<_> = roles
            .iter()
            .map(|(p, exe, _)| {
                eliot_platform_windows::PackageFileSpec::new(
                    p.as_str(),
                    *exe,
                    exact_size(source_dir.path(), p),
                )
                .unwrap()
            })
            .collect();
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
    fn retained_handle_redb_reopen_positive() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        let hashes = populate_source_with_roles(source_dir.path());
        let mut candidate = build_real_candidate(portable.clone(), roots.clone(), hashes);
        let roles = expected_role_map(&candidate);
        let specs: Vec<_> = roles
            .iter()
            .map(|(p, exe, _)| {
                eliot_platform_windows::PackageFileSpec::new(
                    p.as_str(),
                    *exe,
                    exact_size(source_dir.path(), p),
                )
                .unwrap()
            })
            .collect();
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
        let store =
            crate::RedbInstallationTransactionStore::create_planned_at_exact_path(&store_path, &tx)
                .unwrap();
        drop(store);
        let store2 =
            crate::RedbInstallationTransactionStore::open_existing_exact_path(&store_path).unwrap();
        let loaded = store2.load(&h("transaction:positive")).unwrap().unwrap();
        assert_eq!(loaded.transaction_id, tx.transaction_id);
        assert!(SealedPackagePlanner::reopen_and_validate(&loaded).is_ok());
    }
}
