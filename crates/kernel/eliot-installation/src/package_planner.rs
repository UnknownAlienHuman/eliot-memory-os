use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    PackageManifest, PackageStagingError, TrustedSourceBundle, validate_package_relative_path,
};

use crate::PackageArtifactDigest;
use sha2::{Digest, Sha256};

use crate::{
    CandidateManifest, InstallationEpoch, InstallationError, InstallationProfile,
    InstallationTransaction, InstallerEffectPlan, ManagedEnvironmentChangeRequest, PlannedChange,
    candidate_manifest_digest as candidate_digest_fn, handle,
};

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
            if spec.max_size == 0 || spec.max_size > 512 * 1024 * 1024 {
                return Err(InstallationError::InvalidField {
                    field: "installer_effect.package_manifest.files.max_size".to_owned(),
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
        if spec.max_size == 0 || spec.max_size > 512 * 1024 * 1024 {
            return Err(InstallationError::InvalidField {
                field: "installer_effect.package_manifest.files.max_size".to_owned(),
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

fn derive_expected_digests(
    source: &TrustedSourceBundle,
    manifest: &PackageManifest,
) -> Result<Vec<PackageArtifactDigest>, InstallationError> {
    let observed = source
        .observe()
        .map_err(|e| InstallationError::Platform(format!("source observe failed: {e}")))?;
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
        if entry.size > spec.max_size {
            return Err(InstallationError::InvalidField {
                field: "source_bundle".to_owned(),
                reason: "package file exceeds manifest max_size".to_owned(),
            });
        }
        let relative = validate_package_relative_path(Path::new(&spec.relative_path))
            .map_err(|e| package_plan_error(&e))?;
        let mut full = PathBuf::from(source.path());
        for comp in relative.components() {
            full.push(comp);
        }
        let meta = std::fs::symlink_metadata(&full)
            .map_err(|e| InstallationError::Platform(e.to_string()))?;
        if meta.is_symlink() {
            return Err(InstallationError::Platform(
                "reparse point in package file".to_owned(),
            ));
        }
        let bytes = std::fs::read(&full).map_err(|e| InstallationError::Platform(e.to_string()))?;
        if bytes.len() as u64 != entry.size {
            return Err(InstallationError::Platform(
                "size mismatch after read (possible mutation)".to_owned(),
            ));
        }
        let actual_sha = hex_digest(&bytes);
        if actual_sha != entry.sha256 {
            return Err(InstallationError::Platform(
                "hash mismatch (same-size mutation)".to_owned(),
            ));
        }
        let meta2 =
            std::fs::metadata(&full).map_err(|e| InstallationError::Platform(e.to_string()))?;
        if meta2.len() != entry.size {
            return Err(InstallationError::Platform(
                "post-read size mismatch".to_owned(),
            ));
        }
        if spec.executable {
            let header_len = bytes.len().min(1024 * 1024);
            eliot_platform_windows::parse_pe_coff(&bytes[..header_len]).map_err(|e| {
                InstallationError::InvalidField {
                    field: "source_bundle.executable".to_owned(),
                    reason: e.to_string(),
                }
            })?;
        }
        let sha_handle = PlatformHandle::new(entry.sha256.clone()).map_err(|e| {
            InstallationError::InvalidField {
                field: "sha256".to_owned(),
                reason: e.to_string(),
            }
        })?;
        digests.push(PackageArtifactDigest {
            relative_path: spec.relative_path.clone(),
            sha256: sha_handle,
        });
    }
    if digests.len() != observed.files.len() {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(digests)
}

fn enumerate_source_tree(
    source: &TrustedSourceBundle,
) -> Result<BTreeSet<String>, InstallationError> {
    let observed = source
        .observe()
        .map_err(|e| InstallationError::Platform(format!("source observe failed: {e}")))?;
    let mut set = BTreeSet::new();
    for file in observed.files {
        let validated = validate_package_relative_path(Path::new(&file.relative_path))
            .map_err(|e| package_plan_error(&e))?;
        let lower = validated.as_str().to_ascii_lowercase();
        if !set.insert(lower) {
            return Err(InstallationError::Duplicate {
                kind: "package file".to_owned(),
                identity: file.relative_path,
            });
        }
    }
    Ok(set)
}

/// Sealed production planner that derives package facts from a pinned source bundle.
pub struct SealedPackagePlanner;

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
        let observed_tree = enumerate_source_tree(&source)?;
        let manifest_paths: BTreeSet<String> = manifest
            .files
            .iter()
            .map(|f| f.relative_path.to_ascii_lowercase())
            .collect();
        if observed_tree != manifest_paths {
            return Err(InstallationError::IdentityConflict);
        }
        validate_candidate_package_binding(&candidate_manifest, &manifest)?;
        let expected_file_digests = derive_expected_digests(&source, &manifest)?;
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
        let tree = enumerate_source_tree(&source)?;
        if tree != observed_paths {
            return Err(InstallationError::IdentityConflict);
        }
        let derived = derive_expected_digests(&source, manifest)?;
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
            vec![eliot_platform_windows::PackageFileSpec::new("a.txt", false, 1024).unwrap()],
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
            vec![eliot_platform_windows::PackageFileSpec::new("a.txt", false, 1024).unwrap()],
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
        let spec_a = eliot_platform_windows::PackageFileSpec::new("a.txt", false, 1024).unwrap();
        let spec_b = eliot_platform_windows::PackageFileSpec::new("b.txt", false, 1024).unwrap();
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
            vec![eliot_platform_windows::PackageFileSpec::new("a.txt", false, 1024).unwrap()],
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
            vec![eliot_platform_windows::PackageFileSpec::new("a.txt", false, 1024).unwrap()],
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
        let spec = eliot_platform_windows::PackageFileSpec::new("bad.exe", true, 1024).unwrap();
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
    #[test]
    fn role_swap_duplicate_missing_extra_rejected() {
        let (_tmp, portable, roots) = temp_portable_root();
        let source_dir = tempfile::TempDir::new().unwrap();
        let hashes = populate_source_with_roles(source_dir.path());
        let mut candidate = build_real_candidate(portable.clone(), roots.clone(), hashes.clone());
        candidate.signature_ref = h(sha_of(b"valid-sig"));
        let roles = expected_role_map(&candidate);
        let specs: Vec<_> = roles
            .iter()
            .map(|(p, exe, _)| {
                eliot_platform_windows::PackageFileSpec::new(p.as_str(), *exe, 1024 * 1024).unwrap()
            })
            .collect();
        let manifest = PackageManifest::new("candidate", specs.clone()).unwrap();
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
            .push(eliot_platform_windows::PackageFileSpec::new("extra.bin", false, 1024).unwrap());
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
        candidate.signature_ref = h(sha_of(b"valid-sig2"));
        let roles = expected_role_map(&candidate);
        let specs: Vec<_> = roles
            .iter()
            .map(|(p, exe, _)| {
                eliot_platform_windows::PackageFileSpec::new(p.as_str(), *exe, 1024 * 1024).unwrap()
            })
            .collect();
        let manifest = PackageManifest::new("candidate", specs).unwrap();
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
                eliot_platform_windows::PackageFileSpec::new(p.as_str(), *exe, 1024 * 1024).unwrap()
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
        candidate.signature_ref = h(sha_of(b"valid-sig3"));
        let roles = expected_role_map(&candidate);
        let specs: Vec<_> = roles
            .iter()
            .map(|(p, exe, _)| {
                eliot_platform_windows::PackageFileSpec::new(p.as_str(), *exe, 1024 * 1024).unwrap()
            })
            .collect();
        let manifest = PackageManifest::new("candidate", specs).unwrap();
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
