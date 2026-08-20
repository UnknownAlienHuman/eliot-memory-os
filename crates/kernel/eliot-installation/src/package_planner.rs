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

fn derive_expected_digests(
    source: &TrustedSourceBundle,
    manifest: &PackageManifest,
) -> Result<Vec<PackageArtifactDigest>, InstallationError> {
    let mut digests = Vec::with_capacity(manifest.files.len());
    for spec in &manifest.files {
        let relative = validate_package_relative_path(Path::new(&spec.relative_path))
            .map_err(|e| package_plan_error(&e))?;
        let mut full = PathBuf::from(source.path());
        for comp in relative.components() {
            full.push(comp);
        }
        let metadata = std::fs::symlink_metadata(&full).map_err(|_| {
            InstallationError::Platform(format!("package file not found: {}", spec.relative_path))
        })?;
        if metadata.is_symlink() {
            return Err(InstallationError::InvalidField {
                field: "source_bundle".to_owned(),
                reason: "reparse point in package file".to_owned(),
            });
        }
        if !metadata.is_file() {
            return Err(InstallationError::InvalidField {
                field: "source_bundle".to_owned(),
                reason: "package entry is not a regular file".to_owned(),
            });
        }
        if metadata.len() > spec.max_size {
            return Err(InstallationError::InvalidField {
                field: "source_bundle".to_owned(),
                reason: "package file exceeds manifest max_size".to_owned(),
            });
        }
        let bytes = std::fs::read(&full).map_err(|e| InstallationError::Platform(e.to_string()))?;
        if bytes.len() as u64 > spec.max_size {
            return Err(InstallationError::InvalidField {
                field: "source_bundle".to_owned(),
                reason: "package file exceeds bound after read".to_owned(),
            });
        }
        if spec.executable {
            let header_len = bytes.len().min(1024 * 1024);
            let evidence =
                eliot_platform_windows::parse_pe_coff(&bytes[..header_len]).map_err(|e| {
                    InstallationError::InvalidField {
                        field: "source_bundle.executable".to_owned(),
                        reason: e.to_string(),
                    }
                })?;
            let _ = evidence;
        }
        let sha = hex_digest(&bytes);
        let sha_handle =
            PlatformHandle::new(sha.clone()).map_err(|e| InstallationError::InvalidField {
                field: "sha256".to_owned(),
                reason: e.to_string(),
            })?;
        if sha_handle.as_str().len() != 64
            || !sha_handle
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(InstallationError::InvalidField {
                field: "sha256".to_owned(),
                reason: "invalid digest".to_owned(),
            });
        }
        digests.push(PackageArtifactDigest {
            relative_path: spec.relative_path.clone(),
            sha256: sha_handle,
        });
    }
    Ok(digests)
}

fn enumerate_source_tree(
    source: &TrustedSourceBundle,
) -> Result<BTreeSet<String>, InstallationError> {
    let root = source.path();
    let mut set = BTreeSet::new();
    let mut stack = vec![PathBuf::from(root)];
    let mut prefix_stack = vec![Vec::<String>::new()];
    let mut depth = 0usize;
    while let Some(dir) = stack.pop() {
        let prefix = prefix_stack.pop().unwrap_or_default();
        if depth > 32 {
            return Err(InstallationError::InvalidField {
                field: "source_bundle".to_owned(),
                reason: "path depth exceeded".to_owned(),
            });
        }
        let entries =
            std::fs::read_dir(&dir).map_err(|e| InstallationError::Platform(e.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|e| InstallationError::Platform(e.to_string()))?;
            let name_os = entry.file_name();
            let name = name_os.to_str().ok_or(InstallationError::InvalidField {
                field: "source_bundle".to_owned(),
                reason: "invalid utf8 filename".to_owned(),
            })?;
            let meta = std::fs::symlink_metadata(entry.path())
                .map_err(|e| InstallationError::Platform(e.to_string()))?;
            if meta.is_symlink() {
                return Err(InstallationError::InvalidField {
                    field: "source_bundle".to_owned(),
                    reason: "reparse point in source tree".to_owned(),
                });
            }
            let mut comps = prefix.clone();
            comps.push(name.to_owned());
            let rel = comps.join("/");
            validate_package_relative_path(Path::new(&rel)).map_err(|e| package_plan_error(&e))?;
            if meta.is_dir() {
                stack.push(entry.path());
                prefix_stack.push(comps);
                depth += 1;
            } else if meta.is_file() {
                let lower = rel.to_ascii_lowercase();
                if !set.insert(lower) {
                    return Err(InstallationError::Duplicate {
                        kind: "package file".to_owned(),
                        identity: rel,
                    });
                }
            } else {
                return Err(InstallationError::InvalidField {
                    field: "source_bundle".to_owned(),
                    reason: "unsupported entry kind".to_owned(),
                });
            }
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
        let expected_file_digests = derive_expected_digests(&source, &manifest)?;
        let candidate_manifest_digest = candidate_digest_fn(&candidate_manifest)?;
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
            ..
        } = pkg
        else {
            unreachable!()
        };
        let expected_candidate = candidate_digest_fn(&transaction.candidate_manifest)?;
        if expected_candidate != *candidate_manifest_digest {
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
            signature_ref: h("evidence:sig"),
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
}
