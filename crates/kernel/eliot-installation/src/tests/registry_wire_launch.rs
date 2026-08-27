//! Test oracle for registry wire and launch binding.
//! Architecture: A11.2, A12.3, A13.8, A13.9, ARCH-AUTH-01, ARCH-SEC-02, ARCH-RES-03
//! Implementation: I2.16, I2.17, I2.18, I2.23, I3.15, I15.3, I15.8, I18.36, I18.40
//! Test-oracle-only: no production/migration/canonical/authority ownership or invalid-state resurrection.

use std::path::Path;
use std::sync::atomic::Ordering;

use super::NEXT_TRANSACTION_ROOT;
use super::classify_registry_table;
use super::decode_registry_bytes;
use super::host_capability;
use super::installer_plan_parts;
use super::must;
use super::protected_program_data_root;
use super::registering_transaction;
use super::reseal;
use super::sha256_hex;
use super::system_registration_transaction;
use super::test_activation_approval;
use super::test_commit_fence;
use super::test_handle;
use super::test_path;
use super::test_transaction_activation_approval;
use super::validate_installer_effects;
use crate::ActivePhaseBRebind;
use crate::ActivePhaseBRebindIntent;
use crate::ApprovedGeneration;
use crate::ApprovedGenerationRegistry;
use crate::ContractVersion;
use crate::InstallationError;
use crate::InstallationProfile;
use crate::InstallationTransaction;
use crate::InstallerEffectPlan;
use crate::InstallerServiceRole;
use crate::LEGACY_REGISTRY_TABLE;
use crate::PlatformHandle;
use crate::ResourceGeneration;
use crate::RuntimeLaunchDescriptor;
use crate::RuntimeStateRoots;
use crate::active_phase_b_rebind_intent_digest;
use crate::approved_path;
use crate::candidate_manifest_digest;
use crate::lexical_windows_path;
use crate::phase_b_static_template_for_candidate;
use crate::valid_installation_key;
use redb::Database;

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

#[cfg(windows)]
#[test]
fn current_registry_rejects_omitted_watchdog_service_control_grant_member() {
    let transaction = system_registration_transaction();
    let registry = ApprovedGenerationRegistry {
        generations: vec![ApprovedGeneration {
            manifest: transaction.candidate_manifest.clone(),
            approval: test_transaction_activation_approval(
                &transaction,
                test_handle("approval:control-grant-wire"),
            ),
            active: false,
            last_known_good: false,
        }],
        service_registration_approvals: must(transaction.service_registration_approvals()),
        active_generation: None,
        last_known_good_generation: None,
        pending_activation: None,
        last_terminal_activation: None,
        ..ApprovedGenerationRegistry::new()
    };
    must(registry.validate());
    let mut value = must(serde_json::to_value(&registry));
    for approval in value["service_registration_approvals"]
        .as_array_mut()
        .unwrap_or_else(|| unreachable!())
    {
        approval
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .remove("service_control_grant");
    }
    let bytes = must(serde_json::to_vec(&value));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::CorruptRegistry { reason })
            if reason.contains("current registry wire")
    ));
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
fn v9_registry_wire_requires_explicit_migration_to_v15() {
    let mut legacy = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
    object["registry_wire_version"] = serde_json::json!({
        "major": 9,
        "minor": 0,
        "patch": 0
    });
    object.remove("active_phase_b_rebind");
    let bytes = must(serde_json::to_vec(&legacy));
    let Err(error) = decode_registry_bytes(&bytes) else {
        panic!("raw v9 registry must require explicit migration");
    };
    assert!(
        matches!(
            error,
            InstallationError::MigrationRequired { ref reason }
                if reason.contains("registry wire 9.0.0") && reason.contains("15.0.0")
        ),
        "unexpected raw v9 classification: {error:?}"
    );
}

#[test]
fn v10_registry_with_v1_rebind_requires_restage_without_adoption() {
    let transaction = registering_transaction();
    let manifest = &transaction.candidate_manifest;
    let fence = test_commit_fence(manifest);
    let prior = fence
        .phase_b_live_binding
        .as_ref()
        .unwrap_or_else(|| unreachable!());
    let mut legacy_rebind = ActivePhaseBRebind {
        intent: must(ActivePhaseBRebindIntent::new(
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            test_handle("active-phase-b-rebind-wire"),
            must(candidate_manifest_digest(manifest)),
            test_handle("a".repeat(64)),
            prior,
            test_handle("host-owner:wire"),
            test_handle("b".repeat(64)),
            test_handle("c".repeat(64)),
            prior.host_epoch_lineage.clone(),
            prior.host_epoch_sequence + 1,
            test_handle("activation-lineage:wire"),
            2,
            must(phase_b_static_template_for_candidate(manifest)),
        )),
        prepared: None,
        receipt: None,
        recovery_history: Vec::new(),
    };
    legacy_rebind.intent.wire = test_handle("eliot.host.phase-b-rebind.v1");
    legacy_rebind.intent.request_digest =
        must(active_phase_b_rebind_intent_digest(&legacy_rebind.intent));
    let mut raw_v10 = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    raw_v10["registry_wire_version"] = serde_json::json!({
        "major": 10,
        "minor": 0,
        "patch": 0
    });
    raw_v10["active_phase_b_rebind"] = must(serde_json::to_value(legacy_rebind));
    let bytes = must(serde_json::to_vec(&raw_v10));
    let error = decode_registry_bytes(&bytes)
        .expect_err("raw v10 nested v1 authority must require explicit re-stage");
    assert!(matches!(
        error,
        InstallationError::MigrationRequired { reason }
            if reason.contains("wire v10")
                && reason.contains("re-stage as v14")
                && reason.contains("never synthesized or adopted")
    ));
}

#[test]
fn v11_registry_wire_requires_explicit_migration_to_v15() {
    let mut legacy = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    legacy["registry_wire_version"] = must(serde_json::to_value(ContractVersion::new(11, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("registry wire 11.0.0") && reason.contains("15.0.0")
    ));
}

#[test]
fn v15_registry_wire_round_trips_without_synthesizing_control_grants() {
    let current = ApprovedGenerationRegistry::new();
    let bytes = must(serde_json::to_vec(&current));
    let decoded = must(decode_registry_bytes(&bytes));
    assert_eq!(decoded, current);
    assert_eq!(
        decoded.registry_wire_version(),
        ContractVersion::new(15, 0, 0)
    );
    assert!(decoded.active_phase_b_rebind().is_none());
}

#[test]
fn v12_registry_wire_requires_explicit_migration_to_v15() {
    let mut legacy = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    legacy["registry_wire_version"] = must(serde_json::to_value(ContractVersion::new(12, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("registry wire 12.0.0") && reason.contains("15.0.0")
    ));
}

#[test]
fn v13_registry_wire_requires_explicit_migration_to_v15() {
    let mut legacy = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    legacy["registry_wire_version"] = must(serde_json::to_value(ContractVersion::new(13, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("registry wire 13.0.0") && reason.contains("15.0.0")
    ));
}

#[test]
fn v14_registry_wire_requires_explicit_migration_to_v15() {
    let mut legacy = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    legacy["registry_wire_version"] = must(serde_json::to_value(ContractVersion::new(14, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("registry wire 14.0.0") && reason.contains("15.0.0")
    ));
}

#[test]
fn v15_registry_wire_rejects_omitted_mandatory_rebind_member() {
    let mut current = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    current
        .as_object_mut()
        .unwrap_or_else(|| unreachable!())
        .remove("active_phase_b_rebind");
    let bytes = must(serde_json::to_vec(&current));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::CorruptRegistry { reason })
            if reason.contains("missing mandatory fields")
    ));

    let mut nested = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    let transaction = registering_transaction();
    let manifest = &transaction.candidate_manifest;
    let fence = test_commit_fence(manifest);
    let prior = fence
        .phase_b_live_binding
        .as_ref()
        .unwrap_or_else(|| unreachable!());
    let active_rebind = ActivePhaseBRebind {
        intent: must(ActivePhaseBRebindIntent::new(
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            test_handle("active-phase-b-rebind-nested"),
            must(candidate_manifest_digest(manifest)),
            test_handle("a".repeat(64)),
            prior,
            test_handle("host-owner:nested"),
            test_handle("b".repeat(64)),
            test_handle("c".repeat(64)),
            prior.host_epoch_lineage.clone(),
            prior.host_epoch_sequence + 1,
            test_handle("activation-lineage:nested"),
            2,
            must(phase_b_static_template_for_candidate(manifest)),
        )),
        prepared: None,
        receipt: None,
        recovery_history: Vec::new(),
    };
    nested["active_phase_b_rebind"] = must(serde_json::to_value(active_rebind));
    nested["active_phase_b_rebind"]
        .as_object_mut()
        .unwrap_or_else(|| unreachable!())
        .remove("prepared");
    let bytes = must(serde_json::to_vec(&nested));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::CorruptRegistry { .. })
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

    let mut protected_snapshot = descriptor.clone();
    protected_snapshot.protected_snapshot_digest = test_handle("b".repeat(64));
    assert_ne!(
        sha256_hex(&must(protected_snapshot.unsigned_bytes())),
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

    let mut old_wire = must(serde_json::to_value(descriptor));
    old_wire
        .as_object_mut()
        .expect("runtime descriptor object")
        .remove("protected_snapshot_digest");
    assert!(serde_json::from_value::<RuntimeLaunchDescriptor>(old_wire).is_err());

    let mut uppercase_protected = descriptor.clone();
    uppercase_protected.protected_snapshot_digest = test_handle("A".repeat(64));
    assert!(uppercase_protected.validate().is_err());

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
