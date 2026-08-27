//! Architecture A2.3/A12.3/A13.7; Implementation I2.16/I2.23/I5.9/I5.22; test-oracle only/no runtime, Store or authority ownership.

#![allow(clippy::expect_used)]

use super::*;

fn v1_migration() -> CompiledMigration {
    CompiledMigration::new(
        schema::MIGRATION_ID_V1,
        schema::SCHEMA_DDL,
        SchemaGeneration::new(schema::GENERATION_V1).expect("valid"),
    )
}

fn v2_baseline_migration() -> CompiledMigration {
    CompiledMigration::new(
        schema::MIGRATION_ID_V2,
        schema::SCHEMA_DDL_V2,
        SchemaGeneration::new(schema::GENERATION_V2).expect("valid"),
    )
}

fn v1_to_v2_migration() -> CompiledMigration {
    CompiledMigration::new(
        schema::MIGRATION_ID_V1_TO_V2,
        schema::SCHEMA_MIGRATION_V1_TO_V2_DDL,
        SchemaGeneration::new(schema::GENERATION_V2).expect("valid"),
    )
}

fn genesis_fixture() -> (eliot_store_api::RequestMeta, StoreGenesisRequest) {
    let fence = StateFence::new(
        eliot_contracts::AuthorityEpoch::genesis(),
        eliot_contracts::ResourceGeneration::genesis(),
    );
    let payload = b"{\"seed\":true}".to_vec();
    let owner = RecoveryRecord {
        namespace: "owner".to_owned(),
        key: "seed".to_owned(),
        state_fence: fence.clone(),
        revision: 1,
        schema: "opaque.v1".to_owned(),
        value_digest: eliot_store_api::sha256_hex(&payload),
        payload,
    };
    let request = StoreGenesisRequest {
        contract_version: CONTRACT_VERSION,
        operation_id: OperationId::new("genesis-op").expect("operation id"),
        idempotency_key: "genesis-key".to_owned(),
        canonical_request_hash: String::new(),
        state_fence: fence.clone(),
        owner_records: vec![owner],
    }
    .with_computed_digest()
    .expect("genesis digest");
    let context = eliot_store_api::RequestMeta {
        request_id: eliot_contracts::RequestId::new("genesis-request").expect("request id"),
        session_id: None,
        task_id: None,
        product_id: eliot_contracts::ProductId::new("product").expect("product id"),
        source_id: eliot_contracts::SourceId::new("source").expect("source id"),
        state_fence: fence,
        clock: eliot_contracts::ClockReading::default(),
    };
    (context, request)
}

fn genesis_state(request: &StoreGenesisRequest, receipt: Option<WriteReceipt>) -> GenesisState {
    GenesisState {
        schema: Some(schema_meta_record(&v2_baseline_migration(), "1000")),
        fence: Some(FenceRecord {
            state_fence: request.state_fence.clone(),
            next_commit_sequence: receipt.as_ref().map_or(1, |_| 2),
            next_outbox_sequence: 1,
        }),
        owners: if receipt.is_some() {
            request.owner_records.clone()
        } else {
            Vec::new()
        },
        jobs: Vec::new(),
        receipts: receipt.into_iter().collect(),
        revision_heads: Vec::new(),
        ordering_heads: Vec::new(),
        events: Vec::new(),
        projections: Vec::new(),
        outbox: Vec::new(),
        relations: Vec::new(),
    }
}

#[test]
fn genesis_sql_guards_all_absent_state_and_advances_only_commit_sequence() {
    let (context, request) = genesis_fixture();
    let receipt = genesis_receipt(&context, &request, 1).expect("genesis receipt");
    let sql = build_genesis_sql(request.owner_records.len());
    assert!(schema::TX_GENESIS_SCHEMA_GUARD.contains("type::is_object($genesis_schema)"));
    assert!(schema::TX_GENESIS_SCHEMA_GUARD.contains("type::is_object($genesis_fence)"));
    assert!(!schema::TX_GENESIS_SCHEMA_GUARD.contains("array::len($genesis_schema"));
    assert!(!schema::TX_GENESIS_SCHEMA_GUARD.contains("array::len($genesis_fence"));
    assert!(sql.starts_with(schema::TX_GENESIS_BEGIN));
    assert!(sql.contains(schema::TX_GENESIS_SCHEMA_GUARD));
    assert!(sql.contains(schema::TX_GENESIS_EMPTY_GUARD));
    assert!(sql.contains(&schema::indexed(schema::TX_GENESIS_CREATE_OWNER, 0)));
    assert!(sql.contains(schema::TX_GENESIS_FENCE_CAS));
    assert!(sql.contains(schema::TX_GENESIS_CREATE_RECEIPT));
    assert!(sql.ends_with(schema::TX_GENESIS_COMMIT));
    let bindings = build_genesis_bindings(
        &SurrealAdapterConfig {
            endpoint: "ws://127.0.0.1:18000/rpc".to_owned(),
            namespace: "ns".to_owned(),
            database: "db".to_owned(),
            username: "user".to_owned(),
            password: secrecy::SecretString::new("password".to_owned().into()),
            provider_bind_address: "127.0.0.1:18000".to_owned(),
            installation_id: "install".to_owned(),
            installation_profile: "portable_dev".to_owned(),
            runtime_state_roots_digest: "a".repeat(64),
            provider_executable_path: "C:\\surreal.exe".to_owned(),
            provider_artifact_digest: "b".repeat(64),
            provider_arguments: Vec::new(),
            store_data_root: "C:\\data".to_owned(),
            store_work_root: "C:\\work".to_owned(),
            store_temp_root: "C:\\temp".to_owned(),
            connect_timeout_ms: 1000,
            query_timeout_ms: 1000,
            expected_provider_major: 3,
            expected_schema_generation: SchemaGeneration::v2(),
        },
        &request,
        &receipt,
    )
    .expect("genesis bindings");
    assert_eq!(bindings.get("expected_generation"), Some(&json!("2.0.0")));
    assert_eq!(
        bindings
            .get("fence")
            .and_then(Value::as_object)
            .and_then(|f| f.get("next_commit_sequence")),
        Some(&json!(2))
    );
    assert_eq!(
        bindings
            .get("fence")
            .and_then(Value::as_object)
            .and_then(|f| f.get("next_outbox_sequence")),
        Some(&json!(1))
    );
}

#[test]
fn genesis_replay_requires_exact_committed_state_and_is_immutable() {
    let (context, request) = genesis_fixture();
    let receipt = genesis_receipt(&context, &request, 1).expect("genesis receipt");
    validate_genesis_receipt_envelope(&context, &request, &receipt).expect("valid envelope");
    let replay_state = genesis_state(&request, Some(receipt.clone()));
    validate_replayed_genesis_state(&replay_state, &request).expect("exact replay state");
    assert_eq!(replay_state.receipts[0], receipt);

    let mut stale_sequence = replay_state.clone();
    stale_sequence
        .fence
        .as_mut()
        .expect("fence")
        .next_commit_sequence = 1;
    assert_eq!(
        validate_replayed_genesis_state(&stale_sequence, &request),
        Err(AdapterError::Store(StoreError::IdentityConflict))
    );

    let mut substituted = replay_state.clone();
    substituted.owners[0].key = "substituted".to_owned();
    assert_eq!(
        validate_replayed_genesis_state(&substituted, &request),
        Err(AdapterError::Store(StoreError::IdentityConflict))
    );
}

#[test]
fn genesis_fresh_state_rejects_partial_presence_and_sql_marks_unknown_outcome() {
    let (_, request) = genesis_fixture();
    let mut partial = genesis_state(&request, None);
    partial.owners = request.owner_records.clone();
    assert_eq!(
        validate_fresh_genesis_state(&partial),
        Err(AdapterError::Store(StoreError::IdentityConflict))
    );
    let stale = genesis_state(
        &request,
        Some(genesis_receipt(&genesis_fixture().0, &request, 1).expect("receipt")),
    );
    assert!(build_genesis_sql(1).contains("genesis_state_conflict"));
    assert!(build_genesis_sql(1).contains("genesis_fence_conflict"));
    assert_eq!(
        AdapterError::Store(StoreError::MissingReceiptEnvelope).into_store_error(),
        StoreError::MissingReceiptEnvelope
    );
    assert_eq!(stale.receipts.len(), 1);
}

#[test]
fn recovery_sql_is_one_transaction_with_requested_owner_bindings_and_sorted_output_helper() {
    let (_, request) = genesis_fixture();
    let recovery_request = StoreRecoveryRequest {
        contract_version: CONTRACT_VERSION,
        state_fence: request.state_fence,
        records: vec![request.owner_records[0].record_key()],
        include_receipts: true,
        include_jobs: true,
    };
    let sql = build_recovery_sql(&recovery_request);
    assert!(sql.starts_with(schema::TX_BEGIN));
    assert!(sql.contains("recovery_namespace0"));
    assert!(sql.contains(schema::READ_ALL_RECOVERY_JOBS));
    assert!(sql.contains(schema::READ_ALL_RECEIPTS));
    assert!(sql.ends_with(schema::TX_COMMIT));
    let bindings = build_recovery_bindings(&recovery_request);
    assert_eq!(bindings.get("recovery_namespace0"), Some(&json!("owner")));
    assert_eq!(bindings.get("recovery_key0"), Some(&json!("seed")));
}

#[test]
fn recovery_result_requires_exact_requested_presence_and_sorts_deterministically() {
    let (_, request) = genesis_fixture();
    let mut second = request.owner_records[0].clone();
    second.key = "a-seed".to_owned();
    second.payload = b"{\"seed\":\"a\"}".to_vec();
    second.value_digest = eliot_store_api::sha256_hex(&second.payload);
    let first_key = request.owner_records[0].record_key();
    let second_key = second.record_key();
    let snapshot = build_recovery_snapshot(
        RecoverySnapshotInput {
            schema: Some(schema_meta_record(&v2_baseline_migration(), "1000")),
            fence: Some(FenceRecord {
                state_fence: request.state_fence.clone(),
                next_commit_sequence: 2,
                next_outbox_sequence: 1,
            }),
            owner_records: vec![request.owner_records[0].clone(), second.clone()],
            job_records: Vec::new(),
            receipts: Vec::new(),
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
        },
        &SchemaGeneration::v2(),
        &request.state_fence,
        &[first_key.clone(), second_key.clone()],
    )
    .expect("recovery snapshot");
    assert_eq!(snapshot.owner_records[0].record_key(), second_key);
    assert_eq!(snapshot.owner_records[1].record_key(), first_key);

    let missing = build_recovery_snapshot(
        RecoverySnapshotInput {
            schema: Some(schema_meta_record(&v2_baseline_migration(), "1000")),
            fence: Some(FenceRecord {
                state_fence: request.state_fence.clone(),
                next_commit_sequence: 2,
                next_outbox_sequence: 1,
            }),
            owner_records: vec![request.owner_records[0].clone()],
            job_records: Vec::new(),
            receipts: Vec::new(),
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
        },
        &SchemaGeneration::v2(),
        &request.state_fence,
        &[first_key, second_key],
    );
    assert!(matches!(
        missing,
        Err(AdapterError::Store(StoreError::InvalidField {
            field: "recovery.records",
            ..
        }))
    ));
}

#[test]
fn exact_applied_identity_is_a_replay_without_provider_effect() {
    let migration = v1_migration();
    let observed = schema_meta_record(&migration, "1000");
    assert!(matches!(
        migration_preflight(Some(observed), &migration),
        Ok(MigrationPreflight::ExactReplay)
    ));
    let v2 = v2_baseline_migration();
    let observed_v2 = schema_meta_record(&v2, "1000");
    assert!(matches!(
        migration_preflight(Some(observed_v2), &v2),
        Ok(MigrationPreflight::ExactReplay)
    ));
    let fwd = v1_to_v2_migration();
    let v1_record = schema_meta_record(&v1_migration(), "1000");
    let v2_from_v1 = schema_meta_record_for_v1_to_v2(&v1_record, &fwd, "2000");
    assert!(matches!(
        migration_preflight(Some(v2_from_v1), &fwd),
        Ok(MigrationPreflight::ExactReplay)
    ));
}

#[test]
fn identity_mismatch_is_rejected_before_provider_effect() {
    let migration = v1_migration();
    let mut observed = schema_meta_record(&migration, "1000");
    observed.generation = "2.0.0".to_owned();
    observed.migrations[0].generation = "2.0.0".to_owned();
    assert!(matches!(
        migration_preflight(Some(observed), &migration),
        Err(AdapterError::Config(_) | AdapterError::PartialOutcome)
    ));
}

#[test]
fn empty_database_admits_exactly_v2_initial_plan() {
    let v2 = v2_baseline_migration();
    assert!(matches!(
        migration_preflight(None, &v2),
        Ok(MigrationPreflight::Empty)
    ));
    let v1 = v1_migration();
    assert!(matches!(
        migration_preflight(None, &v1),
        Err(AdapterError::Config(_))
    ));
    let fwd = v1_to_v2_migration();
    assert!(matches!(
        migration_preflight(None, &fwd),
        Err(AdapterError::Config(_))
    ));
}

#[test]
fn valid_exact_v1_admits_exactly_v1_to_v2() {
    let v1 = v1_migration();
    let observed = schema_meta_record(&v1, "1000");
    let fwd = v1_to_v2_migration();
    assert!(matches!(
        migration_preflight(Some(observed.clone()), &fwd),
        Ok(MigrationPreflight::V1ToV2)
    ));
    let v2_baseline = v2_baseline_migration();
    assert!(matches!(
        migration_preflight(Some(observed), &v2_baseline),
        Err(AdapterError::Config(_))
    ));
}

#[test]
fn exact_v2_yields_replay_no_mutation() {
    let v2 = v2_baseline_migration();
    let observed = schema_meta_record(&v2, "1000");
    assert!(matches!(
        migration_preflight(Some(observed), &v2),
        Ok(MigrationPreflight::ExactReplay)
    ));
}

#[test]
fn wrong_predecessor_is_rejected() {
    let v1 = v1_migration();
    let v2 = v2_baseline_migration();
    let observed_v2 = schema_meta_record(&v2, "1000");
    assert!(matches!(
        migration_preflight(Some(observed_v2), &v1),
        Err(AdapterError::Config(_))
    ));
}

#[test]
fn wrong_checksum_is_rejected() {
    let mut fwd = v1_to_v2_migration();
    fwd.checksum_sha256 = "0".repeat(64);
    let v1 = v1_migration();
    let observed = schema_meta_record(&v1, "1000");
    assert!(matches!(
        migration_preflight(Some(observed), &fwd),
        Err(AdapterError::Config(_))
    ));
}

#[test]
fn wrong_migration_id_is_rejected() {
    let mut fwd = v1_to_v2_migration();
    fwd.migration_id = "wrong.id".to_owned();
    let v1 = v1_migration();
    let observed = schema_meta_record(&v1, "1000");
    assert!(matches!(
        migration_preflight(Some(observed), &fwd),
        Err(AdapterError::Config(_))
    ));
}

#[test]
fn wrong_generation_is_rejected() {
    let wrong = CompiledMigration::new(
        schema::MIGRATION_ID_V2,
        schema::SCHEMA_DDL_V2,
        SchemaGeneration::new("9.9.9").expect("valid"),
    );
    assert!(matches!(
        migration_preflight(None, &wrong),
        Err(AdapterError::Config(_))
    ));
    let v1 = v1_migration();
    let observed = schema_meta_record(&v1, "1000");
    let mut fwd = v1_to_v2_migration();
    fwd.generation_after = SchemaGeneration::new("9.9.9").expect("valid");
    assert!(matches!(
        migration_preflight(Some(observed), &fwd),
        Err(AdapterError::Config(_))
    ));
}

#[test]
fn wrong_bridge_range_is_rejected() {
    let v2 = v2_baseline_migration();
    let mut observed = schema_meta_record(&v2, "1000");
    observed.compatible_bridge_range = "wrong.adapter".to_owned();
    assert!(matches!(
        migration_preflight(Some(observed), &v2),
        Err(AdapterError::Config(_))
    ));
}

#[test]
fn partial_metadata_is_fail_closed() {
    let v2 = v2_baseline_migration();
    let mut observed = schema_meta_record(&v2, "1000");
    observed.migrations.clear();
    assert_eq!(
        migration_preflight(Some(observed), &v2),
        Err(AdapterError::PartialOutcome)
    );
    let mut observed2 = schema_meta_record(&v2, "1000");
    observed2.migration_state = "APPLYING".to_owned();
    assert_eq!(
        migration_preflight(Some(observed2), &v2),
        Err(AdapterError::PartialOutcome)
    );
    let mut observed3 = schema_meta_record(&v2, "1000");
    observed3.migrations[0].migration_id = String::new();
    assert_eq!(
        migration_preflight(Some(observed3), &v2),
        Err(AdapterError::PartialOutcome)
    );
}

#[test]
fn unknown_metadata_is_fail_closed() {
    let v2 = v2_baseline_migration();
    let mut observed = schema_meta_record(&v2, "1000");
    observed.generation = "9.9.9".to_owned();
    assert_eq!(
        migration_preflight(Some(observed), &v2),
        Err(AdapterError::PartialOutcome)
    );
    let mut observed2 = schema_meta_record(&v2, "1000");
    observed2.migrations.push(SchemaMigrationIdentity {
        migration_id: "extra".to_owned(),
        migration_checksum_sha256: "a".repeat(64),
        generation: "3.0.0".to_owned(),
    });
    assert_eq!(
        migration_preflight(Some(observed2), &v2),
        Err(AdapterError::PartialOutcome)
    );
}

#[test]
fn bridge_range_fence_and_state_are_fenced() {
    let v1 = v1_migration();
    let observed = schema_meta_record(&v1, "1000");
    let fwd = v1_to_v2_migration();
    let ok = migration_preflight(Some(observed.clone()), &fwd).expect("v1 to v2");
    assert_eq!(ok, MigrationPreflight::V1ToV2);
    let mut wrong_fence = observed;
    wrong_fence.compatible_bridge_range = "other".to_owned();
    assert!(matches!(
        migration_preflight(Some(wrong_fence), &fwd),
        Err(AdapterError::Config(_))
    ));
}

#[test]
fn post_read_requires_the_complete_durable_identity() {
    let migration = v1_migration();
    let mut observed = schema_meta_record(&migration, "1000");
    observed.migrations.clear();
    assert_eq!(
        migration_preflight(Some(observed), &migration),
        Err(AdapterError::PartialOutcome)
    );
}

#[test]
fn transitional_metadata_is_fail_closed() {
    let migration = v1_migration();
    let mut observed = schema_meta_record(&migration, "1000");
    observed.migration_state = "APPLYING".to_owned();
    assert_eq!(
        migration_preflight(Some(observed), &migration),
        Err(AdapterError::PartialOutcome)
    );
}

#[test]
fn history_append_preserves_v1_and_appends_v2() {
    let v2 = v2_baseline_migration();
    let record = schema_meta_record(&v2, "1000");
    assert_eq!(record.migrations.len(), 2);
    assert_eq!(record.migrations[0].migration_id, schema::MIGRATION_ID_V1);
    assert_eq!(record.migrations[0].generation, schema::GENERATION_V1);
    assert_eq!(record.migrations[1].migration_id, schema::MIGRATION_ID_V2);
    assert_eq!(record.generation, schema::GENERATION_V2);
    assert_eq!(record.migration_id, schema::MIGRATION_ID_V2);
    let v1 = v1_migration();
    let v1_record = schema_meta_record(&v1, "1000");
    let fwd = v1_to_v2_migration();
    let v1_to_v2_record = schema_meta_record_for_v1_to_v2(&v1_record, &fwd, "2000");
    assert_eq!(v1_to_v2_record.migrations.len(), 2);
    assert_eq!(
        v1_to_v2_record.migrations[0].migration_id,
        schema::MIGRATION_ID_V1
    );
    assert_eq!(
        v1_to_v2_record.migrations[1].migration_id,
        schema::MIGRATION_ID_V1_TO_V2
    );
    assert_eq!(v1_to_v2_record.generation, schema::GENERATION_V2);
}

#[test]
fn v1_ddl_bytes_are_immutable_and_v2_is_additive() {
    assert!(!schema::SCHEMA_DDL.contains("recovery_owner"));
    assert!(schema::SCHEMA_DDL_V2.contains(schema::SCHEMA_DDL.trim()));
    assert!(schema::SCHEMA_DDL_V2.contains("recovery_owner"));
    assert!(schema::SCHEMA_DDL_V2.contains("recovery_job"));
    assert!(schema::SCHEMA_MIGRATION_V1_TO_V2_DDL.contains("recovery_owner"));
    assert!(!schema::SCHEMA_MIGRATION_V1_TO_V2_DDL.contains("DEFINE TABLE schema_meta"));
}

#[test]
fn transaction_has_no_destructive_statements_and_no_fence_rewrite_for_forward() {
    for ddl in [
        schema::SCHEMA_DDL,
        schema::SCHEMA_DDL_V2,
        schema::SCHEMA_MIGRATION_V1_TO_V2_DDL,
    ] {
        let lower = ddl.to_ascii_lowercase();
        assert!(!lower.contains("drop "));
        assert!(!lower.contains("delete "));
        assert!(!lower.contains("remove "));
        assert!(!lower.contains("reset"));
    }
    let v1 = v1_migration();
    let v1_record = schema_meta_record(&v1, "1000");
    let fwd = v1_to_v2_migration();
    let record = schema_meta_record_for_v1_to_v2(&v1_record, &fwd, "2000");
    assert_eq!(record.migrations.len(), 2);
    let forward_sql = build_forward_sql();
    assert!(!forward_sql.to_ascii_lowercase().contains("drop "));
    assert!(!forward_sql.contains(schema::TX_CREATE_FENCE));
    assert!(!forward_sql.contains(schema::TX_UPSERT_FENCE));
    assert!(forward_sql.contains(schema::TX_GUARD_FENCE));
    assert!(forward_sql.contains(schema::TX_GUARD_SCHEMA_PREDECESSOR));
    assert!(forward_sql.contains(schema::TX_UPDATE_SCHEMA_META_CAS));
    assert!(forward_sql.contains(schema::RECOVERY_TABLES_DDL.trim()));
    let fence = FenceRecord {
        state_fence: StateFence::new(
            eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
            eliot_contracts::ResourceGeneration::new(1).expect("gen"),
        ),
        next_commit_sequence: 7,
        next_outbox_sequence: 9,
    };
    let bindings = build_forward_bindings(&v1_record, &fence, &record);
    assert_eq!(
        bindings.get("expected_state_fence"),
        Some(&json!(fence.state_fence))
    );
    assert_eq!(
        bindings.get("expected_commit_sequence"),
        Some(&json!(7_u64))
    );
    assert!(is_guard_conflict("schema_predecessor_mismatch"));
    assert!(is_guard_conflict("schema_fence_guard_mismatch"));
    assert!(!is_guard_conflict("other_error"));
}

#[test]
fn forward_sql_contains_predecessor_cas_and_fence_guard_no_data_mutation() {
    let sql = build_forward_sql();
    assert!(sql.starts_with(schema::TX_BEGIN));
    assert!(sql.ends_with(schema::TX_COMMIT));
    assert!(sql.contains(schema::TX_GUARD_FENCE));
    assert!(sql.contains(schema::TX_GUARD_SCHEMA_PREDECESSOR));
    assert!(sql.contains(schema::TX_UPDATE_SCHEMA_META_CAS));
    assert!(!sql.contains(schema::TX_CREATE_FENCE));
    assert!(!sql.contains(schema::TX_UPSERT_FENCE));
    assert!(!sql.contains(schema::TX_CREATE_RECEIPT));
    assert!(!sql.contains(schema::TX_CREATE_REVISION));
    assert!(!sql.contains(schema::TX_UPSERT_REVISION));
    let bindings_keys = schema::forward_migration_expected_bindings();
    assert!(bindings_keys.contains(&"expected_state_fence"));
    assert!(bindings_keys.contains(&"expected_generation"));
    for key in bindings_keys {
        assert!(sql.contains(key) || key.contains("schema_meta"));
    }
}

#[test]
fn wrong_state_fence_is_rejected_by_forward_guard() {
    let v1 = v1_migration();
    let existing = schema_meta_record(&v1, "1000");
    let fence_ok = FenceRecord {
        state_fence: StateFence::new(
            eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
            eliot_contracts::ResourceGeneration::new(1).expect("gen"),
        ),
        next_commit_sequence: 1,
        next_outbox_sequence: 1,
    };
    let fence_bad = FenceRecord {
        state_fence: StateFence::new(
            eliot_contracts::AuthorityEpoch::new(2).expect("epoch"),
            eliot_contracts::ResourceGeneration::new(1).expect("gen"),
        ),
        next_commit_sequence: 1,
        next_outbox_sequence: 1,
    };
    let new_record = schema_meta_record_for_v1_to_v2(&existing, &v1_to_v2_migration(), "2000");
    let ok_bind = build_forward_bindings(&existing, &fence_ok, &new_record);
    let bad_bind = build_forward_bindings(&existing, &fence_bad, &new_record);
    assert_ne!(
        ok_bind.get("expected_state_fence"),
        bad_bind.get("expected_state_fence")
    );
    assert!(is_guard_conflict("schema_fence_guard_mismatch"));
    let sql = build_forward_sql();
    assert!(sql.contains("schema_fence_guard_mismatch"));
}

#[test]
fn changed_sequence_is_rejected_by_forward_guard() {
    let v1 = v1_migration();
    let existing = schema_meta_record(&v1, "1000");
    let fence_ok = FenceRecord {
        state_fence: StateFence::new(
            eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
            eliot_contracts::ResourceGeneration::new(1).expect("gen"),
        ),
        next_commit_sequence: 1,
        next_outbox_sequence: 1,
    };
    let fence_changed = FenceRecord {
        state_fence: fence_ok.state_fence.clone(),
        next_commit_sequence: 99,
        next_outbox_sequence: 1,
    };
    let new_record = schema_meta_record_for_v1_to_v2(&existing, &v1_to_v2_migration(), "2000");
    let ok_bind = build_forward_bindings(&existing, &fence_ok, &new_record);
    let changed_bind = build_forward_bindings(&existing, &fence_changed, &new_record);
    assert_ne!(
        ok_bind.get("expected_commit_sequence"),
        changed_bind.get("expected_commit_sequence")
    );
    let fence_changed2 = FenceRecord {
        state_fence: fence_ok.state_fence.clone(),
        next_commit_sequence: 1,
        next_outbox_sequence: 99,
    };
    let changed_bind2 = build_forward_bindings(&existing, &fence_changed2, &new_record);
    assert_ne!(
        ok_bind.get("expected_outbox_sequence"),
        changed_bind2.get("expected_outbox_sequence")
    );
    assert!(is_guard_conflict("schema_fence_guard_mismatch"));
}

#[test]
fn unknown_top_level_field_fails_deserialization() {
    let v2 = v2_baseline_migration();
    let record = schema_meta_record(&v2, "1000");
    let mut value = serde_json::to_value(&record).expect("serialize");
    if let Value::Object(map) = &mut value {
        map.insert("extra_top_level".to_owned(), json!("boom"));
    }
    let res: Result<SchemaMetaRecord, _> = serde_json::from_value(value);
    assert!(
        res.is_err(),
        "deny_unknown_fields must reject extra top-level"
    );
}

#[test]
fn unknown_history_entry_field_fails_deserialization() {
    let v2 = v2_baseline_migration();
    let record = schema_meta_record(&v2, "1000");
    let mut value = serde_json::to_value(&record).expect("serialize");
    if let Value::Object(map) = &mut value
        && let Some(Value::Array(arr)) = map.get_mut("migrations")
        && let Some(Value::Object(entry)) = arr.get_mut(0)
    {
        entry.insert("extra_entry_field".to_owned(), json!("boom"));
    }
    let res: Result<SchemaMetaRecord, _> = serde_json::from_value(value);
    assert!(
        res.is_err(),
        "deny_unknown_fields must reject extra history entry"
    );
}

#[test]
fn schema_and_fence_records_round_trip_as_json() {
    let migration = v2_baseline_migration();
    let schema = schema_meta_record(&migration, "1000");
    let fence = FenceRecord {
        state_fence: StateFence::new(
            eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
            eliot_contracts::ResourceGeneration::new(1).expect("generation"),
        ),
        next_commit_sequence: 2,
        next_outbox_sequence: 3,
    };
    let schema_json = serde_json::to_vec(&schema).expect("schema serialize");
    let fence_json = serde_json::to_vec(&fence).expect("fence serialize");
    assert_eq!(
        serde_json::from_slice::<SchemaMetaRecord>(&schema_json).expect("schema deserialize"),
        schema
    );
    assert_eq!(
        serde_json::from_slice::<FenceRecord>(&fence_json).expect("fence deserialize"),
        fence
    );
}

#[test]
fn unknown_fence_record_field_fails_deserialization() {
    let fence = FenceRecord {
        state_fence: StateFence::new(
            eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
            eliot_contracts::ResourceGeneration::new(1).expect("generation"),
        ),
        next_commit_sequence: 1,
        next_outbox_sequence: 1,
    };
    for extra_field in ["extra_fence_field", "id"] {
        let mut value = serde_json::to_value(&fence).expect("serialize");
        if let Value::Object(map) = &mut value {
            map.insert(extra_field.to_owned(), json!("boom"));
        }
        let result: Result<FenceRecord, _> = serde_json::from_value(value);
        assert!(
            result.is_err(),
            "deny_unknown_fields must reject extra fence field {extra_field}"
        );
    }
}

#[test]
fn predecessor_cas_binds_every_predecessor_field_and_history_value() {
    let v1 = v1_migration();
    let existing = schema_meta_record(&v1, "1000");
    let fence = FenceRecord {
        state_fence: StateFence::new(
            eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
            eliot_contracts::ResourceGeneration::new(1).expect("generation"),
        ),
        next_commit_sequence: 1,
        next_outbox_sequence: 1,
    };
    let next = schema_meta_record_for_v1_to_v2(&existing, &v1_to_v2_migration(), "2000");
    let bindings = build_forward_bindings(&existing, &fence, &next);
    for key in schema::forward_migration_expected_bindings() {
        assert!(bindings.contains_key(key), "missing binding {key}");
    }
    assert_eq!(bindings.get("expected_updated_at"), Some(&json!("1000")));

    let mut changed = existing.clone();
    changed.updated_at = "1001".to_owned();
    let changed_bindings = build_forward_bindings(&changed, &fence, &next);
    assert_ne!(
        bindings.get("expected_updated_at"),
        changed_bindings.get("expected_updated_at")
    );
    let mut changed_history = existing.clone();
    changed_history.migrations[0].migration_id = "tampered".to_owned();
    let changed_history_bindings = build_forward_bindings(&changed_history, &fence, &next);
    assert_ne!(
        bindings.get("expected_migration_0_id"),
        changed_history_bindings.get("expected_migration_0_id")
    );
    let sql = build_forward_sql();
    for key in [
        "expected_bridge_range",
        "expected_migration_state",
        "expected_migrations_len",
        "expected_migration_0_id",
        "expected_migration_0_checksum",
        "expected_migration_0_generation",
        "expected_updated_at",
    ] {
        assert!(sql.contains(key), "CAS SQL missing {key}");
    }
}

#[test]
fn genesis_and_mixed_head_presence_choose_create_or_update_per_head() {
    assert_eq!(
        revision_write_template(true, false),
        schema::TX_CREATE_REVISION
    );
    assert_eq!(
        revision_write_template(false, false),
        schema::TX_CREATE_REVISION
    );
    assert_eq!(
        revision_write_template(false, true),
        schema::TX_UPSERT_REVISION
    );
    assert_eq!(
        ordering_write_template(true, false),
        schema::TX_CREATE_ORDERING
    );
    assert_eq!(
        ordering_write_template(false, false),
        schema::TX_CREATE_ORDERING
    );
    assert_eq!(
        ordering_write_template(false, true),
        schema::TX_UPSERT_ORDERING
    );
}

#[test]
fn validation_query_keeps_schema_fence_heads_and_commit_in_one_transaction() {
    assert!(READ_VALIDATION_SNAPSHOT.starts_with("BEGIN TRANSACTION;"));
    assert!(READ_VALIDATION_SNAPSHOT.contains("schema_meta:current"));
    assert!(READ_VALIDATION_SNAPSHOT.contains("canonical_fence:current"));
    assert!(READ_VALIDATION_SNAPSHOT.contains("SELECT VALUE body FROM revision_head"));
    assert!(READ_VALIDATION_SNAPSHOT.ends_with("COMMIT TRANSACTION;"));
}

#[test]
fn canonical_fence_record_reads_use_explicit_flat_projection() {
    let (_, request) = genesis_fixture();
    let recovery_request = StoreRecoveryRequest {
        contract_version: CONTRACT_VERSION,
        state_fence: request.state_fence,
        records: vec![request.owner_records[0].record_key()],
        include_receipts: true,
        include_jobs: true,
    };
    let expected_projection = "SELECT VALUE { state_fence: state_fence, next_commit_sequence: next_commit_sequence, next_outbox_sequence: next_outbox_sequence } FROM ONLY canonical_fence:current";
    let recovery_sql = build_recovery_sql(&recovery_request);
    for (name, query) in [
        ("validation", READ_VALIDATION_SNAPSHOT),
        ("read_fence", schema::READ_FENCE),
        ("genesis_read", schema::READ_GENESIS_SCHEMA_AND_STATE),
        ("genesis_guard", schema::TX_GENESIS_SCHEMA_GUARD),
        ("recovery", recovery_sql.as_str()),
    ] {
        assert!(query.contains(expected_projection), "{name} projection");
        assert!(
            !query.contains("SELECT VALUE body FROM ONLY canonical_fence:current"),
            "{name} must not read the legacy body field"
        );
        assert!(
            !query.contains("SELECT * FROM ONLY canonical_fence:current"),
            "{name} must not admit the SurrealDB id field"
        );
    }
}

#[test]
fn validation_result_indexes_admit_a_fresh_empty_canonical_store() {
    let migration = v2_baseline_migration();
    let fence = StateFence::new(
        eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
        eliot_contracts::ResourceGeneration::new(1).expect("generation"),
    );
    let snapshot = build_validation_snapshot(
        Some(schema_meta_record(&migration, "1000")),
        Some(FenceRecord {
            state_fence: fence,
            next_commit_sequence: 1,
            next_outbox_sequence: 1,
        }),
        Vec::new(),
        &migration.generation_after,
        1_000,
        Value::Null,
    )
    .expect("fresh snapshot");
    assert!(snapshot.revision_heads.is_empty());
    assert_eq!(snapshot.validation_revision, 1);
}

#[test]
fn validation_rejects_missing_or_malformed_fence() {
    let migration = v2_baseline_migration();
    let missing = build_validation_snapshot(
        Some(schema_meta_record(&migration, "1000")),
        None,
        Vec::new(),
        &migration.generation_after,
        1_000,
        Value::Null,
    );
    assert_eq!(missing, Err(AdapterError::Store(StoreError::Unavailable)));

    let malformed = build_validation_snapshot(
        Some(schema_meta_record(&migration, "1000")),
        Some(FenceRecord {
            state_fence: StateFence::new(
                eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
                eliot_contracts::ResourceGeneration::new(1).expect("generation"),
            ),
            next_commit_sequence: 0,
            next_outbox_sequence: 1,
        }),
        Vec::new(),
        &migration.generation_after,
        1_000,
        Value::Null,
    );
    assert_eq!(malformed, Err(AdapterError::PartialOutcome));
}

#[test]
fn readiness_oracle_observed_1_0_0_is_migration_required_and_2_0_0_is_ready() {
    let expected = SchemaGeneration::v2();
    let observed_v1 = Some(schema::GENERATION_V1.to_owned());
    let observed_v2 = Some(schema::GENERATION_V2.to_owned());
    assert!(matches!(
        readiness_from_observation(observed_v1, &expected),
        SemanticReadiness::MigrationRequired { .. }
    ));
    assert!(matches!(
        readiness_from_observation(observed_v2, &expected),
        SemanticReadiness::Ready { .. }
    ));
    assert!(matches!(
        readiness_from_observation(None, &expected),
        SemanticReadiness::MigrationRequired { .. }
    ));
}

#[test]
fn ready_v2_requires_a_valid_canonical_fence() {
    let expected = SchemaGeneration::v2();
    let ready = readiness_from_observation(Some(schema::GENERATION_V2.to_owned()), &expected);
    assert!(matches!(ready, SemanticReadiness::Ready { .. }));
    assert!(matches!(
        readiness_with_fence(ready.clone(), None, &expected),
        Ok(SemanticReadiness::MigrationRequired { observed: None, .. })
    ));

    let malformed = FenceRecord {
        state_fence: StateFence::new(
            eliot_contracts::AuthorityEpoch::new(1).expect("epoch"),
            eliot_contracts::ResourceGeneration::new(1).expect("generation"),
        ),
        next_commit_sequence: 0,
        next_outbox_sequence: 1,
    };
    assert_eq!(
        readiness_with_fence(ready, Some(malformed), &expected),
        Err(AdapterError::PartialOutcome)
    );
}
