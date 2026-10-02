use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use eliot_contracts::{
    AuthorityEpoch, EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex,
};
use eliot_platform::SecretReference;
use eliot_receipts::{ProofCeiling, ReceiptCore, ReceiptDisposition, ReceiptEnvelope};
use eliot_runtime_contracts::{
    Ed25519SupervisionLeaseSigner, GenerationCutoverRecord as RuntimeGenerationCutoverRecord,
    GenerationCutoverState, LeaseState, RegisteredActivityWakePolicy, SignedSupervisionLease,
    SupervisionGenerationBinding, SupervisionLeaseActiveStateBinding,
    SupervisionLeasePredecessorProof, SupervisionLeaseSigner, SupervisionLeaseTerminalDisposition,
    SupervisionLeaseVerificationContext, SupervisionLeaseVerifier, SupervisionObservationScope,
    SupervisionTrustAnchor, VerifiedSupervisionLease, VerifiedSupervisionLeaseTerminalTransition,
};
use eliot_security_contracts::{InstructionTaint, PrivacyClass};
use redb::{ReadableDatabase, ReadableTable};
use serde_json::{Value, json};

use crate::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Canonical lineage fixtures (Implements #64): every contour lineage that can
// reach an `EpochId` wire shape (receipt authority, fence canonical JSON) must
// name a canonical UUID lineage, because `EpochLineageId` validation rejects
// display-name labels at deserialization. Contours that never cross that
// boundary keep their display names.
const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const TEST_LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";
const TEST_LINEAGE_C: &str = "550e8400-e29b-41d4-a716-446655440002";

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
        std::num::NonZeroU64::new(sequence).expect("sequence"),
    )
    .expect("epoch")
}

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);

/// Provider for operational-surface projection tests (appendix P4).
///
/// Delegates every shared check to the single [`crate::test_support::KernelRouteEvidence`]
/// binding instead of redefining it: only recovery-inbox import diverges, which
/// the Kernel route never authenticates by design but the surface projection
/// must stage as data. Receipt disposition on those staged items still runs
/// through the shared structural receipt check.
struct SurfaceProjectionEvidence;

impl CanonicalEvidenceProvider for SurfaceProjectionEvidence {
    fn verify_ordering_heads(&self, scopes: &[ScopeReservationRequest]) -> Result<(), OrsError> {
        crate::test_support::KernelRouteEvidence.verify_ordering_heads(scopes)
    }

    fn verify_reconciliation(
        &self,
        token: &WriterReservationToken,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        crate::test_support::KernelRouteEvidence.verify_reconciliation(token, reconciliation)
    }

    fn verify_receipt(&self, receipt: &ReceiptEnvelope) -> Result<(), OrsError> {
        crate::test_support::KernelRouteEvidence.verify_receipt(receipt)
    }

    fn verify_recovery_inbox(&self, _item: &RecoveryInboxItem) -> Result<(), OrsError> {
        Ok(())
    }
}

struct RejectReadbackEvidence;

impl CanonicalEvidenceProvider for RejectReadbackEvidence {
    fn verify_ordering_heads(&self, _scopes: &[ScopeReservationRequest]) -> Result<(), OrsError> {
        Ok(())
    }

    fn verify_reconciliation(
        &self,
        _token: &WriterReservationToken,
        _reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "fixture rejected unauthenticated readback".to_owned(),
        ))
    }

    fn verify_receipt(&self, _receipt: &ReceiptEnvelope) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "fixture rejected unauthenticated receipt".to_owned(),
        ))
    }

    fn verify_recovery_inbox(&self, _item: &RecoveryInboxItem) -> Result<(), OrsError> {
        Ok(())
    }
}

struct GenesisHeadEvidence;

impl CanonicalEvidenceProvider for GenesisHeadEvidence {
    fn verify_ordering_heads(&self, scopes: &[ScopeReservationRequest]) -> Result<(), OrsError> {
        if scopes.iter().all(|scope| {
            scope.expected_head.sequence == 0
                && scope.expected_head.head_sha256 == "00".repeat(32)
                && scope.expected_head.revision_head.as_deref() == Some("revision-0")
        }) {
            Ok(())
        } else {
            Err(OrsError::CanonicalEvidence(
                "canonical genesis head mismatch".to_owned(),
            ))
        }
    }

    fn verify_reconciliation(
        &self,
        _token: &WriterReservationToken,
        _reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        Ok(())
    }

    fn verify_receipt(&self, _receipt: &ReceiptEnvelope) -> Result<(), OrsError> {
        Ok(())
    }

    fn verify_recovery_inbox(&self, _item: &RecoveryInboxItem) -> Result<(), OrsError> {
        Ok(())
    }
}

fn coordinator_with_evidence(
    path: &PathBuf,
    evidence: Arc<dyn CanonicalEvidenceProvider>,
) -> Result<OrsCoordinator, OrsError> {
    Ok(OrsCoordinator::new(RedbRecoveryStore::open_with_evidence(
        path, evidence,
    )?))
}

fn coordinator(path: &PathBuf) -> Result<OrsCoordinator, OrsError> {
    coordinator_with_evidence(path, Arc::new(crate::test_support::KernelRouteEvidence))
}

fn database_path(label: &str) -> PathBuf {
    let serial = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "eliot-ors-{label}-{}-{serial}.redb",
        std::process::id()
    ))
}

fn cleanup(path: &PathBuf) {
    let _ignored = std::fs::remove_file(path);
}

fn activation_result_record(
    ticket_id: &str,
    result_sha256: &str,
    ticket_payload: &str,
    result_payload: &str,
    phase: ActivationResultRetentionPhase,
) -> ActivationResultRetentionRecord {
    ActivationResultRetentionRecord {
        ticket_id: ticket_id.to_owned(),
        ticket_sha256: "a".repeat(64),
        ticket_payload: ticket_payload.to_owned(),
        result_sha256: result_sha256.to_owned(),
        result_payload: result_payload.to_owned(),
        connection_id: "connection-1".to_owned(),
        state_fence: "state-fence-1".to_owned(),
        phase,
        retention_order: 0,
    }
}

fn activation_lifecycle_record(
    record: &ActivationResultRetentionRecord,
) -> ActivationLifecycleRecord {
    ActivationLifecycleRecord {
        ticket_id: record.ticket_id.clone(),
        ticket_sha256: record.ticket_sha256.clone(),
        ticket_payload: record.ticket_payload.clone(),
        activation_request_id: format!("request-{}", record.ticket_id),
        activation_request_sha256: "c".repeat(64),
        connection_id: record.connection_id.clone(),
        state_fence: record.state_fence.clone(),
        kernel_deadline_unix_ms: 10_000,
        cancellation_id: format!("cancel-{}", record.ticket_id),
        state: ActivationLifecycleState::Pending,
        lifecycle_order: 0,
        result_sha256: None,
        claim_owner: None,
        claim_expires_at_unix_ms: None,
        successor_of: None,
        successor_ticket_id: None,
        terminal_reason: None,
    }
}

fn retain_activation_result(
    store: &RedbRecoveryStore,
    record: &ActivationResultRetentionRecord,
) -> Result<ActivationResultRetentionRecord, OrsError> {
    if store
        .load_all_activation_results()?
        .into_iter()
        .any(|existing| existing.ticket_id == record.ticket_id)
    {
        return store.commit_activation_result(record, "eliotd", None, 2);
    }
    store.stage_activation_ticket(&activation_lifecycle_record(record), 1)?;
    store.claim_activation_ticket(&record.ticket_id, "eliotd", 2, 3)?;
    store.commit_activation_result(record, "eliotd", None, 2)
}

#[test]
fn activation_result_retention_round_trips_replays_conflicts_and_reopens() -> TestResult {
    let path = database_path("activation-result-retention-round-trip");
    let store = RedbRecoveryStore::open(&path)?;
    let record = activation_result_record(
        "ticket-1",
        &"b".repeat(64),
        "opaque-ticket-payload",
        "opaque-result-payload",
        ActivationResultRetentionPhase::AcceptedTerminal,
    );
    let retained = retain_activation_result(&store, &record)?;
    assert!(retained.retention_order > 0);
    assert_eq!(retain_activation_result(&store, &record)?, retained);
    let mut changed_connection = record.clone();
    changed_connection.connection_id = "connection-2".to_owned();
    assert!(matches!(
        retain_activation_result(&store, &changed_connection),
        Err(OrsError::ActivationResultRetentionIdentityConflict { .. }
            | OrsError::ActivationLifecycleIdentityConflict { .. })
    ));
    let mut changed_fence = record.clone();
    changed_fence.state_fence = "state-fence-2".to_owned();
    assert!(matches!(
        retain_activation_result(&store, &changed_fence),
        Err(OrsError::ActivationResultRetentionIdentityConflict { .. }
            | OrsError::ActivationLifecycleIdentityConflict { .. })
    ));
    assert_eq!(
        store.load_activation_result("ticket-1", &"b".repeat(64))?,
        Some(retained.clone())
    );
    assert_eq!(store.load_all_activation_results()?, vec![retained.clone()]);
    assert!(matches!(
        store.load_activation_result("ticket-1", &"c".repeat(64)),
        Err(OrsError::ActivationResultRetentionIdentityConflict { .. }
            | OrsError::ActivationLifecycleIdentityConflict { .. })
    ));

    let mut conflict = record.clone();
    conflict.result_payload = "changed-result".to_owned();
    assert!(matches!(
        retain_activation_result(&store, &conflict),
        Err(OrsError::ActivationResultRetentionIdentityConflict { .. }
            | OrsError::ActivationLifecycleIdentityConflict { .. })
    ));
    drop(store);

    let reopened = RedbRecoveryStore::open(&path)?;
    assert_eq!(
        reopened.load_activation_result("ticket-1", &"b".repeat(64))?,
        Some(retained)
    );
    cleanup(&path);
    Ok(())
}

#[test]
fn activation_result_retention_defaults_unpersisted_order_but_rejects_zero_persisted_order()
-> TestResult {
    let record = activation_result_record(
        "ticket-default-order",
        &"b".repeat(64),
        "opaque-ticket-payload",
        "opaque-result-payload",
        ActivationResultRetentionPhase::AcceptedTerminal,
    );
    let mut serialized = serde_json::to_value(&record)?;
    let object = serialized
        .as_object_mut()
        .ok_or_else(|| std::io::Error::other("retention record is not an object"))?;
    object.remove("retention_order");
    let restored: ActivationResultRetentionRecord = serde_json::from_value(serialized)?;
    assert_eq!(restored, record);

    let path = database_path("activation-result-retention-zero-order");
    let store = RedbRecoveryStore::open(&path)?;
    drop(store);
    let database = redb::Database::create(&path)?;
    let write = database.begin_write()?;
    let table_definition: redb::TableDefinition<&str, &str> =
        redb::TableDefinition::new("ors_agent_activation_results_v1");
    let mut table = write.open_table(table_definition)?;
    let mut persisted = serde_json::to_value(&record)?;
    persisted["retention_order"] = json!(0);
    table.insert(
        "ticket-default-order",
        serde_json::to_string(&persisted)?.as_str(),
    )?;
    drop(table);
    write.commit()?;
    drop(database);

    assert!(matches!(
        RedbRecoveryStore::open(&path),
        Err(OrsError::IntegrityProblem { .. })
    ));
    cleanup(&path);
    Ok(())
}

#[test]
fn activation_result_retention_rejects_corruption_on_reopen() -> TestResult {
    let path = database_path("activation-result-retention-corrupt");
    let store = RedbRecoveryStore::open(&path)?;
    drop(store);

    let database = redb::Database::create(&path)?;
    let write = database.begin_write()?;
    let table_definition: redb::TableDefinition<&str, &str> =
        redb::TableDefinition::new("ors_agent_activation_results_v1");
    let mut table = write.open_table(table_definition)?;
    table.insert("ticket-corrupt", "{\"ticket_id\":\"ticket-corrupt\"}")?;
    drop(table);
    write.commit()?;
    drop(database);

    assert!(matches!(
        RedbRecoveryStore::open(&path),
        Err(OrsError::IntegrityProblem { .. })
    ));
    cleanup(&path);
    Ok(())
}

#[test]
fn activation_result_retention_prunes_count_and_payload_bounds() -> TestResult {
    let path = database_path("activation-result-retention-prune");
    let store = RedbRecoveryStore::open(&path)?;
    let payload = "p".repeat(64 * 1024);
    for index in 0..65 {
        let record = activation_result_record(
            &format!("ticket-{index}"),
            &format!("{index:064x}"),
            &payload[..32 * 1024],
            &payload[..32 * 1024],
            ActivationResultRetentionPhase::AcceptedTerminal,
        );
        retain_activation_result(&store, &record)?;
    }
    assert!(
        store
            .load_activation_result("ticket-0", &format!("{0:064x}", 0))?
            .is_none(),
        "oldest record must be pruned"
    );
    assert!(
        store
            .load_activation_result("ticket-64", &format!("{:064x}", 64))?
            .is_some()
    );
    assert_eq!(store.prune_activation_results()?, 0);
    drop(store);

    let reopened = RedbRecoveryStore::open(&path)?;
    assert!(
        reopened
            .load_activation_result("ticket-0", &format!("{:064x}", 0))?
            .is_none()
    );
    assert!(
        reopened
            .load_activation_result("ticket-64", &format!("{:064x}", 64))?
            .is_some()
    );
    cleanup(&path);
    Ok(())
}

#[test]
fn store_rebind_commit_order_is_durable_and_idempotent() -> TestResult {
    let path = database_path("store-rebind-order");
    let store = RedbRecoveryStore::open(&path)?;
    let make_record = |operation_id: &str,
                       request_digest: &str,
                       state: StoreRebindReplayState|
     -> Result<StoreRebindReplayRecord, OrsError> {
        Ok(StoreRebindReplayRecord {
            operation_id: OperationIdentity::new(operation_id)?,
            request_digest: request_digest.to_owned(),
            candidate_binding_digest: "a".repeat(64),
            store_fence: "b".repeat(64),
            requirement_digest: "c".repeat(64),
            process_id: 42,
            process_start_time_100ns: 7,
            process_image_path: r"C:\eliot\store.exe".to_owned(),
            job_name: r"Local\Eliot-Store-order".to_owned(),
            generation: 1,
            authority_epoch: 1,
            state,
            receipt: (state == StoreRebindReplayState::Committed)
                .then(|| request_digest.to_owned()),
            commit_order: 0,
        })
    };

    let first_pending = make_record(
        "store-rebind-order-first",
        &"d".repeat(64),
        StoreRebindReplayState::Pending,
    )?;
    assert!(store.begin_store_rebind(&first_pending)?.is_none());
    let mut substituted_pending = first_pending.clone();
    substituted_pending.process_id += 1;
    assert!(store.begin_store_rebind(&substituted_pending).is_err());
    substituted_pending.process_id = first_pending.process_id;
    substituted_pending.requirement_digest = "f".repeat(64);
    assert!(store.persist_store_rebind(&substituted_pending).is_err());
    let mut first_committed = make_record(
        first_pending.operation_id.as_str(),
        &first_pending.request_digest,
        StoreRebindReplayState::Committed,
    )?;
    first_committed.commit_order = 999;
    store.persist_store_rebind(&first_committed)?;
    let first = store
        .load_store_rebind(&first_pending.operation_id, &first_pending.request_digest)?
        .ok_or_else(|| std::io::Error::other("first committed replay is absent"))?;
    assert!(first.commit_order > 0);
    assert_ne!(first.commit_order, 999);

    let second_pending = make_record(
        "store-rebind-order-second",
        &"e".repeat(64),
        StoreRebindReplayState::Pending,
    )?;
    assert!(store.begin_store_rebind(&second_pending)?.is_none());
    let second_committed = make_record(
        second_pending.operation_id.as_str(),
        &second_pending.request_digest,
        StoreRebindReplayState::Committed,
    )?;
    store.persist_store_rebind(&second_committed)?;
    let second = store
        .load_store_rebind(&second_pending.operation_id, &second_pending.request_digest)?
        .ok_or_else(|| std::io::Error::other("second committed replay is absent"))?;
    assert!(second.commit_order > first.commit_order);

    // A retry with the caller's zero order cannot overwrite the durable
    // linearization point.
    store.persist_store_rebind(&first_committed)?;
    let retried = store
        .load_store_rebind(&first_pending.operation_id, &first_pending.request_digest)?
        .ok_or_else(|| std::io::Error::other("idempotent committed replay is absent"))?;
    assert_eq!(retried.commit_order, first.commit_order);

    drop(store);
    let reopened = RedbRecoveryStore::open(&path)?;
    let reopened_records = reopened.load_all_store_rebinds()?;
    assert_eq!(
        reopened_records
            .iter()
            .map(|record| record.commit_order)
            .filter(|order| *order > 0)
            .count(),
        2
    );
    let mut substituted = first_committed.clone();
    substituted.receipt = Some("f".repeat(64));
    assert!(matches!(
        substituted.validate(),
        Err(OrsError::InvalidField {
            field: "store_rebind_receipt",
            ..
        })
    ));
    cleanup(&path);
    Ok(())
}

fn label(value: &str) -> Result<OpaqueLabel, OrsError> {
    OpaqueLabel::new(value)
}

fn epoch(lineage: &str, value: u64) -> Result<EpochLineage, OrsError> {
    Ok(EpochLineage {
        current: EpochIdentity {
            lineage_id: label(lineage)?,
            epoch: value,
        },
        predecessor: None,
    })
}

fn successor(prior: &EpochIdentity, lineage: &str, value: u64) -> Result<EpochLineage, OrsError> {
    Ok(EpochLineage {
        current: EpochIdentity {
            lineage_id: label(lineage)?,
            epoch: value,
        },
        predecessor: Some(prior.clone()),
    })
}

fn fence(authority_epoch: &EpochLineage) -> Result<StateFenceSnapshot, OrsError> {
    // Exact-tuple fence contour (Implements #64): the snapshot's canonical JSON
    // carries the canonical `EpochId` object shape so it deserializes into the
    // migrated fence contracts; the retained `u64` contour observes the same
    // sequence and never authorizes on its own.
    StateFenceSnapshot::capture(
        &json!({
            "authority_epoch": {
                "lineage_id": authority_epoch.current.lineage_id.as_str(),
                "sequence": authority_epoch.current.epoch
            },
            "integration_revision": null,
            "policy_revision": null,
            "resource_generation": 1,
            "task_revision": null
        }),
        authority_epoch.current.epoch,
    )
}

fn access() -> Result<RecoveryAccessClass, OrsError> {
    Ok(RecoveryAccessClass {
        privacy: PrivacyClass::Private,
        visibility: label("owner-only")?,
        instruction_taint: InstructionTaint::DataOnly,
    })
}

fn operational_input(
    record_id: &str,
    subject_id: &str,
    authority_epoch: EpochLineage,
    payload: &str,
) -> Result<OperationalRecordInput, OrsError> {
    let state_fence = fence(&authority_epoch)?;
    OperationalRecordInput::encrypted(
        OperationalRecordContext {
            record_id: label(record_id)?,
            subject_id: label(subject_id)?,
            authority_epoch,
            state_fence,
            created_at_ms: 100,
            cleanup_after_ms: Some(10_000),
        },
        SecretReference::new("test-key-provider", "operational-key-1")
            .map_err(|error| OrsError::Contract(error.to_string()))?,
        payload.as_bytes().to_vec(),
    )
}

fn request(
    reservation_id: &str,
    operation_id: &str,
    writer_epoch: EpochLineage,
    scopes: &[&str],
) -> TestResult<ReservationRequest> {
    let state_fence = fence(&writer_epoch)?;
    let envelope = RecoveryPayloadEnvelope::encrypted(
        RecoveryEnvelopeContext {
            operation_or_checkpoint_id: label(operation_id)?,
            privacy_and_visibility_class: access()?,
            authority_epoch: writer_epoch.clone(),
            state_fence,
            created_at_ms: 10,
            known_at_ms: 11,
            expires_at_ms: Some(10_000),
        },
        SecretReference::new("test-key-provider", "key-1")?,
        format!("opaque-{operation_id}").into_bytes(),
    )?;
    Ok(ReservationRequest {
        reservation_id: label(reservation_id)?,
        envelope,
        writer_epoch,
        scopes: scopes
            .iter()
            .map(|scope| {
                Ok(ScopeReservationRequest {
                    scope: label(scope)?,
                    expected_head: ExpectedOrderingHead {
                        sequence: 0,
                        head_sha256: "00".repeat(32),
                        revision_head: Some("revision-0".to_owned()),
                    },
                })
            })
            .collect::<Result<Vec<_>, OrsError>>()?,
        prepared_transition_sha256: "11".repeat(32),
        expires_at_ms: 1_000,
        recovery_owner: label("kernel-recovery-owner")?,
    })
}

fn receipt(token: &WriterReservationToken, disposition: &Value) -> TestResult<ReceiptEnvelope> {
    let state_fence: Value = serde_json::from_str(&token.state_fence.canonical_json)?;
    let contract = serde_json::to_value(eliot_receipts::contract_identity()?)?;
    let request_id = format!("request-{}", token.operation_id.as_str());
    let core: ReceiptCore = serde_json::from_value(json!({
        "contract": contract,
        "kind": "OPERATION",
        "work_scope": {
            "scope_id": token.scopes[0].scope.as_str(),
            "product_id": "product-1",
            "resource_generation": 1,
            "state_fence": state_fence
        },
        "task": null,
        "session": null,
        "causal": {
            "state_fence": state_fence,
            "transaction_sequence": token.scopes[0].reserved_sequence,
            "parent_receipt_id": null,
            "predecessor_receipt_ids": []
        },
        "request": {
            "metadata": {
                "request_id": request_id,
                "session_id": null,
                "task_id": null,
                "product_id": "product-1",
                "source_id": "source-1",
                "state_fence": state_fence,
                "clock": {
                    "valid_time_ms": 20,
                    "known_time_ms": 21,
                    "transaction_sequence": token.scopes[0].reserved_sequence,
                    "monotonic_ns": 22
                }
            },
            "state_fence": state_fence
        },
        "operation": {
            "operation_id": token.operation_id.as_str(),
            "request_id": request_id,
            "idempotency_key": token.reservation_id.as_str(),
            "operation_kind": "canonical-write",
            "effect": "REVERSIBLE_MUTATION",
            "state_fence": state_fence
        },
        "authority": {
            "authority_id": "authority-1",
            "authority_owner": "governor",
            "authority_epoch": {
                "lineage_id": token.writer_epoch.current.lineage_id.as_str(),
                "sequence": token.writer_epoch.current.epoch
            },
            "state_fence": state_fence,
            "allowed_effect": "REVERSIBLE_MUTATION",
            "proof_ceiling": "SCOPED_VERIFICATION"
        },
        "artifacts": [],
        "verifier": null,
        "problem": null,
        "coordination": null,
        "disposition": disposition
    }))?;
    Ok(ReceiptEnvelope::issue(core)?)
}

fn reconciliation(
    token: &WriterReservationToken,
    receipt: ReceiptEnvelope,
    disposition: CanonicalDisposition,
) -> Result<CanonicalReconciliation, OrsError> {
    let receipt_id = label(receipt.identity.receipt_id.as_str())?;
    let receipt_sha = receipt.identity.canonical_sha256.clone();
    Ok(CanonicalReconciliation {
        reservation_id: token.reservation_id.clone(),
        operation_id: token.operation_id.clone(),
        reservation_order: token.reservation_order,
        state_fence: token.state_fence.clone(),
        recovery_owner: token.recovery_owner.clone(),
        scopes: token
            .scopes
            .iter()
            .map(|reserved| CanonicalScopeObservation {
                scope: reserved.scope.clone(),
                prior_head: reserved.expected_head.clone(),
                committed_sequence: reserved.reserved_sequence,
                committed_head_sha256: receipt_sha.clone(),
                committed_revision_head: Some(format!("receipt:{}", receipt_id.as_str())),
                receipt_id: receipt_id.clone(),
            })
            .collect(),
        receipt,
        disposition,
    })
}

fn success_disposition() -> Value {
    json!({"kind": "SUCCESS", "proof": "SCOPED_VERIFICATION"})
}

fn assert_invalid_physical_replay_receipt_is_rejected(
    completed: &ProcessStartReplayRecord,
    receipt: &eliot_process::ProcessStartReceipt,
) -> TestResult {
    let mut wire = serde_json::to_value(receipt)?;
    wire["identity"]["suspended"]["physical"]["start_time_100ns"] = json!(0);
    let invalid_completed = ProcessStartReplayRecord {
        receipt: Some(serde_json::from_value(wire)?),
        ..completed.clone()
    };
    assert!(matches!(
        invalid_completed.validate(),
        Err(OrsError::IntegrityProblem { .. })
    ));
    Ok(())
}

#[test]
fn envelope_validation_rejects_tamper_version_and_bad_fence() -> TestResult {
    let original = request(
        "reservation-a",
        "operation-a",
        epoch(TEST_LINEAGE_A, 7)?,
        &["a"],
    )?;
    original.envelope.validate()?;

    let mut tampered = original.envelope.clone();
    if let RecoveryPayload::Encrypted { ciphertext, .. } = &mut tampered.payload {
        ciphertext.push(1);
    }
    assert!(matches!(
        tampered.validate(),
        Err(OrsError::PayloadIntegrityMismatch)
    ));

    let mut wrong_version = original.envelope.clone();
    wrong_version.contract_version += 1;
    assert!(matches!(
        wrong_version.validate(),
        Err(OrsError::UnsupportedContractVersion(_))
    ));

    let mut wrong_fence = original.envelope;
    wrong_fence.state_fence.observed_authority_epoch = 8;
    assert!(matches!(
        wrong_fence.validate(),
        Err(OrsError::FenceMismatch)
    ));
    Ok(())
}

#[test]
fn process_start_replay_has_one_atomic_winner_and_rejects_substitution() -> TestResult {
    let path = database_path("process-replay-state-machine");
    let store = Arc::new(RedbRecoveryStore::open(&path)?);
    let operation_id = OperationIdentity::new("process-replay-operation")?;
    let owner = eliot_process::ProcessOwnerBinding::new(
        "testd",
        "a".repeat(64),
        test_epoch(1),
        eliot_process::Generation::new(1)?,
    )?;
    let record = ProcessStartReplayRecord {
        operation_id: operation_id.clone(),
        admission_digest: "ab".repeat(32),
        owner: owner.clone(),
        state: ProcessStartReplayState::Reserved,
        receipt: None,
    };
    let barrier = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let record = record.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            store.begin_process_start(&record)
        }));
    }
    let mut acquired = 0;
    for worker in workers {
        match worker.join().map_err(|_| "replay worker panicked")?? {
            None => acquired += 1,
            Some(existing) => assert_eq!(existing, record),
        }
    }
    assert_eq!(acquired, 1);

    let mut wrong_digest = record.clone();
    wrong_digest.admission_digest = "cd".repeat(32);
    assert!(matches!(
        store.begin_process_start(&wrong_digest),
        Err(OrsError::IntegrityProblem { .. })
    ));
    let mut unknown = record.clone();
    unknown.state = ProcessStartReplayState::Unknown;
    store.persist_process_start(&unknown)?;
    store.persist_process_start(&unknown)?;
    assert_eq!(
        store
            .load_process_start(&operation_id)?
            .ok_or("unknown replay state")?
            .state,
        ProcessStartReplayState::Unknown
    );
    assert!(store.persist_process_start(&record).is_err());

    let completed_id = OperationIdentity::new("process-replay-completed")?;
    let completed_receipt = process_start_receipt(completed_id.as_str(), &"55".repeat(32))?;
    let completed_reservation = ProcessStartReplayRecord {
        operation_id: completed_id.clone(),
        admission_digest: record.admission_digest.clone(),
        owner: record.owner.clone(),
        state: ProcessStartReplayState::Reserved,
        receipt: None,
    };
    let completed = ProcessStartReplayRecord {
        state: ProcessStartReplayState::Completed,
        receipt: Some(completed_receipt.clone()),
        ..completed_reservation.clone()
    };
    assert_invalid_physical_replay_receipt_is_rejected(&completed, &completed_receipt)?;
    store.begin_process_start(&completed_reservation)?;
    store.persist_process_start(&completed)?;
    store.persist_process_start(&completed)?;
    let mut replacement_receipt = serde_json::to_value(completed_receipt)?;
    replacement_receipt["binding"]["permit_digest"] = json!("66".repeat(32));
    let conflicting_completed = ProcessStartReplayRecord {
        receipt: Some(serde_json::from_value(replacement_receipt)?),
        ..completed
    };
    assert!(store.persist_process_start(&conflicting_completed).is_err());

    drop(store);
    let reopened = RedbRecoveryStore::open(&path)?;
    assert_eq!(
        reopened
            .load_process_start(&operation_id)?
            .ok_or("replay restart state")?
            .state,
        ProcessStartReplayState::Unknown
    );
    let mut corrupted = record;
    corrupted.state = ProcessStartReplayState::Completed;
    corrupted.receipt = None;
    reopened.write_process_start_raw_for_test(&corrupted)?;
    assert!(reopened.load_process_start(&operation_id).is_err());
    cleanup(&path);
    Ok(())
}

fn supervision_binding(
    state: LeaseState,
    issued_at_offset_ms: u64,
) -> TestResult<SupervisionLeaseBinding> {
    static SUPERVISION_TEST_EPOCH_MS: OnceLock<u64> = OnceLock::new();
    let issued_at_ms = SUPERVISION_TEST_EPOCH_MS
        .get_or_init(|| {
            u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
            )
            .unwrap_or(u64::MAX.saturating_sub(3_600_000))
            .saturating_add(3_600_000)
        })
        .saturating_add(issued_at_offset_ms);
    let terminal_disposition = match state {
        LeaseState::Released => Some(SupervisionLeaseTerminalDisposition::Released),
        LeaseState::Expired => Some(SupervisionLeaseTerminalDisposition::Expired),
        LeaseState::Revoked => Some(SupervisionLeaseTerminalDisposition::Revoked),
        LeaseState::Superseded => Some(SupervisionLeaseTerminalDisposition::Superseded),
        LeaseState::Closed => Some(SupervisionLeaseTerminalDisposition::Closed),
        LeaseState::Requested
        | LeaseState::Active
        | LeaseState::Expiring
        | LeaseState::Reconciling => None,
    };
    let revoked = state == LeaseState::Revoked;
    Ok(SupervisionLeaseBinding {
        scope_ref: label("scope-supervision")?,
        observation_scope: SupervisionObservationScope {
            targets: vec!["target-1".to_owned()],
            sensor_profile: "kernel-heartbeat".to_owned(),
            claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
            governance_axis: "runtime-live".to_owned(),
        },
        installation_id: label("installation-1")?,
        host_epoch: AuthorityEpoch::new(1)?,
        activation_id: label("activation-1")?,
        activation_generation: ResourceGeneration::new(1)?,
        kernel_epoch: test_epoch(2),
        kernel_front_door_server_sid: "S-1-5-19".to_owned(),
        kernel_front_door_session_id: 0,
        kernel_front_door_artifact_sha256: "a".repeat(64),
        watchdog_epoch: AuthorityEpoch::new(1)?,
        generation_binding: SupervisionGenerationBinding {
            target_id: "target-1".to_owned(),
            target_generation: ResourceGeneration::new(1)?,
            module_id: "module-1".to_owned(),
            module_generation: ResourceGeneration::new(1)?,
            process_id: "kernel-process-1".to_owned(),
            process_generation: ResourceGeneration::new(1)?,
        },
        state_fence: StateFence::new(test_epoch(2), ResourceGeneration::new(1)?),
        issued_at_ms,
        expires_at_ms: issued_at_ms + 900,
        renew_before_ms: issued_at_ms + 450,
        wake_policy: RegisteredActivityWakePolicy::Disabled,
        state,
        terminal_disposition,
        revocation_reason: revoked.then(|| "test revocation".to_owned()),
        revocation_id: revoked.then(|| "revoke-1".to_owned()),
        revocation_epoch: revoked.then(|| AuthorityEpoch::new(2)).transpose()?,
    })
}

fn supervision_request(
    ticket_id: &str,
    operation_id: &str,
    lease_id: &str,
    expected_revision: Option<u64>,
    operation: SupervisionLeaseOperation,
    binding: SupervisionLeaseBinding,
) -> Result<SupervisionLeasePrepareRequest, OrsError> {
    Ok(SupervisionLeasePrepareRequest {
        ticket_id: label(ticket_id)?,
        operation_id: label(operation_id)?,
        lease_id: label(lease_id)?,
        expected_revision,
        operation,
        binding,
    })
}

fn verified_supervision_stage(
    stage: &SupervisionLeaseStageReceipt,
) -> TestResult<VerifiedSupervisionLease> {
    verified_supervision_ticket(&stage.ticket)
}

fn signed_supervision_ticket(
    ticket: &SupervisionLeaseCommitTicket,
) -> TestResult<SignedSupervisionLease> {
    let signer =
        Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])?;
    Ok(ticket.expected_payload()?.sign(&signer)?)
}

fn verified_supervision_ticket(
    ticket: &SupervisionLeaseCommitTicket,
) -> TestResult<VerifiedSupervisionLease> {
    verify_supervision_envelope(&signed_supervision_ticket(ticket)?)
}

fn verify_supervision_envelope(
    envelope: &SignedSupervisionLease,
) -> TestResult<VerifiedSupervisionLease> {
    let (anchor, context) = supervision_verification_inputs(envelope)?;
    Ok(anchor.verify(envelope, &context)?)
}

fn supervision_predecessor_proof(
    prior_active: &VerifiedSupervisionLease,
    snapshot: &SupervisionLeaseSnapshot,
) -> SupervisionLeasePredecessorProof {
    SupervisionLeasePredecessorProof {
        lease_id: snapshot.record.lease_id.as_str().to_owned(),
        record_id: snapshot.record.record_id.as_str().to_owned(),
        lease_revision: snapshot.record.revision,
        receipt_sha256: snapshot.receipt.receipt_sha256.clone(),
        envelope_sha256: prior_active.envelope_digest().to_owned(),
    }
}

fn verified_terminal_supervision_ticket(
    ticket: &SupervisionLeaseCommitTicket,
    prior_active: &VerifiedSupervisionLease,
    predecessor: &SupervisionLeasePredecessorProof,
) -> TestResult<VerifiedSupervisionLeaseTerminalTransition> {
    let envelope = signed_supervision_ticket(ticket)?;
    let (anchor, _) = supervision_verification_inputs(&envelope)?;
    Ok(anchor.verify_terminal_transition(prior_active, &envelope, predecessor)?)
}

fn assert_active_verifier_rejects_terminal_and_expired(
    active_envelope: &SignedSupervisionLease,
    terminal_envelope: &SignedSupervisionLease,
) -> TestResult {
    let (terminal_anchor, terminal_context) = supervision_verification_inputs(terminal_envelope)?;
    assert!(matches!(
        terminal_anchor.verify(terminal_envelope, &terminal_context),
        Err(eliot_runtime_contracts::SupervisionLeaseError::InactiveLease)
    ));
    let (active_anchor, mut expired_context) = supervision_verification_inputs(active_envelope)?;
    expired_context.now_ms = active_envelope.payload.expires_at_ms;
    assert!(matches!(
        active_anchor.verify(active_envelope, &expired_context),
        Err(eliot_runtime_contracts::SupervisionLeaseError::Expired)
    ));
    Ok(())
}

fn assert_terminal_verifier_rejects_missing_or_wrong_predecessor(
    anchor: &SupervisionTrustAnchor,
    active: &VerifiedSupervisionLease,
    terminal_envelope: &SignedSupervisionLease,
    predecessor: &SupervisionLeasePredecessorProof,
    active_ticket: &SupervisionLeaseCommitTicket,
) -> TestResult {
    let mut missing_evidence = predecessor.clone();
    missing_evidence.receipt_sha256.clear();
    assert!(matches!(
        anchor.verify_terminal_transition(active, terminal_envelope, &missing_evidence),
        Err(eliot_runtime_contracts::SupervisionLeaseError::InvalidContext(_))
    ));

    let mut wrong_prior_ticket = active_ticket.clone();
    wrong_prior_ticket.ticket_id = label("ticket-wrong-prior")?;
    wrong_prior_ticket.operation_id = label("operation-wrong-prior")?;
    wrong_prior_ticket.lease_id = label("lease-wrong-prior")?;
    wrong_prior_ticket.record_id = label("lease-wrong-prior::r00000000000000000001")?;
    let wrong_prior = verified_supervision_ticket(&wrong_prior_ticket)?;
    assert!(matches!(
        anchor.verify_terminal_transition(&wrong_prior, terminal_envelope, predecessor),
        Err(
            eliot_runtime_contracts::SupervisionLeaseError::TerminalTransitionMismatch(
                "active predecessor"
            )
        )
    ));
    Ok(())
}

fn supervision_verification_inputs(
    envelope: &SignedSupervisionLease,
) -> TestResult<(SupervisionTrustAnchor, SupervisionLeaseVerificationContext)> {
    let payload = &envelope.payload;
    let signer =
        Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])?;
    let anchor = SupervisionTrustAnchor::new(
        payload.installation_id.clone(),
        signer.signer_id(),
        signer.key_id(),
        signer.public_key().to_vec(),
    )?;
    let generation = &payload.generation_binding;
    let context = SupervisionLeaseVerificationContext {
        now_ms: payload.issued_at_ms + 1,
        lease_id: payload.lease_id.clone(),
        host_epoch: payload.host_epoch,
        activation_id: payload.activation_id.clone(),
        activation_generation: payload.activation_generation,
        kernel_epoch: payload.kernel_epoch.clone(),
        watchdog_epoch: payload.watchdog_epoch,
        state_fence: payload.state_fence.clone(),
        scope_ref: payload.scope_ref.clone(),
        observation_scope: payload.observation_scope.clone(),
        target_id: generation.target_id.clone(),
        module_id: generation.module_id.clone(),
        process_id: generation.process_id.clone(),
        target_generation: generation.target_generation,
        module_generation: generation.module_generation,
        process_generation: generation.process_generation,
        public_key_fingerprint: anchor.public_key_fingerprint().to_owned(),
        ors_mirror: payload.ors_mirror.clone(),
        active_state: SupervisionLeaseActiveStateBinding {
            state: payload.state,
            revocation_id: payload.revocation_id.clone(),
            revocation_epoch: payload.revocation_epoch,
        },
    };
    Ok((anchor, context))
}

#[test]
fn supervision_lease_stage_is_non_authoritative_and_survives_reopen() -> TestResult {
    let path = database_path("supervision-stage-reopen");
    let store = RedbRecoveryStore::open(&path)?;
    let request = supervision_request(
        "ticket-1",
        "operation-1",
        "lease-1",
        None,
        SupervisionLeaseOperation::Commit,
        supervision_binding(LeaseState::Active, 100)?,
    )?;
    let stage = store.prepare_supervision_lease(request.clone())?;
    assert_eq!(stage.ticket.revision, 1);
    assert_eq!(stage.projection, SupervisionLeaseProjection::Staged);
    assert!(
        store
            .load_current_supervision_lease(&label("lease-1")?)?
            .is_none()
    );
    assert_eq!(store.reconcile_staged_supervision_leases(8)?.len(), 1);
    drop(store);

    let reopened = RedbRecoveryStore::open(&path)?;
    let recovered = reopened.reconcile_staged_supervision_lease(&label("lease-1")?)?;
    assert_eq!(recovered, Some(stage.clone()));
    assert_eq!(
        reopened.reconcile_supervision_lease_ticket(&stage.ticket)?,
        Some(SupervisionLeaseTicketReconciliation::Staged(stage.clone()))
    );
    assert_eq!(
        reopened.prepare_supervision_lease(request)?,
        stage,
        "an interrupted live stage must resume the exact reservation"
    );
    assert!(
        reopened
            .load_current_supervision_lease(&label("lease-1")?)?
            .is_none()
    );
    let snapshot =
        reopened.commit_supervision_lease(&stage.ticket, &verified_supervision_stage(&stage)?)?;
    assert_eq!(snapshot.record.revision, 1);
    assert_eq!(
        snapshot.record.projection,
        SupervisionLeaseProjection::Active
    );
    assert_eq!(reopened.reconcile_staged_supervision_leases(8)?.len(), 0);
    assert_eq!(
        reopened.reconcile_supervision_lease_ticket(&stage.ticket)?,
        Some(SupervisionLeaseTicketReconciliation::Committed(Box::new(
            snapshot.clone()
        )))
    );
    assert_eq!(
        reopened
            .load_supervision_lease_history(&label("lease-1")?, 8)?
            .len(),
        1
    );
    drop(reopened);
    let committed_reopen = RedbRecoveryStore::open(&path)?;
    let reopened_current = committed_reopen
        .load_current_supervision_lease(&label("lease-1")?)?
        .ok_or("committed lease disappeared after reopen")?;
    assert_eq!(reopened_current.record.revision, 1);
    assert_eq!(
        committed_reopen
            .load_supervision_lease_history(&label("lease-1")?, 8)?
            .len(),
        1
    );
    drop(committed_reopen);
    cleanup(&path);
    Ok(())
}

#[test]
fn supervision_stage_resolution_schema_requires_migration_for_legacy_stage() -> TestResult {
    let source_path = database_path("supervision-resolution-migration-source");
    let source = RedbRecoveryStore::open(&source_path)?;
    let request = supervision_request(
        "ticket-legacy-stage",
        "operation-legacy-stage",
        "lease-legacy-stage",
        None,
        SupervisionLeaseOperation::Commit,
        supervision_binding(LeaseState::Active, 150)?,
    )?;
    let stage = source.prepare_supervision_lease(request.clone())?;
    let encoded_stage = serde_json::to_string(&stage)?;
    drop(source);

    let legacy_path = database_path("supervision-resolution-migration-target");
    let database = redb::Database::create(&legacy_path)?;
    let write = database.begin_write()?;
    {
        let meta_definition: redb::TableDefinition<&str, &str> =
            redb::TableDefinition::new("ors_meta_v1");
        let staged_definition: redb::TableDefinition<&str, &str> =
            redb::TableDefinition::new("ors_supervision_lease_staged_v1");
        let current_definition: redb::TableDefinition<&str, &str> =
            redb::TableDefinition::new("ors_supervision_lease_current_v1");
        let history_definition: redb::TableDefinition<&str, &str> =
            redb::TableDefinition::new("ors_supervision_lease_history_v1");
        let results_definition: redb::TableDefinition<&str, &str> =
            redb::TableDefinition::new("ors_supervision_lease_results_v1");
        let mut meta = write.open_table(meta_definition)?;
        meta.insert(
            "next_global_order",
            stage.ticket.reservation_order.to_string().as_str(),
        )?;
        drop(meta);
        let mut staged = write.open_table(staged_definition)?;
        staged.insert(stage.ticket.lease_id.as_str(), encoded_stage.as_str())?;
        drop(staged);
        drop(write.open_table(current_definition)?);
        drop(write.open_table(history_definition)?);
        drop(write.open_table(results_definition)?);
    }
    write.commit()?;
    drop(database);

    assert!(matches!(
        RedbRecoveryStore::open(&legacy_path),
        Err(OrsError::MigrationRequired { .. })
    ));

    let database = redb::Database::create(&legacy_path)?;
    let read = database.begin_read()?;
    let meta_definition: redb::TableDefinition<&str, &str> =
        redb::TableDefinition::new("ors_meta_v1");
    assert_eq!(
        read.open_table(meta_definition)?
            .get("supervision_stage_resolution_schema")?
            .map(|value| value.value().to_owned()),
        None
    );
    let resolution_definition: redb::TableDefinition<&str, &str> =
        redb::TableDefinition::new("ors_supervision_lease_stage_resolutions_v1");
    assert!(matches!(
        read.open_table(resolution_definition),
        Err(redb::TableError::TableDoesNotExist(_))
    ));
    drop(read);
    drop(database);
    cleanup(&source_path);
    cleanup(&legacy_path);
    Ok(())
}

#[test]
fn supervision_stage_resolution_schema_rejects_unmarked_authority_table() -> TestResult {
    let path = database_path("supervision-resolution-unmarked");
    let database = redb::Database::create(&path)?;
    let write = database.begin_write()?;
    for name in [
        "ors_meta_v1",
        "ors_supervision_lease_staged_v1",
        "ors_supervision_lease_current_v1",
        "ors_supervision_lease_history_v1",
        "ors_supervision_lease_results_v1",
        "ors_supervision_lease_stage_resolutions_v1",
    ] {
        let definition: redb::TableDefinition<&str, &str> = redb::TableDefinition::new(name);
        drop(write.open_table(definition)?);
    }
    write.commit()?;
    drop(database);

    assert!(matches!(
        RedbRecoveryStore::open(&path),
        Err(OrsError::MigrationRequired { .. })
    ));
    cleanup(&path);
    Ok(())
}

#[test]
fn supervision_lease_commit_rejects_substitution_and_replays_exactly() -> TestResult {
    let path = database_path("supervision-commit-binding");
    let store = RedbRecoveryStore::open(&path)?;
    let stage = store.prepare_supervision_lease(supervision_request(
        "ticket-2",
        "operation-2",
        "lease-2",
        None,
        SupervisionLeaseOperation::Commit,
        supervision_binding(LeaseState::Active, 100)?,
    )?)?;
    let valid = verified_supervision_stage(&stage)?;
    let mut forged = signed_supervision_ticket(&stage.ticket)?;
    forged.payload.activation_id = "substituted-activation".to_owned();
    forged.payload_sha256 = forged.payload.digest()?;
    assert!(forged.validate().is_ok());
    let Err(forged_error) = verify_supervision_envelope(&forged) else {
        return Err("forged signature accepted".into());
    };
    assert!(matches!(
        forged_error.downcast_ref::<eliot_runtime_contracts::SupervisionLeaseError>(),
        Some(eliot_runtime_contracts::SupervisionLeaseError::SignatureInvalid(_))
    ));
    assert!(
        store
            .reconcile_staged_supervision_lease(&label("lease-2")?)?
            .is_some()
    );
    let first = store.commit_supervision_lease(&stage.ticket, &valid)?;
    let replay = store.commit_supervision_lease(&stage.ticket, &valid)?;
    assert_eq!(first, replay);
    assert_eq!(
        store.replay_supervision_lease_commit(&stage.ticket)?,
        Some(first.clone())
    );
    drop(store);
    cleanup(&path);
    Ok(())
}

#[test]
fn supervision_lease_renew_is_monotonic_and_history_is_bounded() -> TestResult {
    let path = database_path("supervision-renew-history");
    let store = RedbRecoveryStore::open(&path)?;
    let first_stage = store.prepare_supervision_lease(supervision_request(
        "ticket-3a",
        "operation-3a",
        "lease-3",
        None,
        SupervisionLeaseOperation::Commit,
        supervision_binding(LeaseState::Active, 100)?,
    )?)?;
    let first = store.commit_supervision_lease(
        &first_stage.ticket,
        &verified_supervision_stage(&first_stage)?,
    )?;
    let second_stage = store.prepare_supervision_lease(supervision_request(
        "ticket-3b",
        "operation-3b",
        "lease-3",
        Some(1),
        SupervisionLeaseOperation::Renew,
        supervision_binding(LeaseState::Active, 200)?,
    )?)?;
    assert_eq!(second_stage.ticket.revision, 2);
    assert_eq!(
        second_stage.ticket.previous_receipt_sha256.as_deref(),
        Some(first.receipt.receipt_sha256.as_str())
    );
    let second = store.commit_supervision_lease(
        &second_stage.ticket,
        &verified_supervision_stage(&second_stage)?,
    )?;
    assert!(second.receipt.operation_order > first.receipt.operation_order);
    assert_eq!(second.record.revision, 2);
    assert!(matches!(
        store.prepare_supervision_lease(supervision_request(
            "ticket-stale",
            "operation-stale",
            "lease-3",
            Some(1),
            SupervisionLeaseOperation::Renew,
            supervision_binding(LeaseState::Active, 300)?,
        )?),
        Err(OrsError::SupervisionLeaseStaleRevision)
    ));
    let mut mismatched_binding = supervision_binding(LeaseState::Active, 250)?;
    mismatched_binding.kernel_epoch = test_epoch(3);
    mismatched_binding.state_fence = StateFence::new(test_epoch(3), ResourceGeneration::new(1)?);
    assert!(matches!(
        store.prepare_supervision_lease(supervision_request(
            "ticket-fence-mismatch",
            "operation-fence-mismatch",
            "lease-3",
            Some(2),
            SupervisionLeaseOperation::Renew,
            mismatched_binding,
        )?),
        Err(OrsError::SupervisionLeaseBindingMismatch)
    ));
    let mut generation_mismatch = supervision_binding(LeaseState::Active, 250)?;
    generation_mismatch.generation_binding.process_generation = ResourceGeneration::new(2)?;
    assert!(matches!(
        store.prepare_supervision_lease(supervision_request(
            "ticket-generation-mismatch",
            "operation-generation-mismatch",
            "lease-3",
            Some(2),
            SupervisionLeaseOperation::Renew,
            generation_mismatch,
        )?),
        Err(OrsError::SupervisionLeaseBindingMismatch)
    ));

    let third_stage = store.prepare_supervision_lease(supervision_request(
        "ticket-3c",
        "operation-3c",
        "lease-3",
        Some(2),
        SupervisionLeaseOperation::Renew,
        supervision_binding(LeaseState::Active, 300)?,
    )?)?;
    store.commit_supervision_lease(
        &third_stage.ticket,
        &verified_supervision_stage(&third_stage)?,
    )?;
    let history = store.load_supervision_lease_history(&label("lease-3")?, 2)?;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].record.revision, 3);
    assert_eq!(history[1].record.revision, 2);
    drop(store);
    cleanup(&path);
    Ok(())
}

#[test]
fn supervision_lease_terminal_requires_verified_durable_predecessor() -> TestResult {
    let path = database_path("supervision-terminal-fence");
    let store = RedbRecoveryStore::open(&path)?;
    let active_stage = store.prepare_supervision_lease(supervision_request(
        "ticket-4a",
        "operation-4a",
        "lease-4",
        None,
        SupervisionLeaseOperation::Commit,
        supervision_binding(LeaseState::Active, 100)?,
    )?)?;
    let active_envelope = signed_supervision_ticket(&active_stage.ticket)?;
    let active_verified = verify_supervision_envelope(&active_envelope)?;
    let active = store.commit_supervision_lease(&active_stage.ticket, &active_verified)?;
    let revoke_stage = store.prepare_supervision_lease(supervision_request(
        "ticket-4b",
        "operation-4b",
        "lease-4",
        Some(1),
        SupervisionLeaseOperation::Revoke,
        supervision_binding(LeaseState::Revoked, 100)?,
    )?)?;
    let terminal_envelope = signed_supervision_ticket(&revoke_stage.ticket)?;
    assert_active_verifier_rejects_terminal_and_expired(&active_envelope, &terminal_envelope)?;
    assert!(matches!(
        store.commit_supervision_lease(&revoke_stage.ticket, &active_verified),
        Err(OrsError::InvalidTransition)
    ));

    let predecessor = supervision_predecessor_proof(&active_verified, &active);
    let (terminal_anchor, _) = supervision_verification_inputs(&terminal_envelope)?;
    assert_terminal_verifier_rejects_missing_or_wrong_predecessor(
        &terminal_anchor,
        &active_verified,
        &terminal_envelope,
        &predecessor,
        &active_stage.ticket,
    )?;

    assert_ne!(active.record.ticket_sha256, active.receipt.receipt_sha256);
    assert_eq!(
        terminal_envelope.payload.ors_mirror.ticket_sha256,
        revoke_stage.ticket_sha256
    );
    assert_eq!(
        terminal_envelope
            .payload
            .ors_mirror
            .previous_receipt_sha256
            .as_deref(),
        Some(active.receipt.receipt_sha256.as_str())
    );
    let mut substituted_proof = predecessor.clone();
    substituted_proof.receipt_sha256 = active.record.ticket_sha256.clone();
    let mut substituted_payload = revoke_stage.ticket.expected_payload()?;
    substituted_payload.ors_mirror.previous_receipt_sha256 =
        Some(substituted_proof.receipt_sha256.clone());
    let signer =
        Ed25519SupervisionLeaseSigner::from_secret_key("kernel-1", "kernel-key-1", [7; 32])?;
    let substituted_envelope = substituted_payload.sign(&signer)?;
    let substituted = terminal_anchor.verify_terminal_transition(
        &active_verified,
        &substituted_envelope,
        &substituted_proof,
    )?;
    assert!(matches!(
        store.commit_terminal_supervision_lease(&revoke_stage.ticket, &substituted),
        Err(OrsError::SupervisionLeaseBindingMismatch)
    ));

    let terminal_verified =
        verified_terminal_supervision_ticket(&revoke_stage.ticket, &active_verified, &predecessor)?;
    let revoked =
        store.commit_terminal_supervision_lease(&revoke_stage.ticket, &terminal_verified)?;
    assert_eq!(
        revoked.record.projection,
        SupervisionLeaseProjection::Terminal
    );
    assert!(matches!(
        store.prepare_supervision_lease(supervision_request(
            "ticket-4c",
            "operation-4c",
            "lease-4",
            Some(2),
            SupervisionLeaseOperation::Renew,
            supervision_binding(LeaseState::Active, 200)?,
        )?),
        Err(OrsError::InvalidTransition)
    ));
    drop(store);
    cleanup(&path);
    Ok(())
}

#[test]
fn supervision_lease_unstaged_ticket_is_authoritatively_absent_and_retryable() -> TestResult {
    let path = database_path("supervision-unstaged-ticket");
    let store = RedbRecoveryStore::open(&path)?;
    let request = supervision_request(
        "ticket-never-staged",
        "operation-never-staged",
        "lease-never-staged",
        None,
        SupervisionLeaseOperation::Commit,
        supervision_binding(LeaseState::Active, 100)?,
    )?;
    let unstaged = SupervisionLeaseCommitTicket {
        ticket_id: request.ticket_id.clone(),
        operation_id: request.operation_id.clone(),
        lease_id: request.lease_id.clone(),
        record_id: label("lease-never-staged::r00000000000000000001")?,
        expected_revision: None,
        revision: 1,
        operation: request.operation,
        binding: request.binding.clone(),
        previous_receipt_sha256: None,
        reservation_order: 99,
    };
    let unstaged_verified = verified_supervision_ticket(&unstaged)?;
    assert!(matches!(
        store.commit_supervision_lease(&unstaged, &unstaged_verified),
        Err(OrsError::SupervisionLeaseTicketNotStaged)
    ));
    assert!(
        store
            .load_current_supervision_lease(&request.lease_id)?
            .is_none()
    );
    assert!(
        store
            .load_supervision_lease_history(&request.lease_id, 8)?
            .is_empty()
    );

    let stage = store.prepare_supervision_lease(request)?;
    let committed =
        store.commit_supervision_lease(&stage.ticket, &verified_supervision_stage(&stage)?)?;
    assert_eq!(committed.record.revision, 1);
    drop(store);
    cleanup(&path);
    Ok(())
}

#[test]
fn supervision_lease_successor_rejects_corrupt_current_snapshot() -> TestResult {
    let path = database_path("supervision-corrupt-current");
    let store = RedbRecoveryStore::open(&path)?;
    let active_stage = store.prepare_supervision_lease(supervision_request(
        "ticket-corrupt-a",
        "operation-corrupt-a",
        "lease-corrupt",
        None,
        SupervisionLeaseOperation::Commit,
        supervision_binding(LeaseState::Active, 100)?,
    )?)?;
    store.commit_supervision_lease(
        &active_stage.ticket,
        &verified_supervision_stage(&active_stage)?,
    )?;
    let renew_stage = store.prepare_supervision_lease(supervision_request(
        "ticket-corrupt-b",
        "operation-corrupt-b",
        "lease-corrupt",
        Some(1),
        SupervisionLeaseOperation::Renew,
        supervision_binding(LeaseState::Active, 200)?,
    )?)?;
    let renew_verified = verified_supervision_stage(&renew_stage)?;
    drop(store);

    let database = redb::Database::create(&path)?;
    let write = database.begin_write()?;
    {
        let definition: redb::TableDefinition<&str, &str> =
            redb::TableDefinition::new("ors_supervision_lease_current_v1");
        let mut table = write.open_table(definition)?;
        let value = table
            .get("lease-corrupt")?
            .ok_or("missing current supervision lease")?;
        let mut invalid: Value = serde_json::from_str(value.value())?;
        drop(value);
        invalid["receipt"]["receipt_sha256"] = json!("00".repeat(32));
        let encoded = serde_json::to_string(&invalid)?;
        table.insert("lease-corrupt", encoded.as_str())?;
    }
    write.commit()?;
    drop(database);

    let reopened = RedbRecoveryStore::open(&path)?;
    assert!(matches!(
        reopened.commit_supervision_lease(&renew_stage.ticket, &renew_verified),
        Err(OrsError::IntegrityProblem {
            record_type: "supervision_lease_current",
            ..
        })
    ));
    assert!(
        reopened
            .reconcile_staged_supervision_lease(&label("lease-corrupt")?)?
            .is_some()
    );
    assert_eq!(
        reopened
            .load_supervision_lease_history(&label("lease-corrupt")?, 8)?
            .len(),
        1
    );
    drop(reopened);
    cleanup(&path);
    Ok(())
}

#[test]
fn supervision_lease_conflicting_stage_is_rejected_and_exact_stage_is_idempotent() -> TestResult {
    let path = database_path("supervision-stage-conflict");
    let store = RedbRecoveryStore::open(&path)?;
    let request = supervision_request(
        "ticket-5a",
        "operation-5a",
        "lease-5",
        None,
        SupervisionLeaseOperation::Commit,
        supervision_binding(LeaseState::Active, 100)?,
    )?;
    let first = store.prepare_supervision_lease(request.clone())?;
    let replay = store.prepare_supervision_lease(request)?;
    assert_eq!(first, replay);
    assert!(matches!(
        store.prepare_supervision_lease(supervision_request(
            "ticket-5b",
            "operation-5b",
            "lease-5",
            None,
            SupervisionLeaseOperation::Commit,
            supervision_binding(LeaseState::Active, 101)?,
        )?),
        Err(OrsError::SupervisionLeaseTicketConflict)
    ));
    drop(store);
    cleanup(&path);
    Ok(())
}

#[test]
fn supervision_lease_expired_crash_stage_is_durably_resolved_and_replaceable() -> TestResult {
    let path = database_path("supervision-expired-stage");
    let store = RedbRecoveryStore::open(&path)?;
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;
    let mut binding = supervision_binding(LeaseState::Active, 500)?;
    binding.issued_at_ms = now_ms.saturating_sub(1);
    binding.renew_before_ms = now_ms.saturating_add(75);
    binding.expires_at_ms = now_ms.saturating_add(150);
    let request = supervision_request(
        "ticket-expired-crash",
        "operation-expired-crash",
        "lease-expired-crash",
        None,
        SupervisionLeaseOperation::Commit,
        binding,
    )?;
    let stage = store.prepare_supervision_lease(request.clone())?;
    drop(store);

    std::thread::sleep(std::time::Duration::from_millis(220));
    let reopened = RedbRecoveryStore::open(&path)?;
    assert!(
        reopened
            .reconcile_staged_supervision_lease(&stage.ticket.lease_id)?
            .is_none()
    );
    let resolution = reopened
        .load_supervision_lease_stage_resolution(&stage.ticket)?
        .ok_or("expired stage resolution is missing")?;
    assert_eq!(
        reopened.reconcile_supervision_lease_ticket(&stage.ticket)?,
        Some(SupervisionLeaseTicketReconciliation::Resolved(
            resolution.clone()
        ))
    );
    assert_eq!(
        resolution.disposition,
        SupervisionLeaseStageResolutionDisposition::Expired
    );
    assert_eq!(resolution.ticket, stage.ticket);
    assert_eq!(resolution.ticket_sha256, stage.ticket_sha256);
    assert!(resolution.resolved_at_ms >= resolution.ticket.binding.expires_at_ms);
    assert!(resolution.resolution_order > resolution.ticket.reservation_order);
    assert!(matches!(
        reopened.commit_supervision_lease(
            &resolution.ticket,
            &verified_supervision_ticket(&resolution.ticket)?,
        ),
        Err(OrsError::SupervisionLeaseTicketResolved)
    ));
    assert!(matches!(
        reopened.prepare_supervision_lease(request),
        Err(OrsError::SupervisionLeaseTicketResolved)
    ));

    let replacement = reopened.prepare_supervision_lease(supervision_request(
        "ticket-expired-replacement",
        "operation-expired-replacement",
        "lease-expired-crash",
        None,
        SupervisionLeaseOperation::Commit,
        supervision_binding(LeaseState::Active, 600)?,
    )?)?;
    assert_eq!(replacement.ticket.revision, 1);
    assert_ne!(replacement.ticket.ticket_id, resolution.ticket.ticket_id);
    drop(reopened);
    cleanup(&path);
    Ok(())
}

#[test]
fn supervision_lease_abort_is_exact_idempotent_and_foreign_ticket_fails_closed() -> TestResult {
    let path = database_path("supervision-abort-stage");
    let store = RedbRecoveryStore::open(&path)?;
    let request = supervision_request(
        "ticket-abort",
        "operation-abort",
        "lease-abort",
        None,
        SupervisionLeaseOperation::Commit,
        supervision_binding(LeaseState::Active, 700)?,
    )?;
    let stage = store.prepare_supervision_lease(request.clone())?;
    let reason = label("operator-cancelled-before-signing")?;
    let first = store.abort_staged_supervision_lease(&stage.ticket, reason.clone())?;
    let replay = store.abort_staged_supervision_lease(&stage.ticket, reason)?;
    assert_eq!(first, replay);
    assert_eq!(
        first.disposition,
        SupervisionLeaseStageResolutionDisposition::Aborted
    );
    assert_eq!(
        store.reconcile_supervision_lease_ticket(&stage.ticket)?,
        Some(SupervisionLeaseTicketReconciliation::Resolved(
            first.clone()
        ))
    );
    assert!(
        store
            .reconcile_staged_supervision_lease(&stage.ticket.lease_id)?
            .is_none()
    );
    assert!(matches!(
        store.commit_supervision_lease(&stage.ticket, &verified_supervision_stage(&stage)?),
        Err(OrsError::SupervisionLeaseTicketResolved)
    ));

    let mut foreign = stage.ticket.clone();
    foreign.lease_id = label("lease-foreign")?;
    foreign.record_id = label("lease-foreign::r00000000000000000001")?;
    assert!(matches!(
        store.load_supervision_lease_stage_resolution(&foreign),
        Err(OrsError::SupervisionLeaseTicketConflict)
    ));
    assert!(matches!(
        store.prepare_supervision_lease(supervision_request(
            stage.ticket.ticket_id.as_str(),
            "operation-foreign",
            "lease-foreign",
            None,
            SupervisionLeaseOperation::Commit,
            supervision_binding(LeaseState::Active, 800)?,
        )?),
        Err(OrsError::SupervisionLeaseTicketConflict)
    ));

    let replacement = store.prepare_supervision_lease(supervision_request(
        "ticket-abort-replacement",
        "operation-abort-replacement",
        "lease-abort",
        None,
        SupervisionLeaseOperation::Commit,
        supervision_binding(LeaseState::Active, 900)?,
    )?)?;
    assert_eq!(replacement.ticket.revision, 1);
    drop(store);
    cleanup(&path);
    Ok(())
}

fn handoff_record(state: AuthorityHandoffState) -> Result<AuthorityHandoffRecord, OrsError> {
    Ok(AuthorityHandoffRecord {
        contract_version: CONTRACT_VERSION,
        handoff_id: OperationIdentity::new("authority-handoff-operation")?,
        descriptor_digest: "01".repeat(32),
        authority_id: OpaqueLabel::new("authority-1")?,
        snapshot_record_id: OperationIdentity::new("snapshot-record")?,
        snapshot_binding_digest: "02".repeat(32),
        authority_epoch: 1,
        generation: 1,
        state_fence_digest: "03".repeat(32),
        secret_reference_identity_digest: "04".repeat(32),
        state,
        issued_at_ms: 100,
        expires_at_ms: 200,
        consumed_at_ms: (state == AuthorityHandoffState::Consumed).then_some(150),
        reconciliation_evidence: (state == AuthorityHandoffState::Unknown)
            .then(|| OpaqueLabel::new("manual-reconciliation-required"))
            .transpose()?,
    })
}

fn process_evidence(
    operation_id: &str,
    lifecycle: &str,
) -> TestResult<eliot_process::ProcessEvidence> {
    Ok(serde_json::from_value(json!({
        "view": {
            "binding": {
                "operation_id": operation_id,
                "process_tree_id": "tree-1",
                "job_id": "job-1",
                "image_id": "image-1",
                "session_id": "session-1",
                "generation": 1,
                "action_lease_ref": "lease-1",
                "authority_id": "authority-1",
                "authority_epoch": {
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 1
                },
                "state_fence": {
                    "authority_epoch": {
                        "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                        "sequence": 1
                    },
                    "generation": 1,
                    "nonce": "fence-1"
                },
                "request_digest": "11".repeat(32),
                "permit_digest": "22".repeat(32),
                "effect_digest": "33".repeat(32),
                "validation_revision": 1
            },
            "lifecycle": lifecycle,
            "health": {
                "status": "healthy",
                "ready": false,
                "observed_at_unix_ms": 1,
                "detail": null
            },
            "cancellation": "not_requested",
            "identity": null,
            "exit": null,
            "descendants": null
        },
        "axes": {
            "status": "OBSERVED",
            "assertability": "NON_ASSERTABLE_UNVERIFIED",
            "accessibility": "AVAILABLE",
            "influence": "ALLOWED",
            "physical": "PRESENT",
            "taint": "CLEAR"
        },
        // #844: the canonical current-version constant, never a second current
        // version literal, so a schema bump on the `eliot-process` owner moves
        // this fixture with it instead of silently pinning a stale wire value.
        "schema_version": eliot_process::PROCESS_EVIDENCE_SCHEMA_VERSION
    }))?)
}

fn process_evidence_record(
    operation_id: &str,
    lifecycle: &str,
    observed_at_ms: i64,
) -> TestResult<ProcessEvidenceRecord> {
    // `new_with_canonical` was sealed away with the v4 `EpochId`-only cutover:
    // the owner binding carries the canonical tuple directly, so the fixture
    // passes `test_epoch(1)` as the authority epoch itself.
    let owner = eliot_process::ProcessOwnerBinding::new(
        "testd",
        "aa".repeat(32),
        test_epoch(1),
        eliot_process::Generation::new(1)?,
    )?;
    Ok(ProcessEvidenceRecord::from_evidence(
        &process_evidence(operation_id, lifecycle)?,
        owner,
        observed_at_ms,
    )?)
}

fn process_start_receipt(
    operation_id: &str,
    permit_digest: &str,
) -> TestResult<eliot_process::ProcessStartReceipt> {
    Ok(serde_json::from_value(json!({
        "binding": {
            "operation_id": operation_id,
            "process_tree_id": "tree-1",
            "job_id": "job-1",
            "image_id": "image-1",
            "session_id": "session-1",
            "generation": 1,
            "action_lease_ref": "lease-1",
            "authority_id": "authority-1",
            "authority_epoch": {
                "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                "sequence": 1
            },
            "state_fence": {
                "authority_epoch": {
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 1
                },
                "generation": 1,
                "nonce": "fence-1"
            },
            "request_digest": "11".repeat(32),
            "permit_digest": permit_digest,
            "effect_digest": "33".repeat(32),
            "validation_revision": 1
        },
        "identity": {
            "suspended": {
                "process_id": "process-1",
                "process_tree_id": "tree-1",
                "job_id": "job-1",
                "image_id": "image-1",
                "session_id": "session-1",
                "generation": 1,
                "physical": {
                    "process_id": 1,
                    "start_time_100ns": 1,
                    "image_path": "C:\\ProgramData\\Eliot\\bin\\eliot-test.exe",
                    "executor_job_name": "Local\\Eliot-ORS-Test"
                },
                "created_suspended_at_unix_ms": 1,
                "executable_sha256": "aa".repeat(32)
            },
            "resumed_at_unix_ms": 2
        },
        "lifecycle": "running"
    }))?)
}

#[test]
fn process_evidence_appends_history_idempotently_and_recovers_in_order() -> TestResult {
    let path = database_path("process-evidence-history");
    let store = RedbRecoveryStore::open(&path)?;
    let operation_id = OperationIdentity::new("process-evidence-operation")?;
    let first = process_evidence_record(operation_id.as_str(), "running", 100)?;
    let second = process_evidence_record(operation_id.as_str(), "exited", 200)?;

    assert_ne!(first.record_key()?, second.record_key()?);
    store.persist_process_evidence(&first)?;
    store.persist_process_evidence(&second)?;
    store.persist_process_evidence(&first)?;
    assert_eq!(
        store.load_process_evidence(&operation_id)?,
        vec![
            ProcessEvidenceReadback::Observation(Box::new(first.clone())),
            ProcessEvidenceReadback::Observation(Box::new(second.clone())),
        ]
    );

    let mut conflicting = first.clone();
    conflicting.owner = eliot_process::ProcessOwnerBinding::new(
        "native",
        conflicting.owner.principal_digest(),
        conflicting.owner.authority_epoch().clone(),
        conflicting.owner.generation(),
    )?;
    assert_eq!(conflicting.record_key()?, first.record_key()?);
    assert!(matches!(
        store.persist_process_evidence(&conflicting),
        Err(OrsError::IntegrityProblem { .. })
    ));
    assert_eq!(
        store.load_process_evidence(&operation_id)?,
        vec![
            ProcessEvidenceReadback::Observation(Box::new(first.clone())),
            ProcessEvidenceReadback::Observation(Box::new(second.clone())),
        ]
    );
    let mut mismatched = first.clone();
    mismatched.operation_id = OperationIdentity::new("other-operation")?;
    assert!(matches!(
        store.persist_process_evidence(&mismatched),
        Err(OrsError::IntegrityProblem { .. })
    ));
    for (field, value) in [
        ("process_tree_id", "other-tree"),
        ("job_id", "other-job"),
        ("image_id", "other-image"),
        ("session_id", "other-session"),
    ] {
        let mut mismatched = first.clone();
        match field {
            "process_tree_id" => mismatched.process_tree_id = OpaqueLabel::new(value)?,
            "job_id" => mismatched.job_id = OpaqueLabel::new(value)?,
            "image_id" => mismatched.image_id = OpaqueLabel::new(value)?,
            "session_id" => mismatched.session_id = OpaqueLabel::new(value)?,
            _ => unreachable!(),
        }
        assert!(matches!(
            store.persist_process_evidence(&mismatched),
            Err(OrsError::IntegrityProblem { .. })
        ));
    }

    let mut escalated = first.clone();
    let mut escalated_wire = serde_json::to_value(&escalated.evidence)?;
    escalated_wire["axes"]["status"] = json!("VERIFIED");
    escalated.evidence = serde_json::from_value(escalated_wire)?;
    assert!(matches!(
        store.persist_process_evidence(&escalated),
        Err(OrsError::IntegrityProblem { .. })
    ));

    let tampered_path = database_path("process-evidence-verified-readback");
    let tampered_store = RedbRecoveryStore::open(&tampered_path)?;
    let mut tampered = first.clone();
    let mut tampered_wire = serde_json::to_value(&tampered.evidence)?;
    tampered_wire["axes"]["status"] = json!("VERIFIED");
    tampered.evidence = serde_json::from_value(tampered_wire)?;
    tampered.evidence_digest = sha256_hex(&serde_json::to_vec(&tampered.evidence)?);
    let first_key = first.record_key()?;
    tampered_store.write_process_evidence_raw_for_test(&first_key, &tampered)?;
    assert!(matches!(
        tampered_store.load_process_evidence(&operation_id),
        Err(OrsError::IntegrityProblem { .. })
    ));
    drop(tampered_store);
    let reopened_tampered = RedbRecoveryStore::open(&tampered_path)?;
    assert!(matches!(
        reopened_tampered.load_process_evidence(&operation_id),
        Err(OrsError::IntegrityProblem { .. })
    ));
    cleanup(&tampered_path);

    drop(store);
    let reopened = RedbRecoveryStore::open(&path)?;
    assert_eq!(
        reopened.load_process_evidence(&operation_id)?,
        vec![
            ProcessEvidenceReadback::Observation(Box::new(first)),
            ProcessEvidenceReadback::Observation(Box::new(second)),
        ]
    );
    cleanup(&path);
    Ok(())
}

#[test]
fn process_evidence_readback_rejects_noncanonical_raw_key_suffix() -> TestResult {
    let path = database_path("process-evidence-canonical-key");
    let store = RedbRecoveryStore::open(&path)?;
    let operation_id = OperationIdentity::new("process-evidence-canonical-operation")?;
    let record = process_evidence_record(operation_id.as_str(), "running", 100)?;
    let canonical = record.record_key()?;
    let tampered = format!("{}::{}", operation_id.as_str(), "0".repeat(64));
    assert_ne!(tampered, canonical);
    store.write_process_evidence_raw_for_test(&tampered, &record)?;
    assert!(matches!(
        store.load_process_evidence(&operation_id),
        Err(OrsError::IntegrityProblem { .. })
    ));
    cleanup(&path);
    Ok(())
}

#[test]
fn process_evidence_raw_wire_handles_colon_percent_siblings_mixed_rows_and_endpoint() -> TestResult
{
    let path = database_path("process-evidence-raw-prefix");
    let store = RedbRecoveryStore::open(&path)?;
    let operation_id = OperationIdentity::new("process:evidence%target")?;
    let sibling_id = OperationIdentity::new("process:evidence%target::sibling")?;
    let record = process_evidence_record(operation_id.as_str(), "running", 100)?;
    let sibling = process_evidence_record(sibling_id.as_str(), "running", 200)?;
    store.persist_process_evidence(&record)?;
    store.persist_process_evidence(&sibling)?;
    assert_eq!(
        store.load_process_evidence(&operation_id)?,
        vec![ProcessEvidenceReadback::Observation(Box::new(
            record.clone()
        ))]
    );
    assert_eq!(
        store.load_process_evidence(&sibling_id)?,
        vec![ProcessEvidenceReadback::Observation(Box::new(sibling))]
    );

    let mixed_path = database_path("process-evidence-encoded-mixed");
    let mixed_store = RedbRecoveryStore::open(&mixed_path)?;
    mixed_store.persist_process_evidence(&record)?;
    let canonical_key = record.record_key()?;
    let raw_prefix = format!("{}::", operation_id.as_str());
    let suffix = canonical_key
        .strip_prefix(raw_prefix.as_str())
        .ok_or("raw process-evidence key prefix")?;
    let encoded_operation = operation_id
        .as_str()
        .replace('%', "%25")
        .replace(':', "%3A");
    let encoded_key = format!("{encoded_operation}::{suffix}");
    mixed_store.write_process_evidence_raw_for_test(&encoded_key, &record)?;
    assert!(matches!(
        mixed_store.load_process_evidence(&operation_id),
        Err(OrsError::IntegrityProblem { .. })
    ));
    cleanup(&mixed_path);

    let endpoint_path = database_path("process-evidence-prefix-endpoint");
    let endpoint_store = RedbRecoveryStore::open(&endpoint_path)?;
    let endpoint_key = format!("{raw_prefix}\u{10ffff}");
    endpoint_store.write_process_evidence_raw_for_test(&endpoint_key, &record)?;
    assert!(matches!(
        endpoint_store.load_process_evidence(&operation_id),
        Err(OrsError::IntegrityProblem { .. })
    ));
    cleanup(&endpoint_path);
    cleanup(&path);
    Ok(())
}

#[test]
fn authority_handoff_is_typed_one_shot_and_survives_restart() -> TestResult {
    let path = database_path("authority-handoff");
    let store = RedbRecoveryStore::open(&path)?;
    let reserved = handoff_record(AuthorityHandoffState::Reserved)?;
    assert!(matches!(
        store.begin_authority_handoff(&reserved)?,
        AuthorityHandoffBegin::Acquired
    ));
    assert!(matches!(
        store.begin_authority_handoff(&reserved)?,
        AuthorityHandoffBegin::Existing(_)
    ));
    let consumed = handoff_record(AuthorityHandoffState::Consumed)?;
    store.persist_authority_handoff(&consumed)?;
    assert!(store.persist_authority_handoff(&reserved).is_err());
    drop(store);
    let reopened = RedbRecoveryStore::open(&path)?;
    assert_eq!(
        reopened
            .load_authority_handoff(&reserved.handoff_id)?
            .ok_or("handoff restart")?
            .state,
        AuthorityHandoffState::Consumed
    );
    cleanup(&path);
    Ok(())
}

#[test]
fn authority_handoff_terminal_consume_can_follow_expired_admission() -> TestResult {
    let path = database_path("authority-handoff-expired-admission");
    let store = RedbRecoveryStore::open(&path)?;
    let reserved = handoff_record(AuthorityHandoffState::Reserved)?;
    assert!(matches!(
        store.begin_authority_handoff(&reserved)?,
        AuthorityHandoffBegin::Acquired
    ));
    let consumed = AuthorityHandoffRecord {
        state: AuthorityHandoffState::Consumed,
        consumed_at_ms: Some(250),
        ..reserved.clone()
    };
    store.persist_authority_handoff(&consumed)?;
    assert_eq!(
        store
            .load_authority_handoff(&reserved.handoff_id)?
            .ok_or("expired-admission handoff")?
            .state,
        AuthorityHandoffState::Consumed
    );
    assert!(
        store
            .persist_authority_handoff(&AuthorityHandoffRecord {
                state: AuthorityHandoffState::Unknown,
                reconciliation_evidence: Some(OpaqueLabel::new("must-not-demote")?),
                ..consumed
            })
            .is_err()
    );
    cleanup(&path);
    Ok(())
}

#[test]
fn authority_handoff_freshness_is_checked_at_begin_without_reserved_race() -> TestResult {
    let path = database_path("authority-handoff-freshness-race");
    cleanup(&path);
    let store = Arc::new(RedbRecoveryStore::open(&path)?);
    let mut expired = handoff_record(AuthorityHandoffState::Reserved)?;
    expired.handoff_id = OperationIdentity::new("authority-handoff-expired-race")?;
    expired.issued_at_ms = 100;
    expired.expires_at_ms = 200;
    let mut future = expired.clone();
    future.handoff_id = OperationIdentity::new("authority-handoff-future-race")?;
    future.issued_at_ms = 201;
    future.expires_at_ms = 300;

    let barrier = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let record = expired.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            matches!(
                store.begin_authority_handoff_at(&record, 200),
                Err(OrsError::AuthorityHandoffNotFresh)
            )
        }));
    }
    for worker in workers {
        assert!(
            worker
                .join()
                .map_err(|_| "expired freshness worker panicked")?
        );
    }
    assert!(store.load_authority_handoff(&expired.handoff_id)?.is_none());
    assert!(matches!(
        store.begin_authority_handoff_at(&future, 200),
        Err(OrsError::AuthorityHandoffNotFresh)
    ));
    assert!(store.load_authority_handoff(&future.handoff_id)?.is_none());
    drop(store);
    cleanup(&path);
    Ok(())
}

#[test]
fn authority_snapshot_cas_updates_same_record_and_rejects_stale_history_writer() -> TestResult {
    let path = database_path("authority-snapshot-cas");
    cleanup(&path);
    let store = RedbRecoveryStore::open(&path)?;
    let lineage = epoch("authority-cas-lineage", 1)?;
    let initial = KernelAuthoritySnapshot::new(operational_input(
        "authority-snapshot-cas-record",
        "authority-snapshot-cas",
        lineage.clone(),
        "replay-revision-1",
    )?)?;
    let initial_receipt = store.commit_authority_snapshot(initial)?;
    let next = KernelAuthoritySnapshot::new(operational_input(
        "authority-snapshot-cas-record",
        "authority-snapshot-cas",
        lineage,
        "replay-revision-2",
    )?)?;
    let expected_payload = next.record().payload.clone();
    let stale_candidate = next.clone();
    let next_receipt = store.commit_authority_snapshot_cas(next, Some(&initial_receipt))?;
    assert!(next_receipt.receipt().operation_order() > initial_receipt.receipt().operation_order());
    assert!(matches!(
        store.commit_authority_snapshot_cas(stale_candidate, Some(&initial_receipt)),
        Err(OrsError::DuplicateConflict)
    ));
    let current = store
        .load_authority_snapshot(&OperationIdentity::new("authority-snapshot-cas")?)?
        .ok_or("current authority snapshot")?;
    assert_eq!(current.receipt(), &next_receipt);
    assert_eq!(current.snapshot().record().payload, expected_payload);
    let forensic = store.logical_snapshot(OrsSnapshotRequest::new(0, 64, 500)?)?;
    assert!(forensic.entry_refs().len() >= 2);
    drop(store);
    let reopened = RedbRecoveryStore::open(&path)?;
    let restarted = reopened
        .load_authority_snapshot(&OperationIdentity::new("authority-snapshot-cas")?)?
        .ok_or("restarted authority snapshot")?;
    assert_eq!(restarted.receipt(), &next_receipt);
    cleanup(&path);
    Ok(())
}

#[test]
fn multi_scope_reservation_is_atomic_ordered_and_conflict_on_duplicate() -> TestResult {
    let path = database_path("atomic");
    cleanup(&path);
    let coordinator = coordinator(&path)?;
    let writer_epoch = epoch(TEST_LINEAGE_A, 7)?;
    let original = request(
        "reservation-a",
        "operation-a",
        writer_epoch.clone(),
        &["scope-b", "scope-a"],
    )?;
    let token = coordinator.reserve(original.clone())?;
    assert_eq!(token.scopes[0].scope.as_str(), "scope-a");
    assert_eq!(token.scopes[1].scope.as_str(), "scope-b");
    assert_eq!(coordinator.reserve(original.clone())?, token);

    let mut conflict = original;
    conflict.prepared_transition_sha256 = "22".repeat(32);
    assert!(matches!(
        coordinator.reserve(conflict),
        Err(OrsError::DuplicateConflict)
    ));

    let second = coordinator.reserve(request(
        "reservation-b",
        "operation-b",
        writer_epoch.clone(),
        &["scope-a"],
    )?)?;
    assert!(second.reservation_order > token.reservation_order);
    assert_eq!(second.scopes[0].reserved_sequence, 2);
    assert!(matches!(
        coordinator.eligible(&second),
        Err(OrsError::PredecessorPending)
    ));
    coordinator.release(&token, &writer_epoch.current)?;
    coordinator.eligible(&second)?;

    let wrong_epoch = epoch(TEST_LINEAGE_B, 1)?;
    let failed = request(
        "reservation-failed",
        "operation-failed",
        wrong_epoch.clone(),
        &["scope-a", "scope-new"],
    )?;
    assert!(matches!(
        coordinator.reserve(failed),
        Err(OrsError::StaleWriterEpoch)
    ));
    let new_only = coordinator.reserve(request(
        "reservation-new",
        "operation-new",
        wrong_epoch,
        &["scope-new"],
    )?)?;
    assert_eq!(new_only.scopes[0].reserved_sequence, 1);

    drop(coordinator);
    cleanup(&path);
    Ok(())
}

#[test]
fn crash_restart_enters_reconciliation_and_receipt_unblocks_scope() -> TestResult {
    let path = database_path("restart");
    cleanup(&path);
    let writer_epoch = epoch(TEST_LINEAGE_A, 7)?;
    let token = {
        let coordinator = coordinator(&path)?;
        let token = coordinator.reserve(request(
            "reservation-a",
            "operation-a",
            writer_epoch.clone(),
            &["scope-a"],
        )?)?;
        coordinator.eligible(&token)?;
        coordinator.execute(&token, &writer_epoch.current)?;
        token
    };

    let coordinator = coordinator(&path)?;
    let page = coordinator
        .store()
        .recover_page(RecoveryCursor::new(0, 1)?)?;
    assert_eq!(page.records[0].state, ReservationState::Reconciling);
    assert!(matches!(
        coordinator.execute(&token, &writer_epoch.current),
        Err(OrsError::InvalidTransition)
    ));
    assert!(matches!(
        coordinator.reserve(request(
            "reservation-b",
            "operation-b",
            writer_epoch.clone(),
            &["scope-a"]
        )?),
        Err(OrsError::ScopeRecoveryRequired)
    ));

    let canonical_receipt = receipt(&token, &success_disposition())?;
    let exact = reconciliation(&token, canonical_receipt, CanonicalDisposition::Committed)?;
    let finalized = coordinator.reconcile(&exact)?;
    assert_eq!(finalized.state, ReservationState::Finalized);
    let mut next = request(
        "reservation-c",
        "operation-c",
        writer_epoch.clone(),
        &["scope-a"],
    )?;
    next.scopes[0].expected_head = ExpectedOrderingHead {
        sequence: token.scopes[0].reserved_sequence,
        head_sha256: exact.receipt.identity.canonical_sha256.clone(),
        revision_head: exact.scopes[0].committed_revision_head.clone(),
    };
    coordinator.reserve(next)?;

    drop(coordinator);
    cleanup(&path);
    Ok(())
}

#[test]
fn unknown_outcome_has_no_blind_replay_or_cleanup_expiry() -> TestResult {
    let path = database_path("unknown");
    cleanup(&path);
    let coordinator = coordinator(&path)?;
    let writer_epoch = epoch(TEST_LINEAGE_A, 7)?;
    let token = coordinator.reserve(request(
        "reservation-a",
        "operation-a",
        writer_epoch.clone(),
        &["scope-a"],
    )?)?;
    coordinator.eligible(&token)?;
    coordinator.execute(&token, &writer_epoch.current)?;
    coordinator.unknown(
        &token,
        &writer_epoch.current,
        label("commit visibility unavailable")?,
    )?;
    assert!(matches!(
        coordinator.execute(&token, &writer_epoch.current),
        Err(OrsError::InvalidTransition)
    ));
    assert!(matches!(
        coordinator
            .store()
            .expire(&token, 2_000, &token.recovery_owner),
        Err(OrsError::UnsafeExpiry)
    ));

    let canonical_receipt = receipt(&token, &success_disposition())?;
    let mut mismatch = reconciliation(
        &token,
        canonical_receipt.clone(),
        CanonicalDisposition::Committed,
    )?;
    mismatch.scopes[0].committed_sequence += 1;
    assert!(matches!(
        coordinator.reconcile(&mismatch),
        Err(OrsError::ReconciliationMismatch)
    ));
    let exact = reconciliation(&token, canonical_receipt, CanonicalDisposition::Committed)?;
    let mut wrong_owner = exact.clone();
    wrong_owner.recovery_owner = label("other-recovery-owner")?;
    assert!(matches!(
        coordinator.reconcile(&wrong_owner),
        Err(OrsError::ReconciliationMismatch)
    ));
    coordinator.reconcile(&exact)?;

    drop(coordinator);
    cleanup(&path);
    Ok(())
}

#[test]
fn lineage_fences_old_owner_and_requires_recovery() -> TestResult {
    let path = database_path("lineage");
    cleanup(&path);
    let coordinator = coordinator(&path)?;
    let old = epoch(TEST_LINEAGE_A, 7)?;
    let token = coordinator.reserve(request(
        "reservation-a",
        "operation-a",
        old.clone(),
        &["scope-a"],
    )?)?;
    coordinator.eligible(&token)?;
    let next = successor(&old.current, "lineage-b", 1)?;
    coordinator
        .store()
        .fence_writer_epoch(&[label("scope-a")?], &next)?;
    assert!(matches!(
        coordinator.release(&token, &old.current),
        Err(OrsError::InvalidTransition)
    ));
    assert!(matches!(
        coordinator.reserve(request(
            "reservation-b",
            "operation-b",
            next.clone(),
            &["scope-a"]
        )?),
        Err(OrsError::ScopeRecoveryRequired)
    ));
    let unrelated = successor(
        &EpochIdentity {
            lineage_id: label("unrelated")?,
            epoch: 9,
        },
        "lineage-c",
        1,
    )?;
    assert!(matches!(
        coordinator
            .store()
            .fence_writer_epoch(&[label("scope-a")?], &unrelated),
        Err(OrsError::InvalidEpochLineage)
    ));

    drop(coordinator);
    cleanup(&path);
    Ok(())
}

#[test]
fn recovery_cursor_is_bounded_and_expiry_requires_owner() -> TestResult {
    let path = database_path("cursor");
    cleanup(&path);
    let coordinator = coordinator(&path)?;
    let writer_epoch = epoch(TEST_LINEAGE_A, 7)?;
    let first = coordinator.reserve(request(
        "reservation-1",
        "operation-1",
        writer_epoch.clone(),
        &["scope-1"],
    )?)?;
    coordinator.reserve(request(
        "reservation-2",
        "operation-2",
        writer_epoch.clone(),
        &["scope-2"],
    )?)?;
    coordinator.reserve(request(
        "reservation-3",
        "operation-3",
        writer_epoch,
        &["scope-3"],
    )?)?;
    let page = coordinator
        .store()
        .recover_page(RecoveryCursor::new(0, 2)?)?;
    assert_eq!(page.records.len(), 2);
    let next = page.next_after_order.ok_or("missing bounded cursor")?;
    let tail = coordinator
        .store()
        .recover_page(RecoveryCursor::new(next, 2)?)?;
    assert_eq!(tail.records.len(), 1);
    assert!(matches!(
        RecoveryCursor::new(0, MAX_RECOVERY_PAGE + 1),
        Err(OrsError::InvalidCursorLimit)
    ));
    assert!(matches!(
        coordinator.store().expire(&first, 2_000, &label("other")?),
        Err(OrsError::RecoveryOwnerMismatch)
    ));
    assert!(matches!(
        coordinator
            .store()
            .expire(&first, 2_000, &first.recovery_owner),
        Err(OrsError::UnsafeExpiry)
    ));
    coordinator.release(&first, &first.writer_epoch.current)?;
    assert_eq!(
        coordinator
            .store()
            .expire(&first, 2_000, &first.recovery_owner)?
            .state,
        ReservationState::Released
    );
    assert!(
        coordinator
            .store()
            .get_envelope(&first.operation_id)?
            .is_none()
    );

    drop(coordinator);
    cleanup(&path);
    Ok(())
}

#[test]
fn canonical_head_readback_blocks_jump_and_preserves_predecessor_fairness() -> TestResult {
    let path = database_path("head-binding");
    cleanup(&path);
    let coordinator = coordinator_with_evidence(&path, Arc::new(GenesisHeadEvidence))?;
    let writer_epoch = epoch(TEST_LINEAGE_A, 7)?;
    let mut fabricated = request(
        "reservation-fabricated",
        "operation-fabricated",
        writer_epoch.clone(),
        &["scope-a"],
    )?;
    fabricated.scopes[0].expected_head.sequence = 999;
    assert!(matches!(
        coordinator.reserve(fabricated),
        Err(OrsError::CanonicalEvidence(_))
    ));

    let first = coordinator.reserve(request(
        "reservation-first",
        "operation-first",
        writer_epoch.clone(),
        &["scope-a"],
    )?)?;
    let second = coordinator.reserve(request(
        "reservation-second",
        "operation-second",
        writer_epoch.clone(),
        &["scope-a"],
    )?)?;
    assert_eq!(first.scopes[0].reserved_sequence, 1);
    assert_eq!(second.scopes[0].reserved_sequence, 2);
    assert!(matches!(
        coordinator.eligible(&second),
        Err(OrsError::PredecessorPending)
    ));

    let disjoint = coordinator.reserve(request(
        "reservation-disjoint",
        "operation-disjoint",
        writer_epoch.clone(),
        &["scope-b"],
    )?)?;
    coordinator.eligible(&disjoint)?;

    coordinator.eligible(&first)?;
    coordinator.execute(&first, &writer_epoch.current)?;
    let rejected_receipt = receipt(
        &first,
        &json!({"kind": "CANCELLED", "reason": "canonical rejection fixture"}),
    )?;
    let rejected = reconciliation(&first, rejected_receipt, CanonicalDisposition::Rejected)?;
    coordinator.reconcile(&rejected)?;
    let gap = coordinator
        .store()
        .scope_terminal(&label("scope-a")?, 1)?
        .ok_or("missing terminal gap")?;
    assert!(gap.is_gap());
    assert_eq!(gap.disposition(), CanonicalDisposition::Rejected);
    coordinator.eligible(&second)?;

    drop(coordinator);
    cleanup(&path);
    Ok(())
}

#[test]
fn reservation_order_and_scope_sequences_hold_over_generated_matrix() -> TestResult {
    let path = database_path("reservation-property");
    cleanup(&path);
    let coordinator = coordinator(&path)?;
    let writer_epoch = epoch("lineage-property", 9)?;
    let mut last_order = 0;
    let mut per_scope = [0_u64; 8];
    for index in 0..64 {
        let scope_index = index % per_scope.len();
        let scope = format!("scope-property-{scope_index}");
        let request = request(
            &format!("reservation-property-{index}"),
            &format!("operation-property-{index}"),
            writer_epoch.clone(),
            &[scope.as_str()],
        )?;
        let token = coordinator.reserve(request.clone())?;
        per_scope[scope_index] += 1;
        assert_eq!(token.scopes[0].reserved_sequence, per_scope[scope_index]);
        assert!(token.reservation_order > last_order);
        last_order = token.reservation_order;
        assert_eq!(coordinator.reserve(request)?, token);
    }
    let mut cursor = 0;
    let mut recovered = 0;
    loop {
        let page = coordinator
            .store()
            .recover_page(RecoveryCursor::new(cursor, 7)?)?;
        recovered += page.records.len();
        let Some(next) = page.next_after_order else {
            break;
        };
        assert!(next > cursor);
        cursor = next;
    }
    assert_eq!(recovered, 64);
    drop(coordinator);
    cleanup(&path);
    Ok(())
}

#[test]
fn caller_issued_receipt_cannot_finalize_without_injected_readback() -> TestResult {
    let path = database_path("readback-auth");
    cleanup(&path);
    let writer_epoch = epoch(TEST_LINEAGE_A, 7)?;
    let token;
    let exact;
    {
        let coordinator = coordinator_with_evidence(&path, Arc::new(RejectReadbackEvidence))?;
        token = coordinator.reserve(request(
            "reservation-a",
            "operation-a",
            writer_epoch.clone(),
            &["scope-a"],
        )?)?;
        coordinator.eligible(&token)?;
        coordinator.execute(&token, &writer_epoch.current)?;
        let caller_issued = receipt(&token, &success_disposition())?;
        exact = reconciliation(&token, caller_issued, CanonicalDisposition::Committed)?;
        assert!(matches!(
            coordinator.reconcile(&exact),
            Err(OrsError::CanonicalEvidence(_))
        ));
        assert_eq!(
            coordinator
                .store()
                .recover_page(RecoveryCursor::new(0, 1)?)?
                .records[0]
                .state,
            ReservationState::Executing
        );
    }
    let coordinator = coordinator(&path)?;
    assert_eq!(
        coordinator.reconcile(&exact)?.state,
        ReservationState::Finalized
    );
    drop(coordinator);
    cleanup(&path);
    Ok(())
}

#[test]
fn persisted_invalid_label_and_envelope_digest_fail_closed() -> TestResult {
    let path = database_path("corrupt-record");
    cleanup(&path);
    let stored;
    {
        let coordinator = coordinator(&path)?;
        coordinator.reserve(request(
            "reservation-a",
            "operation-a",
            epoch(TEST_LINEAGE_A, 7)?,
            &["scope-a"],
        )?)?;
        stored = coordinator
            .store()
            .recover_page(RecoveryCursor::new(0, 1)?)?
            .records
            .into_iter()
            .next()
            .ok_or("missing reservation")?;
    }
    let database = redb::Database::create(&path)?;
    let write = database.begin_write()?;
    {
        let definition: redb::TableDefinition<&str, &str> =
            redb::TableDefinition::new("ors_reservations_v1");
        let mut table = write.open_table(definition)?;
        let mut invalid = serde_json::to_value(&stored)?;
        invalid["token"]["reservation_id"] = json!("");
        let encoded = serde_json::to_string(&invalid)?;
        table.insert(stored.token.reservation_id.as_str(), encoded.as_str())?;
    }
    write.commit()?;
    drop(database);
    assert!(matches!(
        coordinator(&path),
        Err(OrsError::IntegrityProblem {
            record_type: "reservation",
            ..
        })
    ));
    cleanup(&path);

    let envelope_path = database_path("corrupt-envelope");
    cleanup(&envelope_path);
    let operation_id;
    {
        let coordinator = coordinator(&envelope_path)?;
        let token = coordinator.reserve(request(
            "reservation-b",
            "operation-b",
            epoch(TEST_LINEAGE_A, 7)?,
            &["scope-b"],
        )?)?;
        operation_id = token.operation_id;
    }
    let database = redb::Database::create(&envelope_path)?;
    let write = database.begin_write()?;
    {
        let definition: redb::TableDefinition<&str, &str> =
            redb::TableDefinition::new("ors_envelopes_v1");
        let mut table = write.open_table(definition)?;
        let value = table
            .get(operation_id.as_str())?
            .ok_or("missing envelope")?;
        let mut invalid: Value = serde_json::from_str(value.value())?;
        drop(value);
        invalid["payload_sha256"] = json!("00".repeat(32));
        let encoded = serde_json::to_string(&invalid)?;
        table.insert(operation_id.as_str(), encoded.as_str())?;
    }
    write.commit()?;
    drop(database);
    let coordinator = coordinator(&envelope_path)?;
    assert!(matches!(
        coordinator.store().get_envelope(&operation_id),
        Err(OrsError::IntegrityProblem {
            record_type: "recovery_envelope",
            ..
        })
    ));
    drop(coordinator);
    cleanup(&envelope_path);
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one focused fixture covers commit, restart recovery, admission pinning, and receipt fields"
)]
fn cutover_ownership_commit_is_durable_linearization_point() -> TestResult {
    // I14.14 acceptance (issue #1950): after a committed module cutover and a
    // forced restart, a new request in the affected route scope is admitted
    // only to the recorded candidate generation with the recorded new epoch;
    // an old-generation request not named in the committed in-flight
    // disposition set is rejected as stale; a candidate crash before commit
    // leaves new admission routed away from the candidate.
    let path = database_path("cutover-ownership-acceptance");
    cleanup(&path);
    let scope = CapabilityRouteScope::declare("mod-a", "serve", "work", "effects")?;
    let hash = scope.route_scope_hash.clone();
    let candidate = ModuleArtifactIdentity {
        module_id: "mod-a".to_owned(),
        semver: "1.2.0".to_owned(),
        artifact_hash: "a".repeat(64),
        manifest_digest: "c".repeat(64),
        layout_root: format!("modules/mod-a/1.2.0/{}", "a".repeat(64)),
    };
    let incumbent = ModuleArtifactIdentity {
        module_id: "mod-a".to_owned(),
        semver: "1.1.0".to_owned(),
        artifact_hash: "b".repeat(64),
        manifest_digest: "d".repeat(64),
        layout_root: format!("modules/mod-a/1.1.0/{}", "b".repeat(64)),
    };
    let genesis = GenerationCutoverOwnership {
        cutover_id: "cutover-ownership-genesis".to_owned(),
        candidate_artifact: incumbent.clone(),
        incumbent_artifact: None,
        scope: scope.clone(),
        old_generation: None,
        new_generation: ResourceGeneration::new(1)?,
        old_epoch: AuthorityEpoch::new(1)?,
        new_epoch: AuthorityEpoch::new(2)?,
        in_flight: Vec::new(),
        migration: StateMigrationDecision::RetainCompatible,
        health_proof_ref: "health-proof-genesis".to_owned(),
        rollback_boundary: "forward-only".to_owned(),
        unresolved_scopes: Vec::new(),
        linearization_record_id: None,
        state: GenerationCutoverState::Armed,
    };
    let cutover = GenerationCutoverOwnership {
        cutover_id: "cutover-ownership-1".to_owned(),
        candidate_artifact: candidate.clone(),
        incumbent_artifact: Some(incumbent.clone()),
        scope: scope.clone(),
        old_generation: Some(ResourceGeneration::new(1)?),
        new_generation: ResourceGeneration::new(2)?,
        old_epoch: AuthorityEpoch::new(2)?,
        new_epoch: AuthorityEpoch::new(3)?,
        in_flight: vec![InFlightDisposition {
            operation_id: "op-drain".to_owned(),
            kind: InFlightDispositionKind::DrainRead,
        }],
        migration: StateMigrationDecision::CheckpointTransfer,
        health_proof_ref: "health-proof-1".to_owned(),
        rollback_boundary: incumbent.layout_root.clone(),
        unresolved_scopes: vec!["op-unknown".to_owned()],
        linearization_record_id: None,
        state: GenerationCutoverState::Armed,
    };
    // A second scope stages a candidate that never commits: the pre-commit
    // crash case. It must never become active.
    let staged_only = GenerationCutoverOwnership {
        cutover_id: "cutover-ownership-staged-only".to_owned(),
        candidate_artifact: ModuleArtifactIdentity {
            module_id: "mod-b".to_owned(),
            semver: "1.2.0".to_owned(),
            artifact_hash: "e".repeat(64),
            manifest_digest: "f".repeat(64),
            layout_root: format!("modules/mod-b/1.2.0/{}", "e".repeat(64)),
        },
        incumbent_artifact: None,
        scope: CapabilityRouteScope::declare("mod-b", "serve", "work", "effects")?,
        old_generation: None,
        new_generation: ResourceGeneration::new(4)?,
        old_epoch: AuthorityEpoch::new(3)?,
        new_epoch: AuthorityEpoch::new(4)?,
        in_flight: Vec::new(),
        migration: StateMigrationDecision::RetainCompatible,
        health_proof_ref: "health-proof-staged".to_owned(),
        rollback_boundary: "forward-only".to_owned(),
        unresolved_scopes: Vec::new(),
        linearization_record_id: None,
        state: GenerationCutoverState::Armed,
    };
    let staged_hash = staged_only.scope.route_scope_hash.clone();

    let (committed, receipt) = {
        let store = RedbRecoveryStore::open(&path)?;
        store.stage_cutover_ownership(genesis)?;
        store.commit_cutover_ownership("cutover-ownership-genesis")?;
        store.stage_cutover_ownership(cutover)?;
        // While staged, the candidate is durable but inactive: no committed
        // row exists for the scope, so the snapshot admits nothing there.
        let snapshot = CutoverRouteSnapshot::rebuild(
            &store.latest_committed_cutover_ownership(MAX_RECOVERY_PAGE)?,
        )?;
        assert_eq!(
            snapshot.admit(
                &hash,
                ResourceGeneration::new(2)?,
                AuthorityEpoch::new(3)?,
                "op-new"
            ),
            CutoverAdmission::RejectStale
        );
        store.stage_cutover_ownership(staged_only)?;
        store.commit_cutover_ownership("cutover-ownership-1")
    }?;
    assert_eq!(committed.state, GenerationCutoverState::Committed);
    assert!(
        committed
            .linearization_record_id
            .as_deref()
            .unwrap_or_default()
            .starts_with("ors:cutover-ownership:cutover-ownership-1#")
    );
    // The receipt records every required I14.14 field from the commit.
    assert_eq!(receipt.cutover_id, "cutover-ownership-1");
    assert_eq!(receipt.old_generation, Some(ResourceGeneration::new(1)?));
    assert_eq!(receipt.new_generation, ResourceGeneration::new(2)?);
    assert_eq!(receipt.old_epoch, AuthorityEpoch::new(2)?);
    assert_eq!(receipt.new_epoch, AuthorityEpoch::new(3)?);
    assert_eq!(receipt.route_scope_hash, hash);
    assert_eq!(
        receipt.migration,
        StateMigrationDecision::CheckpointTransfer
    );
    assert_eq!(receipt.in_flight.len(), 1);
    assert_eq!(receipt.in_flight[0].operation_id, "op-drain");
    assert_eq!(
        receipt.in_flight[0].kind,
        InFlightDispositionKind::DrainRead
    );
    assert_eq!(
        receipt.linearization_record_id,
        committed
            .linearization_record_id
            .clone()
            .ok_or("linearization")?
    );
    assert_eq!(receipt.health_proof_ref, "health-proof-1");
    assert_eq!(receipt.rollback_boundary, incumbent.layout_root);
    assert_eq!(receipt.unresolved_scopes, vec!["op-unknown".to_owned()]);
    assert_eq!(receipt.state, GenerationCutoverState::Committed);

    // Forced restart: drop the store, reopen the same database, and rebuild
    // the route snapshot solely from committed ORS state.
    drop(receipt);
    let table = CutoverRouteTable::new();
    {
        let store = RedbRecoveryStore::open(&path)?;
        let committed_rows = store.latest_committed_cutover_ownership(MAX_RECOVERY_PAGE)?;
        assert_eq!(committed_rows.len(), 2);
        table.swap_committed(CutoverRouteSnapshot::rebuild(&committed_rows)?);
        // The never-committed candidate reconciles to fenced evidence and
        // still cannot activate its scope.
        let fenced = store.reconcile_staged_cutover_ownership(MAX_RECOVERY_PAGE)?;
        assert_eq!(fenced.len(), 1);
        assert_eq!(
            fenced[0].state,
            GenerationCutoverState::FailedRequiresForwardCutover
        );
    }
    // New requests reach the recorded candidate generation and epoch only.
    assert_eq!(
        table.admit(
            &hash,
            ResourceGeneration::new(2)?,
            AuthorityEpoch::new(3)?,
            "op-new"
        ),
        CutoverAdmission::AdmitCandidate
    );
    assert_eq!(
        table.admit(
            &hash,
            ResourceGeneration::new(2)?,
            AuthorityEpoch::new(2)?,
            "op-new"
        ),
        CutoverAdmission::RejectStale
    );
    // The allowlisted pre-cutover operation finishes under its disposition.
    assert_eq!(
        table.admit(
            &hash,
            ResourceGeneration::new(1)?,
            AuthorityEpoch::new(2)?,
            "op-drain"
        ),
        CutoverAdmission::AdmitAllowlistedOld {
            kind: InFlightDispositionKind::DrainRead
        }
    );
    // Old-generation requests outside the committed disposition set are
    // stale, including unresolved scopes, which stay blocked.
    assert_eq!(
        table.admit(
            &hash,
            ResourceGeneration::new(1)?,
            AuthorityEpoch::new(2)?,
            "op-other"
        ),
        CutoverAdmission::RejectStale
    );
    assert_eq!(
        table.admit(
            &hash,
            ResourceGeneration::new(1)?,
            AuthorityEpoch::new(2)?,
            "op-unknown"
        ),
        CutoverAdmission::RejectStale
    );
    // The pre-commit candidate never owned new admission for its scope.
    assert_eq!(
        table.admit(
            &staged_hash,
            ResourceGeneration::new(4)?,
            AuthorityEpoch::new(4)?,
            "op-new"
        ),
        CutoverAdmission::RejectStale
    );

    cleanup(&path);
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one acceptance proof exercises the complete stage, restart, reconcile, and Recovery Problem surface of issue #1925"
)]
fn accept_after_stage_stages_envelope_and_corruption_becomes_recovery_problem() -> TestResult {
    // ACCEPTED_PENDING is observed only after atomic durable staging plus
    // read-back, hash validation, and operation-identity indexing. After a
    // restart the record enumerates, validates, and reconciles by operation
    // identity into its canonical receipt.
    let path = database_path("accept-after-stage");
    cleanup(&path);
    let writer_epoch = epoch(TEST_LINEAGE_A, 7)?;
    let accepted = {
        let coordinator = coordinator(&path)?;
        let accepted = coordinator.accept_after_stage(request(
            "reservation-accepted",
            "operation-accepted",
            writer_epoch.clone(),
            &["scope-accepted"],
        )?)?;
        assert_eq!(AcceptedPending::outcome_label(), "ACCEPTED_PENDING");
        assert!(accepted.reservation_order > 0);
        assert_eq!(
            accepted.prepared_transition_sha256,
            "11".repeat(32),
            "acceptance must stage the complete opaque prepared operation digest"
        );
        accepted
    };
    {
        let coordinator = coordinator(&path)?;
        let page = coordinator
            .store()
            .recover_page(RecoveryCursor::new(0, 8)?)?;
        let staged = page
            .records
            .iter()
            .find(|record| record.token.reservation_id == accepted.reservation_id)
            .ok_or("staged reservation must enumerate after restart")?;
        let envelope = coordinator
            .store()
            .verify_staged_envelope(&accepted.operation_id)?;
        assert_eq!(envelope.operation_or_checkpoint_id, accepted.operation_id);
        coordinator.eligible(&staged.token)?;
        coordinator.execute(&staged.token, &writer_epoch.current)?;
        let canonical_receipt = receipt(&staged.token, &success_disposition())?;
        let exact = reconciliation(
            &staged.token,
            canonical_receipt,
            CanonicalDisposition::Committed,
        )?;
        let finalized = coordinator.reconcile(&exact)?;
        assert_eq!(finalized.state, ReservationState::Finalized);
        assert!(
            coordinator
                .store()
                .load_recovery_problem(&accepted.operation_id)?
                .is_none(),
            "a cleanly staged operation must not carry a Recovery Problem"
        );
    }
    cleanup(&path);

    // A deliberately corrupted staged payload produces a visible durable
    // Recovery Problem and remains available for disposition across restarts
    // instead of being silently dropped.
    let corrupt_path = database_path("accept-after-stage-corrupt");
    cleanup(&corrupt_path);
    let operation_id = {
        let coordinator = coordinator(&corrupt_path)?;
        let accepted = coordinator.accept_after_stage(request(
            "reservation-corrupt",
            "operation-corrupt",
            epoch(TEST_LINEAGE_A, 7)?,
            &["scope-corrupt"],
        )?)?;
        accepted.operation_id
    };
    {
        let database = redb::Database::create(&corrupt_path)?;
        let write = database.begin_write()?;
        {
            let definition: redb::TableDefinition<&str, &str> =
                redb::TableDefinition::new("ors_envelopes_v1");
            let mut table = write.open_table(definition)?;
            let value = table
                .get(operation_id.as_str())?
                .ok_or("missing staged envelope")?;
            let mut invalid: Value = serde_json::from_str(value.value())?;
            drop(value);
            invalid["payload_sha256"] = json!("00".repeat(32));
            let encoded = serde_json::to_string(&invalid)?;
            table.insert(operation_id.as_str(), encoded.as_str())?;
        }
        write.commit()?;
        drop(database);
    }
    {
        let coordinator = coordinator(&corrupt_path)?;
        assert!(matches!(
            coordinator.store().verify_staged_envelope(&operation_id),
            Err(OrsError::RecoveryProblemRetained { .. })
        ));
        let problem = coordinator
            .store()
            .load_recovery_problem(&operation_id)?
            .ok_or("corrupted payload must retain a Recovery Problem")?;
        assert_eq!(problem.kind, RecoveryProblemKind::HashMismatch);
        assert!(!problem.is_resolved());
        let serialized = serde_json::to_value(&problem)?;
        assert!(serialized.get("ciphertext").is_none());
        assert!(serialized.get("payload").is_none());
    }
    {
        let coordinator = coordinator(&corrupt_path)?;
        let retained = coordinator
            .store()
            .load_recovery_problem(&operation_id)?
            .ok_or("Recovery Problem must survive restart")?;
        let owner = retained.recovery_owner.clone();
        assert!(matches!(
            coordinator.store().resolve_recovery_problem(
                &operation_id,
                &label("receipt-terminal-1")?,
                &label("other-recovery-owner")?
            ),
            Err(OrsError::RecoveryOwnerMismatch)
        ));
        let resolved = coordinator.store().resolve_recovery_problem(
            &operation_id,
            &label("receipt-terminal-1")?,
            &owner,
        )?;
        assert!(resolved.is_resolved());
        let replayed = coordinator.store().resolve_recovery_problem(
            &operation_id,
            &label("receipt-terminal-1")?,
            &owner,
        )?;
        assert_eq!(replayed, resolved);
        assert!(
            coordinator
                .store()
                .load_recovery_problem(&operation_id)?
                .is_some(),
            "a disposed problem must remain loadable, never silently deleted"
        );
    }
    cleanup(&corrupt_path);

    // An undecryptable staged payload (missing key) is reported digest-only
    // and retained until explicit disposition. Plaintext fallback is
    // forbidden by construction: the report carries digests, never bytes.
    let undecryptable_path = database_path("accept-after-stage-undecryptable");
    cleanup(&undecryptable_path);
    {
        let coordinator = coordinator(&undecryptable_path)?;
        let authority_epoch = epoch(TEST_LINEAGE_A, 7)?;
        let problem = RecoveryProblem::new(
            label("operation-undecryptable")?,
            None,
            RecoveryProblemKind::MissingKey,
            label("installation key is unavailable")?,
            Some("33".repeat(32)),
            Some("22".repeat(32)),
            authority_epoch.clone(),
            fence(&authority_epoch)?,
            label("kernel-recovery-owner")?,
            10,
        )?;
        let reported = coordinator.store().report_recovery_problem(problem)?;
        assert!(!reported.is_resolved());
        assert_eq!(
            coordinator
                .store()
                .report_recovery_problem(reported.clone())?,
            reported,
            "an exact replay must return the durable problem unchanged"
        );
        let listed = coordinator.store().list_recovery_problems(8)?;
        assert_eq!(listed, vec![reported.clone()]);
        let resolved = coordinator.store().resolve_recovery_problem(
            &reported.operation_or_checkpoint_id,
            &label("receipt-terminal-2")?,
            &reported.recovery_owner,
        )?;
        assert!(resolved.is_resolved());
    }
    cleanup(&undecryptable_path);
    Ok(())
}

// ---------------------------------------------------------------------------
// T9-03 owner-backed durable replay stream (issue #22, M3).
// ---------------------------------------------------------------------------

fn replay_claim_fixture(
    claim_id: &str,
    generation: u64,
    epoch: u64,
    fence_digest: &str,
) -> TestResult<NativeWorkerClaimRecord> {
    Ok(NativeWorkerClaimRecord {
        contract_version: CONTRACT_VERSION,
        claim_id: OperationIdentity::new(claim_id)?,
        registration_id: OpaqueLabel::new("reg-replay-1")?,
        worker_generation: generation,
        parent_job_id: OpaqueLabel::new("parent-replay-1")?,
        task_id: OpaqueLabel::new("task-replay-1")?,
        work_scope_id: OpaqueLabel::new("scope-replay-1")?,
        decision_id: OpaqueLabel::new("decision-replay-1")?,
        attempt_id: OpaqueLabel::new("attempt-replay-1")?,
        operation_id: OpaqueLabel::new("op-replay-1")?,
        route_class: OpaqueLabel::new("route-replay-1")?,
        budget_digest: "b".repeat(64),
        deadline_unix_ms: 1_700_000_500_000,
        fence_digest: fence_digest.to_owned(),
        authority_epoch: epoch,
        binding_digest: "c".repeat(64),
        request_digest: "d".repeat(64),
        executable_binding_digest: String::new(),
        execution_unit_schema_version: 1,
        predecessor_revision: OpaqueLabel::new("predecessor-replay-0")?,
        resource_envelope_digest: "e".repeat(64),
        // This fixture stages a durable row directly, with no presented
        // executable join, so the cell pair and the binding digest are the
        // modelled absent state
        // (`NativeWorkerClaimRecord`: "absent only for legacy requests without
        // that join"; `validate` accepts `(None, None)` and refuses a half-bound
        // pair). ORS preserves the pair opaquely and never derives one, so
        // inventing a cell here would assert a join this fixture never made.
        capability_cell: None,
        capability_cell_registry_digest: None,
        state: NativeWorkerClaimState::Requested,
        receipt_digest: None,
        admitted_at_unix_ms: None,
        commit_order: 0,
    })
}

fn replay_begin_fixture(
    stream_id: &str,
    request_id: &str,
    fingerprint: &str,
    generation: u64,
    epoch: u64,
    fence_digest: &str,
) -> WorkerReplayBegin {
    WorkerReplayBegin {
        stream_id: stream_id.to_owned(),
        request_id: request_id.to_owned(),
        fingerprint: fingerprint.to_owned(),
        producer_generation: generation,
        authority_epoch: epoch,
        fence_digest: fence_digest.to_owned(),
    }
}

fn replay_draft_fixture(
    stream_id: &str,
    request_id: &str,
    generation: u64,
    epoch: u64,
    fence_digest: &str,
    payload: &str,
) -> WorkerReplayDraft {
    WorkerReplayDraft {
        stream_id: stream_id.to_owned(),
        producer_id: "producer-replay-1".to_owned(),
        producer_generation: generation,
        authority_epoch: epoch,
        fence_digest: fence_digest.to_owned(),
        request_id: request_id.to_owned(),
        causal_predecessor_refs: Vec::new(),
        delivery_class: WorkerReplayDeliveryClass::DurableControl,
        ack_required: true,
        payload_type: "test-event".to_owned(),
        payload: payload.to_owned(),
        disposition: ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
        trace_context: BTreeMap::new(),
    }
}

fn replay_ack_fixture(event: &WorkerReplayEvent, phase: WorkerReplayPhase) -> WorkerReplayAck {
    WorkerReplayAck {
        stream_id: event.stream_id.clone(),
        event_id: event.event_id.clone(),
        sequence: event.sequence,
        producer_generation: event.producer_generation,
        authority_epoch: event.authority_epoch,
        fence_digest: event.fence_digest.clone(),
        phase,
    }
}

/// Opens a store, stages one bound claim, and derives its replay stream.
fn open_bound_replay_stream(
    label: &str,
    claim_id: &str,
    generation: u64,
    epoch: u64,
    fence_digest: &str,
) -> TestResult<(PathBuf, RedbRecoveryStore, String)> {
    let path = database_path(label);
    cleanup(&path);
    let store = RedbRecoveryStore::open(&path)?;
    let claim = replay_claim_fixture(claim_id, generation, epoch, fence_digest)?;
    store.stage_native_worker_claim(&claim)?;
    let stream_id = replay_stream_id(&claim.claim_id, generation)?;
    Ok((path, store, stream_id))
}

#[test]
fn worker_replay_stream_id_constructor_matches_claim_generation_shape() -> TestResult {
    let claim_id = OperationIdentity::new("claim-t9-03-1")?;
    assert_eq!(
        replay_stream_id(&claim_id, 1)?.as_str(),
        "claim-t9-03-1/gen-1"
    );
    let (parsed_claim, parsed_generation) = parse_replay_stream_id("claim-t9-03-1/gen-1")?;
    assert_eq!(parsed_claim, claim_id);
    assert_eq!(parsed_generation, 1);
    assert!(replay_stream_id(&claim_id, 0).is_err());
    assert!(parse_replay_stream_id("claim-t9-03-1/1").is_err());
    assert!(parse_replay_stream_id("claim-t9-03-1/gen-0").is_err());
    assert!(parse_replay_stream_id("no-separator").is_err());
    Ok(())
}

#[test]
fn worker_replay_close_reopen_retains_stream_and_cursors() -> TestResult {
    let fence = "a".repeat(64);
    let (path, store, stream_id) =
        open_bound_replay_stream("replay-reopen", "claim-reopen-1", 1, 1, &fence)?;
    assert!(matches!(
        store.lookup_replay_request(&stream_id, "req-reopen-1", "fp-reopen-1")?,
        WorkerReplayRequestDecision::New
    ));
    assert!(matches!(
        store.begin_replay_request(&replay_begin_fixture(
            &stream_id,
            "req-reopen-1",
            "fp-reopen-1",
            1,
            1,
            &fence
        ))?,
        WorkerReplayRequestDecision::New
    ));
    let first = store.append_replay_event(&replay_draft_fixture(
        &stream_id,
        "req-reopen-1",
        1,
        1,
        &fence,
        "first",
    ))?;
    let second = store.append_replay_event(&replay_draft_fixture(
        &stream_id,
        "req-reopen-1",
        1,
        1,
        &fence,
        "second",
    ))?;
    assert_eq!((first.sequence, second.sequence), (1, 2));
    let cursors =
        store.acknowledge_replay_event(&replay_ack_fixture(&first, WorkerReplayPhase::Durable))?;
    assert_eq!((cursors.producer_cursor, cursors.consumer_cursor), (1, 0));
    let cursors =
        store.acknowledge_replay_event(&replay_ack_fixture(&first, WorkerReplayPhase::Applied))?;
    assert_eq!((cursors.producer_cursor, cursors.consumer_cursor), (1, 1));

    drop(store);
    let reopened = RedbRecoveryStore::open(&path)?;
    let replayed = reopened.replay_stream(&stream_id, 0)?;
    assert_eq!(replayed.len(), 2);
    assert_eq!(replayed[0].event_id, first.event_id);
    assert_eq!(replayed[1].event_id, second.event_id);
    assert_eq!(replayed[1].sequence, 2);
    let decision = reopened.lookup_replay_request(&stream_id, "req-reopen-1", "fp-reopen-1")?;
    assert!(
        matches!(decision, WorkerReplayRequestDecision::Replay(ref events) if events.len() == 2)
    );
    // UNKNOWN advances no cursor after reopen either.
    let cursors = reopened
        .acknowledge_replay_event(&replay_ack_fixture(&second, WorkerReplayPhase::Unknown))?;
    assert_eq!((cursors.producer_cursor, cursors.consumer_cursor), (1, 1));

    drop(reopened);
    cleanup(&path);
    Ok(())
}

#[test]
fn worker_replay_identical_draft_keeps_identity_and_sequence() -> TestResult {
    let fence = "b".repeat(64);
    let (path, store, stream_id) =
        open_bound_replay_stream("replay-idempotent", "claim-idem-1", 1, 1, &fence)?;
    assert!(matches!(
        store.begin_replay_request(&replay_begin_fixture(
            &stream_id,
            "req-idem-1",
            "fp-idem-1",
            1,
            1,
            &fence
        ))?,
        WorkerReplayRequestDecision::New
    ));
    let draft = replay_draft_fixture(&stream_id, "req-idem-1", 1, 1, &fence, "same");
    let first = store.append_replay_event(&draft)?;
    let replayed = store.append_replay_event(&draft)?;
    assert_eq!(first.event_id, replayed.event_id);
    assert_eq!(first.sequence, replayed.sequence);
    assert_eq!(replayed.sequence, 1);
    // A retained acquisition is never a fresh request: begin and lookup both
    // report the retained event.
    let decision = store.begin_replay_request(&replay_begin_fixture(
        &stream_id,
        "req-idem-1",
        "fp-idem-1",
        1,
        1,
        &fence,
    ))?;
    assert!(
        matches!(decision, WorkerReplayRequestDecision::Replay(ref events)
            if events.len() == 1 && events[0].event_id == first.event_id)
    );
    let decision = store.lookup_replay_request(&stream_id, "req-idem-1", "fp-idem-1")?;
    assert!(
        matches!(decision, WorkerReplayRequestDecision::Replay(ref events)
            if events.len() == 1 && events[0].sequence == 1)
    );

    drop(store);
    cleanup(&path);
    Ok(())
}

#[test]
fn worker_replay_changed_fingerprint_conflicts_without_overwrite() -> TestResult {
    let fence = "c".repeat(64);
    let (path, store, stream_id) =
        open_bound_replay_stream("replay-conflict", "claim-conflict-1", 1, 1, &fence)?;
    assert!(matches!(
        store.begin_replay_request(&replay_begin_fixture(
            &stream_id,
            "req-conflict-1",
            "fp-original",
            1,
            1,
            &fence
        ))?,
        WorkerReplayRequestDecision::New
    ));
    assert!(matches!(
        store.begin_replay_request(&replay_begin_fixture(
            &stream_id,
            "req-conflict-1",
            "fp-changed",
            1,
            1,
            &fence
        ))?,
        WorkerReplayRequestDecision::Conflict
    ));
    assert!(matches!(
        store.lookup_replay_request(&stream_id, "req-conflict-1", "fp-changed")?,
        WorkerReplayRequestDecision::Conflict
    ));
    // The durable binding is untouched: the original fingerprint still replays.
    assert!(matches!(
        store.lookup_replay_request(&stream_id, "req-conflict-1", "fp-original")?,
        WorkerReplayRequestDecision::Replay(_)
    ));

    drop(store);
    cleanup(&path);
    Ok(())
}

#[test]
fn worker_replay_foreign_ack_rejects_without_moving_cursors() -> TestResult {
    let fence = "d".repeat(64);
    let (path, store, stream_id) =
        open_bound_replay_stream("replay-foreign-ack", "claim-foreign-1", 1, 1, &fence)?;
    store.begin_replay_request(&replay_begin_fixture(
        &stream_id,
        "req-foreign-1",
        "fp-foreign-1",
        1,
        1,
        &fence,
    ))?;
    let event = store.append_replay_event(&replay_draft_fixture(
        &stream_id,
        "req-foreign-1",
        1,
        1,
        &fence,
        "guarded",
    ))?;

    let mut wrong_id = replay_ack_fixture(&event, WorkerReplayPhase::Applied);
    wrong_id.event_id = "evt-foreign".to_owned();
    assert!(matches!(
        store.acknowledge_replay_event(&wrong_id),
        Err(OrsError::WorkerReplayAckMismatch { .. })
    ));

    let mut wrong_sequence = replay_ack_fixture(&event, WorkerReplayPhase::Applied);
    wrong_sequence.sequence = 999;
    assert!(matches!(
        store.acknowledge_replay_event(&wrong_sequence),
        Err(OrsError::WorkerReplayAckMismatch { .. })
    ));

    // A second bound claim owns a disjoint stream: acknowledging the first
    // event there is foreign and rejected.
    let other_claim = replay_claim_fixture("claim-foreign-2", 1, 1, &fence)?;
    store.stage_native_worker_claim(&other_claim)?;
    let other_stream = replay_stream_id(&other_claim.claim_id, 1)?;
    store.begin_replay_request(&replay_begin_fixture(
        &other_stream,
        "req-foreign-2",
        "fp-foreign-2",
        1,
        1,
        &fence,
    ))?;
    let mut foreign_stream = replay_ack_fixture(&event, WorkerReplayPhase::Applied);
    foreign_stream.stream_id = other_stream.clone();
    assert!(matches!(
        store.acknowledge_replay_event(&foreign_stream),
        Err(OrsError::WorkerReplayAckMismatch { .. })
    ));

    // No rejected acknowledgement moved a cursor: an exact ack still lands on
    // the virgin head.
    let cursors =
        store.acknowledge_replay_event(&replay_ack_fixture(&event, WorkerReplayPhase::Durable))?;
    assert_eq!((cursors.producer_cursor, cursors.consumer_cursor), (1, 0));

    drop(store);
    cleanup(&path);
    Ok(())
}

#[test]
fn worker_replay_generation_change_never_relaunches() -> TestResult {
    let fence = "e".repeat(64);
    let (path, store, stream_id) =
        open_bound_replay_stream("replay-generation", "claim-generation-1", 1, 1, &fence)?;
    store.begin_replay_request(&replay_begin_fixture(
        &stream_id,
        "req-generation-1",
        "fp-generation-1",
        1,
        1,
        &fence,
    ))?;
    let event = store.append_replay_event(&replay_draft_fixture(
        &stream_id,
        "req-generation-1",
        1,
        1,
        &fence,
        "history",
    ))?;
    assert_eq!(event.sequence, 1);

    // A new generation under the same claim is stale against the bound claim:
    // acquire, append, and acknowledge all fail closed.
    let rotated_stream = "claim-generation-1/gen-2".to_owned();
    assert!(matches!(
        store.begin_replay_request(&replay_begin_fixture(
            &rotated_stream,
            "req-generation-2",
            "fp-generation-2",
            2,
            1,
            &fence
        )),
        Err(OrsError::WorkerReplayStaleStream { .. })
    ));
    assert!(matches!(
        store.append_replay_event(&replay_draft_fixture(
            &rotated_stream,
            "req-generation-2",
            2,
            1,
            &fence,
            "relaunched"
        )),
        Err(OrsError::WorkerReplayStaleStream { .. })
    ));
    let mut rotated_ack = replay_ack_fixture(&event, WorkerReplayPhase::Applied);
    rotated_ack.stream_id = rotated_stream.clone();
    rotated_ack.producer_generation = 2;
    assert!(matches!(
        store.acknowledge_replay_event(&rotated_ack),
        Err(OrsError::WorkerReplayStaleStream { .. })
    ));
    // A stale epoch under the current generation is rejected the same way.
    assert!(matches!(
        store.begin_replay_request(&replay_begin_fixture(
            &stream_id,
            "req-generation-3",
            "fp-generation-3",
            1,
            2,
            &fence
        )),
        Err(OrsError::WorkerReplayStaleStream { .. })
    ));
    // Nothing was acquired for the rotated stream, and the retained history
    // still reads.
    assert!(matches!(
        store.lookup_replay_request(&rotated_stream, "req-generation-2", "fp-generation-2")?,
        WorkerReplayRequestDecision::New
    ));
    assert_eq!(store.replay_stream(&stream_id, 0)?.len(), 1);

    drop(store);
    cleanup(&path);
    Ok(())
}

#[test]
fn worker_replay_bounded_page_and_pruned_gap() -> TestResult {
    let fence = "f".repeat(64);
    let (path, store, stream_id) =
        open_bound_replay_stream("replay-page-gap", "claim-page-1", 1, 1, &fence)?;
    store.begin_replay_request(&replay_begin_fixture(
        &stream_id,
        "req-page-1",
        "fp-page-1",
        1,
        1,
        &fence,
    ))?;
    let window = u64::from(MAX_REPLAY_PAGE);
    let total = window + 4;
    let mut envelopes = Vec::new();
    for n in 1..=total {
        let event = store.append_replay_event(&replay_draft_fixture(
            &stream_id,
            "req-page-1",
            1,
            1,
            &fence,
            &format!("payload-{n}"),
        ))?;
        assert_eq!(event.sequence, n);
        envelopes.push(event);
    }
    // An oversized suffix fails instead of truncating silently ...
    assert!(matches!(
        store.replay_stream(&stream_id, 0),
        Err(OrsError::ProjectionLimitExceeded)
    ));
    // ... while a bounded tail pages honestly.
    let tail = store.replay_stream(&stream_id, total - 5)?;
    assert_eq!(tail.len(), 5);
    assert_eq!(tail[0].sequence, total - 4);

    // Every event reaches APPLIED, so retention may prune the prefix while
    // keeping the newest window.
    for event in &envelopes {
        store.acknowledge_replay_event(&replay_ack_fixture(event, WorkerReplayPhase::Applied))?;
    }
    assert_eq!(store.prune_replay_stream(&stream_id)?, 4);
    // The pruned prefix is a loud gap, not an empty success ...
    assert!(matches!(
        store.replay_stream(&stream_id, 0),
        Err(OrsError::WorkerReplayIncomplete { .. })
    ));
    // ... while the retained suffix pages exactly at the bound and a
    // caught-up consumer honestly receives nothing.
    let retained = store.replay_stream(&stream_id, 4)?;
    assert_eq!(retained.len(), usize::from(MAX_REPLAY_PAGE));
    assert_eq!(retained[0].sequence, 5);
    assert_eq!(retained[retained.len() - 1].sequence, total);
    assert!(store.replay_stream(&stream_id, total)?.is_empty());

    drop(store);
    cleanup(&path);
    Ok(())
}

#[test]
fn worker_replay_ack_advances_only_its_phase_cursor() -> TestResult {
    let fence = "9".repeat(64);
    let (path, store, stream_id) =
        open_bound_replay_stream("replay-cursors", "claim-cursor-1", 1, 1, &fence)?;
    store.begin_replay_request(&replay_begin_fixture(
        &stream_id,
        "req-cursor-1",
        "fp-cursor-1",
        1,
        1,
        &fence,
    ))?;
    let first = store.append_replay_event(&replay_draft_fixture(
        &stream_id,
        "req-cursor-1",
        1,
        1,
        &fence,
        "one",
    ))?;
    let second = store.append_replay_event(&replay_draft_fixture(
        &stream_id,
        "req-cursor-1",
        1,
        1,
        &fence,
        "two",
    ))?;

    // DURABLE advances only the producer cursor.
    let cursors =
        store.acknowledge_replay_event(&replay_ack_fixture(&first, WorkerReplayPhase::Durable))?;
    assert_eq!((cursors.producer_cursor, cursors.consumer_cursor), (1, 0));
    // A non-terminal phase persists without moving any cursor.
    let cursors =
        store.acknowledge_replay_event(&replay_ack_fixture(&first, WorkerReplayPhase::Received))?;
    assert_eq!((cursors.producer_cursor, cursors.consumer_cursor), (1, 0));
    // UNKNOWN never advances a cursor.
    let cursors =
        store.acknowledge_replay_event(&replay_ack_fixture(&second, WorkerReplayPhase::Unknown))?;
    assert_eq!((cursors.producer_cursor, cursors.consumer_cursor), (1, 0));
    // APPLIED advances only the consumer cursor, monotonically.
    let cursors =
        store.acknowledge_replay_event(&replay_ack_fixture(&second, WorkerReplayPhase::Applied))?;
    assert_eq!((cursors.producer_cursor, cursors.consumer_cursor), (1, 2));
    // The normal lifecycle order (DURABLE then APPLIED) converges per phase.
    let cursors =
        store.acknowledge_replay_event(&replay_ack_fixture(&second, WorkerReplayPhase::Durable))?;
    assert_eq!((cursors.producer_cursor, cursors.consumer_cursor), (2, 2));
    let cursors =
        store.acknowledge_replay_event(&replay_ack_fixture(&first, WorkerReplayPhase::Rejected))?;
    assert_eq!((cursors.producer_cursor, cursors.consumer_cursor), (2, 2));

    drop(store);
    cleanup(&path);
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table-driven acceptance fixture exercises the complete Appendix P.4 surface"
)]
fn appendix_p4_operational_surface_projects_rollover_and_retains_snapshot() -> TestResult {
    let path = database_path("p4-surface");
    cleanup(&path);
    // Surface projection stages recovery-inbox items as data, which the
    // Kernel-route binding never authenticates: every other check still runs
    // through the single shared binding via `SurfaceProjectionEvidence`.
    let coordinator = coordinator_with_evidence(&path, Arc::new(SurfaceProjectionEvidence))?;
    let store = coordinator.store();
    let old = epoch(TEST_LINEAGE_C, 7)?;
    let token = coordinator.reserve(request(
        "reservation-p4",
        "operation-p4",
        old.clone(),
        &["scope-p4"],
    )?)?;

    store.stage(StagedOperation::new(operational_input(
        "stage-p4",
        "operation-p4",
        old.clone(),
        "opaque-stage",
    )?)?)?;
    store.mark_applying(label("operation-p4")?)?;
    let outcome = receipt(&token, &success_disposition())?;
    store.record_outcome(&outcome)?;
    store.schedule_retry(
        label("operation-p4")?,
        RetryState::new(operational_input(
            "retry-p4",
            "operation-p4",
            old.clone(),
            "opaque-retry",
        )?)?,
    )?;
    store.checkpoint_job(JobCheckpoint::new(operational_input(
        "job-checkpoint-1",
        "job-1",
        old.clone(),
        "opaque-job-checkpoint",
    )?)?)?;
    store.record_delivery_cursor(DeliveryCursorState::new(operational_input(
        "cursor-1",
        "sink-1",
        old.clone(),
        "opaque-cursor",
    )?)?)?;
    store.acknowledge_delivery(DeliveryAcknowledgement::new(operational_input(
        "cursor-ack-1",
        "sink-1",
        old.clone(),
        "opaque-ack",
    )?)?)?;

    store.stage_admission_reservation(AdmissionReservation::new(operational_input(
        "admission-stage-1",
        "admission-1",
        old.clone(),
        "opaque-admission",
    )?)?)?;
    store.activate_admission_reservation(AdmissionReservationActivation::new(
        operational_input(
            "admission-active-1",
            "admission-1",
            old.clone(),
            "opaque-admission-active",
        )?,
    )?)?;
    store.release_admission_reservation(AdmissionReservationRelease::new(operational_input(
        "admission-release-1",
        "admission-1",
        old.clone(),
        "opaque-admission-release",
    )?)?)?;

    store.apply_generation_transition(GenerationTransition::new(operational_input(
        "generation-transition-1",
        "generation-1",
        old.clone(),
        "opaque-generation-transition",
    )?)?)?;
    store.commit_generation_cutover(GenerationCutoverRecord::new(operational_input(
        "generation-cutover-1",
        "route-1",
        old.clone(),
        "opaque-generation-cutover",
    )?)?)?;
    store.bind_session(ActiveSessionBinding::new(operational_input(
        "session-bind-1",
        "session-1",
        old.clone(),
        "opaque-session",
    )?)?)?;
    store.detach_session(SessionDetach::new(operational_input(
        "session-detach-1",
        "session-1",
        old.clone(),
        "opaque-session-detach",
    )?)?)?;
    let broker_registered = store.register_user_broker(
        UserBrokerRegistration::new(operational_input(
            "broker-register-1",
            "broker-1",
            old.clone(),
            "opaque-broker",
        )?)?,
        None,
    )?;
    store.fence_user_broker(
        UserBrokerFence::new(operational_input(
            "broker-fence-1",
            "broker-1",
            old.clone(),
            "opaque-broker-fence",
        )?)?,
        broker_registered.receipt(),
    )?;

    store.commit_authority_snapshot(KernelAuthoritySnapshot::new(operational_input(
        "authority-snapshot-1",
        "kernel-authority",
        old.clone(),
        "opaque-authority-snapshot",
    )?)?)?;
    store.revoke_authority(AuthorityRevocation::new(operational_input(
        "authority-revocation-1",
        "revocation-1",
        old.clone(),
        "opaque-revocation",
    )?)?)?;
    let grant_input = operational_input("grant-active-1", "grant-1", old.clone(), "opaque-grant")?;
    store.activate_capability_grant(CapabilityGrantActivation::new(grant_input.clone())?)?;
    let grant_subject = label("grant-1")?;
    let active_grant = store
        .load_capability_grant(&grant_subject)?
        .ok_or("active capability grant read-back is missing")?;
    assert_eq!(active_grant.phase(), OperationalPhase::Active);
    assert_eq!(active_grant.record(), &grant_input);
    assert!(active_grant.operation_order() > 0);
    store.revoke_capability_grant(CapabilityGrantRevocation::new(operational_input(
        "grant-revoke-1",
        "grant-1",
        old.clone(),
        "opaque-grant-revoke",
    )?)?)?;
    let fenced_grant = store
        .load_capability_grant(&grant_subject)?
        .ok_or("fenced capability grant read-back is missing")?;
    assert_eq!(fenced_grant.phase(), OperationalPhase::Fenced);
    store.activate_capability_introduction(CapabilityIntroductionActivation::new(
        operational_input(
            "capability-intro-1",
            "capability-1",
            old.clone(),
            "opaque-capability",
        )?,
    )?)?;
    store.fence_capability_introduction(CapabilityIntroductionFence::new(operational_input(
        "capability-fence-1",
        "capability-1",
        old.clone(),
        "opaque-capability-fence",
    )?)?)?;

    let inbox = RecoveryInboxItem::bind(
        label("inbox-1")?,
        label("offline-signer-1")?,
        request(
            "reservation-inbox",
            "operation-inbox",
            old.clone(),
            &["scope-inbox"],
        )?
        .envelope,
        b"fixture-signature".to_vec(),
        200,
    )?;
    store.import_recovery_inbox(inbox)?;
    let projection_receipt = receipt(&token, &success_disposition())?;
    let (projection, _) =
        store.projection_page(&projection_receipt, RecoveryCursor::new(0, 16)?)?;
    assert!(
        projection
            .active_generation_refs
            .contains(&"generation-1".to_owned())
    );
    assert!(
        projection
            .active_generation_refs
            .contains(&"route-1".to_owned())
    );
    assert!(
        projection
            .recovery_intent_refs
            .contains(&"inbox-1".to_owned())
    );
    let applied_request = request(
        "reservation-inbox-applied",
        "operation-inbox-applied",
        old.clone(),
        &["scope-inbox-applied"],
    )?;
    let applied_token = coordinator.reserve(applied_request.clone())?;
    store.import_recovery_inbox(RecoveryInboxItem::bind(
        label("inbox-applied")?,
        label("offline-signer-1")?,
        applied_request.envelope,
        b"fixture-signature-applied".to_vec(),
        210,
    )?)?;
    store.record_recovery_inbox_disposition(
        label("inbox-applied")?,
        RecoveryInboxDisposition::Applied,
        &receipt(&applied_token, &success_disposition())?,
    )?;

    let next = successor(&old.current, "kernel-lineage-b", 1)?;
    store.commit_authority_snapshot(KernelAuthoritySnapshot::new(operational_input(
        "authority-snapshot-2",
        "kernel-authority",
        next.clone(),
        "opaque-authority-snapshot-rollover",
    )?)?)?;
    let (control, _) = store.control_projection_page(RecoveryCursor::new(0, 16)?)?;
    assert_eq!(control.authority_lineage, next);
    assert!(control.job_checkpoint_refs.contains(&"job-1".to_owned()));
    assert!(control.delivery_cursor_refs.contains(&"sink-1".to_owned()));
    assert!(control.recovery_inbox_refs.contains(&"inbox-1".to_owned()));
    assert!(
        !control
            .recovery_inbox_refs
            .contains(&"inbox-applied".to_owned())
    );

    let snapshot = store.logical_snapshot(OrsSnapshotRequest::new(0, 64, 500)?)?;
    assert!(snapshot.entry_refs().len() >= 16);
    assert_eq!(snapshot.snapshot_sha256().len(), 64);
    assert_eq!(
        store
            .scan_pending(RecoveryCursor::new(0, 1)?, 1)?
            .records
            .len(),
        1
    );

    drop(coordinator);
    cleanup(&path);
    Ok(())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one focused fixture covers canonical cutover, multi-scope, projection, and recovery evidence"
)]
fn generation_cutover_projection_is_canonical_and_recovery_is_forward_only() -> TestResult {
    let path = database_path("generation-canonical");
    cleanup(&path);
    let coordinator = coordinator(&path)?;
    let store = coordinator.store();
    store.commit_authority_snapshot(KernelAuthoritySnapshot::new(operational_input(
        "generation-authority-1",
        "generation-authority",
        epoch("generation-lineage", 1)?,
        "generation-authority-payload",
    )?)?)?;

    let first = RuntimeGenerationCutoverRecord {
        cutover_id: "cutover-canonical-1".to_owned(),
        route_scope: "daemon".to_owned(),
        old_generation: None,
        new_generation: ResourceGeneration::new(2)?,
        old_epoch: test_epoch(1),
        new_epoch: test_epoch(2),
        state: GenerationCutoverState::Armed,
    };
    let staged = store.stage_generation_cutover(first.clone())?;
    assert_eq!(staged.record().state, GenerationCutoverState::Armed);
    assert_eq!(
        staged.receipt().receipt().phase(),
        OperationalPhase::Applying
    );
    assert!(
        store
            .latest_generation_cutovers(MAX_RECOVERY_PAGE)?
            .is_empty()
    );

    let committed = store.commit_generation_cutover_state(first)?;
    assert_eq!(committed.record().state, GenerationCutoverState::Committed);
    let latest = store.latest_generation_cutovers(MAX_RECOVERY_PAGE)?;
    assert_eq!(latest.len(), 1);
    assert_eq!(
        latest[0].receipt().receipt().operation_order(),
        committed.receipt().receipt().operation_order()
    );
    let (control, _) = store.control_projection_page(RecoveryCursor::new(0, 16)?)?;
    assert!(
        control
            .active_generation_refs
            .contains(&"daemon".to_owned())
    );

    // A second scope may be cut over at the new global epoch.  Recovery later
    // rebinds both current route records to the maximum durable epoch.
    let second = RuntimeGenerationCutoverRecord {
        cutover_id: "cutover-canonical-2".to_owned(),
        route_scope: "worker".to_owned(),
        old_generation: None,
        new_generation: ResourceGeneration::new(3)?,
        old_epoch: test_epoch(2),
        new_epoch: test_epoch(3),
        state: GenerationCutoverState::Armed,
    };
    store.stage_generation_cutover(second.clone())?;
    store.commit_generation_cutover_state(second)?;
    assert_eq!(
        store.latest_generation_cutovers(MAX_RECOVERY_PAGE)?.len(),
        2
    );

    // The selected daemon row is older than the global epoch after the
    // worker cutover.  A live router re-fences it at epoch three, so ORS must
    // accept the preserved generation and advance only the selected scope.
    let daemon_again = RuntimeGenerationCutoverRecord {
        cutover_id: "cutover-canonical-3".to_owned(),
        route_scope: "daemon".to_owned(),
        old_generation: Some(ResourceGeneration::new(2)?),
        new_generation: ResourceGeneration::new(5)?,
        old_epoch: test_epoch(3),
        new_epoch: test_epoch(4),
        state: GenerationCutoverState::Armed,
    };
    store.stage_generation_cutover(daemon_again.clone())?;
    store.commit_generation_cutover_state(daemon_again)?;

    let interrupted = RuntimeGenerationCutoverRecord {
        cutover_id: "cutover-canonical-interrupted".to_owned(),
        route_scope: "scheduler".to_owned(),
        old_generation: None,
        new_generation: ResourceGeneration::new(4)?,
        old_epoch: test_epoch(4),
        new_epoch: test_epoch(5),
        state: GenerationCutoverState::Armed,
    };
    store.stage_generation_cutover(interrupted)?;
    let (control, _) = store.control_projection_page(RecoveryCursor::new(0, 16)?)?;
    assert!(
        control
            .active_generation_refs
            .contains(&"scheduler".to_owned())
    );
    let reconciled = store.reconcile_staged_generation_cutovers(MAX_RECOVERY_PAGE)?;
    assert_eq!(reconciled.len(), 1);
    assert_eq!(
        reconciled[0].record().state,
        GenerationCutoverState::FailedRequiresForwardCutover
    );
    assert_eq!(
        reconciled[0].receipt().receipt().phase(),
        OperationalPhase::Fenced
    );
    assert_eq!(
        store.latest_generation_cutovers(MAX_RECOVERY_PAGE)?.len(),
        2
    );
    let (control, _) = store.control_projection_page(RecoveryCursor::new(0, 16)?)?;
    assert!(
        !control
            .active_generation_refs
            .contains(&"scheduler".to_owned())
    );

    drop(coordinator);
    cleanup(&path);
    Ok(())
}

// ---------------------------------------------------------------------------
// Bridge-event receipt -> retirement -> certified boundary -> position drain
// (issue #2730, open item AUD1; external audit 5845038022).
//
// The audit's defect is precise: `BRIDGE_EVENT_POSITIONS` retained one
// never-deleted row per staged event, so normal successful traffic grew ORS
// storage without bound and the drain stalled. The remedy is bounded
// owner/incarnation range commitments behind a certified compacted boundary,
// and old-sequence non-reuse must survive that deletion.
//
// These tests exercise the ONLY public chain that can prove it:
//   `stage_bridge_event_checked` -> `record_bridge_event_handoff_checked`
//   -> `acknowledge_bridge_event_batch`
//   -> `reconcile_bridge_event_handoffs_checked`
//   -> `record_bridge_event_owner_receipt_checked`
//   -> `retire_bridge_event_handoffs_checked`
//
// The I7.2 receipt phases are respected throughout: the owner-bound
// acknowledgement batch advances only the producer receipt-acknowledged
// frontier, the handoff reconcile carries local staging plus that
// acknowledgement, and NEITHER may retire an event. Only the receiving owner's
// retained acceptance receipt (the one leg whose writer is the receiver) may,
// which is exactly the join at `RedbRecoveryStore::retire_bridge_handoffs_in`
// these tests pin.

/// The store's own on-disk table names, restated here so this module reads
/// durable state directly. Reusing the owner's exact table-name strings keeps
/// the assertions on the real tables rather than on a parallel projection;
/// `store.rs` keeps the definitions private, so the literal is repeated rather
/// than its symbol imported.
const BRIDGE_POSITIONS_TABLE: redb::TableDefinition<&str, &str> =
    redb::TableDefinition::new("ors_bridge_event_positions_v1");
const BRIDGE_CURSORS_TABLE: redb::TableDefinition<&str, &str> =
    redb::TableDefinition::new("ors_bridge_event_cursors_v1");
const BRIDGE_OWNER_RECEIPTS_TABLE: redb::TableDefinition<&str, &str> =
    redb::TableDefinition::new("ors_bridge_event_owner_receipts_v1");
const BRIDGE_COMPACTED_RANGES_TABLE: redb::TableDefinition<&str, &str> =
    redb::TableDefinition::new("ors_bridge_event_compacted_ranges_v1");

/// Receiving-owner dispositions in the store's own vocabulary
/// (`store.rs::parse_bridge_owner_receipt_checked`). `APPLIED` is a determined
/// terminal outcome; `UNKNOWN` is terminal for the receiver's knowledge but
/// never for the obligation.
const RECEIPT_TERMINAL: &str = "APPLIED";
const RECEIPT_UNDETERMINED: &str = "UNKNOWN";

/// One admitted bridge-event owner occurrence for these tests.
///
/// I7.2's `EventEnvelope` identity legs: the stream, its event, the producer
/// and its generation, and the authority epoch text `lineage:sequence`. The
/// owner evidence (lineage, principal, connection, launch nonce, session epoch)
/// is the #2729 authenticated stream/incarnation binding that
/// `stage_bridge_event_checked` binds into the stream-owner row.
struct BridgeStreamFixture {
    lineage: String,
    principal: String,
    producer_id: String,
    stream_id: String,
    connection: String,
    launch_nonce: String,
    session_epoch: u64,
    producer_generation: u64,
}

impl BridgeStreamFixture {
    fn new(label: &str) -> Self {
        Self {
            lineage: TEST_LINEAGE_A.to_owned(),
            principal: format!("S-1-5-21-2730-{label}"),
            producer_id: format!("producer-2730-{label}"),
            stream_id: format!("stream-2730-{label}"),
            connection: format!("connection-2730-{label}"),
            launch_nonce: format!("nonce-2730-{label}"),
            session_epoch: 1,
            producer_generation: 1,
        }
    }

    /// The canonical envelope bytes the ORS stage entry hashes and re-verifies.
    /// `authority_epoch` is the `lineage:sequence` text the sidecar binds.
    fn envelope(&self, event_id: &str, sequence: u64) -> serde_json::Value {
        json!({
            "stream_id": self.stream_id,
            "event_id": event_id,
            "sequence": sequence,
            "producer_id": self.producer_id,
            "producer_generation": self.producer_generation,
            "authority_epoch": format!("{}:{sequence}", self.lineage),
            "delivery_class": "durable_control",
            "ack_required": true,
            "payload_type": "test",
            "payload_or_blob_ref": format!("payload-{event_id}"),
        })
    }

    /// The owner's ADMITTING authorization over exactly these envelope bytes:
    /// both Governor-owned policy legs `Decided`, the proven source class named
    /// by the recipient grant, and no `declared_class` (the owner rule declares
    /// an out-of-scope class only on a rejection).
    fn admitting_authorization(envelope_bytes: &[u8]) -> serde_json::Value {
        json!({
            "verdict": "admitted",
            "source_sha256": sha256_hex(envelope_bytes),
            "scope": "b".repeat(64),
            "policy_revision": eliot_workscope::BRIDGE_INGEST_PRIVACY_POLICY_REVISION,
            "scope_ref": "scope-2730-permitted",
            "source_class": "private",
            "recipient_grant": vec!["private".to_owned()],
            "provider_restriction": "decided",
            "retention_terms": "decided",
        })
    }

    /// One complete `stage_bridge_event_checked` request. The privacy legs come
    /// from the store's own public projection over the owner's own rule, exactly
    /// as the Kernel route composes them, so the persistence gate re-derives the
    /// same verdict rather than being handed one.
    fn stage_request(&self, event_id: &str, sequence: u64) -> TestResult<Value> {
        let envelope = self.envelope(event_id, sequence);
        let envelope_bytes = eliot_contracts::canonical_json_bytes(&envelope)?;
        let decision = RedbRecoveryStore::bridge_event_privacy_decision(
            &envelope_bytes,
            Some(&Self::admitting_authorization(&envelope_bytes)),
        );
        let mut request = json!({
            "stream_id": self.stream_id,
            "event_id": event_id,
            "sequence": sequence,
            "producer_id": self.producer_id,
            "producer_generation": self.producer_generation,
            "authority_epoch": format!("{}:{sequence}", self.lineage),
            "envelope": envelope,
            "envelope_sha256": sha256_hex(&envelope_bytes),
            "staging_connection": self.connection,
            "adapter_version": "eliot.bridge-event.adapter.v1",
            "requested_route": "eliot.bridge-event.forward.v1",
            "owner_principal": self.principal,
            "owner_authority_lineage": self.lineage,
            "owner_connection": self.connection,
            "owner_launch_nonce": self.launch_nonce,
            "owner_session_epoch": self.session_epoch,
        });
        if let (Some(fields), Some(legs)) = (request.as_object_mut(), decision.as_object()) {
            for (key, value) in legs {
                fields.insert(key.clone(), value.clone());
            }
        }
        Ok(request)
    }
}

/// One staged event's durable identity, as the store reported it.
struct StagedBridgeEvent {
    namespace: String,
    event_id: String,
    sequence: u64,
    envelope_sha256: String,
}

/// Stages one event, then persists its handoff — the two steps the Kernel route
/// performs for every forwarded event. The namespace is read back from the
/// store's own `stage_bridge_event_checked` answer rather than recomputed here:
/// the owner-namespace digest is the store's private binding function, and a
/// test-side re-derivation would be a second scheme.
fn stage_and_hand_off(
    store: &RedbRecoveryStore,
    fixture: &BridgeStreamFixture,
    event_id: &str,
    sequence: u64,
) -> TestResult<StagedBridgeEvent> {
    let outcome = store.stage_bridge_event_checked(&fixture.stage_request(event_id, sequence)?)?;
    assert_eq!(
        outcome.get("fresh").and_then(Value::as_bool),
        Some(true),
        "a genuinely new identity above the boundary stages fresh"
    );
    let envelope_sha256 = outcome
        .get("envelope_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            "stage outcome must carry its content commitment".into()
        })?
        .to_owned();
    let namespace = outcome
        .get("owner_namespace")
        .and_then(Value::as_str)
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            "stage outcome must carry its owner namespace".into()
        })?
        .to_owned();
    let handoff = json!({
        "owner_namespace": namespace,
        "event_id": event_id,
        "sequence": sequence,
        "envelope_sha256": envelope_sha256,
        "staging_connection": fixture.connection,
    });
    let recorded = store.record_bridge_event_handoff_checked(&handoff)?;
    assert_eq!(
        recorded.get("fresh").and_then(Value::as_bool),
        Some(true),
        "the first handoff for this identity is a new row"
    );
    Ok(StagedBridgeEvent {
        namespace,
        event_id: event_id.to_owned(),
        sequence,
        envelope_sha256,
    })
}

/// Moves one namespace's acknowledged frontier over `through`, then reconciles
/// the handoffs so the stored reconcile tuple covers it.
///
/// The acknowledgement is the OWNER-BOUND batch entry, not the older
/// `acknowledge_bridge_events(stream_id, ..)`: on the owner-bound path the
/// cursor row is stored under the owner namespace
/// (`RedbRecoveryStore::advance_bridge_cursor_in_checked`), while the older
/// entry resolves `BRIDGE_EVENT_CURSORS` by `stream_id` and would therefore
/// read a durable frontier of zero. This mirrors the I7.2 split: the producer
/// receipt acknowledgement is its own phase, distinct from durability and from
/// the receiving owner's later acceptance.
///
/// The reconcile key is this operation's own identity, shaped as the digest the
/// entry validates.
fn acknowledge_and_reconcile(
    store: &RedbRecoveryStore,
    fixture: &BridgeStreamFixture,
    namespace: &str,
    through: u64,
) -> TestResult {
    let acknowledged = store.acknowledge_bridge_event_batch(&json!({
        "items": [{
            "namespace": namespace,
            "expected_revision": 1,
            "expected_incarnation": 1,
            "sequence": through,
            "owner_authority_lineage": fixture.lineage,
            "owner_principal": fixture.principal,
        }],
    }))?;
    let acked_cursor = acknowledged
        .get("streams")
        .and_then(Value::as_array)
        .and_then(|streams| streams.first())
        .and_then(|entry| entry.get("acked_cursor"))
        .and_then(Value::as_u64)
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            "the acknowledgement batch must report its acked cursor".into()
        })?;
    assert_eq!(
        acked_cursor, through,
        "the producer receipt-acknowledged frontier advances to the acked sequence"
    );
    store.reconcile_bridge_event_handoffs_checked(
        namespace,
        through,
        &sha256_hex(format!("reconcile-{namespace}-{through}").as_bytes()),
    )?;
    Ok(())
}

/// Records the receiving owner's acceptance receipt for one exact handoff.
///
/// `disposition` is passed through verbatim so the refusal cases can present a
/// determined and an undetermined outcome over the same setup.
fn record_owner_receipt(
    store: &RedbRecoveryStore,
    event: &StagedBridgeEvent,
    disposition: &str,
) -> TestResult {
    let receipt = json!({
        "owner_namespace": event.namespace,
        "event_id": event.event_id,
        "sequence": event.sequence,
        "envelope_sha256": event.envelope_sha256,
        "receiving_operation_id": format!(
            "bridge-event-owner-receipt:{}",
            sha256_hex(
                format!(
                    "eliot.bridge-event-owner-receipt|{}|{}|{}",
                    event.namespace, event.event_id, event.sequence
                )
                .as_bytes()
            )
        ),
        "disposition": disposition,
        "receipt_digest": sha256_hex(
            format!("receipt|{}|{}|{disposition}", event.event_id, event.sequence).as_bytes()
        ),
    });
    store.record_bridge_event_owner_receipt_checked(&receipt)?;
    Ok(())
}

/// Runs the public retirement entry for one namespace and returns its answer.
///
/// `expected_revision`/`expected_incarnation` are the owner epoch the entry
/// resolves under; the store refuses any other epoch, so a caller cannot retire
/// under a right it did not hold.
fn retire_handoffs(
    store: &RedbRecoveryStore,
    namespace: &str,
    expected_revision: u64,
    expected_incarnation: u64,
) -> TestResult<Value> {
    Ok(store.retire_bridge_event_handoffs_checked(&json!({
        "namespace": namespace,
        "expected_revision": expected_revision,
        "expected_incarnation": expected_incarnation,
    }))?)
}

/// Reads one namespace's durable position rows directly from the on-disk
/// database: the exact ordered position keys the store retains for it.
///
/// The completeness check is against an INDEPENDENT expected set computed from
/// the sequences the test itself staged, never from the caller's own list.
///
/// The caller must have dropped its [`RedbRecoveryStore`] first: this reopens
/// the same on-disk file, and the store holds it open for the whole session.
fn bridge_position_keys(path: &PathBuf, namespace: &str) -> TestResult<BTreeMap<u64, String>> {
    let database = redb::Database::open(path)?;
    let read = database.begin_read()?;
    let positions = read.open_table(BRIDGE_POSITIONS_TABLE)?;
    let prefix = format!("{namespace}::");
    let end = format!("{prefix}\u{10ffff}");
    let mut retained = BTreeMap::new();
    for entry in positions.range::<&str>(prefix.as_str()..=end.as_str())? {
        let (key, _) = entry?;
        let key = key.value();
        let sequence = key
            .strip_prefix(&prefix)
            .and_then(|tail| tail.parse::<u64>().ok())
            .ok_or_else(|| -> Box<dyn std::error::Error> {
                "position key must be `{namespace}::{sequence}`".into()
            })?;
        retained.insert(sequence, key.to_owned());
    }
    drop(read);
    drop(database);
    Ok(retained)
}

/// Reads the certified compacted boundary one namespace's cursor row retains.
///
/// Requires the store to be dropped first, as [`bridge_position_keys`] does.
fn bridge_compacted_boundary(path: &PathBuf, namespace: &str) -> TestResult<u64> {
    let database = redb::Database::open(path)?;
    let read = database.begin_read()?;
    let cursors = read.open_table(BRIDGE_CURSORS_TABLE)?;
    let encoded = cursors
        .get(namespace)?
        .map(|value| value.value().to_owned())
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            "the admitted stream owner must retain a position cursor".into()
        })?;
    drop(read);
    drop(database);
    // The cursor row is the store's own persisted JSON; `last_compacted_sequence`
    // is the boundary field the retirement entry advances.
    let row: serde_json::Value = serde_json::from_str(&encoded)?;
    row.get("last_compacted_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            "the cursor row must carry its compacted boundary".into()
        })
}

/// Counts the receiving-owner receipts one namespace still retains.
///
/// Requires the store to be dropped first, as [`bridge_position_keys`] does.
fn bridge_retained_receipt_count(path: &PathBuf, namespace: &str) -> TestResult<u64> {
    let database = redb::Database::open(path)?;
    let read = database.begin_read()?;
    let receipts = read.open_table(BRIDGE_OWNER_RECEIPTS_TABLE)?;
    let prefix = format!("{namespace}::");
    let end = format!("{prefix}\u{10ffff}");
    let mut retained = 0_u64;
    for entry in receipts.range::<&str>(prefix.as_str()..=end.as_str())? {
        entry?;
        retained += 1;
    }
    drop(read);
    drop(database);
    Ok(retained)
}

/// Reads whether one namespace has committed a certified compacted range.
///
/// The remedy is ONE cumulative range row per stream, not one row per event, so
/// a stream that keeps retiring must not grow this count. Requires the store to
/// be dropped first, as [`bridge_position_keys`] does.
fn bridge_compacted_range_committed(path: &PathBuf, namespace: &str) -> TestResult<bool> {
    let database = redb::Database::open(path)?;
    let read = database.begin_read()?;
    let ranges = read.open_table(BRIDGE_COMPACTED_RANGES_TABLE)?;
    let committed = ranges.get(namespace)?.is_some();
    drop(read);
    drop(database);
    Ok(committed)
}

/// A1/AUD1 case 1 (positive): the full receipt chain terminalizes, certifies the
/// compacted boundary, and drains the retired position rows.
///
/// The audit's claim is that this never happened — the boundary stayed at zero
/// and every event left one never-deleted position row. Both halves are
/// asserted as VALUES: the boundary advanced past zero, and the position rows
/// for the retired sequences are gone.
#[test]
fn bridge_receipt_retirement_certifies_boundary_and_drains_positions() -> TestResult {
    let path = database_path("bridge-retirement-first-cycle");
    let store = RedbRecoveryStore::open(&path)?;
    let fixture = BridgeStreamFixture::new("first-cycle");
    let first = stage_and_hand_off(&store, &fixture, "event-1", 1)?;
    let second = stage_and_hand_off(&store, &fixture, "event-2", 2)?;
    let third = stage_and_hand_off(&store, &fixture, "event-3", 3)?;
    let namespace = first.namespace.clone();

    acknowledge_and_reconcile(&store, &fixture, &namespace, 3)?;
    for event in [&first, &second, &third] {
        record_owner_receipt(&store, event, RECEIPT_TERMINAL)?;
    }

    let retirement = retire_handoffs(&store, &namespace, 1, 1)?;
    let terminalized = retirement
        .get("terminalized")
        .and_then(Value::as_u64)
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            "the retirement entry must report its terminalized count".into()
        })?;
    assert_eq!(
        terminalized, 3,
        "the joined, receipt-complete, contiguous prefix terminalizes in full"
    );
    drop(store);

    // Durable state is read after the store releases the on-disk file.
    assert_eq!(
        bridge_compacted_boundary(&path, &namespace)?,
        3,
        "the certified compacted boundary advances over every terminalized position"
    );

    // Completeness against an independent expected set: the block staged above
    // is `{1, 2, 3}`, and NONE of them may remain in the position index.
    let expected: Vec<u64> = (1_u64..=3).collect();
    let retained = bridge_position_keys(&path, &namespace)?;
    let undrained: Vec<u64> = expected
        .iter()
        .copied()
        .filter(|sequence| retained.contains_key(sequence))
        .collect();
    assert!(
        undrained.is_empty(),
        "no retired position may remain: undrained {undrained:?}, retained {retained:?}"
    );
    assert_eq!(
        bridge_retained_receipt_count(&path, &namespace)?,
        0,
        "a terminalized receipt is consumed with its handoff"
    );
    assert!(
        bridge_compacted_range_committed(&path, &namespace)?,
        "the certified coverage is one cumulative range row, not one row per event"
    );

    cleanup(&path);
    Ok(())
}

/// A1/AUD1 case 2 (positive): the boundary is REOPENABLE.
///
/// The audit's exact complaint was that the boundary could advance "at most
/// once" and the drain then stalled behind a stale resume anchor, so the second
/// block's positions accumulated forever. A single-cycle test passes even with
/// that defect; this case is the one that discriminates it.
#[test]
fn bridge_certified_boundary_reopens_and_drains_the_next_block() -> TestResult {
    let path = database_path("bridge-retirement-second-cycle");
    let store = RedbRecoveryStore::open(&path)?;
    let fixture = BridgeStreamFixture::new("second-cycle");

    let mut first_block = Vec::new();
    for sequence in 1_u64..=3 {
        first_block.push(stage_and_hand_off(
            &store,
            &fixture,
            &format!("event-{sequence}"),
            sequence,
        )?);
    }
    let namespace = first_block[0].namespace.clone();
    acknowledge_and_reconcile(&store, &fixture, &namespace, 3)?;
    for event in &first_block {
        record_owner_receipt(&store, event, RECEIPT_TERMINAL)?;
    }
    let first_retirement = retire_handoffs(&store, &namespace, 1, 1)?;
    assert_eq!(
        first_retirement.get("terminalized").and_then(Value::as_u64),
        Some(3),
        "the first cycle terminalizes its whole block"
    );
    // The store owns the on-disk file for the whole session, so the durable
    // boundary between cycles is read through a short-lived reopen.
    drop(store);
    let first_boundary = bridge_compacted_boundary(&path, &namespace)?;
    assert_eq!(
        first_boundary, 3,
        "the first cycle certifies through sequence 3"
    );
    let store = RedbRecoveryStore::open(&path)?;

    // Second cycle: the same stream incarnation keeps producing. A boundary
    // that refuses to reopen leaves these rows in place forever.
    let mut second_block = Vec::new();
    for sequence in 4_u64..=6 {
        second_block.push(stage_and_hand_off(
            &store,
            &fixture,
            &format!("event-{sequence}"),
            sequence,
        )?);
    }
    acknowledge_and_reconcile(&store, &fixture, &namespace, 6)?;
    for event in &second_block {
        record_owner_receipt(&store, event, RECEIPT_TERMINAL)?;
    }
    let second_retirement = retire_handoffs(&store, &namespace, 1, 1)?;
    assert_eq!(
        second_retirement
            .get("terminalized")
            .and_then(Value::as_u64),
        Some(3),
        "the second block terminalizes: the boundary and drain both reopen"
    );
    drop(store);

    let second_boundary = bridge_compacted_boundary(&path, &namespace)?;
    assert!(
        second_boundary > first_boundary,
        "the boundary advances a SECOND time: {second_boundary} must exceed {first_boundary}"
    );
    assert_eq!(
        second_boundary, 6,
        "the second cycle certifies through sequence 6"
    );

    // The second block's positions must drain too — this is the half that
    // stalled while the boundary still moved.
    let expected_second: Vec<u64> = vec![4, 5, 6];
    let retained = bridge_position_keys(&path, &namespace)?;
    let undrained: Vec<u64> = expected_second
        .iter()
        .copied()
        .filter(|sequence| retained.contains_key(sequence))
        .collect();
    assert!(
        undrained.is_empty(),
        "the second block must drain as well: undrained {undrained:?}, retained {retained:?}"
    );
    // And the first block must not have come back.
    assert!(
        retained.is_empty(),
        "every retired position stays drained across both cycles: {retained:?}"
    );
    assert!(
        bridge_compacted_range_committed(&path, &namespace)?,
        "two cycles of retirement still commit ONE cumulative range row"
    );

    cleanup(&path);
    Ok(())
}

/// A1/AUD1 case 3 (positive): deleting the position rows does NOT make an old
/// sequence reusable.
///
/// Issue #2730 work item 2: "A missing row below a retained boundary is not a
/// new event." The drain removes the per-event position row, so re-staging a
/// retired identity must answer from retained evidence or with the explicit
/// retired disposition — never `fresh: true`.
#[test]
fn bridge_retired_sequence_is_not_reusable_after_the_drain() -> TestResult {
    let path = database_path("bridge-retirement-non-reuse");
    let store = RedbRecoveryStore::open(&path)?;
    let fixture = BridgeStreamFixture::new("non-reuse");

    let first = stage_and_hand_off(&store, &fixture, "event-1", 1)?;
    let second = stage_and_hand_off(&store, &fixture, "event-2", 2)?;
    let namespace = first.namespace.clone();
    acknowledge_and_reconcile(&store, &fixture, &namespace, 2)?;
    record_owner_receipt(&store, &first, RECEIPT_TERMINAL)?;
    record_owner_receipt(&store, &second, RECEIPT_TERMINAL)?;
    retire_handoffs(&store, &namespace, 1, 1)?;
    drop(store);

    assert_eq!(bridge_compacted_boundary(&path, &namespace)?, 2);
    assert!(
        bridge_position_keys(&path, &namespace)?.is_empty(),
        "the retired positions are drained, so nothing but the certified boundary remains"
    );

    // Re-stage the RETIRED identity at its OLD sequence. The position row is
    // gone and the live record is gone; only the retained commitment and the
    // certified boundary remain.
    let store = RedbRecoveryStore::open(&path)?;
    let replay = store.stage_bridge_event_checked(&fixture.stage_request("event-1", 1)?)?;
    assert_ne!(
        replay.get("fresh").and_then(Value::as_bool),
        Some(true),
        "a retired event identity below the certified boundary is never re-inserted fresh"
    );
    let disposition = replay
        .get("disposition")
        .and_then(Value::as_str)
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            "the replay outcome must carry its disposition".into()
        })?;
    assert!(
        disposition == "duplicate" || disposition == "retired",
        "the replay answers from retained evidence or the explicit retired disposition, got {disposition:?}"
    );
    assert_eq!(
        replay.get("sequence").and_then(Value::as_u64),
        Some(1),
        "the answer stays about the retired position"
    );
    drop(store);

    assert_eq!(
        bridge_position_keys(&path, &namespace)?.len(),
        0,
        "the refused replay inserts no fresh position row"
    );

    cleanup(&path);
    Ok(())
}

/// A1/AUD1 case 4 (refusal): no receiving-owner receipt, no retirement.
///
/// Producer acknowledgement plus a full covering reconcile tuple is exactly
/// what the audit says is NOT enough. This asserts the join at
/// `retire_bridge_handoffs_in` is load-bearing: without the receiver's own
/// retained receipt the handoff is not terminalized and the boundary stays put.
#[test]
fn bridge_handoff_without_owner_receipt_does_not_retire() -> TestResult {
    let path = database_path("bridge-retirement-missing-receipt");
    let store = RedbRecoveryStore::open(&path)?;
    let fixture = BridgeStreamFixture::new("missing-receipt");

    let first = stage_and_hand_off(&store, &fixture, "event-1", 1)?;
    let second = stage_and_hand_off(&store, &fixture, "event-2", 2)?;
    let namespace = first.namespace.clone();
    acknowledge_and_reconcile(&store, &fixture, &namespace, 2)?;

    let retirement = retire_handoffs(&store, &namespace, 1, 1)?;
    assert_eq!(
        retirement.get("terminalized").and_then(Value::as_u64),
        Some(0),
        "an acknowledged and reconciled handoff with no receiver receipt must not terminalize"
    );
    drop(store);

    assert_eq!(
        bridge_retained_receipt_count(&path, &namespace)?,
        0,
        "this case is defined by the ABSENCE of any receiving-owner receipt"
    );
    assert_eq!(
        bridge_compacted_boundary(&path, &namespace)?,
        0,
        "without a terminalized prefix the certified boundary does not move"
    );
    assert_eq!(
        bridge_position_keys(&path, &namespace)?.len(),
        2,
        "an unretired position keeps its row: nothing was deleted"
    );

    // Adding the missing receipt is what unblocks the SAME state — proving the
    // receipt, not the acknowledgement, was the gate.
    let store = RedbRecoveryStore::open(&path)?;
    record_owner_receipt(&store, &first, RECEIPT_TERMINAL)?;
    record_owner_receipt(&store, &second, RECEIPT_TERMINAL)?;
    let retirement = retire_handoffs(&store, &namespace, 1, 1)?;
    assert_eq!(
        retirement.get("terminalized").and_then(Value::as_u64),
        Some(2),
        "the same acknowledged and reconciled handoffs retire once the receipt exists"
    );
    drop(store);

    assert_eq!(
        bridge_compacted_boundary(&path, &namespace)?,
        2,
        "the certified boundary moves only once the receiver's receipt exists"
    );

    cleanup(&path);
    Ok(())
}

/// A1/AUD1 case 5 (refusal): an UNKNOWN receiving-owner disposition does not
/// retire.
///
/// I7.2's `EventAckReceipt` ends at `APPLIED | REJECTED | UNKNOWN`. An
/// undetermined obligation must never be read as applied; `retires()` returns
/// false for `UNKNOWN` explicitly, and this proves the boundary honors that.
#[test]
fn bridge_handoff_with_unknown_owner_disposition_does_not_retire() -> TestResult {
    let path = database_path("bridge-retirement-unknown-receipt");
    let store = RedbRecoveryStore::open(&path)?;
    let fixture = BridgeStreamFixture::new("unknown-receipt");

    let first = stage_and_hand_off(&store, &fixture, "event-1", 1)?;
    let second = stage_and_hand_off(&store, &fixture, "event-2", 2)?;
    let namespace = first.namespace.clone();
    acknowledge_and_reconcile(&store, &fixture, &namespace, 2)?;
    for event in [&first, &second] {
        record_owner_receipt(&store, event, RECEIPT_UNDETERMINED)?;
    }

    let retirement = retire_handoffs(&store, &namespace, 1, 1)?;
    assert_eq!(
        retirement.get("terminalized").and_then(Value::as_u64),
        Some(0),
        "an UNKNOWN receiving-owner disposition is terminal for knowledge, not for the obligation"
    );

    // The refusal is not a one-shot accident: repeating the entry changes
    // nothing, so the obligation is genuinely blocked rather than merely slow.
    let retirement = retire_handoffs(&store, &namespace, 1, 1)?;
    assert_eq!(
        retirement.get("terminalized").and_then(Value::as_u64),
        Some(0),
        "a repeated retirement still refuses an UNKNOWN disposition"
    );
    drop(store);

    assert_eq!(
        bridge_retained_receipt_count(&path, &namespace)?,
        2,
        "both receipts are retained; their disposition is what is undetermined"
    );
    assert_eq!(
        bridge_compacted_boundary(&path, &namespace)?,
        0,
        "an undetermined outcome never certifies a compacted boundary"
    );
    assert_eq!(
        bridge_position_keys(&path, &namespace)?.len(),
        2,
        "nothing is deleted while the receiving outcome is undetermined"
    );

    cleanup(&path);
    Ok(())
}
