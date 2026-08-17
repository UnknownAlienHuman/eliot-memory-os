use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
use eliot_platform::SecretReference;
use eliot_receipts::{ReceiptCore, ReceiptEnvelope};
use eliot_runtime_contracts::{
    GenerationCutoverRecord as RuntimeGenerationCutoverRecord, GenerationCutoverState,
};
use eliot_security_contracts::PrivacyClass;
use redb::ReadableTable;
use serde_json::{Value, json};

use crate::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);

struct TestCanonicalEvidence;

impl CanonicalEvidenceProvider for TestCanonicalEvidence {
    fn verify_ordering_heads(&self, _scopes: &[ScopeReservationRequest]) -> Result<(), OrsError> {
        Ok(())
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
    coordinator_with_evidence(path, Arc::new(TestCanonicalEvidence))
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

fn fence(epoch: u64) -> Result<StateFenceSnapshot, OrsError> {
    StateFenceSnapshot::capture(
        &json!({
            "authority_epoch": epoch,
            "integration_revision": null,
            "policy_revision": null,
            "resource_generation": 1,
            "task_revision": null
        }),
        epoch,
    )
}

fn access() -> Result<RecoveryAccessClass, OrsError> {
    Ok(RecoveryAccessClass {
        privacy: PrivacyClass::Private,
        visibility: label("owner-only")?,
    })
}

fn operational_input(
    record_id: &str,
    subject_id: &str,
    authority_epoch: EpochLineage,
    payload: &str,
) -> Result<OperationalRecordInput, OrsError> {
    let epoch_value = authority_epoch.current.epoch;
    OperationalRecordInput::encrypted(
        OperationalRecordContext {
            record_id: label(record_id)?,
            subject_id: label(subject_id)?,
            authority_epoch,
            state_fence: fence(epoch_value)?,
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
    let epoch_value = writer_epoch.current.epoch;
    let envelope = RecoveryPayloadEnvelope::encrypted(
        RecoveryEnvelopeContext {
            operation_or_checkpoint_id: label(operation_id)?,
            privacy_and_visibility_class: access()?,
            authority_epoch: writer_epoch.clone(),
            state_fence: fence(epoch_value)?,
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
            "authority_epoch": token.writer_epoch.current.epoch,
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

#[test]
fn envelope_validation_rejects_tamper_version_and_bad_fence() -> TestResult {
    let original = request(
        "reservation-a",
        "operation-a",
        epoch("lineage-a", 7)?,
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
        1,
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
                "authority_epoch": 1,
                "state_fence": {
                    "authority_epoch": 1,
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
        "stdout_ref": null,
        "stderr_ref": null,
        "axes": {
            "status": "OBSERVED",
            "assertability": "NON_ASSERTABLE_UNVERIFIED",
            "accessibility": "AVAILABLE",
            "influence": "ALLOWED",
            "physical": "PRESENT",
            "taint": "CLEAR"
        }
    }))?)
}

fn process_evidence_record(
    operation_id: &str,
    lifecycle: &str,
    observed_at_ms: i64,
) -> TestResult<ProcessEvidenceRecord> {
    let owner = eliot_process::ProcessOwnerBinding::new(
        "testd",
        "aa".repeat(32),
        1,
        eliot_process::Generation::new(1)?,
    )?;
    Ok(ProcessEvidenceRecord::from_evidence(
        process_evidence(operation_id, lifecycle)?,
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
            "authority_epoch": 1,
            "state_fence": {
                "authority_epoch": 1,
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
                "pid": 1,
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
        vec![first.clone(), second.clone()]
    );

    let mut conflicting = first.clone();
    conflicting.owner = eliot_process::ProcessOwnerBinding::new(
        "native",
        conflicting.owner.principal_digest(),
        conflicting.owner.authority_epoch(),
        conflicting.owner.generation(),
    )?;
    assert_eq!(conflicting.record_key()?, first.record_key()?);
    assert!(matches!(
        store.persist_process_evidence(&conflicting),
        Err(OrsError::IntegrityProblem { .. })
    ));
    assert_eq!(
        store.load_process_evidence(&operation_id)?,
        vec![first.clone(), second.clone()]
    );
    let mut mismatched = first.clone();
    mismatched.operation_id = OperationIdentity::new("other-operation")?;
    assert!(matches!(
        store.persist_process_evidence(&mismatched),
        Err(OrsError::IntegrityProblem { .. })
    ));
    let mut escalated = first.clone();
    let mut escalated_wire = serde_json::to_value(&escalated.evidence)?;
    escalated_wire["axes"]["status"] = json!("VERIFIED");
    escalated.evidence = serde_json::from_value(escalated_wire)?;
    assert!(matches!(
        store.persist_process_evidence(&escalated),
        Err(OrsError::IntegrityProblem { .. })
    ));

    drop(store);
    let reopened = RedbRecoveryStore::open(&path)?;
    assert_eq!(
        reopened.load_process_evidence(&operation_id)?,
        vec![first, second]
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
fn multi_scope_reservation_is_atomic_ordered_and_conflict_on_duplicate() -> TestResult {
    let path = database_path("atomic");
    cleanup(&path);
    let coordinator = coordinator(&path)?;
    let writer_epoch = epoch("lineage-a", 7)?;
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

    let wrong_epoch = epoch("other-lineage", 1)?;
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
    let writer_epoch = epoch("lineage-a", 7)?;
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
    let writer_epoch = epoch("lineage-a", 7)?;
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
    let old = epoch("lineage-a", 7)?;
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
    let writer_epoch = epoch("lineage-a", 7)?;
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
    let writer_epoch = epoch("lineage-a", 7)?;
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
    let writer_epoch = epoch("lineage-a", 7)?;
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
            epoch("lineage-a", 7)?,
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
            epoch("lineage-a", 7)?,
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
    reason = "one table-driven acceptance fixture exercises the complete Appendix P.4 surface"
)]
fn appendix_p4_operational_surface_projects_rollover_and_retains_snapshot() -> TestResult {
    let path = database_path("p4-surface");
    cleanup(&path);
    let coordinator = coordinator(&path)?;
    let store = coordinator.store();
    let old = epoch("kernel-lineage-a", 7)?;
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
    store.register_user_broker(UserBrokerRegistration::new(operational_input(
        "broker-register-1",
        "broker-1",
        old.clone(),
        "opaque-broker",
    )?)?)?;
    store.fence_user_broker(UserBrokerFence::new(operational_input(
        "broker-fence-1",
        "broker-1",
        old.clone(),
        "opaque-broker-fence",
    )?)?)?;

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
    store.activate_capability_grant(CapabilityGrantActivation::new(operational_input(
        "grant-active-1",
        "grant-1",
        old.clone(),
        "opaque-grant",
    )?)?)?;
    store.revoke_capability_grant(CapabilityGrantRevocation::new(operational_input(
        "grant-revoke-1",
        "grant-1",
        old.clone(),
        "opaque-grant-revoke",
    )?)?)?;
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
        old_epoch: AuthorityEpoch::new(1)?,
        new_epoch: AuthorityEpoch::new(2)?,
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
        old_epoch: AuthorityEpoch::new(2)?,
        new_epoch: AuthorityEpoch::new(3)?,
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
        old_epoch: AuthorityEpoch::new(3)?,
        new_epoch: AuthorityEpoch::new(4)?,
        state: GenerationCutoverState::Armed,
    };
    store.stage_generation_cutover(daemon_again.clone())?;
    store.commit_generation_cutover_state(daemon_again)?;

    let interrupted = RuntimeGenerationCutoverRecord {
        cutover_id: "cutover-canonical-interrupted".to_owned(),
        route_scope: "scheduler".to_owned(),
        old_generation: None,
        new_generation: ResourceGeneration::new(4)?,
        old_epoch: AuthorityEpoch::new(4)?,
        new_epoch: AuthorityEpoch::new(5)?,
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
