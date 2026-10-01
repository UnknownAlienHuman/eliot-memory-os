use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
use eliot_store_api::{
    OperationId, OperationIdentity, OutboxIntentKind, StateFence, WorkAdmissionBudget,
    WorkAdmissionBudgetDimension, WorkAdmissionClaimRef, WorkAdmissionClaims,
    WorkAdmissionRecord, WorkAdmissionSemanticRevision, WorkAdmissionState,
    WORK_ADMISSION_SCHEMA_V1, sha256_hex,
};

use super::record_write;

fn identity(id: &str) -> OperationIdentity {
    OperationIdentity {
        operation_id: OperationId::new(id).expect("operation id"),
        idempotency_key: format!("idem-{id}"),
        canonical_request_hash: "a".repeat(64),
    }
}

fn claim(reference: &str, digest: char) -> WorkAdmissionClaimRef {
    WorkAdmissionClaimRef {
        reference: reference.to_owned(),
        sha256: digest.to_string().repeat(64),
    }
}

fn admitted_record() -> WorkAdmissionRecord {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
        .expect("lineage");
    let authority_epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero"))
        .expect("epoch");
    let state_fence = StateFence::new(authority_epoch.clone(), ResourceGeneration::genesis());
    let canonical_operation_id = OperationId::new("canonical-work-admit")
        .expect("canonical operation");

    WorkAdmissionRecord {
        schema: WORK_ADMISSION_SCHEMA_V1.to_owned(),
        state: WorkAdmissionState::Admitted,
        work_id: "work-1".to_owned(),
        parent_task_id: "parent-task-1".to_owned(),
        task_id: "task-1".to_owned(),
        session_id: "session-1".to_owned(),
        task_revision: "7".to_owned(),
        cell_id: "cell-1".to_owned(),
        payload_digest: "b".repeat(64),
        input_revision: "input-4".to_owned(),
        scope_id: "scope-1".to_owned(),
        term: 2,
        dependencies: Vec::new(),
        budgets: vec![WorkAdmissionBudget {
            dimension: WorkAdmissionBudgetDimension::ComputeSteps,
            limit: 1,
        }],
        route_class: "claude".to_owned(),
        max_retries: 1,
        max_children: 1,
        max_depth: 1,
        max_pending_reviews: 1,
        evidence_required: true,
        receipt_contract_revision: "receipt-v1".to_owned(),
        reservation_id: identity("reservation-1"),
        work_item_id: identity("work-item-1"),
        proposed_attempt_id: identity("attempt-1"),
        stage_operation_id: identity("stage-1"),
        claims: WorkAdmissionClaims {
            resources: claim("resources-1", 'c'),
            lane: claim("lane-1", 'd'),
            environment: claim("environment-1", 'e'),
            effects: claim("effects-1", 'f'),
            quota_view: claim("quota-1", '1'),
        },
        authority_epoch,
        state_fence,
        expires_at_ms: 1_800_000_000_000,
        semantic_admission_revision: WorkAdmissionSemanticRevision {
            key: "owner/canonical".to_owned(),
            revision: "4".to_owned(),
        },
        semantic_admission_predecessor_revision: 3,
        canonical_operation_id: canonical_operation_id.clone(),
        canonical_idempotency_key: "idem-canonical-work-admit".to_owned(),
        launch_outbox_id: OutboxIntentKind::Launch
            .outbox_id(canonical_operation_id.as_str(), 0)
            .expect("launch outbox id"),
    }
}

#[test]
fn work_admission_write_persists_exact_valid_owner_record() {
    let record = admitted_record();

    let (statement, bindings) = record_write(&record).expect("valid admitted work");

    assert!(statement.contains("CREATE type::record($work_admission_table"));
    assert!(statement.contains("work_admission_already_exists"));
    assert_eq!(
        bindings["work_admission_record"]["namespace"],
        "work-admission-v1"
    );
    assert_eq!(
        bindings["work_admission_record"]["schema"],
        WORK_ADMISSION_SCHEMA_V1
    );
    let payload = bindings["work_admission_record"]["payload"]
        .as_array()
        .expect("canonical payload bytes");
    let payload: Vec<u8> = payload
        .iter()
        .map(|byte| u8::try_from(byte.as_u64().expect("payload byte")).expect("u8 payload byte"))
        .collect();
    assert_eq!(
        bindings["work_admission_record"]["value_digest"],
        sha256_hex(&payload)
    );
}

#[test]
fn work_admission_write_refuses_invalid_claim_commitment() {
    let mut record = admitted_record();
    record.claims.effects.sha256 = "not-a-digest".to_owned();

    assert!(record_write(&record).is_err());
}
