use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
use eliot_store_api::{
    CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents, OperationId,
    OperationIdentity, OutboxIntentKind,
    PreparedTransition, ScopeId, SecurityContext, StateFence, TransitionClass,
    WorkAdmissionBudget, WorkAdmissionBudgetAttribution, WorkAdmissionBudgetDimension,
    WorkAdmissionClaimRef, WorkAdmissionClaims, WorkAdmissionOwnerAttribution,
    WorkAdmissionOwnerReadback, WorkAdmissionOwnerReference, WorkAdmissionOwnerRole,
    WorkAdmissionRecord, WorkAdmissionSemanticRevision, WorkAdmissionState,
    WorkAdmissionSwarmBudgetAttribution, WORK_ADMISSION_SCHEMA_V1, bind_issue18_digests,
    generated_operation_manifests, operation_manifest_set_digest,
    supported_admission_contract_set_digest, canonical_json_bytes, sha256_hex,
};
use serde_json::json;

use super::work_admission_statements;

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

fn owner_ref(kind: &str, id: &str, revision: &str, digest: &str) -> WorkAdmissionOwnerReference {
    WorkAdmissionOwnerReference {
        kind: kind.to_owned(),
        id: id.to_owned(),
        revision: revision.to_owned(),
        digest: Some(digest.to_owned()),
    }
}

fn readback(
    role: WorkAdmissionOwnerRole,
    fence: &StateFence,
    id: &str,
    value: serde_json::Value,
) -> WorkAdmissionOwnerReadback {
    let bytes = canonical_json_bytes(&value).expect("owner canonical bytes");
    let canonical_json = String::from_utf8(bytes.clone()).expect("owner UTF-8");
    let sha256 = sha256_hex(&bytes);
    WorkAdmissionOwnerReadback {
        role,
        owner_ref: owner_ref("admission-owner", id, "1", &sha256),
        owner_revision: 1,
        state_fence: fence.clone(),
        canonical_json,
        sha256,
    }
}

fn model_catalog_evidence() -> serde_json::Value {
    let snapshot = json!({
        "schema_version": "eliot.agent-model-catalogue/v1",
        "snapshot_id": "model-catalogue-1",
        "account_scope": "local-opencode",
        "collector_identity": "opencode-collector-1",
        "observed_at_unix_ms": 1_700_000_000_000_u64,
        "expires_at_unix_ms": 1_700_000_300_000_u64,
        "entries": [],
    });
    let bytes = canonical_json_bytes(&snapshot).expect("model snapshot canonicalizes");
    let snapshot_json = String::from_utf8(bytes.clone()).expect("model JSON UTF-8");
    let digest = sha256_hex(&bytes);
    json!({
        "schema": "eliot.work-admission.model-catalog-evidence.v1",
        "model_catalogue": {
            "owner_ref": owner_ref("model-catalogue", "model-catalogue-1", "1", &digest),
            "observed_at_unix_ms": 1_700_000_000_000_u64,
            "expires_at_unix_ms": 1_700_000_300_000_u64,
            "snapshot_json": snapshot_json,
            "sha256": digest,
        },
        "provider_accounts": {
            "kind": "unavailable",
            "schema": "eliot.provider-account-catalogue.observation.v1",
            "source": "opencode-provider-catalogue/v1",
            "reason": "source_exposes_no_account_metadata",
            "model_catalogue_snapshot_id": "model-catalogue-1",
            "observed_at_unix_ms": 1_700_000_000_000_u64,
            "expires_at_unix_ms": 1_700_000_300_000_u64,
            "source_contract_ref": owner_ref("source-contract", "opencode-api-contract", "1", &"a".repeat(64)),
        },
    })
}

fn owner_attribution(fence: &StateFence) -> WorkAdmissionOwnerAttribution {
    use eliot_contracts::RequestId;
    use eliot_protocol::{
        HOST_REQUEST_WIRE_ID, HostRequestEnvelope, HostRequestIdentity, HostRequestKind,
    };

    let requester = json!({"goal": "admit exact durable work"});
    let requester_bytes = canonical_json_bytes(&requester).expect("request bytes");
    let requester_json = String::from_utf8(requester_bytes.clone()).expect("request UTF-8");
    let requester_digest = sha256_hex(&requester_bytes);
    let visibility = json!({"policy": "current role visibility"});
    let visibility_digest = sha256_hex(&canonical_json_bytes(&visibility).expect("policy bytes"));
    let visibility_ref = owner_ref("visibility-policy", "visibility-policy-1", "1", &visibility_digest);
    let staffing = json!({
        "privacy_class": "INTERNAL",
        "recipe": {"role_profiles": [{"visibility_policy": {
            "kind": visibility_ref.kind.clone(),
            "id": visibility_ref.id.clone(),
            "revision": visibility_ref.revision.clone(),
            "digest": visibility_ref.digest.clone(),
        }}]},
        "lanes": [{"route_candidates": [{"privacy_evidence_refs": ["privacy-route-1"]}]}],
    });
    let staffing_bytes = canonical_json_bytes(&staffing).expect("staffing bytes");
    let staffing_json = String::from_utf8(staffing_bytes.clone()).expect("staffing UTF-8");
    let staffing_digest = sha256_hex(&staffing_bytes);
    let mut policy_readback = readback(WorkAdmissionOwnerRole::Policy, fence, "visibility-policy-1", visibility);
    policy_readback.owner_ref = visibility_ref.clone();
    let mut task_readback = readback(
        WorkAdmissionOwnerRole::Task,
        fence,
        "task-1",
        json!({"task_id": "task-1", "goal": "admit exact durable work", "revision": 7, "state_fence": fence}),
    );
    task_readback.owner_revision = 7;
    task_readback.owner_ref.revision = "7".to_owned();
    let staffing_readback = readback(WorkAdmissionOwnerRole::HumanStaffing, fence, "staffing-1", staffing);
    let budget = json!({
        "state_fence": fence,
        "revision": 1,
        "state": {"kind": "configured", "ledger": {"envelope": {
            "envelope_id": "budget-envelope-1", "policy_snapshot_id": "policy-snapshot-1",
            "automation_policy_ref": "automation-policy-1", "cost_authority_ref": "cost-authority-1",
            "provider_tool": {"provider_ref": "provider-1", "tool_ref": "claude"}
        }}}
    });
    let mut owner_readbacks = vec![
        task_readback,
        readback(WorkAdmissionOwnerRole::Plan, fence, "plan-1", json!({"work_id": "work-1"})),
        readback(WorkAdmissionOwnerRole::WorkScope, fence, "scope-1", json!({
            "state_fence": fence, "owner_revision": 1,
            "binding": {"scope": {"scope_ref": "scope-1"}, "privacy_class": "INTERNAL"},
            "guard_receipt": {"disposition": "MATCHED"}
        })),
        policy_readback,
        staffing_readback,
        readback(WorkAdmissionOwnerRole::ModelCatalog, fence, "models-1", model_catalog_evidence()),
        readback(WorkAdmissionOwnerRole::Grants, fence, "grants-1", json!({"revision": 1})),
        readback(WorkAdmissionOwnerRole::Budget, fence, "budget-1", budget),
    ];
    owner_readbacks.sort_by_key(|item| item.role);
    let budget_owner_ref = owner_readbacks.iter().find(|item| item.role == WorkAdmissionOwnerRole::Budget)
        .expect("budget readback").owner_ref.clone();
    let staffing_owner_ref = owner_readbacks.iter().find(|item| item.role == WorkAdmissionOwnerRole::HumanStaffing)
        .expect("staffing readback").owner_ref.clone();
    let host_request = HostRequestEnvelope {
        wire_id: HOST_REQUEST_WIRE_ID.to_owned(),
        wire_version: HostRequestEnvelope::CONTRACT_VERSION,
        kind: HostRequestKind::Invocation,
        connection_id: "connection-1".to_owned(),
        identity: HostRequestIdentity {
            request_id: RequestId::new("request-work-admit-1").expect("request ID"),
            correlation_projection: None,
            idempotency_key: "request-idempotency-1".to_owned(),
            cancellation_id: "request-cancel-1".to_owned(),
            parent_operation_id: None,
            deadline_unix_ms: 2_000_000_000_000,
            capability: "task_controller.coordinate".to_owned(),
            session_id: Some("session-1".to_owned()),
            task_id: Some("task-1".to_owned()),
            work_scope_id: Some("scope-1".to_owned()),
            payload_schema_id: "eliot.task-controller.coordinate.v1".to_owned(),
            payload_sha256: requester_digest.clone(),
        },
        state_fence: fence.clone(),
        descriptor_sha256: "d".repeat(64),
        peer_admission_receipt_sha256: "e".repeat(64),
        activation_binding: None,
        envelope_sha256: String::new(),
    }.with_computed_digest().expect("request digest");
    WorkAdmissionOwnerAttribution {
        request_id: "request-work-admit-1".to_owned(),
        task_controller_operation_id: "task-controller-op-1".to_owned(),
        task_controller_attempt_id: "task-controller-attempt-1".to_owned(),
        task_id: "task-1".to_owned(),
        work_id: "work-1".to_owned(),
        work_scope_id: "scope-1".to_owned(),
        attempt_id: "attempt-1".to_owned(),
        operation_id: "admitted-work-operation-1".to_owned(),
        host_request,
        canonical_requester_json: requester_json,
        canonical_requester_sha256: requester_digest,
        admitted_goal: "admit exact durable work".to_owned(),
        admitted_goal_sha256: sha256_hex(b"admit exact durable work"),
        staffing_plan_request_json: staffing_json,
        staffing_plan_request_sha256: staffing_digest,
        role_visibility_policy_ref: visibility_ref,
        privacy_class: serde_json::from_str("\"INTERNAL\"").expect("privacy enum"),
        route_privacy_evidence_refs: vec!["privacy-route-1".to_owned()],
        budget_attribution: WorkAdmissionBudgetAttribution {
            owner_ref: budget_owner_ref,
            envelope_id: "budget-envelope-1".to_owned(),
            policy_snapshot_id: "policy-snapshot-1".to_owned(),
            automation_policy_ref: "automation-policy-1".to_owned(),
            cost_authority_ref: "cost-authority-1".to_owned(),
            provider_ref: "provider-1".to_owned(),
            tool_ref: "claude".to_owned(),
            swarm: WorkAdmissionSwarmBudgetAttribution::NotApplicable {
                owner_ref: staffing_owner_ref,
                reason: "the current staffing owner admitted solo work".to_owned(),
            },
        },
        owner_readbacks,
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
        admitted_operation_id: OperationId::new("admitted-work-operation-1")
            .expect("admitted operation"),
        claims: WorkAdmissionClaims {
            resources: claim("resources-1", 'c'),
            lane: claim("lane-1", 'd'),
            environment: claim("environment-1", 'e'),
            effects: claim("effects-1", 'f'),
            quota_view: claim("quota-1", '1'),
        },
        owner_attribution: owner_attribution(&state_fence),
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

fn prepared_transition(record: &WorkAdmissionRecord) -> PreparedTransition {
    let state_fence = record.state_fence.clone();
    let snapshot = json!({
        "state_fence": state_fence,
        "owner_revision": record.semantic_admission_revision.revision.parse::<u64>().expect("revision"),
        "work_admission_revision": record.semantic_admission_revision.clone(),
        "current_plan": null,
        "verifier_execution_fact": null,
        "finish_evidence": null,
    });
    let snapshot_json = String::from_utf8(canonical_json_bytes(&snapshot).expect("snapshot bytes"))
        .expect("snapshot utf-8");
    let command = eliot_store_api::admit_work_operation(record.clone(), snapshot_json)
        .expect("admit work command");
    let mut transition = PreparedTransition {
        contract_version: CONTRACT_VERSION,
        identity: OperationIdentity {
            operation_id: record.canonical_operation_id.clone(),
            idempotency_key: record.canonical_idempotency_key.clone(),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: record.state_fence.clone(),
        scope_id: ScopeId::new(&record.scope_id).expect("scope"),
        task_id: Some(record.task_id.clone()),
        ordering_scopes: Vec::new(),
        transition_class: TransitionClass::TaskControl,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest:
            supported_admission_contract_set_digest().expect("contract digest"),
        operation_manifest_digest: operation_manifest_set_digest(
            &generated_operation_manifests().expect("manifests"),
        )
        .expect("manifest digest"),
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
        named_operations: vec![command],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    bind_issue18_digests(&mut transition).expect("transition digests");
    transition.validate().expect("prepared transition");
    transition
}

#[test]
fn work_admission_transition_writes_exact_record_and_canonical_owner_cas() {
    let record = admitted_record();
    let transition = prepared_transition(&record);
    let (statement, bindings) =
        work_admission_statements(&transition).expect("valid work-admission transition");

    assert!(statement.contains("CREATE type::record($work_admission_table"));
    assert!(statement.contains("work_admission_already_exists"));
    assert!(statement.contains("canonical_owner_cas_conflict"));
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
    assert_eq!(bindings["canonical_expected_revision"], 3);
    assert_eq!(bindings["canonical_owner_record"]["revision"], 4);
}

#[test]
fn work_admission_transition_refuses_stale_owner_predecessor() {
    let record = admitted_record();
    let mut transition = prepared_transition(&record);
    transition.named_operations[0]
        .parameters
        .insert("expected_canonical_revision".to_owned(), json!("2"));
    bind_issue18_digests(&mut transition).expect("stale transition digests");

    assert!(work_admission_statements(&transition).is_err());
}
