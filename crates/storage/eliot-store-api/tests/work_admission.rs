use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration, SourceId,
    StateFence,
};
use eliot_store_api::{
    CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents, OperationId, OperationIdentity,
    OutboxIntentKind, PolicyConfigSchemaVersions, PreparedTransition,
    RequestMeta, ScopeId, SecurityContext, TransitionClass, WorkAdmissionBudget,
    WorkAdmissionBudgetAttribution, WorkAdmissionBudgetDimension, WorkAdmissionClaimRef,
    WorkAdmissionClaims, WorkAdmissionOwnerAttribution, WorkAdmissionOwnerReadback,
    WorkAdmissionOwnerReference, WorkAdmissionOwnerRole, WorkAdmissionRecord,
    WorkAdmissionSemanticRevision, WorkAdmissionState, WorkAdmissionSubmission,
    WorkAdmissionSwarmBudgetAttribution,
    WORK_ADMISSION_SCHEMA_V1, WriteReceipt, WriteReceiptStatus, bind_issue18_digests,
    generated_operation_manifests, operation_manifest_set_digest,
    supported_admission_contract_set_digest, canonical_json_bytes,
};
use serde_json::json;

fn fence() -> StateFence {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

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

fn owner_reference(
    kind: &str,
    id: &str,
    revision: &str,
    digest: &str,
) -> WorkAdmissionOwnerReference {
    WorkAdmissionOwnerReference {
        kind: kind.to_owned(),
        id: id.to_owned(),
        revision: revision.to_owned(),
        digest: Some(digest.to_owned()),
    }
}

fn readback(
    role: WorkAdmissionOwnerRole,
    state_fence: &StateFence,
    owner_id: &str,
    value: serde_json::Value,
) -> WorkAdmissionOwnerReadback {
    let bytes = canonical_json_bytes(&value).expect("owner value canonicalizes");
    let canonical_json = String::from_utf8(bytes.clone()).expect("owner bytes are UTF-8");
    let sha256 = sha256_hex(&bytes);
    WorkAdmissionOwnerReadback {
        role,
        owner_ref: owner_reference("admission-owner", owner_id, "1", &sha256),
        owner_revision: 1,
        state_fence: state_fence.clone(),
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
            "owner_ref": owner_reference("model-catalogue", "model-catalogue-1", "1", &digest),
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
            "source_contract_ref": owner_reference("source-contract", "opencode-api-contract", "1", &"a".repeat(64)),
        },
    })
}

fn owner_attribution(
    state_fence: &StateFence,
    work_id: &str,
    task_id: &str,
    scope_id: &str,
    attempt_id: &str,
    operation_id: &str,
) -> WorkAdmissionOwnerAttribution {
    use eliot_contracts::RequestId;
    use eliot_protocol::{
        HOST_REQUEST_WIRE_ID, HostRequestEnvelope, HostRequestIdentity, HostRequestKind,
    };

    let requester = json!({"goal": "admit exact durable work"});
    let requester_bytes = canonical_json_bytes(&requester).expect("request canonicalizes");
    let requester_json = String::from_utf8(requester_bytes.clone()).expect("request UTF-8");
    let requester_digest = sha256_hex(&requester_bytes);
    let visibility_policy_json = json!({"policy": "current role visibility"});
    let visibility_policy_bytes =
        canonical_json_bytes(&visibility_policy_json).expect("policy canonicalizes");
    let visibility_policy_digest = sha256_hex(&visibility_policy_bytes);
    let visibility_ref = owner_reference(
        "visibility-policy",
        "visibility-policy-1",
        "1",
        &visibility_policy_digest,
    );
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
    let staffing_bytes = canonical_json_bytes(&staffing).expect("staffing canonicalizes");
    let staffing_json = String::from_utf8(staffing_bytes.clone()).expect("staffing UTF-8");
    let staffing_digest = sha256_hex(&staffing_bytes);
    let mut policy_readback = readback(
        WorkAdmissionOwnerRole::Policy,
        state_fence,
        "visibility-policy-1",
        visibility_policy_json,
    );
    policy_readback.owner_ref = visibility_ref.clone();
    let human_staffing_readback = readback(
        WorkAdmissionOwnerRole::HumanStaffing,
        state_fence,
        "staffing-plan-1",
        staffing,
    );
    let scope = json!({
        "state_fence": state_fence,
        "owner_revision": 1,
        "binding": {"scope": {"scope_ref": scope_id}, "privacy_class": "INTERNAL"},
        "guard_receipt": {"disposition": "MATCHED"}
    });
    let budget = json!({
        "state_fence": state_fence,
        "revision": 1,
        "state": {"kind": "configured", "ledger": {"envelope": {
            "envelope_id": "budget-envelope-1",
            "policy_snapshot_id": "policy-snapshot-1",
            "automation_policy_ref": "automation-policy-1",
            "cost_authority_ref": "cost-authority-1",
            "provider_tool": {"provider_ref": "provider-1", "tool_ref": "claude"}
        }, "reservations": [{
            "idempotency_key": "budget-reservation-idem-1",
            "receipt": {
                "reservation_id": "budget-reservation-1",
                "envelope_id": "budget-envelope-1",
                "idempotency_key": "budget-reservation-idem-1",
                "operation": {
                    "operation_id": "provider-operation-1",
                    "request_id": "provider-request-1",
                    "idempotency_key": "budget-reservation-idem-1",
                    "state_fence": state_fence
                },
                "authority": {"state_fence": state_fence},
                "provider_tool": {"provider_ref": "provider-1", "tool_ref": "claude"}
            }
        }]}}
    });
    let mut task_readback = readback(
        WorkAdmissionOwnerRole::Task,
        state_fence,
        "task-1",
        json!({
            "task_id": task_id,
            "goal": "admit exact durable work",
            "revision": 7,
            "state_fence": state_fence,
        }),
    );
    task_readback.owner_revision = 7;
    task_readback.owner_ref.revision = "7".to_owned();
    let mut owner_readbacks = vec![
        task_readback,
        readback(WorkAdmissionOwnerRole::Plan, state_fence, "plan-1", json!({"work_id": work_id})),
        readback(WorkAdmissionOwnerRole::WorkScope, state_fence, "scope-1", scope),
        policy_readback,
        human_staffing_readback,
        readback(WorkAdmissionOwnerRole::ModelCatalog, state_fence, "models-1", model_catalog_evidence()),
        readback(WorkAdmissionOwnerRole::Grants, state_fence, "grants-1", json!({"revision": 1})),
        readback(WorkAdmissionOwnerRole::Budget, state_fence, "budget-1", budget),
    ];
    owner_readbacks.sort_by_key(|entry| entry.role);
    let budget_owner_ref = owner_readbacks
        .iter()
        .find(|entry| entry.role == WorkAdmissionOwnerRole::Budget)
        .expect("budget readback")
        .owner_ref
        .clone();
    let human_staffing_owner_ref = owner_readbacks
        .iter()
        .find(|entry| entry.role == WorkAdmissionOwnerRole::HumanStaffing)
        .expect("staffing readback")
        .owner_ref
        .clone();
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
            task_id: Some(task_id.to_owned()),
            work_scope_id: Some(scope_id.to_owned()),
            payload_schema_id: "eliot.task-controller.coordinate.v1".to_owned(),
            payload_sha256: requester_digest.clone(),
        },
        state_fence: state_fence.clone(),
        descriptor_sha256: "d".repeat(64),
        peer_admission_receipt_sha256: "e".repeat(64),
        activation_binding: None,
        envelope_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("authenticated envelope digest");

    WorkAdmissionOwnerAttribution {
        request_id: "request-work-admit-1".to_owned(),
        task_controller_operation_id: "task-controller-op-1".to_owned(),
        task_controller_attempt_id: "task-controller-attempt-1".to_owned(),
        task_id: task_id.to_owned(),
        work_id: work_id.to_owned(),
        work_scope_id: scope_id.to_owned(),
        attempt_id: attempt_id.to_owned(),
        operation_id: operation_id.to_owned(),
        host_request,
        canonical_requester_json: requester_json,
        canonical_requester_sha256: requester_digest,
        admitted_goal: "admit exact durable work".to_owned(),
        admitted_goal_sha256: sha256_hex(b"admit exact durable work"),
        staffing_plan_request_json: staffing_json,
        staffing_plan_request_sha256: staffing_digest,
        role_visibility_policy_ref: visibility_ref,
        privacy_class: eliot_security_contracts::PrivacyClass::Internal,
        route_privacy_evidence_refs: vec!["privacy-route-1".to_owned()],
        budget_attribution: WorkAdmissionBudgetAttribution {
            owner_ref: budget_owner_ref,
            envelope_id: "budget-envelope-1".to_owned(),
            policy_snapshot_id: "policy-snapshot-1".to_owned(),
            automation_policy_ref: "automation-policy-1".to_owned(),
            cost_authority_ref: "cost-authority-1".to_owned(),
            reservation_id: "budget-reservation-1".to_owned(),
            reservation_idempotency_key: "budget-reservation-idem-1".to_owned(),
            provider_ref: "provider-1".to_owned(),
            tool_ref: "claude".to_owned(),
            swarm: WorkAdmissionSwarmBudgetAttribution::NotApplicable {
                owner_ref: human_staffing_owner_ref,
                reason: "the current staffing owner admitted solo work".to_owned(),
            },
        },
        owner_readbacks,
    }
}

fn record() -> WorkAdmissionRecord {
    let state_fence = fence();
    let canonical_operation_id = OperationId::new("canonical-work-admit").expect("operation");
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
        owner_attribution: owner_attribution(
            &state_fence,
            "work-1",
            "task-1",
            "scope-1",
            "attempt-1",
            "admitted-work-operation-1",
        ),
        authority_epoch: state_fence.authority_epoch.clone(),
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
            .expect("launch id"),
    }
}

fn canonical_snapshot_json(record: &WorkAdmissionRecord) -> String {
    let snapshot = json!({
        "state_fence": record.state_fence.clone(),
        "owner_revision": record.semantic_admission_revision.revision.parse::<u64>().expect("revision"),
        "work_admission_revision": record.semantic_admission_revision.clone(),
        "current_plan": null,
        "verifier_execution_fact": null,
        "finish_evidence": null,
    });
    String::from_utf8(canonical_json_bytes(&snapshot).expect("canonical snapshot bytes"))
        .expect("canonical snapshot utf-8")
}

fn prepared() -> PreparedTransition {
    let admitted = record();
    let command = eliot_store_api::admit_work_operation(
        admitted.clone(),
        canonical_snapshot_json(&admitted),
    )
    .expect("admit work");
    let mut transition = PreparedTransition {
        contract_version: CONTRACT_VERSION,
        identity: OperationIdentity {
            operation_id: admitted.canonical_operation_id.clone(),
            idempotency_key: "idem-canonical-work-admit".to_owned(),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: admitted.state_fence.clone(),
        scope_id: ScopeId::new(&admitted.scope_id).expect("scope"),
        task_id: Some(admitted.task_id.clone()),
        ordering_scopes: vec![eliot_store_api::OrderingScopeId::new("work-admission-task-1")
            .expect("ordering scope")],
        transition_class: TransitionClass::TaskControl,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest:
            supported_admission_contract_set_digest().expect("contract set digest"),
        operation_manifest_digest: operation_manifest_set_digest(
            &generated_operation_manifests().expect("operation manifests"),
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
    bind_issue18_digests(&mut transition).expect("derived digests");
    transition.validate().expect("valid transition");
    transition
}

fn request() -> RequestMeta {
    let fence = fence();
    RequestMeta {
        request_id: RequestId::new("request-work-admit-1").expect("request id"),
        session_id: Some(eliot_contracts::SessionId::new("session-1").expect("session")),
        task_id: Some(eliot_contracts::TaskId::new("task-1").expect("task")),
        product_id: ProductId::new("product-1").expect("product"),
        source_id: SourceId::new("source-eliotd").expect("source"),
        state_fence: fence,
        clock: ClockReading::default(),
    }
}

fn receipt(transition: &PreparedTransition) -> WriteReceipt {
    let launch = record().launch_outbox_id;
    WriteReceipt {
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        transition_class: transition.transition_class,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(eliot_store_api::CommitId::new("commit-work-admit-1").expect("commit")),
        state_fence: transition.state_fence.clone(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["admit-work".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: vec![launch],
        operation_manifest_digest: transition.operation_manifest_digest.clone(),
        admission_digest: transition.admission_digest.clone(),
        mutation_plan_digest: transition.mutation_plan_digest.clone(),
        semantic_source_revisions: transition.semantic_source_revisions.clone(),
        policy_config_schema_versions: PolicyConfigSchemaVersions::bound_to(transition),
        error_code: None,
        resubmission: eliot_store_api::Resubmission::None,
        committed_at: Some("2026-10-01T00:00:00Z".to_owned()),
        envelope: None,
    }
}

#[test]
fn work_admission_accepts_exact_original_transition_and_receipt() {
    let transition = prepared();
    let submission = WorkAdmissionSubmission::new(
        request(),
        transition.clone(),
        Vec::new(),
        Vec::new(),
    )
    .expect("original submission");

    submission
        .validate_receipt(&receipt(&transition))
        .expect("exact committed receipt");
}

#[test]
fn work_admission_refuses_a_foreign_budget_reservation_link() {
    let mut admitted = record();
    admitted.owner_attribution.budget_attribution.reservation_id =
        "budget-reservation-foreign".to_owned();
    assert!(admitted.validate().is_err());
}

#[test]
fn work_admission_accepts_explicit_owner_observed_unavailable_account_axis() {
    let admitted = record();
    admitted.validate().expect("current closed account absence observation");
}

#[test]
fn work_admission_refuses_account_absence_without_owner_source_contract() {
    let mut admitted = record();
    let model_readback = admitted
        .owner_attribution
        .owner_readbacks
        .iter_mut()
        .find(|readback| readback.role == WorkAdmissionOwnerRole::ModelCatalog)
        .expect("ModelCatalog owner readback");
    let mut model: serde_json::Value =
        serde_json::from_str(&model_readback.canonical_json).expect("model evidence JSON");
    model["provider_accounts"]
        .as_object_mut()
        .expect("account object")
        .remove("source_contract_ref");
    let bytes = canonical_json_bytes(&model).expect("mutated model canonicalizes");
    model_readback.canonical_json = String::from_utf8(bytes.clone()).expect("canonical UTF-8");
    model_readback.sha256 = sha256_hex(&bytes);
    model_readback.owner_ref.digest = Some(model_readback.sha256.clone());

    assert!(admitted.validate().is_err());
}

#[test]
fn work_admission_refuses_same_operation_with_changed_claim_commitment() {
    let transition = prepared();
    let mut submission = WorkAdmissionSubmission::new(
        request(),
        transition.clone(),
        Vec::new(),
        Vec::new(),
    )
    .expect("original submission");
    let record = submission.prepared_transition.named_operations[0]
        .parameters
        .get_mut("record")
        .expect("admitted record");
    record["claims"]["effects"]["sha256"] = json!("9".repeat(64));

    assert!(submission.validate_receipt(&receipt(&transition)).is_err());
}

#[test]
fn work_admission_refuses_stale_canonical_owner_predecessor() {
    let mut transition = prepared();
    transition.named_operations[0].parameters.insert(
        "expected_canonical_revision".to_owned(),
        json!("2"),
    );
    bind_issue18_digests(&mut transition).expect("bind stale predecessor mutation");

    assert!(WorkAdmissionSubmission::new(
        request(),
        transition,
        Vec::new(),
        Vec::new(),
    )
    .is_err());
}
