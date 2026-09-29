//! Canonical user-automation persistence proofs (issue #1779).
//!
//! Drives the closed `ApplyUserAutomationState` / `GetUserAutomationState`
//! operations through the reference contour: immutable revision lineage
//! with pointer compare-and-set, admission-state transitions without
//! touching immutable revisions, manual-occurrence invocation recording,
//! closed-query projections, and fail-closed conflicts. Revision and
//! invocation documents are built from the REAL Kernel-owned domain
//! types, serialized to the opaque wire JSON, and re-validated through
//! the domain after readback — proving domain fidelity across the opaque
//! store boundary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration,
    SourceId, StateFence,
};
use eliot_kernel_core::user_automation::{
    AutomationCapabilityProfile, AutomationDeliveryTarget, AutomationResourceCeiling,
    AutomationTaskBinding, AutomationTaskKind, AutomationWorkScope, NormalizedSchedule,
    OverlapPolicy, ProviderFingerprintPolicy, RecursionPolicy, RouteCostPolicy, ScheduleKind,
    UserAutomationConfigurationState, UserAutomationExecutionMode, UserAutomationInvocation,
    UserAutomationRevision, UserAutomationTrigger, UserAutomationTriggerOrigin,
};
use eliot_receipts::EffectClass;
use eliot_store_api::{
    AUTOMATION_STATE_ACTIVE, AUTOMATION_STATE_PAUSED, AUTOMATION_STATE_RETIRED,
    CanonicalRequestView, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, OperationIdentity, OrderingScopeId, PreparedTransition, RequestMeta,
    ScopeId, SecurityContext, StoreError, TransitionClass, WriteReceipt, automation_create_params,
    automation_edit_params, automation_failure_params, automation_mutation_request,
    automation_read_request, automation_run_now_params, automation_state_transition_params,
    bind_issue18_digests, canonical_request_hash, operation_manifest_set_digest,
};
use serde_json::Value;

use super::MemoryStore;

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new(LINEAGE).expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::new(1).expect("generation"),
    )
}

fn context(tag: &str) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(format!("request-automation-{tag}")).expect("request"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-automation").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

/// Minimal domain-valid revision: deterministic script mode with all
/// capability gates closed, so every nested owner validation passes.
fn valid_revision(
    automation_id: &str,
    revision: &str,
    state: UserAutomationConfigurationState,
) -> UserAutomationRevision {
    UserAutomationRevision {
        automation_id: automation_id.to_owned(),
        revision: revision.to_owned(),
        supersedes: None,
        owner_principal: "human-1".to_owned(),
        work_scope: AutomationWorkScope {
            scope_id: "scope-1".to_owned(),
            product_id: "product-1".to_owned(),
            workdir_ref: "workdir-1".to_owned(),
        },
        natural_language_intent: "nightly backup".to_owned(),
        schedule: NormalizedSchedule {
            kind: ScheduleKind::OneShot,
            expression: "once".to_owned(),
            calendar: "gregorian".to_owned(),
            timezone: "UTC".to_owned(),
            dst_fold: eliot_kernel_core::user_automation::DstFoldPolicy::First,
            dst_gap: eliot_kernel_core::user_automation::DstGapPolicy::ShiftForward,
            start_at: "2026-09-21T00:00:00Z".to_owned(),
            end_at: None,
            next_occurrences: vec!["2026-09-21T00:00:00Z".to_owned()],
            // This fixture carries a retired shape-only occurrence key, so the
            // owning calendar adapter has not issued a normalization binding
            // for it. Empty evidence can never satisfy the required binding, so
            // the revision stays refused instead of becoming admitted.
            normalization_receipt: Box::new(
                eliot_kernel_core::user_automation::ScheduleNormalizationReceipt {
                    receipt_id: String::new(),
                    normalizer_authority: String::new(),
                    source_digest: String::new(),
                    zone_database_revision:
                        eliot_kernel_core::user_automation::PINNED_ZONE_DATABASE_REVISION.to_owned(),
                    occurrences_digest: String::new(),
                },
            ),
        },
        mode: UserAutomationExecutionMode::DeterministicProcess,
        task: AutomationTaskBinding {
            qualified_ref: "script:backup".to_owned(),
            kind: AutomationTaskKind::QualifiedScript,
            capability_profile: AutomationCapabilityProfile {
                model_access: false,
                provider_access: false,
                automation_scheduling: false,
            },
        },
        portable_skill_package_revision_refs: Vec::new(),
        trusted_tool_definition_refs: Vec::new(),
        workdir_ref: "workdir-1".to_owned(),
        route_cost_policy: RouteCostPolicy {
            route_ref: "local".to_owned(),
            max_cost_units: 1,
            max_duration_ms: 1,
            policy_revision: None,
        },
        provider_policy: ProviderFingerprintPolicy::DeterministicOnly,
        delivery_target: AutomationDeliveryTarget {
            target_ref: "inbox".to_owned(),
            channels: vec![eliot_kernel_core::DeliveryChannel::ControlBoard],
            recipient_refs: Vec::new(),
        },
        preflight_contract_revision: "eliot.user-automation.preflight.v1".to_owned(),
        resource_ceiling: AutomationResourceCeiling {
            max_runtime_ms: 1,
            max_output_bytes: 1,
            max_child_count: 0,
        },
        overlap_policy: OverlapPolicy::ForbidOverlap,
        recursion_policy: RecursionPolicy {
            allow_child_automation: false,
            max_child_depth: 0,
        },
        configuration_state: state,
        work_class: eliot_kernel_core::user_automation::AutomationWorkClass::NormalBackground,
        current_execution_refs: Vec::new(),
        execution_history_query_ref: "history-1".to_owned(),
    }
}

fn revision_json(revision: &UserAutomationRevision) -> String {
    revision
        .validate()
        .expect("fixture revision is domain-valid");
    serde_json::to_string(revision).expect("fixture serializes")
}

/// Builds the verbatim normalization receipt envelope a revision leg must
/// retain, plus the identity those bytes carry.
///
/// The fixture issues a real envelope through the production
/// `ReceiptEnvelope::issue` constructor rather than hand-writing JSON, so the
/// retained bytes are the kind the owner actually stores and the identity is
/// genuinely derived from the core.
fn normalization_envelope(automation_id: &str, revision: &str) -> (String, String) {
    let request_id = RequestId::new("normalize-request").expect("request id");
    let metadata = eliot_receipts::RequestMetadata {
        request_id: request_id.clone(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-automation").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: fence(),
        clock: ClockReading::default(),
    };
    let core = eliot_receipts::ReceiptCore {
        contract: eliot_receipts::contract_identity().expect("receipt contract"),
        kind: eliot_receipts::ReceiptKind::Verification,
        work_scope: eliot_receipts::WorkScopeBinding {
            scope_id: eliot_receipts::WorkScopeId::new("scope-1").expect("scope"),
            product_id: metadata.product_id.clone(),
            resource_generation: ResourceGeneration::new(1).expect("generation"),
            state_fence: fence(),
        },
        task: None,
        session: None,
        causal: eliot_receipts::CausalBinding {
            state_fence: fence(),
            transaction_sequence: eliot_contracts::TransactionSequence::genesis(),
            parent_receipt_id: None,
            predecessor_receipt_ids: Vec::new(),
        },
        request: eliot_receipts::RequestBinding {
            metadata,
            state_fence: fence(),
        },
        operation: eliot_receipts::OperationBinding {
            operation_id: OperationId::new(format!("normalize-{automation_id}-{revision}"))
                .expect("operation"),
            request_id,
            idempotency_key: format!("normalize-{automation_id}-{revision}"),
            operation_kind: "user-automation.schedule.normalize".to_owned(),
            effect: EffectClass::Read,
            state_fence: fence(),
        },
        authority: eliot_receipts::AuthorityBinding {
            authority_id: eliot_contracts::ContractId::new("automation-normalizer")
                .expect("authority id"),
            authority_owner: "human-1".to_owned(),
            authority_epoch: fence().authority_epoch,
            state_fence: fence(),
            allowed_effect: EffectClass::Read,
            proof_ceiling: eliot_receipts::ProofCeiling::ScopedVerification,
        },
        artifacts: vec![eliot_receipts::ArtifactBinding {
            artifact_id: format!("compiled-occurrences:{automation_id}:{revision}"),
            sha256: "a".repeat(64),
            role: eliot_receipts::ReceiptKind::Artifact,
            source_revision: Some(
                eliot_kernel_core::user_automation::PINNED_ZONE_DATABASE_REVISION.to_owned(),
            ),
        }],
        verifier: None,
        problem: None,
        coordination: None,
        disposition: eliot_receipts::ReceiptDisposition::Success {
            proof: eliot_receipts::ProofCeiling::ScopedVerification,
        },
    };
    let envelope = eliot_receipts::ReceiptEnvelope::issue(core).expect("envelope issues");
    let identity = envelope.identity.receipt_id.as_str().to_owned();
    (
        serde_json::to_string(&envelope).expect("envelope serializes"),
        identity,
    )
}

fn invocation_for(automation_id: &str, revision: &str, nonce: &str) -> (String, String) {
    let invocation = UserAutomationInvocation {
        automation_id: automation_id.to_owned(),
        automation_revision: revision.to_owned(),
        trigger: UserAutomationTrigger::Manual {
            nonce: nonce.to_owned(),
        },
        mode: UserAutomationExecutionMode::DeterministicProcess,
        principal_ref: "human-1".to_owned(),
        work_scope_ref: "scope-1".to_owned(),
        workdir_ref: "workdir-1".to_owned(),
        trigger_origin: UserAutomationTriggerOrigin::Human,
        child_depth: 0,
        provenance: None,
    };
    invocation.validate().expect("fixture invocation valid");
    let occurrence_id = invocation
        .occurrence_identity()
        .expect("occurrence derives");
    let json = serde_json::to_string(&invocation).expect("fixture serializes");
    (occurrence_id, json)
}

fn transition_with(
    tag: &str,
    operation: NamedMutationOperation,
    parameters: BTreeMap<String, Value>,
) -> (RequestMeta, PreparedTransition) {
    let ctx = context(tag);
    let manifest_digest =
        operation_manifest_set_digest(&eliot_store_api::generated_operation_manifests().unwrap())
            .unwrap();
    let mut transition = PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new(format!("op-automation-{tag}")).expect("operation id"),
            idempotency_key: format!("idem-automation-{tag}"),
            canonical_request_hash: "0".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("user-automation").expect("scope"),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new("user-automation").expect("ordering")],
        transition_class: TransitionClass::UserAutomation,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: "c".repeat(64),
        operation_manifest_digest: manifest_digest,
        // Issue-#18 digests are derived below via `bind_issue18_digests`,
        // never defaulted; no semantic source is bound here (`[]`).
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
        named_operations: vec![NamedMutationRequest {
            operation,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
    let view = CanonicalRequestView::from_apply(&ctx, &transition, &[], &[]);
    transition.identity.canonical_request_hash =
        canonical_request_hash(&view).expect("hash computes");
    (ctx, transition)
}

fn apply(
    store: &MemoryStore,
    tag: &str,
    operation: NamedMutationOperation,
    parameters: BTreeMap<String, Value>,
) -> Result<WriteReceipt, StoreError> {
    let (ctx, transition) = transition_with(tag, operation, parameters);
    store.apply_transaction(&ctx, transition, &[], &[])
}

fn read(
    store: &MemoryStore,
    query: &str,
    automation_id: Option<&str>,
    include_retired: bool,
) -> Value {
    let request = automation_read_request(
        query.to_owned(),
        automation_id.map(str::to_owned),
        include_retired,
        64,
        fence(),
    )
    .expect("read builds");
    store
        .execute_named_sync(&request)
        .expect("read executes")
        .payload
}

fn check_domain_revision(payload_json: &str, automation_id: &str, revision: &str) {
    let parsed: UserAutomationRevision =
        serde_json::from_str(payload_json).expect("stored document parses");
    parsed
        .validate()
        .expect("stored document stays domain-valid");
    assert_eq!(parsed.automation_id, automation_id);
    assert_eq!(parsed.revision, revision);
}

#[test]
fn full_lifecycle_persists_lineage_with_pointer_cas() {
    let store = MemoryStore::new();
    let first = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    let request = automation_mutation_request(automation_create_params(
        "auto-1".to_owned(),
        "r-1".to_owned(),
        AUTOMATION_STATE_ACTIVE.to_owned(),
        revision_json(&first),
        normalization_envelope("auto-1", "r-1").0,
    ));
    apply(&store, "create-1", request.operation, request.parameters).expect("create commits");
    let payload = read(&store, "current", Some("auto-1"), false);
    assert_eq!(
        payload
            .get("current")
            .and_then(|current| current.get("revision"))
            .and_then(Value::as_str),
        Some("r-1")
    );
    // Edit supersedes with pointer compare-and-set.
    let mut second = valid_revision("auto-1", "r-2", UserAutomationConfigurationState::Active);
    second.supersedes = Some("r-1".to_owned());
    second
        .validate_supersedes(&first)
        .expect("fixture lineage is domain-valid");
    let request = automation_mutation_request(automation_edit_params(
        "auto-1".to_owned(),
        "r-1".to_owned(),
        "r-2".to_owned(),
        AUTOMATION_STATE_ACTIVE.to_owned(),
        revision_json(&second),
        normalization_envelope("auto-1", "r-2").0,
    ));
    apply(&store, "edit-1", request.operation, request.parameters).expect("edit commits");
    let payload = read(&store, "history", Some("auto-1"), false);
    let revisions = payload
        .get("revisions")
        .and_then(Value::as_array)
        .expect("history array");
    assert_eq!(revisions.len(), 2);
    for entry in revisions {
        check_domain_revision(
            entry
                .get("revision_json")
                .and_then(Value::as_str)
                .expect("document"),
            "auto-1",
            entry.get("revision").and_then(Value::as_str).expect("id"),
        );
    }
    // Pause moves admission state without touching the immutable revision.
    let request = automation_mutation_request(automation_state_transition_params(
        "pause".to_owned(),
        "auto-1".to_owned(),
        "r-2".to_owned(),
        AUTOMATION_STATE_PAUSED.to_owned(),
    ));
    apply(&store, "pause-1", request.operation, request.parameters).expect("pause commits");
    let payload = read(&store, "current", Some("auto-1"), false);
    assert_eq!(
        payload
            .get("current")
            .and_then(|current| current.get("configuration_state"))
            .and_then(Value::as_str),
        Some(AUTOMATION_STATE_PAUSED)
    );
    let payload = read(&store, "history", Some("auto-1"), false);
    assert_eq!(
        payload
            .get("revisions")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2),
        "pause writes no revision row"
    );
    // Resume then retire; retired rows filter from the default list.
    let request = automation_mutation_request(automation_state_transition_params(
        "resume".to_owned(),
        "auto-1".to_owned(),
        "r-2".to_owned(),
        AUTOMATION_STATE_ACTIVE.to_owned(),
    ));
    apply(&store, "resume-1", request.operation, request.parameters).expect("resume commits");
    let request = automation_mutation_request(automation_state_transition_params(
        "remove".to_owned(),
        "auto-1".to_owned(),
        "r-2".to_owned(),
        AUTOMATION_STATE_RETIRED.to_owned(),
    ));
    apply(&store, "remove-1", request.operation, request.parameters).expect("remove commits");
    let payload = read(&store, "list", None, false);
    assert_eq!(
        payload
            .get("currents")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0),
        "retired rows filter from the default list"
    );
    let payload = read(&store, "list", None, true);
    assert_eq!(
        payload
            .get("currents")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1),
        "retired rows serve on explicit request"
    );
}

#[test]
fn run_now_records_invocations_by_occurrence() {
    let store = MemoryStore::new();
    let first = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    let request = automation_mutation_request(automation_create_params(
        "auto-1".to_owned(),
        "r-1".to_owned(),
        AUTOMATION_STATE_ACTIVE.to_owned(),
        revision_json(&first),
        normalization_envelope("auto-1", "r-1").0,
    ));
    apply(&store, "create-1", request.operation, request.parameters).expect("create commits");
    let (occurrence_id, invocation) = invocation_for("auto-1", "r-1", "nonce-7");
    assert!(
        occurrence_id.starts_with("user-automation-occurrence:"),
        "occurrence identity carries the domain prefix"
    );
    let request = automation_mutation_request(automation_run_now_params(
        "auto-1".to_owned(),
        "r-1".to_owned(),
        occurrence_id.clone(),
        invocation,
    ));
    apply(&store, "run-1", request.operation, request.parameters).expect("run-now commits");
    let payload = read(&store, "invocations", Some("auto-1"), false);
    let invocations = payload
        .get("invocations")
        .and_then(Value::as_array)
        .expect("invocations array");
    assert_eq!(invocations.len(), 1);
    let stored = invocations[0]
        .get("invocation_json")
        .and_then(Value::as_str)
        .expect("document");
    let parsed: UserAutomationInvocation =
        serde_json::from_str(stored).expect("stored invocation parses");
    parsed
        .validate()
        .expect("stored invocation stays domain-valid");
    assert_eq!(
        parsed.occurrence_identity().expect("occurrence re-derives"),
        occurrence_id,
        "stored invocation re-derives its occurrence identity"
    );
    // Unknown revisions cannot be invoked.
    let (bogus_id, bogus) = invocation_for("auto-1", "r-9", "nonce-8");
    let request = automation_mutation_request(automation_run_now_params(
        "auto-1".to_owned(),
        "r-9".to_owned(),
        bogus_id,
        bogus,
    ));
    assert!(
        apply(&store, "run-2", request.operation, request.parameters).is_err(),
        "unknown revisions cannot be invoked"
    );
}

#[test]
fn lineage_and_key_conflicts_fail_closed() {
    let store = MemoryStore::new();
    let first = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    let create = || {
        automation_mutation_request(automation_create_params(
            "auto-1".to_owned(),
            "r-1".to_owned(),
            AUTOMATION_STATE_ACTIVE.to_owned(),
            revision_json(&first),
            normalization_envelope("auto-1", "r-1").0,
        ))
    };
    let request = create();
    apply(&store, "create-1", request.operation, request.parameters).expect("create commits");
    let request = create();
    assert_eq!(
        apply(&store, "create-2", request.operation, request.parameters),
        Err(StoreError::IdentityConflict),
        "double create fails closed"
    );
    // Stale lineage base fails closed.
    let request = automation_mutation_request(automation_edit_params(
        "auto-1".to_owned(),
        "r-0".to_owned(),
        "r-2".to_owned(),
        AUTOMATION_STATE_ACTIVE.to_owned(),
        revision_json(&valid_revision(
            "auto-1",
            "r-2",
            UserAutomationConfigurationState::Active,
        )),
        normalization_envelope("auto-1", "r-2").0,
    ));
    assert_eq!(
        apply(&store, "edit-stale", request.operation, request.parameters),
        Err(StoreError::IdentityConflict),
        "stale lineage base fails closed"
    );
    // Unknown automation transitions fail closed.
    let request = automation_mutation_request(automation_state_transition_params(
        "pause".to_owned(),
        "auto-absent".to_owned(),
        "r-1".to_owned(),
        AUTOMATION_STATE_PAUSED.to_owned(),
    ));
    assert!(
        apply(
            &store,
            "pause-absent",
            request.operation,
            request.parameters
        )
        .is_err(),
        "unknown automation transitions fail closed"
    );
    // Failure queries project explicit absence.
    let payload = read(&store, "failure", Some("auto-1"), false);
    assert!(payload.get("failure").is_some_and(Value::is_null));
    // Unknown currents project explicit absence.
    let payload = read(&store, "current", Some("auto-absent"), false);
    assert!(payload.get("current").is_some_and(Value::is_null));
}

#[test]
fn automation_operations_reject_a_foreign_transition_class() {
    let store = MemoryStore::new();
    let first = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    let (ctx, mut transition) = transition_with(
        "class-1",
        NamedMutationOperation::ApplyUserAutomationState,
        automation_create_params(
            "auto-1".to_owned(),
            "r-1".to_owned(),
            AUTOMATION_STATE_ACTIVE.to_owned(),
            revision_json(&first),
            normalization_envelope("auto-1", "r-1").0,
        ),
    );
    transition.transition_class = TransitionClass::CaptureCandidate;
    transition.requested_effect_ceiling = EffectClass::Candidate;
    assert_eq!(
        store.apply_transaction(&ctx, transition, &[], &[]),
        Err(StoreError::TransitionClassExceeded)
    );
}

/// Canonical failure document for one failure class.
fn failure_json(fingerprint: &str, dedup_key: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "fingerprint": fingerprint,
        "reason": "{\"CanonicalBlockedConfig\":{\"class\":\"provider-fingerprint\"}}",
        "notification_dedup_key": dedup_key,
    }))
    .expect("failure document serializes")
}

fn failure_params(
    automation_id: &str,
    revision: &str,
    occurrence_id: &str,
    fingerprint: &str,
) -> BTreeMap<String, Value> {
    automation_failure_params(
        automation_id.to_owned(),
        revision.to_owned(),
        occurrence_id.to_owned(),
        failure_json(fingerprint, "caller-key"),
    )
}

#[test]
fn failure_leg_records_converges_and_projects_last() {
    let store = MemoryStore::new();
    let fingerprint = "a".repeat(64);
    // Absence stays explicit before any failure write.
    let payload = read(&store, "failure", Some("auto-1"), false);
    assert!(payload.get("failure").is_some_and(Value::is_null));
    // Unknown revisions fail closed.
    let request =
        automation_mutation_request(failure_params("auto-absent", "r-1", "occ-1", &fingerprint));
    assert!(
        apply(
            &store,
            "failure-absent",
            request.operation,
            request.parameters
        )
        .is_err(),
        "unknown revision failures fail closed"
    );
    // Create the owning revision, then record the failure.
    let first = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    let request = automation_mutation_request(automation_create_params(
        "auto-1".to_owned(),
        "r-1".to_owned(),
        AUTOMATION_STATE_ACTIVE.to_owned(),
        revision_json(&first),
        normalization_envelope("auto-1", "r-1").0,
    ));
    apply(&store, "create-1", request.operation, request.parameters).expect("create commits");
    let request =
        automation_mutation_request(failure_params("auto-1", "r-1", "occ-1", &fingerprint));
    apply(&store, "failure-1", request.operation, request.parameters).expect("failure commits");
    let payload = read(&store, "failure", Some("auto-1"), false);
    let row = payload.get("failure").expect("failure row projects");
    assert_eq!(
        row.get("fingerprint").and_then(Value::as_str),
        Some(fingerprint.as_str())
    );
    assert_eq!(
        row.get("history_ref").and_then(Value::as_str),
        Some(format!("automation-failure:auto-1:r-1:{fingerprint}").as_str()),
    );
    assert_eq!(
        row.get("source_operation_id").and_then(Value::as_str),
        Some("op-automation-failure-1")
    );
    // A repeat of one failure class from another operation converges on
    // the existing row: same reference, first-writer provenance kept.
    let request =
        automation_mutation_request(failure_params("auto-1", "r-1", "occ-2", &fingerprint));
    apply(&store, "failure-2", request.operation, request.parameters).expect("repeat converges");
    let repeat = read(&store, "failure", Some("auto-1"), false);
    assert_eq!(repeat.get("failure"), payload.get("failure"));
    // A divergent document under one failure key fails closed: same
    // fingerprint, different reason wire value.
    let divergent_json = serde_json::to_string(&serde_json::json!({
        "fingerprint": fingerprint,
        "reason": "{\"DeterministicModelAccess\":null}",
        "notification_dedup_key": "caller-key",
    }))
    .expect("divergent document serializes");
    let mut divergent = failure_params("auto-1", "r-1", "occ-3", &fingerprint);
    divergent.insert("failure_json".to_owned(), Value::String(divergent_json));
    let request = automation_mutation_request(divergent);
    assert_eq!(
        apply(
            &store,
            "failure-divergent",
            request.operation,
            request.parameters
        ),
        Err(StoreError::IdentityConflict),
        "divergent failure documents fail closed"
    );
    // A second failure class moves the last-failure pointer.
    let other = "b".repeat(64);
    let request = automation_mutation_request(failure_params("auto-1", "r-1", "occ-4", &other));
    apply(&store, "failure-3", request.operation, request.parameters).expect("second commits");
    let payload = read(&store, "failure", Some("auto-1"), false);
    assert_eq!(
        payload
            .get("failure")
            .and_then(|row| row.get("fingerprint"))
            .and_then(Value::as_str),
        Some(other.as_str())
    );
}

/// Reads the retained normalization envelopes for one exact receipt identity.
fn read_normalization(
    store: &MemoryStore,
    automation_id: &str,
    revision: &str,
    receipt_id: &str,
) -> Vec<Value> {
    let request = eliot_store_api::automation_normalization_read_request(
        automation_id.to_owned(),
        revision.to_owned(),
        receipt_id.to_owned(),
        fence(),
    )
    .expect("normalization read builds");
    store
        .execute_named_sync(&request)
        .expect("normalization read executes")
        .payload
        .get("normalization_envelopes")
        .and_then(Value::as_array)
        .cloned()
        .expect("exact normalization projection")
}

#[test]
fn owner_retains_and_reads_back_its_normalization_envelope() {
    let store = MemoryStore::new();
    let first = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    let (create_envelope, create_identity) = normalization_envelope("auto-1", "r-1");
    let request = automation_mutation_request(automation_create_params(
        "auto-1".to_owned(),
        "r-1".to_owned(),
        AUTOMATION_STATE_ACTIVE.to_owned(),
        revision_json(&first),
        create_envelope.clone(),
    ));
    apply(&store, "create-1", request.operation, request.parameters).expect("create commits");

    // The retained envelope comes back as the OWNER'S OWN bytes, and the
    // envelope's own identity is what selects it.
    let envelopes = read_normalization(&store, "auto-1", "r-1", &create_identity);
    assert_eq!(envelopes.len(), 1, "the owner's retained envelope is answerable");
    assert_eq!(
        envelopes[0]
            .get("envelope_json")
            .and_then(Value::as_str),
        Some(create_envelope.as_str()),
        "the readback returns the exact bytes the owner retained, not a re-derived value"
    );
    let returned: eliot_receipts::ReceiptEnvelope =
        serde_json::from_str(create_envelope.as_str()).expect("retained bytes parse");
    returned.validate().expect("retained envelope is real");
    assert_eq!(
        returned.identity.receipt_id.as_str(),
        create_identity,
        "the retained identity is genuinely content-derived"
    );

    // Selection is by that identity, not by row address: any other identity
    // yields nothing rather than some other envelope.
    let (other_envelope, other_identity) = normalization_envelope("auto-1", "r-2");
    assert!(other_identity != create_identity);
    assert!(
        read_normalization(&store, "auto-1", "r-1", &other_identity).is_empty(),
        "a receipt identity this revision never retained answers nothing"
    );
    assert!(
        read_normalization(&store, "auto-1", "r-2", &create_identity).is_empty(),
        "a receipt identity is not answerable under a revision that never retained it"
    );
    assert!(
        read_normalization(&store, "auto-2", "r-1", &create_identity).is_empty(),
        "a receipt identity is not answerable under another automation"
    );
    let _ = other_envelope;

    // The immutable revision row retains ONE envelope: repeating the leg with a
    // different envelope for the same revision document is a divergent claim
    // about that immutable row, so it fails closed instead of converging.
    let mut replay = request.parameters.clone();
    replay.insert(
        eliot_store_api::AUTOMATION_PARAM_NORMALIZATION_ENVELOPE_JSON.to_owned(),
        Value::String(normalization_envelope("auto-1", "r-1-other").0),
    );
    let replay = automation_mutation_request(replay);
    assert_eq!(
        apply(
            &store,
            "create-replay",
            replay.operation,
            replay.parameters
        ),
        Err(StoreError::IdentityConflict),
        "an immutable revision row cannot be re-bound to a different envelope"
    );

    // An edit retains its OWN envelope for the new revision, and the two
    // revisions stay separately answerable under this one owner.
    let mut second = valid_revision("auto-1", "r-2", UserAutomationConfigurationState::Active);
    second.supersedes = Some("r-1".to_owned());
    second
        .validate_supersedes(&first)
        .expect("fixture lineage is valid");
    let (edit_envelope, edit_identity) = normalization_envelope("auto-1", "r-2");
    let request = automation_mutation_request(automation_edit_params(
        "auto-1".to_owned(),
        "r-1".to_owned(),
        "r-2".to_owned(),
        AUTOMATION_STATE_ACTIVE.to_owned(),
        revision_json(&second),
        edit_envelope.clone(),
    ));
    apply(&store, "edit-1", request.operation, request.parameters).expect("edit commits");
    let envelopes = read_normalization(&store, "auto-1", "r-2", &edit_identity);
    assert_eq!(envelopes.len(), 1);
    assert_eq!(
        envelopes[0].get("envelope_json").and_then(Value::as_str),
        Some(edit_envelope.as_str()),
        "the edit leg retains the envelope it minted for the new revision"
    );
    // The superseded revision's envelope is still retained on its own row.
    assert_eq!(
        read_normalization(&store, "auto-1", "r-1", &create_identity).len(),
        1,
        "the superseded revision keeps its own retained envelope"
    );
}
