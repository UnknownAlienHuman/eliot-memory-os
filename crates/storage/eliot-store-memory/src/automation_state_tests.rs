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
const AUTOMATION_PAGE_LIMIT: u16 = 64;

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
    let admission_contract_set_digest =
        eliot_store_api::supported_admission_contract_set_digest().unwrap();
    let manifest_digest =
        operation_manifest_set_digest(&eliot_store_api::generated_operation_manifests().unwrap())
            .unwrap();
    let mut transition = PreparedTransition {
        contract_version: eliot_store_api::CONTRACT_VERSION,
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
        admission_contract_set_digest,
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

fn read_automation_page(
    store: &MemoryStore,
    query: &str,
    automation_id: &str,
    max_records: u16,
    state_fence: &StateFence,
    cursor: Option<&str>,
) -> Result<Value, StoreError> {
    let mut request = automation_read_request(
        query.to_owned(),
        Some(automation_id.to_owned()),
        false,
        max_records,
        state_fence.clone(),
    )?;
    if let Some(cursor) = cursor {
        request.parameters.insert(
            eliot_store_api::AUTOMATION_PARAM_CURSOR.to_owned(),
            Value::String(cursor.to_owned()),
        );
    }
    Ok(store.execute_named_sync(&request)?.payload)
}

fn read_automation_selector(
    store: &MemoryStore,
    query: &str,
    automation_id: &str,
    max_records: u16,
    state_fence: &StateFence,
    selector: (&str, &str),
    cursor: Option<&str>,
) -> Result<Value, StoreError> {
    let mut request = automation_read_request(
        query.to_owned(),
        Some(automation_id.to_owned()),
        false,
        max_records,
        state_fence.clone(),
    )?;
    request
        .parameters
        .insert(selector.0.to_owned(), Value::String(selector.1.to_owned()));
    if let Some(cursor) = cursor {
        request.parameters.insert(
            eliot_store_api::AUTOMATION_PARAM_CURSOR.to_owned(),
            Value::String(cursor.to_owned()),
        );
    }
    Ok(store.execute_named_sync(&request)?.payload)
}

fn automation_page_cursor(payload: &Value) -> &str {
    payload
        .get("completeness")
        .and_then(|completeness| completeness.get(eliot_store_api::AUTOMATION_PAGE_NEXT_CURSOR))
        .and_then(Value::as_str)
        .expect("truncated page carries its owner cursor")
}

fn automation_page_row_ids(payload: &Value, query: &str) -> Vec<String> {
    let (rows_field, identity_field) = match query {
        eliot_store_api::AUTOMATION_QUERY_HISTORY => ("revisions", "revision"),
        eliot_store_api::AUTOMATION_QUERY_INVOCATIONS => ("invocations", "occurrence_id"),
        _ => panic!("page matrix query is history or invocations"),
    };
    payload
        .get(rows_field)
        .and_then(Value::as_array)
        .expect("automation page rows are an array")
        .iter()
        .map(|row| {
            row.get(identity_field)
                .and_then(Value::as_str)
                .expect("automation page row has its logical identity")
                .to_owned()
        })
        .collect()
}

fn assert_automation_page(
    payload: &Value,
    query: &str,
    expected_ids: &[String],
    truncated: bool,
) -> Vec<String> {
    let actual_ids = automation_page_row_ids(payload, query);
    assert!(
        actual_ids.len() <= usize::from(AUTOMATION_PAGE_LIMIT),
        "one page never exceeds max_records"
    );
    assert_eq!(
        actual_ids.as_slice(),
        expected_ids,
        "page returns its expected logical slice"
    );
    assert_eq!(
        actual_ids.last().map(String::as_str),
        expected_ids.last().map(String::as_str),
        "page tail is the last logical row in the expected slice"
    );
    assert_eq!(
        payload.get("revision").and_then(Value::as_u64),
        Some(actual_ids.len() as u64),
        "page count matches its returned rows"
    );
    let completeness = payload
        .get("completeness")
        .expect("automation page has completeness metadata");
    assert_eq!(
        completeness.get("returned").and_then(Value::as_u64),
        Some(actual_ids.len() as u64),
        "completeness reports the returned page count"
    );
    assert_eq!(
        completeness.get("coverage").and_then(Value::as_str),
        Some(if truncated { "TRUNCATED" } else { "COMPLETE" }),
        "coverage follows the independent eligible-row count"
    );
    let cursor = completeness.get(eliot_store_api::AUTOMATION_PAGE_NEXT_CURSOR);
    assert_eq!(
        cursor.is_some(),
        truncated,
        "only truncated pages carry a cursor"
    );
    if truncated {
        assert!(
            cursor.and_then(Value::as_str).is_some(),
            "a truncated page carries its owner cursor"
        );
    }
    actual_ids
}

fn create_automation_page_corpus(
    store: &MemoryStore,
    automation_id: &str,
    record_count: usize,
) -> (Vec<String>, Vec<String>) {
    assert!(record_count > 0, "pagination corpus has at least one row");

    let first_revision_id = "r-001".to_owned();
    let mut previous = valid_revision(
        automation_id,
        &first_revision_id,
        UserAutomationConfigurationState::Active,
    );
    let create = automation_mutation_request(automation_create_params(
        automation_id.to_owned(),
        previous.revision.clone(),
        AUTOMATION_STATE_ACTIVE.to_owned(),
        revision_json(&previous),
    ));
    apply(
        store,
        &format!("page-matrix-{record_count}-create"),
        create.operation,
        create.parameters,
    )
    .expect("initial pagination revision commits");

    let mut expected_revision_ids = Vec::with_capacity(record_count);
    expected_revision_ids.push(previous.revision.clone());
    for revision_number in 2..=record_count {
        let revision_id = format!("r-{revision_number:03}");
        let mut next = valid_revision(
            automation_id,
            &revision_id,
            UserAutomationConfigurationState::Active,
        );
        next.supersedes = Some(previous.revision.clone());
        next.validate_supersedes(&previous)
            .expect("pagination fixture lineage is valid");
        let edit = automation_mutation_request(automation_edit_params(
            automation_id.to_owned(),
            previous.revision.clone(),
            revision_id,
            AUTOMATION_STATE_ACTIVE.to_owned(),
            revision_json(&next),
        ));
        apply(
            store,
            &format!("page-matrix-{record_count}-edit-{revision_number}"),
            edit.operation,
            edit.parameters,
        )
        .expect("pagination successor revision commits");
        expected_revision_ids.push(next.revision.clone());
        previous = next;
    }
    expected_revision_ids.sort_unstable();

    let mut expected_occurrence_ids = Vec::with_capacity(record_count);
    for (index, revision_id) in expected_revision_ids.iter().enumerate() {
        let run_number = index + 1;
        let nonce = format!("page-matrix-{record_count}-{run_number:03}");
        let (occurrence_id, invocation) = invocation_for(automation_id, revision_id, &nonce);
        let run = automation_mutation_request(automation_run_now_params(
            automation_id.to_owned(),
            revision_id.clone(),
            occurrence_id.clone(),
            invocation,
        ));
        apply(
            store,
            &format!("page-matrix-{record_count}-run-{run_number}"),
            run.operation,
            run.parameters,
        )
        .expect("pagination invocation commits");
        expected_occurrence_ids.push(occurrence_id);
    }
    expected_occurrence_ids.sort_unstable();

    (expected_revision_ids, expected_occurrence_ids)
}

fn read_automation_page_replay(
    store: &MemoryStore,
    query: &str,
    automation_id: &str,
    max_records: u16,
    state_fence: &StateFence,
    cursor: Option<&str>,
    assertion_message: Option<&str>,
) -> Value {
    let payload = read_automation_page(
        store,
        query,
        automation_id,
        max_records,
        state_fence,
        cursor,
    )
    .expect("owner serves the page");
    let replay = read_automation_page(
        store,
        query,
        automation_id,
        max_records,
        state_fence,
        cursor,
    )
    .expect("exact page replay succeeds");
    if let Some(message) = assertion_message {
        assert_eq!(payload, replay, "{message}");
    } else {
        assert_eq!(payload, replay);
    }
    payload
}

fn assert_automation_page_walk(
    store: &MemoryStore,
    query: &str,
    automation_id: &str,
    state_fence: &StateFence,
    expected_ids: &[String],
) -> Vec<(usize, bool)> {
    assert!(!expected_ids.is_empty());
    assert_eq!(
        expected_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        expected_ids.len(),
        "fixture logical identities are unique"
    );

    let limit = usize::from(AUTOMATION_PAGE_LIMIT);
    let mut cursor: Option<String> = None;
    let mut offset = 0;
    let mut page_number = 0;
    let mut walked_ids = Vec::with_capacity(expected_ids.len());
    let mut page_shapes = Vec::new();
    while offset < expected_ids.len() {
        let expected_end = (offset + limit).min(expected_ids.len());
        let expected_page = &expected_ids[offset..expected_end];
        let truncated = expected_end < expected_ids.len();
        let replay_message =
            format!("replaying page {page_number} preserves page and cursor identity");
        let payload = read_automation_page_replay(
            store,
            query,
            automation_id,
            AUTOMATION_PAGE_LIMIT,
            state_fence,
            cursor.as_deref(),
            Some(&replay_message),
        );
        let page_ids = assert_automation_page(&payload, query, expected_page, truncated);
        page_shapes.push((page_ids.len(), truncated));
        if page_number == 1 {
            assert_eq!(
                page_ids.first().map(String::as_str),
                expected_ids.get(limit).map(String::as_str),
                "continuation resumes immediately after the 64-row prefix"
            );
        }
        walked_ids.extend(page_ids);
        offset = expected_end;
        cursor = if truncated {
            Some(automation_page_cursor(&payload).to_owned())
        } else {
            None
        };
        page_number += 1;
    }

    assert_eq!(
        walked_ids.as_slice(),
        expected_ids,
        "page walk has no omissions or reordering"
    );
    assert_eq!(
        walked_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        walked_ids.len(),
        "page walk has no duplicate logical rows"
    );
    assert_eq!(
        walked_ids.last().map(String::as_str),
        expected_ids.last().map(String::as_str),
        "page walk ends at the independently known logical tail"
    );
    page_shapes
}

fn assert_wrong_continuation_tail_refused(
    store: &MemoryStore,
    query: eliot_store_api::AutomationContinuationQuery,
    automation_id: &str,
    read_revision: &str,
    state_fence: &StateFence,
    cursor: &str,
) {
    let reference = eliot_store_api::AutomationContinuationRef::parse_wire(cursor)
        .expect("backend issued a canonical continuation");
    let request = super::MemoryAutomationContinuationRequest {
        query,
        include_retired: false,
        automation_id,
        read_revision,
        state_fence,
        max_records: 1,
    };
    let now_ms = super::memory_continuation_now_ms().expect("clock is available");
    let state = store.lock_state().expect("memory state lock succeeds");
    let retained_count = state.automation_continuations.len();
    let first_page_result = super::memory_continuation_existing_first_page(
        &state,
        &request,
        "wrong-returned-tail",
        now_ms,
    );
    assert!(
        matches!(
            first_page_result,
            Err(StoreError::AutomationContinuation(
                eliot_store_api::AutomationContinuationFailure::StaleSnapshot
            ))
        ),
        "a changed root-page boundary fails closed"
    );
    let result = super::memory_continuation_existing_successor(
        &state,
        &request,
        reference.identifier(),
        "wrong-returned-tail",
        now_ms,
    );
    assert!(
        matches!(
            result,
            Err(StoreError::AutomationContinuation(
                eliot_store_api::AutomationContinuationFailure::StaleSnapshot
            ))
        ),
        "a changed returned boundary fails closed"
    );
    assert_eq!(
        state.automation_continuations.len(),
        retained_count,
        "refusing a changed tail does not mint or retain another cursor"
    );
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

type AutomationPageMatrixCase = (usize, String, Vec<String>, Vec<String>);

fn create_automation_replay_corpus(store: &MemoryStore) -> (Vec<String>, Vec<String>) {
    let mut previous = valid_revision(
        "auto-page-replay",
        "r-1",
        UserAutomationConfigurationState::Active,
    );
    let mut expected_revision_ids = vec![previous.revision.clone()];
    let create = automation_mutation_request(automation_create_params(
        "auto-page-replay".to_owned(),
        "r-1".to_owned(),
        AUTOMATION_STATE_ACTIVE.to_owned(),
        revision_json(&previous),
    ));
    apply(
        store,
        "page-replay-create",
        create.operation,
        create.parameters,
    )
    .expect("initial revision commits");
    for revision_number in 2..=3 {
        let revision = format!("r-{revision_number}");
        let mut next = valid_revision(
            "auto-page-replay",
            &revision,
            UserAutomationConfigurationState::Active,
        );
        next.supersedes = Some(previous.revision.clone());
        next.validate_supersedes(&previous)
            .expect("fixture lineage is valid");
        let edit = automation_mutation_request(automation_edit_params(
            "auto-page-replay".to_owned(),
            previous.revision.clone(),
            revision,
            AUTOMATION_STATE_ACTIVE.to_owned(),
            revision_json(&next),
        ));
        apply(
            store,
            &format!("page-replay-edit-{revision_number}"),
            edit.operation,
            edit.parameters,
        )
        .expect("successor revision commits");
        expected_revision_ids.push(next.revision.clone());
        previous = next;
    }
    expected_revision_ids.sort_unstable();

    let mut expected_occurrence_ids = Vec::new();
    for run_number in 1..=3 {
        let nonce = format!("page-replay-{run_number}");
        let (occurrence_id, invocation) = invocation_for("auto-page-replay", "r-3", &nonce);
        expected_occurrence_ids.push(occurrence_id.clone());
        let run = automation_mutation_request(automation_run_now_params(
            "auto-page-replay".to_owned(),
            "r-3".to_owned(),
            occurrence_id,
            invocation,
        ));
        apply(
            store,
            &format!("page-replay-run-{run_number}"),
            run.operation,
            run.parameters,
        )
        .expect("invocation commits");
    }
    expected_occurrence_ids.sort_unstable();
    (expected_revision_ids, expected_occurrence_ids)
}

fn assert_retained_automation_cursor_count(
    store: &MemoryStore,
    expected_count: usize,
    assertion_message: &str,
) {
    assert_eq!(
        store
            .lock_state()
            .expect("memory state lock succeeds")
            .automation_continuations
            .len(),
        expected_count,
        "{assertion_message}"
    );
}

fn assert_automation_root_page_replay(
    store: &MemoryStore,
    query: &str,
    state_fence: &StateFence,
    expected_cursor_count: usize,
    cursor_count_message: &str,
) -> (Value, String) {
    let page =
        read_automation_page_replay(store, query, "auto-page-replay", 1, state_fence, None, None);
    if query == eliot_store_api::AUTOMATION_QUERY_HISTORY {
        assert_eq!(
            page.get("revision").and_then(Value::as_u64),
            Some(1),
            "history page returns only its one-row bound"
        );
    }
    let cursor = automation_page_cursor(&page).to_owned();
    assert_retained_automation_cursor_count(store, expected_cursor_count, cursor_count_message);
    (page, cursor)
}

fn assert_automation_continuation_page_replay(
    store: &MemoryStore,
    query: &str,
    state_fence: &StateFence,
    cursor: &str,
    coverage_message: &str,
) -> String {
    let page = read_automation_page_replay(
        store,
        query,
        "auto-page-replay",
        1,
        state_fence,
        Some(cursor),
        None,
    );
    assert_eq!(
        page["completeness"]["coverage"], "TRUNCATED",
        "{coverage_message}"
    );
    automation_page_cursor(&page).to_owned()
}

fn assert_automation_root_page_identity_unchanged(
    store: &MemoryStore,
    query: &str,
    state_fence: &StateFence,
    expected_page: &Value,
    assertion_message: &str,
) {
    let replay_expectation = match query {
        eliot_store_api::AUTOMATION_QUERY_HISTORY => {
            "history first-page replay after continuation reads"
        }
        eliot_store_api::AUTOMATION_QUERY_INVOCATIONS => {
            "invocation first-page replay after continuation reads"
        }
        _ => panic!("page identity query is history or invocations"),
    };
    assert_eq!(
        read_automation_page(store, query, "auto-page-replay", 1, state_fence, None,)
            .expect(replay_expectation),
        *expected_page,
        "{assertion_message}"
    );
}

fn create_issue_2860_matrix_cases(store: &MemoryStore) -> Vec<AutomationPageMatrixCase> {
    let mut cases = Vec::new();
    for record_count in [63_usize, 64, 65, 66, 127, 128, 129, 130] {
        let automation_id = format!("auto-page-matrix-{record_count}");
        let (revision_ids, occurrence_ids) =
            create_automation_page_corpus(store, &automation_id, record_count);
        assert_eq!(revision_ids.len(), record_count);
        assert_eq!(occurrence_ids.len(), record_count);
        cases.push((record_count, automation_id, revision_ids, occurrence_ids));
    }
    cases
}

fn create_foreign_probe_corpus(store: &MemoryStore) -> (String, Vec<String>, Vec<String>) {
    // This separately committed automation is a real same-fence row that is
    // foreign to the 64-row target selector. Its high automation identity puts
    // its history row after the target history rows in the owner's key order.
    let automation_id = "z-auto-page-foreign-probe".to_owned();
    let (revision_ids, occurrence_ids) = create_automation_page_corpus(store, &automation_id, 1);
    (automation_id, revision_ids, occurrence_ids)
}

fn assert_issue_2860_matrix_walks(
    store: &MemoryStore,
    state_fence: &StateFence,
    cases: &[AutomationPageMatrixCase],
) {
    // All source mutations precede reads so every continuation stays bound to
    // the same owner-issued read revision throughout the matrix walk.
    for (record_count, automation_id, revision_ids, occurrence_ids) in cases {
        let history_page_shapes = assert_automation_page_walk(
            store,
            eliot_store_api::AUTOMATION_QUERY_HISTORY,
            automation_id,
            state_fence,
            revision_ids,
        );
        let invocation_page_shapes = assert_automation_page_walk(
            store,
            eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
            automation_id,
            state_fence,
            occurrence_ids,
        );
        let expected_page_shapes: &[(usize, bool)] = match *record_count {
            63 => &[(63, false)],
            64 => &[(64, false)],
            65 => &[(64, true), (1, false)],
            66 => &[(64, true), (2, false)],
            // Continued-page fixtures contain the 64-row prefix plus 63,
            // 64, 65, or 66 remaining rows respectively.
            127 => &[(64, true), (63, false)],
            128 => &[(64, true), (64, false)],
            129 => &[(64, true), (64, true), (1, false)],
            130 => &[(64, true), (64, true), (2, false)],
            _ => unreachable!("matrix has only the named boundary sizes"),
        };
        assert_eq!(history_page_shapes.as_slice(), expected_page_shapes);
        assert_eq!(invocation_page_shapes.as_slice(), expected_page_shapes);
    }
}

fn assert_foreign_probe_walks(
    store: &MemoryStore,
    state_fence: &StateFence,
    automation_id: &str,
    revision_ids: &[String],
    occurrence_ids: &[String],
) {
    assert_eq!(
        assert_automation_page_walk(
            store,
            eliot_store_api::AUTOMATION_QUERY_HISTORY,
            automation_id,
            state_fence,
            revision_ids,
        ),
        vec![(1, false)],
        "same-fence foreign history row is real owner data"
    );
    assert_eq!(
        assert_automation_page_walk(
            store,
            eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
            automation_id,
            state_fence,
            occurrence_ids,
        ),
        vec![(1, false)],
        "same-fence foreign invocation row is real owner data"
    );
}

fn assert_exact_issue_2860_selectors(
    store: &MemoryStore,
    state_fence: &StateFence,
    automation_id: &str,
    revision_ids: &[String],
    occurrence_ids: &[String],
) {
    let exact_revision_id = &revision_ids[63];
    let history_cursor = automation_page_cursor(
        &read_automation_page(
            store,
            eliot_store_api::AUTOMATION_QUERY_HISTORY,
            automation_id,
            AUTOMATION_PAGE_LIMIT,
            state_fence,
            None,
        )
        .expect("owner issues a history page cursor from ordinary writes"),
    )
    .to_owned();
    assert_exact_selector_rejects_cursor(
        store,
        eliot_store_api::AUTOMATION_QUERY_HISTORY,
        automation_id,
        state_fence,
        (
            eliot_store_api::AUTOMATION_PARAM_REVISION,
            exact_revision_id,
        ),
        std::slice::from_ref(exact_revision_id),
        history_cursor.as_str(),
    );

    let exact_occurrence_id = &occurrence_ids[63];
    let invocation_cursor = automation_page_cursor(
        &read_automation_page(
            store,
            eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
            automation_id,
            AUTOMATION_PAGE_LIMIT,
            state_fence,
            None,
        )
        .expect("owner issues an invocation page cursor from ordinary writes"),
    )
    .to_owned();
    assert_exact_selector_rejects_cursor(
        store,
        eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
        automation_id,
        state_fence,
        (
            eliot_store_api::AUTOMATION_PARAM_OCCURRENCE_ID,
            exact_occurrence_id,
        ),
        std::slice::from_ref(exact_occurrence_id),
        invocation_cursor.as_str(),
    );
}

fn assert_exact_selector_rejects_cursor(
    store: &MemoryStore,
    query: &str,
    automation_id: &str,
    state_fence: &StateFence,
    selector: (&str, &str),
    expected_ids: &[String],
    cursor: &str,
) {
    let exact = read_automation_selector(
        store,
        query,
        automation_id,
        AUTOMATION_PAGE_LIMIT,
        state_fence,
        selector,
        None,
    )
    .expect("exact automation selector reads");
    assert_automation_page(&exact, query, expected_ids, false);
    assert!(
        matches!(
            read_automation_selector(
                store,
                query,
                automation_id,
                AUTOMATION_PAGE_LIMIT,
                state_fence,
                selector,
                Some(cursor),
            ),
            Err(StoreError::AutomationContinuation(
                eliot_store_api::AutomationContinuationFailure::InvalidOrUnknown
            ))
        ),
        "an exact automation selector rejects its owner-issued page cursor"
    );
}

fn assert_foreign_generation_refusals(
    store: &MemoryStore,
    state_fence: &StateFence,
    automation_id: &str,
) {
    let foreign_generation_fence = StateFence::new(
        state_fence.authority_epoch.clone(),
        ResourceGeneration::new(9).expect("generation"),
    );
    for query in [
        eliot_store_api::AUTOMATION_QUERY_HISTORY,
        eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
    ] {
        assert!(
            matches!(
                read_automation_page(
                    store,
                    query,
                    automation_id,
                    AUTOMATION_PAGE_LIMIT,
                    &foreign_generation_fence,
                    None,
                ),
                Err(StoreError::FenceMismatch)
            ),
            "a read under a foreign generation fails with the owner's typed fence refusal"
        );
    }
}

fn assert_root_and_continued_cursor_identity(
    store: &MemoryStore,
    state_fence: &StateFence,
    history_cursor: &str,
    invocation_cursor: &str,
) {
    for (query, root_cursor, coverage_message, identity_message) in [
        (
            eliot_store_api::AUTOMATION_QUERY_HISTORY,
            history_cursor,
            "continued history page retains its further-row cursor",
            "the continued history page has its own next-page identity",
        ),
        (
            eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
            invocation_cursor,
            "continued invocation page retains its further-row cursor",
            "the continued invocation page has its own next-page identity",
        ),
    ] {
        let continued_cursor = assert_automation_continuation_page_replay(
            store,
            query,
            state_fence,
            root_cursor,
            coverage_message,
        );
        assert_ne!(root_cursor, continued_cursor.as_str(), "{identity_message}");
    }
}

/// Test-only fault injection: corrupted retained root tails must be refused.
fn assert_corrupted_root_cursor_replays_refused(
    store: &MemoryStore,
    state_fence: &StateFence,
    page_cases: [(&str, &str, &[String]); 2],
) {
    for (query, cursor, expected_ids) in page_cases {
        assert!(expected_ids.len() > 1, "fixture has a next logical row");
        let reference = eliot_store_api::AutomationContinuationRef::parse_wire(cursor)
            .expect("backend issued a canonical root continuation");
        let retained_count = {
            let mut state = store.lock_state().expect("memory state lock succeeds");
            let retained_count = state.automation_continuations.len();
            let Some(super::MemoryAutomationContinuationEntry::Active(record)) = state
                .automation_continuations
                .get_mut(reference.identifier())
            else {
                panic!("root cursor retains its original owner record");
            };
            assert_eq!(
                record.exclusive_returned_tail.as_str(),
                expected_ids[0].as_str(),
                "root cursor retains the tail actually returned on its page"
            );
            record.exclusive_returned_tail = expected_ids[1].clone();
            retained_count
        };
        assert!(
            matches!(
                read_automation_page(store, query, "auto-page-replay", 1, state_fence, None,),
                Err(StoreError::AutomationContinuation(
                    eliot_store_api::AutomationContinuationFailure::StaleSnapshot
                ))
            ),
            "a root-page replay refuses a corrupted retained tail"
        );
        assert_retained_automation_cursor_count(
            store,
            retained_count,
            "refusing a corrupted original cursor does not mint a replacement",
        );
    }
}

#[test]
fn automation_page_replay_preserves_first_and_continued_cursor_identity() {
    let store = MemoryStore::new();
    let state_fence = fence();
    let (history_ids, invocation_ids) = create_automation_replay_corpus(&store);

    let (history_first, history_first_cursor) = assert_automation_root_page_replay(
        &store,
        eliot_store_api::AUTOMATION_QUERY_HISTORY,
        &state_fence,
        1,
        "replaying a root page retains one cursor identity",
    );

    let (invocations_first, invocations_first_cursor) = assert_automation_root_page_replay(
        &store,
        eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
        &state_fence,
        2,
        "replaying both root pages does not add duplicate cursors",
    );
    let history_read_revision = history_first["completeness"]["read_revision"]
        .as_str()
        .expect("owner read revision exists")
        .to_owned();
    let invocations_read_revision = invocations_first["completeness"]["read_revision"]
        .as_str()
        .expect("owner read revision exists")
        .to_owned();

    assert_root_and_continued_cursor_identity(
        &store,
        &state_fence,
        &history_first_cursor,
        &invocations_first_cursor,
    );
    assert_retained_automation_cursor_count(
        &store,
        4,
        "replaying continued pages reuses their linked successor cursors",
    );
    assert_automation_root_page_identity_unchanged(
        &store,
        eliot_store_api::AUTOMATION_QUERY_HISTORY,
        &state_fence,
        &history_first,
        "continuing later pages does not change the root page identity",
    );
    assert_automation_root_page_identity_unchanged(
        &store,
        eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
        &state_fence,
        &invocations_first,
        "continuing later pages does not change the root page identity",
    );
    assert_retained_automation_cursor_count(
        &store,
        4,
        "root replays still reuse the original cursor after child issuance",
    );

    assert_wrong_continuation_tail_refused(
        &store,
        eliot_store_api::AutomationContinuationQuery::History,
        "auto-page-replay",
        &history_read_revision,
        &state_fence,
        &history_first_cursor,
    );
    assert_wrong_continuation_tail_refused(
        &store,
        eliot_store_api::AutomationContinuationQuery::Invocations,
        "auto-page-replay",
        &invocations_read_revision,
        &state_fence,
        &invocations_first_cursor,
    );
    assert_corrupted_root_cursor_replays_refused(
        &store,
        &state_fence,
        [
            (
                eliot_store_api::AUTOMATION_QUERY_HISTORY,
                history_first_cursor.as_str(),
                history_ids.as_slice(),
            ),
            (
                eliot_store_api::AUTOMATION_QUERY_INVOCATIONS,
                invocations_first_cursor.as_str(),
                invocation_ids.as_slice(),
            ),
        ],
    );
}

#[test]
fn automation_history_and_invocation_pages_obey_issue_2860_matrix() {
    let store = MemoryStore::new();
    let state_fence = fence();
    let cases = create_issue_2860_matrix_cases(&store);
    let (foreign_automation_id, foreign_revision_ids, foreign_occurrence_ids) =
        create_foreign_probe_corpus(&store);

    assert_issue_2860_matrix_walks(&store, &state_fence, &cases);
    assert_foreign_probe_walks(
        &store,
        &state_fence,
        &foreign_automation_id,
        &foreign_revision_ids,
        &foreign_occurrence_ids,
    );

    let (_, exact_automation_id, exact_revision_ids, exact_occurrence_ids) = cases
        .iter()
        .find(|(record_count, _, _, _)| *record_count == 130)
        .expect("130-row exact-selector fixture exists");
    assert_exact_issue_2860_selectors(
        &store,
        &state_fence,
        exact_automation_id,
        exact_revision_ids,
        exact_occurrence_ids,
    );
    assert_foreign_generation_refusals(&store, &state_fence, exact_automation_id);
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
