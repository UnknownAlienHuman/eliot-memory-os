//! Canonical automation port translation proofs (issue #1779).
//!
//! Drives [`CanonicalUserAutomationStore`] through a scripted store
//! double that echoes applied transitions back as read projections:
//! closed translation per intent (exact transition shape, manifest
//! digest, hash agreement), typed result projection with domain
//! re-validation, replay labeling without remutation, and fail-closed
//! identity/digest/unknown mapping. Durable row semantics are proven
//! through the backend suites; this file proves the port's translation
//! layer only.

#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(clippy::too_many_lines)]

use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroU64;
use std::sync::Mutex;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration,
    SessionId, SourceId, StateFence, TaskId,
};
use eliot_kernel_core::user_automation::{
    AutomationCapabilityProfile, AutomationDeliveryTarget, AutomationResourceCeiling,
    AutomationTaskBinding, AutomationTaskKind, AutomationWorkScope, NormalizedSchedule,
    OverlapPolicy, ProviderFingerprintPolicy, RecursionPolicy, RouteCostPolicy, ScheduleKind,
    UserAutomationConfigurationState, UserAutomationExecutionMode, UserAutomationOperation,
    UserAutomationRevision, UserAutomationTrigger, UserAutomationTriggerOrigin,
};
use eliot_store_api::{
    CanonicalStoreClient, CommitId, NamedReadRequest, OperationIdentity, OrderingHead,
    PreparedTransition, RequestMeta, Resubmission, RevisionDelta, ScopeRevisionView, StoreError,
    WriteReceipt, WriteReceiptStatus,
};
use serde_json::Value;

use super::{
    CanonicalUserAutomationStore, UserAutomationMutationResult, UserAutomationReadResult,
    UserAutomationStoreOutcome, UserAutomationStorePort, UserAutomationStoreRequest,
};

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

fn context() -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new("request-automation-port").expect("request"),
        session_id: Some(SessionId::new("session-automation-port").expect("session")),
        task_id: Some(TaskId::new("task-automation-port").expect("task")),
        product_id: ProductId::new("product-automation").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

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

/// Echo store double: records admitted transitions and serves read
/// projections derived from exactly what was applied. Manufactured
/// frames only, never admission authority.
struct FakeStore {
    applied: Mutex<Vec<PreparedTransition>>,
    sealed: Mutex<HashMap<String, WriteReceipt>>,
}

impl FakeStore {
    fn new() -> Self {
        Self {
            applied: Mutex::new(Vec::new()),
            sealed: Mutex::new(HashMap::new()),
        }
    }

    fn applied_count(&self) -> usize {
        self.applied.lock().expect("applied lock").len()
    }

    fn committed_receipt(
        &self,
        ctx: &RequestMeta,
        transition: &PreparedTransition,
    ) -> WriteReceipt {
        let sequence = self.applied_count() as u64 + 1;
        let operation_id = transition.identity.operation_id.to_string();
        let mut receipt = WriteReceipt {
            operation_id: transition.identity.operation_id.clone(),
            idempotency_key: transition.identity.idempotency_key.clone(),
            canonical_request_hash: transition.identity.canonical_request_hash.clone(),
            transition_class: transition.transition_class,
            status: WriteReceiptStatus::Committed,
            commit_id: Some(CommitId::new(format!("commit-{operation_id}")).expect("commit")),
            state_fence: transition.state_fence.clone(),
            ordering_sequences: transition
                .ordering_scopes
                .iter()
                .map(|scope| OrderingHead {
                    scope: scope.clone(),
                    sequence,
                    state_fence: transition.state_fence.clone(),
                })
                .collect(),
            revision_before_after: Vec::<RevisionDelta>::new(),
            applied_command_ids: vec![format!("command-{operation_id}-0")],
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: transition.operation_manifest_digest.clone(),
            error_code: None,
            resubmission: Resubmission::None,
            committed_at: Some(format!("commit-sequence-{sequence:016}")),
            envelope: None,
        };
        receipt.envelope = Some(
            eliot_store_api::issue_store_receipt_envelope(ctx, transition, &receipt, sequence)
                .expect("envelope issues"),
        );
        receipt.validate().expect("fake receipt validates");
        receipt
    }

    /// Replays applied transitions into the pointer/row projection the
    /// real backends persist.
    fn projection(&self) -> FakeProjection {
        let applied = self.applied.lock().expect("applied lock");
        let mut currents: BTreeMap<String, (String, String, String)> = BTreeMap::new();
        let mut revisions: Vec<(String, String, String)> = Vec::new();
        let mut invocations: Vec<(String, String, String)> = Vec::new();
        for transition in applied.iter() {
            for command in &transition.named_operations {
                let params = &command.parameters;
                let text = |name: &str| -> String {
                    params
                        .get(name)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                match text("operation").as_str() {
                    "create" => {
                        currents.insert(
                            text("automation_id"),
                            (
                                text("revision"),
                                text("configuration_state"),
                                text("revision_json"),
                            ),
                        );
                        revisions.push((
                            text("automation_id"),
                            text("revision"),
                            text("revision_json"),
                        ));
                    }
                    "edit" => {
                        currents.insert(
                            text("automation_id"),
                            (
                                text("revision"),
                                text("configuration_state"),
                                text("revision_json"),
                            ),
                        );
                        revisions.push((
                            text("automation_id"),
                            text("revision"),
                            text("revision_json"),
                        ));
                    }
                    "pause" | "resume" | "remove" => {
                        if let Some(entry) = currents.get_mut(&text("automation_id")) {
                            entry.0 = text("revision");
                            entry.1 = text("configuration_state");
                        }
                    }
                    "run-now" => {
                        invocations.push((
                            text("occurrence_id"),
                            text("automation_id"),
                            text("invocation_json"),
                        ));
                    }
                    _ => {}
                }
            }
        }
        FakeProjection {
            currents,
            revisions,
            invocations,
        }
    }
}

struct FakeProjection {
    currents: BTreeMap<String, (String, String, String)>,
    revisions: Vec<(String, String, String)>,
    invocations: Vec<(String, String, String)>,
}

#[allow(async_fn_in_trait)]
impl CanonicalStoreClient for FakeStore {
    async fn apply_prepared(
        &self,
        ctx: &RequestMeta,
        transition: PreparedTransition,
        _expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
        _expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreError> {
        transition.validate()?;
        let key = transition.identity.operation_id.to_string();
        if let Some(sealed) = self.sealed.lock().expect("sealed lock").get(&key) {
            return Ok(sealed.clone());
        }
        let receipt = self.committed_receipt(ctx, &transition);
        self.sealed
            .lock()
            .expect("sealed lock")
            .insert(key, receipt.clone());
        self.applied.lock().expect("applied lock").push(transition);
        Ok(receipt)
    }

    async fn receipt(&self, operation_id: OperationId) -> Result<Option<WriteReceipt>, StoreError> {
        Ok(self
            .sealed
            .lock()
            .expect("sealed lock")
            .get(&operation_id.to_string())
            .cloned())
    }

    async fn revision_heads(
        &self,
        _keys: Vec<eliot_store_api::RevisionKey>,
    ) -> Result<Vec<eliot_store_api::RevisionHead>, StoreError> {
        Ok(Vec::new())
    }

    async fn validation_snapshot(
        &self,
    ) -> Result<eliot_store_api::CanonicalValidationSnapshot, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn scope_revision_view(
        &self,
        _scope_id: eliot_store_api::ScopeId,
    ) -> Result<ScopeRevisionView, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn ordering_heads(
        &self,
        _scopes: Vec<eliot_store_api::OrderingScopeId>,
    ) -> Result<Vec<eliot_store_api::OrderingHead>, StoreError> {
        Ok(Vec::new())
    }

    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<eliot_store_api::NamedReadResponse, StoreError> {
        use eliot_store_api::NamedReadOperation;
        if query.operation != NamedReadOperation::GetUserAutomationState {
            return Err(StoreError::UnknownOperation);
        }
        let decoded = eliot_store_api::validate_automation_read_params(&query.parameters)?;
        let projection = self.projection();
        let payload = match decoded.query.as_str() {
            "list" => {
                let currents: Vec<Value> = projection
                    .currents
                    .iter()
                    .filter(|(_, (_, state, _))| decoded.include_retired || state != "RETIRED")
                    .map(|(id, (revision, state, _))| {
                        serde_json::json!({
                            "automation_id": id,
                            "revision": revision,
                            "configuration_state": state,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "currents": currents,
                    "revision": currents.len(),
                    "state_fence": query.state_fence,
                })
            }
            "current" => {
                let id = decoded.automation_id.clone().unwrap_or_default();
                match projection.currents.get(&id) {
                    Some((revision, state, _)) => serde_json::json!({
                        "current": {
                            "automation_id": id,
                            "revision": revision,
                            "configuration_state": state,
                        },
                        "revision": 1,
                        "state_fence": query.state_fence,
                    }),
                    None => serde_json::json!({
                        "current": Value::Null,
                        "revision": 0,
                        "state_fence": query.state_fence,
                    }),
                }
            }
            "history" => {
                let id = decoded.automation_id.clone().unwrap_or_default();
                let revisions: Vec<Value> = projection
                    .revisions
                    .iter()
                    .filter(|(entry_id, _, _)| entry_id == &id)
                    .map(|(entry_id, revision, document)| {
                        serde_json::json!({
                            "automation_id": entry_id,
                            "revision": revision,
                            "revision_json": document,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "revisions": revisions,
                    "revision": revisions.len(),
                    "state_fence": query.state_fence,
                })
            }
            "invocations" => {
                let id = decoded.automation_id.clone().unwrap_or_default();
                let invocations: Vec<Value> = projection
                    .invocations
                    .iter()
                    .filter(|(_, entry_id, _)| entry_id == &id)
                    .map(|(occurrence, entry_id, document)| {
                        serde_json::json!({
                            "occurrence_id": occurrence,
                            "automation_id": entry_id,
                            "invocation_json": document,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "invocations": invocations,
                    "revision": invocations.len(),
                    "state_fence": query.state_fence,
                })
            }
            "failure" => serde_json::json!({
                "failure": Value::Null,
                "revision": 0,
                "state_fence": query.state_fence,
            }),
            _ => return Err(StoreError::UnknownOperation),
        };
        Ok(eliot_store_api::NamedReadResponse {
            operation: query.operation,
            state_fence: query.state_fence.clone(),
            revision_heads: Vec::new(),
            payload,
        })
    }

    async fn health(&self) -> Result<eliot_store_api::StoreHealth, StoreError> {
        Err(StoreError::Unavailable)
    }
}

fn intent(
    operation: UserAutomationOperation,
) -> eliot_kernel_core::user_automation::UserAutomationOperatorIntent {
    eliot_kernel_core::user_automation::UserAutomationOperatorIntent {
        intent_id: "intent-1".to_owned(),
        principal_ref: "human-1".to_owned(),
        state_fence: fence(),
        operation,
    }
}

fn store_request(
    operation_id: &str,
    operation: UserAutomationOperation,
) -> UserAutomationStoreRequest {
    UserAutomationStoreRequest {
        context: context(),
        authenticated_principal: "human-1".to_owned(),
        identity: OperationIdentity {
            operation_id: OperationId::new(operation_id).expect("operation"),
            idempotency_key: format!("idem-{operation_id}"),
            canonical_request_hash: "0".repeat(64),
        },
        intent: intent(operation),
    }
}

/// Admits one request through the port, adopting the computed canonical
/// hash the way the Kernel route issues it (proves the digest-mismatch
/// arm on the first pass, then proceeds admitted).
async fn admitted_response(
    port: &CanonicalUserAutomationStore<FakeStore>,
    operation_id: &str,
    operation: UserAutomationOperation,
) -> super::UserAutomationStoreResponse {
    try_admitted(port, operation_id, operation)
        .await
        .expect("admitted request executes")
}

/// Two-phase admission returning the raw result for negative proofs.
///
/// Reads admit on the first pass (no transition, no hash check);
/// mutations report the digest mismatch first, then proceed admitted
/// with the route-issued hash.
async fn try_admitted(
    port: &CanonicalUserAutomationStore<FakeStore>,
    operation_id: &str,
    operation: UserAutomationOperation,
) -> Result<super::UserAutomationStoreResponse, StoreError> {
    let draft = store_request(operation_id, operation.clone());
    match port.execute_user_automation(draft).await {
        Err(StoreError::TransitionDigestMismatch { observed, .. }) => {
            let mut admitted = store_request(operation_id, operation);
            admitted.identity.canonical_request_hash = observed;
            port.execute_user_automation(admitted).await
        }
        unexpected => unexpected,
    }
}

#[tokio::test]
async fn create_lists_and_reads_back_typed_revision() {
    let fake = FakeStore::new();
    let port = CanonicalUserAutomationStore::new(fake);
    let revision = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    let response = admitted_response(
        &port,
        "op-port-create-1",
        UserAutomationOperation::Create {
            revision: revision.clone(),
        },
    )
    .await;
    let (receipt, result) = match response.outcome {
        UserAutomationStoreOutcome::Committed { receipt, result } => (receipt, result),
        unexpected => panic!("create must commit, got {unexpected:?}"),
    };
    assert_eq!(
        receipt.operation_id.to_string(),
        "op-port-create-1",
        "receipt binds the admitted identity"
    );
    let UserAutomationMutationResult::Revision {
        revision: stored,
        cancelled_wake_ids,
    } = result
    else {
        panic!("create must project a revision");
    };
    assert_eq!(stored, revision);
    assert!(cancelled_wake_ids.is_empty());
    // List serves the typed revision; status/history/inspect agree.
    let response = admitted_response(
        &port,
        "op-port-list-1",
        UserAutomationOperation::List {
            include_retired: false,
        },
    )
    .await;
    let UserAutomationStoreOutcome::Read {
        result: UserAutomationReadResult::List { revisions },
    } = response.outcome
    else {
        panic!("list must read");
    };
    assert_eq!(revisions, vec![revision.clone()]);
    let response = admitted_response(
        &port,
        "op-port-status-1",
        UserAutomationOperation::Status {
            automation_id: "auto-1".to_owned(),
        },
    )
    .await;
    let UserAutomationStoreOutcome::Read {
        result: UserAutomationReadResult::Status {
            revision: status, ..
        },
    } = response.outcome
    else {
        panic!("status must read");
    };
    assert_eq!(status, revision);
    let response = admitted_response(
        &port,
        "op-port-inspect-1",
        UserAutomationOperation::InspectLastFailure {
            automation_id: "auto-1".to_owned(),
        },
    )
    .await;
    let UserAutomationStoreOutcome::Read {
        result:
            UserAutomationReadResult::InspectLastFailure {
                revision: bound,
                failure,
                ..
            },
    } = response.outcome
    else {
        panic!("inspect must read");
    };
    assert_eq!(bound, revision);
    assert_eq!(failure, None);
}

#[tokio::test]
async fn edit_pause_remove_move_lineage_with_typed_results() {
    let fake = FakeStore::new();
    let port = CanonicalUserAutomationStore::new(fake);
    let first = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    admitted_response(
        &port,
        "op-port-create-2",
        UserAutomationOperation::Create {
            revision: first.clone(),
        },
    )
    .await;
    let mut second = valid_revision("auto-1", "r-2", UserAutomationConfigurationState::Active);
    second.supersedes = Some("r-1".to_owned());
    let response = admitted_response(
        &port,
        "op-port-edit-2",
        UserAutomationOperation::Edit {
            previous_revision: first,
            revision: second.clone(),
        },
    )
    .await;
    let UserAutomationStoreOutcome::Committed { result, .. } = response.outcome else {
        panic!("edit must commit");
    };
    let UserAutomationMutationResult::Revision { revision, .. } = result else {
        panic!("edit must project a revision");
    };
    assert_eq!(revision, second);
    for (tag, operation, state) in [
        (
            "pause",
            UserAutomationOperation::Pause {
                automation_id: "auto-1".to_owned(),
                automation_revision: "r-2".to_owned(),
            },
            UserAutomationConfigurationState::Paused,
        ),
        (
            "resume",
            UserAutomationOperation::Resume {
                automation_id: "auto-1".to_owned(),
                automation_revision: "r-2".to_owned(),
            },
            UserAutomationConfigurationState::Active,
        ),
        (
            "remove",
            UserAutomationOperation::Remove {
                automation_id: "auto-1".to_owned(),
                automation_revision: "r-2".to_owned(),
            },
            UserAutomationConfigurationState::Retired,
        ),
    ] {
        let response = admitted_response(&port, &format!("op-port-{tag}-2"), operation).await;
        let UserAutomationStoreOutcome::Committed { result, .. } = response.outcome else {
            panic!("{tag} must commit");
        };
        let UserAutomationMutationResult::Revision { revision, .. } = result else {
            panic!("{tag} must project a revision");
        };
        assert_eq!(revision.configuration_state, state);
        assert_eq!(revision.revision, "r-2");
    }
    // Retired rows filter from the default list.
    let response = admitted_response(
        &port,
        "op-port-list-2",
        UserAutomationOperation::List {
            include_retired: false,
        },
    )
    .await;
    let UserAutomationStoreOutcome::Read {
        result: UserAutomationReadResult::List { revisions },
    } = response.outcome
    else {
        panic!("list must read");
    };
    assert!(revisions.is_empty());
}

#[tokio::test]
async fn run_now_projects_invocation_and_pending_wake() {
    let fake = FakeStore::new();
    let port = CanonicalUserAutomationStore::new(fake);
    let revision = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    admitted_response(
        &port,
        "op-port-create-3",
        UserAutomationOperation::Create {
            revision: revision.clone(),
        },
    )
    .await;
    let response = admitted_response(
        &port,
        "op-port-run-3",
        UserAutomationOperation::RunNow {
            automation_id: "auto-1".to_owned(),
            automation_revision: "r-1".to_owned(),
            nonce: "nonce-7".to_owned(),
        },
    )
    .await;
    let expected_identity = response.identity.clone();
    let expected_fence = response.state_fence.clone();
    let UserAutomationStoreOutcome::Committed { result, .. } = response.outcome else {
        panic!("run-now must commit");
    };
    let UserAutomationMutationResult::RunNow {
        invocation,
        wake_intent,
    } = result
    else {
        panic!("run-now must project an invocation");
    };
    assert_eq!(invocation.automation_id, "auto-1");
    assert_eq!(invocation.automation_revision, "r-1");
    assert_eq!(
        invocation.trigger,
        UserAutomationTrigger::Manual {
            nonce: "nonce-7".to_owned()
        }
    );
    assert_eq!(
        invocation.trigger_origin,
        UserAutomationTriggerOrigin::Human
    );
    let provenance = invocation
        .require_run_now_provenance(&expected_fence)
        .expect("RunNow retains authenticated Human provenance");
    assert!(provenance.request_metadata.session_id.is_some());
    assert!(provenance.request_metadata.task_id.is_some());
    assert_eq!(
        provenance.source_operation,
        UserAutomationOperation::RunNow {
            automation_id: "auto-1".to_owned(),
            automation_revision: "r-1".to_owned(),
            nonce: "nonce-7".to_owned(),
        }
    );
    assert_eq!(provenance.operation_id, expected_identity.operation_id);
    assert_eq!(
        provenance.idempotency_key,
        expected_identity.idempotency_key
    );
    assert_eq!(
        provenance.canonical_request_hash,
        expected_identity.canonical_request_hash
    );
    let mut missing_task = invocation.clone();
    missing_task
        .provenance
        .as_mut()
        .expect("stored provenance")
        .request_metadata
        .task_id = None;
    assert!(
        missing_task
            .require_run_now_provenance(&expected_fence)
            .is_err()
    );
    let mut changed_nonce = invocation.clone();
    let UserAutomationTrigger::Manual { nonce } = &mut changed_nonce.trigger else {
        panic!("RunNow trigger is manual");
    };
    *nonce = "different-nonce".to_owned();
    assert!(
        changed_nonce
            .require_run_now_provenance(&expected_fence)
            .is_err()
    );
    let mut child = invocation.clone();
    child.child_depth = 1;
    assert!(child.require_run_now_provenance(&expected_fence).is_err());
    assert_eq!(
        invocation
            .occurrence_identity()
            .expect("occurrence derives"),
        wake_intent.wake_id,
        "wake binds the derived occurrence"
    );
    assert_eq!(
        wake_intent.state,
        eliot_runtime_contracts::WakeIntentState::Pending,
        "wake stays inert and pending"
    );
}

#[tokio::test]
async fn replay_reports_replayed_without_remutation() {
    let fake = FakeStore::new();
    let port = CanonicalUserAutomationStore::new(fake);
    let revision = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    let operation = UserAutomationOperation::Create {
        revision: revision.clone(),
    };
    let first = admitted_response(&port, "op-port-replay-4", operation.clone()).await;
    let UserAutomationStoreOutcome::Committed { receipt, .. } = first.outcome else {
        panic!("first call must commit");
    };
    let applied = port.client().applied_count();
    let second = admitted_response(&port, "op-port-replay-4", operation).await;
    let UserAutomationStoreOutcome::Replayed {
        receipt: replayed,
        result,
    } = second.outcome
    else {
        panic!("second call must replay");
    };
    assert_eq!(replayed.operation_id, receipt.operation_id);
    assert_eq!(port.client().applied_count(), applied);
    let UserAutomationMutationResult::Revision {
        revision: stored, ..
    } = result
    else {
        panic!("replay must project");
    };
    assert_eq!(stored, revision);
}

#[tokio::test]
async fn divergent_identity_and_unknown_automation_fail_closed() {
    let fake = FakeStore::new();
    let port = CanonicalUserAutomationStore::new(fake);
    let revision = valid_revision("auto-1", "r-1", UserAutomationConfigurationState::Active);
    admitted_response(
        &port,
        "op-port-sealed-5",
        UserAutomationOperation::Create {
            revision: revision.clone(),
        },
    )
    .await;
    // Same identity with different bytes conflicts against the seal.
    // The forged bytes need their route-issued hash first: the port
    // checks the digest before the sealed identity.
    let mut other = revision.clone();
    other.natural_language_intent = "forged intent".to_owned();
    let forged = UserAutomationOperation::Create { revision: other };
    let draft = store_request("op-port-sealed-5", forged.clone());
    let observed = match port.execute_user_automation(draft).await {
        Err(StoreError::TransitionDigestMismatch { observed, .. }) => observed,
        unexpected => panic!("forged first pass must report the digest, got {unexpected:?}"),
    };
    let mut request = store_request("op-port-sealed-5", forged);
    request.identity.canonical_request_hash = observed;
    assert_eq!(
        port.execute_user_automation(request).await.map(|_| ()),
        Err(StoreError::IdentityConflict)
    );
    // Unknown automations fail closed on reads.
    assert!(
        try_admitted(
            &port,
            "op-port-status-5",
            UserAutomationOperation::Status {
                automation_id: "auto-absent".to_owned(),
            },
        )
        .await
        .is_err(),
        "status on unknown automation must fail"
    );
}
