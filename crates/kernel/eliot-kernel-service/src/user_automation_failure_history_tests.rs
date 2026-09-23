//! Port tests for canonical failure-history persistence (issue #1779).
//!
//! A real [`MemoryStore`] reference contour backs the Store-owned
//! adapter; the actual consumer binding runs the frozen
//! [`UserAutomationService::execute_occurrence`] BlockedConfig path
//! through [`UserAutomationRuntimeComposition`] with stub
//! durable-job/wake/notification ports. Proves: first failure records
//! the canonical row and publishes the deterministic reference; repeats
//! of one failure class converge with the identical reference;
//! replays resolve without remutation; unknown revisions and tampered
//! fingerprints fail before any effect. B3 notification stays stubbed
//! (B3 owns delivery); no fake store, no separate journal.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SessionId, SourceId, StateFence,
};
use eliot_kernel_core::user_automation::{
    AutomationCapabilityProfile, AutomationDeliveryTarget, AutomationResourceCeiling,
    AutomationTaskBinding, AutomationTaskKind, AutomationWorkScope, DeliveryChannel, DstFoldPolicy,
    DstGapPolicy, NormalizedSchedule, NotificationDraft, OverlapPolicy, ProviderFingerprintPolicy,
    RecursionPolicy, RouteCostPolicy, ScheduleKind, USER_AUTOMATION_PREFLIGHT_CONTRACT_REVISION,
    USER_AUTOMATION_SCOPE, UserAutomationConfigurationState, UserAutomationExecutionMode,
    UserAutomationExecutionProjection, UserAutomationInvocation, UserAutomationPreflightProjection,
    UserAutomationRevision, UserAutomationTrigger, UserAutomationTriggerOrigin,
};
use eliot_kernel_core::{
    AutomationExecutionReference, AutomationFailureNotificationProjection, AutomationRecipient,
    AutomationRecipientRole, NotificationSeverity,
};
use eliot_runtime_contracts::WakeIntent;
use eliot_store_api::{
    CanonicalRequestView, CanonicalStoreClient, CanonicalValidationSnapshot,
    EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest, NamedReadRequest,
    NamedReadResponse, OperationIdentity, OrderingHead, OrderingScopeId, PreparedTransition,
    RequestMeta, ScopeId, ScopeRevisionView, SecurityContext, StoreError, StoreHealth,
    TransitionClass, WriteReceipt, automation_create_params, automation_read_request,
    canonical_request_hash, generated_operation_manifests, operation_manifest_set_digest,
};
use eliot_store_memory::MemoryStore;
use serde_json::Value;

use super::user_automation_execution::{
    UserAutomationDurableJobPort, UserAutomationFailureHistoryPort, UserAutomationRuntimeAdmission,
    UserAutomationRuntimeError, UserAutomationRuntimePort, UserAutomationWakeCancellation,
    UserAutomationWakePort,
};
use super::user_automation_failure_history::StoreUserAutomationFailureHistory;
use super::{UserAutomationService, UserAutomationStorePort, UserAutomationStoreRequest};

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn state_fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new(LINEAGE).expect("lineage"),
        NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch");
    let mut fence = StateFence::new(epoch, ResourceGeneration::genesis());
    fence.policy_revision = Some(PolicyRevision::genesis());
    fence
}

fn metadata() -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new("automation-request").expect("request"),
        session_id: Some(SessionId::new("session-1").expect("session")),
        task_id: None,
        product_id: ProductId::new("eliot-test").expect("product"),
        source_id: SourceId::new("eliot-user-automation").expect("source"),
        state_fence: state_fence(),
        clock: ClockReading {
            valid_time_ms: Some(1),
            known_time_ms: Some(1),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        },
    }
}

fn revision(automation_id: &str, revision_id: &str) -> UserAutomationRevision {
    UserAutomationRevision {
        automation_id: automation_id.to_owned(),
        revision: revision_id.to_owned(),
        supersedes: None,
        owner_principal: "human-1".to_owned(),
        work_scope: AutomationWorkScope {
            scope_id: "scope-1".to_owned(),
            product_id: "eliot-test".to_owned(),
            workdir_ref: "workdir-1".to_owned(),
        },
        natural_language_intent: "run the qualified deterministic check".to_owned(),
        schedule: NormalizedSchedule {
            kind: ScheduleKind::Recurring,
            expression: "at 12:00".to_owned(),
            calendar: "gregorian".to_owned(),
            timezone: "America/New_York".to_owned(),
            dst_fold: DstFoldPolicy::First,
            dst_gap: DstGapPolicy::ShiftForward,
            start_at: "2026-09-21T00:00:00Z".to_owned(),
            end_at: None,
            next_occurrences: vec!["2026-09-21T12:00:00-04:00".to_owned()],
        },
        mode: UserAutomationExecutionMode::DeterministicProcess,
        task: AutomationTaskBinding {
            qualified_ref: "script:checks/v1".to_owned(),
            kind: AutomationTaskKind::QualifiedScript,
            capability_profile: AutomationCapabilityProfile {
                model_access: false,
                provider_access: false,
                automation_scheduling: false,
            },
        },
        portable_skill_package_revision_refs: vec!["skill-package@1".to_owned()],
        workdir_ref: "workdir-1".to_owned(),
        route_cost_policy: RouteCostPolicy {
            route_ref: "deterministic-local".to_owned(),
            max_cost_units: 1,
            max_duration_ms: 1_000,
            policy_revision: Some(PolicyRevision::genesis()),
        },
        provider_policy: ProviderFingerprintPolicy::DeterministicOnly,
        delivery_target: AutomationDeliveryTarget {
            target_ref: "human-1".to_owned(),
            channels: vec![DeliveryChannel::ControlBoard],
            recipient_refs: vec!["human-1".to_owned()],
        },
        preflight_contract_revision: USER_AUTOMATION_PREFLIGHT_CONTRACT_REVISION.to_owned(),
        resource_ceiling: AutomationResourceCeiling {
            max_runtime_ms: 1_000,
            max_output_bytes: 4_096,
            max_child_count: 0,
        },
        overlap_policy: OverlapPolicy::ForbidOverlap,
        recursion_policy: RecursionPolicy {
            allow_child_automation: false,
            max_child_depth: 0,
        },
        configuration_state: UserAutomationConfigurationState::BlockedConfig,
        work_class: eliot_kernel_core::user_automation::AutomationWorkClass::Maintenance,
        current_execution_refs: Vec::new(),
        execution_history_query_ref: "history:automation-1".to_owned(),
    }
}

fn source_receipt(context: &RequestMeta) -> eliot_receipts::ReceiptEnvelope {
    let core: eliot_receipts::ReceiptCore = serde_json::from_value(serde_json::json!({
        "contract": eliot_receipts::contract_identity().expect("contract"),
        "kind": "VERIFICATION",
        "work_scope": {
            "scope_id": "scope-1",
            "product_id": "eliot-test",
            "resource_generation": context.state_fence.resource_generation,
            "state_fence": context.state_fence
        },
        "task": null,
        "session": {
            "session_id": context.session_id,
            "authority_epoch": context.state_fence.authority_epoch,
            "state_fence": context.state_fence
        },
        "causal": {
            "state_fence": context.state_fence,
            "transaction_sequence": 1,
            "parent_receipt_id": null,
            "predecessor_receipt_ids": []
        },
        "request": {"metadata": context, "state_fence": context.state_fence},
        "operation": {
            "operation_id": "operation-g08",
            "request_id": context.request_id,
            "idempotency_key": "source-key",
            "operation_kind": "g08_notification_projection",
            "effect": "READ",
            "state_fence": context.state_fence
        },
        "authority": {
            "authority_id": "authority-g08",
            "authority_owner": "G-08",
            "authority_epoch": context.state_fence.authority_epoch,
            "state_fence": context.state_fence,
            "allowed_effect": "READ",
            "proof_ceiling": "SCOPED_VERIFICATION"
        },
        "artifacts": [],
        "verifier": null,
        "problem": null,
        "coordination": null,
        "disposition": {"kind": "SUCCESS", "proof": "SCOPED_VERIFICATION"}
    }))
    .expect("receipt core");
    eliot_receipts::ReceiptEnvelope::issue(core).expect("receipt")
}

fn failure_notification(context: &RequestMeta) -> AutomationFailureNotificationProjection {
    AutomationFailureNotificationProjection {
        canonical: NotificationDraft {
            notification_id: eliot_platform::PlatformHandle::new("caller-id").expect("id"),
            severity: NotificationSeverity::ActionRequired,
            subject: "Automation blocked".to_owned(),
            summary: "Configuration requires attention".to_owned(),
            evidence_handles: vec!["preflight-receipt".to_owned()],
            affected_scope: "automation-1".to_owned(),
            owner: "UserAutomation".to_owned(),
            required_action: "Review configuration".to_owned(),
            deadline_or_review: None,
            dedup_key: "caller-key".to_owned(),
            delivery_channels: vec![DeliveryChannel::ControlBoard],
            state_fence: context.state_fence.clone(),
        },
        subject: "Automation blocked".to_owned(),
        summary: "Configuration requires attention".to_owned(),
        recipients: vec![AutomationRecipient {
            principal: eliot_platform::PlatformHandle::new("human-1").expect("principal"),
            role: AutomationRecipientRole::AuthorizedRole,
        }],
    }
}

fn blocked_projection(
    context: &RequestMeta,
    automation_id: &str,
    revision_id: &str,
) -> (
    UserAutomationInvocation,
    UserAutomationPreflightProjection,
    WakeIntent,
) {
    let rev = revision(automation_id, revision_id);
    let invocation = UserAutomationInvocation {
        automation_id: rev.automation_id.clone(),
        automation_revision: rev.revision.clone(),
        trigger: UserAutomationTrigger::Scheduled {
            occurrence_key: rev.schedule.next_occurrences[0].clone(),
        },
        mode: rev.mode,
        principal_ref: rev.owner_principal.clone(),
        work_scope_ref: rev.work_scope.scope_id.clone(),
        workdir_ref: rev.workdir_ref.clone(),
        trigger_origin: UserAutomationTriggerOrigin::ScheduledWake,
        child_depth: 0,
        provenance: None,
    };
    let occurrence_id = invocation.occurrence_identity().expect("occurrence");
    let wake_intent = rev
        .compile_wake_intent(&occurrence_id, context.state_fence.clone())
        .expect("wake");
    let mut projection = UserAutomationPreflightProjection {
        automation_id: rev.automation_id.clone(),
        automation_revision: rev.revision.clone(),
        mode: rev.mode,
        occurrence_id,
        revision: rev,
        configuration_state: UserAutomationConfigurationState::BlockedConfig,
        config_snapshot: serde_json::from_value(serde_json::json!({
            "snapshot_id": "snapshot-1",
            "machine_id": "machine-1",
            "scope_id": USER_AUTOMATION_SCOPE,
            "revision": PolicyRevision::genesis(),
            "source_completeness": "COMPLETE",
            "settings": [],
            "policy_owner": {"owner_ref": "human-1"},
            "policy_fence": {
                "policy_snapshot_id": "snapshot-1",
                "state_fence": context.state_fence
            },
            "state_fence": context.state_fence,
            "parent_snapshot_id": null,
            "rollback_of": null
        }))
        .expect("config snapshot"),
        source_receipt: source_receipt(context),
        execution: UserAutomationExecutionProjection {
            current_execution_refs: Vec::new(),
            unresolved_reconciliation_refs: Vec::new(),
            history_query_ref: "history:automation-1".to_owned(),
        },
        observed_provider_fingerprint: None,
        trusted_skill_package_revision_refs: vec!["skill-package@1".to_owned()],
        trusted_tool_definition_refs: vec!["tool-def@1".to_owned()],
        delivery_available: true,
        trigger_origin: UserAutomationTriggerOrigin::ScheduledWake,
        child_depth: 0,
        failure: None,
    };
    let reason =
        eliot_kernel_core::user_automation::UserAutomationFailureReason::CanonicalBlockedConfig {
            class: "provider-fingerprint".to_owned(),
        };
    projection.failure = Some(
        eliot_kernel_core::user_automation::UserAutomationFailureProjection {
            failure_fingerprint: projection
                .revision
                .failure_fingerprint(&reason)
                .expect("fingerprint"),
            reason,
            notification: failure_notification(context),
        },
    );
    (invocation, projection, wake_intent)
}

fn execution_request(
    context: RequestMeta,
    tag: &str,
    invocation: UserAutomationInvocation,
    projection: UserAutomationPreflightProjection,
    wake_intent: WakeIntent,
) -> super::user_automation_execution::UserAutomationExecutionRequest {
    super::user_automation_execution::UserAutomationExecutionRequest {
        context,
        authenticated_principal: "human-1".to_owned(),
        identity: OperationIdentity {
            operation_id: OperationId::new(format!("automation-execution-{tag}"))
                .expect("operation"),
            idempotency_key: format!("automation-execution-key-{tag}"),
            canonical_request_hash: "a".repeat(64),
        },
        invocation,
        projection,
        wake_intent,
    }
}

struct UnusedStore;

#[allow(async_fn_in_trait)]
impl UserAutomationStorePort for UnusedStore {
    async fn execute_user_automation(
        &self,
        _request: UserAutomationStoreRequest,
    ) -> Result<super::UserAutomationStoreResponse, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn receipt(
        &self,
        _operation_id: OperationId,
    ) -> Result<Option<WriteReceipt>, StoreError> {
        Ok(None)
    }
}

struct UnreachableJob;
struct UnreachableWake;

#[allow(async_fn_in_trait)]
impl UserAutomationDurableJobPort for UnreachableJob {
    async fn admit_occurrence(
        &self,
        _request: UserAutomationRuntimeAdmission,
    ) -> Result<AutomationExecutionReference, UserAutomationRuntimeError> {
        Err(UserAutomationRuntimeError::Unavailable(
            "durable job must not be called on the failure path".to_owned(),
        ))
    }
}

#[allow(async_fn_in_trait)]
impl UserAutomationWakePort for UnreachableWake {
    async fn cancel_pending_wakes(
        &self,
        _request: UserAutomationWakeCancellation,
    ) -> Result<Vec<String>, UserAutomationRuntimeError> {
        Err(UserAutomationRuntimeError::Unavailable(
            "wake must not be called on the failure path".to_owned(),
        ))
    }
}

struct StubNotify;

#[allow(async_fn_in_trait)]
impl super::user_automation_execution::UserAutomationNotificationPort for StubNotify {
    async fn deliver_user_automation_failure(
        &self,
        request: super::user_automation_execution::UserAutomationFailureRecord,
    ) -> Result<
        super::user_automation_execution::UserAutomationNotificationDelivery,
        UserAutomationRuntimeError,
    > {
        Ok(
            super::user_automation_execution::UserAutomationNotificationDelivery {
                state_fence: request.context.state_fence.clone(),
                dedup_key: request.failure.notification.canonical.dedup_key.clone(),
                deduplicated: false,
                notification_receipt_ref: Some("notification-receipt-1".to_owned()),
            },
        )
    }
}

/// Creates the owning revision directly through the reference contour.
async fn create_revision(store: &MemoryStore, automation_id: &str, revision_id: &str) {
    let rev = revision(automation_id, revision_id);
    let document = serde_json::to_string(&rev).expect("revision serializes");
    let parameters = automation_create_params(
        automation_id.to_owned(),
        revision_id.to_owned(),
        eliot_store_api::AUTOMATION_STATE_ACTIVE.to_owned(),
        document,
    );
    let context = metadata();
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().expect("catalogue"))
            .expect("set digest");
    let mut transition = PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new(format!("op-create-{automation_id}-{revision_id}"))
                .expect("operation"),
            idempotency_key: format!("idem-create-{automation_id}-{revision_id}"),
            canonical_request_hash: "0".repeat(64),
        },
        state_fence: state_fence(),
        scope_id: ScopeId::new("user-automation").expect("scope"),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new("user-automation").expect("ordering")],
        transition_class: TransitionClass::UserAutomation,
        requested_effect_ceiling: eliot_receipts::EffectClass::ReversibleMutation,
        admission_contract_set_digest: "c".repeat(64),
        operation_manifest_digest: manifest_digest,
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::ApplyUserAutomationState,
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
    let view = CanonicalRequestView::from_apply(&context, &transition, &[], &[]);
    transition.identity.canonical_request_hash =
        canonical_request_hash(&view).expect("hash computes");
    let receipt = eliot_store_api::CanonicalStoreClient::apply_prepared(
        store,
        &context,
        transition,
        Vec::new(),
        Vec::new(),
    )
    .await
    .expect("create commits");
    assert_eq!(
        receipt.status,
        eliot_store_api::WriteReceiptStatus::Committed
    );
}

fn expected_history_ref(fingerprint: &str) -> String {
    format!("automation-failure:automation-1:revision-7:{fingerprint}")
}

/// Shared reference-contour handle: forwards the closed port to one
/// borrowed [`MemoryStore`] so tests observe the real rows the adapter
/// commits. Forwarding only; no semantics, no authority.
struct SharedStore<'a>(&'a MemoryStore);

#[allow(async_fn_in_trait)]
impl CanonicalStoreClient for SharedStore<'_> {
    async fn apply_prepared(
        &self,
        ctx: &RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: Vec<eliot_store_api::RevisionHeadExpectation>,
        expected_ordering_heads: Vec<eliot_store_api::OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreError> {
        eliot_store_api::CanonicalStoreClient::apply_prepared(
            self.0,
            ctx,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
        )
        .await
    }

    async fn receipt(&self, operation_id: OperationId) -> Result<Option<WriteReceipt>, StoreError> {
        eliot_store_api::CanonicalStoreClient::receipt(self.0, operation_id).await
    }

    async fn revision_heads(
        &self,
        keys: Vec<eliot_store_api::RevisionKey>,
    ) -> Result<Vec<eliot_store_api::RevisionHead>, StoreError> {
        eliot_store_api::CanonicalStoreClient::revision_heads(self.0, keys).await
    }

    async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, StoreError> {
        eliot_store_api::CanonicalStoreClient::validation_snapshot(self.0).await
    }

    async fn scope_revision_view(
        &self,
        scope_id: ScopeId,
    ) -> Result<ScopeRevisionView, StoreError> {
        eliot_store_api::CanonicalStoreClient::scope_revision_view(self.0, scope_id).await
    }

    async fn ordering_heads(
        &self,
        scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<OrderingHead>, StoreError> {
        eliot_store_api::CanonicalStoreClient::ordering_heads(self.0, scopes).await
    }

    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        eliot_store_api::CanonicalStoreClient::execute_named(self.0, query).await
    }

    async fn health(&self) -> Result<StoreHealth, StoreError> {
        eliot_store_api::CanonicalStoreClient::health(self.0).await
    }
}

/// Builds one owner-valid failure record and seals it over the exact
/// failure transition the port will commit, mirroring the Kernel route
/// contract: the seal binds these bytes, and the port verifies it
/// before any write.
fn sealed_record(
    tag: &str,
    automation_id: &str,
    revision_id: &str,
) -> super::user_automation_execution::UserAutomationFailureRecord {
    let context = metadata();
    let (invocation, projection, _) = blocked_projection(&context, automation_id, revision_id);
    let occurrence_id = invocation.occurrence_identity().expect("occurrence");
    let failure = projection.failure.clone().expect("blocked carries failure");
    let mut record = super::user_automation_execution::UserAutomationFailureRecord {
        context,
        authenticated_principal: "human-1".to_owned(),
        identity: OperationIdentity {
            operation_id: OperationId::new(format!("automation-failure-{tag}")).expect("operation"),
            idempotency_key: format!("automation-failure-key-{tag}"),
            canonical_request_hash: "0".repeat(64),
        },
        revision: projection.revision.clone(),
        invocation,
        preflight: eliot_kernel_core::user_automation::UserAutomationPreflightReceipt {
            automation_id: automation_id.to_owned(),
            automation_revision: revision_id.to_owned(),
            occurrence_id,
            config_snapshot_id: "snapshot-1".to_owned(),
            configuration_state: UserAutomationConfigurationState::BlockedConfig,
            work_class: eliot_kernel_core::user_automation::AutomationWorkClass::Maintenance,
            model_access_allowed_after_admission: false,
            source_receipt: source_receipt(&metadata()),
        },
        failure,
    };
    record.validate().expect("record is owner-valid");
    let (transition, _) = super::user_automation_failure_history::build_failure_transition(&record)
        .expect("transition builds");
    let view = CanonicalRequestView::from_apply(&record.context, &transition, &[], &[]);
    record.identity.canonical_request_hash = canonical_request_hash(&view).expect("seal computes");
    record
}

#[tokio::test]
async fn sealed_failure_records_canonical_row() {
    let store = MemoryStore::new();
    create_revision(&store, "automation-1", "revision-7").await;
    let history = StoreUserAutomationFailureHistory::new(SharedStore(&store));
    let record = sealed_record("first", "automation-1", "revision-7");
    let recorded = history
        .record_failure(record.clone())
        .await
        .expect("failure records");
    assert_eq!(recorded.operation_id, record.identity.operation_id);
    assert_eq!(recorded.idempotency_key, record.identity.idempotency_key);
    assert_eq!(
        recorded.canonical_request_hash,
        record.identity.canonical_request_hash
    );
    assert_eq!(recorded.state_fence, record.context.state_fence);
    assert_eq!(recorded.automation_id, "automation-1");
    assert_eq!(recorded.automation_revision, "revision-7");
    assert_eq!(
        recorded.failure_fingerprint,
        record.failure.failure_fingerprint
    );
    let occurrence_id = record.invocation.occurrence_identity().expect("occurrence");
    assert_eq!(recorded.occurrence_id, occurrence_id);
    assert_eq!(
        recorded.history_ref,
        expected_history_ref(&record.failure.failure_fingerprint)
    );
    assert_eq!(recorded.dedup_key, "caller-key");
    assert!(!recorded.deduplicated);
    recorded
        .validate_for(&record)
        .expect("owner validates the response");
    // The canonical row retains the verbatim document with
    // first-writer provenance.
    let query = automation_read_request(
        eliot_store_api::AUTOMATION_QUERY_FAILURE.to_owned(),
        Some("automation-1".to_owned()),
        false,
        1,
        state_fence(),
    )
    .expect("read builds");
    let payload = eliot_store_api::CanonicalStoreClient::execute_named(&SharedStore(&store), query)
        .await
        .expect("read executes")
        .payload;
    let row = payload.get("failure").expect("failure row projects");
    assert_eq!(
        row.get("source_operation_id").and_then(Value::as_str),
        Some("automation-failure-first")
    );
    let document: eliot_store_api::AutomationFailureDocument = serde_json::from_str(
        row.get("failure_json")
            .and_then(Value::as_str)
            .expect("document"),
    )
    .expect("document parses");
    assert_eq!(document.fingerprint, record.failure.failure_fingerprint);
    assert_eq!(document.notification_dedup_key, "caller-key");
}

#[tokio::test]
async fn convergent_repeat_and_replay_resolve_identically() {
    let store = MemoryStore::new();
    create_revision(&store, "automation-1", "revision-7").await;
    let history = StoreUserAutomationFailureHistory::new(SharedStore(&store));
    let first = sealed_record("first", "automation-1", "revision-7");
    let recorded = history
        .record_failure(first.clone())
        .await
        .expect("failure records");
    // A repeat of one failure class from another parent operation
    // converges: identical reference, deduplicated flag set.
    let second = sealed_record("second", "automation-1", "revision-7");
    let converged = history
        .record_failure(second.clone())
        .await
        .expect("repeat converges");
    assert_eq!(converged.history_ref, recorded.history_ref);
    assert!(converged.deduplicated);
    assert_eq!(converged.failure_fingerprint, recorded.failure_fingerprint);
    converged
        .validate_for(&second)
        .expect("owner validates the converged response");
    // A replay of the sealed parent operation resolves without
    // remutation: identical reference, creator provenance kept.
    let replay = history
        .record_failure(first.clone())
        .await
        .expect("replay resolves");
    assert_eq!(replay.history_ref, recorded.history_ref);
    assert!(!replay.deduplicated);
    replay
        .validate_for(&first)
        .expect("owner validates the replayed response");
}

#[tokio::test]
async fn composition_delivers_sealed_failure_to_publication() {
    let store = MemoryStore::new();
    create_revision(&store, "automation-1", "revision-7").await;
    let history = StoreUserAutomationFailureHistory::new(SharedStore(&store));
    let job = UnreachableJob;
    let wake = UnreachableWake;
    let notify = StubNotify;
    let composition = super::user_automation_execution::UserAutomationRuntimeComposition::new(
        &job, &wake, &history, &notify,
    );
    let record = sealed_record("first", "automation-1", "revision-7");
    let publication = composition
        .deliver_user_automation_failure(record.clone())
        .await
        .expect("composition publishes");
    assert_eq!(publication.operation_id, record.identity.operation_id);
    assert_eq!(
        publication.history_ref,
        expected_history_ref(&record.failure.failure_fingerprint)
    );
    assert_eq!(publication.dedup_key, "caller-key");
    assert!(!publication.deduplicated);
    assert_eq!(
        publication.notification_receipt_ref.as_deref(),
        Some("notification-receipt-1")
    );
    publication
        .validate_for(&record)
        .expect("owner validates the publication");
}

#[tokio::test]
async fn unknown_revision_unsealed_and_tampered_records_fail_closed() {
    let store = MemoryStore::new();
    create_revision(&store, "automation-1", "revision-7").await;
    let history = StoreUserAutomationFailureHistory::new(SharedStore(&store));
    // Unknown revision: the canonical leg fails closed, no row appears.
    let absent = sealed_record("absent", "automation-absent", "revision-9");
    let outcome = history.record_failure(absent).await;
    assert!(
        matches!(outcome, Err(UserAutomationRuntimeError::Rejected(_))),
        "unknown revision failures fail closed"
    );
    let query = automation_read_request(
        eliot_store_api::AUTOMATION_QUERY_FAILURE.to_owned(),
        Some("automation-absent".to_owned()),
        false,
        1,
        state_fence(),
    )
    .expect("read builds");
    let payload = eliot_store_api::CanonicalStoreClient::execute_named(&SharedStore(&store), query)
        .await
        .expect("read executes")
        .payload;
    assert!(payload.get("failure").is_some_and(Value::is_null));
    // Unsealed records fail at the boundary before any write.
    let mut unsealed = sealed_record("unsealed", "automation-1", "revision-7");
    unsealed.identity.canonical_request_hash = "b".repeat(64);
    let outcome = history.record_failure(unsealed).await;
    assert!(
        matches!(outcome, Err(UserAutomationRuntimeError::Rejected(_))),
        "unsealed records fail closed"
    );
    // Tampered fingerprint: owner validation refuses before any dispatch.
    let context = metadata();
    let (invocation, mut projection, wake_intent) =
        blocked_projection(&context, "automation-1", "revision-7");
    if let Some(failure) = projection.failure.as_mut() {
        failure.failure_fingerprint = "0".repeat(64);
    }
    let stub_store = UnusedStore;
    let service = UserAutomationService::new(&stub_store);
    let outcome = service
        .execute_occurrence(
            execution_request(context, "tampered", invocation, projection, wake_intent),
            &super::user_automation_execution::UserAutomationRuntimeComposition::new(
                &UnreachableJob,
                &UnreachableWake,
                &history,
                &StubNotify,
            ),
        )
        .await;
    assert!(
        matches!(
            outcome,
            Err(super::user_automation_execution::UserAutomationExecutionError::Contract(
                eliot_kernel_core::user_automation::UserAutomationError::FailureFingerprintMismatch
            ))
        ),
        "tampered fingerprints refuse with the owner mismatch identity"
    );
}
