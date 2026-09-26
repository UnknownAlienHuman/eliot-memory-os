//! Canonical notification-state persistence proofs (issue #1780).
//!
//! Drives the closed `ApplyNotificationState` / `GetNotificationState`
//! operations through the reference contour: atomic record+outbox commit,
//! dedup coalescing with occurrence counting, delivery/ack visibility,
//! receipt-bound resolution, forged-authority rejection, and exact-identity
//! reconciliation without remutation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, EpochId, EpochLineageId, OperationId, ProductId,
    RequestId, ResourceGeneration, SourceId, StateFence, TransactionSequence,
};
use eliot_kernel_core::{DeliveryState, ResolutionAuthorization};
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, CausalBinding, EffectClass, OperationBinding, ProofCeiling,
    ReceiptCore, ReceiptDisposition, ReceiptEnvelope, ReceiptKind, RequestBinding,
    WorkScopeBinding, WorkScopeId, contract_identity,
};
use eliot_store_api::{CanonicalRequestView, EventProjectionRelationIntents};
use eliot_store_api::{
    NOTIFY_MUTATION_ACKNOWLEDGE, NOTIFY_MUTATION_DELIVERY, NOTIFY_MUTATION_RESOLVE,
    NOTIFY_MUTATION_UPSERT, NOTIFY_PARAM_AUTHORIZATION_JSON, NOTIFY_PARAM_CHANNEL,
    NOTIFY_PARAM_DEDUP_KEY, NOTIFY_PARAM_DELIVERY_JSON, NOTIFY_PARAM_DISPOSITION,
    NOTIFY_PARAM_MUTATION, NOTIFY_PARAM_NOTIFICATION_ID, NOTIFY_PARAM_PRINCIPAL,
    NOTIFY_PARAM_RECORD_JSON, NOTIFY_PARAM_SOURCE_RECEIPT_JSON, NamedMutationOperation,
    NamedMutationRequest, OperationIdentity, OrderingScopeId, PreparedTransition, RequestMeta,
    ScopeId, SecurityContext, StoreError, TransitionClass, WriteReceipt, WriteReceiptStatus,
    bind_issue18_digests, canonical_request_hash, operation_manifest_set_digest,
};
use serde_json::{Value, json};

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
        request_id: RequestId::new(format!("request-notify-{tag}")).expect("request"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-notify").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn draft_value(key: &str, severity: &str) -> Value {
    json!({
        "notification_id": format!("notification-{key}"),
        "severity": severity,
        "subject": "subject",
        "summary": "summary",
        "evidence_handles": ["evidence-1"],
        "affected_scope": "scope-1",
        "owner": "owner-1",
        "required_action": "review",
        "deadline_or_review": null,
        "dedup_key": key,
        "delivery_channels": ["CONTROL_BOARD", "NATIVE_TOAST"],
        "state_fence": serde_json::to_value(fence()).expect("fence json"),
    })
}

fn source_receipt() -> ReceiptEnvelope {
    source_receipt_for("owner-1")
}

fn source_receipt_for(owner: &str) -> ReceiptEnvelope {
    let fence = fence();
    let request_id = RequestId::new("resolve-request").expect("request id");
    let metadata = RequestMeta {
        request_id: request_id.clone(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-notify").expect("product"),
        source_id: SourceId::new("owner-1").expect("source"),
        state_fence: fence.clone(),
        clock: ClockReading::default(),
    };
    ReceiptEnvelope::issue(ReceiptCore {
        contract: contract_identity().expect("contract"),
        kind: ReceiptKind::Verification,
        work_scope: WorkScopeBinding {
            scope_id: WorkScopeId::new("scope-1").expect("scope"),
            product_id: metadata.product_id.clone(),
            resource_generation: ResourceGeneration::new(1).expect("generation"),
            state_fence: fence.clone(),
        },
        task: None,
        session: None,
        causal: CausalBinding {
            state_fence: fence.clone(),
            transaction_sequence: TransactionSequence::genesis(),
            parent_receipt_id: None,
            predecessor_receipt_ids: Vec::new(),
        },
        request: RequestBinding {
            metadata,
            state_fence: fence.clone(),
        },
        operation: OperationBinding {
            operation_id: OperationId::new("resolve-operation").expect("operation"),
            request_id,
            idempotency_key: "resolve-idempotency".to_owned(),
            operation_kind: "notification.resolve".to_owned(),
            effect: EffectClass::ReversibleMutation,
            state_fence: fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new("authority-owner-1").expect("authority"),
            authority_owner: owner.to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect: EffectClass::ReversibleMutation,
            proof_ceiling: ProofCeiling::ScopedVerification,
        },
        artifacts: vec![ArtifactBinding {
            artifact_id: ArtifactId::new("evidence-1").expect("artifact"),
            sha256: eliot_contracts::sha256_hex(b"evidence-1"),
            role: ReceiptKind::Artifact,
            source_revision: Some("test".to_owned()),
        }],
        verifier: None,
        problem: None,
        coordination: None,
        disposition: ReceiptDisposition::Success {
            proof: ProofCeiling::ScopedVerification,
        },
    })
    .expect("receipt")
}

fn upsert_params(key: &str, severity: &str) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            NOTIFY_PARAM_MUTATION.to_owned(),
            Value::String(NOTIFY_MUTATION_UPSERT.to_owned()),
        ),
        (
            NOTIFY_PARAM_DEDUP_KEY.to_owned(),
            Value::String(key.to_owned()),
        ),
        (
            NOTIFY_PARAM_RECORD_JSON.to_owned(),
            draft_value(key, severity),
        ),
        (
            NOTIFY_PARAM_SOURCE_RECEIPT_JSON.to_owned(),
            serde_json::to_value(source_receipt()).expect("receipt json"),
        ),
    ])
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
            operation_id: OperationId::new(format!("op-notify-{tag}")).expect("operation id"),
            idempotency_key: format!("idem-notify-{tag}"),
            canonical_request_hash: "0".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("notification-state").expect("scope"),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new("notification-state").expect("ordering")],
        transition_class: TransitionClass::NotificationState,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: "c".repeat(64),
        // Issue #18: placeholder bindings, derived below via
        // `bind_issue18_digests` (empty heads in this helper).
        semantic_source_revisions: Vec::new(),
        admission_digest: String::new(),
        operation_manifest_digest: manifest_digest,
        mutation_plan_digest: String::new(),
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
    let view = CanonicalRequestView::from_apply(&ctx, &transition, &[], &[]);
    transition.identity.canonical_request_hash =
        canonical_request_hash(&view).expect("hash computes");
    // Issue #18: the admission digest covers the canonical hash, so bind
    // after the hash is final.
    bind_issue18_digests(&mut transition, Vec::new()).expect("fixture digests bind");
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

fn record_for(store: &MemoryStore, dedup_key: &str) -> eliot_kernel_core::Notification {
    store
        .lock_state()
        .expect("state")
        .notifications
        .get(dedup_key)
        .expect("record")
        .clone()
}

#[test]
fn upsert_persists_one_record_with_atomic_outbox() {
    let store = MemoryStore::new();
    let receipt = apply(
        &store,
        "upsert-1",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("disk-full", "WARNING"),
    )
    .expect("upsert commits");
    assert_eq!(receipt.status, WriteReceiptStatus::Committed);
    // One generic transition outbox intent plus one notification intent per
    // mutation, all committed atomically under the same receipt.
    assert_eq!(receipt.outbox_refs.len(), 2);
    let outbox = store.outbox().expect("outbox");
    assert_eq!(outbox.len(), 2);
    let notify_id = "outbox-op-notify-upsert-1-notify-0";
    assert!(
        receipt
            .outbox_refs
            .iter()
            .any(|id| id.as_str() == notify_id)
    );
    let intent = outbox
        .iter()
        .find(|intent| intent.outbox_id.as_str() == notify_id)
        .expect("notification outbox intent");
    assert_eq!(intent.state, eliot_store_api::OutboxState::Arrived);
    let record = record_for(&store, "disk-full");
    assert_eq!(record.occurrences, 1);
    assert_eq!(record.revision, 1);
    assert_eq!(record.delivery, DeliveryState::Pending);
    assert!(record.is_unresolved());
}

#[test]
fn repeat_dedup_updates_one_record_and_replay_returns_same_receipt() {
    let store = MemoryStore::new();
    let first = apply(
        &store,
        "dedup-1",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("disk-full", "WARNING"),
    )
    .expect("first upsert");
    // A distinct operation with the same dedup key coalesces: one record,
    // occurrences incremented, new receipt.
    let second = apply(
        &store,
        "dedup-2",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("disk-full", "WARNING"),
    )
    .expect("repeat upsert");
    assert_ne!(second.commit_id, first.commit_id);
    assert_eq!(record_for(&store, "disk-full").occurrences, 2);
    assert_eq!(store.lock_state().expect("state").notifications.len(), 1);
    // Byte-identical replay of the first identity returns the original
    // receipt without remutation.
    let (ctx, transition) = transition_with(
        "dedup-1",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("disk-full", "WARNING"),
    );
    let replayed = store
        .apply_transaction(&ctx, transition, &[], &[])
        .expect("replay");
    assert_eq!(replayed.commit_id, first.commit_id);
    assert_eq!(record_for(&store, "disk-full").occurrences, 2);

    let mut divergent = upsert_params("disk-full", "WARNING");
    if let Some(Value::Object(record)) = divergent.get_mut(NOTIFY_PARAM_RECORD_JSON) {
        record.insert("subject".to_owned(), Value::String("changed".to_owned()));
    }
    assert_eq!(
        apply(
            &store,
            "dedup-1",
            NamedMutationOperation::ApplyNotificationState,
            divergent
        ),
        Err(StoreError::IdentityConflict)
    );
}

#[test]
fn delivery_ack_and_read_visibility() {
    let store = MemoryStore::new();
    apply(
        &store,
        "vis-1",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("backup-failed", "CRITICAL"),
    )
    .expect("upsert");
    let delivery = BTreeMap::from([
        (
            NOTIFY_PARAM_MUTATION.to_owned(),
            Value::String(NOTIFY_MUTATION_DELIVERY.to_owned()),
        ),
        (
            NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
            Value::String("notification-backup-failed".to_owned()),
        ),
        (
            NOTIFY_PARAM_CHANNEL.to_owned(),
            Value::String("NATIVE_TOAST".to_owned()),
        ),
        (
            NOTIFY_PARAM_DELIVERY_JSON.to_owned(),
            json!({"kind": "FAILED", "reason": "toast provider failed"}),
        ),
    ]);
    apply(
        &store,
        "vis-2",
        NamedMutationOperation::ApplyNotificationState,
        delivery,
    )
    .expect("delivery records");
    let record = record_for(&store, "backup-failed");
    assert!(record.is_failed_delivery());
    assert!(record.is_unresolved());

    let ack = BTreeMap::from([
        (
            NOTIFY_PARAM_MUTATION.to_owned(),
            Value::String(NOTIFY_MUTATION_ACKNOWLEDGE.to_owned()),
        ),
        (
            NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
            Value::String("notification-backup-failed".to_owned()),
        ),
        (
            NOTIFY_PARAM_PRINCIPAL.to_owned(),
            Value::String("operator-1".to_owned()),
        ),
    ]);
    apply(
        &store,
        "vis-3",
        NamedMutationOperation::ApplyNotificationState,
        ack,
    )
    .expect("ack records");
    let record = record_for(&store, "backup-failed");
    assert!(record.is_unresolved());
    assert!(record.is_failed_delivery());
    assert!(!record.should_popup(false));

    let query =
        eliot_store_api::notification_read_request(None, None, None, true, 10, None, fence())
            .expect("read builds");
    let response = store.execute_named_sync(&query).expect("read executes");
    let payload = response.payload;
    let metrics = payload.get("metrics").expect("metrics");
    assert_eq!(metrics.get("failed_delivery_unresolved"), Some(&json!(1)));
    assert_eq!(metrics.get("acknowledged_unresolved"), Some(&json!(1)));
    assert_eq!(metrics.get("critical_unresolved"), Some(&json!(1)));
}

#[test]
fn forged_resolution_is_rejected_and_bound_resolution_closes() {
    let store = MemoryStore::new();
    apply(
        &store,
        "res-1",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("kernel-fence", "CRITICAL"),
    )
    .expect("upsert");
    let resolve_with = |authorization: Value| {
        BTreeMap::from([
            (
                NOTIFY_PARAM_MUTATION.to_owned(),
                Value::String(NOTIFY_MUTATION_RESOLVE.to_owned()),
            ),
            (
                NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
                Value::String("notification-kernel-fence".to_owned()),
            ),
            (
                NOTIFY_PARAM_DISPOSITION.to_owned(),
                Value::String("fixed".to_owned()),
            ),
            (NOTIFY_PARAM_AUTHORIZATION_JSON.to_owned(), authorization),
        ])
    };
    let forged = resolve_with(json!({
        "receipt": {"identity": {"receipt_id": "forged", "canonical_sha256": "f".repeat(64)}},
        "evidence_handles": ["evidence-1"],
    }));
    assert!(matches!(
        apply(
            &store,
            "res-2",
            NamedMutationOperation::ApplyNotificationState,
            forged
        ),
        Err(StoreError::Serialization(_))
    ));

    let empty_evidence = resolve_with(json!({
        "receipt": serde_json::to_value(source_receipt()).expect("receipt json"),
        "evidence_handles": [],
    }));
    assert!(matches!(
        apply(
            &store,
            "res-3",
            NamedMutationOperation::ApplyNotificationState,
            empty_evidence
        ),
        Err(StoreError::InvalidField { .. })
    ));

    let intruder = serde_json::to_value(source_receipt_for("intruder")).expect("receipt json");
    let misbound = resolve_with(json!({
        "receipt": intruder,
        "evidence_handles": ["evidence-1"],
    }));
    assert_eq!(
        apply(
            &store,
            "res-3b",
            NamedMutationOperation::ApplyNotificationState,
            misbound
        ),
        Err(StoreError::EffectCeilingExceeded)
    );

    let authorization = ResolutionAuthorization {
        receipt: source_receipt(),
        evidence_handles: vec!["evidence-1".to_owned()],
    };
    let bound = resolve_with(serde_json::to_value(authorization).expect("auth json"));
    apply(
        &store,
        "res-4",
        NamedMutationOperation::ApplyNotificationState,
        bound,
    )
    .expect("bound resolution commits");
    let record = record_for(&store, "kernel-fence");
    assert!(!record.is_unresolved());
    assert_eq!(
        record
            .resolution_ref
            .as_ref()
            .expect("resolution")
            .authority_owner,
        "owner-1"
    );
}

#[test]
fn unknown_identity_and_fence_divergence_fail_closed() {
    let store = MemoryStore::new();
    let ack = BTreeMap::from([
        (
            NOTIFY_PARAM_MUTATION.to_owned(),
            Value::String(NOTIFY_MUTATION_ACKNOWLEDGE.to_owned()),
        ),
        (
            NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
            Value::String("notification-ghost".to_owned()),
        ),
        (
            NOTIFY_PARAM_PRINCIPAL.to_owned(),
            Value::String("operator-1".to_owned()),
        ),
    ]);
    assert!(matches!(
        apply(
            &store,
            "neg-1",
            NamedMutationOperation::ApplyNotificationState,
            ack
        ),
        Err(StoreError::InvalidField { .. })
    ));

    let (mut ctx, transition) = transition_with(
        "neg-2",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("fence-test", "WARNING"),
    );
    ctx.state_fence = StateFence::new(
        ctx.state_fence.authority_epoch.clone(),
        ResourceGeneration::new(9).expect("generation"),
    );
    assert_eq!(
        store.apply_transaction(&ctx, transition, &[], &[]),
        Err(StoreError::FenceMismatch)
    );
}

#[test]
fn receipt_lookup_reconciles_without_remutation() {
    let store = MemoryStore::new();
    let receipt = apply(
        &store,
        "rec-1",
        NamedMutationOperation::ApplyNotificationState,
        upsert_params("disk-full", "WARNING"),
    )
    .expect("upsert commits");
    let stored = store
        .receipt_sync(&receipt.operation_id)
        .expect("receipt lookup");
    assert!(stored.is_some());
    assert_eq!(record_for(&store, "disk-full").occurrences, 1);
}
