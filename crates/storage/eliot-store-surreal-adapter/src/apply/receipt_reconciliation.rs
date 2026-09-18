//! Physical receipt, idempotency and fence reconciliation reads for the Surreal adapter.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01.
//! Implementation: I5.1, I5.9, I5.19, I5.20, I5.3, I2.23 — R2 storage execution, receipt/read-export and bridge named operations via the Surreal bridge.
//! Ownership: physical receipt/idempotency/fence reconciliation reads only; no semantic policy, transition/write, authority, retry/default or Store-SDK ownership beyond the existing adapter port.

use serde_json::{Map, json};

use crate::SurrealStoreAdapter;
use crate::client;
use crate::config::SurrealAdapterConfig;
use crate::error::AdapterError;
use crate::schema;
use eliot_store_api::{
    CanonicalRequestView, OperationId, OrderingHeadExpectation, RevisionHeadExpectation,
    WriteReceipt, canonical_request_hash, validate_store_receipt_envelope,
    verify_canonical_request_hash,
};

use super::{FenceRecord, Idempotency, take_optional, take_vec};

/// Resolves a durable receipt by operation identity; the reconciliation read.
pub(crate) async fn read_receipt(
    adapter: &SurrealStoreAdapter,
    operation_id: OperationId,
) -> Result<Option<WriteReceipt>, AdapterError> {
    let db = super::client(adapter).await?;
    super::ensure_ready(adapter, db).await?;
    read_receipt_by_operation(db, &adapter.config, &operation_id).await
}

pub(super) async fn read_receipt_by_operation(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    operation_id: &OperationId,
) -> Result<Option<WriteReceipt>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert("table".to_owned(), json!(schema::table::WRITE_RECEIPT));
    bindings.insert("key".to_owned(), json!(operation_id.to_string()));
    let mut response = client::query(
        db,
        config,
        "read.receipt_by_operation",
        schema::READ_RECEIPT_BY_OPERATION,
        bindings,
    )
    .await?;
    let receipt = take_optional::<WriteReceipt>(&mut response, 0)?;
    if let Some(receipt) = &receipt {
        receipt.validate()?;
        receipt.require_reconciliation_envelope()?;
    }
    Ok(receipt)
}

pub(super) async fn read_idempotency(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    ctx: &eliot_store_api::RequestMeta,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<Idempotency, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "operation_id".to_owned(),
        json!(transition.identity.operation_id.to_string()),
    );
    bindings.insert(
        "idempotency_key".to_owned(),
        json!(transition.identity.idempotency_key),
    );
    let mut response = client::query(
        db,
        config,
        "read.receipt_idempotency",
        schema::READ_RECEIPT_IDEMPOTENCY,
        bindings,
    )
    .await?;
    let by_operation = take_vec::<WriteReceipt>(&mut response, 0)?;
    let by_idempotency = take_vec::<WriteReceipt>(&mut response, 1)?;
    classify_idempotency(by_operation, by_idempotency, ctx, transition)
}

/// Decides replay/conflict/none from durable idempotency reads (slice C2).
///
/// Pure over already-read receipts so the exact-retry decision is provable
/// without provider effects: an exact operation/idempotency/canonical-hash
/// triple with a valid envelope replays the byte-identical receipt (no
/// re-effect); any identity divergence is a conflict; absence means no prior
/// attempt. A triple match with a broken envelope fails closed with the
/// envelope error instead of replaying or conflicting.
pub(super) fn classify_idempotency(
    by_operation: Vec<WriteReceipt>,
    by_idempotency: Vec<WriteReceipt>,
    ctx: &eliot_store_api::RequestMeta,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<Idempotency, AdapterError> {
    if let Some(receipt) = by_operation.into_iter().next() {
        receipt.validate()?;
        return if receipt.idempotency_key == transition.identity.idempotency_key
            && receipt.canonical_request_hash == transition.identity.canonical_request_hash
        {
            validate_store_receipt_envelope(ctx, transition, &receipt)?;
            Ok(Idempotency::Replay(receipt))
        } else {
            Ok(Idempotency::Conflict)
        };
    }
    if let Some(receipt) = by_idempotency.into_iter().next() {
        receipt.validate()?;
        return if receipt.canonical_request_hash == transition.identity.canonical_request_hash
            && receipt.operation_id == transition.identity.operation_id
        {
            validate_store_receipt_envelope(ctx, transition, &receipt)?;
            Ok(Idempotency::Replay(receipt))
        } else {
            Ok(Idempotency::Conflict)
        };
    }
    Ok(Idempotency::None)
}

/// Decides replay/conflict/digest-mismatch from durable reads (RECHECK-63
/// slice C).
///
/// Recomputes the canonical hash from the exact values to be executed
/// (`ctx` + `transition` + expected heads) via the shared helper BEFORE any
/// idempotency-lookup success is returned: supplied != recomputed is
/// `TransitionDigestMismatch` (mapped to `TRANSITION_DIGEST_MISMATCH`) with no
/// transaction and no replay. Same key + different executable bytes
/// (recomputed != stored, supplied == recomputed) stays `IdentityConflict`
/// with no transaction. Exact triple with a valid envelope replays.
///
/// Residual wiring (cannot edit `apply.rs` here): `apply.rs:579`
/// `read_idempotency(db, &adapter.config, ctx, &transition)` must pass the
/// `expected_revision_heads` / `expected_ordering_heads` from
/// `apply_prepared_with_authority` and call this function, otherwise the live
/// Surreal path keeps the legacy hash-blind classifier.
#[allow(dead_code)]
pub(super) fn classify_idempotency_with_expected_heads(
    by_operation: Vec<WriteReceipt>,
    by_idempotency: Vec<WriteReceipt>,
    ctx: &eliot_store_api::RequestMeta,
    transition: &eliot_store_api::PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<Idempotency, AdapterError> {
    let view = CanonicalRequestView::from_apply(
        ctx,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    );
    verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash)
        .map_err(AdapterError::Store)?;
    let recomputed = canonical_request_hash(&view).map_err(AdapterError::Store)?;
    // From here supplied == recomputed, so stored-vs-supplied and
    // stored-vs-recomputed coincide; compare against recomputed explicitly so
    // the receipt invariant (binds recomputed) is what gates replay.
    if let Some(receipt) = by_operation.into_iter().next() {
        receipt.validate()?;
        return if receipt.idempotency_key == transition.identity.idempotency_key
            && receipt.canonical_request_hash == recomputed
        {
            validate_store_receipt_envelope(ctx, transition, &receipt)?;
            Ok(Idempotency::Replay(receipt))
        } else {
            Ok(Idempotency::Conflict)
        };
    }
    if let Some(receipt) = by_idempotency.into_iter().next() {
        receipt.validate()?;
        return if receipt.canonical_request_hash == recomputed
            && receipt.operation_id == transition.identity.operation_id
        {
            validate_store_receipt_envelope(ctx, transition, &receipt)?;
            Ok(Idempotency::Replay(receipt))
        } else {
            Ok(Idempotency::Conflict)
        };
    }
    Ok(Idempotency::None)
}

pub(super) async fn read_fence(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Option<FenceRecord>, AdapterError> {
    let mut response = client::query(
        db,
        config,
        "read.canonical_fence",
        schema::READ_FENCE,
        Map::new(),
    )
    .await?;
    // S1 #775 real-provider compatibility: a never-defined fence table
    // observes absent-table, which preflight translates into `None`. Draining
    // leaves statement values untouched, so every other observation decodes
    // below with exactly its prior disposition.
    let errors = response.take_errors();
    if !errors.is_empty() && errors.iter().all(|error| client::is_absent_table(error)) {
        return Ok(None);
    }
    take_optional::<FenceRecord>(&mut response, 0)
}

#[cfg(test)]
mod idempotency_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::plan::{build_receipt, plan_apply};
    use eliot_store_api::{
        EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
        OperationIdentity, OperationManifestDigest, OrderingScopeId, ScopeId, SecurityContext,
        TransitionClass,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_fence() -> eliot_store_api::StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new(TEST_LINEAGE_A).expect("canonical test lineage-A");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("epoch");
        eliot_store_api::StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn fixture() -> (
        eliot_store_api::RequestMeta,
        eliot_store_api::PreparedTransition,
    ) {
        let fence = test_fence();
        let context = eliot_store_api::RequestMeta {
            request_id: eliot_contracts::RequestId::new("request-idem").expect("request id"),
            session_id: None,
            task_id: None,
            product_id: eliot_contracts::ProductId::new("product-idem").expect("product"),
            source_id: eliot_contracts::SourceId::new("source-idem").expect("source"),
            state_fence: fence.clone(),
            clock: eliot_contracts::ClockReading::default(),
        };
        let transition = eliot_store_api::PreparedTransition {
            identity: OperationIdentity {
                operation_id: eliot_store_api::OperationId::new("op-idem").expect("operation"),
                idempotency_key: "idem-key".to_owned(),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence: fence,
            scope_id: ScopeId::new("scope-idem").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-idem").expect("ordering")],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "b".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-idem")
                .expect("manifest digest"),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([("subject".to_owned(), json!("op-idem"))]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        };
        (context, transition)
    }

    fn committed_receipt(
        context: &eliot_store_api::RequestMeta,
        transition: &eliot_store_api::PreparedTransition,
    ) -> WriteReceipt {
        let plan = plan_apply(transition, &[], &[], 1, 1).expect("plan applies");
        build_receipt(context, transition, &plan).expect("receipt builds")
    }

    #[test]
    fn exact_retry_replays_the_byte_identical_receipt() {
        let (context, transition) = fixture();
        let receipt = committed_receipt(&context, &transition);
        match classify_idempotency(vec![receipt.clone()], Vec::new(), &context, &transition)
            .expect("exact triple classifies")
        {
            Idempotency::Replay(replayed) => {
                assert_eq!(replayed, receipt, "exact retry replays without re-effect");
            }
            Idempotency::Conflict | Idempotency::None => {
                panic!("exact triple must replay")
            }
        }
    }

    #[test]
    fn identity_divergence_is_a_conflict_not_a_replay() {
        let (context, transition) = fixture();
        let receipt = committed_receipt(&context, &transition);
        // Same operation, substituted canonical hash.
        let mut substituted = receipt.clone();
        substituted.canonical_request_hash = "c".repeat(64);
        assert!(matches!(
            classify_idempotency(vec![substituted], Vec::new(), &context, &transition)
                .expect("hash divergence classifies"),
            Idempotency::Conflict
        ));
        // Same idempotency key, different operation identity: a second
        // self-consistent receipt that cannot be this transition's replay.
        let mut other_transition = transition.clone();
        other_transition.identity.operation_id =
            eliot_store_api::OperationId::new("op-other").expect("operation");
        let other_receipt = committed_receipt(&context, &other_transition);
        assert!(matches!(
            classify_idempotency(Vec::new(), vec![other_receipt], &context, &transition)
                .expect("operation divergence classifies"),
            Idempotency::Conflict
        ));
        // No prior attempt.
        assert!(matches!(
            classify_idempotency(Vec::new(), Vec::new(), &context, &transition)
                .expect("absence classifies"),
            Idempotency::None
        ));
    }

    #[test]
    fn triple_match_with_broken_envelope_fails_closed() {
        let (context, transition) = fixture();
        let receipt = committed_receipt(&context, &transition);
        // Same admitted triple, but the envelope belongs to a different
        // commit sequence, so it cannot be the receipt's own envelope.
        let later_plan = plan_apply(&transition, &[], &[], 2, 1).expect("later plan applies");
        let later =
            build_receipt(&context, &transition, &later_plan).expect("later receipt builds");
        assert_ne!(
            receipt.envelope, later.envelope,
            "different commit sequences bind different envelopes"
        );
        let mut tampered = receipt.clone();
        tampered.envelope = later.envelope.clone();
        assert!(
            classify_idempotency(vec![tampered], Vec::new(), &context, &transition).is_err(),
            "envelope substitution must fail closed, never replay"
        );
    }

    #[test]
    fn recomputed_classifier_rejects_tamper_before_replay_and_keeps_conflict_split() {
        use crate::plan::{build_receipt_with_expected_heads, plan_apply};
        use eliot_store_api::{CanonicalRequestView, StoreError, canonical_request_hash};

        // RECHECK-63 slice C (pure, no live DB): supplied != recomputed is
        // TRANSITION_DIGEST_MISMATCH with no replay; same-key-different-bytes
        // with supplied == recomputed stays IDENTITY_CONFLICT (Conflict).
        let (context, mut transition) = fixture();
        let view = CanonicalRequestView::from_apply(&context, &transition, &[], &[]);
        let recomputed = canonical_request_hash(&view).expect("recomputed digest");
        assert_ne!(
            recomputed,
            "a".repeat(64),
            "legacy placeholder is never the real digest"
        );
        transition.identity.canonical_request_hash = recomputed.clone();
        let plan = plan_apply(&transition, &[], &[], 1, 1).expect("plan applies");
        let receipt = build_receipt_with_expected_heads(&context, &transition, &plan, &[], &[])
            .expect("receipt binds recomputed");
        assert_eq!(receipt.canonical_request_hash, recomputed);
        // Exact replays.
        assert!(matches!(
            classify_idempotency_with_expected_heads(
                vec![receipt.clone()],
                Vec::new(),
                &context,
                &transition,
                &[],
                &[]
            )
            .expect("exact classifies"),
            Idempotency::Replay(replayed) if replayed == receipt
        ));
        // Tampered executable bytes with the old claim: typed mismatch, never
        // a replay and never a conflict success.
        let mut tampered = transition.clone();
        tampered.named_operations[0]
            .parameters
            .insert("subject".to_owned(), json!("tampered"));
        assert!(matches!(
            classify_idempotency_with_expected_heads(
                vec![receipt.clone()],
                Vec::new(),
                &context,
                &tampered,
                &[],
                &[]
            ),
            Err(AdapterError::Store(
                StoreError::TransitionDigestMismatch { .. }
            ))
        ));
        assert!(matches!(
            classify_idempotency_with_expected_heads(
                Vec::new(),
                Vec::new(),
                &context,
                &tampered,
                &[],
                &[]
            ),
            Err(AdapterError::Store(
                StoreError::TransitionDigestMismatch { .. }
            ))
        ));
        // Same idempotency key, different executable bytes, each side
        // self-consistent (supplied == recomputed for its own bytes): the
        // stored receipt differs from the new recomputed, so Conflict.
        let mut forked = transition.clone();
        forked.identity.operation_id =
            eliot_store_api::OperationId::new("op-idem-fork").expect("operation");
        forked.named_operations[0]
            .parameters
            .insert("subject".to_owned(), json!("forked"));
        let forked_view = CanonicalRequestView::from_apply(&context, &forked, &[], &[]);
        forked.identity.canonical_request_hash =
            canonical_request_hash(&forked_view).expect("forked digest");
        assert_ne!(
            forked.identity.canonical_request_hash, recomputed,
            "fork binds a different recomputed digest"
        );
        assert!(matches!(
            classify_idempotency_with_expected_heads(
                vec![receipt],
                Vec::new(),
                &context,
                &forked,
                &[],
                &[]
            )
            .expect("fork classifies"),
            Idempotency::Conflict
        ));
    }
}
