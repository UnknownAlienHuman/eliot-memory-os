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
use crate::source_artifact_context::{CanonicalCausalProjection, StoredReceiptHead};
use eliot_store_api::{
    CanonicalRequestView, OperationId, OrderingHeadExpectation, RevisionHeadExpectation,
    StateFence, StoreError, WriteReceipt, canonical_request_hash, committed_receipt_sequence,
    verify_canonical_request_hash, verify_ordering_scope_binding,
};

use super::{FenceRecord, Idempotency, schema_contract::validate_fence_record, take_optional, take_vec};

/// Reads the canonical allocation cursor and its predecessor in one database
/// read transaction, then derives the only causal projection the next apply
/// may bind.
pub(super) async fn read_causal_allocation(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    expected_state_fence: &StateFence,
) -> Result<(Option<FenceRecord>, CanonicalCausalProjection), AdapterError> {
    let mut response = client::query(
        db,
        config,
        "read.canonical_causal_allocation",
        schema::READ_CAUSAL_ALLOCATION,
        Map::new(),
    )
    .await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        if errors.iter().all(client::is_absent_table) {
            let projection = CanonicalCausalProjection::from_store_readback(
                expected_state_fence,
                1,
                None,
            )?;
            return Ok((None, projection));
        }
        return Err(AdapterError::PartialOutcome);
    }

    // The transaction opener occupies result zero, so the fence and receipt
    // rows are the next two bounded statements.
    let fence = take_optional::<FenceRecord>(&mut response, 1)?;
    if let Some(fence) = &fence {
        validate_fence_record(fence)?;
        if fence.state_fence != *expected_state_fence {
            return Err(AdapterError::Store(StoreError::FenceMismatch));
        }
    }
    let heads = take_vec::<StoredReceiptHead>(&mut response, 2)?;
    let next_sequence = fence
        .as_ref()
        .map_or(1, |record| record.next_commit_sequence);
    let predecessor = causal_predecessor(next_sequence, &heads)?;
    let projection = CanonicalCausalProjection::from_store_readback(
        expected_state_fence,
        next_sequence,
        predecessor,
    )?;
    Ok((fence, projection))
}

/// Re-reads a committed receipt and its sequence-selected predecessor in one
/// database transaction. The expected envelope's causal fields are never used
/// to choose or validate the predecessor.
pub(super) async fn read_causal_replay(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    operation_id: &OperationId,
    expected_receipt: &WriteReceipt,
) -> Result<CanonicalCausalProjection, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert("operation_id".to_owned(), json!(operation_id.to_string()));
    let mut response = client::query(
        db,
        config,
        "read.canonical_causal_replay",
        schema::READ_CAUSAL_REPLAY_BY_OPERATION,
        bindings,
    )
    .await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let target = take_vec::<StoredReceiptHead>(&mut response, 1)?;
    let predecessors = take_vec::<StoredReceiptHead>(&mut response, 2)?;
    if target.len() != 1
        || target[0].receipt != *expected_receipt
        || target[0].receipt.operation_id != *operation_id
    {
        return Err(AdapterError::Store(StoreError::InvalidReceipt));
    }
    let committed = &target[0];
    committed.receipt.validate()?;
    if committed_receipt_sequence(&committed.receipt)? != committed.commit_sequence {
        return Err(AdapterError::Store(StoreError::InvalidReceipt));
    }
    let predecessor = causal_predecessor(committed.commit_sequence, &predecessors)?;
    CanonicalCausalProjection::from_store_readback(
        &committed.receipt.state_fence,
        committed.commit_sequence,
        predecessor,
    )
}

fn causal_predecessor(
    commit_sequence: u64,
    rows: &[StoredReceiptHead],
) -> Result<Option<&StoredReceiptHead>, AdapterError> {
    if commit_sequence == 1 {
        if rows.is_empty() {
            return Ok(None);
        }
        return Err(AdapterError::Store(StoreError::InvalidReceipt));
    }
    let expected = commit_sequence - 1;
    let Some(head) = rows.first() else {
        return Err(AdapterError::Store(StoreError::InvalidReceipt));
    };
    if head.commit_sequence != expected
        || rows
            .get(1)
            .is_some_and(|next| next.commit_sequence == expected)
    {
        return Err(AdapterError::Store(StoreError::InvalidReceipt));
    }
    Ok(Some(head))
}

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
        let causal = read_causal_replay(db, config, operation_id, receipt).await?;
        if receipt.require_reconciliation_envelope()?.core.causal != *causal.binding() {
            return Err(AdapterError::Store(StoreError::InvalidReceipt));
        }
    }
    Ok(receipt)
}

/// Resolves durable idempotency state for one exact admitted transition
/// (issue #63).
///
/// Recomputes the canonical request hash from the exact values to be
/// executed (`ctx` + `transition` + expected heads) via the ONE shared
/// helper BEFORE any provider read: supplied != recomputed is
/// `TransitionDigestMismatch` (mapped to `TRANSITION_DIGEST_MISMATCH`) with
/// no lookup success, no transaction and no receipt. The carried ordering
/// scopes must also still equal the hashed expected ordering heads, so a
/// post-admission scope edit fails here too. Replay/conflict is
/// then decided stored-vs-recomputed (never stored-vs-supplied), so a
/// mutated executable payload cannot replay an earlier receipt even when
/// the transported claim is stale.
pub(super) async fn read_idempotency(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
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
    verify_ordering_scope_binding(transition, expected_ordering_heads)
        .map_err(AdapterError::Store)?;
    verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash)
        .map_err(AdapterError::Store)?;
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
    classify_idempotency_with_expected_heads(
        by_operation,
        by_idempotency,
        ctx,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    )
}

/// Decides replay/conflict/digest-mismatch from durable reads (issue #63).
///
/// Pure over already-read receipts so the exact-retry decision is provable
/// without provider effects. Recomputes the canonical hash from the exact
/// values to be executed (`ctx` + `transition` + expected heads) via the
/// shared helper BEFORE any idempotency-lookup success is returned:
/// supplied != recomputed is `TransitionDigestMismatch` (mapped to
/// `TRANSITION_DIGEST_MISMATCH`) with no transaction and no replay. Same
/// key + different executable bytes (recomputed != stored, supplied ==
/// recomputed) stays `IdentityConflict` with no transaction — including a
/// retry that differs only in bound semantic source revisions, which are
/// hash-bound set-like input through the shared view, so the forked digest
/// reaches the `Conflict` arm instead of the replay-candidate check. An exact
/// triple becomes only a replay candidate here; its sequence and predecessor
/// are independently reread before the envelope can validate. Any other
/// identity divergence is a conflict; absence means no prior attempt.
///
/// From the recompute on, supplied == recomputed, so stored-vs-supplied and
/// stored-vs-recomputed coincide; the comparisons below name the recomputed
/// value explicitly so the receipt invariant (receipts bind the recomputed
/// digest) is what gates replay.
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
    verify_ordering_scope_binding(transition, expected_ordering_heads)
        .map_err(AdapterError::Store)?;
    verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash)
        .map_err(AdapterError::Store)?;
    let recomputed = canonical_request_hash(&view).map_err(AdapterError::Store)?;
    if let Some(receipt) = by_operation.into_iter().next() {
        receipt.validate()?;
        return if receipt.idempotency_key == transition.identity.idempotency_key
            && receipt.canonical_request_hash == recomputed
        {
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
        let mut transition = eliot_store_api::PreparedTransition {
            contract_version: eliot_store_api::CONTRACT_VERSION,
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
            // Issue-#18 digests are derived, never defaulted; no semantic
            // source is bound here (`[]`).
            admission_digest: String::new(),
            mutation_plan_digest: String::new(),
            semantic_source_revisions: Vec::new(),
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
        eliot_store_api::bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
        (context, transition)
    }

    fn committed_receipt(
        context: &eliot_store_api::RequestMeta,
        transition: &eliot_store_api::PreparedTransition,
    ) -> WriteReceipt {
        let plan = plan_apply(transition, &[], &[], 1, 1).expect("plan applies");
        build_receipt(context, transition, &plan).expect("receipt builds")
    }

    /// Binds the transition claim to the recomputed digest (issue #63).
    ///
    /// The classifier verifies supplied == recomputed before any replay, so
    /// fixtures stamp the real digest the same way Governor admission does;
    /// the legacy `"a".repeat(64)` placeholder never verifies.
    fn stamp(
        context: &eliot_store_api::RequestMeta,
        transition: &mut eliot_store_api::PreparedTransition,
    ) {
        let view = CanonicalRequestView::from_apply(context, transition, &[], &[]);
        transition.identity.canonical_request_hash =
            canonical_request_hash(&view).expect("stamped digest");
    }

    #[test]
    fn exact_retry_replays_the_byte_identical_receipt() {
        let (context, mut transition) = fixture();
        stamp(&context, &mut transition);
        let receipt = committed_receipt(&context, &transition);
        match classify_idempotency_with_expected_heads(
            vec![receipt.clone()],
            Vec::new(),
            &context,
            &transition,
            &[],
            &[],
        )
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
        let (context, mut transition) = fixture();
        stamp(&context, &mut transition);
        let receipt = committed_receipt(&context, &transition);
        // Same operation, substituted canonical hash.
        let mut substituted = receipt.clone();
        substituted.canonical_request_hash = "c".repeat(64);
        assert!(matches!(
            classify_idempotency_with_expected_heads(
                vec![substituted],
                Vec::new(),
                &context,
                &transition,
                &[],
                &[]
            )
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
            classify_idempotency_with_expected_heads(
                Vec::new(),
                vec![other_receipt],
                &context,
                &transition,
                &[],
                &[]
            )
            .expect("operation divergence classifies"),
            Idempotency::Conflict
        ));
        // No prior attempt.
        assert!(matches!(
            classify_idempotency_with_expected_heads(
                Vec::new(),
                Vec::new(),
                &context,
                &transition,
                &[],
                &[]
            )
            .expect("absence classifies"),
            Idempotency::None
        ));
    }

    #[test]
    fn triple_match_with_broken_envelope_fails_closed() {
        let (context, mut transition) = fixture();
        stamp(&context, &mut transition);
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
            classify_idempotency_with_expected_heads(
                vec![tampered],
                Vec::new(),
                &context,
                &transition,
                &[],
                &[]
            )
            .is_err(),
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
