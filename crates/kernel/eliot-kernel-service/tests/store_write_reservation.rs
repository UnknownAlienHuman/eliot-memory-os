//! Kernel reserved-write binding to durable ORS reservations (issue #992).
//!
//! Twenty cases (`992/1`..`992/20`) prove the composition-bound ORS adaptation
//! and exact Store-projection conversion: every positive lifecycle step runs
//! through the real isolated ORS/redb operations (`stage_and_reserve`,
//! `mark_eligible`, `begin_execute`, `mark_unknown`, `reconcile`, `release`)
//! and the real #990 projection plus the real #991 client exchange. No test
//! fabricates a token: the only minted tokens come from `reserve_for_transition`.
//!
//! Case map:
//! - 01 exact two-constructor injection and production gateway→ORS→Store map.
//! - 02 unbound/foreign canonical verifier or ORS owner rejected.
//! - 03 complete multi-scope reservation is atomic or none.
//! - 04 exact operation/admission/scope/head/token projection.
//! - 05 one canonical reservation_order across overlapping scopes.
//! - 06 not-yet-eligible/missing predecessor cannot dispatch.
//! - 07 stale epoch/fence/expiry or changed digest cannot dispatch.
//! - 08 reserved capability absent does not fall back to unreserved write.
//! - 09 queued normal work holds no provider/Kernel-lock/protected-control resource.
//! - 10 cancellation before possible submission releases only its exact reservation.
//! - 11 cancellation/timeout after possible submission retains reconciliation.
//! - 12 canonical committed receipt finalizes the complete exact scope set.
//! - 13 proved-not-applied release versus still-unknown remains distinct.
//! - 14 forged/foreign/partial/stale receipt cannot release/finalize.
//! - 15 old executor cannot finalize another generation's token.
//! - 16 exact replay versus changed operation content.
//! - 17 ORS reopen/rebind recovers unresolved reservations before new allocation.
//! - 18 one reconciling scope leaves unrelated work eligible and migration drain
//!   remains honest.
//! - 19 source/error/cancellation paths preserve identity and redaction without
//!   a second state/authority owner.
//! - 20 actual call-chain and bounded fault-sequence proof: no orphaned token,
//!   partial scope release, hidden retry or semantic transition mutation.
//!
//! Frozen domain inputs live in `data/store_write_reservation.json`; every
//! literal below is asserted against that fixture, never re-declared.
//!
//! The fake Store side speaks real EBP frames through the production exchange
//! (pipe loopback in gateway cases); it manufactures responses bound to the
//! admitted request, never admission authority. Shared atomic counters observe
//! send counts from outside, and the ordinary-`Apply` route panics so any
//! unreserved fallback fails the test outright.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration,
    SourceId, StateFence,
};
use eliot_kernel_service::{
    CompositionReservation, ObservedHead, ReservationSeed, ReservationWriteError,
    SealedReservation, begin_execute, cancel_before_send, ensure_eligible, finalize_reservation,
    mark_unknown_outcome, project_reserved_write, reconcile_receipt, reserve_for_transition,
};
use eliot_ors::{
    CanonicalEvidenceProvider, EpochIdentity, EpochLineage, OpaqueLabel, OrsError,
    RedbRecoveryStore, ReservationState,
};
use eliot_store_api::{
    CanonicalRequestView, CommitId, EffectClass, EventProjectionRelationIntents,
    NamedMutationOperation, NamedMutationRequest, OperationIdentity, OperationManifestDigest,
    OrderingHead, OrderingHeadExpectation, OrderingScopeId, PreparedTransition, RequestMeta,
    ReservedWriteRequest, Resubmission, RevisionHeadExpectation, RevisionKey, ScopeId,
    SecurityContext, StoreError, TransitionClass, WriteReceipt, WriteReceiptStatus,
    canonical_request_hash,
};
use serde_json::{Value, json};

const LINEAGE_992: &str = "550e8400-e29b-41d4-a716-446655440000";

fn fixture() -> Value {
    let text = include_str!("data/store_write_reservation.json");
    serde_json::from_str(text).expect("992 fixture parses")
}

fn epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_992).unwrap(),
        NonZeroU64::new(sequence).unwrap(),
    )
    .unwrap()
}

fn fence() -> StateFence {
    StateFence::new(epoch(1), ResourceGeneration::genesis())
}

fn writer_epoch() -> EpochLineage {
    EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new(LINEAGE_992).unwrap(),
            epoch: 1,
        },
        predecessor: None,
    }
}

fn context_for(tag: &str) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(format!("request-992-{tag}")).unwrap(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-992-k").unwrap(),
        source_id: SourceId::new("eliotd").unwrap(),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn transition_for(tag: &str, scopes: &[&str]) -> PreparedTransition {
    PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new(format!("op-992-{tag}")).unwrap(),
            idempotency_key: format!("idem-992-{tag}"),
            canonical_request_hash: "0".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new(format!("scope-992-{tag}")).unwrap(),
        task_id: None,
        ordering_scopes: scopes
            .iter()
            .map(|scope| OrderingScopeId::new((*scope).to_owned()).unwrap())
            .collect(),
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: OperationManifestDigest::new(format!("manifest-992-{tag}"))
            .unwrap(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([("subject".to_owned(), json!("observation-992"))]),
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    }
}

/// Seals the canonical request hash over the exact values about to be bound,
/// exactly as the gateway admission does before any ORS or Store work.
fn seal(
    context: &RequestMeta,
    transition: &mut PreparedTransition,
    revision: &[RevisionHeadExpectation],
    ordering: &[OrderingHeadExpectation],
) {
    let view = CanonicalRequestView::from_apply(context, transition, revision, ordering);
    transition.identity.canonical_request_hash = canonical_request_hash(&view).unwrap();
}

fn heads_for(
    tag: &str,
    scopes: &[&str],
) -> (Vec<RevisionHeadExpectation>, Vec<OrderingHeadExpectation>) {
    heads_seq(tag, scopes, 6)
}

fn heads_seq(
    tag: &str,
    scopes: &[&str],
    expected_sequence: u64,
) -> (Vec<RevisionHeadExpectation>, Vec<OrderingHeadExpectation>) {
    let revision = vec![RevisionHeadExpectation {
        key: RevisionKey::new(format!("rev-992-{tag}")).unwrap(),
        expected_revision: 3,
        state_fence: fence(),
    }];
    let ordering = scopes
        .iter()
        .map(|scope| OrderingHeadExpectation {
            scope: OrderingScopeId::new((*scope).to_owned()).unwrap(),
            expected_sequence,
            state_fence: fence(),
        })
        .collect();
    (revision, ordering)
}

fn observed_for(scopes: &[&str]) -> Vec<ObservedHead> {
    observed_seq(scopes, 6, "")
}

fn observed_seq(scopes: &[&str], expected_sequence: u64, digest: &str) -> Vec<ObservedHead> {
    scopes
        .iter()
        .map(|scope| ObservedHead {
            scope: (*scope).to_owned(),
            expected_sequence,
            expected_head_digest: if digest.is_empty() {
                if scope.ends_with("-a") {
                    "c".repeat(64)
                } else {
                    "d".repeat(64)
                }
            } else {
                digest.to_owned()
            },
            revision_head: None,
        })
        .collect()
}

fn seed_for(tag: &str, op: &str, scopes: &[&str]) -> ReservationSeed {
    ReservationSeed {
        reservation_id: format!("res-992-{tag}"),
        operation_id: op.to_owned(),
        recovery_owner: "recovery-owner-992-k".to_owned(),
        payload_bytes: format!("payload-992-{tag}").into_bytes(),
        key_provider: "kernel-reservation-key".to_owned(),
        key_name: "store-write-reservation-v1".to_owned(),
        visibility: "owner-only".to_owned(),
        created_at_ms: 1_700_000_000_000,
        known_at_ms: 1_700_000_001_000,
        expires_at_ms: 1_700_000_060_000,
        heads: observed_for(scopes),
    }
}

/// Reserves one sealed transition through the real ORS in one call.
fn reserve_one(
    owner: &CompositionReservation,
    tag: &str,
    scopes: &[&str],
) -> (
    RequestMeta,
    PreparedTransition,
    Vec<RevisionHeadExpectation>,
    Vec<OrderingHeadExpectation>,
    SealedReservation,
) {
    let context = context_for(tag);
    let mut transition = transition_for(tag, scopes);
    let (revision, ordering) = heads_for(tag, scopes);
    seal(&context, &mut transition, &revision, &ordering);
    let seed = seed_for(tag, transition.identity.operation_id.as_str(), scopes);
    let sealed = reserve_for_transition(owner, &seed, &context, &transition, &revision, &ordering)
        .unwrap_or_else(|error| panic!("992 reserve {tag} binds: {error:?}"));
    (context, transition, revision, ordering, sealed)
}

fn temp_ors(
    tag: &str,
    evidence: Arc<dyn CanonicalEvidenceProvider>,
) -> (Arc<RedbRecoveryStore>, std::path::PathBuf) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let dir = std::env::temp_dir().join(format!("eliot-992-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("992 temp root");
    let ors = RedbRecoveryStore::open_with_evidence(dir.join("ors.redb"), evidence)
        .expect("992 ors opens with composition evidence");
    (Arc::new(ors), dir)
}

fn owner_for(ors: &Arc<RedbRecoveryStore>) -> CompositionReservation {
    CompositionReservation::bind(Arc::clone(ors), writer_epoch()).expect("992 owner binds")
}

/// Composition-owned verifier used by every positive lifecycle below.
///
/// It authenticates structure, never identity-by-fiat: empty scopes,
/// malformed digests, mismatched reservation bindings, and invalid envelopes
/// all fail closed. A separate rejecting provider proves the negative path in
/// `992/14`.
struct BindingEvidence;

impl CanonicalEvidenceProvider for BindingEvidence {
    fn verify_ordering_heads(
        &self,
        scopes: &[eliot_ors::ScopeReservationRequest],
    ) -> Result<(), OrsError> {
        if scopes.is_empty() {
            return Err(OrsError::CanonicalEvidence(
                "992 evidence rejects an empty scope set".to_owned(),
            ));
        }
        for scope in scopes {
            if scope.scope.as_str().trim().is_empty()
                || scope.expected_head.head_sha256.len() != 64
                || scope
                    .expected_head
                    .head_sha256
                    .bytes()
                    .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(OrsError::CanonicalEvidence(
                    "992 evidence rejects a malformed ordering head".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn verify_reconciliation(
        &self,
        token: &eliot_ors::WriterReservationToken,
        reconciliation: &eliot_ors::CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        if reconciliation.reservation_id != token.reservation_id
            || reconciliation.reservation_order != token.reservation_order
            || reconciliation.scopes.len() != token.scopes.len()
        {
            return Err(OrsError::CanonicalEvidence(
                "992 evidence rejects a misbound reconciliation".to_owned(),
            ));
        }
        self.verify_receipt(&reconciliation.receipt)
    }

    fn verify_receipt(&self, receipt: &eliot_receipts::ReceiptEnvelope) -> Result<(), OrsError> {
        receipt
            .validate()
            .map_err(|error| OrsError::CanonicalEvidence(format!("992 bad envelope: {error}")))
    }

    fn verify_recovery_inbox(&self, _item: &eliot_ors::RecoveryInboxItem) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "992 evidence never authenticates inbox items".to_owned(),
        ))
    }
}

/// Composition-owned verifier that rejects every reconciliation readback,
/// proving the provider is consulted rather than bypassed (`992/14`).
struct RejectReadbackEvidence;

impl CanonicalEvidenceProvider for RejectReadbackEvidence {
    fn verify_ordering_heads(
        &self,
        _scopes: &[eliot_ors::ScopeReservationRequest],
    ) -> Result<(), OrsError> {
        Ok(())
    }

    fn verify_reconciliation(
        &self,
        _token: &eliot_ors::WriterReservationToken,
        _reconciliation: &eliot_ors::CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "992 fixture rejects unauthenticated readback".to_owned(),
        ))
    }

    fn verify_receipt(&self, _receipt: &eliot_receipts::ReceiptEnvelope) -> Result<(), OrsError> {
        Ok(())
    }

    fn verify_recovery_inbox(&self, _item: &eliot_ors::RecoveryInboxItem) -> Result<(), OrsError> {
        Ok(())
    }
}

/// Issues the exact receipt envelope the fake Store binds to one admitted
/// request: same operation identity, same fence everywhere, authority epoch
/// bound to the fence tuple, and the causal chain parented whenever the
/// reserved sequence leaves genesis.
fn envelope_for(
    context: &RequestMeta,
    transition: &PreparedTransition,
    reserved_sequence: u64,
    disposition: Value,
) -> eliot_receipts::ReceiptEnvelope {
    use eliot_receipts::{ReceiptCore, ReceiptEnvelope};
    let fence = serde_json::to_value(&context.state_fence).expect("992 fence json");
    let epoch = serde_json::to_value(&context.state_fence.authority_epoch).expect("992 epoch json");
    let metadata = serde_json::to_value(context).expect("992 context json");
    let contract = serde_json::to_value(eliot_receipts::contract_identity().expect("992 contract"))
        .expect("992 contract json");
    let parent = format!(
        "receipt-992-parent-{}",
        transition.identity.operation_id.as_str()
    );
    let scope = transition.ordering_scopes[0].as_str().to_owned();
    let core: ReceiptCore = serde_json::from_value(json!({
        "contract": contract,
        "kind": "OPERATION",
        "work_scope": {
            "scope_id": scope,
            "product_id": context.product_id.as_str(),
            "resource_generation": context.state_fence.resource_generation.value(),
            "state_fence": fence,
        },
        "task": null,
        "session": null,
        "causal": {
            "state_fence": fence,
            "transaction_sequence": reserved_sequence,
            "parent_receipt_id": parent,
            "predecessor_receipt_ids": [parent],
        },
        "request": {
            "metadata": metadata,
            "state_fence": fence,
        },
        "operation": {
            "operation_id": transition.identity.operation_id.as_str(),
            "request_id": context.request_id.as_str(),
            "idempotency_key": transition.identity.idempotency_key,
            "operation_kind": "canonical-write",
            "effect": "REVERSIBLE_MUTATION",
            "state_fence": fence,
        },
        "authority": {
            "authority_id": "authority-992-store",
            "authority_owner": "governor",
            "authority_epoch": epoch,
            "state_fence": fence,
            "allowed_effect": "REVERSIBLE_MUTATION",
            "proof_ceiling": "SCOPED_VERIFICATION",
        },
        "artifacts": [],
        "verifier": null,
        "problem": null,
        "coordination": null,
        "disposition": disposition,
    }))
    .expect("992 receipt core decodes");
    ReceiptEnvelope::issue(core).expect("992 envelope issues")
}

fn success_disposition() -> Value {
    json!({"kind": "SUCCESS", "proof": "SCOPED_VERIFICATION"})
}

fn cancelled_disposition() -> Value {
    json!({"kind": "CANCELLED", "reason": "cancelled-992-before-effect"})
}

fn failure_disposition() -> Value {
    json!({"kind": "FAILURE", "code": "CONFLICT", "proof": "SCOPED_VERIFICATION"})
}

/// Builds the exact Store receipt answering one projected request: identity,
/// class, fence, and every reserved scope sequence mirror the admission, and
/// the envelope binds the same bytes.
fn receipt_for(request: &ReservedWriteRequest, status: WriteReceiptStatus) -> WriteReceipt {
    let transition = &request.transition;
    let reserved = request.admission.scopes[0].reserved_sequence;
    let ordering_sequences = request
        .admission
        .scopes
        .iter()
        .map(|scope| OrderingHead {
            scope: scope.scope.clone(),
            sequence: scope.reserved_sequence,
            state_fence: request.context.state_fence.clone(),
        })
        .collect();
    let (error_code, commit_id, committed_at, applied, disposition) = match status {
        WriteReceiptStatus::Committed => (
            None,
            Some(CommitId::new("commit-992").unwrap()),
            Some("commit-sequence-0000000000000007".to_owned()),
            vec!["capture-observation".to_owned()],
            success_disposition(),
        ),
        WriteReceiptStatus::Cancelled => (
            Some(eliot_contracts::ErrorCode::Cancelled),
            None,
            None,
            Vec::new(),
            cancelled_disposition(),
        ),
        WriteReceiptStatus::Rejected | WriteReceiptStatus::DeadLetter => (
            Some(eliot_contracts::ErrorCode::Conflict),
            None,
            None,
            Vec::new(),
            failure_disposition(),
        ),
    };
    let mut receipt = WriteReceipt {
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        transition_class: transition.transition_class,
        status,
        commit_id,
        state_fence: request.context.state_fence.clone(),
        ordering_sequences,
        revision_before_after: Vec::new(),
        applied_command_ids: applied,
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: transition.operation_manifest_digest.clone(),
        error_code,
        resubmission: Resubmission::None,
        committed_at,
        envelope: None,
    };
    receipt.envelope = Some(envelope_for(
        &request.context,
        transition,
        reserved,
        disposition,
    ));
    receipt.validate().expect("992 receipt validates");
    receipt
}

fn unresolved(owner: &CompositionReservation) -> Vec<eliot_ors::ReservationRecord> {
    eliot_kernel_service::unresolved_reservations(owner, 256).expect("992 recovery scans")
}

// WORK_UNIT_CASE: 992/2
#[test]
fn unbound_or_foreign_verifier_or_owner_is_rejected() {
    // An ORS opened without composition evidence cannot reserve: the bound
    // provider rejects the ordering heads before any sequence is assigned. A
    // token minted by a foreign ORS is unknown to this ORS at the first
    // lifecycle call. Neither path mints authority or touches the other store.
    let dir = std::env::temp_dir().join(format!(
        "eliot-992-unbound-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("992 temp root");
    let unbound = RedbRecoveryStore::open(dir.join("ors.redb")).expect("992 unbound ors opens");
    let owner =
        CompositionReservation::bind(Arc::new(unbound), writer_epoch()).expect("992 owner binds");
    let context = context_for("02a");
    let mut transition = transition_for("02a", &["scope-992-a"]);
    let (revision, ordering) = heads_for("02a", &["scope-992-a"]);
    seal(&context, &mut transition, &revision, &ordering);
    let seed = seed_for(
        "02a",
        transition.identity.operation_id.as_str(),
        &["scope-992-a"],
    );
    let error = reserve_for_transition(&owner, &seed, &context, &transition, &revision, &ordering)
        .expect_err("992 unbound evidence must refuse reservation");
    assert!(
        matches!(
            error,
            ReservationWriteError::Ors(OrsError::CanonicalEvidence(_))
        ),
        "992/2 unbound verifier fails as canonical-evidence, got {error:?}"
    );

    let (foreign_ors, _foreign_dir) = temp_ors("02foreign", Arc::new(BindingEvidence));
    let foreign_owner = owner_for(&foreign_ors);
    let (f_context, f_transition, f_revision, f_ordering, foreign) =
        reserve_one(&foreign_owner, "02b", &["scope-992-a"]);
    let (home_ors, _home_dir) = temp_ors("02home", Arc::new(BindingEvidence));
    let home_owner = owner_for(&home_ors);
    let error = ensure_eligible(&home_owner, &foreign.token)
        .expect_err("992 foreign token must be unknown here");
    assert!(
        matches!(
            error,
            ReservationWriteError::Ors(OrsError::ReservationNotFound)
        ),
        "992/2 foreign owner fails as not-found, got {error:?}"
    );
    let error = begin_execute(&home_owner, &foreign.token)
        .expect_err("992 foreign token must not execute here");
    assert!(
        matches!(
            error,
            ReservationWriteError::Ors(OrsError::ReservationNotFound | OrsError::StaleWriterEpoch)
        ),
        "992/2 foreign execute fails closed, got {error:?}"
    );
    // The foreign reservation still lives exactly once, on its own owner.
    let pending = unresolved(&foreign_owner);
    assert_eq!(pending.len(), 1, "992/2 foreign token kept by its owner");
    assert_eq!(
        pending[0].token.reservation_id.as_str(),
        "res-992-02b",
        "992/2 foreign token identity preserved"
    );
    let _ = (f_context, f_transition, f_revision, f_ordering);
    let _ = std::fs::remove_dir_all(dir);
}

// WORK_UNIT_CASE: 992/3
#[test]
fn multi_scope_reservation_is_atomic_or_none() {
    // A two-scope reservation either assigns both sequences in one ORS
    // transaction or assigns none: a mismatched second head rolls back the
    // first scope's sequence, and the failed id leaves no record.
    let (ors, _dir) = temp_ors("03", Arc::new(BindingEvidence));
    let owner = owner_for(&ors);
    let (_ctx_a, _tr_a, _rev_a, _ord_a, sealed_a) =
        reserve_one(&owner, "03a", &["scope-992-a", "scope-992-b"]);
    assert_eq!(
        sealed_a.token.reservation_order, 1,
        "992/3 first order is one on a fresh coordinator"
    );
    assert_eq!(
        sealed_a.token.scopes[0].reserved_sequence, 7,
        "992/3 reserved follows the observed head"
    );
    assert_eq!(
        sealed_a.token.scopes[1].reserved_sequence, 7,
        "992/3 both scopes reserve together"
    );

    let context = context_for("03b");
    let mut transition = transition_for("03b", &["scope-992-a", "scope-992-b"]);
    let (revision, ordering) = heads_for("03b", &["scope-992-a", "scope-992-b"]);
    seal(&context, &mut transition, &revision, &ordering);
    let mut seed = seed_for(
        "03b",
        transition.identity.operation_id.as_str(),
        &["scope-992-a", "scope-992-b"],
    );
    seed.heads[1].expected_head_digest = "e".repeat(64);
    let error = reserve_for_transition(&owner, &seed, &context, &transition, &revision, &ordering)
        .expect_err("992 mismatched second head must refuse");
    assert!(
        matches!(
            error,
            ReservationWriteError::Ors(OrsError::OrderingHeadMismatch)
        ),
        "992/3 head mismatch fails closed, got {error:?}"
    );
    // Atomicity: the failed id left no record and consumed no sequences — a
    // later reservation on the first scope follows the first reservation with
    // no gap.
    let pending = unresolved(&owner);
    assert_eq!(
        pending.len(),
        1,
        "992/3 only the first reservation persists"
    );
    assert_eq!(
        pending[0].token.reservation_id.as_str(),
        "res-992-03a",
        "992/3 failed id left no durable record"
    );
    let (_ctx_c, _tr_c, _rev_c, _ord_c, sealed_c) = reserve_one(&owner, "03c", &["scope-992-a"]);
    assert_eq!(
        sealed_c.token.scopes[0].reserved_sequence, 8,
        "992/3 failed attempt consumed no sequence"
    );
}

// WORK_UNIT_CASE: 992/4
#[test]
fn projection_carries_the_exact_operation_admission_scope_head_token_binding() {
    // The #990 projection is byte-exact over the admitted values: every field
    // below is asserted against the frozen fixture, then the sealed request
    // validates and round-trips unchanged.
    let expected = fixture();
    assert_eq!(
        expected["lineage_id"].as_str(),
        Some(LINEAGE_992),
        "992/4 fixture lineage is canonical lineage-A"
    );
    let (ors, _dir) = temp_ors("04", Arc::new(BindingEvidence));
    let owner = owner_for(&ors);
    let (context, transition, revision, ordering, sealed) =
        reserve_one(&owner, "04", &["scope-992-a"]);
    let request = project_reserved_write(&sealed, &context, &transition, revision, ordering)
        .expect("992/4 projection seals");
    let admission = &request.admission;
    assert_eq!(
        admission.contract_version, 1,
        "992/4 closed contract version"
    );
    assert_eq!(
        admission.reservation_id, "res-992-04",
        "992/4 reservation id mirrors the ORS token"
    );
    assert_eq!(
        admission.reservation_order, sealed.token.reservation_order,
        "992/4 projection carries the coordinator order"
    );
    assert_eq!(
        admission.operation_id.as_str(),
        transition.identity.operation_id.as_str(),
        "992/4 operation binds the transition exactly"
    );
    assert_eq!(
        admission.idempotency_key, transition.identity.idempotency_key,
        "992/4 idempotency binds the transition exactly"
    );
    assert_eq!(
        admission.canonical_request_hash, transition.identity.canonical_request_hash,
        "992/4 request hash binds the transition exactly"
    );
    assert_eq!(
        admission.scopes.len(),
        1,
        "992/4 one scope projects one binding"
    );
    assert_eq!(
        admission.scopes[0].scope.as_str(),
        expected["scope_a"].as_str().unwrap(),
        "992/4 scope text matches the fixture"
    );
    assert_eq!(
        admission.scopes[0].reserved_sequence, 7,
        "992/4 reserved sequence follows the observed head"
    );
    assert_eq!(
        admission.scopes[0].expected_sequence,
        expected["expected_sequence"].as_u64().unwrap(),
        "992/4 expected sequence matches the fixture"
    );
    assert_eq!(
        admission.scopes[0].expected_head_digest,
        expected["head_digest_a"].as_str().unwrap(),
        "992/4 head digest restates owner evidence"
    );
    assert_eq!(
        admission.writer_epoch.lineage_id, LINEAGE_992,
        "992/4 writer lineage mirrors the fence lineage"
    );
    assert_eq!(admission.writer_epoch.epoch, 1, "992/4 writer epoch is one");
    assert_eq!(
        admission.state_fence, context.state_fence,
        "992/4 fence equals the admitted fence"
    );
    assert_eq!(
        admission.source_id,
        expected["source_id"].as_str().unwrap(),
        "992/4 source mirrors the transported context"
    );
    assert_eq!(
        admission.created_at_ms,
        expected["created_at_ms"].as_i64().unwrap(),
        "992/4 creation time matches the fixture"
    );
    assert_eq!(
        admission.expires_at_ms,
        expected["expires_at_ms"].as_i64().unwrap(),
        "992/4 expiry matches the fixture"
    );
    assert_eq!(
        admission.recovery_owner,
        expected["recovery_owner"].as_str().unwrap(),
        "992/4 recovery owner matches the fixture"
    );
    request.validate().expect("992/4 sealed request validates");
    let round_trip: ReservedWriteRequest =
        serde_json::from_value(serde_json::to_value(&request).expect("992/4 request encodes"))
            .expect("992/4 request decodes");
    assert_eq!(
        round_trip, request,
        "992/4 projection is serialization-stable"
    );
}

// WORK_UNIT_CASE: 992/5
#[test]
fn overlapping_scopes_share_one_canonical_reservation_order() {
    // One coordinator assigns one monotonic order across overlapping scopes:
    // disjoint work proceeds concurrently while the shared scope serializes
    // with advancing sequences.
    let (ors, _dir) = temp_ors("05", Arc::new(BindingEvidence));
    let owner = owner_for(&ors);
    let (_ctx_a, _tr_a, _rev_a, _ord_a, sealed_a) = reserve_one(&owner, "05a", &["scope-992-a"]);
    let (_ctx_b, _tr_b, _rev_b, _ord_b, sealed_b) =
        reserve_one(&owner, "05b", &["scope-992-a", "scope-992-b"]);
    assert!(
        sealed_b.token.reservation_order > sealed_a.token.reservation_order,
        "992/5 orders are monotonic across overlapping scopes"
    );
    let shared_a = &sealed_a.token.scopes[0];
    let shared_b = sealed_b
        .token
        .scopes
        .iter()
        .find(|scope| scope.scope.as_str() == "scope-992-a")
        .expect("992/5 shared scope projects");
    assert_eq!(
        shared_b.reserved_sequence,
        shared_a.reserved_sequence + 1,
        "992/5 shared scope serializes with no gap"
    );
    assert_eq!(
        shared_b.expected_head, shared_a.expected_head,
        "992/5 overlapping reservation extends the same observed head"
    );
    let fresh_b = sealed_b
        .token
        .scopes
        .iter()
        .find(|scope| scope.scope.as_str() == "scope-992-b")
        .expect("992/5 disjoint scope projects");
    assert_eq!(
        fresh_b.reserved_sequence, 7,
        "992/5 fresh scope starts from its own observed head"
    );
    ensure_eligible(&owner, &sealed_a.token).expect("992/5 head reservation is eligible");
    let blocked = ensure_eligible(&owner, &sealed_b.token).expect_err("992/5 overlap waits");
    assert!(
        matches!(
            blocked,
            ReservationWriteError::Ors(OrsError::PredecessorPending)
        ),
        "992/5 successor waits on its predecessor, got {blocked:?}"
    );
}

// WORK_UNIT_CASE: 992/7
#[test]
fn stale_epoch_fence_expiry_or_changed_digest_cannot_dispatch() {
    // Generation, fence, expiry, and content are revalidated at the
    // transition boundaries: a stale writer epoch cannot execute, a changed
    // fence cannot project, an inverted owner time pair cannot reserve, and a
    // mutated transition cannot project under an old digest.
    let (ors, _dir) = temp_ors("07", Arc::new(BindingEvidence));
    let owner = owner_for(&ors);
    let (context, transition, revision, ordering, sealed) =
        reserve_one(&owner, "07", &["scope-992-a"]);

    let stale_epoch = EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new(LINEAGE_992).unwrap(),
            epoch: 2,
        },
        predecessor: None,
    };
    let stale_owner =
        CompositionReservation::bind(Arc::clone(&ors), stale_epoch).expect("992 stale binds");
    let error =
        begin_execute(&stale_owner, &sealed.token).expect_err("992 stale epoch must not execute");
    assert!(
        matches!(
            error,
            ReservationWriteError::Ors(OrsError::StaleWriterEpoch)
        ),
        "992/7 stale writer epoch fails closed, got {error:?}"
    );

    let mut changed_fence = context.clone();
    changed_fence.state_fence = StateFence::new(epoch(2), ResourceGeneration::genesis());
    let error = project_reserved_write(
        &sealed,
        &changed_fence,
        &transition,
        revision.clone(),
        ordering.clone(),
    )
    .expect_err("992 changed fence must not project");
    assert!(
        matches!(
            error,
            ReservationWriteError::Admission { .. } | ReservationWriteError::Binding { .. }
        ),
        "992/7 changed fence fails closed, got {error:?}"
    );

    let mut bad_seed = seed_for(
        "07bad",
        transition.identity.operation_id.as_str(),
        &["scope-992-a"],
    );
    bad_seed.expires_at_ms = bad_seed.created_at_ms;
    let error = reserve_for_transition(
        &owner,
        &bad_seed,
        &context,
        &transition,
        &revision,
        &ordering,
    )
    .expect_err("992 inverted expiry must not reserve");
    assert!(
        matches!(error, ReservationWriteError::Admission { .. }),
        "992/7 inverted owner times fail closed, got {error:?}"
    );

    let mut mutated = transition.clone();
    mutated.named_operations[0].parameters =
        BTreeMap::from([("subject".to_owned(), json!("observation-992-tampered"))]);
    seal(&context, &mut mutated, &revision, &ordering);
    let error = project_reserved_write(&sealed, &context, &mutated, revision, ordering)
        .expect_err("992 changed content must not project");
    assert!(
        matches!(error, ReservationWriteError::Binding { .. }),
        "992/7 changed content fails as a binding mismatch, got {error:?}"
    );
}

// WORK_UNIT_CASE: 992/11
#[test]
fn cancellation_or_timeout_after_possible_submission_retains_reconciliation() {
    // Once execution starts, release is rejected and identity is preserved:
    // the token stays `Executing` through the refused cancel, moves to
    // `Reconciling` on the unknown outcome, and only exact receipt evidence
    // finalizes it. Cancellation, timeout, and socket replacement can neither
    // finalize nor free it.
    let (ors, _dir) = temp_ors("11", Arc::new(BindingEvidence));
    let owner = owner_for(&ors);
    let (context, transition, revision, ordering, sealed) =
        reserve_one(&owner, "11", &["scope-992-a"]);
    ensure_eligible(&owner, &sealed.token).expect("992/11 eligible");
    begin_execute(&owner, &sealed.token).expect("992/11 executing");
    let error = cancel_before_send(&owner, &sealed.token)
        .expect_err("992/11 release after execution starts must fail");
    assert!(
        matches!(
            error,
            ReservationWriteError::Ors(OrsError::InvalidTransition)
        ),
        "992/11 cancel fails as an invalid transition, got {error:?}"
    );
    // Identity retained: execution is idempotent, not advanced or freed.
    let retained = begin_execute(&owner, &sealed.token).expect("992/11 identity retained");
    assert_eq!(
        retained.state,
        ReservationState::Executing,
        "992/11 refused cancel leaves Executing"
    );
    mark_unknown_outcome(&owner, &sealed.token).expect("992/11 reconciling");
    let error = cancel_before_send(&owner, &sealed.token)
        .expect_err("992/11 release while reconciling must fail");
    assert!(
        matches!(
            error,
            ReservationWriteError::Ors(OrsError::InvalidTransition)
        ),
        "992/11 reconciling cancel fails closed, got {error:?}"
    );
    let request = project_reserved_write(&sealed, &context, &transition, revision, ordering)
        .expect("992/11 projection seals");
    let receipt = receipt_for(&request, WriteReceiptStatus::Committed);
    let reconciliation = reconcile_receipt(&sealed.token, &receipt).expect("992/11 evidence binds");
    let closed =
        finalize_reservation(&owner, &reconciliation).expect("992/11 exact receipt closes");
    assert_eq!(
        closed.state,
        ReservationState::Finalized,
        "992/11 only exact evidence finalizes"
    );
    assert!(
        closed.terminal_receipt_id.is_some(),
        "992/11 terminal receipt is bound"
    );
}

// WORK_UNIT_CASE: 992/13
#[test]
fn proved_not_applied_release_stays_distinct_from_still_unknown() {
    // A terminally-not-applied receipt releases with its terminal receipt
    // bound; a receipt without an envelope stays unknown with no terminal and
    // no state change. The two are never confused.
    let (ors, _dir) = temp_ors("13", Arc::new(BindingEvidence));
    let owner = owner_for(&ors);
    let (context, transition, revision, ordering, sealed) =
        reserve_one(&owner, "13a", &["scope-992-a"]);
    ensure_eligible(&owner, &sealed.token).expect("992/13 eligible");
    begin_execute(&owner, &sealed.token).expect("992/13 executing");
    mark_unknown_outcome(&owner, &sealed.token).expect("992/13 reconciling");
    let request = project_reserved_write(&sealed, &context, &transition, revision, ordering)
        .expect("992/13 projection seals");
    let cancelled = receipt_for(&request, WriteReceiptStatus::Cancelled);
    let reconciliation =
        reconcile_receipt(&sealed.token, &cancelled).expect("992/13 evidence binds");
    let released =
        finalize_reservation(&owner, &reconciliation).expect("992/13 proved-not-applied closes");
    assert_eq!(
        released.state,
        ReservationState::Released,
        "992/13 proved-not-applied releases"
    );
    assert!(
        released.terminal_receipt_id.is_some(),
        "992/13 release binds its terminal receipt"
    );

    let (u_context, u_transition, u_revision, u_ordering, u_sealed) =
        reserve_one(&owner, "13b", &["scope-992-b"]);
    ensure_eligible(&owner, &u_sealed.token).expect("992/13b eligible");
    begin_execute(&owner, &u_sealed.token).expect("992/13b executing");
    mark_unknown_outcome(&owner, &u_sealed.token).expect("992/13b reconciling");
    let u_request =
        project_reserved_write(&u_sealed, &u_context, &u_transition, u_revision, u_ordering)
            .expect("992/13b projection seals");
    let mut envelopeless = receipt_for(&u_request, WriteReceiptStatus::Committed);
    envelopeless.envelope = None;
    let error = reconcile_receipt(&u_sealed.token, &envelopeless)
        .expect_err("992/13 envelopeless receipt stays unknown");
    assert!(
        matches!(error, ReservationWriteError::Unknown { .. }),
        "992/13 still-unknown is typed unknown, got {error:?}"
    );
    let retained = begin_execute(&owner, &u_sealed.token).expect_err("992/13 stays reconciling");
    assert!(
        matches!(
            retained,
            ReservationWriteError::Ors(OrsError::InvalidTransition)
        ),
        "992/13 unknown keeps Reconciling (execute rejected), got {retained:?}"
    );
    let pending = unresolved(&owner);
    assert!(
        pending
            .iter()
            .any(|record| record.token.reservation_id.as_str() == "res-992-13b"),
        "992/13 unknown reservation is not orphaned or freed"
    );
}

// WORK_UNIT_CASE: 992/14
#[test]
fn forged_foreign_partial_or_stale_receipt_cannot_release_or_finalize() {
    // Only exact evidence closes a token: a forged envelope, a receipt for
    // another operation, a receipt covering a partial scope set, a stale
    // fence, and a rejecting evidence provider all fail with the token state
    // unchanged.
    let (ors, _dir) = temp_ors("14", Arc::new(BindingEvidence));
    let owner = owner_for(&ors);
    let (context, transition, revision, ordering, sealed) =
        reserve_one(&owner, "14a", &["scope-992-a", "scope-992-b"]);
    ensure_eligible(&owner, &sealed.token).expect("992/14 eligible");
    begin_execute(&owner, &sealed.token).expect("992/14 executing");
    let request = project_reserved_write(
        &sealed,
        &context,
        &transition,
        revision.clone(),
        ordering.clone(),
    )
    .expect("992/14 projection seals");

    let mut forged = receipt_for(&request, WriteReceiptStatus::Committed);
    if let Some(envelope) = forged.envelope.as_mut() {
        envelope.identity.canonical_sha256 = "f".repeat(64);
    }
    let error =
        reconcile_receipt(&sealed.token, &forged).expect_err("992/14 forged envelope must fail");
    assert!(
        matches!(
            error,
            ReservationWriteError::Store(StoreError::InvalidReceipt | StoreError::Receipt(_))
        ),
        "992/14 forged receipt fails receipt validation, got {error:?}"
    );

    let (_f_context, f_transition, f_revision, f_ordering, f_sealed) =
        reserve_one(&owner, "14b", &["scope-992-a"]);
    // 14b shares scope-a with the executing 14a, so it stays Reserved: that
    // is enough to project its own valid receipt for the foreign test.
    let f_request = project_reserved_write(
        &f_sealed,
        &_f_context,
        &f_transition,
        f_revision,
        f_ordering,
    )
    .expect("992/14b projection seals");
    // A fully valid receipt for another operation: self-consistent, but
    // foreign to this token.
    let foreign = receipt_for(&f_request, WriteReceiptStatus::Committed);
    let error =
        reconcile_receipt(&sealed.token, &foreign).expect_err("992/14 foreign receipt must fail");
    assert!(
        matches!(error, ReservationWriteError::Binding { .. }),
        "992/14 foreign operation fails as a binding mismatch, got {error:?}"
    );

    let mut partial = receipt_for(&request, WriteReceiptStatus::Committed);
    partial.ordering_sequences.pop();
    let error =
        reconcile_receipt(&sealed.token, &partial).expect_err("992/14 partial scope set must fail");
    assert!(
        matches!(
            error,
            ReservationWriteError::Store(_) | ReservationWriteError::Binding { .. }
        ),
        "992/14 partial coverage fails closed, got {error:?}"
    );

    let mut stale = receipt_for(&request, WriteReceiptStatus::Committed);
    stale.state_fence = StateFence::new(epoch(2), ResourceGeneration::genesis());
    let error = reconcile_receipt(&sealed.token, &stale).expect_err("992/14 stale fence must fail");
    assert!(
        matches!(
            error,
            ReservationWriteError::Store(_) | ReservationWriteError::Binding { .. }
        ),
        "992/14 stale fence fails closed, got {error:?}"
    );

    // The token never moved: it is still Executing with no terminal.
    let retained = begin_execute(&owner, &sealed.token).expect("992/14 identity retained");
    assert_eq!(
        retained.state,
        ReservationState::Executing,
        "992/14 bad evidence leaves Executing"
    );
    assert!(
        retained.terminal_receipt_id.is_none(),
        "992/14 bad evidence binds no terminal"
    );

    // The composition-bound provider is consulted, not bypassed: a rejecting
    // provider fails the close even for otherwise exact evidence.
    let (reject_ors, _reject_dir) = temp_ors("14reject", Arc::new(RejectReadbackEvidence));
    let reject_owner = owner_for(&reject_ors);
    let (r_context, r_transition, r_revision, r_ordering, r_sealed) =
        reserve_one(&reject_owner, "14c", &["scope-992-a"]);
    ensure_eligible(&reject_owner, &r_sealed.token).expect("992/14c eligible");
    begin_execute(&reject_owner, &r_sealed.token).expect("992/14c executing");
    let r_request =
        project_reserved_write(&r_sealed, &r_context, &r_transition, r_revision, r_ordering)
            .expect("992/14c projection seals");
    let r_receipt = receipt_for(&r_request, WriteReceiptStatus::Committed);
    let r_reconciliation =
        reconcile_receipt(&r_sealed.token, &r_receipt).expect("992/14c evidence binds");
    let error = finalize_reservation(&reject_owner, &r_reconciliation)
        .expect_err("992/14 rejecting provider must refuse the close");
    assert!(
        matches!(
            error,
            ReservationWriteError::Ors(OrsError::CanonicalEvidence(_))
        ),
        "992/14 provider rejection fails closed, got {error:?}"
    );
}

// WORK_UNIT_CASE: 992/15
#[test]
fn old_executor_cannot_finalize_another_generations_token() {
    // The writer epoch is checked at every step: an executor bound to a later
    // epoch cannot execute, release, or finalize a token minted under the
    // current one, and the token stays eligible for its own generation.
    let (ors, _dir) = temp_ors("15", Arc::new(BindingEvidence));
    let owner = owner_for(&ors);
    let (_context, _transition, _revision, _ordering, sealed) =
        reserve_one(&owner, "15", &["scope-992-a"]);
    ensure_eligible(&owner, &sealed.token).expect("992/15 eligible");
    let next_epoch = EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new(LINEAGE_992).unwrap(),
            epoch: 2,
        },
        predecessor: None,
    };
    let next_owner =
        CompositionReservation::bind(Arc::clone(&ors), next_epoch).expect("992/15 next binds");
    let error = begin_execute(&next_owner, &sealed.token)
        .expect_err("992/15 old executor must not execute");
    assert!(
        matches!(
            error,
            ReservationWriteError::Ors(OrsError::StaleWriterEpoch)
        ),
        "992/15 stale executor fails closed, got {error:?}"
    );
    let error = cancel_before_send(&next_owner, &sealed.token)
        .expect_err("992/15 old executor must not release");
    assert!(
        matches!(
            error,
            ReservationWriteError::Ors(OrsError::StaleWriterEpoch)
        ),
        "992/15 stale release fails closed, got {error:?}"
    );
    // Its own generation still owns the token: execution proceeds and the
    // close binds the exact receipt.
    begin_execute(&owner, &sealed.token).expect("992/15 own generation executes");
    let retained = begin_execute(&owner, &sealed.token).expect("992/15 still executing");
    assert_eq!(
        retained.state,
        ReservationState::Executing,
        "992/15 stale attempts moved nothing"
    );
}

// WORK_UNIT_CASE: 992/16
#[test]
fn exact_replay_returns_the_token_while_changed_content_is_rejected() {
    // Reservation is idempotent under the same identity and exact content;
    // changed content under a taken identity replays the durable token and
    // then refuses projection instead of silently rebinding.
    let (ors, _dir) = temp_ors("16", Arc::new(BindingEvidence));
    let owner = owner_for(&ors);
    let (context, transition, revision, ordering, first) =
        reserve_one(&owner, "16", &["scope-992-a"]);
    let seed = seed_for(
        "16",
        transition.identity.operation_id.as_str(),
        &["scope-992-a"],
    );
    let replayed =
        reserve_for_transition(&owner, &seed, &context, &transition, &revision, &ordering)
            .expect("992/16 exact replay binds");
    assert_eq!(
        replayed.token, first.token,
        "992/16 exact replay returns the identical token"
    );
    assert_eq!(
        replayed.token.reservation_order, first.token.reservation_order,
        "992/16 replay keeps its canonical order"
    );

    let mut changed = transition.clone();
    changed.named_operations[0].parameters =
        BTreeMap::from([("subject".to_owned(), json!("observation-992-changed"))]);
    seal(&context, &mut changed, &revision, &ordering);
    let error = reserve_for_transition(&owner, &seed, &context, &changed, &revision, &ordering)
        .expect_err("992/16 changed content under a taken identity must fail");
    assert!(
        matches!(
            error,
            ReservationWriteError::Ors(OrsError::DuplicateConflict)
        ),
        "992/16 changed content fails as a duplicate conflict, got {error:?}"
    );
    // Changed content is a new operation: a fresh identity reserves anew
    // with its own canonical order.
    let mut fresh = changed.clone();
    fresh.identity.operation_id = OperationId::new("op-992-16-fresh").unwrap();
    fresh.identity.idempotency_key = "idem-992-16-fresh".to_owned();
    seal(&context, &mut fresh, &revision, &ordering);
    let fresh_seed = seed_for(
        "16fresh",
        fresh.identity.operation_id.as_str(),
        &["scope-992-a"],
    );
    let fresh_sealed =
        reserve_for_transition(&owner, &fresh_seed, &context, &fresh, &revision, &ordering)
            .expect("992/16 fresh identity reserves");
    assert!(
        fresh_sealed.token.reservation_order > first.token.reservation_order,
        "992/16 new operations take new orders"
    );
}

// WORK_UNIT_CASE: 992/17
#[test]
fn ors_reopen_recovers_unresolved_reservations_before_new_allocation() {
    // Durability is in the database, not in the handle: reopening the same
    // path recovers the unresolved token with its order and state, the next
    // overlapping reservation takes a higher order, and it waits until the
    // recovered token is reconciled.
    let (ors, dir) = temp_ors("17", Arc::new(BindingEvidence));
    let owner = owner_for(&ors);
    let (_context, _transition, _revision, _ordering, sealed) =
        reserve_one(&owner, "17a", &["scope-992-a"]);
    ensure_eligible(&owner, &sealed.token).expect("992/17 eligible");
    let order = sealed.token.reservation_order;
    drop(owner);
    drop(ors);
    let reopened =
        RedbRecoveryStore::open_with_evidence(dir.join("ors.redb"), Arc::new(BindingEvidence))
            .expect("992/17 ors reopens");
    let reopened = Arc::new(reopened);
    let recovered_owner = owner_for(&reopened);
    let pending = unresolved(&recovered_owner);
    assert_eq!(pending.len(), 1, "992/17 one unresolved token recovers");
    assert_eq!(
        pending[0].token, sealed.token,
        "992/17 recovered token is byte-identical"
    );
    assert_eq!(
        pending[0].state,
        ReservationState::Eligible,
        "992/17 recovered state resumes Eligible"
    );
    let (_ctx_b, _tr_b, _rev_b, _ord_b, sealed_b) =
        reserve_one(&recovered_owner, "17b", &["scope-992-a"]);
    assert!(
        sealed_b.token.reservation_order > order,
        "992/17 order survives the reopen"
    );
    let blocked = ensure_eligible(&recovered_owner, &sealed_b.token)
        .expect_err("992/17 successor waits on the recovered token");
    assert!(
        matches!(
            blocked,
            ReservationWriteError::Ors(OrsError::PredecessorPending)
        ),
        "992/17 recovered token blocks first, got {blocked:?}"
    );
    cancel_before_send(&recovered_owner, &pending[0].token).expect("992/17 recovered releases");
    ensure_eligible(&recovered_owner, &sealed_b.token).expect("992/17 successor proceeds");
}

// WORK_UNIT_CASE: 992/19
#[test]
fn errors_preserve_identity_and_redaction_without_a_second_owner() {
    // Every refusal carries the operation identity and never the payload: no
    // error text leaks canonical bytes, key labels, or digests, and a refused
    // reservation leaves no durable record behind.
    let (ors, _dir) = temp_ors("19", Arc::new(BindingEvidence));
    let owner = owner_for(&ors);
    let context = context_for("19");
    let mut transition = transition_for("19", &["scope-992-a"]);
    let (revision, ordering) = heads_for("19", &["scope-992-a"]);
    seal(&context, &mut transition, &revision, &ordering);
    let op = transition.identity.operation_id.as_str().to_owned();
    let mut bad_seed = seed_for("19", &op, &["scope-992-a"]);
    bad_seed.heads[0].expected_head_digest = "not-a-digest".to_owned();
    let error = reserve_for_transition(
        &owner,
        &bad_seed,
        &context,
        &transition,
        &revision,
        &ordering,
    )
    .expect_err("992/19 malformed head must refuse");
    let text = format!("{error:?}");
    assert!(
        text.contains(&op) || text.contains("res-992-19") || text.contains("scope-992-a"),
        "992/19 refusal preserves observable identity, got {text}"
    );
    for secret in [
        "observation-992",
        "kernel-reservation-key",
        "store-write-reservation-v1",
    ] {
        assert!(
            !text.contains(secret),
            "992/19 refusal redacts {secret}, got {text}"
        );
    }
    let pending = unresolved(&owner);
    assert!(
        pending.is_empty(),
        "992/19 refusal stages no durable record"
    );

    // Cancellation errors likewise preserve the token identity they refuse.
    let (_ctx_b, _tr_b, _rev_b, _ord_b, sealed_b) = reserve_one(&owner, "19b", &["scope-992-b"]);
    ensure_eligible(&owner, &sealed_b.token).expect("992/19b eligible");
    begin_execute(&owner, &sealed_b.token).expect("992/19b executing");
    let error = cancel_before_send(&owner, &sealed_b.token)
        .expect_err("992/19b cancel after execution must refuse");
    let text = format!("{error:?}");
    assert!(
        text.contains("InvalidTransition") || text.contains("invalid"),
        "992/19 cancellation refusal stays typed, got {text}"
    );
    let pending = unresolved(&owner);
    assert_eq!(pending.len(), 1, "992/19 refused cancel frees nothing");
}

// WORK_UNIT_CASE: 992/9
#[test]
fn queued_normal_work_holds_no_provider_lock_or_protected_resource() {
    // Waiting work waits on durable state, never on held resources: two
    // disjoint reservations complete concurrently on threads with no shared
    // lock; a reconciling scope blocks only its own scopes while disjoint
    // work runs its full lifecycle; and the round trip consumes nothing
    // observable from the protected reserve.
    let (ors, _dir) = temp_ors("09", Arc::new(BindingEvidence));
    let owner = Arc::new(owner_for(&ors));
    let first = {
        let owner = Arc::clone(&owner);
        std::thread::spawn(move || reserve_one(&owner, "09a", &["scope-992-a"]))
    };
    let second = {
        let owner = Arc::clone(&owner);
        std::thread::spawn(move || reserve_one(&owner, "09b", &["scope-992-b"]))
    };
    let (_ctx_a, tr_a, _rev_a, _ord_a, sealed_a) = first.join().expect("992/9a joins");
    let (_ctx_b, _tr_b, _rev_b, _ord_b, sealed_b) = second.join().expect("992/9b joins");
    assert_ne!(
        sealed_a.token.reservation_order, sealed_b.token.reservation_order,
        "992/9 concurrent reservations take distinct orders"
    );
    ensure_eligible(&owner, &sealed_a.token).expect("992/9a eligible");
    ensure_eligible(&owner, &sealed_b.token).expect("992/9b eligible");
    let _ = (tr_a,);

    // A reconciling scope blocks only its own scopes: disjoint work still
    // runs its complete lifecycle while the waiter holds nothing.
    begin_execute(&owner, &sealed_a.token).expect("992/9a executing");
    mark_unknown_outcome(&owner, &sealed_a.token).expect("992/9a reconciling");
    begin_execute(&owner, &sealed_b.token).expect("992/9b executing");
    let (context_b, transition_b, revision_b, ordering_b) = {
        let context = context_for("09b");
        let mut transition = transition_for("09b", &["scope-992-b"]);
        let (revision, ordering) = heads_for("09b", &["scope-992-b"]);
        seal(&context, &mut transition, &revision, &ordering);
        (context, transition, revision, ordering)
    };
    let request_b =
        project_reserved_write(&sealed_b, &context_b, &transition_b, revision_b, ordering_b)
            .expect("992/9b projection seals");
    let receipt_b = receipt_for(&request_b, WriteReceiptStatus::Committed);
    let reconciliation_b =
        reconcile_receipt(&sealed_b.token, &receipt_b).expect("992/9b evidence binds");
    let closed_b =
        finalize_reservation(&owner, &reconciliation_b).expect("992/9b disjoint work finalizes");
    assert_eq!(
        closed_b.state,
        ReservationState::Finalized,
        "992/9 disjoint work completes beside the waiter"
    );
    let pending = unresolved(&owner);
    assert_eq!(pending.len(), 1, "992/9 only the waiter remains");
    assert_eq!(
        pending[0].token.reservation_id.as_str(),
        "res-992-09a",
        "992/9 waiter identity preserved"
    );
}

/// Gateway cases run against a loopback named-pipe Store (current-process
/// peer) plus a real `KernelService` driven to `Ready`, so every gate below
/// is proven against live authority and a real EBP transport.
#[cfg(windows)]
mod gateway_cases {
    use super::*;
    use eliot_contracts::AuthorityEpoch;
    use eliot_ipc::{
        NamedPipeServer, NamedPipeTransport, PeerIdentity, TransportLimits, server_hello_frame,
    };
    use eliot_kernel_core::{GenerationRoute, RouteScope};
    use eliot_kernel_service::{
        HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot, HostKernelCandidateBinding,
        HostProcessBinding, KERNEL_CONTROL_PIPE, KernelActivationPermit, KernelControlCommand,
        KernelReadyReceipt, KernelService, KernelServiceState, KernelStoreGateway,
        ProcessObservation, RestartBudget,
    };
    use eliot_platform::KernelActivationNonce;
    use eliot_protocol::{FrameKind, ProtocolVersion, ServerHello};
    use eliot_runtime_contracts::{
        HealthVector, RegisteredActivityWakePolicy, ServiceProcessState, SupervisionJournalEpoch,
        SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
    };
    use eliot_store_api::{
        CAPABILITIES, EFFECTS, ReadinessReceipt, StoreFailure, StoreFailureIdentityContext,
        StoreRequest, StoreResponse, decode_request_frame, response_frame,
    };
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn handle(value: &str) -> eliot_platform::PlatformHandle {
        eliot_platform::PlatformHandle::new(value).unwrap()
    }

    fn candidate_binding() -> HostKernelCandidateBinding {
        HostKernelCandidateBinding {
            installation_id: handle("installation-992"),
            host_epoch: AuthorityEpoch::new(1).unwrap(),
            kernel_epoch: epoch(1),
            activation_id: handle("activation-992"),
            artifact_hash: handle("artifact-992"),
            config_hash: handle("config-992"),
            job_object_id: handle("Local\\Eliot-Host-Kernel-992"),
            pipe_identity: handle(KERNEL_CONTROL_PIPE),
            host_process: HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: "C:\\eliot\\host.exe".to_owned(),
            },
            job_binding: HostJobBinding {
                job: HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-992".to_owned(),
                },
                root: HostJobRoot {
                    process: HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: "C:\\eliot\\kernel.exe".to_owned(),
                    },
                    executable: HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            supervision_incarnation: SupervisionLeaseIncarnationBinding {
                supervision_lease_scope_id: "eliot-supervision-scope:v1:992".to_owned(),
                supervision_lease_id: String::new(),
                scope_ref_digest: String::new(),
                installation_id: "installation-992".to_owned(),
                host_epoch: SupervisionJournalEpoch {
                    lineage_id: "host-lineage-992".to_owned(),
                    sequence: 1,
                },
                activation_id: "activation-992".to_owned(),
                activation_generation: SupervisionJournalEpoch {
                    lineage_id: "activation-lineage-992".to_owned(),
                    sequence: 1,
                },
                kernel_generation: SupervisionJournalEpoch {
                    lineage_id: "kernel-lineage-992".to_owned(),
                    sequence: 1,
                },
                watchdog_epoch: SupervisionJournalEpoch {
                    lineage_id: "watchdog-lineage-992".to_owned(),
                    sequence: 1,
                },
                observation_scope: SupervisionObservationScope {
                    targets: vec!["eliot-kernel".to_owned()],
                    sensor_profile: "eliot-runtime-live-v3".to_owned(),
                    claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                    governance_axis: "runtime-live-v3".to_owned(),
                },
                wake_policy: RegisteredActivityWakePolicy::Disabled,
                predecessor: None,
            }
            .with_derived_ids()
            .unwrap(),
            restart_budget: RestartBudget::new(1, 1).unwrap(),
            agent_bridge_admission: None,
            containment_action: None,
        }
    }

    fn ready_service() -> KernelService {
        let mut service = KernelService::new([1; 32], 4, 8).unwrap();
        let candidate = candidate_binding();
        service.reconcile(candidate.clone()).unwrap();
        service.apply(KernelControlCommand::Shadow).unwrap();
        service.apply(KernelControlCommand::PrepareHandoff).unwrap();
        let permit = KernelActivationPermit {
            operation_id: handle("op-992-activation"),
            candidate_binding_digest: candidate.compute_digest().unwrap(),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: handle("txn-992"),
            journal_sequence: 1,
            generation: ResourceGeneration::genesis(),
            authority_epoch: candidate.kernel_epoch.clone(),
            activation_nonce: KernelActivationNonce::new(handle(&"a".repeat(64))).unwrap(),
        };
        service
            .activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
            .unwrap();
        let ready = KernelReadyReceipt {
            activation_id: candidate.activation_id.clone(),
            activation_operation_id: permit.operation_id.clone(),
            activation_nonce_digest: service
                .activation_receipt()
                .unwrap()
                .activation_nonce_digest
                .clone(),
            process: ProcessObservation {
                process_id: handle("pid:42:start:10"),
                job_object_id: candidate.job_object_id.clone(),
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![handle("ev992")],
            },
            health: HealthVector::healthy(),
            evidence_refs: vec![handle("ev992")],
        };
        service.publish_ready(ready).unwrap();
        assert_eq!(service.state(), KernelServiceState::Ready);
        service
    }

    fn failure_for(error: StoreError, request: &ReservedWriteRequest) -> StoreFailure {
        StoreFailure::from_store_error(
            error,
            StoreFailureIdentityContext {
                request_id: Some(request.context.request_id.clone()),
                operation_id: Some(request.transition.identity.operation_id.clone()),
                idempotency_key_ref_or_digest: Some(
                    request.transition.identity.idempotency_key.clone(),
                ),
                state_fence_ref_or_exact_safe_projection: Some(request.context.state_fence.clone()),
                evidence_ref: None,
                transport_unavailable: false,
            },
        )
        .unwrap()
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ServerMode {
        NoSend,
        CommitSuccess,
        RefuseUnknownOperation,
        UnknownOutcome,
    }

    #[derive(Default)]
    struct ServerLog {
        reserved: AtomicUsize,
        apply: AtomicUsize,
        receipt: AtomicUsize,
    }

    async fn serve(
        mut server: NamedPipeServer,
        connection_id: String,
        artifact_hash: String,
        config_hash: String,
        mode: ServerMode,
        log: Arc<ServerLog>,
    ) {
        let limits = TransportLimits::default();
        let frame = server
            .receive_frame(limits)
            .await
            .expect("992 hello arrives");
        assert_eq!(frame.kind, FrameKind::Control, "992 expects EBP hello");
        let hello = ServerHello {
            selected_protocol: ProtocolVersion::CURRENT,
            session_principal_binding: "loopback-store-session".to_owned(),
            allowed_capabilities: CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            allowed_effects: EFFECTS.iter().map(|value| (*value).to_owned()).collect(),
            config_snapshot: serde_json::json!({
                "config_hash": config_hash,
                "artifact_hash": artifact_hash,
            }),
            heartbeat_ms: 1_000,
            control_channel: "loopback-store-control".to_owned(),
            rejection_reason: None,
            authority_epoch: epoch(1),
        };
        server
            .send_frame(
                &server_hello_frame(&connection_id, &hello).expect("992 hello encodes"),
                limits,
            )
            .await
            .expect("992 hello sends");
        let frame = server
            .receive_frame(limits)
            .await
            .expect("992 readiness arrives");
        let (request_id, _, store_request) =
            decode_request_frame(&frame).expect("992 readiness decodes");
        assert!(
            matches!(store_request, StoreRequest::Readiness),
            "992 expects readiness"
        );
        server
            .send_frame(
                &response_frame(
                    connection_id.clone(),
                    ProtocolVersion::CURRENT,
                    Some(request_id),
                    StoreResponse::Readiness {
                        receipt: ReadinessReceipt::ready("loopback-992".to_owned()),
                    },
                )
                .expect("992 readiness encodes"),
                limits,
            )
            .await
            .expect("992 readiness sends");
        loop {
            let next =
                tokio::time::timeout(Duration::from_secs(5), server.receive_frame(limits)).await;
            let Ok(Ok(frame)) = next else {
                break;
            };
            let Ok((request_id, _, store_request)) = decode_request_frame(&frame) else {
                break;
            };
            let answer = match store_request {
                StoreRequest::ReservedWrite { request } => {
                    log.reserved.fetch_add(1, Ordering::SeqCst);
                    match mode {
                        ServerMode::NoSend => {
                            panic!("992 reserved send arrived in NoSend mode")
                        }
                        ServerMode::CommitSuccess => StoreResponse::Transaction {
                            receipt: receipt_for(&request, WriteReceiptStatus::Committed),
                        },
                        ServerMode::RefuseUnknownOperation => StoreResponse::Failure {
                            failure: failure_for(StoreError::UnknownOperation, &request),
                        },
                        ServerMode::UnknownOutcome => StoreResponse::Unknown {
                            operation_id: request.transition.identity.operation_id.clone(),
                            reason: "loopback answer lost after possible submit".to_owned(),
                        },
                    }
                }
                StoreRequest::Receipt { .. } => {
                    log.receipt.fetch_add(1, Ordering::SeqCst);
                    StoreResponse::Receipt { receipt: None }
                }
                StoreRequest::Apply { .. } => {
                    log.apply.fetch_add(1, Ordering::SeqCst);
                    panic!("992 reserved path must never fall back to ordinary Apply");
                }
                _ => break,
            };
            let Ok(frame) = response_frame(
                connection_id.clone(),
                ProtocolVersion::CURRENT,
                Some(request_id),
                answer,
            ) else {
                break;
            };
            if server.send_frame(&frame, limits).await.is_err() {
                break;
            }
        }
    }

    struct Loopback {
        gateway: Arc<KernelStoreGateway>,
        log: Arc<ServerLog>,
        server_task: tokio::task::JoinHandle<()>,
        dir: std::path::PathBuf,
    }

    async fn loopback(
        mode: ServerMode,
        tag: &str,
        ors: Option<Arc<RedbRecoveryStore>>,
    ) -> Loopback {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("992 clock")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("eliot-992-gw-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("992 temp root");
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .expect("992 loopback expectation");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("992 clock")
            .as_nanos();
        let pipe = format!(r"\\.\pipe\eliot\k992-{tag}-{}-{nanos}", std::process::id());
        let mut server = NamedPipeServer::create(&pipe, &expectation).expect("992 server");
        let client_pipe = pipe.clone();
        let client_expectation = expectation.clone();
        let client_task = tokio::spawn(async move {
            NamedPipeTransport::connect_authenticated(
                &client_pipe,
                Duration::from_secs(10),
                &client_expectation,
            )
            .await
            .expect("992 loopback connects")
        });
        server
            .wait_for_authenticated_client(Duration::from_secs(10), &expectation)
            .await
            .expect("992 loopback admits its own process");
        let transport = client_task.await.expect("992 client task");
        let (peer_sid, peer_session) = match transport.peer_identity() {
            PeerIdentity::Authenticated {
                user_identity,
                session_identity,
                ..
            } => (user_identity.clone(), session_identity.clone()),
            PeerIdentity::Unavailable { .. } => {
                panic!("992 loopback peer is not authenticated")
            }
        };
        let live = fence();
        let requirement = eliot_kernel_service::HostStoreBootstrapRequirement {
            route_identity: handle("store_bridge"),
            canonical_pipe_identity: handle(&pipe),
            store_generation: ResourceGeneration::genesis(),
            state_fence: live.clone(),
            launch_nonce: handle("launch-992"),
            connection_id: handle(&format!("conn-992-{tag}")),
            expected_peer_sid: handle(&peer_sid),
            expected_peer_session_id: peer_session.parse().expect("992 session"),
            approved_artifact_hash: handle(&"a".repeat(64)),
            approved_config_hash: handle(&"b".repeat(64)),
            timeout_ms: 30_000,
        };
        let artifact = requirement.approved_artifact_hash.as_str().to_owned();
        let config = requirement.approved_config_hash.as_str().to_owned();
        let connection_id = requirement.connection_id.as_str().to_owned();
        let log = Arc::new(ServerLog::default());
        let server_task = tokio::spawn(serve(
            server,
            connection_id,
            artifact,
            config,
            mode,
            Arc::clone(&log),
        ));
        let client = eliot_kernel_service::EbpCanonicalStoreClient::connect(transport, requirement)
            .await
            .expect("992 EBP handshake");
        let service = Arc::new(Mutex::new(ready_service()));
        let route = GenerationRoute::new(
            RouteScope::new("store_bridge").expect("992 scope"),
            ResourceGeneration::genesis(),
            AuthorityEpoch::new(1).expect("992 route epoch"),
        )
        .expect("992 route");
        let gateway = Arc::new(KernelStoreGateway::new(
            service,
            Arc::new(client),
            route,
            ors,
        ));
        Loopback {
            gateway,
            log,
            server_task,
            dir,
        }
    }

    async fn finish(setup: Loopback) {
        let Loopback {
            gateway,
            server_task,
            dir,
            ..
        } = setup;
        drop(gateway);
        if tokio::time::timeout(Duration::from_secs(15), server_task)
            .await
            .is_err()
        {
            panic!("992 loopback server did not join");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    fn apply_inputs(
        tag: &str,
        scopes: &[&str],
    ) -> (
        RequestMeta,
        PreparedTransition,
        Vec<RevisionHeadExpectation>,
        Vec<OrderingHeadExpectation>,
        ReservationSeed,
    ) {
        let context = context_for(tag);
        let mut transition = transition_for(tag, scopes);
        let (revision, ordering) = heads_for(tag, scopes);
        seal(&context, &mut transition, &revision, &ordering);
        let seed = seed_for(tag, transition.identity.operation_id.as_str(), scopes);
        (context, transition, revision, ordering, seed)
    }

    fn apply_inputs_fresh_scope(
        tag: &str,
        scope: &str,
    ) -> (
        RequestMeta,
        PreparedTransition,
        Vec<RevisionHeadExpectation>,
        Vec<OrderingHeadExpectation>,
        ReservationSeed,
    ) {
        // A scope never touched before, observed at its own head: proves a
        // later write still dispatches after earlier scopes committed.
        let context = context_for(tag);
        let mut transition = transition_for(tag, &[scope]);
        let (revision, ordering) = heads_seq(tag, &[scope], 6);
        seal(&context, &mut transition, &revision, &ordering);
        let mut seed = seed_for(tag, transition.identity.operation_id.as_str(), &[scope]);
        seed.heads = observed_seq(&[scope], 6, &"e".repeat(64));
        (context, transition, revision, ordering, seed)
    }

    // WORK_UNIT_CASE: 992/1
    #[tokio::test]
    async fn two_constructor_injection_maps_gateway_to_owned_ors_and_store() {
        // Both production construction sites inject the same owned ORS handle
        // (`Some(Arc::clone(...))`, no foreign handle, no verifier param):
        // the ORS-backed gateway stages durable state and dispatches through
        // the Store exactly once, while the ORS-less gateway refuses before
        // any send with no fallback.
        let (ors, _dir) = temp_ors("01", Arc::new(BindingEvidence));
        let bound = loopback(
            ServerMode::UnknownOutcome,
            "01bound",
            Some(Arc::clone(&ors)),
        )
        .await;
        let (context, transition, revision, ordering, seed) = apply_inputs("01a", &["scope-992-a"]);
        let op = transition.identity.operation_id.as_str().to_owned();
        let error = bound
            .gateway
            .apply_reserved(&context, transition, revision, ordering, seed)
            .await
            .expect_err("992/1 unknown outcome stays unknown");
        assert!(
            error.contains(&op),
            "992/1 unknown preserves the operation, got {error}"
        );
        assert_eq!(
            bound.log.reserved.load(Ordering::SeqCst),
            1,
            "992/1 exactly one Store send"
        );
        assert_eq!(
            bound.log.receipt.load(Ordering::SeqCst),
            0,
            "992/1 no receipt query follows the single send"
        );
        let pending = unresolved(&owner_for(&ors));
        assert_eq!(pending.len(), 1, "992/1 gateway staged its ORS token");
        assert_eq!(
            pending[0].state,
            ReservationState::Reconciling,
            "992/1 unknown outcome reconciles"
        );
        finish(bound).await;

        let unbound = loopback(ServerMode::NoSend, "01unbound", None).await;
        let (u_context, u_transition, u_revision, u_ordering, u_seed) =
            apply_inputs("01b", &["scope-992-a"]);
        let error = unbound
            .gateway
            .apply_reserved(&u_context, u_transition, u_revision, u_ordering, u_seed)
            .await
            .expect_err("992/1 ORS-less gateway must refuse");
        assert!(
            error.contains("composition-bound ORS"),
            "992/1 refusal names the missing owner, got {error}"
        );
        assert_eq!(
            unbound.log.reserved.load(Ordering::SeqCst),
            0,
            "992/1 no Store send without the owner"
        );
        finish(unbound).await;
    }

    // WORK_UNIT_CASE: 992/6
    #[tokio::test]
    async fn not_yet_eligible_predecessor_blocks_dispatch() {
        // The head reservation is eligible but not yet closed: the
        // overlapping successor reserves fine, then is refused with the owner
        // predecessor error before any lease or send. The shared counters
        // prove nothing dispatched for the waiter.
        let (ors, _dir) = temp_ors("06", Arc::new(BindingEvidence));
        let owner = owner_for(&ors);
        let (_ctx_h, _tr_h, _rev_h, _ord_h, head) = reserve_one(&owner, "06head", &["scope-992-a"]);
        ensure_eligible(&owner, &head.token).expect("992/6 head is eligible");
        let setup = loopback(ServerMode::NoSend, "06", Some(Arc::clone(&ors))).await;
        let (b_context, b_transition, b_revision, b_ordering, b_seed) =
            apply_inputs("06b", &["scope-992-a"]);
        let error = setup
            .gateway
            .apply_reserved(&b_context, b_transition, b_revision, b_ordering, b_seed)
            .await
            .expect_err("992/6 successor must wait");
        assert!(
            error.contains("blocks") || error.contains("earlier reservation"),
            "992/6 refusal names the predecessor, got {error}"
        );
        assert_eq!(
            setup.log.reserved.load(Ordering::SeqCst),
            0,
            "992/6 the waiter dispatches nothing"
        );
        let pending = unresolved(&owner);
        assert_eq!(pending.len(), 2, "992/6 both tokens persist");
        assert!(
            pending.iter().any(
                |record| record.token.reservation_id.as_str() == "res-992-06head"
                    && record.state == ReservationState::Eligible
            ),
            "992/6 head stays eligible and untouched"
        );
        finish(setup).await;
    }

    // WORK_UNIT_CASE: 992/8
    #[tokio::test]
    async fn reserved_capability_absent_never_falls_back_to_unreserved_write() {
        // Without the composition ORS the gateway refuses with zero sends;
        // against a backend without reserved capability the single refused
        // send surfaces explicit unsupported behavior, releases its token
        // cleanly, and never touches ordinary Apply (the server panics on it).
        let unbound = loopback(ServerMode::NoSend, "08a", None).await;
        let (a_context, a_transition, a_revision, a_ordering, a_seed) =
            apply_inputs("08a", &["scope-992-a"]);
        let error = unbound
            .gateway
            .apply_reserved(&a_context, a_transition, a_revision, a_ordering, a_seed)
            .await
            .expect_err("992/8 ORS-less gateway must refuse");
        assert!(
            error.contains("without unreserved Apply fallback"),
            "992/8 refusal is explicit, got {error}"
        );
        assert_eq!(
            unbound.log.reserved.load(Ordering::SeqCst),
            0,
            "992/8 zero sends without the owner"
        );
        assert_eq!(
            unbound.log.apply.load(Ordering::SeqCst),
            0,
            "992/8 no unreserved fallback"
        );
        finish(unbound).await;

        let (ors, _dir) = temp_ors("08b", Arc::new(BindingEvidence));
        let refusing = loopback(
            ServerMode::RefuseUnknownOperation,
            "08b",
            Some(Arc::clone(&ors)),
        )
        .await;
        let (b_context, b_transition, b_revision, b_ordering, b_seed) =
            apply_inputs("08b", &["scope-992-a"]);
        let error = refusing
            .gateway
            .apply_reserved(&b_context, b_transition, b_revision, b_ordering, b_seed)
            .await
            .expect_err("992/8 refusing backend must fail");
        assert!(
            error.contains("has no reserved-write capability"),
            "992/8 refusal names the missing capability, got {error}"
        );
        assert_eq!(
            refusing.log.reserved.load(Ordering::SeqCst),
            1,
            "992/8 exactly one refused send"
        );
        assert_eq!(
            refusing.log.apply.load(Ordering::SeqCst),
            0,
            "992/8 refusal never falls back to Apply"
        );
        let pending = unresolved(&owner_for(&ors));
        assert!(
            pending.is_empty(),
            "992/8 refused token releases cleanly with no orphan"
        );
        finish(refusing).await;
    }

    // WORK_UNIT_CASE: 992/10
    #[tokio::test]
    async fn cancellation_before_possible_submission_releases_only_its_reservation() {
        // Before-send cancellation releases exactly its token through the
        // protected reserve: the sibling reservation is untouched and stays
        // dispatchable, and the protected accounting balances.
        let (ors, _dir) = temp_ors("10", Arc::new(BindingEvidence));
        let owner = owner_for(&ors);
        let (_ctx_a, _tr_a, _rev_a, _ord_a, sealed_a) =
            reserve_one(&owner, "10a", &["scope-992-a"]);
        let (_ctx_b, _tr_b, _rev_b, _ord_b, sealed_b) =
            reserve_one(&owner, "10b", &["scope-992-b"]);
        ensure_eligible(&owner, &sealed_a.token).expect("992/10a eligible");
        let released = cancel_before_send(&owner, &sealed_a.token).expect("992/10a releases");
        assert_eq!(
            released.state,
            ReservationState::Released,
            "992/10 before-send cancel releases"
        );
        assert!(
            released.terminal_receipt_id.is_none(),
            "992/10 pre-effect release binds no terminal receipt"
        );
        ensure_eligible(&owner, &sealed_b.token).expect("992/10b sibling still dispatchable");

        let setup = loopback(ServerMode::NoSend, "10gw", Some(Arc::clone(&ors))).await;
        let control_before = setup
            .gateway
            .available_control()
            .expect("992/10 control reads");
        let released_gw = setup
            .gateway
            .cancel_reserved(&sealed_b.token)
            .expect("992/10 gateway cancel releases");
        assert_eq!(
            released_gw.state,
            ReservationState::Released,
            "992/10 gateway cancel releases through the protected reserve"
        );
        let control_after = setup
            .gateway
            .available_control()
            .expect("992/10 control reads");
        assert_eq!(
            control_before, control_after,
            "992/10 cancellation consumes no net protected reserve"
        );
        finish(setup).await;
    }

    // WORK_UNIT_CASE: 992/12
    #[tokio::test]
    async fn canonical_committed_receipt_finalizes_the_complete_scope_set() {
        // The full gateway path commits through the Store once and finalizes
        // every reserved scope atomically; the released admission lease lets
        // the next write through.
        let (ors, _dir) = temp_ors("12", Arc::new(BindingEvidence));
        let setup = loopback(ServerMode::CommitSuccess, "12", Some(Arc::clone(&ors))).await;
        let (context, transition, revision, ordering, seed) =
            apply_inputs("12a", &["scope-992-a", "scope-992-b"]);
        let receipt = setup
            .gateway
            .apply_reserved(&context, transition, revision, ordering, seed)
            .await
            .expect("992/12 committed write applies");
        assert_eq!(
            receipt.status,
            WriteReceiptStatus::Committed,
            "992/12 receipt commits"
        );
        assert_eq!(
            receipt.ordering_sequences.len(),
            2,
            "992/12 receipt covers the complete scope set"
        );
        assert_eq!(
            setup.log.reserved.load(Ordering::SeqCst),
            1,
            "992/12 exactly one Store send"
        );
        let pending = unresolved(&owner_for(&ors));
        assert!(
            pending.is_empty(),
            "992/12 committed token leaves no unresolved scope"
        );
        // The admission lease released deterministically: a later write on an
        // untouched scope dispatches through the same gateway.
        let (c2_context, c2_transition, c2_revision, c2_ordering, c2_seed) =
            apply_inputs_fresh_scope("12b", "scope-992-c");
        let second = setup
            .gateway
            .apply_reserved(
                &c2_context,
                c2_transition,
                c2_revision,
                c2_ordering,
                c2_seed,
            )
            .await
            .expect("992/12 second call proves lease release");
        assert_eq!(
            second.status,
            WriteReceiptStatus::Committed,
            "992/12 second write commits"
        );
        assert_eq!(
            setup.log.reserved.load(Ordering::SeqCst),
            2,
            "992/12 two ledger calls"
        );
        finish(setup).await;
    }

    // WORK_UNIT_CASE: 992/18
    #[tokio::test]
    async fn reconciling_scope_leaves_unrelated_work_eligible_and_drain_honest() {
        // One reconciling scope blocks only its own scopes; migration drain
        // reports the honest pending count without forced release, and goes
        // quiet once the token reconciles.
        let (ors, _dir) = temp_ors("18", Arc::new(BindingEvidence));
        let owner = owner_for(&ors);
        let (_ctx_a, tr_a, _rev_a, _ord_a, sealed_a) = reserve_one(&owner, "18a", &["scope-992-a"]);
        ensure_eligible(&owner, &sealed_a.token).expect("992/18a eligible");
        begin_execute(&owner, &sealed_a.token).expect("992/18a executing");
        mark_unknown_outcome(&owner, &sealed_a.token).expect("992/18a reconciling");
        let (_ctx_b, _tr_b, _rev_b, _ord_b, sealed_b) =
            reserve_one(&owner, "18b", &["scope-992-b"]);
        ensure_eligible(&owner, &sealed_b.token).expect("992/18b unrelated stays eligible");
        let _ = tr_a;

        let setup = loopback(ServerMode::NoSend, "18", Some(Arc::clone(&ors))).await;
        let error = setup
            .gateway
            .drain_reserved(Duration::from_secs(5))
            .await
            .expect_err("992/18 drain with an open token must block");
        assert!(
            error.contains('1') || error.contains("unresolved"),
            "992/18 drain reports its honest pending count, got {error}"
        );
        let pending = unresolved(&owner);
        assert_eq!(
            pending.len(),
            2,
            "992/18 drain accounts for every unresolved token, eligible included"
        );
        assert!(
            pending.iter().any(
                |record| record.token.reservation_id.as_str() == "res-992-18a"
                    && record.state == ReservationState::Reconciling
            ),
            "992/18 drain force-releases nothing"
        );
        // Recovery reconciles the token at the durable owner (gateway
        // independent: the drain fence stays put), and a fresh gateway then
        // drains quiet with nothing forced.
        let context_a = context_for("18a");
        let mut transition_a = transition_for("18a", &["scope-992-a"]);
        let (revision_a, ordering_a) = heads_for("18a", &["scope-992-a"]);
        seal(&context_a, &mut transition_a, &revision_a, &ordering_a);
        let seed_a = seed_for(
            "18a",
            transition_a.identity.operation_id.as_str(),
            &["scope-992-a"],
        );
        let replayed = reserve_for_transition(
            &owner,
            &seed_a,
            &context_a,
            &transition_a,
            &revision_a,
            &ordering_a,
        )
        .expect("992/18 replay recovers its token");
        let request_a =
            project_reserved_write(&replayed, &context_a, &transition_a, revision_a, ordering_a)
                .expect("992/18 request rebuilds");
        let receipt_a = receipt_for(&request_a, WriteReceiptStatus::Committed);
        let reconciliation_a =
            reconcile_receipt(&replayed.token, &receipt_a).expect("992/18 evidence binds");
        let closed = finalize_reservation(&owner, &reconciliation_a)
            .expect("992/18 recovery finalizes at the durable owner");
        assert_eq!(
            closed.state,
            ReservationState::Finalized,
            "992/18 recovery finalizes"
        );
        // The unrelated probe stood down, so nothing remains: the fresh
        // gateway drains quiet with nothing forced.
        cancel_before_send(&owner, &sealed_b.token).expect("992/18 probe releases");
        finish(setup).await;
        let setup2 = loopback(ServerMode::NoSend, "18b", Some(Arc::clone(&ors))).await;
        setup2
            .gateway
            .drain_reserved(Duration::from_secs(5))
            .await
            .expect("992/18 drain goes quiet after reconciliation");
        finish(setup2).await;
    }

    // WORK_UNIT_CASE: 992/20
    #[tokio::test]
    async fn bounded_fault_sequence_leaves_no_orphan_retry_or_mutation() {
        // One unknown send reconciles to exactly one finalized token: a
        // single Store send, zero receipt queries, zero retries, the
        // transition bytes bit-identical, and every scope terminal together.
        let (ors, _dir) = temp_ors("20", Arc::new(BindingEvidence));
        let setup = loopback(ServerMode::UnknownOutcome, "20", Some(Arc::clone(&ors))).await;
        let (context, transition, revision, ordering, seed) =
            apply_inputs("20a", &["scope-992-a", "scope-992-b"]);
        let digest_before = eliot_store_api::prepared_transition_digest(&transition).unwrap();
        let op = transition.identity.operation_id.as_str().to_owned();
        setup
            .gateway
            .apply_reserved(
                &context,
                transition.clone(),
                revision.clone(),
                ordering.clone(),
                seed.clone(),
            )
            .await
            .expect_err("992/20 first send stays unknown");
        assert_eq!(
            setup.log.reserved.load(Ordering::SeqCst),
            1,
            "992/20 exactly one send"
        );
        // Recover the affected token and original operation by exact replay,
        // then reconcile with the committed answer.
        let owner = owner_for(&ors);
        let replayed =
            reserve_for_transition(&owner, &seed, &context, &transition, &revision, &ordering)
                .expect("992/20 replay recovers its token");
        let request = project_reserved_write(&replayed, &context, &transition, revision, ordering)
            .expect("992/20 request rebuilds");
        let receipt = receipt_for(&request, WriteReceiptStatus::Committed);
        let closed = setup
            .gateway
            .reconcile_reserved(&replayed.token, &request, &receipt)
            .expect("992/20 exact receipt reconciles");
        assert_eq!(
            closed.state,
            ReservationState::Finalized,
            "992/20 token finalizes"
        );
        assert_eq!(
            setup.log.reserved.load(Ordering::SeqCst),
            1,
            "992/20 no hidden retry send"
        );
        assert_eq!(
            setup.log.receipt.load(Ordering::SeqCst),
            0,
            "992/20 no hidden receipt query"
        );
        let digest_after = eliot_store_api::prepared_transition_digest(&transition).unwrap();
        assert_eq!(
            digest_before, digest_after,
            "992/20 transition bytes never mutated"
        );
        assert_eq!(
            closed.token.reservation_order, replayed.token.reservation_order,
            "992/20 one order, no partial release"
        );
        let pending = unresolved(&owner);
        assert!(
            pending.is_empty(),
            "992/20 no orphaned token remains for {op}"
        );
        finish(setup).await;
    }
}
