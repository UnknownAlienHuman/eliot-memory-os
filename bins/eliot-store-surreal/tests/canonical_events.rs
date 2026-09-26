//! Canonical-event acceptance proof for issue #1931.
//!
//! A committed multi-scope operation resolves to one event ID with one valid
//! chain link per declared scope (same identity/payload, per-scope sequence
//! and previous hash), and its receipt, outbox intent, and audit fields appear
//! atomically. A projection is readable as current only when its publication
//! record names matching source heads, generation, definition digest, and an
//! atomic data/provenance receipt. Rebuild initiates from the Doctor path,
//! never from an ordinary semantic write command.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::uninlined_format_args)]

use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, OperationId, ResourceGeneration, StateFence};
use eliot_store_api::{
    CommitId, EventId, OperationManifestDigest, OrderingHead, OrderingScopeId, OutboxId,
    OutboxIntent, OutboxState, ProjectionMode, ProjectionPublicationId,
    ProjectionPublicationRecord, ProjectionStatus, Resubmission, RevisionHead, RevisionKey,
    SplitView, TransitionClass, WriteReceipt, WriteReceiptStatus,
};
use eliot_store_surreal::{
    CanonicalEvent, CommittedCanonicalTransition, DoctorRebuildAuthority,
    FencedProjectionPublication, SemanticWritePath, request_projection_rebuild,
    request_rebuild_from_semantic_write,
};

const LINEAGE_1931: &str = "550e8400-e29b-41d4-a716-446655440193";

fn fence() -> StateFence {
    fence_at_epoch(1)
}

fn fence_at_epoch(counter: u64) -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new(LINEAGE_1931).unwrap(),
        NonZeroU64::new(counter).unwrap(),
    )
    .unwrap();
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn multi_scope_event() -> CanonicalEvent {
    CanonicalEvent::issue(
        EventId::new("event-1931-1").unwrap(),
        OperationId::new("op-1931-1").unwrap(),
        "store.apply.epistemic".to_owned(),
        "a".repeat(64),
        vec![
            (
                OrderingScopeId::new("scope-1931-a").unwrap(),
                7,
                "0".repeat(64),
            ),
            (
                OrderingScopeId::new("scope-1931-b").unwrap(),
                3,
                "0".repeat(64),
            ),
        ],
        11,
        fence(),
    )
    .unwrap()
}

fn committed_bundle() -> CommittedCanonicalTransition {
    let event = multi_scope_event();
    let outbox = OutboxIntent {
        outbox_id: OutboxId::new("outbox-1931-1").unwrap(),
        operation_id: event.operation_id.clone(),
        sequence: 1,
        payload_digest: "e".repeat(64),
        state_fence: fence(),
        arrival_fence: "arrival-1931-1".to_owned(),
        claim_fence: None,
        state: OutboxState::Arrived,
    };
    let receipt = WriteReceipt {
        operation_id: event.operation_id.clone(),
        idempotency_key: "idem-1931-1".to_owned(),
        canonical_request_hash: "b".repeat(64),
        transition_class: TransitionClass::Epistemic,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new("commit-1931-1").unwrap()),
        state_fence: fence(),
        ordering_sequences: vec![
            OrderingHead {
                scope: OrderingScopeId::new("scope-1931-a").unwrap(),
                sequence: 7,
                state_fence: fence(),
            },
            OrderingHead {
                scope: OrderingScopeId::new("scope-1931-b").unwrap(),
                sequence: 3,
                state_fence: fence(),
            },
        ],
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["cmd-1931-1".to_owned()],
        emitted_event_ids: vec![event.event_id.clone()],
        projection_refs: Vec::new(),
        outbox_refs: vec![outbox.outbox_id.clone()],
        operation_manifest_digest: OperationManifestDigest::new("d".repeat(64)).unwrap(),
        // Issue #18: standalone fixture
        semantic_source_revisions: Vec::new(),
        admission_digest: "f".repeat(64),
        mutation_plan_digest: "f".repeat(64),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: None,
    };
    CommittedCanonicalTransition {
        event,
        receipt,
        outbox: vec![outbox],
        audit_chain_digest: "f".repeat(64),
    }
}

fn source_heads() -> Vec<RevisionHead> {
    vec![RevisionHead {
        key: RevisionKey::new("rev-1931-1").unwrap(),
        revision: 4,
        state_fence: fence(),
    }]
}

fn fenced_publication() -> FencedProjectionPublication {
    let record = ProjectionPublicationRecord {
        publication_id: ProjectionPublicationId::new("pub-1931-1").unwrap(),
        projection_kind: "graph/concept".to_owned(),
        projection_generation: 2,
        source_generation: 5,
        source_cursor: 9,
        state_fence: fence(),
        mode: ProjectionMode::Delta,
        source_revision_heads: source_heads(),
        atomic_data_commit: CommitId::new("commit-1931-9").unwrap(),
        provenance_manifest_ref: "manifest-1931-9".to_owned(),
        visible_lag_checkpoint: None,
        split_view: SplitView::None,
        status: ProjectionStatus::Current,
    };
    FencedProjectionPublication {
        record,
        projection_definition_digest: "c".repeat(64),
        atomic_commit_ref: CommitId::new("commit-1931-9").unwrap(),
    }
}

#[test]
fn multi_scope_commit_carries_one_event_identity_with_one_link_per_scope() {
    let bundle = committed_bundle();
    assert!(bundle.validate_atomic().is_ok());
    assert_eq!(bundle.event.ordering_links.len(), 2);
    for link in &bundle.event.ordering_links {
        link.verify(&bundle.event.event_id, &bundle.event.payload_digest)
            .expect("every declared scope carries a valid chain link");
    }
    let scopes: Vec<&str> = bundle
        .event
        .ordering_links
        .iter()
        .map(|link| link.ordering_scope.as_str())
        .collect();
    assert!(scopes.contains(&"scope-1931-a"));
    assert!(scopes.contains(&"scope-1931-b"));
    // Same identity/payload, per-scope sequence: the two links differ only by
    // scope, sequence, and (here genesis-equal) previous hash lineage.
    assert_ne!(
        bundle.event.ordering_links[0].event_hash,
        bundle.event.ordering_links[1].event_hash
    );
}

#[test]
fn tampered_link_hash_and_detached_receipt_fail_closed() {
    let mut bundle = committed_bundle();
    bundle.event.ordering_links[0].event_hash = "1".repeat(64);
    assert!(bundle.validate_atomic().is_err());

    let mut detached = committed_bundle();
    detached.receipt.operation_id = OperationId::new("op-1931-other").unwrap();
    assert!(detached.validate_atomic().is_err());
}

#[test]
fn projection_readable_as_current_only_with_matching_fence_record() {
    let publication = fenced_publication();
    assert!(
        publication
            .check_current(&source_heads(), 5, &"c".repeat(64))
            .is_ok()
    );
    // Stale definition digest.
    assert!(
        publication
            .check_current(&source_heads(), 5, &"d".repeat(64))
            .is_err()
    );
    // Mismatched source generation.
    assert!(
        publication
            .check_current(&source_heads(), 6, &"c".repeat(64))
            .is_err()
    );
    // Mismatched source heads.
    assert!(publication.check_current(&[], 5, &"c".repeat(64)).is_err());
    // Broken atomic data/provenance coupling.
    let mut decoupled = fenced_publication();
    decoupled.atomic_commit_ref = CommitId::new("commit-1931-other").unwrap();
    assert!(
        decoupled
            .check_current(&source_heads(), 5, &"c".repeat(64))
            .is_err()
    );
    // Non-current status is never readable as current.
    let mut stale = fenced_publication();
    stale.record.status = ProjectionStatus::Stale;
    assert!(
        stale
            .check_current(&source_heads(), 5, &"c".repeat(64))
            .is_err()
    );
}

#[test]
fn projection_rebuild_initiates_only_from_doctor_path() {
    let publication = fenced_publication();
    let authority = DoctorRebuildAuthority::doctor_authorize();
    let plan = request_projection_rebuild(&authority, &publication, 3).unwrap();
    assert_eq!(plan.target_generation, 3);
    assert_eq!(plan.projection_kind, "graph/concept");
    assert!(
        request_rebuild_from_semantic_write(&SemanticWritePath, "graph/concept").is_err(),
        "ordinary semantic write commands cannot initiate a rebuild"
    );
}

#[test]
fn atomic_bundle_rejects_phantom_or_missing_members() {
    // Phantom outbox ref: the receipt names an outbox id with no committed intent.
    let mut phantom_outbox = committed_bundle();
    phantom_outbox
        .receipt
        .outbox_refs
        .push(OutboxId::new("outbox-1931-ghost").unwrap());
    assert!(phantom_outbox.validate_atomic().is_err());

    // Missing intent: the receipt still references the intent, but it is absent.
    let mut missing_intent = committed_bundle();
    missing_intent.outbox.clear();
    assert!(missing_intent.validate_atomic().is_err());

    // Phantom ordering sequence: the receipt claims a scope the event never linked.
    let mut phantom_scope = committed_bundle();
    phantom_scope.receipt.ordering_sequences.push(OrderingHead {
        scope: OrderingScopeId::new("scope-1931-ghost").unwrap(),
        sequence: 1,
        state_fence: fence(),
    });
    assert!(phantom_scope.validate_atomic().is_err());

    // Phantom emitted event: the transition resolves to exactly one event ID.
    let mut phantom_event = committed_bundle();
    phantom_event
        .receipt
        .emitted_event_ids
        .push(EventId::new("event-1931-ghost").unwrap());
    assert!(phantom_event.validate_atomic().is_err());
}

#[test]
fn projection_current_requires_same_fence_source_heads() {
    let publication = fenced_publication();
    // Same keys and revisions, but a foreign epoch fence: not current here.
    let mut foreign = source_heads();
    foreign[0].state_fence = fence_at_epoch(2);
    assert!(
        publication
            .check_current(&foreign, 5, &"c".repeat(64))
            .is_err()
    );
}
