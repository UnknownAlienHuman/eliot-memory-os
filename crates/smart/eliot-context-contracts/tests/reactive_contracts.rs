#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/reactive.rs"]
mod support;

use eliot_context_contracts::{AttentionResolution, ReactiveInputError, canonical_planning_digest};
use support::{coverage_event, empty_snapshot, open_attention, profile};

#[test]
fn context_planning_view_retains_original_canonical_closure() {
    let (view, admitted, rendered_bytes, admitted_bytes) = support::context_view();
    let retained = eliot_context_contracts::ContextPlanningView::new(
        support::id("view"),
        view,
        admitted,
        rendered_bytes,
        admitted_bytes,
    )
    .expect("complete immutable context closure");
    retained.validate().expect("retained context closure");
    let bounded = eliot_context_contracts::ReactivePlanningBindings {
        request_id: eliot_contracts::RequestId::new("request-bound").expect("request"),
        operation_id: eliot_contracts::OperationId::new("operation-bound").expect("operation"),
        idempotency_key: "idempotency-bound".to_owned(),
        task_id: support::task(),
        attempt_id: eliot_agent_contracts::AgentAttemptId::new("attempt-bound").expect("attempt"),
        scope_id: support::scope(),
        state_fence: support::fence(),
        view_id: support::id("view"),
        view_digest: support::digest(),
        admitted_set_digest: support::digest(),
        assembly_digest: support::digest(),
        measurement_digest: support::digest(),
        input_digest: support::digest(),
        bounds: eliot_context_contracts::ReactivePlanningBounds {
            max_input_bytes: 1,
            max_items: 1,
            max_references: 1,
        },
    };
    assert!(matches!(
        bounded.validate_against(&retained),
        Err(ReactiveInputError::InvalidField {
            field: "bindings.input_bytes",
            ..
        })
    ));
}

#[test]
fn delivered_protocol_closure_is_valid_and_bounded() {
    let (context_view, payload, event, ack, receipt, assembly_receipt, profile) =
        support::delivered_fixture();
    ack.validate_against(&payload).expect("exact current ack");
    let closure = eliot_context_contracts::DeliveryEvidenceClosure {
        context_view,
        profile,
        assembly_receipt,
        delivery_claim: None,
        delivery_owner_id: None,
        payload: payload.clone(),
        event: event.clone(),
        acknowledgements: vec![ack],
        receipts: vec![receipt],
        evidence: Vec::new(),
    };
    closure.validate().expect("complete delivery closure");
    assert!(canonical_planning_digest(&"x".repeat(300 * 1024)).is_err());

    let mut mismatched = closure;
    mismatched.event.event_id.push_str("-replay-conflict");
    assert!(matches!(
        mismatched.validate(),
        Err(ReactiveInputError::BindingMismatch {
            field: "delivery.event_payload"
        })
    ));

    let (context_view, payload, event, ack, receipt, assembly_receipt, profile) =
        support::delivered_fixture();
    let item = context_view.view.rendered[0].clone();
    let mut content = support::content_ref();
    content.artifact_id = Some(item.atom_id.clone());
    content.content_sha256 = canonical_planning_digest(&item.representation).expect("item digest");
    content.source_revision = item.source_revision.clone();
    let mut source = support::content_ref();
    source.artifact_id = Some(item.source_id.clone());
    source.content_sha256 = item.source_digest.clone();
    source.source_revision = item.source_revision.clone();
    let record_closure = eliot_context_contracts::DeliveryEvidenceClosure {
        context_view,
        profile: profile.clone(),
        assembly_receipt,
        delivery_claim: None,
        delivery_owner_id: None,
        payload: payload.clone(),
        event,
        acknowledgements: vec![ack],
        receipts: vec![receipt],
        evidence: Vec::new(),
    };
    let record = eliot_context_contracts::PriorDeliveryBinding {
        record_id: "record-delivered".to_owned(),
        operation_id: payload.operation_id.clone(),
        request_id: payload.request_id.clone(),
        idempotency_key: payload.idempotency_key.clone(),
        item_id: item.atom_id.to_string(),
        content,
        source,
        profile,
        validity: eliot_protocol::ReactiveContextValidity::Current,
        lifecycle: eliot_protocol::ReactiveContextLifecycleEvidence {
            stage: eliot_protocol::ReactiveContextStage::RecipientReceived,
            predecessor: None,
            owner_receipt: None,
        },
        stage: eliot_protocol::ReactiveContextStage::RecipientReceived,
        acknowledgement_phase: Some(eliot_protocol::AckPhase::Received),
        predecessor_ids: Vec::new(),
        replay_identity: "replay-delivered".to_owned(),
        session_id: payload.recipient.session_id.clone(),
        runtime_id: payload.recipient.runtime_id.clone(),
        runtime_generation: payload.recipient.runtime_generation,
        host_generation: support::fence().resource_generation,
        task_id: payload.task_id.clone(),
        attempt_id: payload.attempt_id.clone(),
        scope_id: payload.work_scope.scope_id.clone(),
        state_fence: payload.work_scope.state_fence.clone(),
        closure: Some(record_closure),
    };
    record.validate().expect("semantic delivered history");
    let mut snapshot = support::empty_snapshot();
    snapshot.denominator = eliot_context_contracts::SnapshotDenominator {
        observed: 1,
        expected: Some(1),
        completeness: eliot_context_contracts::SnapshotCompleteness::Partial,
    };
    snapshot.records.push(record);
    snapshot.snapshot_digest = snapshot.canonical_digest().expect("snapshot digest");
    snapshot.validate().expect("delivered history in snapshot");
    assert_eq!(
        snapshot.canonical_digest(),
        snapshot.clone().canonical_digest()
    );
    snapshot.records[0].source.source_revision = "changed".to_owned();
    assert!(snapshot.validate().is_err());
}

#[test]
fn retained_partial_snapshot_allows_equal_known_denominator() {
    let mut snapshot = empty_snapshot();
    snapshot.denominator.completeness = eliot_context_contracts::SnapshotCompleteness::Partial;
    snapshot.denominator.observed = 2;
    snapshot.denominator.expected = Some(2);
    let mut unknown = support::unknown_record();
    snapshot.records.push(unknown.clone());
    unknown.record_id = "record-2".to_owned();
    unknown.item_id = "item-2".to_owned();
    unknown.operation_id = eliot_contracts::OperationId::new("operation-2").expect("operation");
    unknown.request_id = eliot_contracts::RequestId::new("request-2").expect("request");
    unknown.idempotency_key = "idempotency-2".to_owned();
    unknown.replay_identity = "replay-2".to_owned();
    unknown.stage = eliot_protocol::ReactiveContextStage::DeliveryAttempted;
    unknown.lifecycle.stage = eliot_protocol::ReactiveContextStage::DeliveryAttempted;
    unknown.lifecycle.predecessor = Some(eliot_protocol::ReactiveContextStage::EnqueuedPersisted);
    snapshot.records.push(unknown);
    snapshot.snapshot_digest = snapshot.canonical_digest().expect("snapshot digest");
    snapshot.validate().expect("partial snapshot is retained");
}

#[test]
fn attention_acknowledgement_does_not_resolve_obligation() {
    let member = open_attention();
    assert_eq!(
        member.acknowledgement,
        eliot_context_contracts::AttentionAcknowledgement::Acknowledged
    );
    assert_eq!(member.resolution, AttentionResolution::Open);
    member.validate().expect("acknowledged open attention");

    let mut terminal = member;
    terminal.resolution = AttentionResolution::Resolved;
    assert!(terminal.validate().is_err());
    let mut resolved = support::resolved_attention();
    let (_context, _payload, _event, _ack, receipt, _assembly, _profile) =
        support::delivered_fixture();
    let mut core = receipt.core;
    core.authority.authority_owner = resolved.owner_id.clone();
    core.artifacts.push(eliot_receipts::ArtifactBinding {
        artifact_id: resolved.attention_id.clone(),
        sha256: resolved.claim_digest.clone(),
        role: eliot_receipts::ReceiptKind::Artifact,
        source_revision: Some(resolved.source_revision.clone()),
    });
    core.artifacts.push(eliot_receipts::ArtifactBinding {
        artifact_id: resolved.claim_artifact_id.clone(),
        sha256: resolved.claim_digest.clone(),
        role: eliot_receipts::ReceiptKind::Artifact,
        source_revision: Some(resolved.source_revision.clone()),
    });
    resolved.owner_closure.receipts =
        vec![eliot_receipts::ReceiptEnvelope::issue(core).expect("attention claim receipt")];
    resolved
        .validate()
        .expect("terminal attention retains owner evidence");

    let mut waived = support::open_attention();
    waived.resolution = AttentionResolution::Waived;
    waived.waiver_authority = Some("waiver-authority".to_owned());
    waived.claim_digest = waived
        .canonical_resolution_claim_digest()
        .expect("waiver claim digest");
    let (_context, _payload, _event, _ack, receipt, _assembly, _profile) =
        support::delivered_fixture();
    let mut waiver_core = receipt.core;
    waiver_core.authority.authority_owner = "waiver-authority".to_owned();
    waiver_core.artifacts.push(eliot_receipts::ArtifactBinding {
        artifact_id: waived.attention_id.clone(),
        sha256: waived.claim_digest.clone(),
        role: eliot_receipts::ReceiptKind::Artifact,
        source_revision: Some(waived.source_revision.clone()),
    });
    waiver_core.artifacts.push(eliot_receipts::ArtifactBinding {
        artifact_id: waived.claim_artifact_id.clone(),
        sha256: waived.claim_digest.clone(),
        role: eliot_receipts::ReceiptKind::Artifact,
        source_revision: Some(waived.source_revision.clone()),
    });
    waived.owner_closure.resolution_receipt =
        Some(eliot_receipts::ReceiptEnvelope::issue(waiver_core).expect("waiver receipt"));
    waived.validate().expect("named waiver authority receipt");

    let mut superseded = support::open_attention();
    superseded.resolution = AttentionResolution::Superseded;
    let mut replacement = support::content_ref();
    replacement.artifact_id = Some(support::id("replacement"));
    superseded.superseded_by = Some(replacement.clone());
    superseded.claim_digest = superseded
        .canonical_resolution_claim_digest()
        .expect("supersession claim digest");
    let (_context, _payload, _event, _ack, receipt, _assembly, _profile) =
        support::delivered_fixture();
    let mut supersession_core = receipt.core;
    supersession_core.authority.authority_owner = superseded.owner_id.clone();
    supersession_core
        .artifacts
        .push(eliot_receipts::ArtifactBinding {
            artifact_id: superseded.attention_id.clone(),
            sha256: superseded.claim_digest.clone(),
            role: eliot_receipts::ReceiptKind::Artifact,
            source_revision: Some(superseded.source_revision.clone()),
        });
    supersession_core
        .artifacts
        .push(eliot_receipts::ArtifactBinding {
            artifact_id: superseded.claim_artifact_id.clone(),
            sha256: superseded.claim_digest.clone(),
            role: eliot_receipts::ReceiptKind::Artifact,
            source_revision: Some(superseded.source_revision.clone()),
        });
    supersession_core
        .artifacts
        .push(eliot_receipts::ArtifactBinding {
            artifact_id: replacement.artifact_id.clone().expect("replacement id"),
            sha256: replacement.content_sha256.clone(),
            role: eliot_receipts::ReceiptKind::Artifact,
            source_revision: Some(replacement.source_revision.clone()),
        });
    superseded.owner_closure.resolution_receipt = Some(
        eliot_receipts::ReceiptEnvelope::issue(supersession_core).expect("supersession receipt"),
    );
    superseded
        .validate()
        .expect("explicit replacement owner receipt");
}

#[test]
fn coverage_profile_binds_each_event_to_profile_identity() {
    let mut coverage = profile();
    coverage.profile_digest = coverage.canonical_digest().expect("coverage digest");
    coverage.validate().expect("coverage profile");
    coverage.events[0].host_id = "other-host".to_owned();
    coverage.events[0].claim_digest = coverage.events[0]
        .canonical_claim_digest()
        .expect("resealed event claim digest");
    coverage.profile_digest = coverage
        .canonical_digest()
        .expect("resealed profile digest");
    assert!(matches!(
        coverage.validate(),
        Err(ReactiveInputError::BindingMismatch {
            field: "coverage.event_profile_binding"
        })
    ));
    let mut event = coverage_event();
    event.event = "vendor-hook".to_owned();
    assert!(matches!(
        event.validate(),
        Err(ReactiveInputError::InvalidField {
            field: "coverage.event",
            ..
        })
    ));
    event.event = "UNKNOWN:vendor-hook".to_owned();
    event.claim_digest = event
        .canonical_claim_digest()
        .expect("unknown claim digest");
    event.validate().expect("explicitly unknown event");

    let (_context, payload, _envelope, _ack, receipt, _assembly, _profile) =
        support::delivered_fixture();
    let mut fresh = coverage_event();
    fresh.freshness = eliot_context_contracts::CoverageFreshness::Fresh;
    fresh.source.artifact_id =
        Some(eliot_contracts::ArtifactId::new("representation").expect("artifact"));
    fresh.source.content_sha256 = payload.view.representation.content_sha256;
    let mut owner_evidence = support::owner_evidence();
    owner_evidence.provenance.raw_handle = Some(fresh.source.content_sha256.clone());
    fresh.evidence = vec![owner_evidence];
    fresh.claim_digest = fresh.canonical_claim_digest().expect("fresh claim digest");
    let mut core = receipt.core;
    core.authority.authority_owner = fresh.owner_id.clone();
    core.artifacts.push(eliot_receipts::ArtifactBinding {
        artifact_id: fresh.claim_artifact_id.clone(),
        sha256: fresh.claim_digest.clone(),
        role: eliot_receipts::ReceiptKind::Artifact,
        source_revision: Some(fresh.source.source_revision.clone()),
    });
    fresh.receipts = vec![eliot_receipts::ReceiptEnvelope::issue(core).expect("claim receipt")];
    fresh
        .validate()
        .expect("fresh capability evidence and receipt");
}
