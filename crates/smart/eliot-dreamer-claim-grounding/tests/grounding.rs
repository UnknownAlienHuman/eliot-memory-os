#![allow(clippy::expect_used, clippy::too_many_lines)]

mod support;

use std::collections::BTreeSet;

use eliot_dreamer_claim_grounding::{
    Cancellation, GroundingControls, GroundingRequest, ground_draft, ground_draft_with_controls,
};
use eliot_dreamer_contracts::grounding::canonical::{GradeAssignment, SupportResult};
use support::{
    CAUSAL_CONTENT, artifact, causal_payload, claim, claim_with_payload, complete_absence_payload,
    draft, job, manifest_for, manifest_for_typed, policy,
};

fn supported_record() -> eliot_dreamer_contracts::grounding::canonical::SupportRecord {
    eliot_dreamer_contracts::grounding::canonical::SupportRecord {
        proposition: eliot_dreamer_contracts::grounding::PropositionId::new("proposition-1")
            .expect("proposition"),
        result: SupportResult::Supported,
        handles: BTreeSet::from([artifact("evidence-1")]),
        validity: eliot_dreamer_contracts::grounding::canonical::ValidityBounds {
            scope: "grounding-scope".into(),
            window_start_ms: None,
            window_end_ms: None,
            version: "revision-grounding".into(),
            precision: "file".into(),
        },
        grade: GradeAssignment::known(
            eliot_dreamer_contracts::grounding::canonical::EvidenceGrade::Grounded,
        ),
        task_id: support::task(),
        fence: support::fence(),
        temporal: None,
        assurance: None,
        reopen_reason: None,
        proof_digest: support::DIGEST.into(),
    }
}

#[test]
fn exact_typed_assertion_is_the_only_support_witness() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let draft = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let job = job(
        manifest.digest.clone(),
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let grounded = ground_draft(job, draft.bundle.clone(), manifest.clone(), draft, policy())
        .expect("grounded");
    let record = &grounded.ledger.records["claim-1"];
    assert_eq!(record.disposition, SupportResult::Supported);
    assert_eq!(
        record.accepted_support,
        BTreeSet::from([artifact("evidence-1")])
    );
    assert_eq!(record.witnesses.len(), 1);
    grounded.validate().expect("validated handoff");
}

#[test]
fn contradiction_wins_and_counterevidence_is_retained() {
    let mut manifest = manifest_for("proposition-1", Some(supported_record()));
    let mut contradiction = manifest.references[&artifact("evidence-1")].assertions[0].clone();
    contradiction.assertion_id = "assertion-contradiction".into();
    let contradiction_support = contradiction.support.as_mut().expect("support");
    contradiction_support.result = SupportResult::Contradicted;
    contradiction_support.handles = BTreeSet::from([artifact("evidence-2")]);
    let mut counter_reference = manifest.references[&artifact("evidence-1")].clone();
    counter_reference.handle = artifact("evidence-2");
    counter_reference.assertions = vec![contradiction];
    manifest
        .references
        .insert(artifact("evidence-2"), counter_reference);
    manifest.digest = manifest.computed_digest().expect("manifest digest");
    let mut material_claim = claim("claim-1", "proposition-1", Some("evidence-1"));
    material_claim
        .proposed_counterevidence
        .insert(artifact("evidence-2"));
    material_claim.source_preimage_digest = material_claim.computed_digest().expect("claim digest");
    let draft = draft(
        &manifest,
        vec![material_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let grounded = ground_draft(
        draft.job.clone(),
        draft.bundle.clone(),
        manifest,
        draft,
        policy(),
    )
    .expect("grounded");
    assert_eq!(
        grounded.ledger.records["claim-1"].disposition,
        SupportResult::Contradicted
    );
    assert!(
        !grounded.ledger.records["claim-1"]
            .accepted_support
            .is_empty()
    );
    assert_eq!(
        grounded.ledger.records["claim-1"].accepted_counterevidence,
        BTreeSet::from([artifact("evidence-2")])
    );
    assert_eq!(grounded.ledger.records["claim-1"].witnesses.len(), 2);
}

#[test]
fn quota_preserves_the_exact_unprocessed_suffix() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let claims = vec![
        claim("claim-1", "proposition-1", Some("evidence-1")),
        claim("claim-2", "proposition-2", Some("evidence-1")),
    ];
    let draft = draft(
        &manifest,
        claims,
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let request = GroundingRequest::new(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft.bundle.clone(),
        manifest,
        draft,
        policy(),
    )
    .with_controls(GroundingControls {
        whole_claim_quota: Some(1),
        cancellation: Cancellation::NotCancelled,
        deadline_exceeded: false,
    });
    let grounded = ground_draft_with_controls(request).expect("bounded result");
    assert_eq!(
        grounded.ledger.unprocessed_claim_ids,
        BTreeSet::from(["claim-2".into()])
    );
    assert_eq!(
        grounded.ledger.unprocessed_reason.as_deref(),
        Some("whole-claim quota exhausted")
    );
}

#[test]
fn curation_without_exact_screen_binding_cannot_be_supported() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let base = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Curation,
    );
    let screen = support::eligible_screen();
    let mut screened = base.clone();
    screened.screen = Some(screen.clone());
    screened.claims[0].screen_target = Some(support::screen_target(screen));
    screened.claims[0].source_preimage_digest = screened.claims[0]
        .computed_digest()
        .expect("screened claim digest");
    screened.draft_digest = screened.computed_digest().expect("screened draft digest");
    let grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Curation,
        ),
        screened.bundle.clone(),
        manifest.clone(),
        screened.clone(),
        policy(),
    )
    .expect("grounded");
    assert_eq!(
        grounded.ledger.records["claim-1"].disposition,
        SupportResult::Supported
    );
    assert_eq!(grounded.screen, screened.screen);
    assert_eq!(
        grounded.input.claims[0].screen_target,
        screened.claims[0].screen_target
    );

    let mut absent = screened.clone();
    absent.claims[0].screen_target = None;
    absent.claims[0].source_preimage_digest = absent.claims[0]
        .computed_digest()
        .expect("absent claim digest");
    absent.draft_digest = absent.computed_digest().expect("absent draft digest");
    let grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Curation,
        ),
        absent.bundle.clone(),
        manifest.clone(),
        absent,
        policy(),
    )
    .expect("absent binding grounded");
    assert_eq!(
        grounded.ledger.records["claim-1"].disposition,
        SupportResult::Unknown
    );

    let mut changed = screened;
    let target = changed.claims[0].screen_target.as_mut().expect("target");
    target.screen.profile = "changed-profile".into();
    changed.claims[0].source_preimage_digest = changed.claims[0]
        .computed_digest()
        .expect("changed claim digest");
    changed.draft_digest = changed.computed_digest().expect("changed draft digest");
    let grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Curation,
        ),
        changed.bundle.clone(),
        manifest,
        changed,
        policy(),
    )
    .expect("changed binding grounded");
    assert_eq!(
        grounded.ledger.records["claim-1"].disposition,
        SupportResult::Unknown
    );
}

#[test]
fn causal_precision_requires_a_closed_mechanism_relation() {
    let payload = causal_payload();
    let (lineage, assurance) = match &payload {
        eliot_dreamer_contracts::grounding::PrecisionPayload::Causal { causal } => {
            (causal.source_lineage.clone(), causal.assurance.clone())
        }
        _ => panic!("causal payload"),
    };
    let mut support = supported_record();
    support.proposition =
        eliot_dreamer_contracts::grounding::PropositionId::new("proposition-causal")
            .expect("proposition");
    let manifest = manifest_for_typed(
        "proposition-causal",
        payload.clone(),
        Some(support),
        Some(lineage),
        Some(assurance),
        CAUSAL_CONTENT,
    );
    let mut correlation_payload = payload.clone();
    if let eliot_dreamer_contracts::grounding::PrecisionPayload::Causal { causal } =
        &mut correlation_payload
    {
        causal.status = eliot_dreamer_contracts::grounding::canonical::CausalStatus::Correlation;
        causal.ceiling = eliot_dreamer_contracts::grounding::canonical::EvidenceGrade::Grounded;
        causal.digest = causal.compute_digest().expect("correlation digest");
    }
    let mut manifest = manifest;
    let mut correlation_assertion =
        manifest.references[&artifact("evidence-1")].assertions[0].clone();
    correlation_assertion.assertion_id = "assertion-correlation".into();
    correlation_assertion.precision = correlation_payload.clone();
    correlation_assertion.proposition_digest =
        eliot_dreamer_contracts::grounding::proposition_content_digest(
            &correlation_payload.kind(),
            &correlation_payload,
        )
        .expect("correlation proposition digest");
    manifest
        .references
        .get_mut(&artifact("evidence-1"))
        .expect("reference")
        .assertions
        .push(correlation_assertion);
    manifest.digest = manifest.computed_digest().expect("manifest digest");
    let draft = draft(
        &manifest,
        vec![
            claim_with_payload("causal", "proposition-causal", payload, Some("evidence-1")),
            claim_with_payload(
                "correlation",
                "proposition-causal",
                correlation_payload,
                Some("evidence-1"),
            ),
        ],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft.bundle.clone(),
        manifest,
        draft,
        policy(),
    )
    .expect("grounded");
    assert_eq!(
        grounded.ledger.records["causal"].disposition,
        SupportResult::Supported
    );
    assert_eq!(
        grounded.ledger.records["correlation"].disposition,
        SupportResult::Unknown
    );
}

#[test]
fn absence_requires_complete_closed_coverage() {
    let (complete_payload, denominator, receipt) = complete_absence_payload();
    let mut support = supported_record();
    support.proposition =
        eliot_dreamer_contracts::grounding::PropositionId::new("proposition-absence")
            .expect("proposition");
    let mut complete_manifest = manifest_for_typed(
        "proposition-absence",
        complete_payload.clone(),
        Some(support),
        None,
        None,
        support::DIGEST,
    );
    complete_manifest
        .coverage_denominators
        .insert(denominator.digest.clone(), denominator.clone());
    complete_manifest
        .coverage_receipts
        .insert(denominator.digest.clone(), receipt.clone());
    complete_manifest.digest = complete_manifest
        .computed_digest()
        .expect("manifest digest");
    let complete_draft = draft(
        &complete_manifest,
        vec![claim_with_payload(
            "absence",
            "proposition-absence",
            complete_payload,
            Some("evidence-1"),
        )],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let complete = ground_draft(
        job(
            complete_manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        complete_draft.bundle.clone(),
        complete_manifest,
        complete_draft,
        policy(),
    )
    .expect("complete");
    assert_eq!(
        complete.ledger.records["absence"].disposition,
        SupportResult::Supported
    );

    let mut partial_receipt = receipt;
    partial_receipt.members[0].disposition =
        eliot_dreamer_contracts::grounding::canonical::MemberDisposition::Unavailable;
    partial_receipt.digest = partial_receipt
        .compute_digest()
        .expect("partial receipt digest");
    let partial_payload =
        eliot_dreamer_contracts::grounding::PrecisionPayload::AbsenceExhaustiveNegative {
            domain: denominator.class.clone(),
            denominator: Box::new(denominator.clone()),
            receipt: Some(Box::new(partial_receipt.clone())),
            absence_proof: None,
        };
    let mut partial_support = supported_record();
    partial_support.proposition =
        eliot_dreamer_contracts::grounding::PropositionId::new("proposition-absence")
            .expect("proposition");
    let mut partial_manifest = manifest_for_typed(
        "proposition-absence",
        partial_payload.clone(),
        Some(partial_support),
        None,
        None,
        support::DIGEST,
    );
    partial_manifest
        .coverage_denominators
        .insert(denominator.digest.clone(), denominator.clone());
    partial_manifest
        .coverage_receipts
        .insert(denominator.digest.clone(), partial_receipt.clone());
    partial_manifest.digest = partial_manifest.computed_digest().expect("manifest digest");
    let partial_draft = draft(
        &partial_manifest,
        vec![claim_with_payload(
            "absence",
            "proposition-absence",
            partial_payload,
            Some("evidence-1"),
        )],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let partial = ground_draft(
        job(
            partial_manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        partial_draft.bundle.clone(),
        partial_manifest,
        partial_draft,
        policy(),
    )
    .expect("partial");
    assert_eq!(
        partial.ledger.records["absence"].disposition,
        SupportResult::Unknown
    );
}
