#![allow(clippy::expect_used, clippy::too_many_lines)]

mod support;

use std::collections::{BTreeMap, BTreeSet};

use eliot_dreamer_claim_grounding::{
    Cancellation, GroundingControls, GroundingRequest, ground_draft, ground_draft_with_controls,
};
use eliot_dreamer_contracts::grounding::canonical::{GradeAssignment, SupportResult};
use eliot_dreamer_contracts::grounding::{ClaimKind, PrecisionPayload};
use support::{
    CAUSAL_CONTENT, artifact, causal_payload, claim, claim_with_components, claim_with_payload,
    comparative_payload, complete_absence_payload, draft, identity_payload, job, manifest_for,
    manifest_for_typed, non_material_claim, policy, quote_payload, recommendation_payload,
    refresh_claim, refresh_draft, refresh_manifest, refresh_policy, support_for,
    temporal_payload, temporal_record, temporal_support_for,
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

// WORK_UNIT_CASE: 602/1
#[test]
fn valid_complete_structured_draft_manifest_reconciles() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let draft = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft.bundle.clone(),
        manifest.clone(),
        draft.clone(),
        policy(),
    )
    .expect("valid complete grounded");
    assert_eq!(
        grounded.ledger.expected_claim_ids,
        BTreeSet::from(["claim-1".to_owned()])
    );
    assert!(grounded.ledger.unprocessed_claim_ids.is_empty());
    assert!(grounded.ledger.unprocessed_reason.is_none());
    assert_eq!(
        grounded.ledger.records["claim-1"].disposition,
        SupportResult::Supported
    );
    assert_eq!(grounded.draft_digest, draft.draft_digest);
    assert_eq!(grounded.manifest_digest, manifest.digest);
    assert_eq!(grounded.output_digest, grounded.computed_digest().expect("output digest"));
    grounded.validate().expect("valid handoff");
}

// WORK_UNIT_CASE: 602/2
#[test]
fn exact_claim_kind_and_disposition_vocabulary_is_closed() {
    let kinds = [
        (ClaimKind::NumericQuantified, support::payload()),
        (ClaimKind::TemporalVersioned, temporal_payload()),
        (ClaimKind::Causal, causal_payload()),
        (
            ClaimKind::AbsenceExhaustiveNegative,
            complete_absence_payload().0,
        ),
        (ClaimKind::ComparativeSuperlative, comparative_payload()),
        (ClaimKind::QuoteAttribution, quote_payload()),
        (
            ClaimKind::RecommendationNormativeInference,
            recommendation_payload(),
        ),
        (ClaimKind::IdentityEntity, identity_payload()),
    ];
    assert_eq!(kinds.len(), 8);
    for (kind, payload) in &kinds {
        assert_eq!(&payload.kind(), kind);
        let debug = format!("{kind:?}");
        assert!(!debug.to_lowercase().contains("other"), "no catch-all Other: {debug}");
    }
    let policy_kinds = policy().permitted_kinds;
    for (kind, _) in &kinds {
        assert!(policy_kinds.contains(kind), "policy admits {kind:?}");
    }
    let dispositions = [
        SupportResult::Supported,
        SupportResult::Partial,
        SupportResult::Contradicted,
        SupportResult::Unsupported,
        SupportResult::Unknown,
        SupportResult::OutsideManifest,
        SupportResult::Stale,
        SupportResult::Superseded,
        SupportResult::JustifiedNotApplicable,
    ];
    assert_eq!(dispositions.len(), 9);
    let mut seen = BTreeSet::new();
    for disposition in dispositions {
        let debug = format!("{disposition:?}");
        assert!(seen.insert(debug.clone()), "distinct disposition: {debug}");
        assert!(!debug.to_lowercase().contains("other"), "no Other: {debug}");
    }
    for (kind, _) in &kinds {
        let covered = match kind {
            ClaimKind::NumericQuantified
            | ClaimKind::TemporalVersioned
            | ClaimKind::Causal
            | ClaimKind::AbsenceExhaustiveNegative
            | ClaimKind::ComparativeSuperlative
            | ClaimKind::QuoteAttribution
            | ClaimKind::RecommendationNormativeInference
            | ClaimKind::IdentityEntity => true,
        };
        assert!(covered, "exhaustive match proves closed vocabulary");
    }
}

// WORK_UNIT_CASE: 602/3
#[test]
fn duplicate_changed_and_denominator_identities_are_exact() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let base = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let mut duplicated = base.clone();
    duplicated.claims.push(claim("claim-1", "proposition-1", Some("evidence-1")));
    assert!(
        duplicated.computed_digest().is_err(),
        "duplicate identity cannot normalize"
    );
    let mut changed = claim("claim-1", "proposition-1", Some("evidence-1"));
    changed.proposition =
        eliot_dreamer_contracts::grounding::PropositionId::new("proposition-changed")
            .expect("proposition");
    changed.proposition_digest =
        eliot_dreamer_contracts::grounding::proposition_content_digest(&changed.kind, &changed.payload)
            .expect("digest");
    changed.component_digests = BTreeMap::from([(
        "value".to_owned(),
        eliot_dreamer_contracts::grounding::component_content_digest(
            &changed.proposition,
            "value",
        )
        .expect("component"),
    )]);
    refresh_claim(&mut changed);
    assert_ne!(
        changed.source_preimage_digest,
        base.claims[0].source_preimage_digest
    );
    let changed_draft = draft(
        &manifest,
        vec![changed],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        changed_draft.bundle.clone(),
        manifest.clone(),
        changed_draft,
        policy(),
    )
    .expect("changed proposition grounds");
    assert_eq!(
        grounded.ledger.records["claim-1"].disposition,
        SupportResult::Unknown
    );
    let grounded_base = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        base.bundle.clone(),
        manifest.clone(),
        base.clone(),
        policy(),
    )
    .expect("base grounds");
    assert_eq!(
        grounded_base.ledger.expected_claim_ids,
        BTreeSet::from(["claim-1".to_owned()])
    );
    assert_eq!(
        grounded_base.ledger.records.len(),
        grounded_base.ledger.expected_claim_ids.len()
    );
}

// WORK_UNIT_CASE: 602/4
#[test]
fn context_mismatches_are_typed_errors() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let draft = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let mut bad_job = job(
        manifest.digest.clone(),
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    bad_job.frozen_manifest_digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
    assert!(
        ground_draft(
            bad_job,
            draft.bundle.clone(),
            manifest.clone(),
            draft.clone(),
            policy()
        )
        .is_err(),
        "frozen manifest mismatch must fail"
    );
    let mut other_job = job(
        manifest.digest.clone(),
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    other_job.operation_id = "other-operation".into();
    assert!(
        ground_draft(
            other_job,
            draft.bundle.clone(),
            manifest.clone(),
            draft.clone(),
            policy()
        )
        .is_err(),
        "job drift from draft must fail"
    );
    let mut bad_manifest = manifest.clone();
    bad_manifest.scope_id = "other-scope".into();
    refresh_manifest(&mut bad_manifest);
    assert!(
        ground_draft(
            job(
                manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            draft.bundle.clone(),
            bad_manifest,
            draft.clone(),
            policy()
        )
        .is_err(),
        "manifest scope drift must fail"
    );
    let mut bad_route = draft.clone();
    bad_route.route.fingerprint =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into();
    refresh_draft(&mut bad_route);
    assert!(
        ground_draft(
            job(
                manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            bad_route.bundle.clone(),
            manifest.clone(),
            bad_route,
            policy()
        )
        .is_err(),
        "route fingerprint drift must fail"
    );
}

// WORK_UNIT_CASE: 602/5
#[test]
fn replay_is_deterministic_and_same_id_conflicts_invalidate() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let draft = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let job_value = job(
        manifest.digest.clone(),
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let first = ground_draft(
        job_value.clone(),
        draft.bundle.clone(),
        manifest.clone(),
        draft.clone(),
        policy(),
    )
    .expect("first replay");
    let second = ground_draft(
        job_value.clone(),
        draft.bundle.clone(),
        manifest.clone(),
        draft.clone(),
        policy(),
    )
    .expect("second replay");
    assert_eq!(first.output_digest, second.output_digest);
    assert_eq!(first.ledger.ledger_digest, second.ledger.ledger_digest);
    let mut changed_claim = claim("claim-1", "proposition-1", None);
    refresh_claim(&mut changed_claim);
    let mut changed_draft = draft.clone();
    changed_draft.claims = vec![changed_claim];
    refresh_draft(&mut changed_draft);
    let changed = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        changed_draft.bundle.clone(),
        manifest.clone(),
        changed_draft,
        policy(),
    )
    .expect("changed draft grounds");
    assert_ne!(first.output_digest, changed.output_digest);
    assert_eq!(
        changed.ledger.records["claim-1"].disposition,
        SupportResult::Unknown
    );
    let mut other_manifest = manifest.clone();
    other_manifest.source_revision = "revision-other".into();
    refresh_manifest(&mut other_manifest);
    assert!(
        ground_draft(
            job_value,
            draft.bundle.clone(),
            other_manifest,
            draft,
            policy()
        )
        .is_err(),
        "manifest conflict must fail bindings"
    );
}

// WORK_UNIT_CASE: 602/6
#[test]
fn absent_stale_and_revision_mismatched_handles_are_preserved() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let mut absent_claim = claim("claim-absent", "proposition-1", Some("evidence-1"));
    absent_claim.proposed_support = BTreeSet::from([support::artifact("missing-evidence")]);
    refresh_claim(&mut absent_claim);
    let absent_draft = draft(
        &manifest,
        vec![absent_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let absent = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        absent_draft.bundle.clone(),
        manifest.clone(),
        absent_draft,
        policy(),
    )
    .expect("absent handle grounds");
    let absent_record = &absent.ledger.records["claim-absent"];
    assert_eq!(absent_record.disposition, SupportResult::OutsideManifest);
    assert!(absent_record.unresolved_support.contains(&support::artifact("missing-evidence")));
    assert!(!absent_record.unknowns.is_empty());

    let mut stale_manifest = manifest.clone();
    let stale_ref = stale_manifest
        .references
        .get_mut(&support::artifact("evidence-1"))
        .expect("reference");
    stale_ref.stale = true;
    refresh_manifest(&mut stale_manifest);
    let stale_draft = draft(
        &stale_manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let stale = ground_draft(
        job(
            stale_manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        stale_draft.bundle.clone(),
        stale_manifest,
        stale_draft,
        policy(),
    )
    .expect("stale handle grounds");
    assert_eq!(stale.ledger.records["claim-1"].disposition, SupportResult::Stale);
    assert!(!stale.ledger.records["claim-1"].rejected_support.is_empty());

    let temporal_manifest = manifest_for_typed(
        "proposition-temporal",
        temporal_payload(),
        Some(temporal_support_for("proposition-temporal")),
        None,
        None,
        support::DIGEST,
    );
    let mut revised_payload = temporal_payload();
    if let PrecisionPayload::TemporalVersioned { revision, .. } = &mut revised_payload {
        *revision = "revision-old".into();
    }
    let revised_claim =
        claim_with_payload("claim-temporal", "proposition-temporal", revised_payload, Some("evidence-1"));
    let revised_draft = draft(
        &temporal_manifest,
        vec![revised_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let revised = ground_draft(
        job(
            temporal_manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        revised_draft.bundle.clone(),
        temporal_manifest,
        revised_draft,
        policy(),
    )
    .expect("revision mismatch grounds");
    assert_eq!(
        revised.ledger.records["claim-temporal"].disposition,
        SupportResult::Unknown
    );
}

// WORK_UNIT_CASE: 602/7
#[test]
fn url_looking_text_without_manifest_identity_cannot_support() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let mut url_claim = claim("claim-url", "proposition-1", Some("evidence-1"));
    url_claim.proposed_support =
        BTreeSet::from([support::artifact("https://example.com/paper")]);
    refresh_claim(&mut url_claim);
    let url_draft = draft(
        &manifest,
        vec![url_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        url_draft.bundle.clone(),
        manifest.clone(),
        url_draft,
        policy(),
    )
    .expect("url handle grounds");
    let record = &grounded.ledger.records["claim-url"];
    assert_eq!(record.disposition, SupportResult::OutsideManifest);
    assert!(record.witnesses.is_empty());
    assert!(record.accepted_support.is_empty());
    let bare = draft(
        &manifest,
        vec![claim("claim-bare", "proposition-1", None)],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let bare_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        bare.bundle.clone(),
        manifest,
        bare,
        policy(),
    )
    .expect("bare claim grounds");
    assert_eq!(
        bare_grounded.ledger.records["claim-bare"].disposition,
        SupportResult::Unknown
    );
    assert!(bare_grounded.ledger.records["claim-bare"].witnesses.is_empty());
}

// WORK_UNIT_CASE: 602/8
#[test]
fn unresolved_lineage_and_transform_without_provenance_stay_unknown() {
    let mut manifest = manifest_for("proposition-1", Some(supported_record()));
    let reference = manifest
        .references
        .get_mut(&support::artifact("evidence-1"))
        .expect("reference");
    let mut lineage = reference.source_lineage.clone().expect("lineage");
    lineage.predecessors = BTreeSet::from([
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()
    ]);
    reference.source_lineage = Some(lineage);
    refresh_manifest(&mut manifest);
    let draft_unclosed = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let unclosed = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft_unclosed.bundle.clone(),
        manifest.clone(),
        draft_unclosed,
        policy(),
    )
    .expect("unclosed lineage grounds");
    assert_eq!(
        unclosed.ledger.records["claim-1"].disposition,
        SupportResult::Unknown
    );
    assert!(!unclosed.ledger.records["claim-1"].unknowns.is_empty());

    let mut bare_manifest = manifest_for("proposition-1", Some(supported_record()));
    let bare_ref = bare_manifest
        .references
        .get_mut(&support::artifact("evidence-1"))
        .expect("reference");
    bare_ref.source_lineage = None;
    bare_ref.provenance = None;
    refresh_manifest(&mut bare_manifest);
    let bare_draft = draft(
        &bare_manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let bare = ground_draft(
        job(
            bare_manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        bare_draft.bundle.clone(),
        bare_manifest,
        bare_draft,
        policy(),
    )
    .expect("transform without provenance grounds");
    assert_eq!(
        bare.ledger.records["claim-1"].disposition,
        SupportResult::Unknown
    );
    assert!(!bare.ledger.records["claim-1"].unknowns.is_empty());
}

// WORK_UNIT_CASE: 602/9
#[test]
fn privacy_disclosure_and_assurance_mismatch_are_bounded() {
    let mut manifest = manifest_for("proposition-1", Some(supported_record()));
    let reference = manifest
        .references
        .get_mut(&support::artifact("evidence-1"))
        .expect("reference");
    reference.privacy =
        eliot_dreamer_contracts::grounding::canonical::PrivacyHandling::Purged;
    reference.disclosure =
        eliot_dreamer_contracts::grounding::canonical::DisclosureClass::Restricted;
    refresh_manifest(&mut manifest);
    let draft_value = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft_value.bundle.clone(),
        manifest.clone(),
        draft_value,
        policy(),
    )
    .expect("restricted handling grounds");
    let record = &grounded.ledger.records["claim-1"];
    assert_eq!(record.disposition, SupportResult::Supported);
    assert_eq!(
        record.assertability_ceiling,
        eliot_dreamer_contracts::grounding::canonical::PositionAssertability::HypothesisCandidate
    );

    let mut bad_manifest = manifest_for("proposition-1", Some(supported_record()));
    let bad_ref = bad_manifest
        .references
        .get_mut(&support::artifact("evidence-1"))
        .expect("reference");
    bad_ref.source_assurance = Some(
        eliot_dreamer_contracts::grounding::canonical::SourceAssurance::new(
            eliot_dreamer_contracts::grounding::canonical::SourceId::new("other-source")
                .expect("source"),
            eliot_dreamer_contracts::grounding::canonical::SourceRevisionId::new(
                "revision-grounding",
            )
            .expect("revision"),
            support::DIGEST,
        )
        .expect("assurance"),
    );
    assert!(
        bad_manifest.computed_digest().is_ok(),
        "digest preimage still canonical"
    );
    refresh_manifest(&mut bad_manifest);
    let bad_draft = draft(
        &bad_manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    assert!(
        ground_draft(
            job(
                bad_manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            bad_draft.bundle.clone(),
            bad_manifest,
            bad_draft,
            policy(),
        )
        .is_err(),
        "assurance owner drift must fail closed"
    );
}

// WORK_UNIT_CASE: 602/10
#[test]
fn fully_supported_claim_covers_every_material_component() {
    let mut manifest = manifest_for("proposition-1", Some(supported_record()));
    let reference = manifest
        .references
        .get_mut(&support::artifact("evidence-1"))
        .expect("reference");
    let mut second = reference.assertions[0].clone();
    second.assertion_id = "assertion-2".into();
    second.component = "detail".into();
    reference.assertions.push(second);
    refresh_manifest(&mut manifest);
    let full_claim = claim_with_components(
        "claim-full",
        "proposition-1",
        support::payload(),
        Some("evidence-1"),
        &["detail"],
    );
    assert_eq!(full_claim.component_digests.len(), 2);
    let full_draft = draft(
        &manifest,
        vec![full_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        full_draft.bundle.clone(),
        manifest,
        full_draft,
        policy(),
    )
    .expect("fully supported grounds");
    let record = &grounded.ledger.records["claim-full"];
    assert_eq!(record.disposition, SupportResult::Supported);
    assert_eq!(record.component_outcomes.len(), 2);
    assert!(
        record.component_outcomes.values().all(|outcome| *outcome == SupportResult::Supported)
    );
    assert_eq!(record.witnesses.len(), 2);
    grounded.validate().expect("valid handoff");
}

// WORK_UNIT_CASE: 602/11
#[test]
fn no_handle_yields_unknown_without_manifest_search() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let draft_value = draft(
        &manifest,
        vec![claim("claim-bare", "proposition-1", None)],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft_value.bundle.clone(),
        manifest,
        draft_value,
        policy(),
    )
    .expect("bare claim grounds");
    let record = &grounded.ledger.records["claim-bare"];
    assert_eq!(record.disposition, SupportResult::Unknown);
    assert!(record.witnesses.is_empty());
    assert!(record.accepted_support.is_empty());
    assert!(record.accepted_counterevidence.is_empty());
    assert_eq!(record.component_outcomes["value"], SupportResult::Unknown);
}

// WORK_UNIT_CASE: 602/12
#[test]
fn partial_subclaim_closure_is_explicit() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let child_supported = claim("child-1", "proposition-1", Some("evidence-1"));
    let child_unknown = claim("child-2", "proposition-2", None);
    let mut parent = claim("parent", "proposition-1", None);
    parent.component_digests = BTreeMap::new();
    parent.subclaim_ids = BTreeSet::from(["child-1".to_owned(), "child-2".to_owned()]);
    refresh_claim(&mut parent);
    let draft_value = draft(
        &manifest,
        vec![child_supported, child_unknown, parent],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft_value.bundle.clone(),
        manifest,
        draft_value,
        policy(),
    )
    .expect("subclaim closure grounds");
    assert_eq!(
        grounded.ledger.records["child-1"].disposition,
        SupportResult::Supported
    );
    assert_eq!(
        grounded.ledger.records["child-2"].disposition,
        SupportResult::Unknown
    );
    assert_eq!(
        grounded.ledger.records["parent"].disposition,
        SupportResult::Partial
    );
}
