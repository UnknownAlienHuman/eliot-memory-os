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
    refresh_claim, refresh_draft, refresh_manifest, refresh_policy, support_for, temporal_payload,
    temporal_support_for,
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
    assert_eq!(
        grounded.output_digest,
        grounded.computed_digest().expect("output digest")
    );
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
        assert!(
            !debug.to_lowercase().contains("other"),
            "no catch-all Other: {debug}"
        );
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
    duplicated
        .claims
        .push(claim("claim-1", "proposition-1", Some("evidence-1")));
    assert!(
        duplicated.computed_digest().is_err(),
        "duplicate identity cannot normalize"
    );
    let mut changed = claim("claim-1", "proposition-1", Some("evidence-1"));
    changed.proposition =
        eliot_dreamer_contracts::grounding::PropositionId::new("proposition-changed")
            .expect("proposition");
    changed.proposition_digest = eliot_dreamer_contracts::grounding::proposition_content_digest(
        &changed.kind,
        &changed.payload,
    )
    .expect("digest");
    changed.component_digests = BTreeMap::from([(
        "value".to_owned(),
        eliot_dreamer_contracts::grounding::component_content_digest(&changed.proposition, "value")
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
    bad_job.frozen_manifest_digest =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
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
    let mut bad_task = draft.clone();
    bad_task.task_id = eliot_dreamer_contracts::grounding::canonical::TaskId::new("other-task")
        .expect("other task");
    refresh_draft(&mut bad_task);
    assert!(
        ground_draft(
            job(
                manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            bad_task.bundle.clone(),
            manifest.clone(),
            bad_task,
            policy()
        )
        .is_err(),
        "task drift must fail"
    );
    // AttemptIdentity binds the job attempts budget via attempt_number
    // (attempt_id is format-checked only), so bumping attempt_number past
    // maximum_attempts is the typed negative for attempt drift.
    let mut bad_attempt = draft.clone();
    bad_attempt.attempt.attempt_number = 2;
    refresh_draft(&mut bad_attempt);
    assert!(
        ground_draft(
            job(
                manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            bad_attempt.bundle.clone(),
            manifest.clone(),
            bad_attempt,
            policy()
        )
        .is_err(),
        "attempt drift must fail"
    );
    let alt_fence = eliot_dreamer_contracts::grounding::canonical::StateFence::new(
        eliot_dreamer_contracts::grounding::canonical::EpochId::new(
            eliot_dreamer_contracts::grounding::canonical::EpochLineageId::new(
                "550e8400-e29b-41d4-a716-446655440001",
            )
            .expect("alt lineage"),
            std::num::NonZeroU64::new(2).expect("non-zero sequence"),
        )
        .expect("alt epoch"),
        eliot_dreamer_contracts::grounding::canonical::ResourceGeneration::genesis(),
    );
    let mut bad_fence = draft.clone();
    bad_fence.state_fence = alt_fence;
    refresh_draft(&mut bad_fence);
    assert!(
        ground_draft(
            job(
                manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            bad_fence.bundle.clone(),
            manifest.clone(),
            bad_fence,
            policy()
        )
        .is_err(),
        "fence drift must fail"
    );
    // StructuredModelDraft::validate only format-checks raw_output_digest, so a
    // fresh valid digest still grounds; the drift must instead surface in the
    // output digest, which covers the retained input preimage.
    let mut bad_raw = draft.clone();
    bad_raw.raw_output_digest =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into();
    refresh_draft(&mut bad_raw);
    let base_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft.bundle.clone(),
        manifest.clone(),
        draft.clone(),
        policy(),
    )
    .expect("base draft grounds");
    let raw_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        bad_raw.bundle.clone(),
        manifest.clone(),
        bad_raw,
        policy(),
    )
    .expect("raw-output variant grounds");
    assert_ne!(
        base_grounded.output_digest, raw_grounded.output_digest,
        "raw-output drift must change the witness"
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
    assert!(
        absent_record
            .unresolved_support
            .contains(&support::artifact("missing-evidence"))
    );
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
    assert_eq!(
        stale.ledger.records["claim-1"].disposition,
        SupportResult::Stale
    );
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
    let revised_claim = claim_with_payload(
        "claim-temporal",
        "proposition-temporal",
        revised_payload,
        Some("evidence-1"),
    );
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
    url_claim.proposed_support = BTreeSet::from([support::artifact("https://example.com/paper")]);
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
    assert!(
        bare_grounded.ledger.records["claim-bare"]
            .witnesses
            .is_empty()
    );
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
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
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
    reference.privacy = eliot_dreamer_contracts::grounding::canonical::PrivacyHandling::Purged;
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
        record
            .component_outcomes
            .values()
            .all(|outcome| *outcome == SupportResult::Supported)
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

// WORK_UNIT_CASE: 602/13
#[test]
fn contradictory_support_and_counterevidence_are_both_preserved() {
    let mut manifest = manifest_for("proposition-1", Some(supported_record()));
    let mut contradiction =
        manifest.references[&support::artifact("evidence-1")].assertions[0].clone();
    contradiction.assertion_id = "assertion-contradiction".into();
    let contradiction_support = contradiction.support.as_mut().expect("support");
    contradiction_support.result = SupportResult::Contradicted;
    contradiction_support.handles = BTreeSet::from([support::artifact("evidence-2")]);
    let mut counter_reference = manifest.references[&support::artifact("evidence-1")].clone();
    counter_reference.handle = support::artifact("evidence-2");
    counter_reference.assertions = vec![contradiction];
    manifest
        .references
        .insert(support::artifact("evidence-2"), counter_reference);
    refresh_manifest(&mut manifest);
    let mut material_claim = claim("claim-1", "proposition-1", Some("evidence-1"));
    material_claim
        .proposed_counterevidence
        .insert(support::artifact("evidence-2"));
    refresh_claim(&mut material_claim);
    let draft_value = draft(
        &manifest,
        vec![material_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let grounded = ground_draft(
        draft_value.job.clone(),
        draft_value.bundle.clone(),
        manifest,
        draft_value,
        policy(),
    )
    .expect("contradiction grounds");
    let record = &grounded.ledger.records["claim-1"];
    assert_eq!(record.disposition, SupportResult::Contradicted);
    assert!(!record.accepted_support.is_empty());
    assert_eq!(
        record.accepted_counterevidence,
        BTreeSet::from([support::artifact("evidence-2")])
    );
    assert_eq!(record.witnesses.len(), 2);
}

// WORK_UNIT_CASE: 602/14
#[test]
fn related_but_not_entailing_evidence_stays_unsupported() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let mut related_payload = support::payload();
    if let PrecisionPayload::NumericQuantified { value, .. } = &mut related_payload {
        *value = "99".into();
    }
    let related = claim_with_payload(
        "claim-related",
        "proposition-1",
        related_payload,
        Some("evidence-1"),
    );
    let related_draft = draft(
        &manifest,
        vec![related],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        related_draft.bundle.clone(),
        manifest.clone(),
        related_draft,
        policy(),
    )
    .expect("related grounds");
    assert_eq!(
        grounded.ledger.records["claim-related"].disposition,
        SupportResult::Unknown
    );
    assert!(
        grounded.ledger.records["claim-related"]
            .witnesses
            .is_empty()
    );
    let foreign = claim("claim-foreign", "proposition-foreign", Some("evidence-1"));
    let foreign_draft = draft(
        &manifest,
        vec![foreign],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let foreign_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        foreign_draft.bundle.clone(),
        manifest,
        foreign_draft,
        policy(),
    )
    .expect("foreign grounds");
    assert_eq!(
        foreign_grounded.ledger.records["claim-foreign"].disposition,
        SupportResult::Unknown
    );
}

// WORK_UNIT_CASE: 602/15
#[test]
fn authority_outside_claim_domain_never_promotes() {
    let trusted = manifest_for("proposition-1", Some(supported_record()));
    let trusted_draft = draft(
        &trusted,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let trusted_grounded = ground_draft(
        job(
            trusted.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        trusted_draft.bundle.clone(),
        trusted.clone(),
        trusted_draft,
        policy(),
    )
    .expect("trusted grounds");
    let mut modeled = manifest_for("proposition-1", Some(supported_record()));
    let modeled_ref = modeled
        .references
        .get_mut(&support::artifact("evidence-1"))
        .expect("reference");
    modeled_ref.authority =
        eliot_dreamer_contracts::grounding::canonical::EvidenceAuthority::ModelInterpretation;
    refresh_manifest(&mut modeled);
    let modeled_draft = draft(
        &modeled,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let modeled_grounded = ground_draft(
        job(
            modeled.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        modeled_draft.bundle.clone(),
        modeled,
        modeled_draft,
        policy(),
    )
    .expect("modeled grounds");
    for grounded in [&trusted_grounded, &modeled_grounded] {
        assert_eq!(
            grounded.ledger.records["claim-1"].disposition,
            SupportResult::Supported
        );
        assert_eq!(
            grounded.ledger.records["claim-1"].assertability_ceiling,
            eliot_dreamer_contracts::grounding::canonical::PositionAssertability::HypothesisCandidate
        );
    }
    let _ = trusted;
}

// WORK_UNIT_CASE: 602/16
#[test]
fn weakest_grade_wins_and_dependent_sources_do_not_inflate() {
    let mut manifest = manifest_for("proposition-1", Some(supported_record()));
    let reference = manifest
        .references
        .get_mut(&support::artifact("evidence-1"))
        .expect("reference");
    reference.grade_ceiling =
        eliot_dreamer_contracts::grounding::canonical::EvidenceGrade::Orienting;
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
    .expect("weakest grade grounds");
    assert_eq!(
        grounded.ledger.records["claim-1"].grade_ceiling,
        eliot_dreamer_contracts::grounding::canonical::EvidenceGrade::Orienting
    );
    let mut doubled = manifest.clone();
    let mut second = doubled.references[&support::artifact("evidence-1")].clone();
    second.handle = support::artifact("evidence-2");
    for assertion in &mut second.assertions {
        assertion.assertion_id = "assertion-2".into();
        if let Some(support) = assertion.support.as_mut() {
            support.handles = BTreeSet::from([support::artifact("evidence-2")]);
        }
    }
    doubled
        .references
        .insert(support::artifact("evidence-2"), second);
    refresh_manifest(&mut doubled);
    let mut doubled_claim = claim("claim-1", "proposition-1", Some("evidence-1"));
    doubled_claim
        .proposed_support
        .insert(support::artifact("evidence-2"));
    refresh_claim(&mut doubled_claim);
    let doubled_draft = draft(
        &doubled,
        vec![doubled_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let doubled_grounded = ground_draft(
        job(
            doubled.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        doubled_draft.bundle.clone(),
        doubled,
        doubled_draft,
        policy(),
    )
    .expect("dependent doubling grounds");
    assert_eq!(
        doubled_grounded.ledger.records["claim-1"].grade_ceiling,
        eliot_dreamer_contracts::grounding::canonical::EvidenceGrade::Orienting
    );
    assert_eq!(
        doubled_grounded.ledger.records["claim-1"].disposition,
        SupportResult::Supported
    );
}

// WORK_UNIT_CASE: 602/17
#[test]
fn stale_transformed_and_partial_evidence_lower_or_block_ceiling() {
    let mut stale_manifest = manifest_for("proposition-1", Some(supported_record()));
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
    .expect("stale grounds");
    assert_eq!(
        stale.ledger.records["claim-1"].disposition,
        SupportResult::Stale
    );

    let mut partial_support = supported_record();
    partial_support.result = SupportResult::Partial;
    let partial_manifest = manifest_for("proposition-1", Some(partial_support));
    let partial_draft = draft(
        &partial_manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
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
    .expect("partial grounds");
    assert_eq!(
        partial.ledger.records["claim-1"].disposition,
        SupportResult::Partial
    );
    assert!(
        partial.ledger.records["claim-1"]
            .unknowns
            .iter()
            .any(|unknown| unknown.contains("incomplete"))
    );
}

// WORK_UNIT_CASE: 602/18
#[test]
fn confidence_repetition_and_citation_count_cannot_raise_support() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let single = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let single_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        single.bundle.clone(),
        manifest.clone(),
        single,
        policy(),
    )
    .expect("single grounds");
    assert_eq!(
        single_grounded.ledger.records["claim-1"].disposition,
        SupportResult::Supported
    );
    let single_grade = single_grounded.ledger.records["claim-1"].grade_ceiling;
    let mut repeated_claim = claim("claim-1", "proposition-1", Some("evidence-1"));
    repeated_claim
        .proposed_support
        .insert(support::artifact("missing-extra"));
    refresh_claim(&mut repeated_claim);
    let repeated_draft = draft(
        &manifest,
        vec![repeated_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let repeated = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        repeated_draft.bundle.clone(),
        manifest,
        repeated_draft,
        policy(),
    )
    .expect("repeated grounds");
    assert_ne!(
        repeated.ledger.records["claim-1"].disposition,
        SupportResult::Supported
    );
    assert_eq!(
        repeated.ledger.records["claim-1"].disposition,
        SupportResult::Partial
    );
    assert!(
        repeated.ledger.records["claim-1"].grade_ceiling <= single_grade,
        "extra citations must not raise the ceiling"
    );
}

// WORK_UNIT_CASE: 602/19
#[test]
fn numeric_value_unit_denominator_and_rounding_are_exact() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let valid = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let valid_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        valid.bundle.clone(),
        manifest.clone(),
        valid,
        policy(),
    )
    .expect("valid numeric grounds");
    assert_eq!(
        valid_grounded.ledger.records["claim-1"].disposition,
        SupportResult::Supported
    );
    for (label, mutate) in [("value", "43"), ("unit", "grams")] {
        let mut payload = support::payload();
        if let PrecisionPayload::NumericQuantified { value, unit, .. } = &mut payload {
            if label == "value" {
                *value = mutate.into();
            } else {
                *unit = mutate.into();
            }
        }
        let mutated = claim_with_payload("claim-1", "proposition-1", payload, Some("evidence-1"));
        let mutated_draft = draft(
            &manifest,
            vec![mutated],
            eliot_dreamer_contracts::JobClass::Orientation,
        );
        let grounded = ground_draft(
            job(
                manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            mutated_draft.bundle.clone(),
            manifest.clone(),
            mutated_draft,
            policy(),
        )
        .expect("mutated numeric grounds");
        assert_eq!(
            grounded.ledger.records["claim-1"].disposition,
            SupportResult::Unknown,
            "numeric {label} must be exact"
        );
    }
    let mut inflated = support::payload();
    if let PrecisionPayload::NumericQuantified { interval, .. } = &mut inflated {
        *interval = Some("42-42".into());
    }
    let inflated_claim =
        claim_with_payload("claim-1", "proposition-1", inflated, Some("evidence-1"));
    let inflated_draft = draft(
        &manifest,
        vec![inflated_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let inflated_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        inflated_draft.bundle.clone(),
        manifest,
        inflated_draft,
        policy(),
    )
    .expect("inflated numeric grounds");
    assert_eq!(
        inflated_grounded.ledger.records["claim-1"].disposition,
        SupportResult::Unknown,
        "one-step precision inflation must not support"
    );
}

// WORK_UNIT_CASE: 602/20
#[test]
fn current_versus_historical_version_and_time_mismatch_stays_unknown() {
    let temporal_manifest = manifest_for_typed(
        "proposition-temporal",
        temporal_payload(),
        Some(temporal_support_for("proposition-temporal")),
        None,
        None,
        support::DIGEST,
    );
    let valid = draft(
        &temporal_manifest,
        vec![claim_with_payload(
            "claim-temporal",
            "proposition-temporal",
            temporal_payload(),
            Some("evidence-1"),
        )],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let valid_grounded = ground_draft(
        job(
            temporal_manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        valid.bundle.clone(),
        temporal_manifest.clone(),
        valid,
        policy(),
    )
    .expect("valid temporal grounds");
    assert_eq!(
        valid_grounded.ledger.records["claim-temporal"].disposition,
        SupportResult::Supported
    );
    let mut old_payload = temporal_payload();
    if let PrecisionPayload::TemporalVersioned { version, .. } = &mut old_payload {
        *version = "revision-old".into();
    }
    let old_claim = claim_with_payload(
        "claim-temporal",
        "proposition-temporal",
        old_payload,
        Some("evidence-1"),
    );
    let old_draft = draft(
        &temporal_manifest,
        vec![old_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let old_grounded = ground_draft(
        job(
            temporal_manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        old_draft.bundle.clone(),
        temporal_manifest.clone(),
        old_draft,
        policy(),
    )
    .expect("old version grounds");
    assert_eq!(
        old_grounded.ledger.records["claim-temporal"].disposition,
        SupportResult::Unknown
    );
    let mut shifted = temporal_payload();
    if let PrecisionPayload::TemporalVersioned { temporal, .. } = &mut shifted {
        *temporal =
            eliot_dreamer_contracts::grounding::canonical::TemporalRecord::new(1, 2, 3, 4, 5)
                .expect("temporal");
    }
    let shifted_claim = claim_with_payload(
        "claim-temporal",
        "proposition-temporal",
        shifted,
        Some("evidence-1"),
    );
    let shifted_draft = draft(
        &temporal_manifest,
        vec![shifted_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let shifted_grounded = ground_draft(
        job(
            temporal_manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        shifted_draft.bundle.clone(),
        temporal_manifest,
        shifted_draft,
        policy(),
    )
    .expect("shifted time grounds");
    assert_eq!(
        shifted_grounded.ledger.records["claim-temporal"].disposition,
        SupportResult::Unknown
    );
}

// WORK_UNIT_CASE: 602/21
#[test]
fn chronology_correlation_and_dependency_cannot_support_causal() {
    let mechanism = causal_payload();
    let (lineage, assurance) = match &mechanism {
        PrecisionPayload::Causal { causal } => {
            (causal.source_lineage.clone(), causal.assurance.clone())
        }
        _ => panic!("causal payload"),
    };
    let mut support = supported_record();
    support.proposition =
        eliot_dreamer_contracts::grounding::PropositionId::new("proposition-causal")
            .expect("proposition");
    let base_manifest = manifest_for_typed(
        "proposition-causal",
        mechanism.clone(),
        Some(support),
        Some(lineage),
        Some(assurance),
        CAUSAL_CONTENT,
    );
    for status in [
        eliot_dreamer_contracts::grounding::canonical::CausalStatus::Association,
        eliot_dreamer_contracts::grounding::canonical::CausalStatus::Correlation,
        eliot_dreamer_contracts::grounding::canonical::CausalStatus::DependencyPreconditionEnablement,
    ] {
        let mut weak = mechanism.clone();
        if let PrecisionPayload::Causal { causal } = &mut weak {
            causal.status = status;
            causal.ceiling = eliot_dreamer_contracts::grounding::canonical::EvidenceGrade::Grounded;
            causal.digest = causal.compute_digest().expect("weak digest");
        }
        let weak_claim =
            claim_with_payload("claim-weak", "proposition-causal", weak, Some("evidence-1"));
        let weak_draft = draft(
            &base_manifest,
            vec![weak_claim],
            eliot_dreamer_contracts::JobClass::Orientation,
        );
        let grounded = ground_draft(
            job(
                base_manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            weak_draft.bundle.clone(),
            base_manifest.clone(),
            weak_draft,
            policy(),
        )
        .expect("weak causal grounds");
        assert_eq!(
            grounded.ledger.records["claim-weak"].disposition,
            SupportResult::Unknown,
            "status {status:?} must not support causality"
        );
    }
    let strong = draft(
        &base_manifest,
        vec![claim_with_payload(
            "claim-strong",
            "proposition-causal",
            mechanism,
            Some("evidence-1"),
        )],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let strong_grounded = ground_draft(
        job(
            base_manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        strong.bundle.clone(),
        base_manifest,
        strong,
        policy(),
    )
    .expect("mechanism grounds");
    assert_eq!(
        strong_grounded.ledger.records["claim-strong"].disposition,
        SupportResult::Supported
    );
}

// WORK_UNIT_CASE: 602/22
#[test]
fn causal_rival_and_confounder_changes_invalidate_support() {
    let mechanism = causal_payload();
    let (lineage, assurance) = match &mechanism {
        PrecisionPayload::Causal { causal } => {
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
        mechanism.clone(),
        Some(support),
        Some(lineage),
        Some(assurance),
        CAUSAL_CONTENT,
    );
    let valid = draft(
        &manifest,
        vec![claim_with_payload(
            "claim-causal",
            "proposition-causal",
            mechanism.clone(),
            Some("evidence-1"),
        )],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let valid_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        valid.bundle.clone(),
        manifest.clone(),
        valid,
        policy(),
    )
    .expect("valid causal grounds");
    assert_eq!(
        valid_grounded.ledger.records["claim-causal"].disposition,
        SupportResult::Supported
    );
    let mut dropped_rival = mechanism.clone();
    if let PrecisionPayload::Causal { causal } = &mut dropped_rival {
        causal.rivals = BTreeSet::from(["rival-2".into()]);
        causal.digest = causal.compute_digest().expect("rival digest");
    }
    let rival_claim = claim_with_payload(
        "claim-causal",
        "proposition-causal",
        dropped_rival,
        Some("evidence-1"),
    );
    let rival_draft = draft(
        &manifest,
        vec![rival_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let rival_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        rival_draft.bundle.clone(),
        manifest.clone(),
        rival_draft,
        policy(),
    )
    .expect("rival change grounds");
    assert_eq!(
        rival_grounded.ledger.records["claim-causal"].disposition,
        SupportResult::Unknown,
        "rival substitution must invalidate"
    );
    let mut dropped_confounder = mechanism;
    if let PrecisionPayload::Causal { causal } = &mut dropped_confounder {
        causal.confounders = BTreeSet::from(["confounder-2".into()]);
        causal.digest = causal.compute_digest().expect("confounder digest");
    }
    let confounder_claim = claim_with_payload(
        "claim-causal",
        "proposition-causal",
        dropped_confounder,
        Some("evidence-1"),
    );
    let confounder_draft = draft(
        &manifest,
        vec![confounder_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let confounder_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        confounder_draft.bundle.clone(),
        manifest,
        confounder_draft,
        policy(),
    )
    .expect("confounder change grounds");
    assert_eq!(
        confounder_grounded.ledger.records["claim-causal"].disposition,
        SupportResult::Unknown,
        "confounder substitution must limit"
    );
}

// WORK_UNIT_CASE: 602/23
#[test]
fn absence_complete_supports_while_partial_or_unavailable_stays_unknown() {
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
    refresh_manifest(&mut complete_manifest);
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
    .expect("complete absence");
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
    refresh_manifest(&mut partial_manifest);
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
    .expect("partial absence");
    assert_eq!(
        partial.ledger.records["absence"].disposition,
        SupportResult::Unknown
    );
}

// WORK_UNIT_CASE: 602/24
#[test]
fn comparative_requires_exact_population_and_compatible_measure() {
    let payload = comparative_payload();
    let manifest = manifest_for_typed(
        "proposition-comparative",
        payload.clone(),
        Some(support_for(
            "proposition-comparative",
            BTreeSet::from([support::artifact("evidence-1")]),
            SupportResult::Supported,
            eliot_dreamer_contracts::grounding::canonical::EvidenceGrade::Grounded,
            None,
        )),
        None,
        None,
        support::DIGEST,
    );
    let valid = draft(
        &manifest,
        vec![claim_with_payload(
            "claim-comparative",
            "proposition-comparative",
            payload,
            Some("evidence-1"),
        )],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let valid_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        valid.bundle.clone(),
        manifest.clone(),
        valid,
        policy(),
    )
    .expect("valid comparative grounds");
    assert_eq!(
        valid_grounded.ledger.records["claim-comparative"].disposition,
        SupportResult::Supported
    );
    let mut missing = comparative_payload();
    if let PrecisionPayload::ComparativeSuperlative { population, .. } = &mut missing {
        *population = "different-population".into();
    }
    let missing_claim = claim_with_payload(
        "claim-comparative",
        "proposition-comparative",
        missing,
        Some("evidence-1"),
    );
    let missing_draft = draft(
        &manifest,
        vec![missing_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let missing_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        missing_draft.bundle.clone(),
        manifest.clone(),
        missing_draft,
        policy(),
    )
    .expect("missing population grounds");
    assert_eq!(
        missing_grounded.ledger.records["claim-comparative"].disposition,
        SupportResult::Unknown
    );
    let mut incompatible = comparative_payload();
    if let PrecisionPayload::ComparativeSuperlative { measure, .. } = &mut incompatible {
        *measure = "throughput".into();
    }
    let incompatible_claim = claim_with_payload(
        "claim-comparative",
        "proposition-comparative",
        incompatible,
        Some("evidence-1"),
    );
    let incompatible_draft = draft(
        &manifest,
        vec![incompatible_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let incompatible_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        incompatible_draft.bundle.clone(),
        manifest,
        incompatible_draft,
        policy(),
    )
    .expect("incompatible measure grounds");
    assert_eq!(
        incompatible_grounded.ledger.records["claim-comparative"].disposition,
        SupportResult::Unknown
    );
}

// WORK_UNIT_CASE: 602/25
#[test]
fn exact_quote_beats_paraphrase_and_attribution_mismatch() {
    let payload = quote_payload();
    let manifest = manifest_for_typed(
        "proposition-quote",
        payload.clone(),
        Some(support_for(
            "proposition-quote",
            BTreeSet::from([support::artifact("evidence-1")]),
            SupportResult::Supported,
            eliot_dreamer_contracts::grounding::canonical::EvidenceGrade::Grounded,
            None,
        )),
        None,
        None,
        support::DIGEST,
    );
    let valid = draft(
        &manifest,
        vec![claim_with_payload(
            "claim-quote",
            "proposition-quote",
            payload,
            Some("evidence-1"),
        )],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let valid_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        valid.bundle.clone(),
        manifest.clone(),
        valid,
        policy(),
    )
    .expect("valid quote grounds");
    assert_eq!(
        valid_grounded.ledger.records["claim-quote"].disposition,
        SupportResult::Supported
    );
    let mut paraphrase = quote_payload();
    if let PrecisionPayload::QuoteAttribution { quoted_text, .. } = &mut paraphrase {
        *quoted_text = "similar sentence with same meaning".into();
    }
    let paraphrase_claim = claim_with_payload(
        "claim-quote",
        "proposition-quote",
        paraphrase,
        Some("evidence-1"),
    );
    let paraphrase_draft = draft(
        &manifest,
        vec![paraphrase_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let paraphrase_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        paraphrase_draft.bundle.clone(),
        manifest.clone(),
        paraphrase_draft,
        policy(),
    )
    .expect("paraphrase grounds");
    assert_eq!(
        paraphrase_grounded.ledger.records["claim-quote"].disposition,
        SupportResult::Unknown
    );
    let mut misattributed = quote_payload();
    if let PrecisionPayload::QuoteAttribution { attributed_to, .. } = &mut misattributed {
        *attributed_to = "other-source".into();
    }
    let misattributed_claim = claim_with_payload(
        "claim-quote",
        "proposition-quote",
        misattributed,
        Some("evidence-1"),
    );
    let misattributed_draft = draft(
        &manifest,
        vec![misattributed_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let misattributed_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        misattributed_draft.bundle.clone(),
        manifest,
        misattributed_draft,
        policy(),
    )
    .expect("misattribution grounds");
    assert_eq!(
        misattributed_grounded.ledger.records["claim-quote"].disposition,
        SupportResult::Unknown
    );
}

// WORK_UNIT_CASE: 602/26
#[test]
fn recommendation_keeps_facts_assumptions_and_inference_separate() {
    let payload = recommendation_payload();
    let manifest = manifest_for_typed(
        "proposition-recommendation",
        payload.clone(),
        Some(support_for(
            "proposition-recommendation",
            BTreeSet::from([support::artifact("evidence-1")]),
            SupportResult::Supported,
            eliot_dreamer_contracts::grounding::canonical::EvidenceGrade::Grounded,
            None,
        )),
        None,
        None,
        support::DIGEST,
    );
    let valid = draft(
        &manifest,
        vec![claim_with_payload(
            "claim-recommendation",
            "proposition-recommendation",
            payload,
            Some("evidence-1"),
        )],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let valid_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        valid.bundle.clone(),
        manifest.clone(),
        valid,
        policy(),
    )
    .expect("valid recommendation grounds");
    let record = &valid_grounded.ledger.records["claim-recommendation"];
    assert_eq!(record.disposition, SupportResult::Supported);
    assert_eq!(
        record.assertability_ceiling,
        eliot_dreamer_contracts::grounding::canonical::PositionAssertability::HypothesisCandidate
    );
    let mut changed_assumption = recommendation_payload();
    if let PrecisionPayload::RecommendationNormativeInference { assumptions, .. } =
        &mut changed_assumption
    {
        *assumptions = BTreeSet::from(["assumption-2".into()]);
    }
    let assumption_claim = claim_with_payload(
        "claim-recommendation",
        "proposition-recommendation",
        changed_assumption,
        Some("evidence-1"),
    );
    let assumption_draft = draft(
        &manifest,
        vec![assumption_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let assumption_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        assumption_draft.bundle.clone(),
        manifest.clone(),
        assumption_draft,
        policy(),
    )
    .expect("changed assumption grounds");
    assert_eq!(
        assumption_grounded.ledger.records["claim-recommendation"].disposition,
        SupportResult::Unknown
    );
    let mut changed_rule = recommendation_payload();
    if let PrecisionPayload::RecommendationNormativeInference { inference_rule, .. } =
        &mut changed_rule
    {
        *inference_rule = "different rule".into();
    }
    let rule_claim = claim_with_payload(
        "claim-recommendation",
        "proposition-recommendation",
        changed_rule,
        Some("evidence-1"),
    );
    let rule_draft = draft(
        &manifest,
        vec![rule_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let rule_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        rule_draft.bundle.clone(),
        manifest,
        rule_draft,
        policy(),
    )
    .expect("changed rule grounds");
    assert_eq!(
        rule_grounded.ledger.records["claim-recommendation"].disposition,
        SupportResult::Unknown
    );
}

// WORK_UNIT_CASE: 602/27
#[test]
fn identity_requires_exact_entity_version_and_scope() {
    let payload = identity_payload();
    let manifest = manifest_for_typed(
        "proposition-identity",
        payload.clone(),
        Some(support_for(
            "proposition-identity",
            BTreeSet::from([support::artifact("evidence-1")]),
            SupportResult::Supported,
            eliot_dreamer_contracts::grounding::canonical::EvidenceGrade::Grounded,
            None,
        )),
        None,
        None,
        support::DIGEST,
    );
    let valid = draft(
        &manifest,
        vec![claim_with_payload(
            "claim-identity",
            "proposition-identity",
            payload,
            Some("evidence-1"),
        )],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let valid_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        valid.bundle.clone(),
        manifest.clone(),
        valid,
        policy(),
    )
    .expect("valid identity grounds");
    assert_eq!(
        valid_grounded.ledger.records["claim-identity"].disposition,
        SupportResult::Supported
    );
    let mut similar = identity_payload();
    if let PrecisionPayload::IdentityEntity { entity, .. } = &mut similar {
        *entity = "entity-1-similar".into();
    }
    let similar_claim = claim_with_payload(
        "claim-identity",
        "proposition-identity",
        similar,
        Some("evidence-1"),
    );
    let similar_draft = draft(
        &manifest,
        vec![similar_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let similar_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        similar_draft.bundle.clone(),
        manifest.clone(),
        similar_draft,
        policy(),
    )
    .expect("similar name grounds");
    assert_eq!(
        similar_grounded.ledger.records["claim-identity"].disposition,
        SupportResult::Unknown
    );
    let mut wrong_version = identity_payload();
    if let PrecisionPayload::IdentityEntity { version, .. } = &mut wrong_version {
        *version = "revision-old".into();
    }
    let version_claim = claim_with_payload(
        "claim-identity",
        "proposition-identity",
        wrong_version,
        Some("evidence-1"),
    );
    let version_draft = draft(
        &manifest,
        vec![version_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let version_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        version_draft.bundle.clone(),
        manifest.clone(),
        version_draft,
        policy(),
    )
    .expect("wrong version grounds");
    assert_eq!(
        version_grounded.ledger.records["claim-identity"].disposition,
        SupportResult::Unknown,
        "version mismatch must not be supported"
    );
    let mut wrong_scope = identity_payload();
    if let PrecisionPayload::IdentityEntity { scope, .. } = &mut wrong_scope {
        *scope = "other-scope".into();
    }
    let scope_claim = claim_with_payload(
        "claim-identity",
        "proposition-identity",
        wrong_scope,
        Some("evidence-1"),
    );
    let scope_draft = draft(
        &manifest,
        vec![scope_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let scope_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        scope_draft.bundle.clone(),
        manifest,
        scope_draft,
        policy(),
    )
    .expect("wrong scope grounds");
    assert_eq!(
        scope_grounded.ledger.records["claim-identity"].disposition,
        SupportResult::Unknown,
        "scope mismatch must not be supported"
    );
}

// WORK_UNIT_CASE: 602/28
#[test]
fn dropped_counterevidence_cannot_yield_a_complete_witness() {
    let mut manifest = manifest_for("proposition-1", Some(supported_record()));
    let mut contradiction =
        manifest.references[&support::artifact("evidence-1")].assertions[0].clone();
    contradiction.assertion_id = "assertion-contradiction".into();
    let contradiction_support = contradiction.support.as_mut().expect("support");
    contradiction_support.result = SupportResult::Contradicted;
    contradiction_support.handles = BTreeSet::from([support::artifact("evidence-2")]);
    let mut counter_reference = manifest.references[&support::artifact("evidence-1")].clone();
    counter_reference.handle = support::artifact("evidence-2");
    counter_reference.assertions = vec![contradiction];
    manifest
        .references
        .insert(support::artifact("evidence-2"), counter_reference);
    refresh_manifest(&mut manifest);
    let without_counter = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let without_grounded = ground_draft(
        without_counter.job.clone(),
        without_counter.bundle.clone(),
        manifest.clone(),
        without_counter,
        policy(),
    )
    .expect("without counterevidence grounds");
    assert_eq!(
        without_grounded.ledger.records["claim-1"].disposition,
        SupportResult::Unknown
    );
    assert!(
        without_grounded.ledger.records["claim-1"]
            .unknowns
            .iter()
            .any(|entry| entry.contains("dropped counterevidence")),
        "selective draft must record dropped counterevidence"
    );
    assert!(
        without_grounded.ledger.records["claim-1"].witnesses.len() < 2,
        "selective draft must not yield a complete witness"
    );
    let mut with_counter_claim = claim("claim-1", "proposition-1", Some("evidence-1"));
    with_counter_claim
        .proposed_counterevidence
        .insert(support::artifact("evidence-2"));
    refresh_claim(&mut with_counter_claim);
    let with_counter = draft(
        &manifest,
        vec![with_counter_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let with_grounded = ground_draft(
        with_counter.job.clone(),
        with_counter.bundle.clone(),
        manifest,
        with_counter,
        policy(),
    )
    .expect("with counterevidence grounds");
    assert_eq!(
        with_grounded.ledger.records["claim-1"].disposition,
        SupportResult::Contradicted
    );
    assert_eq!(with_grounded.ledger.records["claim-1"].witnesses.len(), 2);
    assert_ne!(
        without_grounded.output_digest, with_grounded.output_digest,
        "dropping counterevidence must change the witness"
    );
}

// WORK_UNIT_CASE: 602/29
#[test]
fn every_material_claim_has_terminal_disposition_and_residue_is_exact() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let mut draft_value = draft(
        &manifest,
        vec![
            claim("claim-1", "proposition-1", Some("evidence-1")),
            claim("claim-2", "proposition-2", None),
        ],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    draft_value.non_material_claims = vec![non_material_claim("residue-1")];
    refresh_draft(&mut draft_value);
    let grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft_value.bundle.clone(),
        manifest.clone(),
        draft_value.clone(),
        policy(),
    )
    .expect("denominator grounds");
    assert_eq!(
        grounded.ledger.expected_claim_ids,
        BTreeSet::from(["claim-1".to_owned(), "claim-2".to_owned()])
    );
    assert_eq!(
        grounded.ledger.nonmaterial_claim_ids,
        BTreeSet::from(["residue-1".to_owned()])
    );
    assert!(grounded.ledger.unprocessed_claim_ids.is_empty());
    assert!(grounded.ledger.unprocessed_reason.is_none());
    for claim_id in ["claim-1", "claim-2"] {
        let record = &grounded.ledger.records[claim_id];
        assert!(
            matches!(
                record.disposition,
                SupportResult::Supported
                    | SupportResult::Partial
                    | SupportResult::Contradicted
                    | SupportResult::Unsupported
                    | SupportResult::Unknown
                    | SupportResult::OutsideManifest
                    | SupportResult::Stale
                    | SupportResult::Superseded
                    | SupportResult::JustifiedNotApplicable
            ),
            "visible terminal disposition for {claim_id}"
        );
    }
    assert_eq!(
        grounded.ledger.records["claim-1"].disposition,
        SupportResult::Supported
    );
    assert_eq!(
        grounded.ledger.records["claim-2"].disposition,
        SupportResult::Unknown
    );
    let request = GroundingRequest::new(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft_value.bundle.clone(),
        manifest,
        draft_value,
        policy(),
    )
    .with_controls(GroundingControls {
        whole_claim_quota: Some(1),
        cancellation: Cancellation::NotCancelled,
        deadline_exceeded: false,
    });
    let bounded = ground_draft_with_controls(request).expect("bounded");
    assert_eq!(bounded.ledger.records.len(), 1);
    assert_eq!(
        bounded.ledger.unprocessed_claim_ids.len(),
        1,
        "unprocessed residue must be exact"
    );
    assert!(bounded.ledger.unprocessed_reason.is_some());
}

// WORK_UNIT_CASE: 602/30
#[test]
fn claim_order_permutation_preserves_output_while_mutation_invalidates() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let first_claim = claim("claim-1", "proposition-1", Some("evidence-1"));
    let second_claim = claim("claim-2", "proposition-2", None);
    let forward = draft(
        &manifest,
        vec![first_claim.clone(), second_claim.clone()],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let backward = draft(
        &manifest,
        vec![second_claim, first_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    assert_eq!(
        forward.draft_digest, backward.draft_digest,
        "canonical digest must sort claims"
    );
    let forward_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        forward.bundle.clone(),
        manifest.clone(),
        forward,
        policy(),
    )
    .expect("forward grounds");
    let backward_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        backward.bundle.clone(),
        manifest.clone(),
        backward,
        policy(),
    )
    .expect("backward grounds");
    assert_eq!(
        forward_grounded.output_digest, backward_grounded.output_digest,
        "ordering must preserve canonical output"
    );
    assert_eq!(
        forward_grounded.ledger.records["claim-1"].disposition,
        backward_grounded.ledger.records["claim-1"].disposition
    );
    let mut mutated = claim("claim-1", "proposition-1", Some("evidence-1"));
    mutated.proposed_support = BTreeSet::new();
    refresh_claim(&mut mutated);
    let mutated_draft = draft(
        &manifest,
        vec![mutated, claim("claim-2", "proposition-2", None)],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let mutated_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        mutated_draft.bundle.clone(),
        manifest,
        mutated_draft,
        policy(),
    )
    .expect("mutated grounds");
    assert_ne!(
        forward_grounded.output_digest, mutated_grounded.output_digest,
        "load-bearing mutation must invalidate"
    );
    assert_eq!(
        mutated_grounded.ledger.records["claim-1"].disposition,
        SupportResult::Unknown
    );
}

// WORK_UNIT_CASE: 602/31
#[test]
fn exact_bounds_and_one_over_preserve_omission_without_false_completeness() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let draft_value = draft(
        &manifest,
        vec![
            claim("claim-1", "proposition-1", Some("evidence-1")),
            claim("claim-2", "proposition-2", Some("evidence-1")),
        ],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let full = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft_value.bundle.clone(),
        manifest.clone(),
        draft_value.clone(),
        policy(),
    )
    .expect("full bounds ground");
    assert!(full.ledger.unprocessed_claim_ids.is_empty());
    let one_over = GroundingRequest::new(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft_value.bundle.clone(),
        manifest.clone(),
        draft_value.clone(),
        policy(),
    )
    .with_controls(GroundingControls {
        whole_claim_quota: Some(1),
        cancellation: Cancellation::NotCancelled,
        deadline_exceeded: false,
    });
    let bounded = ground_draft_with_controls(one_over).expect("one-over grounds");
    assert_eq!(
        bounded.ledger.unprocessed_claim_ids,
        BTreeSet::from(["claim-2".to_owned()])
    );
    assert_eq!(
        bounded.ledger.unprocessed_reason.as_deref(),
        Some("whole-claim quota exhausted")
    );
    assert!(
        !bounded.ledger.records.contains_key("claim-2"),
        "omission must not look complete"
    );
    let mut tight_policy = policy();
    tight_policy.max_claims = 1;
    refresh_policy(&mut tight_policy);
    assert!(
        ground_draft(
            job(
                manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            draft_value.bundle.clone(),
            manifest,
            draft_value,
            tight_policy,
        )
        .is_err(),
        "policy ceiling must fail closed"
    );
}

// WORK_UNIT_CASE: 602/32
#[test]
fn cancellation_deadline_and_incomplete_coverage_cannot_all_ground() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let draft_value = draft(
        &manifest,
        vec![
            claim("claim-1", "proposition-1", Some("evidence-1")),
            claim("claim-2", "proposition-2", None),
        ],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let cancelled = ground_draft_with_controls(
        GroundingRequest::new(
            job(
                manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            draft_value.bundle.clone(),
            manifest.clone(),
            draft_value.clone(),
            policy(),
        )
        .with_controls(GroundingControls {
            whole_claim_quota: Some(4_096),
            cancellation: Cancellation::Cancelled("operator stop".into()),
            deadline_exceeded: false,
        }),
    )
    .expect("cancelled grounds");
    assert!(!cancelled.ledger.unprocessed_claim_ids.is_empty());
    assert_eq!(
        cancelled.ledger.unprocessed_reason.as_deref(),
        Some("operator stop")
    );
    assert!(
        !(cancelled.ledger.unprocessed_claim_ids.is_empty()
            && cancelled
                .ledger
                .records
                .values()
                .all(|record| record.disposition == SupportResult::Supported)),
        "cancellation cannot yield all-grounded"
    );
    let expired = ground_draft_with_controls(
        GroundingRequest::new(
            job(
                manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            draft_value.bundle.clone(),
            manifest.clone(),
            draft_value.clone(),
            policy(),
        )
        .with_controls(GroundingControls {
            whole_claim_quota: Some(4_096),
            cancellation: Cancellation::NotCancelled,
            deadline_exceeded: true,
        }),
    )
    .expect("expired grounds");
    assert!(!expired.ledger.unprocessed_claim_ids.is_empty());
    let incomplete = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft_value.bundle.clone(),
        manifest,
        draft_value,
        policy(),
    )
    .expect("incomplete grounds");
    assert_eq!(
        incomplete.ledger.records["claim-2"].disposition,
        SupportResult::Unknown
    );
    assert!(
        !incomplete
            .ledger
            .records
            .values()
            .all(|record| record.disposition == SupportResult::Supported),
        "incomplete coverage cannot yield all-grounded"
    );
}

// WORK_UNIT_CASE: 602/33
#[test]
fn unknown_versions_kinds_and_permissive_defaults_are_rejected() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let mut bad_version = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    bad_version.schema_version = 99;
    refresh_draft(&mut bad_version);
    assert!(
        ground_draft(
            job(
                manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            bad_version.bundle.clone(),
            manifest.clone(),
            bad_version,
            policy(),
        )
        .is_err(),
        "unknown schema version must fail"
    );
    let mut kind_mismatch = claim("claim-1", "proposition-1", Some("evidence-1"));
    kind_mismatch.kind = ClaimKind::TemporalVersioned;
    assert!(
        kind_mismatch.validate().is_err(),
        "kind and payload mismatch must fail"
    );
    let mut blank_id = claim("claim-1", "proposition-1", Some("evidence-1"));
    blank_id.claim_id.clear();
    assert!(blank_id.validate().is_err(), "blank identity must fail");
    let mut bad_policy = policy();
    bad_policy.schema_version = 99;
    refresh_policy(&mut bad_policy);
    let draft_value = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    assert!(
        ground_draft(
            job(
                manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            draft_value.bundle.clone(),
            manifest,
            draft_value,
            bad_policy,
        )
        .is_err(),
        "unknown policy version must fail"
    );
}

// WORK_UNIT_CASE: 602/34
#[test]
fn malformed_bounded_inputs_fail_closed_without_panic_or_leak() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let empty = draft(
        &manifest,
        Vec::new(),
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let empty_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        empty.bundle.clone(),
        manifest.clone(),
        empty,
        policy(),
    )
    .expect("empty draft grounds");
    assert!(empty_grounded.ledger.records.is_empty());
    assert!(empty_grounded.ledger.expected_claim_ids.is_empty());
    assert!(empty_grounded.ledger.unprocessed_claim_ids.is_empty());
    let mut blank = claim("claim-1", "proposition-1", Some("evidence-1"));
    blank.claim_id = String::new();
    let blank_draft = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let mut malformed_draft = blank_draft;
    malformed_draft.claims[0] = blank;
    let error = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        malformed_draft.bundle.clone(),
        manifest.clone(),
        malformed_draft,
        policy(),
    )
    .expect_err("blank identity must fail closed");
    let message = format!("{error:?}");
    assert!(message.len() < 2000, "diagnostics must stay bounded");
    assert!(!message.contains("secret-sensitive-proposition"), "no leak");
    let mut oversized = draft(
        &manifest,
        vec![claim("claim-1", "proposition-1", Some("evidence-1"))],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    oversized.claims[0].proposed_support = (0..65)
        .map(|index| support::artifact(&format!("evidence-{index}")))
        .collect();
    assert!(
        ground_draft(
            job(
                manifest.digest.clone(),
                eliot_dreamer_contracts::JobClass::Orientation,
            ),
            oversized.bundle.clone(),
            manifest,
            oversized,
            policy(),
        )
        .is_err(),
        "over-ceiling handles must fail closed"
    );
}

// WORK_UNIT_CASE: 602/35
#[test]
fn api_guard_excludes_extraction_entailment_retrieval_and_effects() {
    let manifest = manifest_for("proposition-1", Some(supported_record()));
    let draft_value = draft(
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
        draft_value.bundle.clone(),
        manifest.clone(),
        draft_value.clone(),
        policy(),
    )
    .expect("pure operation grounds");
    let second = ground_draft(
        job_value.clone(),
        draft_value.bundle.clone(),
        manifest.clone(),
        draft_value.clone(),
        policy(),
    )
    .expect("pure operation replays");
    assert_eq!(first.output_digest, second.output_digest);
    assert_eq!(first.input, draft_value, "no hidden input mutation");
    assert_eq!(first.manifest, manifest, "no hidden manifest mutation");
    let prose_claim = claim("claim-prose", "proposition-prose-about-topic", None);
    let prose_draft = draft(
        &manifest,
        vec![prose_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let prose_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        prose_draft.bundle.clone(),
        manifest.clone(),
        prose_draft,
        policy(),
    )
    .expect("prose claim grounds");
    assert_eq!(
        prose_grounded.ledger.records["claim-prose"].disposition,
        SupportResult::Unknown,
        "no prose extraction pipeline"
    );
    let missing = draft(
        &manifest,
        vec![claim(
            "claim-missing",
            "proposition-1",
            Some("absent-handle"),
        )],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let missing_grounded = ground_draft(
        job(
            manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        missing.bundle.clone(),
        manifest,
        missing,
        policy(),
    )
    .expect("absent handle grounds");
    assert_eq!(
        missing_grounded.ledger.records["claim-missing"].disposition,
        SupportResult::OutsideManifest,
        "no retrieval or search"
    );
}

// WORK_UNIT_CASE: 602/35 (compile-time surface and zero runtime I/O guarantee)
#[test]
fn api_surface_is_pure_and_restricted() {
    fn assert_pure_fn<Req, Out>(
        _f: fn(Req) -> Result<Out, eliot_dreamer_contracts::ContractViolation>,
    ) {
    }
    assert_pure_fn(eliot_dreamer_claim_grounding::ground_draft_with_controls);
}


// WORK_UNIT_CASE: 602/36
#[test]
fn supported_claims_have_complete_exact_coverage_without_promotion() {
    let numeric_manifest = manifest_for("proposition-1", Some(supported_record()));
    let temporal_manifest = manifest_for_typed(
        "proposition-temporal",
        temporal_payload(),
        Some(temporal_support_for("proposition-temporal")),
        None,
        None,
        support::DIGEST,
    );
    let numeric_claim = claim("claim-numeric", "proposition-1", Some("evidence-1"));
    let temporal_claim = claim_with_payload(
        "claim-temporal",
        "proposition-temporal",
        temporal_payload(),
        Some("evidence-1"),
    );
    let numeric_grounded = ground_draft(
        job(
            numeric_manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        draft(
            &numeric_manifest,
            vec![numeric_claim],
            eliot_dreamer_contracts::JobClass::Orientation,
        )
        .bundle
        .clone(),
        numeric_manifest.clone(),
        draft(
            &numeric_manifest,
            vec![claim("claim-numeric", "proposition-1", Some("evidence-1"))],
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        policy(),
    )
    .expect("numeric property grounds");
    let temporal_draft = draft(
        &temporal_manifest,
        vec![temporal_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let temporal_grounded = ground_draft(
        job(
            temporal_manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        temporal_draft.bundle.clone(),
        temporal_manifest,
        temporal_draft,
        policy(),
    )
    .expect("temporal property grounds");
    for grounded in [&numeric_grounded, &temporal_grounded] {
        for record in grounded.ledger.records.values() {
            if record.disposition == SupportResult::Supported {
                assert!(
                    record
                        .component_outcomes
                        .values()
                        .all(|outcome| *outcome == SupportResult::Supported),
                    "supported requires complete component coverage"
                );
                assert!(!record.witnesses.is_empty(), "supported requires a witness");
                for witness in &record.witnesses {
                    assert!(
                        record.accepted_support.contains(&witness.handle)
                            || record.accepted_counterevidence.contains(&witness.handle)
                    );
                    assert!(
                        grounded.manifest.references.contains_key(&witness.handle),
                        "witness must resolve in the frozen manifest"
                    );
                }
                assert_eq!(
                    record.assertability_ceiling,
                    eliot_dreamer_contracts::grounding::canonical::PositionAssertability::HypothesisCandidate,
                    "grounding never promotes to truth"
                );
                assert!(
                    record.grade_ceiling
                        <= eliot_dreamer_contracts::grounding::canonical::EvidenceGrade::Grounded,
                    "no higher grade than weakest evidence"
                );
            }
        }
        grounded.validate().expect("property handoff validates");
    }
    let presence_manifest = manifest_for("proposition-1", Some(supported_record()));
    let presence_claim = claim("claim-presence", "proposition-other", Some("evidence-1"));
    let presence_draft = draft(
        &presence_manifest,
        vec![presence_claim],
        eliot_dreamer_contracts::JobClass::Orientation,
    );
    let presence = ground_draft(
        job(
            presence_manifest.digest.clone(),
            eliot_dreamer_contracts::JobClass::Orientation,
        ),
        presence_draft.bundle.clone(),
        presence_manifest,
        presence_draft,
        policy(),
    )
    .expect("presence-only grounds");
    assert_ne!(
        presence.ledger.records["claim-presence"].disposition,
        SupportResult::Supported,
        "references alone cannot prove truth or causality"
    );
}
