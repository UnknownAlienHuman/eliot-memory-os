//! Integration-test entrypoint for the two functional capability cells this
//! crate declares in `module.toml`:
//!
//! * `smart.understanding.common_ground` (`[[ownership]]` :134) — the
//!   `CommonGroundAssessment` candidate and the `common_ground_*` half of the
//!   frozen `UnderstandingAssessment` field contract;
//! * `smart.understanding.scoped_assessment` (`[[ownership]]` :144) — the
//!   `ScopedUnderstandingAssessment` candidate and the `scoped_*` half.
//!
//! # Proof surface and honest limits
//!
//! This entrypoint exercises the crate's **public** API only. It proves, per
//! cell: the persisted-annex shape and its canonical leg order, the frozen
//! contract-version gate, the frozen-digest tamper check, and the text/slot
//! bounds. It also proves the shared closure rule the audit's rescued W2d
//! assertion names — a held-out closure leg is required for a product claim
//! and is not required otherwise — against the real `ClosureLeg` /
//! `LegEvidence` / `AssessmentClosure` surface.
//!
//! What this entrypoint deliberately does **not** claim, because the crate's
//! dependency closure makes it unreachable from an integration test:
//!
//! `assess_common_ground`, `assess_scoped`, and both `recheck` methods take an
//! `OwnerContext`, whose `view: &ActiveUnderstandingView` can only be built
//! through `eliot_context_contracts::ContextBinding`. `ContextBinding` names
//! `eliot_agent_contracts::AgentAttemptId` and `eliot_receipts::WorkScopeId`,
//! and `ContextCandidate::proof` names `eliot_receipts::ProofCeiling`. None of
//! those three crates is a dependency of this package, and none of this
//! package's five dependencies re-exports them. The package manifest declares
//! no `[dev-dependencies]`, and issue #238 reserves `Cargo.toml` and
//! package-root integration to the integration owner, so this entrypoint
//! cannot construct a valid owner context and therefore never reaches
//! `gate_owner` or `decide_status`. Those remain covered only by their
//! definitions. Widening this coverage needs the integration owner to add the
//! three dependencies; it is not a defect in the cells.
//!
//! Per `module.toml`, the crate's own proof ceiling is
//! `STATIC_FIELD_CONTRACT_ONLY`. Nothing here is edge, product, or pulse proof.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::{
    ArtifactId, ContractVersion, EpochId, EpochLineageId, ResourceGeneration, StateFence,
    sha256_hex,
};
use eliot_dreamer_contracts::self_query::{
    AcceptedSourceProjection, AcceptedSourceRef, ArchitectureSourceStatus, NormativePairBinding,
};
use eliot_understanding_assessment::{
    AssessmentClosure, AssessmentError, AssessmentScope, AssessmentStatus, CitedFamily, ClosureLeg,
    CommonGroundAssessment, EvidenceCite, FREEZE_ID, LegEvidence, MAX_EVIDENCE_CITES,
    MAX_MISSING_INPUTS, MAX_SCOPE_TEXT, ScopedUnderstandingAssessment, UA_CONTRACT_VERSION,
};

const ARCHITECTURE_DIGEST: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const IMPLEMENTATION_DIGEST: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";

fn digest() -> String {
    "a".repeat(64)
}

/// One well-formed lowercase-hex digest, distinct per call site so a digest
/// comparison in an assertion is never satisfied by two equal values.
fn distinct_digest(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn handle(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact identity")
}

fn fence() -> StateFence {
    let lineage =
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture epoch lineage");
    let epoch = EpochId::new(
        lineage,
        std::num::NonZeroU64::new(1).expect("epoch sequence"),
    )
    .expect("fixture epoch");
    StateFence::new(
        epoch,
        ResourceGeneration::new(1).expect("fixture resource generation"),
    )
}

/// An onboarded scope: a non-blank onboarding slice and no missing inputs, which
/// is exactly what `AssessmentScope::is_onboarded` requires.
fn onboarded_scope() -> AssessmentScope {
    AssessmentScope {
        question_family: "understanding-question".to_owned(),
        task_family: "understanding-task".to_owned(),
        product_id: "understanding-product".to_owned(),
        scope_id: "understanding-scope".to_owned(),
        state_fence: fence(),
        onboarding_slice: "onboarding-slice".to_owned(),
        missing_inputs: Vec::new(),
    }
}

/// A well-formed accepted-source cite.
fn accepted_cite(seed: char) -> EvidenceCite {
    EvidenceCite {
        handle: handle("accepted-source"),
        family: CitedFamily::AcceptedSource,
        revision: "r1".to_owned(),
        digest: distinct_digest(seed),
    }
}

/// The `NormativePairBinding` whose `pair_key` is the real digest of the two
/// document digests over the owner's documented preimage, so the fixture is a
/// genuinely valid pair binding rather than a well-shaped placeholder.
fn pair_binding() -> NormativePairBinding {
    let mut preimage = b"eliot-normative-pair-v1\0".to_vec();
    preimage.extend_from_slice(ARCHITECTURE_DIGEST.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(IMPLEMENTATION_DIGEST.as_bytes());
    preimage.push(0);
    NormativePairBinding {
        architecture_digest: ARCHITECTURE_DIGEST.to_owned(),
        implementation_digest: IMPLEMENTATION_DIGEST.to_owned(),
        pair_key: format!("sha256:{}", sha256_hex(&preimage)),
        document_set: "understanding-documents".to_owned(),
        architecture_revision: "architecture-revision".to_owned(),
        implementation_revision: "implementation-revision".to_owned(),
        accepted_by: eliot_contracts::SourceId::new("understanding-owner")
            .expect("fixture pair acceptor"),
        acceptance_receipt: eliot_contracts::ReceiptId::new("understanding-acceptance")
            .expect("fixture pair acceptance receipt"),
    }
}

fn accepted_source_ref() -> AcceptedSourceRef {
    AcceptedSourceRef {
        source_handle: handle("accepted-source"),
        owner: eliot_contracts::SourceId::new("understanding-owner").expect("fixture ref owner"),
        revision: "r1".to_owned(),
        digest: distinct_digest('b'),
        status: ArchitectureSourceStatus::Accepted,
        acceptance_receipt: eliot_contracts::ReceiptId::new("understanding-acceptance")
            .expect("fixture ref acceptance receipt"),
    }
}

/// A closure with every leg filled except the one named, which is how the
/// held-out rule is isolated: only `held_out` is left empty.
fn closure_missing(leg: ClosureLeg) -> AssessmentClosure {
    let mut closure = AssessmentClosure {
        rival_model: vec![accepted_cite('1')],
        pre_probe_prediction: vec![accepted_cite('2')],
        discriminator: vec![accepted_cite('3')],
        outcome_verifier: vec![accepted_cite('4')],
        revision: vec![accepted_cite('5')],
        held_out: vec![accepted_cite('6')],
    };
    match leg {
        ClosureLeg::RivalModel => closure.rival_model.clear(),
        ClosureLeg::PreProbePrediction => closure.pre_probe_prediction.clear(),
        ClosureLeg::Discriminator => closure.discriminator.clear(),
        ClosureLeg::OutcomeVerifier => closure.outcome_verifier.clear(),
        ClosureLeg::Revision => closure.revision.clear(),
        ClosureLeg::HeldOut => closure.held_out.clear(),
    }
    closure
}

/// A complete Common Ground candidate, digest-bound, as `assess_common_ground`
/// would emit it. Built here field-by-field because the constructor's
/// `OwnerContext` is unreachable from this package's dependency closure.
fn common_ground_candidate(product_claims: bool) -> CommonGroundAssessment {
    let closure = AssessmentClosure {
        rival_model: vec![accepted_cite('1')],
        pre_probe_prediction: vec![accepted_cite('2')],
        discriminator: vec![accepted_cite('3')],
        outcome_verifier: vec![accepted_cite('4')],
        revision: vec![accepted_cite('5')],
        held_out: if product_claims {
            vec![accepted_cite('6')]
        } else {
            Vec::new()
        },
    };
    let mut candidate = CommonGroundAssessment {
        contract_version: UA_CONTRACT_VERSION,
        scope: onboarded_scope(),
        common_ground_terminology_compatibility: vec![accepted_cite('a')],
        common_ground_reference_compatibility: vec![accepted_cite('b')],
        common_ground_commitment_compatibility: vec![accepted_cite('c')],
        common_ground_action_consequence_compatibility: vec![accepted_cite('d')],
        common_ground_goals_decisions_invariants_rivals_unknowns_survival_after_model_harness_change:
            vec![accepted_cite('e')],
        common_ground_public_inheritance_transfer_refs: vec![accepted_cite('f')],
        common_ground_requalification_scope_for_tacit_competence: "requalification-scope".to_owned(),
        closure_evidence: LegEvidence::annex(&closure),
        product_claims,
        status: AssessmentStatus::LocallyAdequate,
        digest: String::new(),
    };
    candidate.digest = candidate
        .compute_digest()
        .expect("common ground candidate digest");
    candidate
}

/// A complete scoped candidate, digest-bound, as `assess_scoped` would emit it.
fn scoped_candidate() -> ScopedUnderstandingAssessment {
    let mut candidate = ScopedUnderstandingAssessment {
        contract_version: UA_CONTRACT_VERSION,
        scope: onboarded_scope(),
        scoped_subject_route_or_coupled_system: "understanding-subject".to_owned(),
        scoped_question_and_task_family: "understanding-question/understanding-task".to_owned(),
        scoped_product_and_state_fence: "understanding-product".to_owned(),
        scoped_current_model_and_rivals: vec![accepted_cite('1')],
        scoped_material_unknowns: vec![accepted_cite('2')],
        scoped_pre_probe_predictions_fixed_before_observation: vec![accepted_cite('3')],
        scoped_selected_discriminator_or_action: vec![accepted_cite('4')],
        scoped_observed_outcome_and_verifier: vec![accepted_cite('5')],
        scoped_model_revision_after_outcome: vec![accepted_cite('6')],
        scoped_counterfactual_or_held_out_evidence: vec![accepted_cite('7')],
        scoped_transfer_boundary_and_requalification: "transfer-boundary".to_owned(),
        scoped_onboarding_slice_and_missing_inputs: "onboarding-slice".to_owned(),
        scoped_status_not_onboarded_or_untested_or_locally_adequate_or_refuted_or_inconclusive_or_stale:
            AssessmentStatus::LocallyAdequate,
        scoped_unanswerable_stale_case_where_applicable: Vec::new(),
        scoped_counterfactual_intervention_or_state_update_case_where_applicable: Vec::new(),
        scoped_held_out_compositional_transfer_where_applicable: Vec::new(),
        scoped_abstention_precision_coverage_where_applicable: Vec::new(),
        digest: String::new(),
    };
    candidate.digest = candidate.compute_digest().expect("scoped candidate digest");
    candidate
}

// ---------------------------------------------------------------------------
// The assertion issue #238's audit most cares about (rescued W2d assertion).
// Absent from `main` entirely before this entrypoint.
// ---------------------------------------------------------------------------

/// The held-out closure leg is required **only** for a product claim.
///
/// This is the rule `module.toml` states twice — `denominator_rule`
/// ("for product claims verify held-out or leakage-controlled evidence") and
/// the `W9-UA-HELDOUT-WHERE-PRODUCT-CLAIM-APPLIES` validation gate — and it is
/// the only closure leg whose requirement is conditional on the product-claim
/// flag. Every other leg is required unconditionally.
///
/// The assertion is made against `AssessmentClosure::missing` /
/// `AssessmentClosure::is_complete_for`, which is the single closure-completeness
/// check both `assess_common_ground` and `assess_scoped` consult
/// (`src/lib.rs` :1325 and :1748) and which `CommonGroundAssessment::recheck`
/// re-applies leg-by-leg (:1193).
#[test]
fn held_out_closure_leg_is_required_only_for_product_claims() {
    // Held-out empty, every other leg filled.
    let closure = closure_missing(ClosureLeg::HeldOut);
    closure.validate().expect("shape-valid closure");

    // A product claim cannot be closed without held-out evidence.
    assert_eq!(
        closure.missing(true),
        vec!["closure.held_out"],
        "a product claim must require the held-out closure leg"
    );
    assert!(
        !closure.is_complete_for(true),
        "an empty held-out leg must not close a product claim"
    );

    // The same closure closes a claim that is not a product claim.
    assert!(
        closure.missing(false).is_empty(),
        "held-out must not be required when the claim is not a product claim, got {:?}",
        closure.missing(false)
    );
    assert!(
        closure.is_complete_for(false),
        "held-out must not be required when the claim is not a product claim"
    );

    // With held-out evidence present the product claim closes too.
    let complete = AssessmentClosure {
        rival_model: vec![accepted_cite('1')],
        pre_probe_prediction: vec![accepted_cite('2')],
        discriminator: vec![accepted_cite('3')],
        outcome_verifier: vec![accepted_cite('4')],
        revision: vec![accepted_cite('5')],
        held_out: vec![accepted_cite('6')],
    };
    assert!(complete.missing(true).is_empty());
    assert!(complete.is_complete_for(true));
    assert!(complete.is_complete_for(false));

    // Every other leg is required unconditionally: emptying any one of them is
    // missing under *both* flag values. This is what makes the held-out leg the
    // only conditional one rather than merely one conditional leg.
    for leg in [
        ClosureLeg::RivalModel,
        ClosureLeg::PreProbePrediction,
        ClosureLeg::Discriminator,
        ClosureLeg::OutcomeVerifier,
        ClosureLeg::Revision,
    ] {
        let closure = closure_missing(leg);
        let name = LegEvidence::name(leg);
        assert_eq!(
            closure.missing(false),
            vec![name],
            "{name} must be required for a non-product claim"
        );
        assert_eq!(
            closure.missing(true),
            vec![name],
            "{name} must be required for a product claim"
        );
        assert!(!closure.is_complete_for(false));
        assert!(!closure.is_complete_for(true));
    }
}

// ---------------------------------------------------------------------------
// Cell `smart.understanding.common_ground`
// ---------------------------------------------------------------------------

/// The persisted closure annex carries exactly one entry per closure leg, in
/// canonical order, so `recheck` can re-apply the identical role gate the
/// constructor ran. The held-out leg is persisted last and is labelled
/// `closure.held_out`.
#[test]
fn common_ground_annex_is_persisted_in_canonical_leg_order() {
    let closure = AssessmentClosure {
        rival_model: vec![accepted_cite('1')],
        pre_probe_prediction: vec![accepted_cite('2')],
        discriminator: vec![accepted_cite('3')],
        outcome_verifier: vec![accepted_cite('4')],
        revision: vec![accepted_cite('5')],
        held_out: vec![accepted_cite('6')],
    };
    let annex = LegEvidence::annex(&closure);

    let legs: Vec<ClosureLeg> = annex.iter().map(|entry| entry.leg).collect();
    assert_eq!(
        legs,
        vec![
            ClosureLeg::RivalModel,
            ClosureLeg::PreProbePrediction,
            ClosureLeg::Discriminator,
            ClosureLeg::OutcomeVerifier,
            ClosureLeg::Revision,
            ClosureLeg::HeldOut,
        ],
        "the annex must follow the canonical leg order"
    );

    // Each persisted leg carries exactly the cites its closure slot supplied.
    for entry in &annex {
        let expected = match entry.leg {
            ClosureLeg::RivalModel => &closure.rival_model,
            ClosureLeg::PreProbePrediction => &closure.pre_probe_prediction,
            ClosureLeg::Discriminator => &closure.discriminator,
            ClosureLeg::OutcomeVerifier => &closure.outcome_verifier,
            ClosureLeg::Revision => &closure.revision,
            ClosureLeg::HeldOut => &closure.held_out,
        };
        assert_eq!(&entry.cites, expected);
    }

    assert_eq!(LegEvidence::name(ClosureLeg::HeldOut), "closure.held_out");
}

/// A digest-bound Common Ground candidate in the frozen contract version
/// validates, and its digest is stable across recomputation.
#[test]
fn common_ground_candidate_validates_at_the_frozen_contract_version() {
    let candidate = common_ground_candidate(true);
    candidate.validate().expect("common ground candidate");
    assert_eq!(candidate.contract_version, UA_CONTRACT_VERSION);
    assert_eq!(
        candidate.digest,
        candidate.compute_digest().expect("recomputed digest"),
        "the frozen digest must be reproducible"
    );
    assert_eq!(candidate.closure_evidence.len(), 6);
}

/// The annex is the crate's own recheck contract: dropping a leg, adding one,
/// or reordering them is refused, because `recheck` gates each list by its
/// stored label.
#[test]
fn common_ground_candidate_refuses_an_annex_that_is_not_canonical() {
    let candidate = common_ground_candidate(true);

    let mut short = candidate.clone();
    short.closure_evidence.pop();
    assert_eq!(
        short.validate(),
        Err(AssessmentError::InvalidField {
            field: "assessment.closure_evidence",
            reason: "annex must carry exactly one entry per closure leg",
        }),
        "a missing closure leg must be refused"
    );

    let mut extra = candidate.clone();
    extra
        .closure_evidence
        .push(LegEvidence::annex(&AssessmentClosure::default())[0].clone());
    assert!(matches!(
        extra.validate(),
        Err(AssessmentError::InvalidField { .. })
    ));

    let mut reordered = candidate.clone();
    reordered.closure_evidence.swap(0, 5);
    assert_eq!(
        reordered.validate(),
        Err(AssessmentError::InvalidField {
            field: "assessment.closure_evidence",
            reason: "annex legs must follow canonical order",
        }),
        "a reordered annex must be refused"
    );
}

/// `validate()` is a shape and tamper check: any post-construction mutation of
/// a covered field breaks the frozen digest. This is what makes a persisted
/// candidate's recheck meaningful.
#[test]
fn common_ground_candidate_refuses_a_tampered_digest() {
    let mut candidate = common_ground_candidate(true);
    candidate.common_ground_public_inheritance_transfer_refs = vec![accepted_cite('9')];
    assert_eq!(
        candidate.validate(),
        Err(AssessmentError::DigestMismatch {
            field: "assessment.digest",
        }),
        "mutating a covered field must break the frozen digest"
    );

    // The product-claim flag is digest-bound, so flipping it is a tamper too.
    let mut flipped = common_ground_candidate(false);
    flipped.product_claims = true;
    assert_eq!(
        flipped.validate(),
        Err(AssessmentError::DigestMismatch {
            field: "assessment.digest",
        }),
        "the product-claim flag must be digest-bound"
    );
}

/// The crate envelope rejects contract-version drift: `validate()` accepts
/// exactly `UA_CONTRACT_VERSION`, so a 1.0.0 candidate from branch history
/// cannot be re-sealed as current.
#[test]
fn common_ground_candidate_refuses_contract_version_drift() {
    let mut candidate = common_ground_candidate(false);
    candidate.contract_version = ContractVersion::new(1, 0, 0);
    assert_eq!(
        candidate.validate(),
        Err(AssessmentError::VersionMismatch),
        "a 1.0.0 candidate must be refused at 1.1.0"
    );
}

// ---------------------------------------------------------------------------
// Cell `smart.understanding.scoped_assessment`
// ---------------------------------------------------------------------------

/// A digest-bound scoped candidate validates and carries the closure legs in the
/// frozen `scoped_*` fields.
#[test]
fn scoped_candidate_validates_at_the_frozen_contract_version() {
    let candidate = scoped_candidate();
    candidate.validate().expect("scoped candidate");
    assert_eq!(candidate.contract_version, UA_CONTRACT_VERSION);
    assert_eq!(
        candidate.digest,
        candidate.compute_digest().expect("recomputed digest")
    );
    assert_eq!(
        candidate.scoped_question_and_task_family, "understanding-question/understanding-task",
        "the scoped field must be the declared question/task family"
    );
    assert_eq!(
        candidate.scoped_product_and_state_fence,
        "understanding-product"
    );
}

/// The same tamper and version gates apply to the scoped cell, and the
/// `*_where_applicable` slots are shape-checked but never required.
#[test]
fn scoped_candidate_refuses_tampering_and_version_drift() {
    let mut tampered = scoped_candidate();
    tampered.scoped_observed_outcome_and_verifier = vec![accepted_cite('9')];
    assert_eq!(
        tampered.validate(),
        Err(AssessmentError::DigestMismatch {
            field: "assessment.digest",
        })
    );

    let mut drifted = scoped_candidate();
    drifted.contract_version = ContractVersion::new(1, 0, 0);
    assert_eq!(drifted.validate(), Err(AssessmentError::VersionMismatch));

    // `*_where_applicable` slots stay optional: the candidate above carries all
    // four empty and still validates, which is the "where applicable" rule.
    let candidate = scoped_candidate();
    assert!(
        candidate
            .scoped_held_out_compositional_transfer_where_applicable
            .is_empty()
    );
    candidate.validate().expect("optional slots stay optional");
}

/// Text identity fields are bounded and non-blank: a blank, control-bearing or
/// overlong field is refused by name rather than carried into a candidate.
///
/// `validate()` checks these texts before it recomputes the digest, so each case
/// below fails on its own field rather than on `assessment.digest` even though
/// the mutation also invalidated the carried digest.
#[test]
fn scoped_candidate_refuses_blank_and_control_bearing_text() {
    let mut blank = scoped_candidate();
    blank.scoped_transfer_boundary_and_requalification = "   ".to_owned();
    assert!(matches!(
        blank.validate(),
        Err(AssessmentError::InvalidField {
            field: "assessment.scoped_transfer_boundary_and_requalification",
            ..
        })
    ));

    let mut control = scoped_candidate();
    control.scoped_subject_route_or_coupled_system = "subject\u{7}route".to_owned();
    assert!(matches!(
        control.validate(),
        Err(AssessmentError::InvalidField {
            field: "assessment.scoped_subject_route_or_coupled_system",
            ..
        })
    ));

    let mut overlong = scoped_candidate();
    overlong.scoped_product_and_state_fence = "x".repeat(MAX_SCOPE_TEXT + 1);
    assert!(matches!(
        overlong.validate(),
        Err(AssessmentError::InvalidField {
            field: "assessment.scoped_product_and_state_fence",
            ..
        })
    ));
}

// ---------------------------------------------------------------------------
// Shared surface: the denominator anchor and the shared cite / owner surface.
// These types belong to neither cell alone and are exercised through the same
// public surface both assessments use.
// ---------------------------------------------------------------------------

/// Onboarding is the denominator anchor: `LOCALLY_ADEQUATE` is forbidden until
/// a non-blank slice exists and nothing is missing.
#[test]
fn assessment_scope_onboarding_requires_a_slice_and_no_missing_inputs() {
    let scope = onboarded_scope();
    scope.validate().expect("onboarded scope");
    assert!(scope.is_onboarded());

    let mut no_slice = onboarded_scope();
    no_slice.onboarding_slice = String::new();
    no_slice
        .validate()
        .expect("an absent slice is still shape-valid");
    assert!(
        !no_slice.is_onboarded(),
        "a blank onboarding slice must not count as onboarded"
    );

    let mut missing = onboarded_scope();
    missing.missing_inputs = vec!["accepted-source-projection".to_owned()];
    assert!(
        !missing.is_onboarded(),
        "a scope with missing inputs must not count as onboarded"
    );

    let mut unbounded = onboarded_scope();
    unbounded.missing_inputs = vec!["input".to_owned(); MAX_MISSING_INPUTS + 1];
    assert!(
        matches!(
            unbounded.validate(),
            Err(AssessmentError::InvalidField {
                field: "scope.missing_inputs",
                ..
            })
        ),
        "the missing-input list must stay bounded"
    );
}

/// An accepted-source cite is built from the projected ref exactly, and the
/// projection's exact-triple check accepts that cite while refusing drift.
#[test]
fn accepted_source_cite_is_built_from_the_projected_ref_exactly() {
    let reference = accepted_source_ref();
    let projection = AcceptedSourceProjection::project(
        handle("understanding-projection"),
        pair_binding(),
        fence(),
        vec![reference.clone()],
    )
    .expect("accepted-source projection");

    let cite = EvidenceCite::accepted(&reference).expect("accepted-source cite");
    assert_eq!(cite.family, CitedFamily::AcceptedSource);
    assert_eq!(cite.handle, reference.source_handle);
    assert_eq!(cite.revision, reference.revision);
    assert_eq!(cite.digest, reference.digest);

    projection
        .check_cited(&cite.handle, &cite.revision, &cite.digest)
        .expect("the cite must revalidate against its projection");

    // Any triple drift is stale, with no similarity fallback.
    assert!(
        projection
            .check_cited(&cite.handle, "r2", &cite.digest)
            .is_err(),
        "revision drift must be refused"
    );
    assert!(
        projection
            .check_cited(&cite.handle, &cite.revision, &distinct_digest('c'))
            .is_err(),
        "digest drift must be refused"
    );
}

/// Cite shape is checked independently of any owner object: a non-hex or
/// uppercase digest and an unbounded revision are refused.
#[test]
fn evidence_cite_refuses_a_malformed_revision_or_digest() {
    let uppercase = EvidenceCite {
        handle: handle("accepted-source"),
        family: CitedFamily::AcceptedSource,
        revision: "r1".to_owned(),
        digest: "A".repeat(64),
    };
    assert!(matches!(
        uppercase.validate(),
        Err(AssessmentError::InvalidField {
            field: "cite.digest",
            ..
        })
    ));

    let short = EvidenceCite {
        handle: handle("accepted-source"),
        family: CitedFamily::AcceptedSource,
        revision: "r1".to_owned(),
        digest: "a".repeat(63),
    };
    assert!(matches!(
        short.validate(),
        Err(AssessmentError::InvalidField {
            field: "cite.digest",
            ..
        })
    ));

    let long_revision = EvidenceCite {
        handle: handle("accepted-source"),
        family: CitedFamily::AcceptedSource,
        revision: "r".repeat(MAX_SCOPE_TEXT + 1),
        digest: digest(),
    };
    assert!(matches!(
        long_revision.validate(),
        Err(AssessmentError::InvalidField {
            field: "cite.revision",
            ..
        })
    ));
}

/// One cite list may not exceed the declared bound. This is the per-slot bound
/// both assessments apply through `AssessmentClosure::validate`.
#[test]
fn closure_cite_lists_are_bounded() {
    let cite = accepted_cite('a');
    let closure = AssessmentClosure {
        rival_model: vec![cite.clone(); MAX_EVIDENCE_CITES + 1],
        ..AssessmentClosure::default()
    };
    assert!(
        matches!(
            closure.validate(),
            Err(AssessmentError::InvalidField {
                field: "closure.rival_model",
                ..
            })
        ),
        "a cite list above the declared bound must be refused"
    );
}

/// The declared freeze identity and contract version are the exact ones this
/// entrypoint is written against; a drift here invalidates every assertion in
/// this file.
#[test]
fn crate_envelope_declares_the_freeze_and_contract_version_under_test() {
    assert_eq!(
        FREEZE_ID,
        "cognitive-rev12-contract-schema-freeze-2026-09-22-r8"
    );
    assert_eq!(UA_CONTRACT_VERSION, ContractVersion::new(1, 1, 0));
}
