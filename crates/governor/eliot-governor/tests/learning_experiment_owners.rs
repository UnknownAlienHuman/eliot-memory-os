//! Owner-seam fixtures for the Governor improvement-experiment producers
//! (`#45`, CC-007).
//!
//! Acceptance bullet under test: "Attribution, outcome, experiment, and promotion
//! are distinct versioned contracts" — for the experiment half only. This file
//! fixes the behaviour of the eight owner seams
//! [`eliot_learning_contracts::ImprovementExperimentCandidate`] had no producer
//! for, plus the outer-loop producer itself, so a later owner cannot regress any
//! of them.
//!
//! Every case drives the real production entry point
//! `crates/governor/eliot-governor/src/learning_experiment.rs::run_improvement_experiment_loop`,
//! which is the call
//! `crates/meta/eliot-improvement/src/lib.rs::ImprovementCandidate::transition_lifecycle`
//! makes on the live daemon's `accepted_for_experiment` edge.
//!
//! Refusals use the existing typed vocabulary only: an absent owner is
//! [`eliot_governor::ExperimentRefusal::OwnerAbsent`] naming its seam, a
//! content failure is [`eliot_learning_contracts::LearningContractError`], and a
//! maintenance-owner record failure is
//! [`eliot_maintenance::PipelineError`]. No case asserts a string verdict or a
//! boolean.

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_governor::{
    AssignmentOwnerRecord, AttributionLineageOwnerRecord, BoundedPlanOwnerRecord,
    ContaminationOwnerRecord, EvidenceFreezeOwnerRecord, ExperimentLoopOutcome,
    ExperimentOwnerInput, ExperimentRefusal, MechanismOwnerRecord, OutcomeOwnerRecord,
    RollbackOwnerRecord, derive_experiment_candidate, run_improvement_experiment_loop,
};
use eliot_learning_contracts::{
    AssessmentDimension, AssignmentKind, AttributedSubject, CausalCeiling, ContractBinding,
    DimensionAssessment, DimensionStatus, ImprovementExperimentCandidate,
    LearningAssessmentCandidate, LearningContractError, OverlayId, SourceDenominator, SubjectKind,
    TargetId, UseAttributionCandidate, UseBasis, UseDisposition,
};
use eliot_maintenance::{
    ActivationEvidence, ExperimentPlan, IMPROVEMENT_EFFECT_CEILING,
    IMPROVEMENT_RISK_CEILING_BOUNDED, IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
    ImprovementEvidenceExecution, ImprovementProposal, MechanismDeclaration, PipelineError,
    RollbackContract,
};
use eliot_receipts::{ProofCeiling, WorkScopeId};

/// Shorthand for a fallible fixture step.
type Fixture = Result<(), Box<dyn std::error::Error>>;

const ATTRIBUTION_SEAM: &str = "experiment.attribution_owner";
const MECHANISM_SEAM: &str = "experiment.mechanism_owner";
const PLAN_SEAM: &str = "experiment.bounded_plan_owner";
const ASSIGNMENT_SEAM: &str = "experiment.assignment_owner";
const ROLLBACK_SEAM: &str = "experiment.rollback_owner";
const CONTAMINATION_SEAM: &str = "experiment.contamination_owner";
const FREEZE_SEAM: &str = "experiment.evidence_freeze_owner";
const OUTCOME_SEAM: &str = "experiment.outcome_owner";

fn aid(value: &str) -> Result<ArtifactId, Box<dyn std::error::Error>> {
    Ok(ArtifactId::new(value)?)
}

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn target(value: &str) -> Result<TargetId, Box<dyn std::error::Error>> {
    Ok(TargetId::new(value)?)
}

fn binding(tag: &str) -> Result<ContractBinding, Box<dyn std::error::Error>> {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?;
    let sequence = std::num::NonZeroU64::new(1).ok_or("nonzero fixture sequence")?;
    Ok(ContractBinding {
        schema_version: 1,
        policy_revision: PolicyRevision::genesis(),
        request_id: RequestId::new(format!("request-45e-{tag}"))?,
        operation_id: OperationId::new(format!("operation-45e-{tag}"))?,
        product_id: ProductId::new("eliot")?,
        task_id: TaskId::new(format!("task-45e-{tag}"))?,
        scope: WorkScopeId::new(format!("scope-45e-{tag}"))?,
        state_fence: StateFence::new(
            EpochId::new(lineage, sequence).map_err(|_| "valid fixture epoch")?,
            ResourceGeneration::genesis(),
        ),
        source: eliot_learning_contracts::identity::SourceLineage {
            owner: SourceId::new(format!("source-45e-{tag}"))?,
            snapshot: aid(&format!("snapshot-45e-{tag}"))?,
            revision: TaskRevision::genesis(),
            digest: digest(&format!("source-45e-{tag}")),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
    })
}

fn dimension(
    name: AssessmentDimension,
    owner_receipt: ArtifactId,
    tag: &str,
) -> Result<DimensionAssessment, Box<dyn std::error::Error>> {
    Ok(DimensionAssessment {
        dimension: name,
        status: DimensionStatus::Pass,
        evidence: vec![aid(&format!("dimension-evidence-45e-{tag}"))?],
        owner_receipt: Some(owner_receipt),
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        metric_ids: vec![aid(&format!("dimension-metric-45e-{tag}"))?],
        causal_ceiling: CausalCeiling::Observational,
    })
}

/// The sealed attribution the experiment consumes.
///
/// Built through the attribution owner's own shape so the experiment's lineage
/// is a real owner record rather than four restated strings.
fn attribution(
    tag: &str,
    shared: &ContractBinding,
) -> Result<UseAttributionCandidate, Box<dyn std::error::Error>> {
    let subject_id = aid(&format!("subject-45e-{tag}"))?;
    let rival = aid(&format!("rival-45e-{tag}"))?;
    let mut candidate = UseAttributionCandidate {
        binding: shared.clone(),
        attribution_id: aid(&format!("use-attribution-45e-{tag}"))?,
        target: target(&format!("target-45e-{tag}"))?,
        subject: AttributedSubject {
            kind: SubjectKind::Skill,
            id: subject_id.clone(),
            version: format!("v1.0.0-45e-{tag}"),
            digest: digest(&format!("subject-record-45e-{tag}")),
        },
        decision_action_id: aid(&format!("decided-action-45e-{tag}"))?,
        source_delta_id: aid(&format!("learning-delta:45e:{tag}"))?,
        source_delta_digest: digest(&format!("stored-delta-45e-{tag}")),
        disposition: UseDisposition::Used,
        use_basis: UseBasis::DirectObservation,
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        eligible_refs: vec![subject_id],
        non_use: vec![],
        competing_contributors: vec![rival],
        evaluator_receipt: aid(&format!("independent-observation-45e-{tag}"))?,
        evidence_refs: vec![aid(&format!("attribution-evidence-45e-{tag}"))?],
        dimensions: vec![
            dimension(
                AssessmentDimension::ActionLinkedUse,
                aid(&format!("action-use-receipt-45e-{tag}"))?,
                &format!("{tag}-action-linked-use"),
            )?,
            dimension(
                AssessmentDimension::Harm,
                aid(&format!("harm-receipt-45e-{tag}"))?,
                &format!("{tag}-harm"),
            )?,
            dimension(
                AssessmentDimension::SourceEvaluatorIndependence,
                aid(&format!("independence-receipt-45e-{tag}"))?,
                &format!("{tag}-independence"),
            )?,
        ],
        claim_ceiling: CausalCeiling::Observational,
        canonical_digest: String::new(),
    };
    candidate.seal()?;
    Ok(candidate)
}

/// Per-case knobs, so every refusal is a named owner-record defect rather than a
/// hand-built verdict.
#[allow(
    clippy::struct_excessive_bools,
    reason = "one knob per owner-record defect this fixture has to express"
)]
#[derive(Clone)]
struct Knobs {
    declared_before_results: bool,
    evaluator_is_executor: bool,
    effect_ceiling: String,
    risk_ceiling: String,
    seed_digest: String,
    blank_rollback: bool,
    empty_prior_exposure: bool,
    activation_execution: ImprovementEvidenceExecution,
    activation_independent: bool,
    foreign_experiment_binding: bool,
    self_independence_receipt: bool,
}

impl Default for Knobs {
    fn default() -> Self {
        Self {
            declared_before_results: true,
            evaluator_is_executor: false,
            effect_ceiling: IMPROVEMENT_EFFECT_CEILING.to_owned(),
            risk_ceiling: IMPROVEMENT_RISK_CEILING_BOUNDED.to_owned(),
            seed_digest: digest("assignment-seed-45e"),
            blank_rollback: false,
            empty_prior_exposure: false,
            activation_execution: ImprovementEvidenceExecution::Executed,
            activation_independent: true,
            foreign_experiment_binding: false,
            self_independence_receipt: false,
        }
    }
}

/// Every published owner record for one experiment derivation, plus the eight
/// owner seams over them.
///
/// Each owned record is leaked for the fixture's lifetime so the owner records
/// can borrow it, exactly as the attribution fixture does.
struct Owners {
    attribution: &'static UseAttributionCandidate,
    mechanism: &'static MechanismDeclaration,
    plan: &'static ExperimentPlan,
    proposal: &'static ImprovementProposal,
    activation: &'static ActivationEvidence,
    rollback: &'static RollbackContract,
    assessment: &'static LearningAssessmentCandidate,
    input: ExperimentOwnerInput<'static>,
}

/// Build all eight owner records and the presentation over them.
#[allow(
    clippy::too_many_lines,
    reason = "one owner-record construction block per owner seam, kept together so the fixture reads as the owners' records"
)]
fn owners(tag: &str, knobs: &Knobs) -> Result<Box<Owners>, Box<dyn std::error::Error>> {
    let shared = binding(tag)?;
    let attribution = Box::leak(Box::new(attribution(tag, &shared)?));
    let proposal = Box::leak(Box::new(proposal(tag, knobs)));
    let mechanism = Box::leak(Box::new(MechanismDeclaration {
        mechanism_id: format!("mechanism-45e-{tag}"),
        hypothesis: format!("the declared change reduces the recorded regret for {tag}"),
        causal_link: format!("declared causal link for {tag}"),
        declared_ref: format!("mechanism-declaration-ref-45e-{tag}"),
        declared_before_results: knobs.declared_before_results,
    }));
    let executor = if knobs.evaluator_is_executor {
        "testd-20".to_owned()
    } else {
        format!("independent-evaluator-45e-{tag}")
    };
    let plan = Box::leak(Box::new(ExperimentPlan {
        experiment_id: format!("bounded-experiment-45e-{tag}"),
        testd_owner_id: "testd-20".to_owned(),
        evaluator_id: executor,
        scope_ref: format!("scope-45e-{tag}"),
        budget_ref: format!("budget-45e-{tag}"),
        deadline_ref: format!("deadline-45e-{tag}"),
        operation_ref: format!("operation-45e-{tag}"),
        idempotency_key: format!("idempotency-45e-{tag}"),
        scope_refinement: None,
    }));
    let activation = Box::leak(Box::new(ActivationEvidence {
        evidence_id: format!("activation-evidence-45e-{tag}"),
        verifier_id: plan.evaluator_id.clone(),
        independent: knobs.activation_independent,
        verifier_passed: true,
        raw_evidence_ref: format!("raw-evidence-45e-{tag}"),
        run_ref: format!("run-45e-{tag}"),
        content_revision_ref: format!("content-revision-45e-{tag}"),
        execution: knobs.activation_execution,
        bound_candidate_id: proposal.candidate_id.clone(),
        bound_experiment_id: if knobs.foreign_experiment_binding {
            "another-bounded-experiment-45e".to_owned()
        } else {
            plan.experiment_id.clone()
        },
    }));
    let blank = if knobs.blank_rollback {
        String::new()
    } else {
        format!("rollback-45e-{tag}")
    };
    let rollback = Box::leak(Box::new(RollbackContract {
        rollback_ref: blank.clone(),
        disable_ref: blank.clone(),
        reopen_ref: blank.clone(),
        expiry_ref: blank.clone(),
        rollback_owner_id: format!("rollback-owner-45e-{tag}"),
        forward_repair_ref: blank,
        invalidation_set: vec![],
    }));
    let independence_receipt = if knobs.self_independence_receipt {
        aid(&format!("assessment-receipt-45e-{tag}"))?
    } else {
        aid(activation.evidence_id.as_str())?
    };
    let assessment = Box::leak(Box::new(assessment(tag, &shared, independence_receipt)?));
    let seed_digest: &'static String = Box::leak(Box::new(knobs.seed_digest.clone()));
    let assignment_receipt = aid(&format!("assignment-receipt-45e-{tag}"))?;
    let contamination_policy: &'static String =
        Box::leak(Box::new(format!("prior exposure is accounted for {tag}")));
    let prior_exposure: &'static Vec<ArtifactId> = if knobs.empty_prior_exposure {
        Box::leak(Box::new(Vec::new()))
    } else {
        Box::leak(Box::new(vec![aid(&format!("prior-exposure-45e-{tag}"))?]))
    };
    let contamination_receipt = aid(&format!("contamination-receipt-45e-{tag}"))?;
    let freeze_receipt = aid(&format!("freeze-receipt-45e-{tag}"))?;

    let attribution_seam = AttributionLineageOwnerRecord {
        attribution: Box::leak(Box::new((*attribution).clone())),
    };
    let mechanism_seam = MechanismOwnerRecord {
        declaration: mechanism,
        proposal,
    };
    let plan_seam = BoundedPlanOwnerRecord { plan, proposal };
    let assignment_seam = AssignmentOwnerRecord {
        kind: AssignmentKind::Randomized,
        seed_digest: seed_digest.as_str(),
        owner_receipt: Box::leak(Box::new(assignment_receipt)),
    };
    let rollback_seam = RollbackOwnerRecord { contract: rollback };
    let contamination_seam = ContaminationOwnerRecord {
        policy: contamination_policy.as_str(),
        accounted_refs: prior_exposure,
        owner_receipt: Box::leak(Box::new(contamination_receipt)),
    };
    let freeze_seam = EvidenceFreezeOwnerRecord {
        proposal,
        activation,
        freeze_receipt: Box::leak(Box::new(freeze_receipt)),
    };
    let outcome_seam = OutcomeOwnerRecord {
        assessment,
        plan,
        activation,
    };
    Ok(Box::new(Owners {
        attribution,
        mechanism,
        plan,
        proposal,
        activation,
        rollback,
        assessment,
        input: ExperimentOwnerInput {
            attribution: Some(Box::leak(Box::new(attribution_seam))),
            mechanism: Some(Box::leak(Box::new(mechanism_seam))),
            plan: Some(Box::leak(Box::new(plan_seam))),
            assignment: Some(Box::leak(Box::new(assignment_seam))),
            rollback: Some(Box::leak(Box::new(rollback_seam))),
            contamination: Some(Box::leak(Box::new(contamination_seam))),
            freeze: Some(Box::leak(Box::new(freeze_seam))),
            outcome: Some(Box::leak(Box::new(outcome_seam))),
        },
    }))
}

/// The Governor-side proposal the freeze owner commits.
fn proposal(tag: &str, knobs: &Knobs) -> ImprovementProposal {
    ImprovementProposal {
        proposal_id: format!("proposal-45e-{tag}"),
        candidate_id: format!("candidate-45e-{tag}"),
        campaign_id: format!("campaign-45e-{tag}"),
        closure_id: format!("closure-45e-{tag}"),
        closure_digest: format!("closure-digest-45e-{tag}"),
        evidence_refs: vec![
            format!("closure-evidence-45e-{tag}"),
            format!("canonical-evidence-45e-{tag}"),
        ],
        target_capability: format!("capability-45e-{tag}"),
        target_generation: format!("generation-45e-{tag}"),
        mechanism: MechanismDeclaration {
            mechanism_id: format!("mechanism-45e-{tag}"),
            hypothesis: format!("the declared change reduces the recorded regret for {tag}"),
            causal_link: format!("declared causal link for {tag}"),
            declared_ref: format!("mechanism-declaration-ref-45e-{tag}"),
            declared_before_results: true,
        },
        expected_delta: format!("expected delta for {tag}"),
        risk_ceiling: knobs.risk_ceiling.clone(),
        effect_ceiling: knobs.effect_ceiling.clone(),
        budget_ref: format!("budget-45e-{tag}"),
        deadline_ref: format!("deadline-45e-{tag}"),
        privacy_class: format!("privacy-class-45e-{tag}"),
        invalidation_set: vec![format!("invalidation-45e-{tag}")],
        operation_ref: format!("operation-45e-{tag}"),
        idempotency_key: format!("idempotency-45e-{tag}"),
        source_identity: format!("source-identity-45e-{tag}"),
        runtime_identity: format!("runtime-identity-45e-{tag}"),
        data_identity: format!("data-identity-45e-{tag}"),
    }
}

/// The dimensioned assessment the outcome owner published.
fn assessment(
    tag: &str,
    shared: &ContractBinding,
    independence_receipt: ArtifactId,
) -> Result<LearningAssessmentCandidate, Box<dyn std::error::Error>> {
    let mut assessment = LearningAssessmentCandidate {
        binding: shared.clone(),
        target: target(&format!("target-45e-{tag}"))?,
        overlay_id: OverlayId::from_artifact(aid(&format!("overlay-45e-{tag}"))?),
        activation_id: aid(&format!("activation-45e-{tag}"))?,
        activation_digest: digest(&format!("activation-content-45e-{tag}")),
        assessment_receipt: aid(&format!("assessment-receipt-45e-{tag}"))?,
        dimensions: vec![
            dimension(
                AssessmentDimension::BaselineControlQuality,
                aid(&format!("control-receipt-45e-{tag}"))?,
                &format!("{tag}-baseline-control"),
            )?,
            dimension(
                AssessmentDimension::Harm,
                aid(&format!("harm-receipt-45e-{tag}"))?,
                &format!("{tag}-harm"),
            )?,
            dimension(
                AssessmentDimension::Confounders,
                aid(&format!("confounder-receipt-45e-{tag}"))?,
                &format!("{tag}-confounders"),
            )?,
            DimensionAssessment {
                dimension: AssessmentDimension::SourceEvaluatorIndependence,
                status: DimensionStatus::Pass,
                evidence: vec![aid(&format!("independence-evidence-45e-{tag}"))?],
                owner_receipt: Some(independence_receipt),
                denominator: SourceDenominator {
                    declared: 1,
                    observed: 1,
                },
                metric_ids: vec![aid(&format!("independence-metric-45e-{tag}"))?],
                causal_ceiling: CausalCeiling::Observational,
            },
        ],
        causal_ceiling: CausalCeiling::Observational,
        external_review_refs: vec![],
        canonical_digest: String::new(),
    };
    assessment.seal()?;
    Ok(assessment)
}

/// Positive case: every owner seam published, and every one of the twenty-two
/// fields is bound to the owner that published it.
#[test]
fn experimental_candidate_binds_each_field_to_its_owner() -> Fixture {
    let published = owners("positive", &Knobs::default())?;
    let outcome = run_improvement_experiment_loop(&published.input);
    let ExperimentLoopOutcome::Experimental(boxed) = outcome else {
        panic!("a fully owner-published derivation must produce an experiment");
    };
    let candidate: &ImprovementExperimentCandidate = &boxed;
    candidate.validate()?;
    candidate.validate_against_attribution(published.attribution)?;

    // Seam 1 — attribution-lineage owner: four fields, all read out of the
    // sealed attribution record.
    assert_eq!(candidate.binding, published.attribution.binding);
    assert_eq!(candidate.target, published.attribution.target);
    assert_eq!(
        candidate.attribution_id,
        published.attribution.attribution_id
    );
    assert_eq!(
        candidate.attribution_digest,
        published.attribution.canonical_digest
    );

    // Seam 2 — mechanism owner.
    assert_eq!(candidate.hypothesis, published.mechanism.hypothesis);
    assert!(!candidate.pre_observation_discriminator.as_str().is_empty());

    // Seam 3 — bounded-plan owner.
    assert_eq!(
        candidate.eligibility,
        format!(
            "scope={};budget={};deadline={}",
            published.plan.scope_ref, published.plan.budget_ref, published.plan.deadline_ref
        )
    );
    assert_ne!(candidate.intervention_id, candidate.control_id);
    assert!(!candidate.safeguards.is_empty());
    assert_eq!(candidate.stop_conditions.len(), 2);

    // Seam 4 — assignment owner.
    assert_eq!(candidate.assignment, AssignmentKind::Randomized);
    assert_eq!(candidate.assignment_seed_digest.len(), 64);

    // Seam 5 — rollback owner. The five handles this fixture publishes collapse to
    // one identity by content, so the derived set cannot be inflated by
    // repeating a reference.
    assert_eq!(
        candidate.rollback_refs,
        vec![aid(&published.rollback.rollback_ref)?]
    );

    // Seam 6 — contamination owner.
    assert_eq!(
        candidate.contamination_policy,
        "prior exposure is accounted for positive"
    );
    assert_eq!(candidate.prior_exposure_refs.len(), 1);

    // Seam 7 — evidence-freeze owner. The digest is the maintenance owner's own
    // domain-separated, versioned commitment, not a digest recomputed here.
    let commitment = eliot_maintenance::proposal_digest(published.proposal)?;
    assert_eq!(candidate.evidence_freeze_digest, commitment.digest);
    assert!(
        candidate
            .evidence_freeze_refs
            .contains(&ArtifactId::new(published.activation.evidence_id.clone())?)
    );

    // Seam 8 — outcome/verifier owner: the dimensioned result and the weakest
    // causal ceiling it supports, never a scalar score.
    assert_eq!(
        candidate.outcome_dimensions,
        published.assessment.dimensions
    );
    assert_eq!(candidate.claim_ceiling, published.assessment.causal_ceiling);
    assert!(
        candidate
            .outcome_dimensions
            .iter()
            .any(|item| item.dimension == AssessmentDimension::BaselineControlQuality),
        "the baseline/control arm must be dimensioned, not summarized"
    );
    assert!(
        candidate
            .outcome_dimensions
            .iter()
            .any(|item| item.dimension == AssessmentDimension::Harm),
        "harm stays an independent dimension of the experiment outcome"
    );

    // The independence dimension is carried by the independent activation
    // record's own identity, so the executor cannot certify its own
    // independence.
    let independence_dimension = candidate
        .outcome_dimensions
        .iter()
        .find(|item| item.dimension == AssessmentDimension::SourceEvaluatorIndependence)
        .ok_or("the independence dimension is mandatory")?;
    assert_eq!(
        independence_dimension.owner_receipt.as_ref(),
        Some(&ArtifactId::new(published.activation.evidence_id.clone())?)
    );

    // Identity is content: a different attribution lineage never shares the
    // experiment identity.
    let other_owners = owners("other-lineage", &Knobs::default())?;
    let ExperimentLoopOutcome::Experimental(other_boxed) =
        run_improvement_experiment_loop(&other_owners.input)
    else {
        panic!("a fully owner-published derivation must produce an experiment");
    };
    assert_ne!(candidate.experiment_id, other_boxed.experiment_id);
    Ok(())
}

/// Refusal case per owner seam: an owner that published nothing is named by its
/// own typed refusal, never defaulted and never passed through.
#[test]
fn each_absent_owner_seam_is_named_by_its_own_typed_refusal() -> Fixture {
    let owners = owners("absent", &Knobs::default())?;
    let published = owners.input;

    let cases = [
        (
            ATTRIBUTION_SEAM,
            ExperimentOwnerInput {
                attribution: None,
                ..published
            },
        ),
        (
            MECHANISM_SEAM,
            ExperimentOwnerInput {
                mechanism: None,
                ..published
            },
        ),
        (
            PLAN_SEAM,
            ExperimentOwnerInput {
                plan: None,
                ..published
            },
        ),
        (
            ASSIGNMENT_SEAM,
            ExperimentOwnerInput {
                assignment: None,
                ..published
            },
        ),
        (
            ROLLBACK_SEAM,
            ExperimentOwnerInput {
                rollback: None,
                ..published
            },
        ),
        (
            CONTAMINATION_SEAM,
            ExperimentOwnerInput {
                contamination: None,
                ..published
            },
        ),
        (
            FREEZE_SEAM,
            ExperimentOwnerInput {
                freeze: None,
                ..published
            },
        ),
        (
            OUTCOME_SEAM,
            ExperimentOwnerInput {
                outcome: None,
                ..published
            },
        ),
    ];

    for (field, presentation) in cases {
        let outcome = run_improvement_experiment_loop(&presentation);
        let ExperimentLoopOutcome::NotExperimental { reason } = outcome else {
            panic!("an absent owner seam ({field}) must be refused, never derived");
        };
        assert_eq!(
            reason,
            ExperimentRefusal::OwnerAbsent { field },
            "the refusal must name the exact absent owner seam"
        );
    }

    // The production presentation of the improvement-intake seam publishes no
    // experiment owner record at all, and its verdict is the honest absence of
    // the first seam rather than a pass.
    let outcome = run_improvement_experiment_loop(&ExperimentOwnerInput::no_owner_records());
    let ExperimentLoopOutcome::NotExperimental { reason } = outcome else {
        panic!("an intake seam with no owner records must produce no experiment");
    };
    assert_eq!(
        reason,
        ExperimentRefusal::OwnerAbsent {
            field: ATTRIBUTION_SEAM
        }
    );
    Ok(())
}

/// Refusal cases for the mechanism and bounded-plan owner seams.
#[test]
fn mechanism_and_plan_owner_records_are_refused_by_content() -> Fixture {
    let post_hoc = owners(
        "post-hoc-mechanism",
        &Knobs {
            declared_before_results: false,
            ..Knobs::default()
        },
    )?;
    assert_eq!(
        refusal(&run_improvement_experiment_loop(&post_hoc.input)),
        ExperimentRefusal::OwnerRecord(PipelineError::MechanismNotPredeclared),
        "a mechanism declared after the results explains any result and proves nothing"
    );

    let self_controlled = owners(
        "self-controlled",
        &Knobs {
            evaluator_is_executor: true,
            ..Knobs::default()
        },
    )?;
    assert_eq!(
        refusal(&run_improvement_experiment_loop(&self_controlled.input)),
        ExperimentRefusal::Owner(LearningContractError::NonIndependentAssessment),
        "a control arm named by the executor is not a control"
    );

    let widened = owners(
        "widened-ceiling",
        &Knobs {
            effect_ceiling: "active-generation".to_owned(),
            ..Knobs::default()
        },
    )?;
    assert_eq!(
        refusal(&run_improvement_experiment_loop(&widened.input)),
        ExperimentRefusal::Owner(LearningContractError::CandidateCeiling),
        "a proposal that widens the effect ceiling never reaches the safeguards"
    );

    let unsupported_risk = owners(
        "unsupported-risk",
        &Knobs {
            risk_ceiling: "unbounded".to_owned(),
            ..Knobs::default()
        },
    )?;
    assert_eq!(
        refusal(&run_improvement_experiment_loop(&unsupported_risk.input)),
        ExperimentRefusal::OwnerRecord(PipelineError::UnsupportedRiskCeiling {
            encoding_version: IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
        }),
        "an unsupported risk ceiling keeps the maintenance owner's own vocabulary"
    );
    Ok(())
}

/// Refusal cases for the assignment, rollback and contamination owner seams.
#[test]
fn assignment_rollback_and_contamination_records_are_refused_by_content() -> Fixture {
    let unseeded = owners(
        "unseeded-assignment",
        &Knobs {
            seed_digest: "seed-45e".to_owned(),
            ..Knobs::default()
        },
    )?;
    assert_eq!(
        refusal(&run_improvement_experiment_loop(&unseeded.input)),
        ExperimentRefusal::Owner(LearningContractError::InvalidDigest {
            field: "experiment.assignment_seed_digest"
        }),
        "an assignment seed that is not a digest is not formatted into one"
    );

    let unnamed_rollback = owners(
        "unnamed-rollback",
        &Knobs {
            blank_rollback: true,
            ..Knobs::default()
        },
    )?;
    assert_eq!(
        refusal(&run_improvement_experiment_loop(&unnamed_rollback.input)),
        ExperimentRefusal::Owner(LearningContractError::Foundation),
        "naming a rollback requires the rollback owner's own handle"
    );

    let silent_contamination = owners(
        "silent-contamination",
        &Knobs {
            empty_prior_exposure: true,
            ..Knobs::default()
        },
    )?;
    assert_eq!(
        refusal(&run_improvement_experiment_loop(
            &silent_contamination.input
        )),
        ExperimentRefusal::Owner(LearningContractError::MissingOwnerEvidence {
            field: "experiment.prior_exposure_refs"
        }),
        "silence is not a contamination policy"
    );
    Ok(())
}

/// Refusal cases for the outcome/verifier owner seam: an unexecuted, dependent
/// or unbound evaluation is refused as exactly that and never becomes "no
/// effect".
#[test]
fn outcome_owner_records_are_refused_by_content() -> Fixture {
    let not_executed = owners(
        "not-executed",
        &Knobs {
            activation_execution: ImprovementEvidenceExecution::NotExecuted,
            ..Knobs::default()
        },
    )?;
    assert_eq!(
        refusal(&run_improvement_experiment_loop(&not_executed.input)),
        ExperimentRefusal::OwnerRecord(PipelineError::EvidenceNotExecuted {
            status: "not-executed",
        }),
        "an unexecuted evaluation is never downgraded into a weaker success"
    );

    let dependent = owners(
        "dependent-evaluation",
        &Knobs {
            activation_independent: false,
            ..Knobs::default()
        },
    )?;
    assert_eq!(
        refusal(&run_improvement_experiment_loop(&dependent.input)),
        ExperimentRefusal::OwnerRecord(PipelineError::EvidenceNotIndependent),
        "an evaluation inside the candidate's own domain certifies nothing"
    );

    let unbound = owners(
        "unbound-evaluation",
        &Knobs {
            foreign_experiment_binding: true,
            ..Knobs::default()
        },
    )?;
    assert_eq!(
        refusal(&run_improvement_experiment_loop(&unbound.input)),
        ExperimentRefusal::OwnerRecord(PipelineError::UnboundRelation {
            relation: "experiment: activation evidence is bound to another bounded plan",
        }),
        "an activation record over another plan cannot close this one"
    );

    let self_certified = owners(
        "self-certified-independence",
        &Knobs {
            self_independence_receipt: true,
            ..Knobs::default()
        },
    )?;
    assert_eq!(
        refusal(&run_improvement_experiment_loop(&self_certified.input)),
        ExperimentRefusal::Owner(LearningContractError::NonIndependentAssessment),
        "the outcome owner cannot certify its own evaluator independence"
    );
    Ok(())
}

/// The strict entry point and the loop producer agree, and the producer never
/// returns a candidate for a presentation whose lineage it could not validate.
#[test]
fn strict_entry_point_agrees_with_the_loop_producer() -> Fixture {
    let owners = owners("strict", &Knobs::default())?;
    let candidate = derive_experiment_candidate(&owners.input)?;
    let ExperimentLoopOutcome::Experimental(boxed) = run_improvement_experiment_loop(&owners.input)
    else {
        panic!("the strict entry point and the producer must agree");
    };
    assert_eq!(boxed.as_ref(), &candidate);

    let absent = derive_experiment_candidate(&ExperimentOwnerInput::no_owner_records())
        .err()
        .ok_or("an intake seam with no owner records must produce no experiment")?;
    assert_eq!(
        absent,
        ExperimentRefusal::OwnerAbsent {
            field: ATTRIBUTION_SEAM
        }
    );
    Ok(())
}

/// The one refusal the producer records for a presentation with no owner records.
fn refusal(outcome: &ExperimentLoopOutcome) -> ExperimentRefusal {
    let ExperimentLoopOutcome::NotExperimental { reason } = outcome else {
        panic!("the case under test must be refused");
    };
    reason.clone()
}
