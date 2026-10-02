//! A3 fixtures for the Governor promotion gate (`#45`, CC-007).
//!
//! Acceptance bullet under test: "Promotion can be rolled back without deleting
//! evidence/history."
//!
//! These fixtures drive the real production entry point of the gate — the
//! `PromotionBoundaryInput::Published` presentation that
//! `crates/governor/eliot-governor/src/learning_promotion.rs::PromotionBoundaryInput::evaluate`
//! dispatches to `evaluate_promotion`, and which `learning_closure.rs` presents
//! at the learning-closure seam. They deliberately do **not** claim a production
//! presenter: the owner-published boundary, its attribution and its experiment
//! still have no production producer, and nothing here invents one. What these
//! fixtures fix is the behaviour of the gate itself once a real owner does
//! publish, so a future issuer cannot regress it:
//!
//! - the rollback appends to the retained history and reseals, and every
//!   evaluation dimension, its evidence and its owner receipt, the rollout
//!   boundary, the canary requirement and the invalidation conditions survive;
//! - a substituted or foreign boundary (wrong identity, wrong evidence digest,
//!   wrong fence) is refused with the existing typed contract error, carried
//!   across the seam as a typed `PromotionRefusal` rather than collapsed into a
//!   boolean or a bare string.

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_governor::{LearningPromotionOutcome, PromotionBoundaryInput, PromotionRefusal};
use eliot_learning_contracts::{
    AgentAttemptId, AssessmentDimension, AssignmentKind, AttributedSubject, CampaignId,
    CausalCeiling, ContractBinding, DimensionAssessment, DimensionStatus, HistoryRetention,
    ImprovementExperimentCandidate, LearningContractError, NonUseDeclaration, OverlayId,
    PromotionBoundaryCandidate, PromotionMutationTarget, RolloutBoundary, SourceDenominator,
    SubjectKind, TargetId, UseAttributionCandidate, UseBasis, UseDisposition,
};
use eliot_learning_delta::{ConsequentialBoundary, StoredDeltaDisposition, StoredLearningDelta};
use eliot_receipts::{ProofCeiling, WorkScopeId};

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
    let sequence = std::num::NonZeroU64::new(1).ok_or("nonzero test sequence")?;
    Ok(ContractBinding {
        schema_version: 1,
        policy_revision: PolicyRevision::genesis(),
        request_id: RequestId::new(format!("request-a3-{tag}"))?,
        operation_id: OperationId::new(format!("operation-a3-{tag}"))?,
        product_id: ProductId::new("eliot")?,
        task_id: TaskId::new(format!("task-a3-{tag}"))?,
        scope: WorkScopeId::new(format!("scope-a3-{tag}"))?,
        state_fence: StateFence::new(
            EpochId::new(lineage, sequence).map_err(|_| "valid test epoch")?,
            ResourceGeneration::genesis(),
        ),
        source: eliot_learning_contracts::identity::SourceLineage {
            owner: SourceId::new(format!("source-a3-{tag}"))?,
            snapshot: aid(&format!("snapshot-a3-{tag}"))?,
            revision: TaskRevision::genesis(),
            digest: digest(&format!("source-a3-{tag}")),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
    })
}

fn dimension(
    name: AssessmentDimension,
    status: DimensionStatus,
    tag: &str,
) -> Result<DimensionAssessment, Box<dyn std::error::Error>> {
    let established = matches!(
        status,
        DimensionStatus::Pass
            | DimensionStatus::Fail
            | DimensionStatus::Harm
            | DimensionStatus::NoEffect
    );
    let (evidence, owner_receipt) = if established {
        (
            vec![aid(&format!("evidence-a3-{tag}"))?],
            Some(aid(&format!("receipt-a3-{tag}"))?),
        )
    } else {
        (vec![], None)
    };
    Ok(DimensionAssessment {
        dimension: name,
        status,
        evidence,
        owner_receipt,
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
        metric_ids: vec![aid(&format!("metric-a3-{tag}"))?],
        causal_ceiling: CausalCeiling::Observational,
    })
}

fn promotion_dimensions(tag: &str) -> Result<Vec<DimensionAssessment>, Box<dyn std::error::Error>> {
    Ok(vec![
        dimension(
            AssessmentDimension::Harm,
            DimensionStatus::Harm,
            &format!("{tag}-harm"),
        )?,
        dimension(
            AssessmentDimension::OutcomeValidity,
            DimensionStatus::Pass,
            &format!("{tag}-outcome"),
        )?,
    ])
}

/// The committed durable record the boundary adjudicates.
fn stored_record(
    tag: &str,
    binding: &ContractBinding,
) -> Result<StoredLearningDelta, Box<dyn std::error::Error>> {
    Ok(StoredLearningDelta {
        campaign_id: CampaignId::from_artifact(aid(&format!("campaign-a3-{tag}"))?),
        attempt_id: AgentAttemptId::new(format!("attempt-a3-{tag}"))?,
        state_fence: binding.state_fence.clone(),
        actor_id: format!("actor-a3-{tag}"),
        route_id: format!("route-a3-{tag}"),
        overlay_id: OverlayId::from_artifact(aid(&format!("overlay-a3-{tag}"))?),
        consequential_boundary: ConsequentialBoundary::MaterialImplementationAttempt,
        strategy_fingerprint: digest(&format!("strategy-a3-{tag}")),
        evidence_refs: vec![aid(&format!("stored-evidence-a3-{tag}"))?],
        delta_artifact: aid(&format!("learning-delta:a3:{tag}"))?,
        delta_digest: digest(&format!("stored-delta-a3-{tag}")),
        retry_relation: None,
        disposition: StoredDeltaDisposition::NextProbeChanged,
        admission_receipt_id: None,
    })
}

fn valid_attribution(
    tag: &str,
    binding: &ContractBinding,
    delta: &StoredLearningDelta,
) -> Result<UseAttributionCandidate, Box<dyn std::error::Error>> {
    let subject_id = aid(&format!("subject-a3-{tag}"))?;
    let mut candidate = UseAttributionCandidate {
        binding: binding.clone(),
        attribution_id: aid(&format!("attribution-a3-{tag}"))?,
        target: target(&format!("target-self-a3-{tag}"))?,
        subject: AttributedSubject {
            kind: SubjectKind::Candidate,
            id: subject_id.clone(),
            version: format!("v1.0.0-{tag}"),
            digest: digest(&format!("subject-record-a3-{tag}")),
        },
        decision_action_id: aid(&format!("decision-a3-{tag}"))?,
        source_delta_id: delta.delta_artifact.clone(),
        source_delta_digest: delta.delta_digest.clone(),
        disposition: UseDisposition::Used,
        use_basis: UseBasis::DirectObservation,
        denominator: SourceDenominator {
            declared: 3,
            observed: 3,
        },
        eligible_refs: vec![subject_id, aid(&format!("eligible-rival-a3-{tag}"))?],
        non_use: vec![NonUseDeclaration {
            subject: aid(&format!("non-use-a3-{tag}"))?,
            reason: "out of scope for this decision".to_owned(),
        }],
        competing_contributors: vec![aid(&format!("competitor-a3-{tag}"))?],
        evaluator_receipt: aid(&format!("evaluator-a3-{tag}"))?,
        evidence_refs: vec![aid(&format!("attr-evidence-a3-{tag}"))?],
        dimensions: vec![
            dimension(
                AssessmentDimension::ActionLinkedUse,
                DimensionStatus::Pass,
                &format!("{tag}-attr-action"),
            )?,
            dimension(
                AssessmentDimension::Harm,
                DimensionStatus::NoEffect,
                &format!("{tag}-attr-harm"),
            )?,
            dimension(
                AssessmentDimension::SourceEvaluatorIndependence,
                DimensionStatus::Pass,
                &format!("{tag}-attr-independence"),
            )?,
        ],
        claim_ceiling: CausalCeiling::Observational,
        canonical_digest: String::new(),
    };
    candidate.seal()?;
    Ok(candidate)
}

fn valid_experiment(
    tag: &str,
    binding: &ContractBinding,
    target: &TargetId,
    attribution: &UseAttributionCandidate,
) -> Result<ImprovementExperimentCandidate, Box<dyn std::error::Error>> {
    let mut candidate = ImprovementExperimentCandidate {
        binding: binding.clone(),
        experiment_id: aid(&format!("experiment-a3-{tag}"))?,
        target: target.clone(),
        attribution_id: attribution.attribution_id.clone(),
        attribution_digest: attribution.canonical_digest.clone(),
        hypothesis: format!("candidate {tag} improves adherence without new harm"),
        eligibility: format!("eligible when fence and scope match {tag}"),
        assignment: AssignmentKind::Randomized,
        assignment_seed_digest: digest(&format!("seed-a3-{tag}")),
        intervention_id: aid(&format!("intervention-a3-{tag}"))?,
        control_id: aid(&format!("control-a3-{tag}"))?,
        pre_observation_discriminator: aid(&format!("discriminator-a3-{tag}"))?,
        safeguards: vec![aid(&format!("safeguard-a3-{tag}"))?],
        stop_conditions: vec![format!("stop on harm signal {tag}")],
        rollback_refs: vec![aid(&format!("exp-rollback-a3-{tag}"))?],
        contamination_policy: format!("exclude prior exposure {tag}"),
        prior_exposure_refs: vec![aid(&format!("prior-a3-{tag}"))?],
        evidence_freeze_digest: digest(&format!("freeze-a3-{tag}")),
        evidence_freeze_refs: vec![aid(&format!("frozen-a3-{tag}"))?],
        outcome_dimensions: vec![
            dimension(
                AssessmentDimension::BaselineControlQuality,
                DimensionStatus::Pass,
                &format!("{tag}-exp-control"),
            )?,
            dimension(
                AssessmentDimension::Harm,
                DimensionStatus::NoEffect,
                &format!("{tag}-exp-harm"),
            )?,
            dimension(
                AssessmentDimension::Confounders,
                DimensionStatus::Pass,
                &format!("{tag}-exp-confounders"),
            )?,
        ],
        claim_ceiling: CausalCeiling::Observational,
        canonical_digest: String::new(),
    };
    candidate.seal()?;
    Ok(candidate)
}

fn valid_promotion(
    tag: &str,
    binding: &ContractBinding,
    target: &TargetId,
    attribution: &UseAttributionCandidate,
    experiment: &ImprovementExperimentCandidate,
) -> Result<PromotionBoundaryCandidate, Box<dyn std::error::Error>> {
    let mut candidate = PromotionBoundaryCandidate {
        binding: binding.clone(),
        promotion_id: aid(&format!("promotion-a3-{tag}"))?,
        target: target.clone(),
        attribution_id: attribution.attribution_id.clone(),
        attribution_digest: attribution.canonical_digest.clone(),
        experiment_id: experiment.experiment_id.clone(),
        experiment_digest: experiment.canonical_digest.clone(),
        governor_receipt_ref: Some(aid(&format!("governor-receipt-a3-{tag}"))?),
        rollout: RolloutBoundary {
            reversible: true,
            canary_required: true,
            invalidation_conditions: vec![format!("harm signal {tag}")],
        },
        mutation_target: PromotionMutationTarget::CandidateOnly,
        supersedes: vec![],
        invalidates: vec![],
        history_retention: HistoryRetention::RetainAlways,
        evaluation_dimensions: promotion_dimensions(tag)?,
        claim_ceiling: CausalCeiling::Observational,
        canonical_digest: String::new(),
    };
    candidate.seal()?;
    Ok(candidate)
}

/// Positive case: a rolled-back promotion keeps its evidence and its history.
///
/// Drives the production `PromotionBoundaryInput::Published` dispatch, so the
/// verdict is produced by `evaluate_promotion` -> `rollback_promotion` ->
/// `PromotionBoundaryCandidate::invalidate`, and checks the acceptance bullet
/// directly rather than being told about it.
#[test]
fn rolled_back_promotion_retains_evidence_and_history() -> Result<(), Box<dyn std::error::Error>> {
    let tag = "rollback";
    let binding = binding(tag)?;
    let target = target(&format!("target-self-a3-{tag}"))?;
    let stored = stored_record(tag, &binding)?;
    stored.validate()?;
    let attribution = valid_attribution(tag, &binding, &stored)?;
    let experiment = valid_experiment(tag, &binding, &target, &attribution)?;
    let promotion = valid_promotion(tag, &binding, &target, &attribution, &experiment)?;

    let presented_digest = promotion.canonical_digest.clone();
    let presented_dimensions = promotion.evaluation_dimensions.clone();
    let presented_rollout = promotion.rollout.clone();
    let invalidation = aid("invalidation-a3-rollback")?;
    let invalidations = vec![invalidation.clone()];

    let outcome = PromotionBoundaryInput::Published {
        promotion: &promotion,
        attribution: &attribution,
        experiment: &experiment,
        invalidations: &invalidations,
    }
    .evaluate(&stored, None);

    let LearningPromotionOutcome::Admitted(receipt) = outcome else {
        panic!("a valid published boundary with one invalidation must be admitted");
    };
    assert_eq!(receipt.promotion_id, promotion.promotion_id);
    assert_eq!(receipt.delta_artifact, stored.delta_artifact);
    assert_eq!(receipt.delta_digest, stored.delta_digest);
    // The rollback appended to the retained history and resealed under a new
    // canonical digest: the identity of the boundary changed, nothing was
    // deleted to make room for it.
    assert_eq!(receipt.retained_invalidations, invalidations);
    assert_ne!(receipt.promotion_digest, presented_digest);
    // The evidence survived the rollback byte for byte.
    assert_eq!(receipt.retained_dimensions, presented_dimensions);
    assert_eq!(
        receipt.retained_history_retention,
        HistoryRetention::RetainAlways
    );
    assert!(!receipt.active_generation_evaluated);
    assert!(receipt.delivery.is_none());

    // The owner's own published record is not mutated by the evaluation: the
    // gate rolls a sealed copy back, so the presented boundary and its history
    // are still exactly what the owner published.
    assert_eq!(promotion.canonical_digest, presented_digest);
    assert!(promotion.invalidates.is_empty());

    // And the rollback itself preserves the whole record, not only the digest.
    let mut rolled_back = promotion.clone();
    eliot_governor::rollback_promotion(&mut rolled_back, &invalidation)?;
    // `invalidation` is cloned here because the repeat-rollback refusal below
    // still has to borrow the same artifact id; the assertion compares the
    // recorded invalidation list, not ownership of the id.
    assert_eq!(rolled_back.invalidates, vec![invalidation.clone()]);
    assert_eq!(rolled_back.evaluation_dimensions, presented_dimensions);
    assert_eq!(rolled_back.rollout, presented_rollout);
    assert_eq!(
        rolled_back.history_retention,
        HistoryRetention::RetainAlways
    );
    assert_eq!(rolled_back.attribution_digest, attribution.canonical_digest);
    assert_eq!(rolled_back.experiment_digest, experiment.canonical_digest);
    assert_ne!(rolled_back.canonical_digest, presented_digest);
    rolled_back.validate()?;

    // A history that would delete evidence never reaches the gate, so a second
    // rollback of the same identity is the only typed refusal here.
    let mut repeated = rolled_back.clone();
    assert!(matches!(
        eliot_governor::rollback_promotion(&mut repeated, &invalidation),
        Err(eliot_governor::LearningPromotionError::Refused(
            PromotionRefusal::Boundary(LearningContractError::Duplicate { .. })
        ))
    ));
    Ok(())
}

/// Refusal case: a foreign or substituted boundary is refused with the existing
/// typed error, and the typed refusal survives the seam unchanged.
#[test]
fn foreign_or_substituted_boundary_is_refused_with_typed_cause()
-> Result<(), Box<dyn std::error::Error>> {
    let tag = "substituted";
    // Built before the local `binding` and `target` shadow the fixture
    // constructors below.
    let foreign_binding = binding(&format!("{tag}-foreign"))?;
    let foreign_target = target(&format!("target-self-a3-foreign-{tag}"))?;
    let binding = binding(tag)?;
    let target = target(&format!("target-self-a3-{tag}"))?;
    let stored = stored_record(tag, &binding)?;
    let attribution = valid_attribution(tag, &binding, &stored)?;
    let experiment = valid_experiment(tag, &binding, &target, &attribution)?;
    let promotion = valid_promotion(tag, &binding, &target, &attribution, &experiment)?;
    let invalidations: Vec<ArtifactId> = vec![];

    let mut wrong_identity = promotion.clone();
    wrong_identity.target = foreign_target;
    wrong_identity.seal()?;

    let mut wrong_evidence_digest = promotion.clone();
    wrong_evidence_digest.attribution_digest = digest("foreign-attribution-digest");
    wrong_evidence_digest.seal()?;

    let mut wrong_fence = promotion.clone();
    wrong_fence.binding = foreign_binding;
    wrong_fence.seal()?;

    for (case, boundary) in [
        ("wrong identity", &wrong_identity),
        ("wrong evidence digest", &wrong_evidence_digest),
        ("wrong fence", &wrong_fence),
    ] {
        let outcome = PromotionBoundaryInput::Published {
            promotion: boundary,
            attribution: &attribution,
            experiment: &experiment,
            invalidations: &invalidations,
        }
        .evaluate(&stored, None);

        let LearningPromotionOutcome::Withheld { reason } = outcome else {
            panic!("a substituted boundary ({case}) must be withheld, never admitted");
        };
        assert!(
            matches!(
                &reason,
                PromotionRefusal::Boundary(LearningContractError::ScopeMismatch {
                    field: "promotion.lineage"
                })
            ),
            "substituted boundary ({case}) must be refused as a lineage mismatch, got {reason:?}"
        );
    }

    // The honest absent presentation stays distinguishable from a refusal: the
    // committed record simply has no boundary, which is not a lineage failure.
    let LearningPromotionOutcome::Withheld { reason } =
        PromotionBoundaryInput::absent().evaluate(&stored, None)
    else {
        panic!("an absent boundary is never an admitted promotion");
    };
    assert_eq!(reason, PromotionRefusal::MissingBoundary);
    Ok(())
}
