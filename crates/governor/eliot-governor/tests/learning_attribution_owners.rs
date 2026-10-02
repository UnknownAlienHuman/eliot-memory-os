//! Owner-seam fixtures for the Governor use-attribution producers (`#45`, CC-007).
//!
//! Acceptance bullet under test: "Attribution, outcome, experiment, and promotion
//! are distinct versioned contracts" — for the attribution half only. This file
//! fixes the behaviour of the five owner seams
//! [`eliot_learning_contracts::UseAttributionCandidate`] had no producer for
//! (`subject`, `decision_action_id`, `disposition`, `use_basis`, `eligible_refs`,
//! `non_use`, `competing_contributors`, `evaluator_receipt`, `dimensions`) plus the
//! independent-observation producer, so a later owner cannot regress any of them.
//!
//! Every case drives the real production entry point
//! `crates/governor/eliot-governor/src/learning_attribution.rs::attribute_committed_attempt`,
//! which mints the independent observation through `issue_independence_receipt` and
//! derives the candidate through `attribute_observed_use` — the same two calls
//! `crates/governor/eliot-governor/src/learning_closure.rs::LearningClosureService::close_attempt`
//! makes on every committed record.
//!
//! Refusals use the existing typed vocabulary: an absent owner is a typed
//! [`eliot_governor::AttributionRefusal::OwnerAbsent`] variant naming its seam, and
//! every content failure is the existing
//! [`eliot_learning_contracts::LearningContractError`] travelling as the typed
//! source. No case asserts a string verdict or a boolean.

use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_governor::{
    AttributionOutcome, AttributionRefusal, AttributorIdentity, DecisionOwnerRecord,
    DeliveredUseOwnerRecord, FailureDomain, IndependenceOutcome, IndependentObservation,
    IndependentObservationReceipt, IndependentObservationRoute, UseBasisOwnerRecord,
    attribute_committed_attempt, issue_independence_receipt,
};
use eliot_learning_contracts::{
    ActivationSection, ActivationStatus, AdherenceSection, AdherenceStatus, AssessmentDimension,
    AttributedSubject, CausalCeiling, ContractBinding, DeliverySection, DeliveryStatus,
    DimensionAssessment, DimensionStatus, HarnessActivationReceiptCandidate,
    LearningAssessmentCandidate, LearningContractError, LifecycleStage, NonUseDeclaration,
    OverlayId, RetrievalSection, RetrievalStatus, SourceDenominator, StageDisposition,
    StageObservation, SubjectKind, TargetId, UseAttributionCandidate, UseBasis, UseDisposition,
};
use eliot_receipts::{ProofCeiling, WorkScopeId};

/// Shorthand for a fallible fixture step.
type Fixture = Result<(), Box<dyn std::error::Error>>;

const DELIVERY_SEAM: &str = "attribution.delivery_owner";
const DECISION_SEAM: &str = "attribution.decision_owner";
const BASIS_SEAM: &str = "attribution.basis_owner";
const EVALUATION_SEAM: &str = "attribution.evaluation_owner";
const INDEPENDENCE_SEAM: &str = "attribution.independence_owner";

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
        request_id: RequestId::new(format!("request-45-{tag}"))?,
        operation_id: OperationId::new(format!("operation-45-{tag}"))?,
        product_id: ProductId::new("eliot")?,
        task_id: TaskId::new(format!("task-45-{tag}"))?,
        scope: WorkScopeId::new(format!("scope-45-{tag}"))?,
        state_fence: StateFence::new(
            EpochId::new(lineage, sequence).map_err(|_| "valid fixture epoch")?,
            ResourceGeneration::genesis(),
        ),
        source: eliot_learning_contracts::identity::SourceLineage {
            owner: SourceId::new(format!("source-45-{tag}"))?,
            snapshot: aid(&format!("snapshot-45-{tag}"))?,
            revision: TaskRevision::genesis(),
            digest: digest(&format!("source-45-{tag}")),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
    })
}

fn stage(
    name: LifecycleStage,
    predecessor: Option<LifecycleStage>,
    tag: &str,
) -> Result<StageObservation, Box<dyn std::error::Error>> {
    Ok(StageObservation {
        stage: name,
        disposition: StageDisposition::Observed,
        predecessor,
        owner_receipt: Some(aid(&format!("stage-receipt-45-{tag}"))?),
        evidence: vec![aid(&format!("stage-evidence-45-{tag}"))?],
        denominator: SourceDenominator {
            declared: 1,
            observed: 1,
        },
    })
}

fn dimension(
    name: AssessmentDimension,
    status: DimensionStatus,
    owner_receipt: Option<ArtifactId>,
    tag: &str,
) -> Result<DimensionAssessment, Box<dyn std::error::Error>> {
    let established = matches!(
        status,
        DimensionStatus::Pass
            | DimensionStatus::Fail
            | DimensionStatus::Harm
            | DimensionStatus::NoEffect
    );
    let evidence = if established {
        vec![aid(&format!("dimension-evidence-45-{tag}"))?]
    } else {
        vec![]
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
        metric_ids: vec![aid(&format!("dimension-metric-45-{tag}"))?],
        causal_ceiling: CausalCeiling::Observational,
    })
}

/// The delivery/use owner's published activation receipt.
///
/// I12.24 lines 227-254 define this record; its retrieval, delivery, observable
/// activation and adherence sections stay orthogonal, which is what makes the
/// derived disposition a corroboration rather than an assertion.
#[allow(
    clippy::too_many_arguments,
    reason = "one owner value per receipt field group"
)]
fn delivered_activation(
    tag: &str,
    shared: &ContractBinding,
    subject_id: &ArtifactId,
    rival_skill: &ArtifactId,
    rival_memory: &ArtifactId,
    rival_procedure: &ArtifactId,
) -> Result<HarnessActivationReceiptCandidate, Box<dyn std::error::Error>> {
    let mut receipt = HarnessActivationReceiptCandidate {
        binding: shared.clone(),
        activation_id: aid(&format!("activation-45-{tag}"))?,
        target: target(&format!("target-45-{tag}"))?,
        view_digest: digest(&format!("view-45-{tag}")),
        delta_id: aid(&format!("view-delta-45-{tag}"))?,
        overlay_id: OverlayId::from_artifact(aid(&format!("overlay-45-{tag}"))?),
        admission_receipt: aid(&format!("admission-45-{tag}"))?,
        activation_request_receipt: aid(&format!("activation-request-45-{tag}"))?,
        stages: vec![
            stage(
                LifecycleStage::CandidateProduced,
                None,
                &format!("{tag}-produced"),
            )?,
            stage(
                LifecycleStage::Adhered,
                Some(LifecycleStage::Visible),
                &format!("{tag}-adhered"),
            )?,
            stage(
                LifecycleStage::UsedInAction,
                Some(LifecycleStage::Adhered),
                &format!("{tag}-used"),
            )?,
        ],
        member_denominator: SourceDenominator {
            declared: 4,
            observed: 4,
        },
        metrics: vec![],
        attrition: vec![],
        confounders: vec![],
        independent_evaluator_receipt: None,
        compiled_view_ref: aid(&format!("compiled-view-45-{tag}"))?,
        context_compiler_revision: format!("compiler-revision-45-{tag}"),
        render_profile_revision: format!("render-profile-revision-45-{tag}"),
        stable_harness_refs: vec![aid(&format!("stable-harness-45-{tag}"))?],
        task_family_harness_refs: vec![aid(&format!("family-harness-45-{tag}"))?],
        skill_refs: vec![subject_id.clone(), rival_skill.clone()],
        memory_refs: vec![rival_memory.clone()],
        procedure_refs: vec![rival_procedure.clone()],
        preserved_success_ref: None,
        eligibility_and_retrieval_reason: Some(format!("eligible for the decision 45-{tag}")),
        retrieval: RetrievalSection {
            status: RetrievalStatus::Retrieved,
            expansion_or_tool_query_refs: vec![],
        },
        delivery: DeliverySection {
            status: DeliveryStatus::Full,
            packet_position: Some(0),
            serialized_digest: Some(digest(&format!("packet-45-{tag}"))),
            bytes: Some(256),
            actual_tokens: Some(64),
        },
        activation: ActivationSection {
            status: ActivationStatus::Observed,
            acknowledgement_ref: Some(aid(&format!("acknowledgement-45-{tag}"))?),
            observation_limit_reason: None,
            first_qualifying_observable_use_ref: Some(aid(&format!("qualifying-use-45-{tag}"))?),
        },
        adherence: AdherenceSection {
            status: AdherenceStatus::NotAssessed,
            early_mid_final_checkpoint_refs: vec![],
            prescribed_or_avoided_action_and_required_verifier_refs: vec![],
        },
        conflicts_suppression_or_compaction_loss: vec![],
        downstream_decision_action_artifact_and_verifier_refs: vec![],
        receipt_completeness_and_missing_fields: vec![],
        invalidation_expiry_and_missingness: vec![],
        canonical_digest: String::new(),
    };
    receipt.seal()?;
    Ok(receipt)
}

/// The outcome/verifier owner's dimensioned assessment, bound by content to the
/// delivery owner's receipt.
fn outcome_assessment(
    tag: &str,
    shared: &ContractBinding,
    activation: &HarnessActivationReceiptCandidate,
    independence_receipt: &ArtifactId,
) -> Result<LearningAssessmentCandidate, Box<dyn std::error::Error>> {
    let mut assessment = LearningAssessmentCandidate {
        binding: shared.clone(),
        target: target(&format!("target-45-{tag}"))?,
        overlay_id: activation.overlay_id.clone(),
        activation_id: activation.activation_id.clone(),
        activation_digest: activation.canonical_digest.clone(),
        assessment_receipt: aid(&format!("assessment-receipt-45-{tag}"))?,
        dimensions: vec![
            dimension(
                AssessmentDimension::ActionLinkedUse,
                DimensionStatus::Pass,
                Some(aid(&format!("action-use-receipt-45-{tag}"))?),
                &format!("{tag}-action-linked-use"),
            )?,
            dimension(
                AssessmentDimension::Harm,
                DimensionStatus::NoEffect,
                Some(aid(&format!("harm-receipt-45-{tag}"))?),
                &format!("{tag}-harm"),
            )?,
            dimension(
                AssessmentDimension::SourceEvaluatorIndependence,
                DimensionStatus::Pass,
                Some(independence_receipt.clone()),
                &format!("{tag}-independence"),
            )?,
        ],
        causal_ceiling: CausalCeiling::Observational,
        external_review_refs: vec![],
        canonical_digest: String::new(),
    };
    assessment.seal()?;
    Ok(assessment)
}

/// Every published owner record for one attribution derivation.
struct Owners {
    tag: String,
    binding: ContractBinding,
    source_delta_id: ArtifactId,
    source_delta_digest: String,
    attributor: AttributorIdentity,
    route: IndependentObservationRoute,
    decided_action_id: ArtifactId,
    observed_action_digest: String,
    subject_id: ArtifactId,
    rival_skill: ArtifactId,
    rival_memory: ArtifactId,
    rival_procedure: ArtifactId,
    subject: AttributedSubject,
    activation: HarnessActivationReceiptCandidate,
    non_use: Vec<NonUseDeclaration>,
    decision_receipt: ArtifactId,
    acceptance_item: ArtifactId,
    basis_route: ArtifactId,
    basis_receipt: ArtifactId,
    basis_observed: Vec<ArtifactId>,
    delivery: DeliveredUseOwnerRecord<'static>,
}

/// Build the five owner records.
///
/// The delivery/use owner record borrows the activation receipt and the subject,
/// so both are leaked for the lifetime of the fixture; nothing else escapes.
fn owners(tag: &str) -> Result<Box<Owners>, Box<dyn std::error::Error>> {
    let shared = binding(tag)?;
    let subject_id = aid(&format!("subject-skill-45-{tag}"))?;
    let rival_skill = aid(&format!("rival-skill-45-{tag}"))?;
    let rival_memory = aid(&format!("rival-memory-45-{tag}"))?;
    let rival_procedure = aid(&format!("rival-procedure-45-{tag}"))?;
    let activation = delivered_activation(
        tag,
        &shared,
        &subject_id,
        &rival_skill,
        &rival_memory,
        &rival_procedure,
    )?;
    let subject = AttributedSubject {
        kind: SubjectKind::Skill,
        id: subject_id.clone(),
        version: format!("v1.2.0-45-{tag}"),
        digest: digest(&format!("subject-record-45-{tag}")),
    };
    let actor_id = format!("actor-45-{tag}");
    let route_id = format!("route-45-{tag}");
    let attributor_failure_domain = FailureDomain::seal(&[actor_id.as_str(), route_id.as_str()])?;
    let attributor = AttributorIdentity {
        actor_id,
        route_id,
        failure_domain: attributor_failure_domain,
    };
    // The observing route sits in a different failure domain: a separate
    // supervising service identity, not the actor's own process or plan route.
    let observer_id = format!("supervising-observer-45-{tag}");
    let observer_domain =
        FailureDomain::seal(&[observer_id.as_str(), "watchdog-independent-observation"])?;
    let route = IndependentObservationRoute {
        route_id: observer_id,
        failure_domain: observer_domain,
        owner_receipt: aid(&format!("observation-route-receipt-45-{tag}"))?,
    };
    let decided_action_id = aid(&format!("decided-action-45-{tag}"))?;
    let observed_action_digest = digest(&format!("decided-action-content-45-{tag}"));
    let non_use = vec![NonUseDeclaration {
        subject: rival_memory.clone(),
        reason: format!("the decision owner rejected the rival memory for attempt 45-{tag}"),
    }];
    let decision_receipt = aid(&format!("decision-owner-receipt-45-{tag}"))?;
    let acceptance_item = aid(&format!("acceptance-item-45-{tag}"))?;
    let basis_route = aid(&format!("verifier-route-45-{tag}"))?;
    let basis_receipt = aid(&format!("basis-owner-receipt-45-{tag}"))?;
    let basis_observed = vec![
        subject_id.clone(),
        rival_skill.clone(),
        rival_memory.clone(),
        rival_procedure.clone(),
    ];
    let leaked_activation: &'static HarnessActivationReceiptCandidate =
        Box::leak(Box::new(activation));
    let leaked_subject: &'static AttributedSubject = Box::leak(Box::new(subject));
    Ok(Box::new(Owners {
        tag: tag.to_owned(),
        binding: shared,
        source_delta_id: aid(&format!("learning-delta:45:{tag}"))?,
        source_delta_digest: digest(&format!("stored-delta-45-{tag}")),
        attributor,
        route,
        decided_action_id,
        observed_action_digest,
        subject_id,
        rival_skill,
        rival_memory,
        rival_procedure,
        subject: (*leaked_subject).clone(),
        activation: (*leaked_activation).clone(),
        non_use,
        decision_receipt,
        acceptance_item,
        basis_route,
        basis_receipt,
        basis_observed,
        delivery: DeliveredUseOwnerRecord {
            activation: leaked_activation,
            subject: leaked_subject,
        },
    }))
}

/// The action/decision owner record for the built owners.
fn decision_record(owners: &Owners) -> DecisionOwnerRecord<'_> {
    DecisionOwnerRecord {
        decided_action_id: &owners.decided_action_id,
        non_use: &owners.non_use,
        owner_receipt: &owners.decision_receipt,
    }
}

/// The basis owner record covering the whole published denominator.
fn basis_record(owners: &Owners, basis: UseBasis) -> UseBasisOwnerRecord<'_> {
    UseBasisOwnerRecord {
        basis,
        acceptance_item_ref: &owners.acceptance_item,
        basis_route: &owners.basis_route,
        owner_receipt: &owners.basis_receipt,
        observed_subject_refs: &owners.basis_observed,
    }
}

/// Mint the independent observation for the built owners.
fn independent_receipt(
    owners: &Owners,
) -> Result<IndependentObservationReceipt, Box<dyn std::error::Error>> {
    Ok(issue_independence_receipt(
        &owners.attributor,
        Some(&owners.route),
        Some(&owners.decided_action_id),
        Some(owners.observed_action_digest.as_str()),
        Some(IndependentObservation::SubjectUsedInAction),
    )?)
}

/// Positive case: every owner seam published, and all nine ownerless fields are
/// bound to the owner that published them.
#[test]
fn attributed_candidate_binds_each_ownerless_field_to_its_owner() -> Fixture {
    let owners = owners("positive")?;
    let decision = decision_record(&owners);
    let basis = basis_record(&owners, UseBasis::DirectObservation);
    let receipt = independent_receipt(&owners)?;
    let assessment = outcome_assessment(
        &owners.tag,
        &owners.binding,
        &owners.activation,
        &receipt.receipt_id,
    )?;

    let (independence, outcome) = attribute_committed_attempt(
        &owners.attributor,
        &owners.source_delta_id,
        &owners.source_delta_digest,
        Some(&owners.route),
        Some(&owners.decided_action_id),
        Some(owners.observed_action_digest.as_str()),
        Some(IndependentObservation::SubjectUsedInAction),
        Some(&owners.delivery),
        Some(&decision),
        Some(&basis),
        Some(&assessment),
    );

    let IndependenceOutcome::Observed(minted) = independence else {
        panic!("a registered observing route outside the attributor domain must mint a receipt");
    };
    assert_eq!(minted.receipt_id, receipt.receipt_id);
    // Independence is content, not presence: the observing route's domain digest
    // differs from the attributor's, and its identity differs from the actor's.
    assert_ne!(
        minted.observation_failure_domain,
        owners.attributor.failure_domain.domain_digest
    );
    assert_ne!(minted.observation_route_id, owners.attributor.route_id);

    let AttributionOutcome::Attributed(boxed) = outcome else {
        panic!("a fully owner-published derivation must be attributed, never refused");
    };
    let candidate: &UseAttributionCandidate = &boxed;
    candidate.validate()?;

    // delivery/use owner
    assert_eq!(candidate.subject, owners.subject);
    assert_eq!(candidate.disposition, UseDisposition::Used);
    assert_eq!(
        candidate.eligible_refs,
        vec![
            owners.rival_procedure.clone(),
            owners.rival_skill.clone(),
            owners.subject_id.clone()
        ]
    );
    assert_eq!(
        candidate.competing_contributors,
        vec![owners.rival_procedure.clone(), owners.rival_skill.clone()]
    );
    // action/decision owner
    assert_eq!(candidate.decision_action_id, owners.decided_action_id);
    assert_eq!(candidate.non_use, owners.non_use);
    assert!(
        candidate
            .non_use
            .iter()
            .any(|entry| entry.subject == owners.rival_memory),
        "the decision owner's explicit rejection is the declared non-use record"
    );
    // basis owner
    assert_eq!(candidate.use_basis, UseBasis::DirectObservation);
    // outcome/verifier owner
    assert_eq!(candidate.dimensions, assessment.dimensions);
    assert_eq!(candidate.claim_ceiling, assessment.causal_ceiling);
    // evaluator owner outside the attributor's failure domain
    assert_eq!(candidate.evaluator_receipt, receipt.receipt_id);

    // The complete denominator is the declared eligible set plus the explicit
    // non-use declarations; nothing is counted twice.
    assert_eq!(candidate.denominator.declared, 4);
    assert_eq!(candidate.denominator.observed, 4);
    // The independence dimension is carried by the independent route's own
    // receipt, not by the attributor's self-assessment.
    let independence_dimension = candidate
        .dimensions
        .iter()
        .find(|item| item.dimension == AssessmentDimension::SourceEvaluatorIndependence)
        .ok_or("the independence dimension is mandatory")?;
    assert_eq!(
        independence_dimension.owner_receipt.as_ref(),
        Some(&receipt.receipt_id)
    );
    Ok(())
}

/// Refusal case per owner seam: an owner that published nothing is named by its
/// own typed refusal, never defaulted and never passed through.
#[test]
fn each_absent_owner_seam_is_named_by_its_own_typed_refusal() -> Fixture {
    let owners = owners("absent")?;
    let decision = decision_record(&owners);
    let basis = basis_record(&owners, UseBasis::DirectObservation);
    let receipt = independent_receipt(&owners)?;
    let assessment = outcome_assessment(
        &owners.tag,
        &owners.binding,
        &owners.activation,
        &receipt.receipt_id,
    )?;
    let observed = Some(&owners.decided_action_id);
    let observed_digest = Some(owners.observed_action_digest.as_str());
    let observation = Some(IndependentObservation::SubjectUsedInAction);

    let cases = [
        (
            DELIVERY_SEAM,
            attribute_committed_attempt(
                &owners.attributor,
                &owners.source_delta_id,
                &owners.source_delta_digest,
                Some(&owners.route),
                observed,
                observed_digest,
                observation,
                None,
                Some(&decision),
                Some(&basis),
                Some(&assessment),
            )
            .1,
        ),
        (
            DECISION_SEAM,
            attribute_committed_attempt(
                &owners.attributor,
                &owners.source_delta_id,
                &owners.source_delta_digest,
                Some(&owners.route),
                observed,
                observed_digest,
                observation,
                Some(&owners.delivery),
                None,
                Some(&basis),
                Some(&assessment),
            )
            .1,
        ),
        (
            BASIS_SEAM,
            attribute_committed_attempt(
                &owners.attributor,
                &owners.source_delta_id,
                &owners.source_delta_digest,
                Some(&owners.route),
                observed,
                observed_digest,
                observation,
                Some(&owners.delivery),
                Some(&decision),
                None,
                Some(&assessment),
            )
            .1,
        ),
        (
            EVALUATION_SEAM,
            attribute_committed_attempt(
                &owners.attributor,
                &owners.source_delta_id,
                &owners.source_delta_digest,
                Some(&owners.route),
                observed,
                observed_digest,
                observation,
                Some(&owners.delivery),
                Some(&decision),
                Some(&basis),
                None,
            )
            .1,
        ),
        (
            INDEPENDENCE_SEAM,
            attribute_committed_attempt(
                &owners.attributor,
                &owners.source_delta_id,
                &owners.source_delta_digest,
                None,
                None,
                None,
                None,
                Some(&owners.delivery),
                Some(&decision),
                Some(&basis),
                Some(&assessment),
            )
            .1,
        ),
    ];

    for (field, outcome) in cases {
        let AttributionOutcome::Unattributed { reason } = outcome else {
            panic!("an absent owner seam ({field}) must be refused, never derived");
        };
        assert_eq!(
            reason,
            AttributionRefusal::OwnerAbsent { field },
            "the refusal must name the exact absent owner seam"
        );
    }

    // With no independent route published, the independence step itself is
    // honestly degraded rather than implied, and nothing is attributed.
    let (independence, outcome) = attribute_committed_attempt(
        &owners.attributor,
        &owners.source_delta_id,
        &owners.source_delta_digest,
        None,
        None,
        None,
        None,
        Some(&owners.delivery),
        Some(&decision),
        Some(&basis),
        Some(&assessment),
    );
    let IndependenceOutcome::NotObserved { reason } = independence else {
        panic!("an absent observing route must not mint an independence receipt");
    };
    assert_eq!(
        reason,
        AttributionRefusal::OwnerAbsent {
            field: "attribution.independent_route"
        }
    );
    let AttributionOutcome::Unattributed { reason } = outcome else {
        panic!("an attribution with no independence receipt must be refused");
    };
    assert_eq!(
        reason,
        AttributionRefusal::OwnerAbsent {
            field: INDEPENDENCE_SEAM
        }
    );
    Ok(())
}

/// Refusal case: an `eligible_refs` claim the basis route did not support is
/// refused by content, so the denominator may not outrun the observation.
#[test]
fn eligible_refs_the_basis_route_did_not_observe_are_refused() -> Fixture {
    let owners = owners("basis-coverage")?;
    let decision = decision_record(&owners);
    let receipt = independent_receipt(&owners)?;
    let assessment = outcome_assessment(
        &owners.tag,
        &owners.binding,
        &owners.activation,
        &receipt.receipt_id,
    )?;
    // The basis owner observed the subject and one rival, but the delivery owner
    // delivered two more surfaces into the same decision opportunity.
    let partial_coverage = vec![owners.subject_id.clone(), owners.rival_skill.clone()];
    let basis = UseBasisOwnerRecord {
        basis: UseBasis::DirectObservation,
        acceptance_item_ref: &owners.acceptance_item,
        basis_route: &owners.basis_route,
        owner_receipt: &owners.basis_receipt,
        observed_subject_refs: &partial_coverage,
    };

    let (_, outcome) = attribute_committed_attempt(
        &owners.attributor,
        &owners.source_delta_id,
        &owners.source_delta_digest,
        Some(&owners.route),
        Some(&owners.decided_action_id),
        Some(owners.observed_action_digest.as_str()),
        Some(IndependentObservation::SubjectUsedInAction),
        Some(&owners.delivery),
        Some(&decision),
        Some(&basis),
        Some(&assessment),
    );

    let AttributionOutcome::Unattributed { reason } = outcome else {
        panic!("a denominator the basis route did not observe must be refused");
    };
    assert_eq!(
        reason,
        AttributionRefusal::Owner(LearningContractError::ScopeMismatch {
            field: "attribution.basis_subject_coverage"
        })
    );
    Ok(())
}

/// Refusal case: retrieval, repetition and model self-judgment are never a use
/// basis, even with a registered verifier route behind them.
#[test]
fn retrieval_count_is_never_a_use_basis() -> Fixture {
    let owners = owners("retrieval-basis")?;
    let decision = decision_record(&owners);
    let receipt = independent_receipt(&owners)?;
    let assessment = outcome_assessment(
        &owners.tag,
        &owners.binding,
        &owners.activation,
        &receipt.receipt_id,
    )?;

    for rejected in [
        UseBasis::RetrievalCount,
        UseBasis::Repetition,
        UseBasis::ModelJudgment,
    ] {
        let basis = basis_record(&owners, rejected);
        let (_, outcome) = attribute_committed_attempt(
            &owners.attributor,
            &owners.source_delta_id,
            &owners.source_delta_digest,
            Some(&owners.route),
            Some(&owners.decided_action_id),
            Some(owners.observed_action_digest.as_str()),
            Some(IndependentObservation::SubjectUsedInAction),
            Some(&owners.delivery),
            Some(&decision),
            Some(&basis),
            Some(&assessment),
        );
        let AttributionOutcome::Unattributed { reason } = outcome else {
            panic!("{rejected:?} must never be admitted as a use basis");
        };
        assert_eq!(
            reason,
            AttributionRefusal::Owner(LearningContractError::ScopeMismatch {
                field: "attribution.use_basis"
            })
        );
    }
    Ok(())
}

/// Refusal case: the independence dimension must be carried by the independent
/// route's own receipt, so the attributor cannot certify its own independence.
#[test]
fn self_assessed_independence_dimension_is_refused() -> Fixture {
    let owners = owners("self-assessed")?;
    let decision = decision_record(&owners);
    let basis = basis_record(&owners, UseBasis::IndependentEvaluator);
    let receipt = independent_receipt(&owners)?;
    // The outcome owner asserts `SOURCE_EVALUATOR_INDEPENDENCE` with its own
    // assessment receipt instead of the independent route's receipt.
    let assessment = outcome_assessment(
        &owners.tag,
        &owners.binding,
        &owners.activation,
        &owners.decision_receipt,
    )?;
    let asserted = assessment
        .dimensions
        .iter()
        .find(|item| item.dimension == AssessmentDimension::SourceEvaluatorIndependence)
        .and_then(|item| item.owner_receipt.clone());
    assert_ne!(asserted, Some(receipt.receipt_id.clone()));

    let (_, outcome) = attribute_committed_attempt(
        &owners.attributor,
        &owners.source_delta_id,
        &owners.source_delta_digest,
        Some(&owners.route),
        Some(&owners.decided_action_id),
        Some(owners.observed_action_digest.as_str()),
        Some(IndependentObservation::SubjectUsedInAction),
        Some(&owners.delivery),
        Some(&decision),
        Some(&basis),
        Some(&assessment),
    );

    let AttributionOutcome::Unattributed { reason } = outcome else {
        panic!("a self-assessed independence dimension must be refused");
    };
    assert_eq!(
        reason,
        AttributionRefusal::Owner(LearningContractError::NonIndependentAssessment)
    );
    Ok(())
}

/// Refusal case: an independent observation of a different action cannot certify
/// this decision opportunity's use claim.
#[test]
fn independence_receipt_must_observe_the_decided_action() -> Fixture {
    let owners = owners("foreign-action")?;
    let decision = decision_record(&owners);
    let basis = basis_record(&owners, UseBasis::IndependentEvaluator);
    let foreign_action = aid("foreign-decided-action-45")?;
    let foreign_digest = digest("foreign-decided-action-content-45");
    let receipt = issue_independence_receipt(
        &owners.attributor,
        Some(&owners.route),
        Some(&foreign_action),
        Some(&foreign_digest),
        Some(IndependentObservation::SubjectUsedInAction),
    )?;
    let assessment = outcome_assessment(
        &owners.tag,
        &owners.binding,
        &owners.activation,
        &receipt.receipt_id,
    )?;

    let (_, outcome) = attribute_committed_attempt(
        &owners.attributor,
        &owners.source_delta_id,
        &owners.source_delta_digest,
        Some(&owners.route),
        Some(&foreign_action),
        Some(&foreign_digest),
        Some(IndependentObservation::SubjectUsedInAction),
        Some(&owners.delivery),
        Some(&decision),
        Some(&basis),
        Some(&assessment),
    );

    let AttributionOutcome::Unattributed { reason } = outcome else {
        panic!("an observation of a different action must be refused");
    };
    assert_eq!(
        reason,
        AttributionRefusal::Owner(LearningContractError::ScopeMismatch {
            field: "attribution.observed_action"
        })
    );
    Ok(())
}

/// The independence producer refuses an observing route inside the attributor's
/// own failure domain, and its receipt identity is content-addressed.
#[test]
fn independence_receipt_refuses_a_route_inside_the_attributing_failure_domain() -> Fixture {
    let owners = owners("inside-domain")?;
    // A route built from the attributor's own service identity and plan route
    // lands in the same failure domain, however it is named.
    let inside_domain = IndependentObservationRoute {
        route_id: format!("{}-redeclared", owners.attributor.route_id),
        failure_domain: owners.attributor.failure_domain.clone(),
        owner_receipt: aid("observation-route-receipt-45-inside")?,
    };
    let refusal = issue_independence_receipt(
        &owners.attributor,
        Some(&inside_domain),
        Some(&owners.decided_action_id),
        Some(owners.observed_action_digest.as_str()),
        Some(IndependentObservation::SubjectUsedInAction),
    )
    .err()
    .ok_or("a route inside the attributor's failure domain must be refused")?;
    assert_eq!(
        refusal,
        AttributionRefusal::Owner(LearningContractError::NonIndependentAssessment)
    );

    // A route that published nothing is the honest A5.5 degradation, not a pass.
    let absent = issue_independence_receipt(
        &owners.attributor,
        None,
        Some(&owners.decided_action_id),
        Some(owners.observed_action_digest.as_str()),
        Some(IndependentObservation::SubjectUsedInAction),
    )
    .err()
    .ok_or("an absent observing route must be refused")?;
    assert_eq!(
        absent,
        AttributionRefusal::OwnerAbsent {
            field: "attribution.independent_route"
        }
    );

    // And the minted receipt identity is recomputed from its content, so a
    // rewritten observation is a typed digest mismatch rather than a new receipt,
    // while a freshly minted observation of the other outcome gets its own id.
    let mut minted = independent_receipt(&owners)?;
    minted.validate()?;
    let sealed_id = minted.receipt_id.clone();
    minted.observation = IndependentObservation::SubjectNotUsedInAction;
    assert_eq!(
        minted.validate(),
        Err(AttributionRefusal::Owner(
            LearningContractError::DigestMismatch {
                field: "attribution.independence.receipt_id"
            }
        ))
    );
    let resealed = issue_independence_receipt(
        &owners.attributor,
        Some(&owners.route),
        Some(&owners.decided_action_id),
        Some(owners.observed_action_digest.as_str()),
        Some(IndependentObservation::SubjectNotUsedInAction),
    )?;
    assert_ne!(resealed.receipt_id, sealed_id);
    resealed.validate()?;
    Ok(())
}
