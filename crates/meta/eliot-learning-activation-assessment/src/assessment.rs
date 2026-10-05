//! Named phases for deterministic A-32 activation assessment composition.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_learning_contracts::{
    ActivationSection, ActivationStatus, AdherenceSection, AdherenceStatus,
    AttemptLearningDeltaCandidate, CampaignHarnessOverlayCandidate, CampaignLearningStateView,
    ContractBinding, DeliverySection, DeliveryStatus, DimensionAssessment, DimensionStatus,
    HarnessActivationReceiptCandidate, LearningAssessmentCandidate, LearningStateViewRecipe,
    MetricObservation, OverlayEligibility, RetrievalSection, RetrievalStatus, StageDisposition,
    StageObservation, TargetId, identity::validate_external_id, overlay_eligibility,
};

use crate::{
    ActivationAssessmentError,
    bounds::{bounded_serialized_len, preflight},
    contracts::{
        AssessmentPolicy, AssessmentResult, IncompleteAssessment, MAX_OUTPUT_BYTES,
        MissingAssessmentField,
    },
};

/// What an owner actually observed about eligibility and retrieval.
///
/// A caller supplies the observation, never the resulting
/// [`RetrievalStatus`]: [`derive_retrieval`] runs the canonical
/// [`overlay_eligibility`] predicate over the sealed overlay's own
/// invalidation, expiry, and campaign fields and then combines it with
/// whether the surface was retrieved and whether an expansion/tool-query
/// actually happened. Nothing here can assert eligibility.
#[derive(serde::Serialize)]
pub struct ObservedRetrieval<'a> {
    /// Campaign this attempt belongs to, used as the requesting campaign.
    pub requesting_campaign_id: &'a str,
    /// Whether the requesting binding matches the admitted overlay scope.
    pub binding_compatible: bool,
    /// Owner wall-clock observation in Unix milliseconds.
    pub now_ms: u64,
    /// Fresh governed cross-task admission, when one was issued.
    pub cross_task: Option<&'a eliot_learning_contracts::CrossTaskAdmission>,
    /// Whether the surface was actually retrieved for this attempt.
    pub retrieved: bool,
    /// Expansion or tool-query refs backing an expanded retrieval.
    pub expansion_or_tool_query_refs: &'a [ArtifactId],
}

/// What an owner actually observed about delivery.
///
/// A caller supplies the observation, never the resulting
/// [`DeliveryStatus`]. [`derive_delivery`] maps a delivered packet position
/// alone to [`DeliveryStatus::Partial`], because a position with no
/// serialized digest is not a complete delivery, and a delivered surface with
/// no packet facts at all to [`DeliveryStatus::Missing`], because a delivery
/// whose bytes are unrecorded is not evidence of delivery.
#[derive(serde::Serialize)]
pub struct ObservedDelivery<'a> {
    /// Whether any delivery was attempted for this attempt.
    pub attempted: bool,
    /// Position of the delivered packet, when recorded.
    pub packet_position: Option<u64>,
    /// Serialized digest of the delivered packet, when recorded.
    pub serialized_digest: Option<&'a str>,
    /// Serialized byte size of the delivered packet, when recorded.
    pub bytes: Option<u64>,
    /// Actual measured tokens of the delivered packet, when recorded.
    pub actual_tokens: Option<u64>,
    /// Acknowledgement the receiving surface returned, when one exists.
    pub acknowledgement_ref: Option<&'a ArtifactId>,
}

/// What an owner actually observed about qualifying observable use.
///
/// This is the ONLY input to `activation.status`. A caller cannot supply a
/// use reference, and an acknowledgement can never enter here:
/// [`derive_activation`] reads only `first_qualifying_use_ref`, and
/// `activation.status = OBSERVED` additionally requires a real delivery
/// status. An acknowledgement is carried separately in
/// [`ActivationSection::acknowledgement_ref`] and is never a use reference.
#[derive(serde::Serialize)]
pub struct ObservedUse<'a> {
    /// Whether an owner actually observed any qualifying use at all.
    ///
    /// `false` is the honest "no qualifying activation evidence was
    /// observed" observation; it does not prove non-use.
    pub observed_any: bool,
    /// The first qualifying observable use an owner recorded.
    ///
    /// This is the evidence itself. It is never derived, defaulted,
    /// substituted, or filled in from an acknowledgement.
    pub first_qualifying_use_ref: Option<&'a ArtifactId>,
    /// Whether the attempt surface could be observed for qualifying use.
    ///
    /// `false` means observability was missing or inconclusive, which is
    /// `UNKNOWN` and never presumed either compliant or non-use.
    pub observable: bool,
}

/// What an owner actually observed about adherence.
///
/// A caller supplies checkpoint, action, and verifier evidence, never the
/// resulting [`AdherenceStatus`]. [`derive_adherence`] records an observed
/// disposition only when qualifying use was itself observed AND both
/// evidence classes are non-empty; a disagreement between the checkpoint
/// signal and the recorded action/verifier evidence is
/// [`AdherenceStatus::ObservedViolated`] with both sets of refs retained.
/// Any absent or inconclusive evidence stays `UNKNOWN`.
#[derive(serde::Serialize)]
pub struct ObservedAdherence<'a> {
    /// Explicit early/mid/final checkpoint signal the owner recorded.
    pub checkpoint_status: AdherenceStatus,
    /// Checkpoint refs backing the recorded signal.
    pub checkpoint_refs: &'a [ArtifactId],
    /// Prescribed-or-avoided action and required verifier refs the owner
    /// recorded.
    pub action_and_verifier_refs: &'a [ArtifactId],
    /// The explicit violation disposition an owner observed.
    pub observed_violation: Option<AdherenceStatus>,
}

/// The five orthogonal receipt sections derived from observed evidence.
pub(crate) struct DerivedSections {
    /// Eligibility reason plus the derived retrieval section.
    pub eligibility_and_retrieval_reason: Option<String>,
    /// Derived retrieval section.
    pub retrieval: RetrievalSection,
    /// Derived delivery section.
    pub delivery: DeliverySection,
    /// Derived observable-activation section.
    pub activation: ActivationSection,
    /// Derived adherence section.
    pub adherence: AdherenceSection,
}

/// Exact immutable evidence and lineage supplied to one assessment call.
pub struct AssessmentInput<'a> {
    /// Binding compared with every canonical record.
    pub binding: &'a ContractBinding,
    /// Target compared with the view and delta.
    pub target: &'a TargetId,
    /// Canonical pre-attempt view.
    pub view: &'a CampaignLearningStateView,
    /// Recipe that defines the view's exact member denominator.
    pub recipe: &'a LearningStateViewRecipe,
    /// Canonical attempt delta.
    pub delta: &'a AttemptLearningDeltaCandidate,
    /// Canonical task-local overlay.
    pub overlay: &'a CampaignHarnessOverlayCandidate,
    /// Stable activation candidate identity, when supplied.
    pub activation_id: Option<&'a ArtifactId>,
    /// External admission receipt identity, when supplied.
    pub admission_receipt: Option<&'a ArtifactId>,
    /// External activation request receipt identity, when supplied.
    pub activation_request_receipt: Option<&'a ArtifactId>,
    /// Assessment owner receipt identity, when supplied.
    pub assessment_receipt: Option<&'a ArtifactId>,
    /// Immutable owner-issued lifecycle observations.
    pub stages: &'a [StageObservation],
    /// Immutable owner-issued metric observations.
    pub metrics: &'a [MetricObservation],
    /// Exact attrition references.
    pub attrition: &'a [ArtifactId],
    /// Exact concurrent-intervention references.
    pub confounders: &'a [ArtifactId],
    /// Independent evaluator receipt, if one exists.
    pub independent_evaluator_receipt: Option<&'a ArtifactId>,
    /// Supplied independent dimensions.
    pub dimensions: &'a [DimensionAssessment],
    /// Explicit external review references.
    pub external_review_refs: &'a [ArtifactId],
    /// Caller-supplied finite assessment parameters.
    pub policy: &'a AssessmentPolicy,
    /// Full compiled-from campaign learning state view ref.
    pub compiled_view_ref: &'a ArtifactId,
    /// Revision of the context compiler that rendered this attempt.
    pub context_compiler_revision: &'a str,
    /// Revision of the render profile used for this attempt.
    pub render_profile_revision: &'a str,
    /// Exact stable harness refs compiled into this attempt.
    pub stable_harness_refs: &'a [ArtifactId],
    /// Task-family harness refs compiled into this attempt.
    pub task_family_harness_refs: &'a [ArtifactId],
    /// Skill refs compiled into this attempt.
    pub skill_refs: &'a [ArtifactId],
    /// Memory refs compiled into this attempt.
    pub memory_refs: &'a [ArtifactId],
    /// Procedure refs compiled into this attempt.
    pub procedure_refs: &'a [ArtifactId],
    /// Preserved success set or constraints ref, when one applies.
    pub preserved_success_ref: Option<&'a ArtifactId>,
    /// Retrieval observations; `RetrievalStatus` is DERIVED from them.
    pub retrieval: ObservedRetrieval<'a>,
    /// Delivery observations; `DeliveryStatus` is DERIVED from them.
    pub delivery: ObservedDelivery<'a>,
    /// Observable-use observations; `ActivationStatus` is DERIVED from them
    /// together with the derived delivery status.
    pub observable_use: ObservedUse<'a>,
    /// Checkpoint/action/verifier observations; `AdherenceStatus` is DERIVED
    /// from them together with the derived activation status.
    pub adherence: ObservedAdherence<'a>,
    /// Conflict, suppression or compaction-loss refs for this attempt.
    pub conflicts_suppression_or_compaction_loss: &'a [ArtifactId],
    /// Downstream decision, action, artifact and verifier refs.
    pub downstream_refs: &'a [ArtifactId],
    /// Receipt completeness notes and missing-field names.
    pub receipt_completeness_and_missing_fields: &'a [String],
    /// Invalidation, expiry and missingness notes.
    pub invalidation_expiry_and_missingness: &'a [String],
}

/// Construct canonical activation and assessment candidates from evidence.
pub fn assess_learning_activation(
    input: &AssessmentInput<'_>,
) -> Result<AssessmentResultOrIncomplete, ActivationAssessmentError> {
    preflight(input)?;
    validate_identity(input)?;
    let missing = missing_mandatory_ids(input);
    if !missing.is_empty() {
        let sections = derive_sections(input)?;
        let snapshot = snapshot(input, &sections)?;
        let incomplete = IncompleteAssessment {
            input: snapshot,
            binding: input.binding.clone(),
            target: input.target.clone(),
            missing,
            supplied_stages: input.stages.to_vec(),
            supplied_dimensions: input.dimensions.to_vec(),
            activation_id: input.activation_id.cloned(),
        };
        let outcome = AssessmentResultOrIncomplete::Incomplete(Box::new(incomplete));
        let _ = bounded_serialized_len(
            &outcome,
            input.policy.max_output_bytes.min(MAX_OUTPUT_BYTES),
            "output",
        )?;
        return Ok(outcome);
    }
    validate_owner_lineage(input)?;
    validate_activation_sections(input)?;
    let sections = derive_sections(input)?;
    prove_overlay_displayable(input)?;
    let input_snapshot = snapshot(input, &sections)?;
    let stages = expected_stages(input.stages, input.policy)?;
    let dimensions = expected_dimensions(input.dimensions, input.policy)?;
    let activation = build_activation_candidate(input, stages, sections)?;
    let mut assessment = LearningAssessmentCandidate {
        binding: input.binding.clone(),
        target: input.target.clone(),
        overlay_id: input.overlay.overlay_id.clone(),
        activation_id: activation.activation_id.clone(),
        activation_digest: activation.canonical_digest.clone(),
        assessment_receipt: required_id(input.assessment_receipt, "assessment_receipt")?,
        dimensions,
        causal_ceiling: eliot_learning_contracts::CausalCeiling::Observational,
        external_review_refs: input.external_review_refs.to_vec(),
        canonical_digest: String::new(),
    };
    assessment
        .seal()
        .map_err(|error| ActivationAssessmentError::contract("assessment.seal", error))?;
    assessment
        .validate_against_activation(&activation)
        .map_err(|error| ActivationAssessmentError::contract("assessment.lineage", error))?;
    let mut result = AssessmentResult {
        input: input_snapshot,
        activation,
        assessment,
        canonical_digest: String::new(),
    };
    let _ = bounded_serialized_len(
        &result,
        input.policy.max_output_bytes.min(MAX_OUTPUT_BYTES),
        "result",
    )?;
    result.seal()?;
    result.validate()?;
    let outcome = AssessmentResultOrIncomplete::Candidate(Box::new(result));
    let _ = bounded_serialized_len(
        &outcome,
        input.policy.max_output_bytes.min(MAX_OUTPUT_BYTES),
        "output",
    )?;
    Ok(outcome)
}

/// Derive the eligibility verdict and the retrieval section from evidence.
///
/// Eligibility is never supplied: it is the canonical
/// [`overlay_eligibility`] predicate evaluated over the sealed overlay's own
/// `invalidated`, `expires_at_ms`, and `campaign_id` fields, the requesting
/// campaign, the binding-compatibility observation, and any fresh governed
/// cross-task admission. A non-eligible surface can never be reported as
/// eligible, because the caller has no field that could say so.
///
/// Retrieval is then derived from eligibility plus what was actually
/// observed, and stays orthogonal to delivery: an eligible surface that was
/// never retrieved is `ELIGIBLE_NOT_RETRIEVED`, and retrieval evidence is
/// recorded for an ineligible surface only as the explicit refusal.
fn derive_retrieval(
    input: &AssessmentInput<'_>,
) -> Result<(Option<String>, RetrievalSection), ActivationAssessmentError> {
    let overlay = input.overlay;
    let eligibility = overlay_eligibility(
        overlay.campaign_id.as_str(),
        input.retrieval.requesting_campaign_id,
        overlay.invalidated,
        overlay.expires_at_ms,
        input.retrieval.now_ms,
        input.retrieval.binding_compatible,
        input.retrieval.cross_task,
    );
    // An ineligible surface that a caller also claims to have retrieved is
    // contradictory evidence, not a status to pick a rung for: refuse
    // instead of silently downgrading to a retrieval status.
    if !matches!(eligibility, OverlayEligibility::Eligible) && input.retrieval.retrieved {
        return Err(ActivationAssessmentError::LineageMismatch {
            field: "retrieval.eligibility",
        });
    }
    ensure_unique_local(
        input.retrieval.expansion_or_tool_query_refs,
        "retrieval.expansion_or_tool_query_refs",
    )?;
    let (reason, status) = match eligibility {
        OverlayEligibility::NotEligible { reason } => {
            (Some(reason.to_owned()), RetrievalStatus::NotEligible)
        }
        OverlayEligibility::Eligible if !input.retrieval.retrieved => {
            (None, RetrievalStatus::EligibleNotRetrieved)
        }
        OverlayEligibility::Eligible if input.retrieval.expansion_or_tool_query_refs.is_empty() => {
            (None, RetrievalStatus::Retrieved)
        }
        OverlayEligibility::Eligible => (None, RetrievalStatus::Expanded),
    };
    Ok((
        reason,
        RetrievalSection {
            status,
            expansion_or_tool_query_refs: input.retrieval.expansion_or_tool_query_refs.to_vec(),
        },
    ))
}

/// Derive the delivery section from observed delivery facts.
///
/// A caller cannot name a delivery status. An attempt that never attempted
/// delivery is [`DeliveryStatus::NotDelivered`] with no packet facts, and
/// crucially carries NO activation evidence requirement: the derived
/// activation section in [`derive_activation`] refuses `OBSERVED` for any
/// non-delivered status, so an eligible-but-undelivered surface can never
/// claim activation. Full delivery requires a recorded serialized digest,
/// because a position and a byte count without the packet's own digest is
/// not a complete delivery.
fn derive_delivery(input: &AssessmentInput<'_>) -> DeliverySection {
    let observed = &input.delivery;
    if !observed.attempted {
        return DeliverySection {
            status: DeliveryStatus::NotDelivered,
            packet_position: None,
            serialized_digest: None,
            bytes: None,
            actual_tokens: None,
        };
    }
    // A recorded, non-blank serialized digest is the packet's own bytes and
    // the only evidence of a full delivery. Without one, a genuinely assembled
    // and placed packet is Partial, and an attempt that placed nothing is
    // Missing. A blank digest is never a delivery, whatever weaker packet
    // facts exist, so it takes the same path as no digest at all.
    let recorded_digest = observed
        .serialized_digest
        .filter(|digest| !digest.trim().is_empty());
    let has_packet_fact = observed.packet_position.is_some()
        || observed.bytes.is_some()
        || observed.actual_tokens.is_some();
    let status = if recorded_digest.is_some() {
        DeliveryStatus::Full
    } else if has_packet_fact {
        DeliveryStatus::Partial
    } else {
        DeliveryStatus::Missing
    };
    DeliverySection {
        status,
        packet_position: observed.packet_position,
        serialized_digest: recorded_digest.map(str::to_owned),
        bytes: observed.bytes,
        actual_tokens: observed.actual_tokens,
    }
}

/// Derive the observable-activation section from real use evidence only.
///
/// `OBSERVED` requires BOTH an actual qualifying observable-use reference
/// from the observability owner AND a delivered surface. The reference is
/// carried through unchanged and is never synthesized, defaulted, or taken
/// from the acknowledgement. When an owner observed nothing qualifying the
/// status is `NOT_OBSERVED`, which records absence of evidence and proves
/// nothing about non-use; when the attempt surface could not be observed at
/// all the status is `UNKNOWN`, which is never presumed either way. The
/// acknowledgement is recorded on its own field and stays orthogonal.
fn derive_activation(
    input: &AssessmentInput<'_>,
    delivery_status: DeliveryStatus,
) -> ActivationSection {
    let observed = &input.observable_use;
    let delivered = matches!(
        delivery_status,
        DeliveryStatus::Full | DeliveryStatus::Partial
    );
    let use_ref = observed.first_qualifying_use_ref;
    let qualifying_use = observed.observed_any
        && use_ref.is_some_and(|id| !id.as_str().trim().is_empty())
        // An acknowledgement is a delivery/attention signal only. Even if a
        // caller pointed the use field at it, that is not qualifying use.
        && use_ref != input.delivery.acknowledgement_ref;
    let status = if qualifying_use && delivered {
        ActivationStatus::Observed
    } else if !observed.observable {
        ActivationStatus::Unknown
    } else {
        ActivationStatus::NotObserved
    };
    ActivationSection {
        status,
        acknowledgement_ref: input.delivery.acknowledgement_ref.cloned(),
        observation_limit_reason: (!observed.observable)
            .then(|| "attempt surface was not observable for qualifying use".to_owned()),
        // A use reference is retained exactly when it qualifies. Without
        // qualifying use there is no use reference to record, so none is
        // fabricated.
        first_qualifying_observable_use_ref: if qualifying_use {
            use_ref.cloned()
        } else {
            None
        },
    }
}

/// Derive the adherence section from checkpoint, action, and verifier
/// evidence only.
///
/// An observed disposition is recorded ONLY when qualifying use was itself
/// observed and both evidence classes are non-empty. An explicit observed
/// violation is `OBSERVED_VIOLATED` and keeps the observed action and
/// checkpoint refs that show it. Anything absent, or any adherence claim
/// without a qualifying use, stays `UNKNOWN` and is never inferred
/// compliance.
fn derive_adherence(
    input: &AssessmentInput<'_>,
    activation_status: ActivationStatus,
) -> Result<AdherenceSection, ActivationAssessmentError> {
    let observed = &input.adherence;
    ensure_unique_local(
        observed.checkpoint_refs,
        "adherence.early_mid_final_checkpoint_refs",
    )?;
    ensure_unique_local(
        observed.action_and_verifier_refs,
        "adherence.prescribed_or_avoided_action_and_required_verifier_refs",
    )?;
    // An adherence claim about a surface that was never qualifying-observed
    // in use cannot be evidence of following the prescription.
    let assessed = activation_status == ActivationStatus::Observed
        && !observed.checkpoint_refs.is_empty()
        && !observed.action_and_verifier_refs.is_empty();
    if !assessed {
        return Ok(AdherenceSection {
            status: AdherenceStatus::Unknown,
            early_mid_final_checkpoint_refs: Vec::new(),
            prescribed_or_avoided_action_and_required_verifier_refs: Vec::new(),
        });
    }
    let status = match observed.observed_violation {
        // An owner-recorded violation is the disposition, and it is kept
        // together with the action/checkpoint refs that observed it.
        Some(AdherenceStatus::ObservedViolated) => AdherenceStatus::ObservedViolated,
        Some(_) | None => match observed.checkpoint_status {
            AdherenceStatus::ObservedFollowed => AdherenceStatus::ObservedFollowed,
            AdherenceStatus::ObservedPartial => AdherenceStatus::ObservedPartial,
            AdherenceStatus::ObservedViolated => AdherenceStatus::ObservedViolated,
            // NotAssessed and Unknown are not compliance.
            AdherenceStatus::NotAssessed | AdherenceStatus::Unknown => AdherenceStatus::Unknown,
        },
    };
    if matches!(
        status,
        AdherenceStatus::ObservedFollowed
            | AdherenceStatus::ObservedPartial
            | AdherenceStatus::ObservedViolated
    ) {
        return Ok(AdherenceSection {
            status,
            early_mid_final_checkpoint_refs: observed.checkpoint_refs.to_vec(),
            prescribed_or_avoided_action_and_required_verifier_refs: observed
                .action_and_verifier_refs
                .to_vec(),
        });
    }
    Ok(AdherenceSection {
        status: AdherenceStatus::Unknown,
        early_mid_final_checkpoint_refs: Vec::new(),
        prescribed_or_avoided_action_and_required_verifier_refs: Vec::new(),
    })
}

/// Derive all five orthogonal sections in dependency order.
///
/// The order is the orthogonality rule made mechanical: eligibility and
/// retrieval come from the sealed overlay plus the retrieval observation,
/// delivery comes from the delivery observation alone, activation comes from
/// real use evidence plus the derived delivery, and adherence comes from
/// checkpoint/action/verifier evidence plus the derived activation. No
/// section reads a caller-supplied status.
fn derive_sections(
    input: &AssessmentInput<'_>,
) -> Result<DerivedSections, ActivationAssessmentError> {
    let (eligibility_and_retrieval_reason, retrieval) = derive_retrieval(input)?;
    let delivery = derive_delivery(input);
    let activation = derive_activation(input, delivery.status);
    let adherence = derive_adherence(input, activation.status)?;
    Ok(DerivedSections {
        eligibility_and_retrieval_reason,
        retrieval,
        delivery,
        activation,
        adherence,
    })
}

/// Build the immutable activation receipt candidate from derived evidence.
///
/// The harness, compiler, and reference slices are cloned from the supplied
/// input without synthesis. The five lifecycle sections are NOT cloned: they
/// are derived by [`derive_sections`] from the observed evidence in
/// [`AssessmentInput`], and the canonical
/// [`HarnessActivationReceiptCandidate::validate_against_lineage`] then
/// re-checks the ack-as-use substitution and evidence-free observed
/// adherence rules on the derived values.
/// Bind the assessed overlay's frozen pre-evaluation fields by digest.
///
/// Reuses the overlay `freeze` digest over the sealed input overlay's own
/// texts, identity and canonical digest, so the receipt records the identical
/// value the admission receipt stores (W3 of #1864).
fn frozen_digest_of_overlay(overlay: &CampaignHarnessOverlayCandidate) -> String {
    eliot_learning_overlay::frozen_digest(
        &eliot_learning_overlay::FrozenPreEvaluation {
            intended_mechanism: overlay.intended_mechanism.clone(),
            prediction: overlay.prediction.clone(),
            expected_observable: overlay.expected_observable.clone(),
            possible_regressions: overlay.possible_regressions.clone(),
            confounders: overlay.confounders.clone(),
            preserved_success_constraint: overlay.preserved_success_constraint.clone(),
            next_discriminator_text: overlay.next_discriminator_text.clone(),
            rollback_condition: overlay.rollback_condition.clone(),
        },
        overlay.overlay_id.as_str(),
        &overlay.canonical_digest,
    )
}

fn build_activation_candidate(
    input: &AssessmentInput<'_>,
    stages: Vec<StageObservation>,
    sections: DerivedSections,
) -> Result<HarnessActivationReceiptCandidate, ActivationAssessmentError> {
    let mut activation = HarnessActivationReceiptCandidate {
        binding: input.binding.clone(),
        activation_id: required_id(input.activation_id, "activation_id")?,
        target: input.target.clone(),
        view_digest: input.view.canonical_digest.clone(),
        delta_id: input.delta.delta_id.clone(),
        overlay_id: input.overlay.overlay_id.clone(),
        admission_receipt: required_id(input.admission_receipt, "admission_receipt")?,
        activation_request_receipt: required_id(
            input.activation_request_receipt,
            "activation_request_receipt",
        )?,
        stages,
        // The canonical view owns the observed member denominator. The local
        // policy denominator is only used for synthesized unknown rows.
        member_denominator: input.view.denominator,
        metrics: input.metrics.to_vec(),
        attrition: input.attrition.to_vec(),
        confounders: input.confounders.to_vec(),
        independent_evaluator_receipt: input.independent_evaluator_receipt.cloned(),
        compiled_view_ref: input.compiled_view_ref.clone(),
        context_compiler_revision: input.context_compiler_revision.to_owned(),
        render_profile_revision: input.render_profile_revision.to_owned(),
        stable_harness_refs: input.stable_harness_refs.to_vec(),
        task_family_harness_refs: input.task_family_harness_refs.to_vec(),
        skill_refs: input.skill_refs.to_vec(),
        memory_refs: input.memory_refs.to_vec(),
        procedure_refs: input.procedure_refs.to_vec(),
        preserved_success_ref: input.preserved_success_ref.cloned(),
        eligibility_and_retrieval_reason: sections.eligibility_and_retrieval_reason,
        retrieval: sections.retrieval,
        delivery: sections.delivery,
        activation: sections.activation,
        adherence: sections.adherence,
        conflicts_suppression_or_compaction_loss: input
            .conflicts_suppression_or_compaction_loss
            .to_vec(),
        downstream_decision_action_artifact_and_verifier_refs: input.downstream_refs.to_vec(),
        receipt_completeness_and_missing_fields: input
            .receipt_completeness_and_missing_fields
            .to_vec(),
        invalidation_expiry_and_missingness: input.invalidation_expiry_and_missingness.to_vec(),
        frozen_pre_evaluation_digest: Some(frozen_digest_of_overlay(input.overlay)),
        canonical_digest: String::new(),
    };
    activation
        .seal()
        .map_err(|error| ActivationAssessmentError::contract("activation.seal", error))?;
    activation
        .validate_against_lineage(input.view, input.delta, input.overlay)
        .map_err(|error| ActivationAssessmentError::contract("activation.lineage", error))?;
    Ok(activation)
}

/// Result arm preserving a constructed candidate or explicit incomplete input.
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(tag = "disposition", content = "value", deny_unknown_fields)]
pub enum AssessmentResultOrIncomplete {
    /// Mandatory identities were supplied and validated.
    Candidate(Box<AssessmentResult>),
    /// Mandatory evidence was absent; no identity was fabricated.
    Incomplete(Box<IncompleteAssessment>),
}

/// Prove the admitted nontrivial overlay is displayable from sealed sources.
///
/// An attempt with an admitted overlay must be able to display the immutable
/// revision, parent, source delta, pre-evaluation prediction, expected
/// observable, regressions/confounders, preserved-success constraint, next
/// discriminator, and rollback condition (acceptance A1). Assessment refuses
/// to certify an activation whose overlay cannot render that bundle: every
/// text comes from the sealed [`CampaignHarnessOverlayCandidate`] carried in
/// the input, which [`validate`] already proved digest-covered.
///
/// [`validate`]: eliot_learning_contracts::CampaignHarnessOverlayCandidate::validate
fn prove_overlay_displayable(input: &AssessmentInput<'_>) -> Result<(), ActivationAssessmentError> {
    use crate::overlay_display_1864::{OverlayDisplayInput, display_admitted_overlay};
    let overlay = input.overlay;
    let admitted_ids: Vec<String> = overlay
        .admitted_delta_ids
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    let parent = format!("task-revision:{}", overlay.parent_revision.value());
    let display_input = OverlayDisplayInput {
        overlay_id: overlay.overlay_id.as_str(),
        revision: overlay.revision,
        parent_revision: &parent,
        admitted_delta_ids: &admitted_ids,
        prediction: &overlay.prediction,
        expected_observable: &overlay.expected_observable,
        regressions: &overlay.possible_regressions,
        confounders: &overlay.confounders,
        preserved_success: &overlay.preserved_success_constraint,
        next_discriminator: &overlay.next_discriminator_text,
        rollback_condition: &overlay.rollback_condition,
    };
    display_admitted_overlay(&display_input).map_err(|_| {
        ActivationAssessmentError::LineageMismatch {
            field: "overlay.display",
        }
    })?;
    Ok(())
}

fn validate_identity(input: &AssessmentInput<'_>) -> Result<(), ActivationAssessmentError> {
    if input.binding != &input.view.binding
        || input.binding != &input.delta.binding
        || input.binding != &input.overlay.binding
        || input.target != &input.view.target
        || input.target != &input.delta.target
    {
        return Err(ActivationAssessmentError::LineageMismatch { field: "binding" });
    }
    validate_external_id(input.target.as_str(), "target")
        .map_err(|error| ActivationAssessmentError::contract("target", error))
}

fn missing_mandatory_ids(input: &AssessmentInput<'_>) -> Vec<MissingAssessmentField> {
    let mut missing = Vec::new();
    if input.activation_id.is_none() {
        missing.push(MissingAssessmentField::ActivationId);
    }
    if input.admission_receipt.is_none() {
        missing.push(MissingAssessmentField::AdmissionReceipt);
    }
    if input.activation_request_receipt.is_none() {
        missing.push(MissingAssessmentField::ActivationRequestReceipt);
    }
    if input.assessment_receipt.is_none() {
        missing.push(MissingAssessmentField::AssessmentReceipt);
    }
    missing
}

fn required_id(
    value: Option<&ArtifactId>,
    field: &'static str,
) -> Result<ArtifactId, ActivationAssessmentError> {
    value
        .cloned()
        .ok_or(ActivationAssessmentError::LineageMismatch { field })
}

fn validate_owner_lineage(input: &AssessmentInput<'_>) -> Result<(), ActivationAssessmentError> {
    input
        .view
        .validate_against(input.recipe)
        .map_err(|error| ActivationAssessmentError::contract("view", error))?;
    input
        .view
        .binding
        .validate()
        .map_err(|error| ActivationAssessmentError::contract("view.binding", error))?;
    input
        .delta
        .validate_against_view(input.view)
        .map_err(|error| ActivationAssessmentError::contract("delta", error))?;
    input
        .overlay
        .validate_against_view_and_deltas(input.view, std::slice::from_ref(input.delta))
        .map_err(|error| ActivationAssessmentError::contract("overlay", error))?;
    validate_supplied_evidence(input.metrics, input.stages, input.dimensions)?;
    Ok(())
}

pub(crate) fn validate_supplied_evidence(
    metrics: &[MetricObservation],
    stages: &[StageObservation],
    dimensions: &[DimensionAssessment],
) -> Result<(), ActivationAssessmentError> {
    for metric in metrics {
        metric
            .validate()
            .map_err(|error| ActivationAssessmentError::contract("metric", error))?;
    }
    let metric_ids = metrics
        .iter()
        .map(|metric| metric.metric_id.as_str())
        .collect::<BTreeSet<_>>();
    for stage in stages {
        stage
            .validate()
            .map_err(|error| ActivationAssessmentError::contract("stage", error))?;
    }
    for dimension in dimensions {
        dimension
            .validate()
            .map_err(|error| ActivationAssessmentError::contract("dimension", error))?;
        if dimension
            .metric_ids
            .iter()
            .any(|metric_id| !metric_ids.contains(metric_id.as_str()))
        {
            return Err(ActivationAssessmentError::LineageMismatch {
                field: "dimension.metric_ids",
            });
        }
    }
    Ok(())
}

/// Crate-local guard for the new receipt sections plus uniqueness of the new
/// reference slices. The canonical contracts crate re-enforces these;
/// this guard fails fast before any candidate is sealed.
pub(crate) fn validate_activation_sections(
    input: &AssessmentInput<'_>,
) -> Result<(), ActivationAssessmentError> {
    // Honest bounded accounting for the new borrowed evidence. `bounds::preflight`
    // (not owned by this work unit) serializes only the original fields, so the
    // new fields are counted here under the same caller-supplied byte limit.
    #[derive(serde::Serialize)]
    struct NewFieldPreflight<'a> {
        compiled_view_ref: &'a ArtifactId,
        context_compiler_revision: &'a str,
        render_profile_revision: &'a str,
        stable_harness_refs: &'a [ArtifactId],
        task_family_harness_refs: &'a [ArtifactId],
        skill_refs: &'a [ArtifactId],
        memory_refs: &'a [ArtifactId],
        procedure_refs: &'a [ArtifactId],
        preserved_success_ref: Option<&'a ArtifactId>,
        retrieval: &'a ObservedRetrieval<'a>,
        delivery: &'a ObservedDelivery<'a>,
        observable_use: &'a ObservedUse<'a>,
        adherence: &'a ObservedAdherence<'a>,
        conflicts_suppression_or_compaction_loss: &'a [ArtifactId],
        downstream_refs: &'a [ArtifactId],
        receipt_completeness_and_missing_fields: &'a [String],
        invalidation_expiry_and_missingness: &'a [String],
    }
    let bounded = NewFieldPreflight {
        compiled_view_ref: input.compiled_view_ref,
        context_compiler_revision: input.context_compiler_revision,
        render_profile_revision: input.render_profile_revision,
        stable_harness_refs: input.stable_harness_refs,
        task_family_harness_refs: input.task_family_harness_refs,
        skill_refs: input.skill_refs,
        memory_refs: input.memory_refs,
        procedure_refs: input.procedure_refs,
        preserved_success_ref: input.preserved_success_ref,
        retrieval: &input.retrieval,
        delivery: &input.delivery,
        observable_use: &input.observable_use,
        adherence: &input.adherence,
        conflicts_suppression_or_compaction_loss: input.conflicts_suppression_or_compaction_loss,
        downstream_refs: input.downstream_refs,
        receipt_completeness_and_missing_fields: input.receipt_completeness_and_missing_fields,
        invalidation_expiry_and_missingness: input.invalidation_expiry_and_missingness,
    };
    let _ = bounded_serialized_len(
        &bounded,
        input
            .policy
            .max_input_bytes
            .min(crate::contracts::MAX_INPUT_BYTES),
        "input",
    )?;
    ensure_unique_local(input.stable_harness_refs, "stable_harness_refs")?;
    ensure_unique_local(input.task_family_harness_refs, "task_family_harness_refs")?;
    ensure_unique_local(input.skill_refs, "skill_refs")?;
    ensure_unique_local(input.memory_refs, "memory_refs")?;
    ensure_unique_local(input.procedure_refs, "procedure_refs")?;
    ensure_unique_local(
        input.conflicts_suppression_or_compaction_loss,
        "conflicts_suppression_or_compaction_loss",
    )?;
    ensure_unique_local(input.downstream_refs, "downstream_refs")?;
    // The five lifecycle sections carry no caller-supplied status, so the
    // ack-as-use and evidence-free-observed-adherence guards now live where
    // the statuses are produced — in `derive_activation` and
    // `derive_adherence` — and are re-enforced by the canonical
    // `HarnessActivationReceiptCandidate::validate` on the derived receipt.
    Ok(())
}

fn ensure_unique_local(
    ids: &[ArtifactId],
    field: &'static str,
) -> Result<(), ActivationAssessmentError> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id.as_str()) {
            return Err(ActivationAssessmentError::Duplicate { field });
        }
    }
    Ok(())
}

/// Retain the complete bounded input together with the DERIVED sections.
///
/// The snapshot stores what the receipt actually carries, so the result can
/// never outlive the evidence it was derived from: the retained sections are
/// the derived ones, not the observations they came from.
fn snapshot(
    input: &AssessmentInput<'_>,
    sections: &DerivedSections,
) -> Result<crate::contracts::AssessmentInputSnapshot, ActivationAssessmentError> {
    let mut snapshot = crate::contracts::AssessmentInputSnapshot {
        recipe: input.recipe.clone(),
        view: input.view.clone(),
        delta: input.delta.clone(),
        overlay: input.overlay.clone(),
        binding: input.binding.clone(),
        target: input.target.clone(),
        policy: input.policy.clone(),
        activation_id: input.activation_id.cloned(),
        admission_receipt: input.admission_receipt.cloned(),
        activation_request_receipt: input.activation_request_receipt.cloned(),
        assessment_receipt: input.assessment_receipt.cloned(),
        stages: input.stages.to_vec(),
        metrics: input.metrics.to_vec(),
        attrition: input.attrition.to_vec(),
        confounders: input.confounders.to_vec(),
        independent_evaluator_receipt: input.independent_evaluator_receipt.cloned(),
        dimensions: input.dimensions.to_vec(),
        external_review_refs: input.external_review_refs.to_vec(),
        compiled_view_ref: input.compiled_view_ref.clone(),
        context_compiler_revision: input.context_compiler_revision.to_owned(),
        render_profile_revision: input.render_profile_revision.to_owned(),
        stable_harness_refs: input.stable_harness_refs.to_vec(),
        task_family_harness_refs: input.task_family_harness_refs.to_vec(),
        skill_refs: input.skill_refs.to_vec(),
        memory_refs: input.memory_refs.to_vec(),
        procedure_refs: input.procedure_refs.to_vec(),
        preserved_success_ref: input.preserved_success_ref.cloned(),
        eligibility_and_retrieval_reason: sections.eligibility_and_retrieval_reason.clone(),
        retrieval: sections.retrieval.clone(),
        delivery: sections.delivery.clone(),
        activation: sections.activation.clone(),
        adherence: sections.adherence.clone(),
        conflicts_suppression_or_compaction_loss: input
            .conflicts_suppression_or_compaction_loss
            .to_vec(),
        downstream_refs: input.downstream_refs.to_vec(),
        receipt_completeness_and_missing_fields: input
            .receipt_completeness_and_missing_fields
            .to_vec(),
        invalidation_expiry_and_missingness: input.invalidation_expiry_and_missingness.to_vec(),
        input_digest: String::new(),
    };
    snapshot.seal()?;
    Ok(snapshot)
}

pub(crate) fn expected_stages(
    supplied: &[StageObservation],
    policy: &AssessmentPolicy,
) -> Result<Vec<StageObservation>, ActivationAssessmentError> {
    let mut stages = Vec::with_capacity(supplied.len() + policy.required_stages.len());
    let mut seen = BTreeSet::new();
    for stage in supplied {
        if !seen.insert(stage.stage) {
            return Err(ActivationAssessmentError::Duplicate { field: "stages" });
        }
        stages.push(stage.clone());
    }
    for required in &policy.required_stages {
        if !seen.contains(required) {
            stages.push(StageObservation {
                stage: *required,
                disposition: StageDisposition::Unknown,
                predecessor: required.required_predecessor(),
                owner_receipt: None,
                evidence: Vec::new(),
                denominator: policy.stage_denominator,
            });
        }
    }
    stages.sort_by_key(|stage| stage.stage);
    Ok(stages)
}

pub(crate) fn expected_dimensions(
    supplied: &[DimensionAssessment],
    policy: &AssessmentPolicy,
) -> Result<Vec<DimensionAssessment>, ActivationAssessmentError> {
    let mut dimensions = Vec::with_capacity(supplied.len() + policy.required_dimensions.len());
    let mut seen = BTreeSet::new();
    for dimension in supplied {
        if !seen.insert(dimension.dimension) {
            return Err(ActivationAssessmentError::Duplicate {
                field: "dimensions",
            });
        }
        let mut retained = dimension.clone();
        retained.causal_ceiling = eliot_learning_contracts::CausalCeiling::Observational;
        dimensions.push(retained);
    }
    for required in &policy.required_dimensions {
        if !seen.contains(required) {
            dimensions.push(DimensionAssessment {
                dimension: *required,
                status: DimensionStatus::Unknown,
                evidence: Vec::new(),
                owner_receipt: None,
                denominator: policy.dimension_denominator,
                metric_ids: Vec::new(),
                causal_ceiling: eliot_learning_contracts::CausalCeiling::Observational,
            });
        }
    }
    dimensions.sort_by_key(|dimension| dimension.dimension);
    Ok(dimensions)
}
