//! Production caller wiring consequential learning-delta derivation to Governor admission.
//!
//! Derivation here is candidate-only: it proposes a durable stored record with
//! lineage, never a behavioral effect. The durable record carries the exact
//! prior observable digest forward to the next materially related attempt.
//! Delivery of any behavioral effect requires a verified Governor admission
//! issued for the stored delta (I12.24 line 179).
//!
//! Boundary authorization is derived, not asserted: the caller supplies the
//! activity name and the lifecycle activities an owner recorded, and
//! [`derive_delta_at_boundary`] derives the boundaries from them. Ordinary
//! reads (`read_file`/`read`/`grep`) are excluded by the same matcher
//! ([`status_for_tool`]) and never derive (line 181), and an empty or
//! ordinary-read activity set refuses before derivation runs.

use eliot_contracts::{ArtifactId, StateFence};
use eliot_learning_activation_assessment::{
    ActivationAssessmentError, AssessmentInput, AssessmentPolicy, AssessmentResultOrIncomplete,
    assess_learning_activation,
};
use eliot_learning_contracts::{
    ActivationSection, AdherenceSection, AgentAttemptId, AttemptLearningDeltaCandidate,
    AttemptLearningOutcome, CampaignHarnessOverlayCandidate, CampaignId, CampaignLearningStateView,
    ContractBinding, DeliverySection, DimensionAssessment, HarnessActivationReceiptCandidate,
    LearningStateViewRecipe, MetricObservation, OverlayId, RetrievalSection, StageObservation,
    TargetId,
};
use eliot_learning_delta::{
    AdmissionReceipt, AttemptCloseDisposition, AttemptEvidence, AttemptStatus,
    ConsequentialBoundary, DeliveryRefusal, DerivationContext, DerivationPolicy,
    LearningDeltaError, LifecycleActivity, RefinerDraft, RetryEquivalence, StoredDeltaDisposition,
    StoredLearningDelta, StoredRetryRelation, check_delivery_typed, delivery_allowed,
    derive_attempt_learning_outcome, derive_boundaries, require_consequential, status_for_boundary,
};
use thiserror::Error;

use crate::Governor;
use crate::learning_admission::{
    LEARNING_ADMISSION_SCHEMA_VERSION, LearningAdmissionClaim, LearningAdmissionError,
    LearningAdmissionPermit, issue_learning_admission, verify_learning_admission,
};

/// Owner-derived identity every stored learning delta must name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredDeltaIdentity {
    /// Named campaign the attempt belongs to.
    pub campaign_id: CampaignId,
    /// Consequential attempt identity.
    pub attempt_id: AgentAttemptId,
    /// State fence the attempt executed under.
    pub state_fence: StateFence,
    /// Actor identity that produced the attempt.
    pub actor_id: String,
    /// Route identity that produced the attempt.
    pub route_id: String,
    /// Overlay identity the attempt was evaluated against.
    pub overlay_id: OverlayId,
    /// Derived consequential boundary that justified the record.
    pub consequential_boundary: ConsequentialBoundary,
    /// Canonical fingerprint of the strategy the attempt applied.
    pub strategy_fingerprint: String,
    /// Raw trace, artifact, and evaluator references observed for the attempt.
    pub evidence_refs: Vec<ArtifactId>,
}

/// Derive a candidate learning outcome only at a derived consequential boundary.
///
/// `activity_name` is the activity/tool identity the owner recorded for the
/// observed step and `observed` are the lifecycle activities the same owner
/// recorded. The boundaries are derived through
/// [`derive_boundaries`], so an ordinary read and an empty activity set both
/// refuse with [`LearningDeltaError::NonConsequential`] before derivation runs,
/// and a caller naming a [`ConsequentialBoundary`] value authorizes nothing.
/// When a boundary is derived, derivation runs as candidate-only proposal;
/// behavioral effect still needs admission.
pub fn derive_delta_at_boundary(
    activity_name: &str,
    observed: &[LifecycleActivity],
    state_view: &CampaignLearningStateView,
    evidence: &AttemptEvidence,
    context: &DerivationContext<'_>,
    draft: Option<&RefinerDraft>,
    policy: &DerivationPolicy,
) -> Result<AttemptLearningOutcome, LearningDeltaError> {
    let boundaries = derive_boundaries(activity_name, observed)?;
    require_consequential(&boundaries)?;
    derive_attempt_learning_outcome(state_view, evidence, context, draft, policy)
}

/// Map an owner-recorded activity set to its derived boundary status.
///
/// The read exclusion and the empty-activity refusal both live in
/// [`derive_boundaries`], so a caller that only needs the status (for example a
/// scheduler deciding whether a step is worth closing) uses the same matcher the
/// derivation wrapper uses and cannot diverge from it.
pub fn attempt_status_for_activity(
    activity_name: &str,
    observed: &[LifecycleActivity],
) -> Result<AttemptStatus, LearningDeltaError> {
    let boundaries = derive_boundaries(activity_name, observed)?;
    Ok(status_for_boundary(Some(require_consequential(
        &boundaries,
    )?)))
}

/// Build the validated durable stored record for a derived outcome.
///
/// Every stored delta names its campaign, attempt, `StateFence`,
/// actor/route/overlay/artifact identity, the derived consequential boundary,
/// the applied strategy fingerprint, its raw trace/evaluator references, the
/// explicit retry relation, and a disposition, all enforced by
/// [`StoredLearningDelta::validate`]. A fresh `Delta` candidate is proposed
/// (`NEXT_PROBE_CHANGED`); a `NoChange` outcome closes honestly as
/// `NO_JUSTIFIED_CHANGE`. A materially equivalent retry relation is refused
/// here: a controlled repeat may justify no change, never a new candidate.
pub fn store_derived_delta(
    outcome: &AttemptLearningOutcome,
    identity: &StoredDeltaIdentity,
    retry_relation: Option<StoredRetryRelation>,
) -> Result<StoredLearningDelta, LearningDeltaError> {
    if retry_relation
        .as_ref()
        .is_some_and(|retry| matches!(retry.equivalence, RetryEquivalence::Equivalent))
    {
        return Err(LearningDeltaError::InvalidInput {
            field: "stored.retry_equivalence",
        });
    }
    let (delta_artifact, delta_digest, evidence_refs, disposition) = match outcome {
        AttemptLearningOutcome::Delta(candidate) => {
            let mut refs = identity.evidence_refs.clone();
            refs.extend(candidate.evidence.iter().cloned());
            (
                candidate.delta_id.clone(),
                candidate.canonical_digest.clone(),
                refs,
                StoredDeltaDisposition::NextProbeChanged,
            )
        }
        AttemptLearningOutcome::NoChange(disposition) => {
            // A close carries no candidate: bind the record to the lead
            // affirmative-evidence handle and the sealed no-change digest.
            let lead = disposition.affirmative_evidence.first().ok_or(
                LearningDeltaError::InvalidInput {
                    field: "stored.close_evidence",
                },
            )?;
            let mut refs = identity.evidence_refs.clone();
            refs.extend(disposition.affirmative_evidence.iter().cloned());
            (
                lead.clone(),
                disposition.canonical_digest.clone(),
                refs,
                AttemptCloseDisposition::NoJustifiedChange.as_stored(),
            )
        }
    };
    let record = StoredLearningDelta {
        campaign_id: identity.campaign_id.clone(),
        attempt_id: identity.attempt_id.clone(),
        state_fence: identity.state_fence.clone(),
        actor_id: identity.actor_id.clone(),
        route_id: identity.route_id.clone(),
        overlay_id: identity.overlay_id.clone(),
        consequential_boundary: identity.consequential_boundary,
        strategy_fingerprint: identity.strategy_fingerprint.clone(),
        evidence_refs: sorted_unique(evidence_refs),
        delta_artifact,
        delta_digest,
        retry_relation,
        disposition,
        admission_receipt_id: None,
    };
    record.validate()?;
    Ok(record)
}

/// Build the validated durable record for an honest close that yields no delta.
///
/// `NO_JUSTIFIED_CHANGE`, `INCONCLUSIVE` and `INVALID_EVIDENCE` are legitimate
/// dispositions: this entry records the close with its own disposition instead
/// of manufacturing a behavioral candidate, so an attempt whose evidence is
/// absent or inconclusive still reaches a durable, visible disposition
/// (I12.24 line 291: silence is not a disposition).
pub fn store_attempt_close(
    identity: &StoredDeltaIdentity,
    close: AttemptCloseDisposition,
    retry_relation: Option<StoredRetryRelation>,
    evidence_refs: Vec<ArtifactId>,
) -> Result<StoredLearningDelta, LearningDeltaError> {
    let mut refs = identity.evidence_refs.clone();
    refs.extend(evidence_refs);
    let refs = sorted_unique(refs);
    let ref_texts: Vec<&str> = refs.iter().map(ArtifactId::as_str).collect();
    // The close anchor is content-addressed from the exact close binding, so
    // two different closes of the same attempt never share one identity.
    let binding = eliot_contracts::canonical_json_bytes(&(
        identity.campaign_id.as_str(),
        identity.attempt_id.as_str(),
        identity.consequential_boundary,
        identity.strategy_fingerprint.as_str(),
        close,
        ref_texts.as_slice(),
    ))
    .map_err(|_| LearningDeltaError::InvalidInput {
        field: "stored.close_binding",
    })?;
    let delta_digest = eliot_contracts::sha256_hex(&binding);
    let delta_artifact =
        ArtifactId::new(format!("learning-delta:{}", delta_digest)).map_err(|_| {
            LearningDeltaError::InvalidInput {
                field: "stored.delta_artifact",
            }
        })?;
    let record = StoredLearningDelta {
        campaign_id: identity.campaign_id.clone(),
        attempt_id: identity.attempt_id.clone(),
        state_fence: identity.state_fence.clone(),
        actor_id: identity.actor_id.clone(),
        route_id: identity.route_id.clone(),
        overlay_id: identity.overlay_id.clone(),
        consequential_boundary: identity.consequential_boundary,
        strategy_fingerprint: identity.strategy_fingerprint.clone(),
        evidence_refs: refs,
        delta_artifact,
        delta_digest,
        retry_relation,
        disposition: close.as_stored(),
        admission_receipt_id: None,
    };
    record.validate()?;
    Ok(record)
}

/// Sort and deduplicate artifact references so the record binds a stable set.
fn sorted_unique(refs: Vec<ArtifactId>) -> Vec<ArtifactId> {
    let mut refs = refs;
    refs.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    refs.dedup();
    refs
}

/// Build the Governor admission claim bound to one stored delta.
///
/// The stored delta's artifact id becomes the claim's candidate subject
/// (`candidate_id`), so the subsequent permit authorizes at most that exact
/// candidate. Mint-time trimming is handled by issuance; inputs are stored as
/// given.
#[allow(clippy::too_many_arguments)]
pub fn admission_claim_for_delta(
    campaign_id: &str,
    target_task_id: &str,
    fence: StateFence,
    delta_artifact_id: &str,
    overlay_id: Option<&str>,
    scope_ref: &str,
    authority_ref: &str,
    retention_ref: &str,
    evaluator_ref: &str,
    rollback_ref: &str,
) -> LearningAdmissionClaim {
    LearningAdmissionClaim {
        schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
        source_campaign_id: campaign_id.to_owned(),
        target_task_id: target_task_id.to_owned(),
        fence,
        overlay_id: overlay_id.map(str::to_owned),
        candidate_id: Some(delta_artifact_id.to_owned()),
        scope_ref: scope_ref.to_owned(),
        authority_ref: authority_ref.to_owned(),
        retention_ref: retention_ref.to_owned(),
        evaluator_ref: evaluator_ref.to_owned(),
        rollback_ref: rollback_ref.to_owned(),
    }
}

/// Issue a Governor admission permit for a stored-delta claim.
///
/// Governor admission is required before any behavioral effect (I12.24 line
/// 179): derivation output stays candidate-only until the owner mints a
/// permit for the bound claim. Thin wrapper over `issue_learning_admission`.
pub fn issue_delta_admission(
    governor: &Governor,
    claim: &LearningAdmissionClaim,
) -> Result<LearningAdmissionPermit, LearningAdmissionError> {
    issue_learning_admission(governor, claim)
}

/// Verify that a delta delivery permit is currently admitted.
///
/// Admitted-only delivery: returns `true` only when
/// `verify_learning_admission` rebinds the permit to the live owner
/// epoch/generation and the current fence. Any refusal means no delivery.
pub fn verify_delta_delivery(
    governor: &Governor,
    permit: &LearningAdmissionPermit,
    current_fence: &StateFence,
) -> bool {
    verify_learning_admission(governor, permit, current_fence).is_ok()
}

/// Check whether a stored delta may be delivered under a receipt.
///
/// An unadmitted proposal is stored but not delivered: delivery requires a
/// verified admission receipt bound to the delta artifact and digest.
pub fn delta_delivery_allowed(
    receipt: Option<&AdmissionReceipt>,
    delta: &StoredLearningDelta,
) -> bool {
    delivery_allowed(receipt, &delta.delta_artifact, &delta.delta_digest)
}

/// Enforce the delivery gate for one stored delta and report the refusal.
///
/// The typed [`DeliveryRefusal`] is what a consumer records, so a stale or
/// mismatched admission receipt is never indistinguishable from an absent one.
/// An unadmitted proposed behavioral change is not delivered to the subsequent
/// attempt.
pub fn delta_delivery_refusal(
    receipt: Option<&AdmissionReceipt>,
    delta: &StoredLearningDelta,
) -> Option<DeliveryRefusal> {
    check_delivery_typed(receipt, &delta.delta_artifact, &delta.delta_digest).err()
}

/// Canonical retry lineage a materially related attempt must reference.
///
/// The relation carries the prior attempt identity, the prior durable delta
/// artifact and digest, the prior canonical strategy fingerprint, the prior
/// observable and evidence references, and the equivalence verdict with its
/// allowed unchanged-retry reason when one exists. Lineage carries the digest
/// so the retry binds to the exact prior observable and evidence.
pub fn retry_lineage_for_delta(delta: &StoredLearningDelta) -> Option<&StoredRetryRelation> {
    delta.lineage_for_retry()
}

/// Exact canonical evidence handles a retry must carry with the lineage.
pub fn retry_canonical_evidence_for_delta(delta: &StoredLearningDelta) -> Vec<ArtifactId> {
    delta.retry_canonical_evidence()
}

/// Fail-closed error for the attempt-close composition below.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AttemptCloseError {
    /// Storing the derived delta failed; no receipt was attempted.
    #[error(transparent)]
    Delta(#[from] LearningDeltaError),
    /// Activation assessment failed or the evidence was incomplete.
    #[error(transparent)]
    Activation(#[from] ActivationAssessmentError),
}

/// Emit the per-attempt activation receipt candidate at attempt close.
///
/// Candidate-only composition over caller-supplied attempt-close evidence
/// (I12.24 l224): the receipt records whether the admitted learning surface
/// was eligible, compiled, retrieved and delivered, whether qualifying
/// observable activation occurred, and whether its prescription was followed
/// or violated. Receipt existence never implies successful delivery, use,
/// adherence or benefit. It does not grant authority, schedule an attempt,
/// promote a candidate, or infer causal benefit.
///
/// Retrieval, delivery, observable activation, adherence and outcome stay
/// orthogonal (I12.24 l256): the fields are not a success ladder, so every
/// section arrives as an explicit caller-supplied param and is passed through
/// to [`assess_learning_activation`] unchanged. In particular:
/// - `first_qualifying_observable_use_ref` is the caller's; nothing is
///   fabricated here. An acknowledgement is a delivery/attention signal only
///   and never substitutes for the qualifying use ref (enforced by assess).
/// - Delivery packet facts (position, digest, bytes, tokens) arrive as params
///   from the Context Compiler owner; nothing is synthesized here.
/// - Missing or inconclusive observability arrives as `UNKNOWN`/`NOT_ASSESSED`
///   statuses from the caller; nothing defaults to compliance.
///
/// The caller is the Task-Controller attempt-close path, which supplies the
/// compiled view/delta/overlay refs, the compiler and render revisions, and
/// the retrieval/delivery/activation/adherence sections from the Context
/// Compiler and observability owners. On the `Candidate` arm the constructed
/// [`HarnessActivationReceiptCandidate`] is returned; on the `Incomplete` arm
/// (caller omitted mandatory receipt identities) an error is returned and no
/// receipt is fabricated.
#[allow(clippy::too_many_arguments)]
pub fn emit_activation_receipt_at_attempt_close(
    binding: &ContractBinding,
    target: &TargetId,
    view: &CampaignLearningStateView,
    recipe: &LearningStateViewRecipe,
    delta: &AttemptLearningDeltaCandidate,
    overlay: &CampaignHarnessOverlayCandidate,
    activation_id: Option<&ArtifactId>,
    admission_receipt: Option<&ArtifactId>,
    activation_request_receipt: Option<&ArtifactId>,
    assessment_receipt: Option<&ArtifactId>,
    stages: &[StageObservation],
    metrics: &[MetricObservation],
    attrition: &[ArtifactId],
    confounders: &[ArtifactId],
    independent_evaluator_receipt: Option<&ArtifactId>,
    dimensions: &[DimensionAssessment],
    external_review_refs: &[ArtifactId],
    policy: &AssessmentPolicy,
    compiled_view_ref: &ArtifactId,
    context_compiler_revision: &str,
    render_profile_revision: &str,
    stable_harness_refs: &[ArtifactId],
    task_family_harness_refs: &[ArtifactId],
    skill_refs: &[ArtifactId],
    memory_refs: &[ArtifactId],
    procedure_refs: &[ArtifactId],
    preserved_success_ref: Option<&ArtifactId>,
    eligibility_and_retrieval_reason: Option<&str>,
    retrieval: &RetrievalSection,
    delivery: &DeliverySection,
    activation: &ActivationSection,
    adherence: &AdherenceSection,
    conflicts_suppression_or_compaction_loss: &[ArtifactId],
    downstream_refs: &[ArtifactId],
    receipt_completeness_and_missing_fields: &[String],
    invalidation_expiry_and_missingness: &[String],
) -> Result<HarnessActivationReceiptCandidate, ActivationAssessmentError> {
    let input = AssessmentInput {
        binding,
        target,
        view,
        recipe,
        delta,
        overlay,
        activation_id,
        admission_receipt,
        activation_request_receipt,
        assessment_receipt,
        stages,
        metrics,
        attrition,
        confounders,
        independent_evaluator_receipt,
        dimensions,
        external_review_refs,
        policy,
        compiled_view_ref,
        context_compiler_revision,
        render_profile_revision,
        stable_harness_refs,
        task_family_harness_refs,
        skill_refs,
        memory_refs,
        procedure_refs,
        preserved_success_ref,
        eligibility_and_retrieval_reason,
        retrieval,
        delivery,
        activation,
        adherence,
        conflicts_suppression_or_compaction_loss,
        downstream_refs,
        receipt_completeness_and_missing_fields,
        invalidation_expiry_and_missingness,
    };
    match assess_learning_activation(&input)? {
        AssessmentResultOrIncomplete::Candidate(result) => Ok(result.activation),
        AssessmentResultOrIncomplete::Incomplete(_) => {
            Err(ActivationAssessmentError::LineageMismatch {
                field: "activation.mandatory_ids",
            })
        }
    }
}

/// Attempt-close production path: store the derived delta, then emit the
/// activation receipt candidate.
///
/// This is the Governor-side composition the Task-Controller attempt-close
/// path calls with the evidence already available at close: the derived
/// `outcome` plus owner identity for [`store_derived_delta`], and the compiled
/// view/delta/overlay refs with compiler/delivery/observability evidence for
/// [`emit_activation_receipt_at_attempt_close`]. Both outputs stay
/// candidate-only; neither grants authority, schedules work, or promotes a
/// delta (I12.24 l224). Retrieval, delivery, activation, adherence and
/// outcome remain orthogonal fields, not a success ladder (I12.24 l256).
#[allow(clippy::too_many_arguments)]
pub fn close_attempt_with_activation_receipt(
    outcome: &AttemptLearningOutcome,
    identity: &StoredDeltaIdentity,
    retry_relation: Option<StoredRetryRelation>,
    binding: &ContractBinding,
    target: &TargetId,
    view: &CampaignLearningStateView,
    recipe: &LearningStateViewRecipe,
    delta: &AttemptLearningDeltaCandidate,
    overlay: &CampaignHarnessOverlayCandidate,
    activation_id: Option<&ArtifactId>,
    admission_receipt: Option<&ArtifactId>,
    activation_request_receipt: Option<&ArtifactId>,
    assessment_receipt: Option<&ArtifactId>,
    stages: &[StageObservation],
    metrics: &[MetricObservation],
    attrition: &[ArtifactId],
    confounders: &[ArtifactId],
    independent_evaluator_receipt: Option<&ArtifactId>,
    dimensions: &[DimensionAssessment],
    external_review_refs: &[ArtifactId],
    policy: &AssessmentPolicy,
    compiled_view_ref: &ArtifactId,
    context_compiler_revision: &str,
    render_profile_revision: &str,
    stable_harness_refs: &[ArtifactId],
    task_family_harness_refs: &[ArtifactId],
    skill_refs: &[ArtifactId],
    memory_refs: &[ArtifactId],
    procedure_refs: &[ArtifactId],
    preserved_success_ref: Option<&ArtifactId>,
    eligibility_and_retrieval_reason: Option<&str>,
    retrieval: &RetrievalSection,
    delivery: &DeliverySection,
    activation: &ActivationSection,
    adherence: &AdherenceSection,
    conflicts_suppression_or_compaction_loss: &[ArtifactId],
    downstream_refs: &[ArtifactId],
    receipt_completeness_and_missing_fields: &[String],
    invalidation_expiry_and_missingness: &[String],
) -> Result<(StoredLearningDelta, HarnessActivationReceiptCandidate), AttemptCloseError> {
    let stored = store_derived_delta(outcome, identity, retry_relation)?;
    let receipt = emit_activation_receipt_at_attempt_close(
        binding,
        target,
        view,
        recipe,
        delta,
        overlay,
        activation_id,
        admission_receipt,
        activation_request_receipt,
        assessment_receipt,
        stages,
        metrics,
        attrition,
        confounders,
        independent_evaluator_receipt,
        dimensions,
        external_review_refs,
        policy,
        compiled_view_ref,
        context_compiler_revision,
        render_profile_revision,
        stable_harness_refs,
        task_family_harness_refs,
        skill_refs,
        memory_refs,
        procedure_refs,
        preserved_success_ref,
        eligibility_and_retrieval_reason,
        retrieval,
        delivery,
        activation,
        adherence,
        conflicts_suppression_or_compaction_loss,
        downstream_refs,
        receipt_completeness_and_missing_fields,
        invalidation_expiry_and_missingness,
    )?;
    Ok((stored, receipt))
}
