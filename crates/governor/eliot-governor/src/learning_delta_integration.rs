//! Production caller wiring consequential learning-delta derivation to Governor admission.
//!
//! Derivation here is candidate-only: it proposes a durable stored record with
//! lineage, never a behavioral effect. The durable record carries the exact
//! prior observable digest forward to the next materially related attempt.
//! Delivery of any behavioral effect requires a verified Governor admission
//! issued for the stored delta (I12.24 line 179).
//!
//! Only the nine consequential boundaries derive; ordinary reads
//! (`read_file`/`grep`) are not consequential and never derive (line 181).

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
    AdmissionReceipt, AttemptCloseDisposition, AttemptEvidence, ConsequentialBoundary,
    DerivationContext, DerivationPolicy, LearningDeltaError, RefinerDraft, StoredDeltaDisposition,
    StoredLearningDelta, delivery_allowed, derive_attempt_learning_outcome,
};
use thiserror::Error;

use crate::Governor;
use crate::learning_admission::{
    LEARNING_ADMISSION_SCHEMA_VERSION, LearningAdmissionClaim, LearningAdmissionError,
    LearningAdmissionPermit, issue_learning_admission, verify_learning_admission,
};

/// Derive a candidate learning outcome only at a consequential boundary.
///
/// Fail-closed trigger rule (W1 trigger wiring, W2 boundary trigger, W3 read
/// exclusion): when `boundary` is `None` the caller observed no consequential
/// boundary (e.g. an ordinary `read_file`/`grep`) and this returns
/// `Err(LearningDeltaError::NonConsequential)` without invoking derivation.
/// When `boundary` is `Some`, the boundary was consequential and derivation
/// runs as candidate-only proposal; behavioral effect still needs admission.
pub fn derive_delta_at_boundary(
    state_view: &CampaignLearningStateView,
    evidence: &AttemptEvidence,
    context: &DerivationContext<'_>,
    draft: Option<&RefinerDraft>,
    policy: &DerivationPolicy,
    boundary: Option<ConsequentialBoundary>,
) -> Result<AttemptLearningOutcome, LearningDeltaError> {
    match boundary {
        None => Err(LearningDeltaError::NonConsequential),
        Some(_) => derive_attempt_learning_outcome(state_view, evidence, context, draft, policy),
    }
}

/// Build the validated durable stored record for a derived outcome.
///
/// W5 caller: every stored delta names its campaign, attempt, `StateFence`,
/// actor/route/overlay/artifact identity and disposition, enforced by
/// [`StoredLearningDelta::validate`]. A fresh `Delta` candidate is proposed
/// (`NEXT_PROBE_CHANGED`) and carries no admission receipt; a `NoChange`
/// outcome closes honestly as `NO_JUSTIFIED_CHANGE` via
/// [`AttemptCloseDisposition::as_stored`] instead of fabricating a behavioral
/// delta (W7). The optional prior id/digest preserves the explicit retry
/// relation (W4/A1).
#[allow(clippy::too_many_arguments)]
pub fn store_derived_delta(
    outcome: &AttemptLearningOutcome,
    campaign_id: CampaignId,
    attempt_id: AgentAttemptId,
    fence: StateFence,
    actor_id: &str,
    route_id: &str,
    overlay_id: OverlayId,
    prior: Option<(&ArtifactId, &str)>,
) -> Result<StoredLearningDelta, LearningDeltaError> {
    let (delta_artifact, delta_digest, disposition) = match outcome {
        AttemptLearningOutcome::Delta(candidate) => (
            candidate.delta_id.clone(),
            candidate.canonical_digest.clone(),
            StoredDeltaDisposition::NextProbeChanged,
        ),
        AttemptLearningOutcome::NoChange(disposition) => {
            // A close carries no candidate: bind the record to the lead
            // affirmative-evidence handle and the sealed no-change digest.
            let lead = disposition.affirmative_evidence.first().ok_or(
                LearningDeltaError::InvalidInput {
                    field: "stored.close_evidence",
                },
            )?;
            (
                lead.clone(),
                disposition.canonical_digest.clone(),
                AttemptCloseDisposition::NoJustifiedChange.as_stored(),
            )
        }
    };
    let record = StoredLearningDelta {
        campaign_id,
        attempt_id,
        state_fence: fence,
        actor_id: actor_id.to_owned(),
        route_id: route_id.to_owned(),
        overlay_id,
        delta_artifact,
        delta_digest,
        prior_delta_id: prior.map(|(id, _)| id.clone()),
        prior_delta_digest: prior.map(|(_, digest)| digest.to_owned()),
        disposition,
        admission_receipt_id: None,
    };
    record.validate()?;
    Ok(record)
}

/// Build the Governor admission claim bound to one stored delta.
///
/// W6 binding of one stored delta to Governor admission: the stored delta's
/// artifact id becomes the claim's candidate subject (`candidate_id`), so the
/// subsequent permit authorizes at most that exact candidate. Mint-time
/// trimming is handled by issuance; inputs are stored as given.
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
/// Admitted-only delivery (A4): returns `true` only when
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
/// verified admission receipt bound to the delta artifact and digest. Thin
/// wrapper over `delivery_allowed`.
pub fn delta_delivery_allowed(
    receipt: Option<&AdmissionReceipt>,
    delta: &StoredLearningDelta,
) -> bool {
    delivery_allowed(receipt, &delta.delta_artifact, &delta.delta_digest)
}

/// Canonical retry lineage referencing the durable delta.
///
/// Retry's canonical lineage references the durable delta (A1); the delta's
/// equivalent-retry/reason records equivalence (A2) and changed
/// hypothesis/strategy is recorded in candidate changes (A3). Lineage carries
/// the digest so the retry binds to the exact prior observable and evidence.
pub fn retry_lineage_for_delta(delta: &StoredLearningDelta) -> (&ArtifactId, &str) {
    delta.lineage_for_retry()
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
/// `outcome` plus identity for [`store_derived_delta`], and the compiled
/// view/delta/overlay refs with compiler/delivery/observability evidence for
/// [`emit_activation_receipt_at_attempt_close`]. Both outputs stay
/// candidate-only; neither grants authority, schedules work, or promotes a
/// delta (I12.24 l224). Retrieval, delivery, activation, adherence and
/// outcome remain orthogonal fields, not a success ladder (I12.24 l256).
#[allow(clippy::too_many_arguments)]
pub fn close_attempt_with_activation_receipt(
    outcome: &AttemptLearningOutcome,
    campaign_id: CampaignId,
    attempt_id: AgentAttemptId,
    fence: StateFence,
    actor_id: &str,
    route_id: &str,
    overlay_id: OverlayId,
    prior: Option<(&ArtifactId, &str)>,
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
    let stored = store_derived_delta(
        outcome,
        campaign_id,
        attempt_id,
        fence,
        actor_id,
        route_id,
        overlay_id,
        prior,
    )?;
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
