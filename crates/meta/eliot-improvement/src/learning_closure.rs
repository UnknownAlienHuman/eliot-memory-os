//! Evidence-bound campaign learning closure candidate assembly.
//!
//! Stateless, zero-effect candidate owner for `meta.learning.closure`
//! (Meta/C1/R7). Assembles one [`CampaignLearningClosureCandidate`] from
//! exact campaign/attempt/delta/overlay-activation/outcome/harm/economics
//! evidence and states the strongest justified externally reviewable
//! disposition. Never performs promotion, activation, publication, rollback,
//! retirement, mutation, or task Finish.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Canonical module identity (mirrors `learning-closure.module.toml`).
pub const MODULE_ID: &str = "meta.learning.closure";
/// Source layer for this cell.
pub const SOURCE_LAYER: &str = "C1";
/// Runtime layer for this cell.
pub const RUNTIME_LAYER: &str = "R7";
/// Product pulse observed by this cell (evidence only, never emitted).
pub const PRODUCT_PULSE: &str = "ONLINE_LEARNING_INNER_LOOP_PULSE_01";
/// Causal property owned by this cell.
pub const CAUSAL_PROPERTY: &str = "campaign learning closure candidate";
/// Schema versions accepted by [`ClosurePolicy::validate`].
pub const SUPPORTED_SCHEMA_VERSIONS: &[u32] = &[1];

/// Exact campaign, target, task, scope, fence, objective and evaluator identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignAndTarget {
    pub campaign_id: String,
    pub target_id: String,
    pub task_id: String,
    pub scope_ref: String,
    pub fence_ref: String,
    pub objective_ref: String,
    pub acceptance_ref: String,
    pub evaluator_id: String,
    pub holdout_ref: String,
}

/// Availability of a single attempt record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttemptStatus {
    Available,
    Partial { reason: String },
    Stale { reason: String },
    Unavailable { reason: String },
    Cancelled { reason: String },
}

/// Delta payload: either a state change or an evidence-backed no-change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaKind {
    Changed {
        before_ref: String,
        after_ref: String,
    },
    NoChange {
        evidence_ref: Option<String>,
    },
}

/// Exact delta bound to one attempt and target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptDelta {
    pub delta_id: String,
    pub attempt_id: String,
    pub target_id: String,
    pub base_state_ref: String,
    pub stale_base: bool,
    pub kind: DeltaKind,
}

/// One attempt with its outcome slot and delta slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub attempt_id: String,
    pub consequential: bool,
    pub non_consequential_reason: Option<String>,
    pub status: AttemptStatus,
    pub has_outcome: bool,
    pub delta: Option<AttemptDelta>,
}

/// Exact attempt denominator: expected ids plus supplied records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptOutcomesAndDeltas {
    pub expected_attempt_ids: Vec<String>,
    pub attempts: Vec<AttemptRecord>,
}

/// Admission/retention state of one overlay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionState {
    Admitted,
    Unadmitted,
    Expired,
    Conflicted,
    RolledBack,
}

/// Exact overlay with admission lineage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayRecord {
    pub overlay_id: String,
    pub attempt_id: String,
    pub base_ref: String,
    pub parent_ref: String,
    pub admission: AdmissionState,
    pub admission_ref: String,
}

/// Canonical A-36 lifecycle stages. Delivery/ack/visibility/selection/
/// adherence/use/action/outcome/benefit/causality are independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStage {
    Delivery,
    Ack,
    Visibility,
    Selection,
    Adherence,
    Use,
    Action,
    Outcome,
    Benefit,
    Causality,
}

impl LifecycleStage {
    /// Every canonical stage, in lifecycle order.
    pub fn all() -> &'static [Self] {
        &[
            Self::Delivery,
            Self::Ack,
            Self::Visibility,
            Self::Selection,
            Self::Adherence,
            Self::Use,
            Self::Action,
            Self::Outcome,
            Self::Benefit,
            Self::Causality,
        ]
    }
}

/// Who produced one stage assessment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceSource {
    IndependentVerifier { verifier_id: String },
    SelfReport { reporter: String },
}

impl EvidenceSource {
    pub fn is_independent(&self) -> bool {
        matches!(self, Self::IndependentVerifier { .. })
    }
}

/// One stage assessment for one attempt/overlay pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageAssessment {
    pub attempt_id: String,
    pub overlay_id: String,
    pub stage: LifecycleStage,
    pub observed: bool,
    pub evidence_ref: Option<String>,
    pub use_linked: bool,
    pub causally_attributed: bool,
    pub source: EvidenceSource,
}

/// Overlay plus activation assessments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayAndActivationAssessments {
    pub overlays: Vec<OverlayRecord>,
    pub assessments: Vec<StageAssessment>,
}

/// Observed outcome shape for one attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutcomeKind {
    Positive,
    Negative,
    Mixed,
    Unchanged,
    Harmful,
    NoEvent,
    Unmeasured,
    Inconclusive,
}

/// Harm accounting for one attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarmRecord {
    pub harm_observed: bool,
    pub harm_ref: Option<String>,
}

/// Causal standing of a benefit claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CausalAttribution {
    Attributed { control_ref: String },
    CorrelationalOnly,
    None,
}

/// One outcome with metric identity, comparison, linkage and causal standing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeRecord {
    pub attempt_id: String,
    pub metric: String,
    pub unit: String,
    pub population: String,
    pub window: String,
    pub source_id: String,
    pub evaluator_id: String,
    pub baseline_ref: String,
    pub control_ref: Option<String>,
    pub kind: OutcomeKind,
    pub harm: HarmRecord,
    pub use_linked: bool,
    pub causal: CausalAttribution,
}

/// Bounded economics evidence for one attempt. Unknown is never zero.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EconomicsRecord {
    pub attempt_id: String,
    pub cost_known: bool,
    pub cost: f64,
    pub currency: String,
    pub unit: String,
}

/// Outcome, harm and economics evidence bundle.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutcomeHarmAndEconomicsEvidence {
    pub outcomes: Vec<OutcomeRecord>,
    pub economics: Vec<EconomicsRecord>,
}

/// One prior closure bound as history only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorClosure {
    pub closure_id: String,
    pub campaign_id: String,
    pub digest: String,
    pub superseded: bool,
}

/// Prior closure history (never re-decided here).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorClosureHistory {
    pub prior: Vec<PriorClosure>,
}

/// Policy governing closure assembly. No clock, I/O or live query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosurePolicy {
    pub schema_version: u32,
    pub allow_checkpoint: bool,
    pub max_attempts: usize,
    pub max_bytes: u64,
    pub require_independent_verifier: bool,
    pub external_owner_id: String,
    pub rollback_owner_id: String,
    pub idempotency_key: String,
    pub operation_ref: String,
}

impl ClosurePolicy {
    fn validate(&self) -> Result<(), LearningClosureError> {
        if !SUPPORTED_SCHEMA_VERSIONS.contains(&self.schema_version) {
            return Err(LearningClosureError::UnsupportedSchema {
                version: self.schema_version,
            });
        }
        non_empty(&self.external_owner_id, "external_owner_id")?;
        non_empty(&self.rollback_owner_id, "rollback_owner_id")?;
        non_empty(&self.idempotency_key, "idempotency_key")?;
        non_empty(&self.operation_ref, "operation_ref")?;
        if self.max_attempts == 0 {
            return Err(LearningClosureError::BoundExceeded {
                detail: "max_attempts must be nonzero".to_string(),
            });
        }
        Ok(())
    }
}

/// Terminal or checkpoint closure standing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClosureStatus {
    ClosedTaskLocal,
    Checkpoint,
    OpenDebt,
    NoReusableDelta,
    DelayedDebt,
}

/// External handoff: names the real decision owner, never a permit/write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalHandoff {
    pub external_owner_id: String,
    pub requested_class: String,
    pub evidence_ref: String,
    pub approval_fence_ref: String,
    pub rollback_owner_id: String,
    pub disable_owner_id: String,
    pub reopen_owner_id: String,
    pub expiry_ref: String,
    pub active_permit: Option<String>,
    pub promotion_receipt: Option<String>,
}

impl ExternalHandoff {
    fn validate(&self) -> Result<(), LearningClosureError> {
        non_empty(&self.external_owner_id, "external_owner_id")?;
        non_empty(&self.requested_class, "requested_class")?;
        if self.active_permit.is_some() || self.promotion_receipt.is_some() {
            return Err(LearningClosureError::PromotionOutputForbidden);
        }
        Ok(())
    }
}

/// Denominator accounting preserved on every candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenominatorAccounting {
    pub expected_attempts: usize,
    pub supplied_attempts: usize,
    pub consequential_attempts: usize,
    pub non_consequential_attempts: usize,
    pub delta_count: usize,
    pub overlay_count: usize,
    pub stage_count: usize,
    pub outcome_count: usize,
    pub economics_count: usize,
}

/// Evidence-bound closure candidate. Candidate only: no promotion, write,
/// effect, permit, lease, retirement execution, or Finish.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignLearningClosureCandidate {
    pub candidate_id: String,
    pub campaign_id: String,
    pub target_id: String,
    pub operation_ref: String,
    pub idempotency_key: String,
    pub status: ClosureStatus,
    pub denominators: DenominatorAccounting,
    pub digest: String,
    pub missing_evidence: Vec<String>,
    pub open_debt: Vec<String>,
    pub conflicts: Vec<String>,
    pub handoff: ExternalHandoff,
    pub proof_ceiling: String,
}

/// Bounded further-evidence disposition (never a fabricated closure).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearningClosureDisposition {
    pub disposition: String,
    pub missing_evidence: Vec<String>,
    pub missing_owner: Option<String>,
    pub open_debt: Vec<String>,
    pub retain_ref: String,
}

/// Assembly output: either a candidate or a bounded disposition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClosureAssembly {
    Candidate(Box<CampaignLearningClosureCandidate>),
    Disposition(LearningClosureDisposition),
}

/// Typed closure failures. No generic campaign-complete flag.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LearningClosureError {
    #[error("required field is missing: {0}")]
    MissingField(&'static str),
    #[error("unsupported schema version: {version}")]
    UnsupportedSchema { version: u32 },
    #[error("duplicate record for id: {id}")]
    DuplicateRecord { id: String },
    #[error("conflicting same-ID records for id: {id}")]
    ConflictingRecord { id: String },
    #[error("evidence-free NoChange is rejected for delta: {delta_id}")]
    EvidenceFreeNoChange { delta_id: String },
    #[error("stale base for delta: {delta_id}")]
    StaleDelta { delta_id: String },
    #[error("wrong-target delta: {delta_id}")]
    WrongTargetDelta { delta_id: String },
    #[error("identity mismatch: {detail}")]
    IdentityMismatch { detail: String },
    #[error("lineage failure: {detail}")]
    LineageFailure { detail: String },
    #[error("bound exceeded: {detail}")]
    BoundExceeded { detail: String },
    #[error("malformed input is rejected without panic: {detail}")]
    Malformed { detail: String },
    #[error("closure candidates never carry promotion output")]
    PromotionOutputForbidden,
}

/// Assemble one evidence-bound closure candidate.
///
/// Pure function of its six inputs: no ambient clock, I/O, or live query.
/// Returns a [`ClosureAssembly::Candidate`] when the exact denominator is
/// complete and justified, a [`ClosureAssembly::Disposition`] when bounded
/// further evidence/retention/debt applies, or a [`LearningClosureError`]
/// for typed schema/identity/evidence/lineage/bound failures.
pub fn assemble_campaign_learning_closure(
    exact_campaign_and_target: CampaignAndTarget,
    exact_attempt_outcomes_and_deltas: AttemptOutcomesAndDeltas,
    exact_overlay_and_activation_assessments: OverlayAndActivationAssessments,
    exact_outcome_harm_and_economics_evidence: OutcomeHarmAndEconomicsEvidence,
    prior_closure_history: PriorClosureHistory,
    closure_policy: ClosurePolicy,
) -> Result<ClosureAssembly, LearningClosureError> {
    validate_campaign(&exact_campaign_and_target)?;
    closure_policy.validate()?;
    validate_bounds(
        &exact_attempt_outcomes_and_deltas,
        &exact_overlay_and_activation_assessments,
        &closure_policy,
    )?;
    check_duplicate_attempts(&exact_attempt_outcomes_and_deltas)?;
    check_duplicate_overlays(&exact_overlay_and_activation_assessments)?;
    validate_attempt_identities(
        &exact_attempt_outcomes_and_deltas,
        &exact_campaign_and_target,
    )?;
    validate_deltas(
        &exact_attempt_outcomes_and_deltas,
        &exact_campaign_and_target,
    )?;
    validate_overlay_lineage(&exact_overlay_and_activation_assessments)?;
    let denominators = account_denominators(
        &exact_attempt_outcomes_and_deltas,
        &exact_overlay_and_activation_assessments,
        &exact_outcome_harm_and_economics_evidence,
    );

    // Attempt denominator completeness (cases 6..8).
    if let Some(disposition) = check_attempt_denominator(
        &exact_campaign_and_target,
        &exact_attempt_outcomes_and_deltas,
        &closure_policy,
    )? {
        return Ok(ClosureAssembly::Disposition(disposition));
    }

    // Overlay retention states can never close task-local (case 13).
    if let Some(disposition) = check_overlay_retention(
        &exact_campaign_and_target,
        &exact_overlay_and_activation_assessments,
        &closure_policy,
    ) {
        return Ok(ClosureAssembly::Disposition(disposition));
    }

    // Stage/outcome/benefit/causality separation + self-report bar (14..20).
    if let Some(disposition) = check_stage_outcome_separation(
        &exact_campaign_and_target,
        &exact_attempt_outcomes_and_deltas,
        &exact_overlay_and_activation_assessments,
        &exact_outcome_harm_and_economics_evidence,
        &closure_policy,
    )? {
        return Ok(ClosureAssembly::Disposition(disposition));
    }

    // Economics unknown-is-not-zero gate (minimal for slice A; full in slice B).
    if let Some(disposition) = check_economics_known(
        &exact_campaign_and_target,
        &exact_outcome_harm_and_economics_evidence,
        &closure_policy,
    ) {
        return Ok(ClosureAssembly::Disposition(disposition));
    }

    let digest = closure_digest(
        &exact_campaign_and_target,
        &exact_attempt_outcomes_and_deltas,
        &exact_overlay_and_activation_assessments,
        &exact_outcome_harm_and_economics_evidence,
        &prior_closure_history,
        &closure_policy,
    );
    let handoff = ExternalHandoff {
        external_owner_id: closure_policy.external_owner_id.clone(),
        requested_class: "task-local-retention".to_string(),
        evidence_ref: exact_campaign_and_target.scope_ref.clone(),
        approval_fence_ref: exact_campaign_and_target.fence_ref.clone(),
        rollback_owner_id: closure_policy.rollback_owner_id.clone(),
        disable_owner_id: closure_policy.rollback_owner_id.clone(),
        reopen_owner_id: closure_policy.external_owner_id.clone(),
        expiry_ref: closure_policy.operation_ref.clone(),
        active_permit: None,
        promotion_receipt: None,
    };
    handoff.validate()?;
    Ok(ClosureAssembly::Candidate(Box::new(
        CampaignLearningClosureCandidate {
            candidate_id: format!(
                "closure-{}-{}",
                exact_campaign_and_target.campaign_id,
                &digest[..16]
            ),
            campaign_id: exact_campaign_and_target.campaign_id.clone(),
            target_id: exact_campaign_and_target.target_id.clone(),
            operation_ref: closure_policy.operation_ref.clone(),
            idempotency_key: closure_policy.idempotency_key.clone(),
            status: ClosureStatus::ClosedTaskLocal,
            denominators,
            digest,
            missing_evidence: Vec::new(),
            open_debt: Vec::new(),
            conflicts: Vec::new(),
            handoff,
            proof_ceiling: "module-proof-only".to_string(),
        },
    )))
}

fn non_empty(value: &str, field: &'static str) -> Result<(), LearningClosureError> {
    if value.trim().is_empty() {
        Err(LearningClosureError::MissingField(field))
    } else {
        Ok(())
    }
}

fn validate_campaign(campaign: &CampaignAndTarget) -> Result<(), LearningClosureError> {
    non_empty(&campaign.campaign_id, "campaign_id")?;
    non_empty(&campaign.target_id, "target_id")?;
    non_empty(&campaign.task_id, "task_id")?;
    non_empty(&campaign.scope_ref, "scope_ref")?;
    non_empty(&campaign.fence_ref, "fence_ref")?;
    non_empty(&campaign.objective_ref, "objective_ref")?;
    non_empty(&campaign.acceptance_ref, "acceptance_ref")?;
    non_empty(&campaign.evaluator_id, "evaluator_id")?;
    non_empty(&campaign.holdout_ref, "holdout_ref")?;
    Ok(())
}

fn validate_bounds(
    attempts: &AttemptOutcomesAndDeltas,
    overlays: &OverlayAndActivationAssessments,
    policy: &ClosurePolicy,
) -> Result<(), LearningClosureError> {
    if attempts.attempts.len() > policy.max_attempts
        || attempts.expected_attempt_ids.len() > policy.max_attempts
    {
        return Err(LearningClosureError::BoundExceeded {
            detail: "attempt count exceeds max_attempts".to_string(),
        });
    }
    let approx_bytes =
        (attempts.attempts.len() + overlays.overlays.len() + overlays.assessments.len()) as u64
            * 256;
    if approx_bytes > policy.max_bytes {
        return Err(LearningClosureError::BoundExceeded {
            detail: "estimated byte bound exceeded".to_string(),
        });
    }
    for id in &attempts.expected_attempt_ids {
        if id.trim().is_empty() || id.len() > 256 {
            return Err(LearningClosureError::Malformed {
                detail: format!("expected attempt id malformed: {id:?}"),
            });
        }
    }
    Ok(())
}

fn check_duplicate_attempts(
    attempts: &AttemptOutcomesAndDeltas,
) -> Result<(), LearningClosureError> {
    let mut seen: BTreeMap<&str, &AttemptRecord> = BTreeMap::new();
    for attempt in &attempts.attempts {
        if attempt.attempt_id.trim().is_empty() {
            return Err(LearningClosureError::MissingField("attempt_id"));
        }
        if let Some(first) = seen.get(attempt.attempt_id.as_str()) {
            if *first == attempt {
                return Err(LearningClosureError::DuplicateRecord {
                    id: attempt.attempt_id.clone(),
                });
            }
            return Err(LearningClosureError::ConflictingRecord {
                id: attempt.attempt_id.clone(),
            });
        }
        seen.insert(attempt.attempt_id.as_str(), attempt);
    }
    Ok(())
}

fn check_duplicate_overlays(
    overlays: &OverlayAndActivationAssessments,
) -> Result<(), LearningClosureError> {
    let mut seen: BTreeMap<&str, &OverlayRecord> = BTreeMap::new();
    for overlay in &overlays.overlays {
        if overlay.overlay_id.trim().is_empty() {
            return Err(LearningClosureError::MissingField("overlay_id"));
        }
        if let Some(first) = seen.get(overlay.overlay_id.as_str()) {
            if *first == overlay {
                return Err(LearningClosureError::DuplicateRecord {
                    id: overlay.overlay_id.clone(),
                });
            }
            return Err(LearningClosureError::ConflictingRecord {
                id: overlay.overlay_id.clone(),
            });
        }
        seen.insert(overlay.overlay_id.as_str(), overlay);
    }
    Ok(())
}

fn validate_attempt_identities(
    attempts: &AttemptOutcomesAndDeltas,
    campaign: &CampaignAndTarget,
) -> Result<(), LearningClosureError> {
    for attempt in &attempts.attempts {
        if !attempt.consequential && attempt.non_consequential_reason.is_none() {
            return Err(LearningClosureError::MissingField(
                "non_consequential_reason",
            ));
        }
        if let Some(delta) = &attempt.delta
            && delta.attempt_id != attempt.attempt_id
        {
            return Err(LearningClosureError::IdentityMismatch {
                detail: format!(
                    "delta {} not bound to attempt {}",
                    delta.delta_id, attempt.attempt_id
                ),
            });
        }
        let _ = campaign;
    }
    Ok(())
}

fn validate_deltas(
    attempts: &AttemptOutcomesAndDeltas,
    campaign: &CampaignAndTarget,
) -> Result<(), LearningClosureError> {
    for attempt in &attempts.attempts {
        let Some(delta) = &attempt.delta else {
            continue;
        };
        if delta.delta_id.trim().is_empty() {
            return Err(LearningClosureError::MissingField("delta_id"));
        }
        if delta.target_id != campaign.target_id {
            return Err(LearningClosureError::WrongTargetDelta {
                delta_id: delta.delta_id.clone(),
            });
        }
        if delta.stale_base {
            return Err(LearningClosureError::StaleDelta {
                delta_id: delta.delta_id.clone(),
            });
        }
        if let DeltaKind::NoChange { evidence_ref } = &delta.kind
            && evidence_ref
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(LearningClosureError::EvidenceFreeNoChange {
                delta_id: delta.delta_id.clone(),
            });
        }
    }
    Ok(())
}

fn validate_overlay_lineage(
    overlays: &OverlayAndActivationAssessments,
) -> Result<(), LearningClosureError> {
    for overlay in &overlays.overlays {
        non_empty(&overlay.base_ref, "base_ref")?;
        non_empty(&overlay.parent_ref, "parent_ref")?;
        non_empty(&overlay.admission_ref, "admission_ref")?;
        if overlay.attempt_id.trim().is_empty() {
            return Err(LearningClosureError::MissingField("attempt_id"));
        }
    }
    for assessment in &overlays.assessments {
        if assessment.attempt_id.trim().is_empty() || assessment.overlay_id.trim().is_empty() {
            return Err(LearningClosureError::MissingField("assessment_binding"));
        }
        if assessment.observed
            && assessment
                .evidence_ref
                .as_deref()
                .is_none_or(|v| v.trim().is_empty())
        {
            return Err(LearningClosureError::LineageFailure {
                detail: format!(
                    "observed stage {:?} for attempt {} lacks evidence",
                    assessment.stage, assessment.attempt_id
                ),
            });
        }
    }
    Ok(())
}

fn account_denominators(
    attempts: &AttemptOutcomesAndDeltas,
    overlays: &OverlayAndActivationAssessments,
    evidence: &OutcomeHarmAndEconomicsEvidence,
) -> DenominatorAccounting {
    DenominatorAccounting {
        expected_attempts: attempts.expected_attempt_ids.len(),
        supplied_attempts: attempts.attempts.len(),
        consequential_attempts: attempts.attempts.iter().filter(|a| a.consequential).count(),
        non_consequential_attempts: attempts
            .attempts
            .iter()
            .filter(|a| !a.consequential)
            .count(),
        delta_count: attempts
            .attempts
            .iter()
            .filter(|a| a.delta.is_some())
            .count(),
        overlay_count: overlays.overlays.len(),
        stage_count: overlays.assessments.len(),
        outcome_count: evidence.outcomes.len(),
        economics_count: evidence.economics.len(),
    }
}

fn check_attempt_denominator(
    campaign: &CampaignAndTarget,
    attempts: &AttemptOutcomesAndDeltas,
    policy: &ClosurePolicy,
) -> Result<Option<LearningClosureDisposition>, LearningClosureError> {
    let expected: BTreeSet<&str> = attempts
        .expected_attempt_ids
        .iter()
        .map(String::as_str)
        .collect();
    let supplied: BTreeSet<&str> = attempts
        .attempts
        .iter()
        .map(|a| a.attempt_id.as_str())
        .collect();
    let missing: Vec<String> = expected
        .difference(&supplied)
        .map(ToString::to_string)
        .collect();
    // Incomplete availability states always need bounded follow-up.
    let mut partial: Vec<String> = Vec::new();
    for attempt in &attempts.attempts {
        match &attempt.status {
            AttemptStatus::Available => {
                if !attempt.has_outcome || attempt.delta.is_none() {
                    partial.push(format!(
                        "attempt {} missing outcome/delta",
                        attempt.attempt_id
                    ));
                }
            }
            AttemptStatus::Partial { reason }
            | AttemptStatus::Stale { reason }
            | AttemptStatus::Unavailable { reason }
            | AttemptStatus::Cancelled { reason } => {
                partial.push(format!(
                    "attempt {} {}: {reason}",
                    attempt.attempt_id,
                    status_label(&attempt.status)
                ));
            }
        }
    }
    if !missing.is_empty() || !partial.is_empty() {
        let mut absent = missing;
        absent.extend(partial);
        return Ok(Some(LearningClosureDisposition {
            disposition: "continue-collect".to_string(),
            missing_evidence: absent,
            missing_owner: Some(campaign.evaluator_id.clone()),
            open_debt: vec![format!(
                "campaign {} denominator incomplete",
                campaign.campaign_id
            )],
            retain_ref: campaign.scope_ref.clone(),
        }));
    }
    let _ = policy;
    Ok(None)
}

fn status_label(status: &AttemptStatus) -> &'static str {
    match status {
        AttemptStatus::Available => "available",
        AttemptStatus::Partial { .. } => "partial",
        AttemptStatus::Stale { .. } => "stale",
        AttemptStatus::Unavailable { .. } => "unavailable",
        AttemptStatus::Cancelled { .. } => "cancelled",
    }
}

fn check_overlay_retention(
    campaign: &CampaignAndTarget,
    overlays: &OverlayAndActivationAssessments,
    _policy: &ClosurePolicy,
) -> Option<LearningClosureDisposition> {
    let retained: Vec<String> = overlays
        .overlays
        .iter()
        .filter(|o| !matches!(o.admission, AdmissionState::Admitted))
        .map(|o| format!("overlay {} {:?}", o.overlay_id, o.admission))
        .collect();
    if retained.is_empty() {
        return None;
    }
    Some(LearningClosureDisposition {
        disposition: "task-local-retain".to_string(),
        missing_evidence: retained.clone(),
        missing_owner: Some(campaign.evaluator_id.clone()),
        open_debt: retained,
        retain_ref: campaign.scope_ref.clone(),
    })
}

fn check_stage_outcome_separation(
    campaign: &CampaignAndTarget,
    attempts: &AttemptOutcomesAndDeltas,
    overlays: &OverlayAndActivationAssessments,
    evidence: &OutcomeHarmAndEconomicsEvidence,
    policy: &ClosurePolicy,
) -> Result<Option<LearningClosureDisposition>, LearningClosureError> {
    // Index observed stages per attempt.
    let mut observed_by_attempt: BTreeMap<&str, BTreeSet<LifecycleStage>> = BTreeMap::new();
    let mut evidence_by_key: BTreeMap<(&str, LifecycleStage), &StageAssessment> = BTreeMap::new();
    for assessment in &overlays.assessments {
        evidence_by_key.insert(
            (assessment.attempt_id.as_str(), assessment.stage),
            assessment,
        );
        if assessment.observed {
            observed_by_attempt
                .entry(assessment.attempt_id.as_str())
                .or_default()
                .insert(assessment.stage);
        }
        if policy.require_independent_verifier
            && assessment.observed
            && !assessment.source.is_independent()
            && matches!(
                assessment.stage,
                LifecycleStage::Outcome | LifecycleStage::Benefit | LifecycleStage::Causality
            )
        {
            return Ok(Some(self_report_disposition(campaign, assessment)));
        }
    }
    // Any self-reported outcome/benefit/causality without independent backing
    // is insufficient even when the policy flag is off: it can only dispose,
    // never close.
    for assessment in &overlays.assessments {
        if assessment.observed
            && !assessment.source.is_independent()
            && matches!(
                assessment.stage,
                LifecycleStage::Outcome | LifecycleStage::Benefit | LifecycleStage::Causality
            )
            && !has_independent_cover(
                evidence_by_key.get(&(assessment.attempt_id.as_str(), assessment.stage)),
            )
        {
            return Ok(Some(self_report_disposition(campaign, assessment)));
        }
    }

    for attempt in &attempts.attempts {
        if !attempt.consequential {
            continue;
        }
        let observed = observed_by_attempt.get(attempt.attempt_id.as_str());
        let has = |stage: LifecycleStage| observed.is_some_and(|set| set.contains(&stage));
        // No inference across stages: each gap names exact missing evidence.
        if has(LifecycleStage::Delivery) && !has(LifecycleStage::Use) {
            return Ok(Some(stage_gap_disposition(
                campaign,
                attempt,
                "delivery-without-use",
            )));
        }
        if (has(LifecycleStage::Visibility) || has(LifecycleStage::Selection))
            && !(has(LifecycleStage::Adherence) && has(LifecycleStage::Use))
        {
            return Ok(Some(stage_gap_disposition(
                campaign,
                attempt,
                "visibility-selection-without-adherence-use",
            )));
        }
        if has(LifecycleStage::Use) && !use_has_outcome_link(attempt, overlays, evidence) {
            return Ok(Some(stage_gap_disposition(
                campaign,
                attempt,
                "use-without-outcome-linkage",
            )));
        }
        if outcome_without_use(attempt, overlays, evidence) {
            return Ok(Some(stage_gap_disposition(
                campaign,
                attempt,
                "outcome-without-proven-use",
            )));
        }
        if benefit_without_causal(attempt, overlays, evidence) {
            return Ok(Some(stage_gap_disposition(
                campaign,
                attempt,
                "benefit-without-causal-attribution",
            )));
        }
    }
    Ok(None)
}

fn has_independent_cover(assessment: Option<&&StageAssessment>) -> bool {
    assessment.is_some_and(|a| a.source.is_independent())
}

fn self_report_disposition(
    campaign: &CampaignAndTarget,
    assessment: &StageAssessment,
) -> LearningClosureDisposition {
    LearningClosureDisposition {
        disposition: "inconclusive".to_string(),
        missing_evidence: vec![format!(
            "attempt {} stage {:?} needs independent verifier, self-report insufficient",
            assessment.attempt_id, assessment.stage
        )],
        missing_owner: Some(campaign.evaluator_id.clone()),
        open_debt: vec!["independent outcome verification".to_string()],
        retain_ref: campaign.scope_ref.clone(),
    }
}

fn stage_gap_disposition(
    campaign: &CampaignAndTarget,
    attempt: &AttemptRecord,
    gap: &str,
) -> LearningClosureDisposition {
    LearningClosureDisposition {
        disposition: "inconclusive".to_string(),
        missing_evidence: vec![format!("attempt {} {gap}", attempt.attempt_id)],
        missing_owner: Some(campaign.evaluator_id.clone()),
        open_debt: vec![format!("stage gap {gap}")],
        retain_ref: campaign.scope_ref.clone(),
    }
}

fn use_has_outcome_link(
    attempt: &AttemptRecord,
    overlays: &OverlayAndActivationAssessments,
    evidence: &OutcomeHarmAndEconomicsEvidence,
) -> bool {
    let use_observed = overlays.assessments.iter().any(|a| {
        a.attempt_id == attempt.attempt_id && a.stage == LifecycleStage::Use && a.observed
    });
    if !use_observed {
        return true;
    }
    overlays.assessments.iter().any(|a| {
        a.attempt_id == attempt.attempt_id
            && matches!(a.stage, LifecycleStage::Outcome | LifecycleStage::Benefit)
            && a.observed
            && a.use_linked
    }) && evidence.outcomes.iter().any(|o| {
        o.attempt_id == attempt.attempt_id && o.use_linked && o.kind != OutcomeKind::Unmeasured
    })
}

fn outcome_without_use(
    attempt: &AttemptRecord,
    overlays: &OverlayAndActivationAssessments,
    evidence: &OutcomeHarmAndEconomicsEvidence,
) -> bool {
    let outcome_claimed = overlays.assessments.iter().any(|a| {
        a.attempt_id == attempt.attempt_id && a.stage == LifecycleStage::Outcome && a.observed
    }) || evidence
        .outcomes
        .iter()
        .any(|o| o.attempt_id == attempt.attempt_id && o.kind != OutcomeKind::Unmeasured);
    if !outcome_claimed {
        return false;
    }
    !overlays
        .assessments
        .iter()
        .any(|a| a.attempt_id == attempt.attempt_id && a.stage == LifecycleStage::Use && a.observed)
}

fn benefit_without_causal(
    attempt: &AttemptRecord,
    overlays: &OverlayAndActivationAssessments,
    evidence: &OutcomeHarmAndEconomicsEvidence,
) -> bool {
    let benefit_claimed = overlays.assessments.iter().any(|a| {
        a.attempt_id == attempt.attempt_id && a.stage == LifecycleStage::Benefit && a.observed
    });
    if !benefit_claimed {
        return false;
    }
    let causal_ok = overlays.assessments.iter().any(|a| {
        a.attempt_id == attempt.attempt_id
            && a.stage == LifecycleStage::Causality
            && a.observed
            && a.causally_attributed
    }) && evidence.outcomes.iter().any(|o| {
        o.attempt_id == attempt.attempt_id
            && matches!(o.causal, CausalAttribution::Attributed { .. })
    });
    !causal_ok
}

fn check_economics_known(
    campaign: &CampaignAndTarget,
    evidence: &OutcomeHarmAndEconomicsEvidence,
    _policy: &ClosurePolicy,
) -> Option<LearningClosureDisposition> {
    let unknown: Vec<String> = evidence
        .economics
        .iter()
        .filter(|e| !e.cost_known)
        .map(|e| format!("attempt {} unknown cost is not zero", e.attempt_id))
        .collect();
    if unknown.is_empty() {
        return None;
    }
    Some(LearningClosureDisposition {
        disposition: "continue-collect".to_string(),
        missing_evidence: unknown.clone(),
        missing_owner: Some(campaign.evaluator_id.clone()),
        open_debt: unknown,
        retain_ref: campaign.scope_ref.clone(),
    })
}

fn closure_digest(
    campaign: &CampaignAndTarget,
    attempts: &AttemptOutcomesAndDeltas,
    overlays: &OverlayAndActivationAssessments,
    evidence: &OutcomeHarmAndEconomicsEvidence,
    history: &PriorClosureHistory,
    policy: &ClosurePolicy,
) -> String {
    let mut hasher = Hasher::new();
    hasher.update(campaign.campaign_id.as_bytes());
    hasher.update(campaign.target_id.as_bytes());
    hasher.update(campaign.task_id.as_bytes());
    hasher.update(campaign.scope_ref.as_bytes());
    for attempt in &attempts.attempts {
        hasher.update(attempt.attempt_id.as_bytes());
        if let Some(delta) = &attempt.delta {
            hasher.update(delta.delta_id.as_bytes());
            hasher.update(delta.base_state_ref.as_bytes());
        }
    }
    for overlay in &overlays.overlays {
        hasher.update(overlay.overlay_id.as_bytes());
        hasher.update(overlay.admission_ref.as_bytes());
    }
    for assessment in &overlays.assessments {
        hasher.update(assessment.attempt_id.as_bytes());
        hasher.update(format!("{:?}", assessment.stage).as_bytes());
    }
    for outcome in &evidence.outcomes {
        hasher.update(outcome.attempt_id.as_bytes());
        hasher.update(outcome.metric.as_bytes());
    }
    for prior in &history.prior {
        hasher.update(prior.digest.as_bytes());
    }
    hasher.update(policy.idempotency_key.as_bytes());
    hasher.finalize().to_hex().to_string()
}
