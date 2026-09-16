//! Advisory outer-loop promotion-input preparation.
//!
//! Stateless, zero-effect cell for `meta.improvement.promotion_input`
//! (Meta/C1/R7, agent_order 38). Prepares one advisory
//! [`PromotionInputCandidate`] from exact closure, improvement candidate and
//! immutable replay/holdout/transfer/retention/pulse/evaluator evidence plus
//! policy. Returns a candidate with gate report only when every mandatory
//! gate is complete at the requested scope; otherwise returns a bounded
//! rejected/incomplete/blocked/conflicted/narrowed disposition naming exact
//! missing evidence and owner. Never carries out a promotion, never changes
//! active generation, policy, or task state, and never issues a receipt.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Canonical module identity (mirrors `promotion.module.toml`).
pub const MODULE_ID: &str = "meta.improvement.promotion_input";
/// Source layer for this cell.
pub const SOURCE_LAYER: &str = "C1";
/// Runtime layer for this cell.
pub const RUNTIME_LAYER: &str = "R7";
/// Pulse observed as evidence only, never emitted.
pub const PRODUCT_PULSE: &str = "ONLINE_LEARNING_INNER_LOOP_PULSE_01";
/// Causal property owned by this cell.
pub const CAUSAL_PROPERTY: &str = "outer-loop promotion-input preparation";
/// Scheduling annotation from the module descriptor (not Self-Quality).
pub const AGENT_ORDER: u32 = 38;
/// Schema versions accepted by policy and evidence bindings.
pub const SUPPORTED_SCHEMA_VERSIONS: &[u32] = &[1];
/// Module proof ceiling; real edge/pulse proof stays separate.
pub const PROOF_CEILING: &str = "module-proof-only";
/// Privacy ceiling; diagnostics stay bounded and redacted.
pub const PRIVACY_CEILING: &str = "redacted-diagnostics-only";
/// Only effect class this cell may name.
pub const REQUESTED_EFFECT: &str = "advisory-only";
/// Diagnostics longer than this are truncated with a redaction marker.
pub const MAX_DIAGNOSTIC_LEN: usize = 256;
/// Durable identity limit for ids.
pub const MAX_ID_LEN: usize = 512;
/// Durable limit for free-form refs.
pub const MAX_REF_LEN: usize = 1024;

/// Exact request/operation/idempotency/candidate plus full identity bundle.
///
/// The request carries the intended identity; the candidate must match it
/// exactly. Any same-field divergence is an identity mismatch, never a merge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionRequest {
    pub request_id: String,
    pub operation_ref: String,
    pub idempotency_key: String,
    pub candidate_id: String,
    pub campaign_id: String,
    pub task_id: String,
    pub scope_ref: String,
    pub fence_ref: String,
    pub base_state_ref: String,
    pub product_id: String,
    pub source_id: String,
    pub artifact_ref: String,
    pub config_ref: String,
    pub stack_ref: String,
    pub platform_ref: String,
    pub environment_ref: String,
    pub objective_ref: String,
    pub acceptance_ref: String,
    pub evaluator_id: String,
    pub holdout_ref: String,
    pub cancelled: bool,
}

/// Immutable closure binding consumed as evidence only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureBinding {
    pub closure_id: String,
    pub campaign_id: String,
    pub digest: String,
    pub valid: bool,
    pub stale: bool,
    pub lineage_ref: String,
    pub schema_version: u32,
    pub revision: u64,
}

/// Improvement candidate proposed for advisory review.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionCandidate {
    pub candidate_id: String,
    pub campaign_id: String,
    pub task_id: String,
    pub scope_ref: String,
    pub fence_ref: String,
    pub base_state_ref: String,
    pub product_id: String,
    pub source_id: String,
    pub artifact_ref: String,
    pub config_ref: String,
    pub stack_ref: String,
    pub platform_ref: String,
    pub environment_ref: String,
    pub objective_ref: String,
    pub acceptance_ref: String,
    pub evaluator_id: String,
    pub holdout_ref: String,
    pub revision: u64,
    pub digest: String,
}

/// One lifecycle gate: observed with compatible, bound evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageGate {
    pub observed: bool,
    pub evidence_ref: Option<String>,
    pub compatible: bool,
    pub use_linked: bool,
}

/// Activation chain: delivery/visibility/selection/adherence/use/action/outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationGates {
    pub activation: StageGate,
    pub visibility: StageGate,
    pub selection: StageGate,
    pub adherence: StageGate,
    pub use_gate: StageGate,
    pub action: StageGate,
    pub outcome: StageGate,
}

/// Benefit claim with causal and comparison standing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenefitEvidence {
    pub benefit_observed: bool,
    pub benefit_ref: Option<String>,
    pub causally_attributed: bool,
    pub control_ref: Option<String>,
    pub comparison_valid: bool,
    pub independent: bool,
    pub use_linked: bool,
}

/// Member outcome kinds retained verbatim; never averaged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberOutcome {
    Positive,
    Negative,
    Mixed,
    Unchanged,
    Harmful,
    Conflicted,
    NoEvent,
}

/// One denominator member with harm accounting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarmMember {
    pub member_id: String,
    pub outcome: MemberOutcome,
    pub harm_observed: bool,
    pub harm_ref: Option<String>,
    pub source_id: String,
}

/// Fixed comparison with replay and holdout bindings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComparisonEvidence {
    pub comparison_ref: String,
    pub control_ref: Option<String>,
    pub replay_refs: Vec<String>,
    pub holdout_refs: Vec<String>,
    pub fixed: bool,
    pub valid: bool,
}

/// Retention over the declared period.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionEvidence {
    pub retention_ref: String,
    pub period_ref: String,
    pub period_complete: bool,
    pub observed: bool,
}

/// Transfer to the exact proposed applicability domain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferEvidence {
    pub transfer_refs: Vec<String>,
    pub tested_domain_ref: String,
    pub proposed_domain_ref: String,
    pub retention_bound: bool,
}

/// Pulse result: only Pass justifies a positive candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PulseResult {
    Pass,
    Regression { detail: String },
    Unknown { reason: String },
    Missing { reason: String },
}

/// Product pulse evidence; package-green never substitutes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductPulseEvidence {
    pub pulse_id: String,
    pub pulse_ref: Option<String>,
    pub result: PulseResult,
    pub package_green: bool,
}

/// Evaluator binding with freshness and independence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatorEvidence {
    pub evaluator_id: String,
    pub stack_ref: String,
    pub fresh: bool,
    pub stale: bool,
    pub independent: bool,
    pub source_id: String,
    pub schema_version: u32,
}

/// Bounded economics; unknown is never zero.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EconomicsEvidence {
    pub cost_known: bool,
    pub cost: f64,
    pub resources_known: bool,
    pub resources_ref: Option<String>,
    pub human_burden_known: bool,
    pub human_burden_ref: Option<String>,
    pub currency: String,
}

/// Rollback/disable/reopen with external owner and expiry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackEvidence {
    pub rollback_ref: Option<String>,
    pub disable_ref: Option<String>,
    pub reopen_ref: Option<String>,
    pub owner_id: String,
    pub expiry_ref: Option<String>,
}

/// Full gate evidence bundle with exact denominators.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PromotionGateEvidence {
    pub activation: ActivationGates,
    pub benefit: BenefitEvidence,
    pub harm_members: Vec<HarmMember>,
    pub comparison: ComparisonEvidence,
    pub retention: RetentionEvidence,
    pub transfer: TransferEvidence,
    pub pulse: ProductPulseEvidence,
    pub evaluator: EvaluatorEvidence,
    pub economics: EconomicsEvidence,
    pub rollback: RollbackEvidence,
    pub expected_member_ids: Vec<String>,
    pub expected_source_ids: Vec<String>,
    pub expected_period_refs: Vec<String>,
    pub expected_gate_ids: Vec<String>,
}

/// Policy governing preparation. No clock, I/O, or live query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionInputPolicy {
    pub schema_version: u32,
    pub max_members: usize,
    pub max_bytes: u64,
    pub max_gates: usize,
    pub external_owner_id: String,
    pub rollback_owner_id: String,
    pub operation_ref: String,
    pub idempotency_key: String,
    pub allow_narrowing: bool,
    pub proof_ceiling: String,
    pub privacy_ceiling: String,
    pub requested_effect: String,
    pub forbid_direct_promotion: bool,
    pub request_direct_promotion: bool,
    pub claimed_promotion_receipt: Option<String>,
}

/// One prior preparation bound as history only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorPromotion {
    pub input_id: String,
    pub candidate_id: String,
    pub digest: String,
    pub superseded: bool,
}

/// Prior history (never re-decided here).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorPromotionHistory {
    pub prior: Vec<PriorPromotion>,
}

/// Denominator accounting preserved on every advisory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionDenominators {
    pub expected_members: usize,
    pub supplied_members: usize,
    pub expected_sources: usize,
    pub supplied_sources: usize,
    pub expected_periods: usize,
    pub supplied_periods: usize,
    pub expected_gates: usize,
    pub supplied_gates: usize,
}

/// One gate line in the advisory report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    pub gate: String,
    pub passed: bool,
    pub evidence_ref: String,
}

/// External handoff: names the real decision owner, never a permit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionHandoff {
    pub external_owner_id: String,
    pub rollback_owner_id: String,
    pub disable_owner_id: String,
    pub reopen_owner_id: String,
    pub expiry_ref: String,
    pub approval_fence_ref: String,
    pub active_permit: Option<String>,
    pub promotion_receipt: Option<String>,
}

/// Advisory candidate. Candidate only: no active state, no receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionInputCandidate {
    pub input_id: String,
    pub candidate_id: String,
    pub campaign_id: String,
    pub operation_ref: String,
    pub idempotency_key: String,
    pub scope_ref: String,
    pub proposed_domain_ref: String,
    pub evaluator_id: String,
    pub product_id: String,
    pub denominators: PromotionDenominators,
    pub digest: String,
    pub gate_report: Vec<GateReport>,
    pub limitations: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub handoff: PromotionHandoff,
    pub proof_ceiling: String,
    pub direct_promotion: bool,
}

/// Bounded disposition when advisory readiness is absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionDisposition {
    pub disposition: String,
    pub missing_evidence: Vec<String>,
    pub missing_owner: Option<String>,
    pub open_obligations: Vec<String>,
    pub retain_ref: String,
    pub original_scope_ref: String,
    pub narrowed_scope_ref: Option<String>,
    pub limitations: Vec<String>,
}

/// Preparation output: advisory or bounded disposition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionPreparation {
    Advisory(Box<PromotionInputCandidate>),
    Disposition(PromotionDisposition),
}

/// Typed preparation failures. No generic ready flag.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PromotionInputError {
    #[error("required field is missing: {0}")]
    MissingField(&'static str),
    #[error("unsupported schema version: {version}")]
    UnsupportedSchema { version: u32 },
    #[error("identity mismatch: {detail}")]
    IdentityMismatch { detail: String },
    #[error("duplicate record for id: {id}")]
    DuplicateRecord { id: String },
    #[error("conflicting same-ID records for id: {id}")]
    ConflictingRecord { id: String },
    #[error("stale evidence is rejected: {detail}")]
    StaleEvidence { detail: String },
    #[error("bound exceeded: {detail}")]
    BoundExceeded { detail: String },
    #[error("malformed input is rejected without panic: {detail}")]
    Malformed { detail: String },
    #[error("promotion output is forbidden: advisory only")]
    PromotionOutputForbidden,
    #[error("widening rejected: {detail}")]
    WideningRejected { detail: String },
    #[error("non-finite metric is not admissible")]
    NonFiniteMetric,
}

/// Prepare one advisory promotion input from exact evidence.
///
/// Pure function of its six inputs: no ambient clock, I/O, or live query.
/// Returns [`PromotionPreparation::Advisory`] when every mandatory gate is
/// complete at the requested scope, a bounded disposition otherwise, or a
/// [`PromotionInputError`] for typed schema/identity/bound failures.
pub fn prepare_promotion_input(
    exact_request: PromotionRequest,
    exact_closure: ClosureBinding,
    exact_candidate: PromotionCandidate,
    exact_gates: PromotionGateEvidence,
    prior_history: PriorPromotionHistory,
    promotion_policy: PromotionInputPolicy,
) -> Result<PromotionPreparation, PromotionInputError> {
    validate_request(&exact_request)?;
    if exact_request.cancelled {
        return Ok(PromotionPreparation::Disposition(blocked_disposition(
            &exact_request,
            "cancelled-operation: request marked cancelled",
            "cancelled operation remains with external owner",
        )));
    }
    validate_policy(&promotion_policy, &exact_request)?;
    validate_bounds(&exact_gates, &promotion_policy)?;
    validate_closure_binding(&exact_closure)?;
    validate_candidate_identities(
        &exact_request,
        &exact_closure,
        &exact_candidate,
        &exact_gates,
    )?;
    check_duplicate_members(&exact_gates)?;
    let denominators = account_denominators(&exact_gates);

    if let Some(disposition) = check_closure_gate(&exact_request, &exact_closure) {
        return Ok(PromotionPreparation::Disposition(disposition));
    }
    if let Some(disposition) = check_activation_gates(&exact_request, &exact_gates) {
        return Ok(PromotionPreparation::Disposition(disposition));
    }
    if let Some(disposition) = check_outcome_linkage(&exact_request, &exact_gates) {
        return Ok(PromotionPreparation::Disposition(disposition));
    }
    if let Some(disposition) = check_benefit_comparison(&exact_request, &exact_gates) {
        return Ok(PromotionPreparation::Disposition(disposition));
    }
    if let Some(disposition) = check_retention_gate(&exact_request, &exact_gates) {
        return Ok(PromotionPreparation::Disposition(disposition));
    }
    if let Some(disposition) = check_transfer_gates(&exact_request, &exact_gates, &promotion_policy)
    {
        return Ok(PromotionPreparation::Disposition(disposition));
    }
    if let Some(disposition) = check_evaluator_gate(&exact_request, &exact_gates) {
        return Ok(PromotionPreparation::Disposition(disposition));
    }
    if let Some(disposition) = check_pulse_gate(&exact_request, &exact_gates) {
        return Ok(PromotionPreparation::Disposition(disposition));
    }
    if let Some(disposition) = check_harm_gate(&exact_request, &exact_gates) {
        return Ok(PromotionPreparation::Disposition(disposition));
    }
    if let Some(disposition) = check_economics_gate(&exact_request, &exact_gates) {
        return Ok(PromotionPreparation::Disposition(disposition));
    }
    if let Some(disposition) = check_rollback_gate(&exact_request, &exact_gates, &promotion_policy)
    {
        return Ok(PromotionPreparation::Disposition(disposition));
    }
    if let Some(disposition) = check_denominators(&exact_request, &exact_gates, &denominators) {
        return Ok(PromotionPreparation::Disposition(disposition));
    }

    let evidence_hex = promotion_evidence_digest(
        &exact_request,
        &exact_closure,
        &exact_candidate,
        &exact_gates,
    );
    let digest = promotion_digest(
        &exact_request,
        &exact_closure,
        &exact_candidate,
        &exact_gates,
        &prior_history,
        &promotion_policy,
    );
    if let Some(disposition) = check_repeat(
        &exact_request,
        &exact_candidate,
        &prior_history,
        &promotion_policy,
        &evidence_hex,
        &digest,
    ) {
        return Ok(PromotionPreparation::Disposition(disposition));
    }

    let input_id = format!(
        "promo-{}-{}",
        truncate_id(&exact_candidate.candidate_id),
        &digest[..16]
    );
    let gate_report = build_gate_report(&exact_gates);
    let handoff = PromotionHandoff {
        external_owner_id: promotion_policy.external_owner_id.clone(),
        rollback_owner_id: promotion_policy.rollback_owner_id.clone(),
        disable_owner_id: promotion_policy.rollback_owner_id.clone(),
        reopen_owner_id: promotion_policy.external_owner_id.clone(),
        expiry_ref: promotion_policy.operation_ref.clone(),
        approval_fence_ref: exact_candidate.fence_ref.clone(),
        active_permit: None,
        promotion_receipt: None,
    };
    Ok(PromotionPreparation::Advisory(Box::new(
        PromotionInputCandidate {
            input_id,
            candidate_id: exact_candidate.candidate_id.clone(),
            campaign_id: exact_candidate.campaign_id.clone(),
            operation_ref: promotion_policy.operation_ref.clone(),
            idempotency_key: promotion_policy.idempotency_key.clone(),
            scope_ref: exact_candidate.scope_ref.clone(),
            proposed_domain_ref: exact_gates.transfer.proposed_domain_ref.clone(),
            evaluator_id: exact_candidate.evaluator_id.clone(),
            product_id: exact_candidate.product_id.clone(),
            denominators,
            digest,
            gate_report,
            limitations: vec![
                "module-proof-only: real edge and pulse proof remain separate".to_string(),
                "unknown-effects-require-external-recovery".to_string(),
                "rollback-reopen-expiry-require-external-owner".to_string(),
            ],
            missing_evidence: Vec::new(),
            handoff,
            proof_ceiling: PROOF_CEILING.to_string(),
            direct_promotion: false,
        },
    )))
}

fn truncate_id(value: &str) -> String {
    let mut out: String = value.chars().take(48).collect();
    out.retain(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if out.is_empty() {
        "id".to_string()
    } else {
        out
    }
}

fn non_empty(value: &str, field: &'static str) -> Result<(), PromotionInputError> {
    if value.trim().is_empty() {
        Err(PromotionInputError::MissingField(field))
    } else {
        Ok(())
    }
}

fn validate_id(value: &str, field: &'static str) -> Result<(), PromotionInputError> {
    non_empty(value, field)?;
    if value.len() > MAX_ID_LEN {
        return Err(PromotionInputError::Malformed {
            detail: format!("{field} exceeds {MAX_ID_LEN} bytes"),
        });
    }
    Ok(())
}

fn validate_ref(value: &str, field: &'static str) -> Result<(), PromotionInputError> {
    non_empty(value, field)?;
    if value.len() > MAX_REF_LEN {
        return Err(PromotionInputError::Malformed {
            detail: format!("{field} exceeds {MAX_REF_LEN} bytes"),
        });
    }
    Ok(())
}

/// Bound a diagnostic string and mark truncation explicitly.
fn redact(value: &str) -> String {
    if value.len() <= MAX_DIAGNOSTIC_LEN {
        value.to_string()
    } else {
        format!("{}...[redacted]", &value[..MAX_DIAGNOSTIC_LEN - 14])
    }
}

fn validate_request(request: &PromotionRequest) -> Result<(), PromotionInputError> {
    validate_id(&request.request_id, "request_id")?;
    validate_id(&request.operation_ref, "operation_ref")?;
    validate_id(&request.idempotency_key, "idempotency_key")?;
    validate_id(&request.candidate_id, "candidate_id")?;
    validate_id(&request.campaign_id, "campaign_id")?;
    validate_id(&request.task_id, "task_id")?;
    validate_ref(&request.scope_ref, "scope_ref")?;
    validate_ref(&request.fence_ref, "fence_ref")?;
    validate_ref(&request.base_state_ref, "base_state_ref")?;
    validate_id(&request.product_id, "product_id")?;
    validate_id(&request.source_id, "source_id")?;
    validate_ref(&request.artifact_ref, "artifact_ref")?;
    validate_ref(&request.config_ref, "config_ref")?;
    validate_ref(&request.stack_ref, "stack_ref")?;
    validate_ref(&request.platform_ref, "platform_ref")?;
    validate_ref(&request.environment_ref, "environment_ref")?;
    validate_ref(&request.objective_ref, "objective_ref")?;
    validate_ref(&request.acceptance_ref, "acceptance_ref")?;
    validate_id(&request.evaluator_id, "evaluator_id")?;
    validate_ref(&request.holdout_ref, "holdout_ref")?;
    Ok(())
}

fn validate_policy(
    policy: &PromotionInputPolicy,
    request: &PromotionRequest,
) -> Result<(), PromotionInputError> {
    if !SUPPORTED_SCHEMA_VERSIONS.contains(&policy.schema_version) {
        return Err(PromotionInputError::UnsupportedSchema {
            version: policy.schema_version,
        });
    }
    non_empty(&policy.external_owner_id, "external_owner_id")?;
    non_empty(&policy.rollback_owner_id, "rollback_owner_id")?;
    non_empty(&policy.operation_ref, "operation_ref")?;
    non_empty(&policy.idempotency_key, "idempotency_key")?;
    non_empty(&policy.proof_ceiling, "proof_ceiling")?;
    non_empty(&policy.privacy_ceiling, "privacy_ceiling")?;
    non_empty(&policy.requested_effect, "requested_effect")?;
    if policy.max_members == 0 {
        return Err(PromotionInputError::BoundExceeded {
            detail: "max_members must be nonzero".to_string(),
        });
    }
    if policy.max_gates == 0 {
        return Err(PromotionInputError::BoundExceeded {
            detail: "max_gates must be nonzero".to_string(),
        });
    }
    if policy.operation_ref != request.operation_ref {
        return Err(PromotionInputError::IdentityMismatch {
            detail: format!(
                "policy operation {:?} vs request {:?}: operation-mismatch",
                redact(&policy.operation_ref),
                redact(&request.operation_ref)
            ),
        });
    }
    if policy.idempotency_key != request.idempotency_key {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "policy idempotency vs request idempotency: idempotency-mismatch".to_string(),
        });
    }
    if !policy.forbid_direct_promotion
        || policy.request_direct_promotion
        || policy.claimed_promotion_receipt.is_some()
    {
        return Err(PromotionInputError::PromotionOutputForbidden);
    }
    if policy.proof_ceiling != PROOF_CEILING {
        return Err(PromotionInputError::WideningRejected {
            detail: format!(
                "proof ceiling {:?} widens beyond {PROOF_CEILING}",
                redact(&policy.proof_ceiling)
            ),
        });
    }
    if policy.privacy_ceiling != PRIVACY_CEILING {
        return Err(PromotionInputError::WideningRejected {
            detail: format!(
                "privacy ceiling {:?} widens beyond {PRIVACY_CEILING}",
                redact(&policy.privacy_ceiling)
            ),
        });
    }
    if policy.requested_effect != REQUESTED_EFFECT {
        return Err(PromotionInputError::WideningRejected {
            detail: format!(
                "requested effect {:?} widens beyond {REQUESTED_EFFECT}",
                redact(&policy.requested_effect)
            ),
        });
    }
    Ok(())
}

fn validate_bounds(
    gates: &PromotionGateEvidence,
    policy: &PromotionInputPolicy,
) -> Result<(), PromotionInputError> {
    if gates.harm_members.len() > policy.max_members
        || gates.expected_member_ids.len() > policy.max_members
    {
        return Err(PromotionInputError::BoundExceeded {
            detail: "member count exceeds max_members".to_string(),
        });
    }
    if gates.expected_gate_ids.len() > policy.max_gates {
        return Err(PromotionInputError::BoundExceeded {
            detail: "gate count exceeds max_gates".to_string(),
        });
    }
    let ref_count = gates.comparison.replay_refs.len()
        + gates.comparison.holdout_refs.len()
        + gates.transfer.transfer_refs.len()
        + gates.harm_members.len()
        + gates.expected_member_ids.len()
        + gates.expected_source_ids.len()
        + gates.expected_period_refs.len()
        + gates.expected_gate_ids.len();
    let approx_bytes = ref_count as u64 * 256;
    if approx_bytes > policy.max_bytes {
        return Err(PromotionInputError::BoundExceeded {
            detail: "estimated byte bound exceeded".to_string(),
        });
    }
    for id in gates
        .expected_member_ids
        .iter()
        .chain(gates.expected_source_ids.iter())
        .chain(gates.expected_gate_ids.iter())
    {
        if id.trim().is_empty() {
            return Err(PromotionInputError::MissingField("expected_id"));
        }
        if id.len() > MAX_ID_LEN {
            return Err(PromotionInputError::Malformed {
                detail: format!("expected id exceeds limit: {}", redact(id)),
            });
        }
    }
    for member in &gates.harm_members {
        if member.member_id.trim().is_empty() {
            return Err(PromotionInputError::MissingField("member_id"));
        }
        if member.member_id.len() > MAX_ID_LEN {
            return Err(PromotionInputError::Malformed {
                detail: format!("member id exceeds limit: {}", redact(&member.member_id)),
            });
        }
        if member.source_id.trim().is_empty() {
            return Err(PromotionInputError::MissingField("member_source_id"));
        }
    }
    if gates.economics.cost_known && !gates.economics.cost.is_finite() {
        return Err(PromotionInputError::NonFiniteMetric);
    }
    if !gates.economics.currency.trim().is_empty() && gates.economics.currency.len() > MAX_ID_LEN {
        return Err(PromotionInputError::Malformed {
            detail: "currency exceeds limit".to_string(),
        });
    }
    Ok(())
}

fn validate_closure_binding(closure: &ClosureBinding) -> Result<(), PromotionInputError> {
    validate_id(&closure.closure_id, "closure_id")?;
    validate_id(&closure.campaign_id, "campaign_id")?;
    non_empty(&closure.digest, "closure_digest")?;
    validate_ref(&closure.lineage_ref, "closure_lineage")?;
    if !SUPPORTED_SCHEMA_VERSIONS.contains(&closure.schema_version) {
        return Err(PromotionInputError::UnsupportedSchema {
            version: closure.schema_version,
        });
    }
    if closure.stale {
        return Err(PromotionInputError::StaleEvidence {
            detail: format!(
                "closure {} is stale: reuse-invalid",
                redact(&closure.closure_id)
            ),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_candidate_identities(
    request: &PromotionRequest,
    closure: &ClosureBinding,
    candidate: &PromotionCandidate,
    gates: &PromotionGateEvidence,
) -> Result<(), PromotionInputError> {
    validate_id(&candidate.candidate_id, "candidate_id")?;
    validate_id(&candidate.campaign_id, "campaign_id")?;
    validate_id(&candidate.task_id, "task_id")?;
    validate_ref(&candidate.scope_ref, "scope_ref")?;
    validate_ref(&candidate.fence_ref, "fence_ref")?;
    validate_ref(&candidate.base_state_ref, "base_state_ref")?;
    validate_id(&candidate.product_id, "product_id")?;
    validate_id(&candidate.source_id, "source_id")?;
    validate_ref(&candidate.artifact_ref, "artifact_ref")?;
    validate_ref(&candidate.config_ref, "config_ref")?;
    validate_ref(&candidate.stack_ref, "stack_ref")?;
    validate_ref(&candidate.platform_ref, "platform_ref")?;
    validate_ref(&candidate.environment_ref, "environment_ref")?;
    validate_ref(&candidate.objective_ref, "objective_ref")?;
    validate_ref(&candidate.acceptance_ref, "acceptance_ref")?;
    validate_id(&candidate.evaluator_id, "evaluator_id")?;
    validate_ref(&candidate.holdout_ref, "holdout_ref")?;
    non_empty(&candidate.digest, "candidate_digest")?;
    if !SUPPORTED_SCHEMA_VERSIONS.contains(&gates.evaluator.schema_version) {
        return Err(PromotionInputError::UnsupportedSchema {
            version: gates.evaluator.schema_version,
        });
    }
    if candidate.candidate_id != request.candidate_id {
        return Err(PromotionInputError::IdentityMismatch {
            detail: format!(
                "candidate {:?} vs request {:?}: candidate-mismatch",
                redact(&candidate.candidate_id),
                redact(&request.candidate_id)
            ),
        });
    }
    if candidate.campaign_id != request.campaign_id || candidate.campaign_id != closure.campaign_id
    {
        return Err(PromotionInputError::IdentityMismatch {
            detail: format!(
                "candidate campaign {:?} vs closure {:?}: campaign-mismatch",
                redact(&candidate.campaign_id),
                redact(&closure.campaign_id)
            ),
        });
    }
    if candidate.task_id != request.task_id {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate task vs request task: task-mismatch".to_string(),
        });
    }
    if candidate.scope_ref != request.scope_ref {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate scope vs request scope: scope-mismatch".to_string(),
        });
    }
    if candidate.fence_ref != request.fence_ref {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate fence vs request fence: fence-mismatch".to_string(),
        });
    }
    if candidate.base_state_ref != request.base_state_ref {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate base vs request base: base-mismatch".to_string(),
        });
    }
    if candidate.product_id != request.product_id {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate product vs request product: product-mismatch".to_string(),
        });
    }
    if candidate.source_id != request.source_id {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate source vs request source: source-mismatch".to_string(),
        });
    }
    if candidate.artifact_ref != request.artifact_ref {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate artifact vs request artifact: artifact-mismatch".to_string(),
        });
    }
    if candidate.config_ref != request.config_ref {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate config vs request config: config-mismatch".to_string(),
        });
    }
    if candidate.stack_ref != request.stack_ref {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate stack vs request stack: stack-mismatch".to_string(),
        });
    }
    if candidate.platform_ref != request.platform_ref {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate platform vs request platform: platform-mismatch".to_string(),
        });
    }
    if candidate.environment_ref != request.environment_ref {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate environment vs request environment: environment-mismatch"
                .to_string(),
        });
    }
    if candidate.objective_ref != request.objective_ref {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate objective vs request objective: objective-mismatch".to_string(),
        });
    }
    if candidate.acceptance_ref != request.acceptance_ref {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate acceptance vs request acceptance: acceptance-mismatch".to_string(),
        });
    }
    if candidate.evaluator_id != request.evaluator_id {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate evaluator vs request evaluator: evaluator-mismatch".to_string(),
        });
    }
    if candidate.holdout_ref != request.holdout_ref {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate holdout vs request holdout: holdout-mismatch".to_string(),
        });
    }
    if candidate.revision != closure.revision {
        return Err(PromotionInputError::IdentityMismatch {
            detail: format!(
                "candidate revision {} vs closure revision {}: revision-mismatch",
                candidate.revision, closure.revision
            ),
        });
    }
    if candidate.evaluator_id != gates.evaluator.evaluator_id {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate evaluator vs evidence evaluator: evaluator-mismatch".to_string(),
        });
    }
    if candidate.stack_ref != gates.evaluator.stack_ref {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate stack vs evidence stack: stack-mismatch".to_string(),
        });
    }
    if candidate.source_id != gates.evaluator.source_id {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate source vs evidence source: source-mismatch".to_string(),
        });
    }
    if !gates
        .comparison
        .holdout_refs
        .contains(&candidate.holdout_ref)
    {
        return Err(PromotionInputError::IdentityMismatch {
            detail: "candidate holdout not in comparison holdouts: holdout-mismatch".to_string(),
        });
    }
    Ok(())
}

fn check_duplicate_members(gates: &PromotionGateEvidence) -> Result<(), PromotionInputError> {
    let mut seen: BTreeMap<&str, &HarmMember> = BTreeMap::new();
    for member in &gates.harm_members {
        if let Some(first) = seen.get(member.member_id.as_str()) {
            if *first == member {
                return Err(PromotionInputError::DuplicateRecord {
                    id: member.member_id.clone(),
                });
            }
            return Err(PromotionInputError::ConflictingRecord {
                id: member.member_id.clone(),
            });
        }
        seen.insert(member.member_id.as_str(), member);
    }
    Ok(())
}

fn account_denominators(gates: &PromotionGateEvidence) -> PromotionDenominators {
    let supplied_sources: BTreeSet<&str> = gates
        .harm_members
        .iter()
        .map(|m| m.source_id.as_str())
        .collect();
    let supplied_periods = usize::from(gates.retention.observed && gates.retention.period_complete);
    let supplied_gates = count_passed_gates(gates);
    PromotionDenominators {
        expected_members: gates.expected_member_ids.len(),
        supplied_members: gates.harm_members.len(),
        expected_sources: gates.expected_source_ids.len(),
        supplied_sources: supplied_sources.len(),
        expected_periods: gates.expected_period_refs.len(),
        supplied_periods,
        expected_gates: gates.expected_gate_ids.len(),
        supplied_gates,
    }
}

fn count_passed_gates(gates: &PromotionGateEvidence) -> usize {
    let mut count = 0;
    for gate in [
        &gates.activation.activation,
        &gates.activation.visibility,
        &gates.activation.selection,
        &gates.activation.adherence,
        &gates.activation.use_gate,
        &gates.activation.action,
        &gates.activation.outcome,
    ] {
        if gate.observed
            && gate.compatible
            && gate
                .evidence_ref
                .as_deref()
                .is_some_and(|v| !v.trim().is_empty())
        {
            count += 1;
        }
    }
    if gates.benefit.benefit_observed
        && gates.benefit.causally_attributed
        && gates.benefit.comparison_valid
        && gates.benefit.independent
    {
        count += 1;
    }
    if gates.comparison.fixed && gates.comparison.valid {
        count += 1;
    }
    if gates.retention.observed && gates.retention.period_complete {
        count += 1;
    }
    if !gates.transfer.transfer_refs.is_empty() && gates.transfer.retention_bound {
        count += 1;
    }
    if matches!(gates.pulse.result, PulseResult::Pass) {
        count += 1;
    }
    if gates.evaluator.fresh && !gates.evaluator.stale && gates.evaluator.independent {
        count += 1;
    }
    if gates.economics.cost_known
        && gates.economics.resources_known
        && gates.economics.human_burden_known
    {
        count += 1;
    }
    count
}

fn incomplete(request: &PromotionRequest, missing: String, debt: &str) -> PromotionDisposition {
    PromotionDisposition {
        disposition: "incomplete".to_string(),
        missing_evidence: vec![redact(&missing)],
        missing_owner: Some(request.evaluator_id.clone()),
        open_obligations: vec![redact(debt)],
        retain_ref: request.scope_ref.clone(),
        original_scope_ref: request.scope_ref.clone(),
        narrowed_scope_ref: None,
        limitations: vec!["advisory-only: no promotion inferred from partial gates".to_string()],
    }
}

fn rejected(request: &PromotionRequest, missing: String, debt: &str) -> PromotionDisposition {
    PromotionDisposition {
        disposition: "rejected".to_string(),
        missing_evidence: vec![redact(&missing)],
        missing_owner: Some(request.evaluator_id.clone()),
        open_obligations: vec![redact(debt)],
        retain_ref: request.scope_ref.clone(),
        original_scope_ref: request.scope_ref.clone(),
        narrowed_scope_ref: None,
        limitations: vec!["rejected-scope-retained: no silent removal".to_string()],
    }
}

fn blocked_disposition(
    request: &PromotionRequest,
    missing: &str,
    debt: &str,
) -> PromotionDisposition {
    PromotionDisposition {
        disposition: "blocked".to_string(),
        missing_evidence: vec![redact(missing)],
        missing_owner: Some(request.evaluator_id.clone()),
        open_obligations: vec![redact(debt)],
        retain_ref: request.scope_ref.clone(),
        original_scope_ref: request.scope_ref.clone(),
        narrowed_scope_ref: None,
        limitations: vec!["blocked-readiness: external owner decision required".to_string()],
    }
}

fn check_closure_gate(
    request: &PromotionRequest,
    closure: &ClosureBinding,
) -> Option<PromotionDisposition> {
    if !closure.valid {
        return Some(rejected(
            request,
            format!(
                "closure {} invalid: valid-closure-required",
                redact(&closure.closure_id)
            ),
            "valid closure binding",
        ));
    }
    None
}

fn stage_ok(gate: &StageGate) -> bool {
    gate.observed
        && gate.compatible
        && gate
            .evidence_ref
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
}

fn check_activation_gates(
    request: &PromotionRequest,
    gates: &PromotionGateEvidence,
) -> Option<PromotionDisposition> {
    let a = &gates.activation;
    if !stage_ok(&a.activation) {
        return Some(incomplete(
            request,
            format!(
                "missing-activation: {}",
                redact_optional(&a.activation.evidence_ref)
            ),
            "activation evidence",
        ));
    }
    if a.activation.observed && !stage_ok(&a.use_gate) {
        return Some(incomplete(
            request,
            "delivery-without-use: activation cannot fill missing use".to_string(),
            "use evidence",
        ));
    }
    if (a.visibility.observed || a.selection.observed)
        && !(stage_ok(&a.adherence) && stage_ok(&a.use_gate))
    {
        return Some(incomplete(
            request,
            "visibility-selection-without-adherence-use: adherence and use both required"
                .to_string(),
            "adherence and use evidence",
        ));
    }
    if !stage_ok(&a.adherence) {
        return Some(incomplete(
            request,
            "missing-adherence: delivery cannot fill adherence".to_string(),
            "adherence evidence",
        ));
    }
    if !stage_ok(&a.use_gate) {
        return Some(incomplete(
            request,
            "missing-use: delivery cannot fill use".to_string(),
            "use evidence",
        ));
    }
    if !stage_ok(&a.visibility) || !stage_ok(&a.selection) {
        return Some(incomplete(
            request,
            "missing-visibility-selection: compatible selection required".to_string(),
            "visibility and selection evidence",
        ));
    }
    if !stage_ok(&a.action) {
        return Some(incomplete(
            request,
            "missing-action: compatible action evidence required".to_string(),
            "action evidence",
        ));
    }
    if !stage_ok(&a.outcome) {
        return Some(incomplete(
            request,
            "missing-outcome: compatible outcome evidence required".to_string(),
            "outcome evidence",
        ));
    }
    None
}

fn redact_optional(value: &Option<String>) -> String {
    match value {
        Some(v) if !v.trim().is_empty() => redact(v),
        _ => "no-evidence-ref".to_string(),
    }
}

fn check_outcome_linkage(
    request: &PromotionRequest,
    gates: &PromotionGateEvidence,
) -> Option<PromotionDisposition> {
    let outcome = &gates.activation.outcome;
    if outcome.observed && !outcome.use_linked {
        return Some(incomplete(
            request,
            "outcome-without-use-linkage: outcome needs exact usage linkage".to_string(),
            "usage-linked outcome",
        ));
    }
    if gates.benefit.benefit_observed && !gates.benefit.use_linked {
        return Some(incomplete(
            request,
            "benefit-without-use-linkage: benefit needs exact usage linkage".to_string(),
            "usage-linked benefit",
        ));
    }
    let linked_outcome = gates
        .harm_members
        .iter()
        .any(|m| matches!(m.outcome, MemberOutcome::Positive | MemberOutcome::NoEvent));
    if gates.benefit.benefit_observed && !linked_outcome && !outcome.use_linked {
        return Some(incomplete(
            request,
            "outcome-without-use-linkage: no linked outcome supports benefit".to_string(),
            "usage-linked outcome",
        ));
    }
    None
}

fn check_benefit_comparison(
    request: &PromotionRequest,
    gates: &PromotionGateEvidence,
) -> Option<PromotionDisposition> {
    let b = &gates.benefit;
    if !b.benefit_observed {
        return Some(incomplete(
            request,
            "missing-benefit: justified benefit required".to_string(),
            "benefit evidence",
        ));
    }
    if b.benefit_ref.as_deref().is_none_or(|v| v.trim().is_empty()) {
        return Some(incomplete(
            request,
            "missing-benefit-ref: benefit evidence ref required".to_string(),
            "benefit evidence",
        ));
    }
    if !b.causally_attributed || b.control_ref.as_deref().is_none_or(|v| v.trim().is_empty()) {
        return Some(incomplete(
            request,
            "benefit-without-causal-attribution: control-backed attribution required".to_string(),
            "causal attribution",
        ));
    }
    if !b.comparison_valid {
        return Some(incomplete(
            request,
            "benefit-without-valid-comparison: fixed comparison required".to_string(),
            "comparison validity",
        ));
    }
    if !b.independent {
        return Some(incomplete(
            request,
            "benefit-without-independence: independent benefit check required".to_string(),
            "independent evaluation",
        ));
    }
    let c = &gates.comparison;
    if c.comparison_ref.trim().is_empty() {
        return Some(incomplete(
            request,
            "missing-comparison-ref: fixed comparison required".to_string(),
            "comparison evidence",
        ));
    }
    if c.control_ref.as_deref().is_none_or(|v| v.trim().is_empty()) {
        return Some(incomplete(
            request,
            "confounder-denominator-incomplete: control required".to_string(),
            "confounder assessment",
        ));
    }
    if c.replay_refs.is_empty() || c.holdout_refs.is_empty() {
        return Some(incomplete(
            request,
            "replay-holdout-incomplete: fixed replay and holdout required".to_string(),
            "replay and holdout evidence",
        ));
    }
    if !c.fixed || !c.valid {
        return Some(incomplete(
            request,
            "comparison-invalid: fixed valid comparison required".to_string(),
            "comparison validity",
        ));
    }
    None
}

fn check_retention_gate(
    request: &PromotionRequest,
    gates: &PromotionGateEvidence,
) -> Option<PromotionDisposition> {
    let r = &gates.retention;
    if r.retention_ref.trim().is_empty()
        || r.period_ref.trim().is_empty()
        || !r.observed
        || !r.period_complete
    {
        return Some(incomplete(
            request,
            format!(
                "missing-retention: period {:?} needs complete observed retention",
                redact(&r.period_ref)
            ),
            "retention over declared period",
        ));
    }
    None
}

fn check_transfer_gates(
    request: &PromotionRequest,
    gates: &PromotionGateEvidence,
    policy: &PromotionInputPolicy,
) -> Option<PromotionDisposition> {
    let t = &gates.transfer;
    if t.transfer_refs.is_empty() || t.tested_domain_ref.trim().is_empty() {
        return Some(incomplete(
            request,
            "missing-transfer: tested applicability domain required".to_string(),
            "transfer evidence",
        ));
    }
    if !t.retention_bound || !gates.retention.observed || !gates.retention.period_complete {
        return Some(incomplete(
            request,
            "transfer-without-retention: transfer is not complete without retention".to_string(),
            "retention-bound transfer",
        ));
    }
    if t.proposed_domain_ref != t.tested_domain_ref {
        if !policy.allow_narrowing {
            return Some(rejected(
                request,
                format!(
                    "transfer-scope-exceeds-tested: proposed {:?} vs tested {:?}",
                    redact(&t.proposed_domain_ref),
                    redact(&t.tested_domain_ref)
                ),
                "exact tested applicability",
            ));
        }
        return Some(PromotionDisposition {
            disposition: "narrowed-for-review".to_string(),
            missing_evidence: vec![redact(&format!(
                "transfer-scope-exceeds-tested: proposed {:?} narrowed to tested {:?}",
                t.proposed_domain_ref, t.tested_domain_ref
            ))],
            missing_owner: Some(request.evaluator_id.clone()),
            open_obligations: vec!["external owner reviews narrowed scope".to_string()],
            retain_ref: request.scope_ref.clone(),
            original_scope_ref: t.proposed_domain_ref.clone(),
            narrowed_scope_ref: Some(t.tested_domain_ref.clone()),
            limitations: vec![
                "original-rejected-scope-retained".to_string(),
                "narrowed-to-tested-domain-only".to_string(),
            ],
        });
    }
    None
}

fn check_evaluator_gate(
    request: &PromotionRequest,
    gates: &PromotionGateEvidence,
) -> Option<PromotionDisposition> {
    let e = &gates.evaluator;
    if e.stale || !e.fresh {
        return Some(blocked_disposition(
            request,
            &format!(
                "stale-evaluator: {:?} reuse-invalid; stack {:?} revalidation required",
                redact(&e.evaluator_id),
                redact(&e.stack_ref)
            ),
            "fresh evaluator and stack",
        ));
    }
    if !e.independent || e.source_id == e.evaluator_id {
        return Some(incomplete(
            request,
            format!(
                "evaluator-dependence: source {:?} must stay independent of evaluator {:?}",
                redact(&e.source_id),
                redact(&e.evaluator_id)
            ),
            "independent evaluation",
        ));
    }
    None
}

fn check_pulse_gate(
    request: &PromotionRequest,
    gates: &PromotionGateEvidence,
) -> Option<PromotionDisposition> {
    let p = &gates.pulse;
    if p.pulse_id != PRODUCT_PULSE {
        return Some(incomplete(
            request,
            format!(
                "wrong-pulse-identity: {:?} vs required {PRODUCT_PULSE}",
                redact(&p.pulse_id)
            ),
            "exact pulse identity",
        ));
    }
    match &p.result {
        PulseResult::Pass => {
            if p.pulse_ref.as_deref().is_none_or(|v| v.trim().is_empty()) {
                return Some(incomplete(
                    request,
                    "missing-product-pulse: pulse evidence ref required; package-green is not pulse"
                        .to_string(),
                    "pulse result evidence",
                ));
            }
            None
        }
        PulseResult::Regression { detail } => Some(rejected(
            request,
            format!("pulse-regression: {}", redact(detail)),
            "pulse regression review",
        )),
        PulseResult::Unknown { reason } | PulseResult::Missing { reason } => Some(incomplete(
            request,
            format!(
                "missing-product-pulse: {}; package-green is not pulse",
                redact(reason)
            ),
            "pulse result evidence",
        )),
    }
}

fn check_harm_gate(
    request: &PromotionRequest,
    gates: &PromotionGateEvidence,
) -> Option<PromotionDisposition> {
    let mut bad: Vec<String> = Vec::new();
    let mut conflicts: Vec<String> = Vec::new();
    for member in &gates.harm_members {
        if member.harm_observed || member.outcome == MemberOutcome::Harmful {
            bad.push(redact(&format!(
                "member {} {:?} harm {}",
                member.member_id,
                member.outcome,
                member.harm_ref.as_deref().unwrap_or("unreferenced-harm")
            )));
        } else if member.outcome == MemberOutcome::Conflicted {
            conflicts.push(redact(&format!(
                "member {} conflicting-outcomes-no-winner",
                member.member_id
            )));
        } else if member.outcome == MemberOutcome::Negative && gates.benefit.benefit_observed {
            bad.push(redact(&format!(
                "member {} Negative minority retained with benefit claim",
                member.member_id
            )));
        }
    }
    if !conflicts.is_empty() {
        return Some(PromotionDisposition {
            disposition: "conflicted".to_string(),
            missing_evidence: conflicts.clone(),
            missing_owner: Some(request.evaluator_id.clone()),
            open_obligations: conflicts,
            retain_ref: request.scope_ref.clone(),
            original_scope_ref: request.scope_ref.clone(),
            narrowed_scope_ref: None,
            limitations: vec!["conflicting members retained: no averaging".to_string()],
        });
    }
    if !bad.is_empty() {
        return Some(PromotionDisposition {
            disposition: "rejected".to_string(),
            missing_evidence: bad.clone(),
            missing_owner: Some(request.evaluator_id.clone()),
            open_obligations: bad,
            retain_ref: request.scope_ref.clone(),
            original_scope_ref: request.scope_ref.clone(),
            narrowed_scope_ref: None,
            limitations: vec!["harm-minority-retained: no averaging away".to_string()],
        });
    }
    if gates.harm_members.is_empty() {
        return Some(incomplete(
            request,
            "missing-members: denominator members required".to_string(),
            "member evidence",
        ));
    }
    None
}

fn check_economics_gate(
    request: &PromotionRequest,
    gates: &PromotionGateEvidence,
) -> Option<PromotionDisposition> {
    let e = &gates.economics;
    if !e.cost_known {
        return Some(incomplete(
            request,
            "unknown-cost: unknown cost is not zero".to_string(),
            "cost evidence",
        ));
    }
    if !e.resources_known {
        return Some(incomplete(
            request,
            "unknown-resources: resource burden must stay explicit".to_string(),
            "resource evidence",
        ));
    }
    if !e.human_burden_known {
        return Some(incomplete(
            request,
            "unknown-human-burden: human burden must stay explicit".to_string(),
            "human burden evidence",
        ));
    }
    if e.currency.trim().is_empty() {
        return Some(incomplete(
            request,
            "missing-currency: bounded economics identity required".to_string(),
            "economics normalization",
        ));
    }
    None
}

fn check_rollback_gate(
    request: &PromotionRequest,
    gates: &PromotionGateEvidence,
    policy: &PromotionInputPolicy,
) -> Option<PromotionDisposition> {
    let r = &gates.rollback;
    let mut gaps: Vec<String> = Vec::new();
    if r.rollback_ref
        .as_deref()
        .is_none_or(|v| v.trim().is_empty())
    {
        gaps.push("missing-rollback".to_string());
    }
    if r.disable_ref.as_deref().is_none_or(|v| v.trim().is_empty()) {
        gaps.push("missing-disable".to_string());
    }
    if r.reopen_ref.as_deref().is_none_or(|v| v.trim().is_empty()) {
        gaps.push("missing-reopen".to_string());
    }
    if r.owner_id.trim().is_empty() || r.owner_id != policy.rollback_owner_id {
        gaps.push(format!(
            "rollback-owner-gap: {:?} needs rollback owner {:?}",
            redact(&r.owner_id),
            redact(&policy.rollback_owner_id)
        ));
    }
    if r.expiry_ref.as_deref().is_none_or(|v| v.trim().is_empty()) {
        gaps.push("missing-expiry".to_string());
    } else if r.expiry_ref.as_deref() != Some(policy.operation_ref.as_str()) {
        gaps.push("expiry-mismatch: expiry must bind operation".to_string());
    }
    if gaps.is_empty() {
        None
    } else {
        Some(PromotionDisposition {
            disposition: "blocked".to_string(),
            missing_evidence: gaps.clone(),
            missing_owner: Some(policy.rollback_owner_id.clone()),
            open_obligations: gaps,
            retain_ref: request.scope_ref.clone(),
            original_scope_ref: request.scope_ref.clone(),
            narrowed_scope_ref: None,
            limitations: vec!["rollback-disable-reopen-owner-required".to_string()],
        })
    }
}

fn check_denominators(
    request: &PromotionRequest,
    gates: &PromotionGateEvidence,
    denominators: &PromotionDenominators,
) -> Option<PromotionDisposition> {
    let supplied_members: BTreeSet<&str> = gates
        .harm_members
        .iter()
        .map(|m| m.member_id.as_str())
        .collect();
    let mut missing: Vec<String> = Vec::new();
    for id in &gates.expected_member_ids {
        if !supplied_members.contains(id.as_str()) {
            missing.push(format!("missing-member {id}"));
        }
    }
    let supplied_sources: BTreeSet<&str> = gates
        .harm_members
        .iter()
        .map(|m| m.source_id.as_str())
        .collect();
    for id in &gates.expected_source_ids {
        if !supplied_sources.contains(id.as_str()) {
            missing.push(format!("missing-source {id}"));
        }
    }
    for period in &gates.expected_period_refs {
        if *period != gates.retention.period_ref {
            missing.push(format!("missing-period {period}"));
        }
    }
    for gate in &gates.expected_gate_ids {
        if gate.trim().is_empty() {
            missing.push("missing-gate-id".to_string());
        }
    }
    if denominators.expected_gates != denominators.supplied_gates {
        missing.push(format!(
            "gate-denominator-incomplete: expected {} vs supplied {}",
            denominators.expected_gates, denominators.supplied_gates
        ));
    }
    if missing.is_empty() {
        None
    } else {
        Some(PromotionDisposition {
            disposition: "incomplete".to_string(),
            missing_evidence: missing.clone().into_iter().map(|m| redact(&m)).collect(),
            missing_owner: Some(request.evaluator_id.clone()),
            open_obligations: vec!["denominator-incomplete: complete versus partial".to_string()],
            retain_ref: request.scope_ref.clone(),
            original_scope_ref: request.scope_ref.clone(),
            narrowed_scope_ref: None,
            limitations: vec!["denominators-preserved: complete-or-partial".to_string()],
        })
    }
}

fn check_repeat(
    request: &PromotionRequest,
    candidate: &PromotionCandidate,
    history: &PriorPromotionHistory,
    policy: &PromotionInputPolicy,
    evidence_hex: &str,
    digest: &str,
) -> Option<PromotionDisposition> {
    let input_id = format!(
        "promo-{}-{}",
        truncate_id(&candidate.candidate_id),
        &digest[..16]
    );
    for prior in &history.prior {
        if prior.input_id == input_id && prior.digest != *digest {
            continue;
        }
        if !prior.superseded
            && prior.candidate_id == candidate.candidate_id
            && prior.digest == *evidence_hex
        {
            return Some(PromotionDisposition {
                disposition: "repeat-review".to_string(),
                missing_evidence: vec![redact(&format!(
                    "materially equivalent repeat of {} under unchanged evidence; blind repeat not recommended",
                    prior.input_id
                ))],
                missing_owner: Some(policy.external_owner_id.clone()),
                open_obligations: vec![redact(&format!("repeat-review {}", prior.input_id))],
                retain_ref: request.scope_ref.clone(),
                original_scope_ref: request.scope_ref.clone(),
                narrowed_scope_ref: None,
                limitations: vec!["repeat-requires-external-review".to_string()],
            });
        }
    }
    let _ = input_id;
    None
}

fn build_gate_report(gates: &PromotionGateEvidence) -> Vec<GateReport> {
    let mut report = Vec::new();
    let stages = [
        ("activation", &gates.activation.activation),
        ("visibility", &gates.activation.visibility),
        ("selection", &gates.activation.selection),
        ("adherence", &gates.activation.adherence),
        ("use", &gates.activation.use_gate),
        ("action", &gates.activation.action),
        ("outcome", &gates.activation.outcome),
    ];
    for (name, gate) in stages {
        report.push(GateReport {
            gate: name.to_string(),
            passed: stage_ok(gate),
            evidence_ref: redact_optional(&gate.evidence_ref),
        });
    }
    report.push(GateReport {
        gate: "benefit".to_string(),
        passed: gates.benefit.benefit_observed,
        evidence_ref: redact_optional(&gates.benefit.benefit_ref),
    });
    report.push(GateReport {
        gate: "comparison".to_string(),
        passed: gates.comparison.fixed && gates.comparison.valid,
        evidence_ref: redact(&gates.comparison.comparison_ref),
    });
    report.push(GateReport {
        gate: "retention".to_string(),
        passed: gates.retention.observed && gates.retention.period_complete,
        evidence_ref: redact(&gates.retention.retention_ref),
    });
    report.push(GateReport {
        gate: "transfer".to_string(),
        passed: !gates.transfer.transfer_refs.is_empty(),
        evidence_ref: redact(
            gates
                .transfer
                .transfer_refs
                .first()
                .map(String::as_str)
                .unwrap_or("no-transfer-ref"),
        ),
    });
    report.push(GateReport {
        gate: "pulse".to_string(),
        passed: matches!(gates.pulse.result, PulseResult::Pass),
        evidence_ref: redact(gates.pulse.pulse_ref.as_deref().unwrap_or("no-pulse-ref")),
    });
    report.push(GateReport {
        gate: "evaluator".to_string(),
        passed: gates.evaluator.fresh && gates.evaluator.independent,
        evidence_ref: redact(&gates.evaluator.evaluator_id),
    });
    report.push(GateReport {
        gate: "economics".to_string(),
        passed: gates.economics.cost_known
            && gates.economics.resources_known
            && gates.economics.human_burden_known,
        evidence_ref: redact(&gates.economics.currency),
    });
    report
}

/// Evidence fingerprint over the four evidence inputs (no history/policy).
pub fn promotion_evidence_digest(
    exact_request: &PromotionRequest,
    exact_closure: &ClosureBinding,
    exact_candidate: &PromotionCandidate,
    exact_gates: &PromotionGateEvidence,
) -> String {
    let mut hasher = Hasher::new();
    hash_evidence(
        &mut hasher,
        exact_request,
        exact_closure,
        exact_candidate,
        exact_gates,
    );
    hasher.finalize().to_hex().to_string()
}

fn field(hasher: &mut Hasher, value: &str) {
    hasher.update(value.as_bytes());
    hasher.update(b"\x00");
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[allow(clippy::too_many_lines)]
fn hash_evidence(
    hasher: &mut Hasher,
    request: &PromotionRequest,
    closure: &ClosureBinding,
    candidate: &PromotionCandidate,
    gates: &PromotionGateEvidence,
) {
    field(hasher, &request.request_id);
    field(hasher, &request.operation_ref);
    field(hasher, &request.idempotency_key);
    field(hasher, &request.candidate_id);
    field(hasher, &request.campaign_id);
    field(hasher, &request.task_id);
    field(hasher, &request.scope_ref);
    field(hasher, &request.fence_ref);
    field(hasher, &request.base_state_ref);
    field(hasher, &request.product_id);
    field(hasher, &request.source_id);
    field(hasher, &request.artifact_ref);
    field(hasher, &request.config_ref);
    field(hasher, &request.stack_ref);
    field(hasher, &request.platform_ref);
    field(hasher, &request.environment_ref);
    field(hasher, &request.objective_ref);
    field(hasher, &request.acceptance_ref);
    field(hasher, &request.evaluator_id);
    field(hasher, &request.holdout_ref);
    field(hasher, &closure.closure_id);
    field(hasher, &closure.campaign_id);
    field(hasher, &closure.digest);
    field(hasher, &closure.lineage_ref);
    field(hasher, &closure.schema_version.to_string());
    field(hasher, &closure.revision.to_string());
    field(hasher, &candidate.candidate_id);
    field(hasher, &candidate.campaign_id);
    field(hasher, &candidate.task_id);
    field(hasher, &candidate.scope_ref);
    field(hasher, &candidate.fence_ref);
    field(hasher, &candidate.base_state_ref);
    field(hasher, &candidate.product_id);
    field(hasher, &candidate.source_id);
    field(hasher, &candidate.artifact_ref);
    field(hasher, &candidate.config_ref);
    field(hasher, &candidate.stack_ref);
    field(hasher, &candidate.platform_ref);
    field(hasher, &candidate.environment_ref);
    field(hasher, &candidate.objective_ref);
    field(hasher, &candidate.acceptance_ref);
    field(hasher, &candidate.evaluator_id);
    field(hasher, &candidate.holdout_ref);
    field(hasher, &candidate.revision.to_string());
    field(hasher, &candidate.digest);
    let stages = [
        ("activation", &gates.activation.activation),
        ("visibility", &gates.activation.visibility),
        ("selection", &gates.activation.selection),
        ("adherence", &gates.activation.adherence),
        ("use", &gates.activation.use_gate),
        ("action", &gates.activation.action),
        ("outcome", &gates.activation.outcome),
    ];
    for (name, gate) in stages {
        field(hasher, name);
        field(hasher, if gate.observed { "observed" } else { "missing" });
        field(hasher, gate.evidence_ref.as_deref().unwrap_or(""));
        field(
            hasher,
            if gate.compatible {
                "compatible"
            } else {
                "incompatible"
            },
        );
        field(
            hasher,
            if gate.use_linked {
                "use-linked"
            } else {
                "unlinked"
            },
        );
    }
    field(
        hasher,
        if gates.benefit.benefit_observed {
            "benefit"
        } else {
            "no-benefit"
        },
    );
    field(hasher, gates.benefit.benefit_ref.as_deref().unwrap_or(""));
    field(
        hasher,
        if gates.benefit.causally_attributed {
            "attributed"
        } else {
            "unattributed"
        },
    );
    field(hasher, gates.benefit.control_ref.as_deref().unwrap_or(""));
    field(
        hasher,
        if gates.benefit.comparison_valid {
            "comparison-valid"
        } else {
            "comparison-invalid"
        },
    );
    field(
        hasher,
        if gates.benefit.independent {
            "independent"
        } else {
            "dependent"
        },
    );
    let mut members: Vec<&HarmMember> = gates.harm_members.iter().collect();
    members.sort_by(|a, b| a.member_id.cmp(&b.member_id));
    for member in members {
        field(hasher, &member.member_id);
        field(hasher, &format!("{:?}", member.outcome));
        field(
            hasher,
            if member.harm_observed {
                "harm"
            } else {
                "no-harm"
            },
        );
        field(hasher, member.harm_ref.as_deref().unwrap_or(""));
        field(hasher, &member.source_id);
    }
    field(hasher, &gates.comparison.comparison_ref);
    field(
        hasher,
        gates.comparison.control_ref.as_deref().unwrap_or(""),
    );
    let mut replay: Vec<&str> = gates
        .comparison
        .replay_refs
        .iter()
        .map(String::as_str)
        .collect();
    replay.sort_unstable();
    for r in replay {
        field(hasher, r);
    }
    let mut holdout: Vec<&str> = gates
        .comparison
        .holdout_refs
        .iter()
        .map(String::as_str)
        .collect();
    holdout.sort_unstable();
    for h in holdout {
        field(hasher, h);
    }
    field(hasher, &gates.retention.retention_ref);
    field(hasher, &gates.retention.period_ref);
    let mut transfers: Vec<&str> = gates
        .transfer
        .transfer_refs
        .iter()
        .map(String::as_str)
        .collect();
    transfers.sort_unstable();
    for t in transfers {
        field(hasher, t);
    }
    field(hasher, &gates.transfer.tested_domain_ref);
    field(hasher, &gates.transfer.proposed_domain_ref);
    field(hasher, &gates.pulse.pulse_id);
    field(hasher, gates.pulse.pulse_ref.as_deref().unwrap_or(""));
    match &gates.pulse.result {
        PulseResult::Pass => field(hasher, "pulse-pass"),
        PulseResult::Regression { detail } => {
            field(hasher, "pulse-regression");
            field(hasher, detail);
        }
        PulseResult::Unknown { reason } => {
            field(hasher, "pulse-unknown");
            field(hasher, reason);
        }
        PulseResult::Missing { reason } => {
            field(hasher, "pulse-missing");
            field(hasher, reason);
        }
    }
    field(hasher, &gates.evaluator.evaluator_id);
    field(hasher, &gates.evaluator.stack_ref);
    field(hasher, &gates.evaluator.source_id);
    field(
        hasher,
        if gates.economics.cost_known {
            "known"
        } else {
            "unknown"
        },
    );
    field(
        hasher,
        &hex_bytes(&gates.economics.cost.to_bits().to_be_bytes()),
    );
    field(hasher, &gates.economics.currency);
    field(
        hasher,
        if gates.economics.resources_known {
            "resources-known"
        } else {
            "resources-unknown"
        },
    );
    field(
        hasher,
        gates.economics.resources_ref.as_deref().unwrap_or(""),
    );
    field(
        hasher,
        if gates.economics.human_burden_known {
            "burden-known"
        } else {
            "burden-unknown"
        },
    );
    let mut expected_members: Vec<&str> = gates
        .expected_member_ids
        .iter()
        .map(String::as_str)
        .collect();
    expected_members.sort_unstable();
    for id in expected_members {
        field(hasher, id);
    }
    let mut expected_sources: Vec<&str> = gates
        .expected_source_ids
        .iter()
        .map(String::as_str)
        .collect();
    expected_sources.sort_unstable();
    for id in expected_sources {
        field(hasher, id);
    }
    let mut expected_periods: Vec<&str> = gates
        .expected_period_refs
        .iter()
        .map(String::as_str)
        .collect();
    expected_periods.sort_unstable();
    for id in expected_periods {
        field(hasher, id);
    }
    let mut expected_gates: Vec<&str> =
        gates.expected_gate_ids.iter().map(String::as_str).collect();
    expected_gates.sort_unstable();
    for id in expected_gates {
        field(hasher, id);
    }
}

/// Full digest: evidence fingerprint plus history and policy binding.
fn promotion_digest(
    request: &PromotionRequest,
    closure: &ClosureBinding,
    candidate: &PromotionCandidate,
    gates: &PromotionGateEvidence,
    history: &PriorPromotionHistory,
    policy: &PromotionInputPolicy,
) -> String {
    let mut hasher = Hasher::new();
    hash_evidence(&mut hasher, request, closure, candidate, gates);
    let mut priors: Vec<&PriorPromotion> = history.prior.iter().collect();
    priors.sort_by(|a, b| {
        (&a.candidate_id, &a.input_id, &a.digest).cmp(&(&b.candidate_id, &b.input_id, &b.digest))
    });
    for prior in priors {
        field(&mut hasher, &prior.input_id);
        field(&mut hasher, &prior.candidate_id);
        field(&mut hasher, &prior.digest);
        field(
            &mut hasher,
            if prior.superseded {
                "superseded"
            } else {
                "active"
            },
        );
    }
    field(&mut hasher, &policy.idempotency_key);
    field(&mut hasher, &policy.operation_ref);
    field(&mut hasher, &policy.external_owner_id);
    field(&mut hasher, &policy.rollback_owner_id);
    hasher.finalize().to_hex().to_string()
}
