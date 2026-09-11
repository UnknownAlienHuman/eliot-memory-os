//! Pure semantic assessment over the retained Failure closure.

use eliot_dreamer_contracts::{
    ContractViolation, FailureCausalStatus, FailureComparator, FailureCoverage,
    FailureEvidenceKind, FailureHistoryEntry, FailureInput, FailureObservationState,
    canonical_bytes, digest_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct TriggerPreimage {
    profile_id: String,
    profile_schema_version: u32,
    owner: String,
    definition_profile_id: String,
    revision: String,
    comparator: FailureComparator,
    dimensions: Vec<eliot_dreamer_contracts::FailureDimension>,
    fingerprint: String,
    signature: String,
    violated_invariant: String,
}

/// Result of evaluating the declared exact trigger profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TriggerAssessment {
    Exact,
    Missing,
    Unsupported,
    NearMatch,
}

/// One of the nine A03 observation states; no states are collapsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OutcomeAssessment {
    NotAttempted,
    Rejected,
    Unavailable,
    PartiallyApplied,
    UnknownOutcome,
    ExecutedButSemanticallyFailed,
    VerifierFailed,
    Cancelled,
    TimedOut,
}

/// Result of comparing the current applicability snapshot with the proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ApplicabilityAssessment {
    Scoped,
    ChangedEnvironment,
    ScopeMismatch,
    Incomplete,
}

/// Counts retained from finite history and controls.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FailureCountSummary {
    pub expected_total: u32,
    pub represented_total: u32,
    pub success_count: u32,
    pub near_match_count: u32,
    pub false_activation_count: u32,
    pub unknown_count: u32,
    pub independent_count: u32,
    pub semantic_success_count: u32,
    pub history_trigger_match_count: u32,
    pub history_trigger_near_match_count: u32,
    pub history_trigger_success_count: u32,
    pub controls: u32,
}

/// Causal ceiling carried by the candidate; it never claims intervention proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CausalLimits {
    pub status: FailureCausalStatus,
    pub may_describe_correlation: bool,
    pub causal_claim_permitted: bool,
    pub limitation_refs: Vec<String>,
}

/// Complete local assessment used by result assembly and callers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureAssessment {
    pub trigger: TriggerAssessment,
    pub outcome: OutcomeAssessment,
    /// The fine-grained state supplied by the upstream handoff.  This is
    /// retained as a declaration; `outcome` is receipt/evidence assessed.
    pub declared_outcome_state: Option<FailureObservationState>,
    pub applicability: ApplicabilityAssessment,
    pub counts: FailureCountSummary,
    pub causal: CausalLimits,
    pub current_trigger_digest: String,
    pub evidence_refs: Vec<String>,
    pub missing_evidence_refs: Vec<String>,
    pub unsupported_modes: Vec<String>,
}

impl FailureAssessment {
    /// Assesses bounded semantic dimensions without mutation or I/O.
    pub fn evaluate(input: &FailureInput) -> Result<Self, ContractViolation> {
        input.validate()?;
        Self::evaluate_validated(input)
    }

    pub(crate) fn evaluate_validated(input: &FailureInput) -> Result<Self, ContractViolation> {
        let trigger = trigger(input);
        let (outcome, declared_outcome_state) = outcome(input);
        let applicability = applicability(input);
        let current_trigger_digest = current_trigger_digest(input)?;
        let counts = counts(input, &current_trigger_digest)?;
        let retained = input
            .action_evidence
            .evidence_envelopes
            .iter()
            .chain(input.history.historical_evidence_envelopes.iter())
            .map(|envelope| canonical_bytes(envelope).map(|bytes| digest_hex(&bytes)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut evidence_refs = Vec::new();
        let mut missing_evidence_refs = Vec::new();
        for evidence in input
            .action_evidence
            .evidence
            .iter()
            .chain(input.history.historical_evidence.iter())
        {
            let is_retained = retained.contains(&evidence.envelope_digest);
            let is_omitted = !is_retained
                && (input
                    .action_evidence
                    .omitted_envelope_refs
                    .contains(&evidence.envelope_digest)
                    || input
                        .history
                        .omitted_evidence_envelope_refs
                        .contains(&evidence.envelope_digest));
            let target = if is_omitted {
                &mut missing_evidence_refs
            } else {
                &mut evidence_refs
            };
            if !target.contains(&evidence.evidence_id) {
                target.push(evidence.evidence_id.clone());
            }
        }
        evidence_refs.sort();
        missing_evidence_refs.sort();
        let mut limitation_refs = vec![
            "causal_mechanism_requires_intervention_evidence".to_owned(),
            "candidate_does_not_grant_block_or_suppression_authority".to_owned(),
        ];
        if applicability == ApplicabilityAssessment::ChangedEnvironment {
            limitation_refs.push("environment_match_is_narrowed".to_owned());
        }
        if applicability == ApplicabilityAssessment::ScopeMismatch {
            limitation_refs.push("task_scope_target_and_effect_join_is_narrowed".to_owned());
        }
        if counts.false_activation_count > 0 {
            limitation_refs.push("false_activation_history_retained".to_owned());
        }
        Ok(Self {
            trigger,
            outcome,
            declared_outcome_state,
            applicability,
            counts,
            causal: CausalLimits {
                status: FailureCausalStatus::Unknown,
                may_describe_correlation: false,
                causal_claim_permitted: false,
                limitation_refs,
            },
            current_trigger_digest,
            evidence_refs,
            missing_evidence_refs,
            unsupported_modes: vec![
                "recurrence_requires_typed_historical_dimensions_and_independence_domain"
                    .to_owned(),
                "causal_mechanism_requires_intervention_evidence".to_owned(),
                "duplicate_refinement_and_extinction_require_owner_authority".to_owned(),
                "mitigation_reopen_and_block_decisions_are_inert".to_owned(),
            ],
        })
    }

    /// Whether this assessment has the complete positive evidence floor.
    #[must_use]
    pub const fn supports_candidate(&self) -> bool {
        matches!(self.trigger, TriggerAssessment::Exact)
            && matches!(
                self.outcome,
                OutcomeAssessment::ExecutedButSemanticallyFailed
            )
            && matches!(self.applicability, ApplicabilityAssessment::Scoped)
            && self.counts.false_activation_count == 0
            && self.missing_evidence_refs.is_empty()
    }
}

fn trigger(input: &FailureInput) -> TriggerAssessment {
    let profile = &input.proposal.comparison;
    if profile.comparator != FailureComparator::ExactEquality {
        return TriggerAssessment::Unsupported;
    }
    if profile.dimensions.is_empty() || !profile.missing_dimensions.is_empty() {
        return TriggerAssessment::Missing;
    }
    let names_match = input.proposal.trigger.len() == profile.dimensions.len()
        && input.proposal.trigger.iter().all(|dimension| {
            profile
                .dimensions
                .iter()
                .any(|candidate| candidate == dimension)
        });
    if names_match && input.proposal.trigger.iter().all(|d| d.validate().is_ok()) {
        TriggerAssessment::Exact
    } else {
        TriggerAssessment::NearMatch
    }
}

fn outcome(input: &FailureInput) -> (OutcomeAssessment, Option<FailureObservationState>) {
    let declared = input.action_evidence.outcome.failure_state;
    let verified = &input.action_evidence.outcome.verified;
    let verified_receipt = input
        .action_evidence
        .outcome
        .verified_receipt_ref
        .as_ref()
        .and_then(|receipt_id| {
            input
                .action_evidence
                .receipts
                .iter()
                .find(|receipt| receipt.identity.receipt_id.as_str() == receipt_id)
        });
    let semantic_evidence = input.action_evidence.evidence.iter().any(|evidence| {
        evidence.kind == FailureEvidenceKind::SemanticVerifier
            && evidence.coverage == FailureCoverage::Complete
            && input.action_evidence.coverage == FailureCoverage::Complete
            && input.action_evidence.outcome.coverage == FailureCoverage::Complete
            && input
                .action_evidence
                .evidence_envelopes
                .iter()
                .chain(input.history.historical_evidence_envelopes.iter())
                .any(|envelope| {
                    canonical_bytes(envelope)
                        .is_ok_and(|bytes| digest_hex(&bytes) == evidence.envelope_digest)
                })
            && input
                .action_evidence
                .receipt_materials
                .iter()
                .any(|material| {
                    material.receipt_id
                        == verified_receipt
                            .map(|receipt| receipt.identity.receipt_id.as_str())
                            .unwrap_or_default()
                })
    });
    let semantic_floor = verified_receipt.is_some_and(|receipt| {
        receipt.core.disposition.kind() == eliot_receipts::ReceiptDispositionKind::Failure
            && receipt.core.verifier.is_some()
    }) && semantic_evidence;
    let assessed = match verified.kind() {
        eliot_receipts::ReceiptDispositionKind::Cancelled
            if verified_receipt.is_some()
                && matches!(declared, Some(FailureObservationState::Cancelled) | None) =>
        {
            OutcomeAssessment::Cancelled
        }
        eliot_receipts::ReceiptDispositionKind::Partial
            if verified_receipt.is_some()
                && matches!(
                    declared,
                    Some(FailureObservationState::PartiallyApplied) | None
                ) =>
        {
            OutcomeAssessment::PartiallyApplied
        }
        eliot_receipts::ReceiptDispositionKind::Failure
            if semantic_floor
                && declared == Some(FailureObservationState::ExecutedButSemanticallyFailed) =>
        {
            OutcomeAssessment::ExecutedButSemanticallyFailed
        }
        _ => OutcomeAssessment::UnknownOutcome,
    };
    (assessed, declared)
}

fn applicability(input: &FailureInput) -> ApplicabilityAssessment {
    let proposal = &input.proposal.applicability;
    let environment = &input.environment;
    if proposal.coverage != FailureCoverage::Complete
        || environment.coverage != FailureCoverage::Complete
    {
        return ApplicabilityAssessment::Incomplete;
    }
    if proposal.task_id != input.operation.task_id
        || proposal.scope_id != input.operation.scope_id
        || proposal.target_id != input.action_evidence.action.target_id
        || proposal.effect_class != input.action_evidence.action.effect_class
    {
        return ApplicabilityAssessment::ScopeMismatch;
    }
    if proposal.environment_id != environment.environment_id
        || proposal.platform != environment.platform
        || proposal.tool_revision != environment.tool_revision
        || proposal.model_revision != environment.model_revision
        || proposal.config_revision != environment.config_revision
        || proposal.capability_revision != environment.capability_revision
    {
        ApplicabilityAssessment::ChangedEnvironment
    } else {
        ApplicabilityAssessment::Scoped
    }
}

fn counts(
    input: &FailureInput,
    trigger_digest: &str,
) -> Result<FailureCountSummary, ContractViolation> {
    let represented_total =
        checked_count(input.history.entries.len(), "failure.assessment.history")?;
    let controls = checked_count(input.proposal.controls.len(), "failure.assessment.controls")?;
    let independent_count = checked_count(
        input
            .history
            .entries
            .iter()
            .filter(|entry| entry.independent)
            .count(),
        "failure.assessment.independent",
    )?;
    let semantic_success_count = checked_count(
        input
            .history
            .entries
            .iter()
            .filter(|entry| entry.semantic_success)
            .count(),
        "failure.assessment.semantic_success",
    )?;
    let history_trigger_match_count = joined_history_count(
        input,
        trigger_digest,
        |_| true,
        "failure.assessment.trigger_matches",
    )?;
    let history_trigger_success_count = joined_history_count(
        input,
        trigger_digest,
        |entry| entry.semantic_success,
        "failure.assessment.trigger_successes",
    )?;
    Ok(FailureCountSummary {
        expected_total: input.history.expected_total,
        represented_total,
        success_count: input.history.success_count,
        near_match_count: input.history.near_match_count,
        false_activation_count: input.history.false_activation_count,
        unknown_count: input.history.unknown_count,
        independent_count,
        semantic_success_count,
        history_trigger_match_count,
        history_trigger_near_match_count: joined_history_count(
            input,
            trigger_digest,
            |entry| entry.near_match,
            "failure.assessment.trigger_near_matches",
        )?,
        history_trigger_success_count,
        controls,
    })
}

fn checked_count(value: usize, field: &'static str) -> Result<u32, ContractViolation> {
    u32::try_from(value).map_err(|_| ContractViolation::OutOfBounds {
        field,
        min: 0,
        max: i64::from(u32::MAX),
        got: i64::MAX,
    })
}

fn joined_history_count(
    input: &FailureInput,
    trigger_digest: &str,
    predicate: impl Fn(&FailureHistoryEntry) -> bool,
    field: &'static str,
) -> Result<u32, ContractViolation> {
    checked_count(
        input
            .history
            .entries
            .iter()
            .filter(|entry| {
                entry.fingerprint_id == input.proposal.fingerprint
                    && entry.trigger_digest == trigger_digest
                    && predicate(entry)
            })
            .count(),
        field,
    )
}

fn current_trigger_digest(input: &FailureInput) -> Result<String, ContractViolation> {
    let mut profile = input.proposal.comparison.clone();
    profile
        .dimensions
        .sort_by(|left, right| left.name.cmp(&right.name));
    profile.missing_dimensions.sort();
    Ok(digest_hex(&canonical_bytes(&TriggerPreimage {
        profile_id: profile.profile_id,
        profile_schema_version: profile.schema_version,
        owner: profile.definition.owner,
        definition_profile_id: profile.definition.profile_id,
        revision: profile.definition.revision,
        comparator: profile.comparator,
        dimensions: profile.dimensions,
        fingerprint: input.proposal.fingerprint.clone(),
        signature: input.proposal.signature.clone(),
        violated_invariant: input.proposal.violated_invariant.clone(),
    })?))
}
