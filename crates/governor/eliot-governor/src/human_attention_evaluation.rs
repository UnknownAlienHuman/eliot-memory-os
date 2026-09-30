//! Governor-owned Human attention evaluation assembly (I11.10, #1784).
//!
//! The Governor prepares the semantic admission of a
//! [`HumanAttentionEvaluation`](eliot_evaluation_contracts::HumanAttentionEvaluation):
//! it assembles bounded owner evidence into one consistently bound package and
//! derives conditional conclusions from it. It authorizes nothing, persists
//! nothing, and completes nothing:
//!
//! - **W3, bounded owner evidence.** [`assemble_human_attention_evidence`]
//!   takes the caller-nominated named reads of notification
//!   delivery/disposition, exact expiring approvals, task/verifier/outcome and
//!   privacy records, binds their source revisions and the evaluation window
//!   consistently, and returns either a complete package or a partial package
//!   carrying the exact gaps. A missing read is an explicit
//!   [`HumanAttentionReadPresentation::Unavailable`] entry with its reason, so
//!   unavailable evidence yields a partial/inconclusive assembly, never
//!   synthetic zeros: this module invents no counts, no denominators and no
//!   observations.
//! - **W4, conditional comparison.** [`assemble_human_attention_claims`]
//!   derives record claims from the observed metrics only. A descriptive record
//!   stays useful without a control; every difference, prevention and
//!   false-negative conclusion requires the declared matched control profile
//!   plus applicable task-risk/exposure context, and preserves selection bias,
//!   censoring, intervention effects and alternative explanations. The closed
//!   claim vocabulary carries no superiority or overall-ranking kind, and this
//!   module emits no aggregate score, so a quieter or stricter profile is never
//!   ranked automatically better.
//!
//! # Boundary
//!
//! Every input is a value the caller already nominated; this module performs no
//! owner read, no clock read, no I/O and no live query, and it holds no
//! authority beyond the assembly it returns. The caller nominates evidence but
//! neither authorizes access to it nor establishes its completeness:
//! authorization stays with the evaluator identity and the owner admission
//! path, and completeness is decided by the record validator downstream, not
//! here. Analysis that needs bounded jobs uses separately admitted jobs on the
//! caller side; this module starts no telemetry collector and makes no model
//! call on a synchronous control gate.
//!
//! The persistence, authorization and projection legs (record creation and
//! correction, canonical transition and receipt, role-filtered ControlBoard
//! view) are separate work owned by their own seams; the assembled
//! [`BoundHumanAttentionEvidence`] and the derived claims are the exact inputs
//! those legs consume.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use eliot_contracts::{ArtifactId, ContractId};
use eliot_evaluation_contracts::{
    ComparisonBasis, HumanAttentionClaim, HumanAttentionClaimApplicability,
    HumanAttentionClaimBasis, HumanAttentionClaimCaveat, HumanAttentionClaimKind,
    HumanAttentionEvidenceKind, HumanAttentionMethod, HumanAttentionMetric,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Named owner-read slot feeding a Human attention evaluation.
///
/// The four slots are different counts from different owners: deduplicated
/// inbox items, delivery attempts and distinct risk events must never be
/// conflated, and neither may stand in for an expiring approval boundary, a
/// task/verifier outcome, or a privacy assessment.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HumanAttentionReadSlot {
    /// Named read of notification delivery and disposition.
    NotificationDeliveryDisposition,
    /// Named read of exact expiring approvals.
    ExpiringApprovals,
    /// Named read of task, verifier and outcome records.
    TaskVerifierOutcome,
    /// Named read of privacy records.
    PrivacyRecords,
}

impl HumanAttentionReadSlot {
    /// Stable read name used in errors, gaps and bound receipts.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotificationDeliveryDisposition => "notification_delivery_disposition",
            Self::ExpiringApprovals => "expiring_approvals",
            Self::TaskVerifierOutcome => "task_verifier_outcome",
            Self::PrivacyRecords => "privacy_records",
        }
    }
}

impl fmt::Display for HumanAttentionReadSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One caller-nominated named owner read.
///
/// The caller presents the exact owner-issued source revision it read and the
/// evaluation window the read was taken for. The Governor binds them; it never
/// re-reads the owner, never authorizes the access, and never declares the
/// read complete.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NominatedHumanAttentionRead {
    /// Which of the four named slots this nomination fills.
    pub read: HumanAttentionReadSlot,
    /// Exact owner-issued source revision the caller read.
    pub source_revision: String,
    /// Evaluation window the read was taken for; must equal the request window.
    pub window_ref: ContractId,
    /// Evidence artifacts the caller nominates from that read. A present read
    /// always names at least one artifact: an observed zero still names the
    /// read that observed it, so an empty nomination is refused and the caller
    /// presents a gap instead.
    pub evidence_refs: Vec<ArtifactId>,
    /// Contract evidence kinds this read feeds. Admissibility of a kind for a
    /// given metric is enforced by the record validator downstream.
    pub evidence_kinds: Vec<HumanAttentionEvidenceKind>,
}

/// Presentation of one read slot: either the caller nominated a read, or the
/// read is unavailable with its exact reason.
///
/// There is no third state. A missing read never becomes an empty nomination
/// or a zero; it becomes a gap the partial assembly carries.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum HumanAttentionReadPresentation {
    /// The caller nominated the owner read for this slot.
    Nominated(NominatedHumanAttentionRead),
    /// The read is unavailable. The reason names the exact gap, for example
    /// which owner could not serve the read inside the evaluation window.
    Unavailable {
        /// Exact reason the read could not be nominated.
        reason: String,
    },
}

/// Caller request to assemble bounded owner evidence for one evaluation window.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionEvidenceRequest {
    /// Evaluation window every nominated read must bind.
    pub evaluation_window_ref: ContractId,
    /// Named read of notification delivery and disposition.
    pub notification_delivery_disposition: HumanAttentionReadPresentation,
    /// Named read of exact expiring approvals.
    pub expiring_approvals: HumanAttentionReadPresentation,
    /// Named read of task, verifier and outcome records.
    pub task_verifier_outcome: HumanAttentionReadPresentation,
    /// Named read of privacy records.
    pub privacy_records: HumanAttentionReadPresentation,
}

/// One bound read: the nominated evidence the assembly accepted unchanged.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundHumanAttentionRead {
    /// Which named slot this read fills.
    pub read: HumanAttentionReadSlot,
    /// Exact owner-issued source revision the caller read.
    pub source_revision: String,
    /// Evidence artifacts the caller nominated, deduplicated and in order.
    pub evidence_refs: Vec<ArtifactId>,
    /// Contract evidence kinds this read feeds.
    pub evidence_kinds: Vec<HumanAttentionEvidenceKind>,
}

/// Exact gap left by one unavailable read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionEvidenceGap {
    /// Which named slot has no nominated read.
    pub read: HumanAttentionReadSlot,
    /// Exact reason the caller gave for the missing read.
    pub reason: String,
}

/// Assembled bounded owner evidence for one evaluation window.
///
/// A complete assembly carries all four bound reads and no gaps. A partial
/// assembly carries the reads that were available alongside the exact gaps, so
/// the persistence leg records the available metrics as explicit unknowns with
/// their reasons rather than as zeros. Use
/// [`BoundHumanAttentionEvidence::require_complete`] where a caller needs the
/// complete package only.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundHumanAttentionEvidence {
    /// Evaluation window every bound read was taken for.
    pub evaluation_window_ref: ContractId,
    /// Accepted reads in slot order.
    pub bound_reads: Vec<BoundHumanAttentionRead>,
    /// Exact gaps for the slots with no nominated read.
    pub gaps: Vec<HumanAttentionEvidenceGap>,
}

impl BoundHumanAttentionEvidence {
    /// Whether every named slot carries a bound read.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    /// Refuses a partial assembly for callers that need the complete package.
    ///
    /// The refusal carries the missing slots; it deletes nothing and invents
    /// nothing.
    pub fn require_complete(&self) -> Result<(), HumanAttentionEvaluationError> {
        if self.is_complete() {
            return Ok(());
        }
        Err(HumanAttentionEvaluationError::PartialEvidence {
            gaps: self.gaps.iter().map(|gap| gap.read).collect(),
        })
    }
}

/// Fail-closed errors of the Human attention evaluation assembly.
///
/// A missing read is never an error: it becomes a gap on the partial assembly.
/// These errors refuse malformed nominations and unsupported conclusions only.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HumanAttentionEvaluationError {
    /// A required text field is blank or contains control characters.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText {
        /// Field that failed text validation.
        field: &'static str,
    },
    /// A nomination was presented in the wrong read slot.
    #[error("nominated read belongs to slot {presented}, not to slot {expected}")]
    ReadSlotMismatch {
        /// Slot the request field requires.
        expected: HumanAttentionReadSlot,
        /// Slot the nomination actually names.
        presented: HumanAttentionReadSlot,
    },
    /// A present read nominates no evidence. An observed zero still names the
    /// read that observed it, so the caller must present a gap instead.
    #[error("nominated {read} carries no evidence references; present a gap instead")]
    EmptyEvidenceRefs {
        /// Slot whose nomination is empty.
        read: HumanAttentionReadSlot,
    },
    /// The same artifact was nominated twice in one read.
    #[error("nominated {read} names the same evidence artifact twice")]
    DuplicateEvidenceRef {
        /// Slot whose nomination repeats an artifact.
        read: HumanAttentionReadSlot,
    },
    /// A present read declares no contract evidence kind.
    #[error("nominated {read} declares no contract evidence kind")]
    NoEvidenceKinds {
        /// Slot whose nomination declares no kind.
        read: HumanAttentionReadSlot,
    },
    /// A nominated read was taken for a different evaluation window.
    #[error("nominated {read} binds a different evaluation window")]
    WindowMismatch {
        /// Slot whose window disagrees with the request window.
        read: HumanAttentionReadSlot,
    },
    /// The assembly is partial; the missing slots travel with the refusal.
    #[error("evidence assembly is partial; no complete package was produced")]
    PartialEvidence {
        /// Slots with no nominated read.
        gaps: Vec<HumanAttentionReadSlot>,
    },
    /// A comparative conclusion has no declared comparison basis at all.
    #[error("a comparative conclusion requires a declared comparison basis")]
    NoDeclaredComparisonBasis,
    /// A comparative conclusion rests on a declared basis that is not the
    /// matched control profile. Pre-change, memory-free and historical
    /// references remain admissible as descriptive context, never as the basis
    /// of a comparative conclusion.
    #[error("a comparative conclusion requires the declared matched control profile")]
    UnmatchedComparisonBasis,
    /// A comparative claim names a profile the record method never declared.
    #[error("comparative claim names an undeclared comparator profile")]
    UnknownMatchedProfile {
        /// Profile the claim names.
        profile: String,
    },
    /// A comparative conclusion drops a required caveat statement.
    #[error("comparative conclusion requires a non-blank {caveat} statement")]
    BlankCaveat {
        /// Caveat whose statement is blank: selection_bias, censoring,
        /// intervention_effect or alternative_explanation.
        caveat: &'static str,
    },
    /// A claim rests on a metric the assembled record did not observe. An
    /// unknown or not-applicable measurement supports no conclusion.
    #[error("claim rests on a metric the record did not observe")]
    UnknownMetricSupport {
        /// Metric without an observed value.
        metric: HumanAttentionMetric,
    },
    /// A claim names no supporting metric.
    #[error("claim names no supporting metric")]
    EmptySupportingMetrics,
    /// A claim names the same supporting metric twice.
    #[error("claim names the same supporting metric twice")]
    DuplicateSupportingMetric {
        /// Repeated metric.
        metric: HumanAttentionMetric,
    },
    /// A prevention credit names no observed pre-exposure prevention count. A
    /// prevented action is credited only from an observed prevention count,
    /// never from a lower blocking or harm figure.
    #[error("attributed prevention requires an observed pre-exposure prevention count")]
    PreventionWithoutObservedPrevention,
    /// A suppression false-negative rate names no observed missed-critical
    /// count. It is never inferred from fewer emitted alerts.
    #[error("suppression false-negative rate requires an observed missed-critical count")]
    SuppressionWithoutMissedCritical,
    /// Volume and profile-shape metrics alone support no conclusion. They
    /// describe how much attention a policy asked for, not what it achieved.
    #[error("volume and profile shape alone support no conclusion")]
    VolumeOnlyConclusion,
    /// A comparator profile does not make a description a difference.
    #[error("only a descriptive observation may stand without a comparator profile")]
    BasisKindMismatch,
    /// Two requested claims share one reference.
    #[error("duplicate claim reference")]
    DuplicateClaimRef {
        /// Repeated claim reference.
        claim_ref: String,
    },
}

/// Declared matched comparison context for one comparative conclusion.
///
/// The matched profile reference must be one the record method declared, and
/// the conclusion applies only to the task-risk and exposure context named
/// here. All four caveats are always present: selection bias, censoring,
/// intervention effects and alternative explanations are preserved on every
/// comparative conclusion by construction.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionMatchedComparison {
    /// Comparator profile declared by the record method.
    pub matched_profile_ref: String,
    /// Task-risk context the conclusion applies to.
    pub task_risk_context: String,
    /// Exposure context the conclusion applies to.
    pub exposure_context: String,
    /// Preserved selection-bias statement.
    pub selection_bias: String,
    /// Preserved censoring statement.
    pub censoring: String,
    /// Preserved intervention-effect statement.
    pub intervention_effect: String,
    /// Preserved alternative-explanation statement.
    pub alternative_explanation: String,
}

/// One conclusion the production evaluator is asked to derive.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedHumanAttentionClaim {
    /// Stable claim reference, unique within the request.
    pub claim_ref: String,
    /// Closed claim kind. There is no superiority or overall-ranking kind, so
    /// no request can ask this module to rank a profile simply better.
    pub kind: HumanAttentionClaimKind,
    /// Claim statement.
    pub statement: String,
    /// Metrics the claim rests on. Each must be observed by the assembled
    /// record; an unknown cannot support a conclusion.
    pub supporting_metrics: Vec<HumanAttentionMetric>,
    /// Matched comparison context, or `None` for a descriptive observation
    /// that asserts no difference.
    pub comparison: Option<HumanAttentionMatchedComparison>,
}

/// Inputs to the production comparative evaluator.
pub struct HumanAttentionComparisonInput<'a> {
    /// Record method carrying the declared comparison basis and comparator
    /// profiles.
    pub method: &'a HumanAttentionMethod,
    /// Evaluation window descriptive claims must bind.
    pub observation_window_ref: &'a ContractId,
    /// Metrics the assembled record measured with an observed value.
    pub observed_metrics: &'a [HumanAttentionMetric],
    /// Requested conclusions in output order.
    pub requested: &'a [RequestedHumanAttentionClaim],
}

/// Assemble bounded owner evidence for one evaluation window.
///
/// This is the W3 producer: a pure function of the caller-nominated reads. It
/// binds source revisions and the evaluation window consistently, keeps every
/// nominated artifact unchanged, and turns each unavailable read into an exact
/// gap. Missing evidence never becomes a zero, a denominator, or an
/// observation; it becomes a [`HumanAttentionEvidenceGap`] the persistence leg
/// records as an explicit unknown with its reason.
///
/// The call fails closed only on malformed nominations: a blank or
/// control-character revision or gap reason, a nomination in the wrong slot, an
/// empty or duplicate-bearing nomination, a nomination without a contract
/// evidence kind, or a read bound to a different window.
#[must_use = "the assembled evidence or its exact gaps must be recorded, not discarded"]
pub fn assemble_human_attention_evidence(
    request: &HumanAttentionEvidenceRequest,
) -> Result<BoundHumanAttentionEvidence, HumanAttentionEvaluationError> {
    let mut bound_reads = Vec::with_capacity(4);
    let mut gaps = Vec::new();
    bind_slot(
        &request.notification_delivery_disposition,
        HumanAttentionReadSlot::NotificationDeliveryDisposition,
        &request.evaluation_window_ref,
        &mut bound_reads,
        &mut gaps,
    )?;
    bind_slot(
        &request.expiring_approvals,
        HumanAttentionReadSlot::ExpiringApprovals,
        &request.evaluation_window_ref,
        &mut bound_reads,
        &mut gaps,
    )?;
    bind_slot(
        &request.task_verifier_outcome,
        HumanAttentionReadSlot::TaskVerifierOutcome,
        &request.evaluation_window_ref,
        &mut bound_reads,
        &mut gaps,
    )?;
    bind_slot(
        &request.privacy_records,
        HumanAttentionReadSlot::PrivacyRecords,
        &request.evaluation_window_ref,
        &mut bound_reads,
        &mut gaps,
    )?;
    Ok(BoundHumanAttentionEvidence {
        evaluation_window_ref: request.evaluation_window_ref.clone(),
        bound_reads,
        gaps,
    })
}

/// Derive conditional record claims from the observed metrics.
///
/// This is the W4 production evaluator: a descriptive request always yields a
/// window-bound descriptive claim, while every difference, prevention and
/// false-negative conclusion is admitted only on the declared matched control
/// profile with applicable task-risk/exposure context and all four preserved
/// caveats. Prevention is credited only from an observed pre-exposure
/// prevention count, a suppression false-negative rate only from an observed
/// missed-critical count, and volume or profile shape alone supports no
/// conclusion. The call fails closed on any unsupported request; it never
/// weakens a request into a descriptive claim and never emits a ranking.
#[must_use = "the derived claims or their exact refusal must be recorded, not discarded"]
pub fn assemble_human_attention_claims(
    input: &HumanAttentionComparisonInput<'_>,
) -> Result<Vec<HumanAttentionClaim>, HumanAttentionEvaluationError> {
    let mut seen_refs = BTreeSet::new();
    let mut claims = Vec::with_capacity(input.requested.len());
    for requested in input.requested {
        non_blank(&requested.claim_ref, "human_attention_claim.claim_ref")?;
        non_blank(&requested.statement, "human_attention_claim.statement")?;
        if !seen_refs.insert(requested.claim_ref.as_str()) {
            return Err(HumanAttentionEvaluationError::DuplicateClaimRef {
                claim_ref: requested.claim_ref.clone(),
            });
        }
        validate_supporting_metrics(requested, input.observed_metrics)?;
        let basis = assemble_claim_basis(requested, input)?;
        claims.push(HumanAttentionClaim {
            claim_ref: requested.claim_ref.clone(),
            kind: requested.kind,
            statement: requested.statement.clone(),
            supporting_metrics: requested.supporting_metrics.clone(),
            basis,
        });
    }
    Ok(claims)
}

/// Volume, delivery and profile-shape metrics.
///
/// Mirrors the closed contract set: these metrics describe how much attention
/// a policy asked for, not what it achieved, so they can never be the sole
/// support of a comparative conclusion.
const fn is_volume_or_profile_shape(metric: HumanAttentionMetric) -> bool {
    use HumanAttentionMetric as M;
    matches!(
        metric,
        M::DeduplicatedInboxItems
            | M::DeliveryAttempts
            | M::NotificationApprovalAndTelemetryProfile
            | M::PolicyAndTaskRiskProfile
    )
}

fn non_blank(value: &str, field: &'static str) -> Result<(), HumanAttentionEvaluationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(HumanAttentionEvaluationError::InvalidText { field });
    }
    Ok(())
}

fn bind_slot(
    presentation: &HumanAttentionReadPresentation,
    expected: HumanAttentionReadSlot,
    window_ref: &ContractId,
    bound_reads: &mut Vec<BoundHumanAttentionRead>,
    gaps: &mut Vec<HumanAttentionEvidenceGap>,
) -> Result<(), HumanAttentionEvaluationError> {
    match presentation {
        HumanAttentionReadPresentation::Nominated(nominated) => {
            if nominated.read != expected {
                return Err(HumanAttentionEvaluationError::ReadSlotMismatch {
                    expected,
                    presented: nominated.read,
                });
            }
            non_blank(
                &nominated.source_revision,
                "human_attention_evidence.read.source_revision",
            )?;
            if nominated.window_ref != *window_ref {
                return Err(HumanAttentionEvaluationError::WindowMismatch {
                    read: nominated.read,
                });
            }
            if nominated.evidence_refs.is_empty() {
                return Err(HumanAttentionEvaluationError::EmptyEvidenceRefs {
                    read: nominated.read,
                });
            }
            let mut seen = BTreeSet::new();
            for evidence_ref in &nominated.evidence_refs {
                if !seen.insert(evidence_ref) {
                    return Err(HumanAttentionEvaluationError::DuplicateEvidenceRef {
                        read: nominated.read,
                    });
                }
            }
            if nominated.evidence_kinds.is_empty() {
                return Err(HumanAttentionEvaluationError::NoEvidenceKinds {
                    read: nominated.read,
                });
            }
            bound_reads.push(BoundHumanAttentionRead {
                read: nominated.read,
                source_revision: nominated.source_revision.clone(),
                evidence_refs: nominated.evidence_refs.clone(),
                evidence_kinds: nominated.evidence_kinds.clone(),
            });
            Ok(())
        }
        HumanAttentionReadPresentation::Unavailable { reason } => {
            non_blank(reason, "human_attention_evidence.unavailable.reason")?;
            gaps.push(HumanAttentionEvidenceGap {
                read: expected,
                reason: reason.clone(),
            });
            Ok(())
        }
    }
}

fn validate_supporting_metrics(
    requested: &RequestedHumanAttentionClaim,
    observed_metrics: &[HumanAttentionMetric],
) -> Result<(), HumanAttentionEvaluationError> {
    if requested.supporting_metrics.is_empty() {
        return Err(HumanAttentionEvaluationError::EmptySupportingMetrics);
    }
    let mut seen = BTreeSet::new();
    for metric in &requested.supporting_metrics {
        if !seen.insert(*metric) {
            return Err(HumanAttentionEvaluationError::DuplicateSupportingMetric {
                metric: *metric,
            });
        }
        if !observed_metrics.contains(metric) {
            return Err(HumanAttentionEvaluationError::UnknownMetricSupport {
                metric: *metric,
            });
        }
    }
    Ok(())
}

fn assemble_claim_basis(
    requested: &RequestedHumanAttentionClaim,
    input: &HumanAttentionComparisonInput<'_>,
) -> Result<HumanAttentionClaimBasis, HumanAttentionEvaluationError> {
    match (&requested.comparison, requested.kind) {
        (None, HumanAttentionClaimKind::DescriptiveObservation) => {
            Ok(HumanAttentionClaimBasis::Descriptive {
                observation_window_ref: input.observation_window_ref.clone(),
            })
        }
        (Some(_), HumanAttentionClaimKind::DescriptiveObservation) => {
            Err(HumanAttentionEvaluationError::BasisKindMismatch)
        }
        (None, _) => Err(HumanAttentionEvaluationError::NoDeclaredComparisonBasis),
        (Some(comparison), kind) => {
            require_matched_basis(input.method)?;
            validate_matched_profile(comparison, input.method)?;
            validate_kind_evidence(requested, kind)?;
            Ok(HumanAttentionClaimBasis::Comparative {
                matched_profile_ref: comparison.matched_profile_ref.clone(),
                applicability: HumanAttentionClaimApplicability {
                    task_risk_context: comparison.task_risk_context.clone(),
                    exposure_context: comparison.exposure_context.clone(),
                },
                caveats: vec![
                    HumanAttentionClaimCaveat::SelectionBias {
                        statement: comparison.selection_bias.clone(),
                    },
                    HumanAttentionClaimCaveat::Censoring {
                        statement: comparison.censoring.clone(),
                    },
                    HumanAttentionClaimCaveat::InterventionEffect {
                        statement: comparison.intervention_effect.clone(),
                    },
                    HumanAttentionClaimCaveat::AlternativeExplanation {
                        statement: comparison.alternative_explanation.clone(),
                    },
                ],
            })
        }
    }
}

/// A comparative conclusion requires the declared matched control profile:
/// the `MatchedControl` basis is the matched-or-paired profile I11.10
/// requires. Any other declared basis stays admissible as descriptive context
/// but cannot carry a comparative conclusion.
fn require_matched_basis(
    method: &HumanAttentionMethod,
) -> Result<(), HumanAttentionEvaluationError> {
    if matches!(
        &method.comparison_basis,
        ComparisonBasis::None | ComparisonBasis::NotApplicableWithReason
    ) {
        return Err(HumanAttentionEvaluationError::NoDeclaredComparisonBasis);
    }
    if method.comparison_basis != ComparisonBasis::MatchedControl {
        return Err(HumanAttentionEvaluationError::UnmatchedComparisonBasis);
    }
    Ok(())
}

fn validate_matched_profile(
    comparison: &HumanAttentionMatchedComparison,
    method: &HumanAttentionMethod,
) -> Result<(), HumanAttentionEvaluationError> {
    non_blank(
        &comparison.matched_profile_ref,
        "human_attention_claim.basis.matched_profile_ref",
    )?;
    if !method
        .comparator_profile_refs
        .iter()
        .any(|profile| profile == &comparison.matched_profile_ref)
    {
        return Err(HumanAttentionEvaluationError::UnknownMatchedProfile {
            profile: comparison.matched_profile_ref.clone(),
        });
    }
    non_blank(
        &comparison.task_risk_context,
        "human_attention_claim.basis.applicability.task_risk_context",
    )?;
    non_blank(
        &comparison.exposure_context,
        "human_attention_claim.basis.applicability.exposure_context",
    )?;
    validate_caveat(&comparison.selection_bias, "selection_bias")?;
    validate_caveat(&comparison.censoring, "censoring")?;
    validate_caveat(&comparison.intervention_effect, "intervention_effect")?;
    validate_caveat(&comparison.alternative_explanation, "alternative_explanation")?;
    Ok(())
}

fn validate_caveat(
    statement: &str,
    caveat: &'static str,
) -> Result<(), HumanAttentionEvaluationError> {
    if statement.trim().is_empty() || statement.chars().any(char::is_control) {
        return Err(HumanAttentionEvaluationError::BlankCaveat { caveat });
    }
    Ok(())
}

/// A prevented action is credited only from an observed pre-exposure
/// prevention count, a suppression false-negative rate only from an observed
/// missed-critical count, and volume or profile shape alone supports no
/// conclusion: neither prevention nor a false-negative rate is inferred from
/// a lower blocking, harm, or alert figure.
fn validate_kind_evidence(
    requested: &RequestedHumanAttentionClaim,
    kind: HumanAttentionClaimKind,
) -> Result<(), HumanAttentionEvaluationError> {
    match kind {
        HumanAttentionClaimKind::DescriptiveObservation => {
            Err(HumanAttentionEvaluationError::BasisKindMismatch)
        }
        HumanAttentionClaimKind::AttributedPrevention
            if !requested
                .supporting_metrics
                .contains(&HumanAttentionMetric::PreExposurePreventionEvents) =>
        {
            Err(HumanAttentionEvaluationError::PreventionWithoutObservedPrevention)
        }
        HumanAttentionClaimKind::SuppressionFalseNegative
            if !requested
                .supporting_metrics
                .contains(&HumanAttentionMetric::MissedCriticalRiskEvents) =>
        {
            Err(HumanAttentionEvaluationError::SuppressionWithoutMissedCritical)
        }
        _ if requested
            .supporting_metrics
            .iter()
            .all(|metric| is_volume_or_profile_shape(*metric)) =>
        {
            Err(HumanAttentionEvaluationError::VolumeOnlyConclusion)
        }
        _ => Ok(()),
    }
}
