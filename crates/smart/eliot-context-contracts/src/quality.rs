//! Independent normative quality dimensions.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContextBinding, ContextError, MeasurementRef};

/// Wire revision of [`QualityDimensionResult`].
///
/// Result schema 1 carried a bare Boolean `passed`. That type could not express
/// `UNKNOWN`, `DEGRADED` or `NOT_APPLICABLE`, so an unevaluated dimension and a
/// passing one were the same value on the wire. Schema 2 replaces it with the
/// closed [`QualityDimensionState`] and adds the required evidence/member set
/// and the rule revision that graded the dimension.
///
/// Compatibility decision, following the `CurrentSystemEvidenceSnapshot`
/// boundary in `eliot-bootstrap`: the declared boundary became a required
/// serialized field, the wire shape changed, and there is deliberately **no
/// default, no clock fallback and no inference** from the old Boolean.
/// Re-emitting a schema-1 result under this shape requires its evidence owner to
/// supply the state, the required member set and the rule revision again. A
/// schema-1 payload is rejected, never reinterpreted: `passed` is not a field of
/// [`QualityDimensionResult`] any more, and that struct denies unknown fields.
pub const QUALITY_RESULT_SCHEMA_VERSION: u32 = 2;

/// The twelve exact I12.13 quality dimensions.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityDimension {
    AcceptanceDecisionCoverage,
    CausalOperationalSufficiency,
    ExactAnchorProvenanceCoverage,
    FreshnessStateFenceCoherence,
    RivalsConflictsUnknownsVisibility,
    NegativeMemoryInvariantCoverage,
    VerifierActionReadiness,
    RouteAccessibilityLayoutRisk,
    InstructionSufficiency,
    PayloadHandleReconstructionCost,
    KnownOmissionsExpansionPaths,
    TelemetryMeasurementCostCoverage,
}

/// The twelve I12.13 dimensions in canonical order.
///
/// Every scorecard carries exactly one result per entry. Omitting a dimension
/// is a structural failure, never a shortcut to success. This constant is the
/// independent denominator of that rule: it is declared here, not supplied by
/// the caller whose scorecard is being checked.
pub const QUALITY_DIMENSIONS: [QualityDimension; 12] = [
    QualityDimension::AcceptanceDecisionCoverage,
    QualityDimension::CausalOperationalSufficiency,
    QualityDimension::ExactAnchorProvenanceCoverage,
    QualityDimension::FreshnessStateFenceCoherence,
    QualityDimension::RivalsConflictsUnknownsVisibility,
    QualityDimension::NegativeMemoryInvariantCoverage,
    QualityDimension::VerifierActionReadiness,
    QualityDimension::RouteAccessibilityLayoutRisk,
    QualityDimension::InstructionSufficiency,
    QualityDimension::PayloadHandleReconstructionCost,
    QualityDimension::KnownOmissionsExpansionPaths,
    QualityDimension::TelemetryMeasurementCostCoverage,
];

/// Closed outcome of one independent quality dimension.
///
/// I12.13 emits a vector, never a scalar. A failed, unknown, degraded or
/// policy-not-applicable dimension has no spelling that reads as a pass, and an
/// inapplicable or degraded dimension carries the explicit reason that admits
/// it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityDimensionState {
    /// Observed evidence covers the dimension.
    Passed,
    /// The dimension failed; the failed invariant or unknown evidence names why.
    Failed,
    /// Required evidence, or the dimension's applicability, is not known.
    Unknown,
    /// Allowed whole-unit degradation with an explicit reason.
    Degraded {
        /// Explicit degradation reason; never empty.
        reason: String,
    },
    /// The dimension does not apply under the governing policy, with the
    /// policy reason that makes it inapplicable.
    NotApplicable {
        /// Policy reason for inapplicability; never empty.
        reason: String,
    },
}

impl QualityDimensionState {
    /// Whether this dimension is an observed pass. Every other state is not a
    /// pass, so a weaker state can never be read as success.
    #[must_use]
    pub const fn is_pass(&self) -> bool {
        matches!(self, Self::Passed)
    }

    /// The explicit reason carried by a degraded or not-applicable state.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Degraded { reason } | Self::NotApplicable { reason } => Some(reason),
            _ => None,
        }
    }

    fn validate(&self) -> Result<(), ContextError> {
        if let Some(reason) = self.reason() {
            crate::validate_text(reason, "quality.state.reason")?;
        }
        Ok(())
    }
}

/// Explicit schema-2 reader for the closed dimension state.
///
/// A bare Boolean is rejected here by name and by version instead of being
/// mapped onto a state. The mapping is not merely cosmetic: a schema-1 `true`
/// is indistinguishable from a graded pass, and a schema-1 `false` is
/// indistinguishable from `UNKNOWN`, `DEGRADED` or `NOT_APPLICABLE`, so
/// accepting either would fabricate a definite grade the wire never carried.
/// There is no permissive fallback and no default; the migration instruction is
/// part of the error.
fn deserialize_dimension_state<'de, D>(deserializer: D) -> Result<QualityDimensionState, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let message = format!(
        "quality result schema 1 Boolean `passed` is not readable as quality result schema \
         {QUALITY_RESULT_SCHEMA_VERSION}: re-emit it as `state` and supply `schema_version`, \
         `rule_revision` and `required_evidence`"
    );
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Bool(_) => Err(<D::Error as serde::de::Error>::custom(message)),
        other => serde_json::from_value(other).map_err(<D::Error as serde::de::Error>::custom),
    }
}

/// One independent dimension result. There is no aggregate scalar.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityDimensionResult {
    /// Wire revision this result was emitted under; never defaulted.
    pub schema_version: u32,
    pub dimension: QualityDimension,
    /// Closed outcome for this dimension.
    ///
    /// Serialization always writes this closed state under this name, so the
    /// migration from the schema-1 Boolean has exactly one direction.
    #[serde(deserialize_with = "deserialize_dimension_state")]
    pub state: QualityDimensionState,
    /// Rule or profile revision that produced this grade.
    pub rule_revision: ArtifactId,
    /// Required evidence/member set for this dimension under that revision.
    ///
    /// A pass is only a pass when every required member was actually observed,
    /// so a partially observed dimension cannot report a confident pass.
    pub required_evidence: Vec<ArtifactId>,
    /// Evidence observed by the current compilation.
    pub evidence: Vec<ArtifactId>,
    pub measurements: Vec<MeasurementRef>,
    pub failed_invariant: Option<ArtifactId>,
    /// Missing or stale elements: exactly what the dimension still lacks.
    pub unknown_evidence: Vec<ArtifactId>,
    pub proof_ceiling: ProofCeiling,
    pub invalidation: Option<ArtifactId>,
    pub binding: ContextBinding,
}

impl QualityDimensionResult {
    fn validate(&self, scorecard_binding: &ContextBinding) -> Result<(), ContextError> {
        if self.schema_version != QUALITY_RESULT_SCHEMA_VERSION
            || self.binding != *scorecard_binding
        {
            return Err(ContextError::QualityIncomplete);
        }
        self.state.validate()?;
        crate::validate_text(self.rule_revision.as_str(), "quality.rule_revision")?;
        match &self.state {
            // A pass is exactly the whole required member set, observed, with
            // no failure and no missing or stale element. A bare valid-looking
            // handle that covers only part of the required set is not a pass.
            QualityDimensionState::Passed => {
                let observed: BTreeSet<&ArtifactId> = self.evidence.iter().collect();
                let complete = !self.required_evidence.is_empty()
                    && self
                        .required_evidence
                        .iter()
                        .all(|member| observed.contains(member));
                if !complete || self.failed_invariant.is_some() || !self.unknown_evidence.is_empty()
                {
                    return Err(ContextError::QualityIncomplete);
                }
            }
            // Failure, unknown evidence and allowed degradation all still
            // name the exact failed invariant or missing element.
            QualityDimensionState::Failed
            | QualityDimensionState::Unknown
            | QualityDimensionState::Degraded { .. } => {
                if self.failed_invariant.is_none() && self.unknown_evidence.is_empty() {
                    return Err(ContextError::QualityIncomplete);
                }
            }
            // A policy reason may make the dimension inapplicable; it may
            // not hide a failed invariant behind that reason.
            QualityDimensionState::NotApplicable { .. } => {
                if self.failed_invariant.is_some() {
                    return Err(ContextError::QualityIncomplete);
                }
            }
        }
        for measurement in &self.measurements {
            measurement.validate()?;
        }
        Ok(())
    }
}

/// One applicability input that must resolve before a packet is graded.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityApplicabilityInput {
    /// The task and its acceptance criteria applicable to this packet.
    TaskAcceptance,
    /// The route this packet is compiled for.
    Route,
    /// The impact classification of the requested effect.
    Impact,
    /// The governing Governance Profile.
    GovernanceProfile,
    /// The protected Safety Floor.
    ProtectedFloor,
    /// The currently active directives.
    ActiveDirective,
}

/// The six applicability inputs, in canonical order.
///
/// This constant is the independent denominator of the applicability rule: a
/// resolution that does not account for every input here is structurally
/// incomplete, not a narrower profile.
pub const QUALITY_APPLICABILITY_INPUTS: [QualityApplicabilityInput; 6] = [
    QualityApplicabilityInput::TaskAcceptance,
    QualityApplicabilityInput::Route,
    QualityApplicabilityInput::Impact,
    QualityApplicabilityInput::GovernanceProfile,
    QualityApplicabilityInput::ProtectedFloor,
    QualityApplicabilityInput::ActiveDirective,
];

/// Resolved applicability of one compiled packet, recorded before grading.
///
/// `resolved` and `unknown` partition [`QUALITY_APPLICABILITY_INPUTS`]. An
/// unknown input is not resolved to the weakest governing profile and it is not
/// dropped: it blocks the dependent decision or effect that needs it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityApplicability {
    /// Inputs resolved to one governing answer before grading began.
    pub resolved: Vec<QualityApplicabilityInput>,
    /// Inputs whose governing answer is still unknown.
    pub unknown: Vec<QualityApplicabilityInput>,
}

impl QualityApplicability {
    fn distinct(
        values: &[QualityApplicabilityInput],
        field: &'static str,
    ) -> Result<BTreeSet<QualityApplicabilityInput>, ContextError> {
        let distinct: BTreeSet<QualityApplicabilityInput> = values.iter().copied().collect();
        if distinct.len() != values.len() {
            return Err(ContextError::InvalidField(field));
        }
        Ok(distinct)
    }

    /// Whether every declared input is accounted for exactly once, as either
    /// resolved or unknown.
    pub fn validate(&self) -> Result<(), ContextError> {
        let resolved = Self::distinct(&self.resolved, "quality.applicability.resolved")?;
        let unknown = Self::distinct(&self.unknown, "quality.applicability.unknown")?;
        let denominator: BTreeSet<QualityApplicabilityInput> =
            QUALITY_APPLICABILITY_INPUTS.into_iter().collect();
        if !resolved.is_disjoint(&unknown) || !resolved.union(&unknown).eq(&denominator) {
            return Err(ContextError::QualityIncomplete);
        }
        Ok(())
    }

    /// The unresolved inputs, in canonical order.
    #[must_use]
    pub fn unresolved(&self) -> Vec<QualityApplicabilityInput> {
        let mut ordered: Vec<QualityApplicabilityInput> = self
            .unknown
            .iter()
            .copied()
            .filter(|input| QUALITY_APPLICABILITY_INPUTS.contains(input))
            .collect();
        ordered.sort_unstable();
        ordered.dedup();
        ordered
    }
}

/// Closed twelve-axis quality scorecard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityScorecard {
    pub binding: ContextBinding,
    /// Applicability resolved for this packet before its dimensions were
    /// graded; never inferred from the grades themselves.
    pub applicability: QualityApplicability,
    pub results: Vec<QualityDimensionResult>,
}

/// A requested dependent decision or effect of one compiled packet.
///
/// I12.13 degradation is whole-unit and operation-specific: a blocked dimension
/// refuses the dependent decision or effect it binds to, while read-only
/// diagnostic display stays available with its limitations visible.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityOperation {
    /// Read-only diagnostic display of a compiled or explicitly incomplete
    /// packet. No dimension is mandatory here, so an incomplete packet stays
    /// displayable with every failed and unknown result visible.
    DiagnosticDisplay,
    /// Compile the packet and hand the assembled view to its consumer.
    Compile,
    /// Perform the dependent decision or effect the packet supports.
    DependentAction,
}

impl QualityOperation {
    /// The dimensions this operation independently requires.
    ///
    /// The relation is a closed function of the operation, so an unresolved
    /// applicability cannot select the weakest profile: it either names the
    /// mandatory dimensions or blocks the action. `Compile` requires all
    /// twelve, which is the protection every current consumer already relies
    /// on, and `DependentAction` requires the exact anchor/provenance, active
    /// directive and required verifier readiness that enable the effect.
    #[must_use]
    pub fn required_dimensions(self) -> &'static [QualityDimension] {
        match self {
            Self::DiagnosticDisplay => &[],
            Self::Compile => &QUALITY_DIMENSIONS,
            Self::DependentAction => &[
                QualityDimension::ExactAnchorProvenanceCoverage,
                QualityDimension::InstructionSufficiency,
                QualityDimension::VerifierActionReadiness,
            ],
        }
    }

    /// Whether an unresolved applicability input blocks this operation.
    ///
    /// Only read-only diagnostic display tolerates an unknown input, and it
    /// still reports it. Every dependent decision or effect blocks: an unknown
    /// applicability is a block, never an optimistic grade and never a skip.
    #[must_use]
    pub const fn blocks_on_unresolved_applicability(self) -> bool {
        matches!(self, Self::Compile | Self::DependentAction)
    }
}

/// Machine-readable suitability refusal class; consumers branch on this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityRefusalKind {
    /// The scorecard is not structurally valid, so it describes no gradeable
    /// packet and no suitability can be read from it.
    InvalidScorecard,
    /// The applicability of the packet is unknown, so the dependent action is
    /// blocked before any dimension is read as sufficient.
    ApplicabilityUnknown,
    /// The requested operation is blocked by the named dimension results.
    OperationBlocked,
}

/// Typed refusal naming the requested operation and every exact dimension
/// result that blocks it. There is no aggregate verdict to read instead.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityRefusal {
    /// Machine-readable refusal class.
    pub kind: QualityRefusalKind,
    /// The requested dependent decision or effect; always named.
    pub operation: QualityOperation,
    /// Exact blocking dimension results in canonical dimension order, carrying
    /// the state and the evidence each blocking result lacks. Empty only for
    /// [`QualityRefusalKind::InvalidScorecard`].
    pub blocking: Vec<QualityDimensionResult>,
    /// Applicability inputs that were never resolved. Empty only for
    /// [`QualityRefusalKind::InvalidScorecard`], and carried alongside the
    /// blocking results so no unresolved input is hidden by a dimension grade.
    pub unresolved_applicability: Vec<QualityApplicabilityInput>,
}

/// Granted suitability of one operation, carrying its remaining limitations.
///
/// A block is an error; a non-blocking uncertainty is a returned value. That is
/// what keeps an informational unknown visible without globally refusing
/// unrelated safe work.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualitySuitability {
    /// The operation this suitability was evaluated for.
    pub operation: QualityOperation,
    /// Applicability inputs that remain unknown and did not block this
    /// operation. Never empty for a blocking operation, because a blocking
    /// operation refuses instead of returning.
    pub unresolved_applicability: Vec<QualityApplicabilityInput>,
}

impl QualityScorecard {
    /// Validate exact closure and independent evidence for every dimension.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        self.applicability.validate()?;
        for result in &self.results {
            result.validate(&self.binding)?;
        }
        // Exactly one result per declared dimension, compared against the
        // constant denominator rather than against a count of this scorecard's
        // own entries. A missing, duplicated, extra or reordered entry makes the
        // ordered vectors differ.
        let declared: Vec<QualityDimension> =
            self.results.iter().map(|result| result.dimension).collect();
        let expected: Vec<QualityDimension> = QUALITY_DIMENSIONS.to_vec();
        if declared != expected {
            return Err(ContextError::QualityIncomplete);
        }
        Ok(())
    }

    /// Whether every one of the twelve dimensions is an observed pass.
    ///
    /// This is the operation-agnostic grading fact only. It grants no action
    /// readiness, authority or task Finish; use
    /// [`QualityScorecard::suitability`] for the requested operation.
    pub fn all_pass(&self) -> Result<bool, ContextError> {
        self.validate()?;
        Ok(self.results.iter().all(|result| result.state.is_pass()))
    }

    /// Check suitability for one requested dependent decision or effect.
    ///
    /// [`QualityScorecard::validate`] stays structural integrity; this is the
    /// separate operation-scoped readiness fact. Three things block, and none of
    /// them can be traded against the others:
    ///
    /// * every dimension in [`QualityOperation::required_dimensions`] must be
    ///   an observed pass, so a failed, unknown, degraded or not-applicable
    ///   dimension blocks its dependent action;
    /// * any unresolved applicability input blocks every operation except
    ///   read-only diagnostic display, which reports it instead;
    /// * `additional_required` carries the blockers a recipe selected. It is
    ///   unioned with the independently mandatory set, so it can add a
    ///   constraint but never remove one.
    pub fn suitability(
        &self,
        operation: QualityOperation,
        additional_required: &[QualityDimension],
    ) -> Result<QualitySuitability, QualityRefusal> {
        if self.validate().is_err() {
            return Err(QualityRefusal {
                kind: QualityRefusalKind::InvalidScorecard,
                operation,
                blocking: Vec::new(),
                unresolved_applicability: Vec::new(),
            });
        }
        let required: BTreeSet<QualityDimension> = operation
            .required_dimensions()
            .iter()
            .chain(additional_required)
            .copied()
            .collect();
        let blocking = self
            .results
            .iter()
            .filter(|result| required.contains(&result.dimension) && !result.state.is_pass())
            .cloned()
            .collect::<Vec<_>>();
        let unresolved_applicability = self.applicability.unresolved();
        let applicability_blocks =
            operation.blocks_on_unresolved_applicability() && !unresolved_applicability.is_empty();
        if blocking.is_empty() && !applicability_blocks {
            return Ok(QualitySuitability {
                operation,
                unresolved_applicability,
            });
        }
        Err(QualityRefusal {
            kind: if applicability_blocks {
                QualityRefusalKind::ApplicabilityUnknown
            } else {
                QualityRefusalKind::OperationBlocked
            },
            operation,
            blocking,
            unresolved_applicability,
        })
    }
}
