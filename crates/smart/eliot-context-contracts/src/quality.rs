//! Independent normative quality dimensions.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContextBinding, ContextError, MeasurementRef};

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
/// is a structural failure, never a shortcut to success.
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

/// Wire compatibility for the pre-migration Boolean `passed` field.
///
/// `true` maps to `PASSED` and `false` maps to `FAILED`. Neither mapping
/// fabricates evidence: the observed-evidence and failed-invariant requirements
/// of [`QualityScorecard::validate`] still apply to both mapped states.
#[derive(Deserialize)]
#[serde(untagged)]
enum QualityDimensionStateWire {
    Legacy(bool),
    State(QualityDimensionState),
}

fn deserialize_dimension_state<'de, D>(deserializer: D) -> Result<QualityDimensionState, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(
        match QualityDimensionStateWire::deserialize(deserializer)? {
            QualityDimensionStateWire::Legacy(true) => QualityDimensionState::Passed,
            QualityDimensionStateWire::Legacy(false) => QualityDimensionState::Failed,
            QualityDimensionStateWire::State(state) => state,
        },
    )
}

/// Rule/profile revision under which one dimension was graded.
///
/// I12.13 grades a dimension against the policy that was in force, never
/// against a caller preference. The revision is bound to the result so a
/// later policy change cannot silently leave an old grade standing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityRuleRevision {
    /// Recipe revision the grade was taken under.
    pub recipe_revision: eliot_contracts::TaskRevision,
    /// Canonical recipe policy digest the grade was taken under.
    pub recipe_digest: String,
    /// Governance Profile revision the grade was taken under.
    pub profile_revision: String,
}

impl QualityRuleRevision {
    /// Validate the revision identity a grade must bind.
    pub fn validate(&self) -> Result<(), ContextError> {
        crate::validate_digest(&self.recipe_digest, "quality.rule.recipe_digest")?;
        crate::validate_text(&self.profile_revision, "quality.rule.profile_revision")
    }
}

/// One independent dimension result. There is no aggregate scalar.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityDimensionResult {
    pub dimension: QualityDimension,
    /// Closed outcome for this dimension.
    ///
    /// The pre-migration wire spelling carried a bare Boolean `passed`. That
    /// spelling is still accepted on read and maps to `PASSED`/`FAILED`
    /// without inventing evidence; serialization always writes the closed
    /// state, so the migration has exactly one direction.
    #[serde(alias = "passed", deserialize_with = "deserialize_dimension_state")]
    pub state: QualityDimensionState,
    /// Members the governing rule required for this dimension. A pass claims
    /// every one of them is covered by `evidence`.
    pub required_evidence: Vec<ArtifactId>,
    /// Members actually observed for this dimension in this compilation.
    pub evidence: Vec<ArtifactId>,
    pub measurements: Vec<MeasurementRef>,
    /// Required members with no current observation.
    pub missing_evidence: Vec<ArtifactId>,
    /// Required members whose observation is not current at this fence.
    pub stale_evidence: Vec<ArtifactId>,
    pub failed_invariant: Option<ArtifactId>,
    pub unknown_evidence: Vec<ArtifactId>,
    /// Applicability of this dimension, resolved before grading. W2: an
    /// unresolved applicability blocks the dependent action; it never resolves
    /// to the weakest profile.
    pub applicability: QualityApplicability,
    /// Rule/profile revision the grade was taken under.
    pub rule: QualityRuleRevision,
    /// Explicit limitation this result carries, when it is not a full pass.
    pub limitation: Option<String>,
    pub proof_ceiling: ProofCeiling,
    pub invalidation: Option<ArtifactId>,
    pub binding: ContextBinding,
}

impl QualityDimensionResult {
    /// Whether this result's observed evidence covers its required member set.
    ///
    /// This is the W1/W3 rule: a grade is never read off the state alone. The
    /// required set is the independent roster the governing rule declared, so
    /// a duplicated evidence handle cannot stand in for a member that was
    /// never observed.
    fn covers_required_evidence(&self) -> bool {
        let required: BTreeSet<_> = self.required_evidence.iter().collect();
        let observed: BTreeSet<_> = self.evidence.iter().collect();
        !required.is_empty() && required.is_subset(&observed)
    }
}

/// The exact output one scorecard grades.
///
/// W4 binds grading to the rendered representation itself, not to the
/// pre-truncated candidate set. `rendered_payload_digest` is the existing
/// canonical payload digest of [`ActiveUnderstandingView`], which is computed
/// over `{schema_version, binding, recipe_digest, fence_digest, rendered}` and
/// therefore already EXCLUDES the scorecard from its own hash input: the
/// circular "receipt contains its own output hash" shape cannot arise.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityScorecardBinding {
    /// Recipe digest the grade was taken under.
    pub recipe_digest: String,
    /// Canonical digest of the exact admitted set that was graded.
    pub admitted_set_digest: String,
    /// Canonical digest of the ordered final rendered payload, which excludes
    /// this scorecard by construction.
    pub rendered_payload_digest: String,
    /// Exact serializer and route the rendered payload was produced through.
    pub serializer_id: String,
    pub route_id: String,
    /// Source/evidence revision the grades were taken against.
    pub evidence_revisions: Vec<ArtifactId>,
    /// Exact omission handles covering every displaced/omitted member.
    pub omission_handles: Vec<ArtifactId>,
}

impl QualityScorecardBinding {
    /// Validate the digest and handle identities the binding must carry.
    pub fn validate(&self) -> Result<(), ContextError> {
        crate::validate_digest(&self.recipe_digest, "quality.binding.recipe_digest")?;
        crate::validate_digest(
            &self.admitted_set_digest,
            "quality.binding.admitted_set_digest",
        )?;
        crate::validate_digest(
            &self.rendered_payload_digest,
            "quality.binding.rendered_payload_digest",
        )?;
        crate::validate_text(&self.serializer_id, "quality.binding.serializer_id")?;
        crate::validate_text(&self.route_id, "quality.binding.route_id")
    }
}

/// Closed twelve-axis quality scorecard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityScorecard {
    pub binding: ContextBinding,
    /// The exact output this scorecard grades.
    pub output: QualityScorecardBinding,
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
}

/// The applicability resolution resolved BEFORE grading.
///
/// W2 requires the applicable task/acceptance, route, impact, Governance
/// Profile, protected floor and active directives to be resolved before a
/// dimension is graded. `Resolved` is the only state that may enable an
/// operation; `Unknown` blocks the dependent action rather than silently
/// selecting the weakest profile, and `NotApplicable` must carry a
/// policy-backed reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "applicability", deny_unknown_fields)]
pub enum QualityApplicability {
    /// Task/acceptance, route, impact, profile, protected floor and active
    /// directives were all resolved for this operation.
    Resolved,
    /// One of those inputs could not be resolved. The dependent action is
    /// blocked; it never falls back to a weaker profile.
    Unknown {
        /// Exact input that could not be resolved.
        unresolved: String,
    },
    /// The dimension does not apply under the governing policy.
    NotApplicable {
        /// Policy reason for inapplicability; never empty.
        reason: String,
    },
}

impl QualityApplicability {
    /// Whether the dependent action may proceed under this applicability.
    fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved)
    }

    fn validate(&self) -> Result<(), ContextError> {
        match self {
            Self::Resolved => Ok(()),
            Self::Unknown { unresolved } => crate::validate_text(
                unresolved,
                "quality.applicability.unresolved",
            ),
            Self::NotApplicable { reason } => {
                crate::validate_text(reason, "quality.applicability.reason")
            }
        }
    }
}

/// Machine-readable suitability refusal class; consumers branch on this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityRefusalKind {
    /// The scorecard is not structurally valid, so it describes no gradeable
    /// packet and no suitability can be read from it.
    InvalidScorecard,
    /// The requested operation is blocked by the named dimension results.
    OperationBlocked,
    /// The applicability of a required input could not be resolved, so the
    /// dependent action is blocked rather than resolved to a weaker profile.
    ApplicabilityUnknown,
}

/// One exact piece of evidence a blocking result lacks, named for the caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityMissingEvidence {
    /// Dimension whose requirement is unmet.
    pub dimension: QualityDimension,
    /// Required members with no current observation.
    pub missing: Vec<ArtifactId>,
    /// Required members whose observation is not current at this fence.
    pub stale: Vec<ArtifactId>,
    /// Evidence that could not be resolved at all.
    pub unknown: Vec<ArtifactId>,
    /// Applicability input that could not be resolved, when one was named.
    pub unresolved_applicability: Option<String>,
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
    /// Exact missing/stale/unknown evidence per blocking dimension, so a
    /// consumer never has to re-derive the gap from the result alone.
    pub missing_evidence: Vec<QualityMissingEvidence>,
}

impl QualityScorecard {
    /// Validate exact closure and independent evidence for every dimension.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        self.output.validate()?;
        let mut seen = BTreeSet::new();
        for result in &self.results {
            if result.binding != self.binding || !seen.insert(result.dimension) {
                return Err(ContextError::QualityIncomplete);
            }
            result.state.validate()?;
            result.applicability.validate()?;
            result.rule.validate()?;
            if let Some(limitation) = &result.limitation {
                crate::validate_text(limitation, "quality.result.limitation")?;
            }
            for measurement in &result.measurements {
                measurement.validate()?;
            }
            // Rule 10: the required member set is the independent roster, so
            // the coverage check compares against it, never against a second
            // copy of the caller-supplied evidence list.
            let required: BTreeSet<_> = result.required_evidence.iter().collect();
            let observed: BTreeSet<_> = result.evidence.iter().collect();
            let missing: BTreeSet<_> = result.missing_evidence.iter().collect();
            let stale: BTreeSet<_> = result.stale_evidence.iter().collect();
            let gap: BTreeSet<_> = missing.union(&stale).copied().collect();
            let uncovered: BTreeSet<_> =
                required.difference(&observed).copied().collect();
            if required.len() != result.required_evidence.len()
                || observed.len() != result.evidence.len()
                || missing.len() != result.missing_evidence.len()
                || stale.len() != result.stale_evidence.len()
                || !missing.is_disjoint(&required)
                || !stale.is_disjoint(&required)
                || !missing.is_disjoint(&stale)
                || !missing.is_subset(&required)
                || !stale.is_subset(&required)
                || uncovered != gap
            {
                return Err(ContextError::QualityIncomplete);
            }
            match &result.state {
                // A pass is exactly observed evidence under a resolved
                // applicability: no failure, no gap in the required member set,
                // and no unresolved applicability.
                QualityDimensionState::Passed => {
                    if !result.applicability.is_resolved()
                        || !result.covers_required_evidence()
                        || result.failed_invariant.is_some()
                        || !result.unknown_evidence.is_empty()
                    {
                        return Err(ContextError::QualityIncomplete);
                    }
                }
                // Failure, unknown evidence and allowed degradation all still
                // name the exact failed invariant or unknown evidence.
                QualityDimensionState::Failed
                | QualityDimensionState::Unknown
                | QualityDimensionState::Degraded { .. } => {
                    if result.failed_invariant.is_none() && result.unknown_evidence.is_empty() {
                        return Err(ContextError::QualityIncomplete);
                    }
                }
                // A policy reason may make the dimension inapplicable; it may
                // not hide a failed invariant behind that reason.
                QualityDimensionState::NotApplicable { .. } => {
                    if result.failed_invariant.is_some() {
                        return Err(ContextError::QualityIncomplete);
                    }
                }
            }
        }
        if seen.len() != QUALITY_DIMENSIONS.len() {
            return Err(ContextError::QualityIncomplete);
        }
        Ok(())
    }

    /// Reject a scorecard that does not describe THIS packet.
    ///
    /// A4 in rule-10 form: the scorecard's OWN binding content is compared
    /// against the packet it is attached to. The expected values are derived
    /// from the packet (recipe, admitted set, rendered payload, serializer,
    /// route, omission handles), never from the scorecard itself, so a
    /// scorecard swapped between two same-fence packets with different
    /// membership or recipes is rejected. Comparing the packet against itself
    /// or checking that a digest field is non-empty would prove nothing.
    pub fn grades_output(
        &self,
        recipe_digest: &str,
        admitted_set_digest: &str,
        rendered_payload_digest: &str,
        serializer_id: &str,
        route_id: &str,
        omission_handles: &[ArtifactId],
    ) -> Result<(), ContextError> {
        if self.output.recipe_digest != recipe_digest
            || self.output.admitted_set_digest != admitted_set_digest
            || self.output.rendered_payload_digest != rendered_payload_digest
            || self.output.serializer_id != serializer_id
            || self.output.route_id != route_id
        {
            return Err(ContextError::IdentityConflict);
        }
        let expected: BTreeSet<_> = omission_handles.iter().collect();
        let actual: BTreeSet<_> = self.output.omission_handles.iter().collect();
        if expected != actual {
            return Err(ContextError::IdentityConflict);
        }
        // Every grade was taken under one rule revision; a scorecard that mixes
        // recipe revisions grades no single output.
        let revisions: BTreeSet<_> = self
            .results
            .iter()
            .map(|result| &result.rule.recipe_digest)
            .collect();
        if revisions.len() != 1 || !revisions.contains(&recipe_digest.to_owned()) {
            return Err(ContextError::IdentityConflict);
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
    /// separate operation-scoped readiness fact, and it is the ONLY readiness
    /// rule. Two directions pull against each other and both are honoured:
    ///
    /// - A dimension the operation independently requires must be an observed
    ///   pass. Failed, unknown, degraded or not-applicable blocks the dependent
    ///   action (W2: unknown applicability blocks).
    /// - A dimension the operation does not require never blocks, so an
    ///   informational non-blocking unknown stays visible without globally
    ///   refusing unrelated safe work (W5/A6).
    ///
    /// `additional_required` carries the blockers a recipe selected: it is
    /// unioned with the independently mandatory set, so it can add a constraint
    /// but never remove one.
    pub fn suitability(
        &self,
        operation: QualityOperation,
        additional_required: &[QualityDimension],
    ) -> Result<(), QualityRefusal> {
        if self.validate().is_err() {
            return Err(QualityRefusal {
                kind: QualityRefusalKind::InvalidScorecard,
                operation,
                blocking: Vec::new(),
                missing_evidence: Vec::new(),
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
        if blocking.is_empty() {
            return Ok(());
        }
        // W2: an unresolved applicability blocks the dependent action under its
        // own refusal class, so a caller can tell "graded failed" from "could
        // not be resolved" without reading the result text.
        let unresolved = blocking.iter().find_map(|result| match &result.applicability {
            QualityApplicability::Unknown { unresolved } => Some(unresolved.clone()),
            _ => None,
        });
        let missing_evidence = blocking
            .iter()
            .map(|result| QualityMissingEvidence {
                dimension: result.dimension,
                missing: result.missing_evidence.clone(),
                stale: result.stale_evidence.clone(),
                unknown: result.unknown_evidence.clone(),
                unresolved_applicability: match &result.applicability {
                    QualityApplicability::Unknown { unresolved } => Some(unresolved.clone()),
                    _ => None,
                },
            })
            .collect();
        Err(QualityRefusal {
            kind: if unresolved.is_some() {
                QualityRefusalKind::ApplicabilityUnknown
            } else {
                QualityRefusalKind::OperationBlocked
            },
            operation,
            blocking,
            missing_evidence,
        })
    }

    /// Non-blocking results that stay visible for an operation.
    ///
    /// W5/A6: an informational unknown, degradation or inapplicability that no
    /// requested operation requires must not disappear, and it must not refuse
    /// anything either. This returns exactly those results so a consumer can
    /// show them as limitations alongside work that is still safe to do.
    pub fn informational(&self, operation: QualityOperation) -> Vec<QualityDimensionResult> {
        let required: BTreeSet<QualityDimension> =
            operation.required_dimensions().iter().copied().collect();
        self.results
            .iter()
            .filter(|result| !required.contains(&result.dimension) && !result.state.is_pass())
            .cloned()
            .collect()
    }
}
