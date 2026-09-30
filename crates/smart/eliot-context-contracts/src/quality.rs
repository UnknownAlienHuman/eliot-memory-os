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

/// Wire revision of [`QualityScorecard`].
///
/// Scorecard schema 1 carried a binding, an applicability partition and twelve
/// results, and nothing that said *which* packet those twelve results were
/// about. Two packets sharing one task, attempt, scope, decision and fence but
/// differing in recipe, membership and rendered representation were therefore
/// indistinguishable to the card, and a card graded against one of them
/// validated against the other. I12.13 grades a rendered packet, so the card now
/// names that packet through [`QualityScorecard::output`].
///
/// The same compatibility decision as the result schema applies, and for a
/// stronger reason: the digests *are* the binding. There is nothing to migrate a
/// schema-1 card *to* — a scorecard that did not name the output it graded has
/// no honest `QualityOutputBinding`, and inventing one during deserialization
/// would fabricate the exact fact the field exists to record. So the version is
/// required, has no default and no clock fallback, and `deny_unknown_fields`
/// refuses a schema-1 payload outright rather than reinterpreting it.
pub const QUALITY_SCORECARD_SCHEMA_VERSION: u32 = 2;

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
    /// Whether this result is a current observed pass.
    ///
    /// A result that carries an invalidation handle has been invalidated by a
    /// route, governing-instruction, source, task or verifier change, so it is a
    /// historical grade and never a current one. The record itself stays on the
    /// card, so the evidence it was read from is still retained and visible.
    #[must_use]
    pub fn is_current_pass(&self) -> bool {
        self.invalidation.is_none() && self.state.is_pass()
    }

    fn validate(&self, scorecard_binding: &ContextBinding) -> Result<(), ContextError> {
        if self.schema_version != QUALITY_RESULT_SCHEMA_VERSION
            || self.binding != *scorecard_binding
        {
            return Err(ContextError::QualityIncomplete);
        }
        self.state.validate()?;
        crate::validate_text(self.rule_revision.as_str(), "quality.rule_revision")?;
        // The required member set is a set. A repeated member states no
        // additional requirement, so a list that repeats one handle cannot
        // stand in for the complete set the grade was taken against.
        let mut required: BTreeSet<&ArtifactId> = BTreeSet::new();
        if self
            .required_evidence
            .iter()
            .any(|member| !required.insert(member))
        {
            return Err(ContextError::QualityIncomplete);
        }
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

/// The one owner answer for one applicability input, or the typed unknown.
///
/// Each input is a question the grading of a packet must be able to answer
/// *before* any dimension is graded. The two states are deliberately not a
/// `bool` and not an `Option`: `Resolved` means one owner supplied the exact
/// answer it holds, and `Unknown` means no owner supplied an answer at all.
/// `Unknown` is a real result, not a failure to build the value — it is what
/// keeps "nobody answered" distinguishable from "the weakest answer was chosen".
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum QualityApplicabilityResolution {
    /// The named owner supplied this input's governing answer.
    Resolved {
        /// Owner that holds this input, in its own stable identity.
        owner: String,
        /// The exact owner-issued reference for this answer.
        answer: String,
    },
    /// No owner supplied this input. The dependent action is blocked.
    Unknown {
        /// Owner that must issue this input.
        missing_owner: String,
    },
}

impl QualityApplicabilityResolution {
    /// Whether this input reached a governing answer.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved { .. })
    }
}

/// The complete owner-resolved answer set for one packet's six inputs.
///
/// This is the value the applicability resolution produces and the value
/// [`QualityApplicability::from_resolutions`] consumes. It is a closed struct
/// rather than a map so every one of [`QUALITY_APPLICABILITY_INPUTS`] is a
/// *required member* on the wire: a producer cannot omit an input it has no
/// answer for, and a `deny_unknown_fields` payload cannot invent an eighth one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityApplicabilityResolutionSet {
    /// The applicable task and its acceptance criteria.
    pub task_acceptance: QualityApplicabilityResolution,
    /// The route this packet is compiled for.
    pub route: QualityApplicabilityResolution,
    /// The impact classification of the requested effect.
    pub impact: QualityApplicabilityResolution,
    /// The governing Governance Profile.
    pub governance_profile: QualityApplicabilityResolution,
    /// The protected Safety Floor.
    pub protected_floor: QualityApplicabilityResolution,
    /// The currently active directives.
    pub active_directive: QualityApplicabilityResolution,
}

impl QualityApplicabilityResolutionSet {
    /// The six answers paired with the input each one answers.
    ///
    /// The pairing is written out explicitly rather than iterated from a
    /// caller-supplied list, so the set cannot be built with one input missing
    /// and another supplied twice.
    #[must_use]
    pub fn entries(&self) -> [(&'static str, &QualityApplicabilityResolution); 6] {
        [
            ("task_acceptance", &self.task_acceptance),
            ("route", &self.route),
            ("impact", &self.impact),
            ("governance_profile", &self.governance_profile),
            ("protected_floor", &self.protected_floor),
            ("active_directive", &self.active_directive),
        ]
    }

    /// Validate the intrinsic shape of every supplied answer.
    ///
    /// A blank owner or answer identity is refused rather than accepted as an
    /// answer: an owner that cannot name itself has not answered.
    pub fn validate(&self) -> Result<(), ContextError> {
        for resolution in self.entries().into_iter().map(|(_, resolution)| resolution) {
            match resolution {
                QualityApplicabilityResolution::Resolved { owner, answer } => {
                    crate::validate_text(owner, "quality.applicability.owner")?;
                    crate::validate_text(answer, "quality.applicability.answer")?;
                }
                QualityApplicabilityResolution::Unknown { missing_owner } => {
                    crate::validate_text(missing_owner, "quality.applicability.missing_owner")?;
                }
            }
        }
        Ok(())
    }
}

impl QualityApplicability {
    /// Partition the six owner answers into resolved and unknown inputs.
    ///
    /// This is the resolution: every entry of
    /// [`QUALITY_APPLICABILITY_INPUTS`] is read from its own owner answer and
    /// placed in exactly one of the two lists. An answer that is absent, typed
    /// `Unknown`, or malformed never becomes `resolved` and never selects a
    /// weaker profile — the input lands in `unknown`, and
    /// [`QualityOperation::blocks_on_unresolved_applicability`] then blocks
    /// every operation except read-only diagnostic display.
    ///
    /// A malformed answer set is a typed [`ContextError`], not a silent
    /// downgrade: a caller cannot hand in a blank owner identity and have the
    /// input quietly become permissive.
    pub fn from_resolutions(
        resolutions: &QualityApplicabilityResolutionSet,
    ) -> Result<Self, ContextError> {
        resolutions.validate()?;
        let mut resolved = Vec::new();
        let mut unknown = Vec::new();
        for (input, resolution) in [
            (
                QualityApplicabilityInput::TaskAcceptance,
                &resolutions.task_acceptance,
            ),
            (QualityApplicabilityInput::Route, &resolutions.route),
            (QualityApplicabilityInput::Impact, &resolutions.impact),
            (
                QualityApplicabilityInput::GovernanceProfile,
                &resolutions.governance_profile,
            ),
            (
                QualityApplicabilityInput::ProtectedFloor,
                &resolutions.protected_floor,
            ),
            (
                QualityApplicabilityInput::ActiveDirective,
                &resolutions.active_directive,
            ),
        ] {
            if resolution.is_resolved() {
                resolved.push(input);
            } else {
                unknown.push(input);
            }
        }
        let applicability = Self { resolved, unknown };
        applicability.validate()?;
        Ok(applicability)
    }

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

/// The exact output one scorecard graded.
///
/// I12.13 grades a *rendered packet*, not a candidate set, so a grade is only
/// about the bytes it was actually produced for. This binding records that
/// output by the identities the packet itself already carries — the recipe
/// revision, the state fence, the ordered admitted payload and the ordered
/// rendered payload — plus the serializer/route identity those bytes were
/// produced under and the source revisions the grades were read from.
///
/// **Anti-circularity.** The scorecard is not an input to any digest here.
/// `admitted_digest` is [`AdmittedContextSet::canonical_payload_digest`] and
/// `rendered_digest` is [`ActiveUnderstandingView::canonical_output_digest`];
/// both hash `{schema_version, binding, recipe_digest, fence_digest, records
/// or rendered}` and neither reads a scorecard. Grading the final
/// representation and hashing that representation therefore stay separate,
/// ordered steps, and there is no "receipt containing its own output hash".
///
/// **Why content and not identity.** A matching [`ContextBinding`] proves
/// task/attempt/scope/decision/fence and nothing else. Two packets can share
/// one binding and still differ in recipe, membership and rendered bytes, so
/// these digests — not the fence — are what make a card swapped between
/// same-fence packets detectable. Whether these values describe *this* packet is
/// decided by the packet: `QualityScorecard::validate` checks the intrinsic
/// shape, and `ActiveUnderstandingView::validate` compares the recorded values
/// against the digests its owner recomputes. Nothing here rehashes what it holds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityOutputBinding {
    /// Canonical digest of the recipe revision that produced the packet.
    pub recipe_digest: String,
    /// Canonical digest of the state fence the packet was compiled under.
    pub fence_digest: String,
    /// `AdmittedContextSet::canonical_payload_digest` of the admitted set.
    pub admitted_digest: String,
    /// `ActiveUnderstandingView::canonical_output_digest` of the ordered
    /// rendered payload: the final representation, not the pre-pruning
    /// candidate set.
    pub rendered_digest: String,
    /// Serializer identity the rendered bytes were produced under.
    pub serializer_id: String,
    /// Serializer revision the rendered bytes were produced under.
    pub serializer_version: String,
    /// Serializer-options digest the rendered bytes were produced under.
    pub serializer_options_digest: String,
    /// Route identity the packet was compiled for.
    pub route_id: String,
    /// Source revisions every grade was read from, one entry per distinct
    /// admitted source snapshot. A repeated revision is one revision, never two
    /// observations, so a duplicated handle cannot stand in for coverage.
    pub evidence_revisions: Vec<ArtifactId>,
    /// Omission handles this packet actually carries, in the order the
    /// admission owner recorded them.
    pub omission_handles: Vec<ArtifactId>,
}

impl QualityOutputBinding {
    /// Validate the intrinsic shape of the binding only.
    ///
    /// This is content, not content-*correspondence*: a well-formed digest here
    /// says nothing about whether it is this packet's digest. The comparison
    /// against the packet is made by the two owners that already compute those
    /// values — the assembly entrypoint and the view's own validation.
    pub fn validate(&self) -> Result<(), ContextError> {
        for (digest, field) in [
            (&self.recipe_digest, "quality.output.recipe_digest"),
            (&self.fence_digest, "quality.output.fence_digest"),
            (&self.admitted_digest, "quality.output.admitted_digest"),
            (&self.rendered_digest, "quality.output.rendered_digest"),
            (
                &self.serializer_options_digest,
                "quality.output.serializer_options_digest",
            ),
        ] {
            crate::validate_digest(digest, field)?;
        }
        crate::validate_text(&self.serializer_id, "quality.output.serializer_id")?;
        crate::validate_text(
            &self.serializer_version,
            "quality.output.serializer_version",
        )?;
        crate::validate_text(&self.route_id, "quality.output.route_id")?;
        // Both lists are sets. Repeating a revision or an omission handle states
        // no additional fact, so a padded list cannot pose as wider coverage.
        for (values, field) in [
            (
                &self.evidence_revisions,
                "quality.output.evidence_revisions",
            ),
            (&self.omission_handles, "quality.output.omission_handles"),
        ] {
            let mut distinct = BTreeSet::new();
            for value in values {
                if !distinct.insert(value.clone()) {
                    return Err(ContextError::Duplicate(field));
                }
            }
        }
        Ok(())
    }
}

/// Closed twelve-axis quality scorecard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityScorecard {
    /// Wire revision this card was emitted under; never defaulted.
    pub schema_version: u32,
    pub binding: ContextBinding,
    /// The exact output these twelve results graded.
    ///
    /// Required and never defaulted: a grade that does not name its output is a
    /// grade about nothing in particular, which is the defect this field exists
    /// to close.
    pub output: QualityOutputBinding,
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
///
/// **`limitations` is the informational half of the partition.** For a blocking
/// operation it is empty, because a blocking operation refuses instead of
/// returning. For read-only diagnostic display it names every dimension this
/// packet did not currently pass, so a granted display suitability is never
/// mistaken for a clean packet: the limitation travels with the grant instead of
/// being dropped on the floor. Each entry is one dimension's own result, with
/// the state and the exact missing evidence it carries, so a reader does not
/// re-derive which anchor, directive or verifier was absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualitySuitability {
    /// The operation this suitability was evaluated for.
    pub operation: QualityOperation,
    /// Applicability inputs that remain unknown and did not block this
    /// operation. Never empty for a blocking operation, because a blocking
    /// operation refuses instead of returning.
    pub unresolved_applicability: Vec<QualityApplicabilityInput>,
    /// Dimension results this packet did not currently pass, in canonical
    /// dimension order, when they are informational for this operation rather
    /// than blocking it.
    ///
    /// Always empty for a blocking operation: a failed or unknown required
    /// dimension is a refusal, not a returned value, so it never reaches this
    /// list. Populated only for an operation that tolerates the dimension
    /// without acting on it — read-only diagnostic display today — which is
    /// exactly the A2 requirement that an incomplete packet stays *visible*
    /// with its limitation named.
    pub limitations: Vec<QualityDimensionResult>,
}

impl QualityScorecard {
    /// Validate exact closure and independent evidence for every dimension.
    ///
    /// This is structural integrity of the card itself. It says the card
    /// describes twelve real dimensions graded against a declared rule revision
    /// and that it names a well-formed output; it does not say the named output
    /// is *this* packet, which only the packet itself can decide — see
    /// `ActiveUnderstandingView::validate`.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.schema_version != QUALITY_SCORECARD_SCHEMA_VERSION {
            return Err(ContextError::QualityIncomplete);
        }
        self.binding.validate()?;
        self.output.validate()?;
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
        Ok(self
            .results
            .iter()
            .all(QualityDimensionResult::is_current_pass))
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
    ///
    /// The two directions of the partition are exact and do not interfere: a
    /// failed or unknown *required* dimension refuses this operation, and only
    /// this operation, because [`QualityOperation::required_dimensions`] is a
    /// closed function of the operation; and when the operation is granted
    /// anyway — read-only diagnostic display, which requires no dimension — the
    /// returned [`QualitySuitability`] names every dimension that did not
    /// currently pass in its `limitations`. An informational non-blocking
    /// unknown therefore stays visible without globally refusing unrelated
    /// work, and optional metric uncertainty can neither conceal a mandatory
    /// failure (it refuses the one operation that requires it) nor disable an
    /// independent safe operation that does not.
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
        // A required dimension blocks when it is not a current pass. A recorded
        // invalidation therefore blocks the same way a failure does: the grade
        // it carried was invalidated and only reevaluation can replace it.
        let blocking = self
            .results
            .iter()
            .filter(|result| required.contains(&result.dimension) && !result.is_current_pass())
            .cloned()
            .collect::<Vec<_>>();
        let unresolved_applicability = self.applicability.unresolved();
        let applicability_blocks =
            operation.blocks_on_unresolved_applicability() && !unresolved_applicability.is_empty();
        if blocking.is_empty() && !applicability_blocks {
            // The grant, not a silent pass. For a blocking operation `blocking` is
            // empty here, so `limitations` is empty too and a returned suitability
            // really did mean every required dimension was a current pass. For
            // read-only diagnostic display no dimension is mandatory, so the same
            // `Ok` arm would otherwise drop every failed and unknown result on the
            // floor; carrying them as limitations is what keeps an incomplete
            // packet visible with its limitation named instead of being displayed
            // as though it were clean.
            let limitations = if operation.blocks_on_unresolved_applicability() {
                Vec::new()
            } else {
                self.results
                    .iter()
                    .filter(|result| !result.is_current_pass())
                    .cloned()
                    .collect::<Vec<_>>()
            };
            return Ok(QualitySuitability {
                operation,
                unresolved_applicability,
                limitations,
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
