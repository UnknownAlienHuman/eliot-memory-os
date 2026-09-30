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

/// One recorded owner dependency whose change invalidates a recorded grade.
///
/// Every variant names ONE existing owner record and names the recorded field
/// of THAT record which is compared, on the graded side and on the current
/// side. No variant introduces a revision, a counter or a registry: each one
/// reads a value the packet already carries, and each side of the comparison
/// is read from a different record. Nothing is recomputed and re-compared
/// against a string this module made up.
///
/// | Reason | Graded under | Now carries |
/// |---|---|---|
/// | `Route` | [`QualityOutputBinding::route_id`] | [`crate::SerializedContextMeasurement::route_id`] |
/// | `GoverningInstruction` | [`QualityOutputBinding::recipe_digest`] | `Recipe::decision.recipe_revision` (the governing policy revision) |
/// | `Source` | [`QualityOutputBinding::evidence_revisions`] | `Measurement::sources` (each admitted `SourceSnapshot`) |
/// | `Task` | [`ContextBinding::task_id`] | the same field on the observed binding |
/// | `Verifier` | [`QualityDimensionResult::rule_revision`] | `Measurement::verifier_rule_revisions` for that dimension |
///
/// The three identity reasons are bound to already-existing check points,
/// which is why the route/serializer identity of a card is now compared with
/// the route identity of the packet it graded rather than only bounded:
///
/// * `Route` — [`crate::SerializedContextMeasurement::validate`] already
///   reads `route_id`, but nothing read it from the *card*. Now it does.
/// * `GoverningInstruction` — [`ContextRecipe::decision`] already carries the
///   governing policy revision and was already required to agree with the
///   binding, but the card never named it. Now it does, so a card graded
///   under an earlier governing revision is detected rather than accepted.
/// * `Source` / `Verifier` — the measurement is the record that already owns
///   the route identity, and it now records which source snapshots that route
///   served from and which verifier revision was in force per dimension.
/// * `Task` — the route is not task-bound by its own recorded policy, so this
///   one is bound to the card's own `ContextBinding`, which is compared
///   re-observation by re-evaluation rather than by a route-level check.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityInvalidationReason {
    /// The packet is compiled for a different route than the grade was taken
    /// under.
    Route,
    /// The governing policy revision under which the packet was compiled
    /// differs from the one the grade was taken under.
    GoverningInstruction,
    /// The route no longer reads the source revision the grade was read from.
    Source,
    /// The task identity differs between the graded binding and the observed
    /// one.
    Task,
    /// The verifier contract revision in force for the dimension differs from
    /// the one that produced this grade.
    Verifier,
}

impl QualityInvalidationReason {
    /// The five invalidation reasons, in canonical order.
    ///
    /// This constant is the independent denominator of the invalidation rule:
    /// it is declared here, not supplied by the caller whose reasons are being
    /// checked, so a caller cannot narrow the rule by evaluating fewer of them.
    pub const INVALIDATION_REASONS: [Self; 5] = [
        Self::Route,
        Self::GoverningInstruction,
        Self::Source,
        Self::Task,
        Self::Verifier,
    ];

    /// The wire spelling of this reason, used in the retained handle so a
    /// reader can name the reason without the enum.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Route => "ROUTE",
            Self::GoverningInstruction => "GOVERNING_INSTRUCTION",
            Self::Source => "SOURCE",
            Self::Task => "TASK",
            Self::Verifier => "VERIFIER",
        }
    }
}

/// One observed invalidation: which recorded owner dependency differs, the
/// recorded value the grade was taken under, and the recorded value it now
/// carries.
///
/// Both sides are values the owners already hold, read from two different
/// records. This type stores the observation; it never decides it. The
/// decision is made once, by the owner of the records being compared — see
/// [`crate::SerializedContextMeasurement::recorded_invalidation`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityInvalidation {
    /// Which recorded owner dependency changed.
    pub reason: QualityInvalidationReason,
    /// The dimension whose recorded grade the change invalidates.
    pub dimension: QualityDimension,
    /// The recorded owner value the grade was taken under.
    pub graded_value: String,
    /// The recorded owner value it now carries.
    pub current_value: String,
}

impl QualityInvalidation {
    /// Validate that this names a real reason, a real dimension and a real
    /// recorded difference.
    fn validate(&self) -> Result<(), ContextError> {
        if !QualityInvalidationReason::INVALIDATION_REASONS.contains(&self.reason) {
            return Err(ContextError::InvalidField("quality.invalidation.reason"));
        }
        if !QUALITY_DIMENSIONS.contains(&self.dimension) {
            return Err(ContextError::InvalidField("quality.invalidation.dimension"));
        }
        crate::validate_text(&self.graded_value, "quality.invalidation.graded_value")?;
        crate::validate_text(&self.current_value, "quality.invalidation.current_value")?;
        // An invalidation that records no difference is not an observation. It
        // is refused rather than retained, so a card cannot carry an
        // invalidation that re-checks to nothing.
        if self.graded_value == self.current_value {
            return Err(ContextError::InvalidField("quality.invalidation.values"));
        }
        Ok(())
    }

    /// The handle recorded on the result this came from.
    ///
    /// It is derived from the two recorded values, so re-deriving it from the
    /// records that produced it yields the same handle and a different pair of
    /// values cannot reuse it.
    fn handle(&self) -> Result<ArtifactId, ContextError> {
        self.validate()?;
        ArtifactId::new(format!(
            "quality-invalidation:{}:{}:{}:{}",
            self.reason.as_str(),
            self.dimension.as_str(),
            self.graded_value,
            self.current_value
        ))
        .map_err(|_| ContextError::InvalidField("quality.invalidation.handle"))
    }
}

impl QualityDimension {
    /// The wire spelling of this dimension, used in the retained handle so a
    /// reader can name the dimension without the enum.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AcceptanceDecisionCoverage => "ACCEPTANCE_DECISION_COVERAGE",
            Self::CausalOperationalSufficiency => "CAUSAL_OPERATIONAL_SUFFICIENCY",
            Self::ExactAnchorProvenanceCoverage => "EXACT_ANCHOR_PROVENANCE_COVERAGE",
            Self::FreshnessStateFenceCoherence => "FRESHNESS_STATE_FENCE_COHERENCE",
            Self::RivalsConflictsUnknownsVisibility => "RIVALS_CONFLICTS_UNKNOWNS_VISIBILITY",
            Self::NegativeMemoryInvariantCoverage => "NEGATIVE_MEMORY_INVARIANT_COVERAGE",
            Self::VerifierActionReadiness => "VERIFIER_ACTION_READINESS",
            Self::RouteAccessibilityLayoutRisk => "ROUTE_ACCESSIBILITY_LAYOUT_RISK",
            Self::InstructionSufficiency => "INSTRUCTION_SUFFICIENCY",
            Self::PayloadHandleReconstructionCost => "PAYLOAD_HANDLE_RECONSTRUCTION_COST",
            Self::KnownOmissionsExpansionPaths => "KNOWN_OMISSIONS_EXPANSION_PATHS",
            Self::TelemetryMeasurementCostCoverage => "TELEMETRY_MEASUREMENT_COST_COVERAGE",
        }
    }
}

impl QualityDimensionResult {
    /// Whether this result is a current observed pass.
    ///
    /// A result that carries an invalidation handle has been invalidated by a
    /// route, governing-instruction, source, task or verifier change, so it is
    /// a historical grade and never a current one. The record itself stays on
    /// the card, so the evidence it was read from is still retained and
    /// visible.
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

    /// Mark every recorded grade named by `observed`, and return those exact
    /// results.
    ///
    /// This is the only place the five [`QualityInvalidationReason`]
    /// dependencies are turned into a recorded handle, and it is reached
    /// through [`crate::SerializedContextMeasurement::reevaluate_against`], the
    /// measurement owner, so both sides of every comparison are that owner's
    /// recorded values and nothing is recomputed here.
    ///
    /// `None` is returned when the card is already untouched by `observed`: the
    /// card is then left exactly as it was, so a re-evaluation that finds
    /// nothing new never rewrites history. A result that already carries an
    /// invalidation keeps the first handle, because a second, later
    /// observation is not a second reason to discard evidence the card already
    /// explains.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the card does not validate, or if an
    /// invalidation naming a dimension this card does not carry was supplied,
    /// so an invalidation can never be recorded against a result that is not
    /// there.
    pub(crate) fn mark_invalidated(
        &mut self,
        observed: &[QualityInvalidation],
    ) -> Result<Option<Vec<QualityDimensionResult>>, ContextError> {
        self.validate()?;
        for invalidation in observed {
            invalidation.validate()?;
        }
        let mut invalidated = Vec::new();
        for invalidation in observed {
            let Some(result) = self
                .results
                .iter_mut()
                .find(|result| result.dimension == invalidation.dimension)
            else {
                return Err(ContextError::InvalidField(
                    "quality.invalidation.dimension",
                ));
            };
            if result.invalidation.is_some() {
                continue;
            }
            result.invalidation = Some(invalidation.handle()?);
            invalidated.push(result.clone());
        }
        if invalidated.is_empty() {
            return Ok(None);
        }
        // The card is read back through its own validation, so a stored
        // invalidation can never leave the card in a state its owner rejects.
        self.validate()?;
        Ok(Some(invalidated))
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
