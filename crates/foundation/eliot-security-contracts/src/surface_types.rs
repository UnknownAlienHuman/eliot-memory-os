//! Wire shapes for source assurance, disclosure, influence, purge and selection.

use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Origin and use assurance for one immutable source observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceAssurance {
    /// Opaque source identity.
    pub source_ref: String,
    /// Stable provenance/locator reference.
    pub provenance_ref: String,
    /// Integrity statement for the source snapshot.
    pub integrity: IntegrityStatus,
    /// Freshness relative to the current scope.
    pub freshness: FreshnessStatus,
    /// Domain competence classification.
    pub competence: CompetenceLevel,
    /// Independence from the decision route.
    pub independence: IndependenceLevel,
    /// Privacy sensitivity of the source.
    pub privacy_class: PrivacyClass,
    /// Instruction taint carried by source content.
    pub instruction_taint: InstructionTaint,
    /// Allowed epistemic uses, never an authority grant.
    pub allowed_epistemic_use: Vec<EpistemicUse>,
    /// Bounded effect ceilings for derived consumers.
    pub allowed_effects: Vec<EffectCeiling>,
    /// Required verifier or explicit empty marker.
    pub required_verifier: Option<String>,
    /// Quarantine/review state.
    pub quarantine: QuarantineState,
    /// Current source fence.
    pub state_fence: StateFence,
}

/// Bounded metadata for one assessed source revision and declared scope.
///
/// The digest identifies bytes supplied by the caller; this contract does not
/// retrieve or independently authenticate those bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssessedSourceRevision {
    pub source_ref: String,
    pub revision: String,
    /// Lowercase SHA-256 of the exact source representation assessed.
    pub digest: String,
    pub scope: SourceAssessmentScope,
}

/// Declared included and excluded scope for an assessment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceAssessmentScope {
    pub scope_ref: String,
    pub included_refs: Vec<String>,
    pub excluded_refs: Vec<String>,
    pub coverage: AssessmentCoverage,
}

/// Assessment record with independent observations separated from model claims.
///
/// This is an evidence and interpretation shape only. It assigns no semantic
/// truth, quarantine state, incident status, capability, or execution authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceSecurityAssessment {
    pub assessment_ref: String,
    pub source: AssessedSourceRevision,
    /// Existing source use, taint, privacy, and effect constraints for this
    /// observation. Assessment content does not widen these constraints.
    pub source_assurance: SourceAssurance,
    /// Features recorded by an independent observation or deterministic rule.
    pub observed_features: Vec<ObservedSourceFeature>,
    /// Interpretations proposed by a model, kept distinct from observations.
    pub model_interpretations: Vec<ModelProposedInterpretation>,
    /// I8.8 indicator observations classified for this exact source revision.
    ///
    /// These are the classified form of the same retained evidence the rows
    /// above carry: each one names the class its producer assigned, the exact
    /// evidence for it, and that producer's provenance. The use boundary
    /// resolves every one of them through the finite indicator-to-source map
    /// and keeps only the narrowing that survives, so a retained record is
    /// evidence and never authority.
    ///
    /// Empty means no indicator was classified for this source, which is not a
    /// finding in either direction; it is the ordinary state for a source that
    /// raised no signal.
    #[serde(default)]
    pub indicator_observations: Vec<crate::RecordedIndicatorObservation>,
}

/// Closed inventory of dimensions that a source assessment may describe.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssessmentDimension {
    Identity,
    Integrity,
    InstructionInjectionRisk,
    DeceptionRisk,
    ExfiltrationRisk,
    PersistenceRisk,
    SuspiciousPattern,
    AffectedCapability,
    SuggestedQuarantine,
    RequiredProbe,
    Confidence,
    Limitation,
}

const REQUIRED_ASSESSMENT_DIMENSIONS: [AssessmentDimension; 12] = [
    AssessmentDimension::Identity,
    AssessmentDimension::Integrity,
    AssessmentDimension::InstructionInjectionRisk,
    AssessmentDimension::DeceptionRisk,
    AssessmentDimension::ExfiltrationRisk,
    AssessmentDimension::PersistenceRisk,
    AssessmentDimension::SuspiciousPattern,
    AssessmentDimension::AffectedCapability,
    AssessmentDimension::SuggestedQuarantine,
    AssessmentDimension::RequiredProbe,
    AssessmentDimension::Confidence,
    AssessmentDimension::Limitation,
];

/// Closed value vocabulary for assessment dimensions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum AssessmentValue {
    Identity(IdentityAssurance),
    Integrity(IntegrityStatus),
    InstructionInjectionRisk(RiskSignal),
    DeceptionRisk(RiskSignal),
    ExfiltrationRisk(RiskSignal),
    PersistenceRisk(RiskSignal),
    SuspiciousPattern(SuspiciousPattern),
    AffectedCapability(String),
    SuggestedQuarantine(QuarantineState),
    RequiredProbe(String),
    Confidence(AssessmentConfidence),
    Limitation(String),
    Unknown(AssessmentDimension),
}

/// Bounded identity evidence classification; it does not establish identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityAssurance {
    Attributed,
    Unverified,
    Conflicted,
    Unknown,
}

/// Signal state without numeric policy thresholds or a truth conclusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskSignal {
    Observed,
    NotObserved,
    Unknown,
}

/// Suspicious-pattern classes recorded as features, not as semantic findings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SuspiciousPattern {
    InstructionOverride,
    AuthorityImpersonation,
    SecretSolicitation,
    DataExfiltrationRequest,
    PersistenceRequest,
    Obfuscation,
    Other,
}

/// Qualitative confidence label; it has no policy threshold semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssessmentConfidence {
    Low,
    Moderate,
    High,
    Unknown,
}

/// Closed coverage/unknown status required for each individual dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssessmentCoverage {
    Complete,
    Partial,
    Unknown,
    NotApplicable,
}

/// Interval on an explicitly named source-local clock or revision sequence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssessmentInterval {
    pub timebase_ref: String,
    pub start: u64,
    pub end: Option<u64>,
}

/// Provenance for a feature recorded independently of a model interpretation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedFeatureOrigin {
    pub observer_ref: String,
    pub observation_revision: String,
    /// Present only when a deterministic rule contributed to the observation.
    pub rule_ref: Option<String>,
    /// Present only when a deterministic rule contributed to the observation.
    pub rule_revision: Option<String>,
}

/// One independently recorded feature with dimension-local provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedSourceFeature {
    pub value: AssessmentValue,
    pub origin: ObservedFeatureOrigin,
    pub evidence_handles: Vec<String>,
    pub observed_interval: AssessmentInterval,
    pub applicable_interval: AssessmentInterval,
    pub coverage: AssessmentCoverage,
}

/// Model provenance. This shape has no rule identity or deterministic flag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelInterpretationOrigin {
    pub model_ref: String,
    pub model_revision: String,
    pub profile_revision: String,
}

/// One model-proposed interpretation with dimension-local evidence and limits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelProposedInterpretation {
    pub value: AssessmentValue,
    pub origin: ModelInterpretationOrigin,
    pub evidence_handles: Vec<String>,
    pub observed_interval: AssessmentInterval,
    pub applicable_interval: AssessmentInterval,
    pub coverage: AssessmentCoverage,
}

pub(crate) fn assessment_text(
    value: &str,
    field: &'static str,
) -> Result<(), crate::SecurityContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(crate::SecurityContractError::InvalidText { field });
    }
    Ok(())
}

pub(crate) fn assessment_digest(
    value: &str,
    field: &'static str,
) -> Result<(), crate::SecurityContractError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(crate::SecurityContractError::InvalidText { field });
    }
    Ok(())
}

pub(crate) fn assessment_refs(
    values: &[String],
    field: &'static str,
) -> Result<(), crate::SecurityContractError> {
    if values.is_empty() {
        return Err(crate::SecurityContractError::EmptyCollection { field });
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        assessment_text(value, field)?;
        if !seen.insert(value) {
            return Err(crate::SecurityContractError::DuplicateReference { field });
        }
    }
    Ok(())
}

impl AssessmentInterval {
    /// Validates an ordered interval within its declared timebase.
    ///
    /// # Errors
    ///
    /// Returns an error when the timebase is blank or the end precedes the start.
    pub fn validate(&self) -> Result<(), crate::SecurityContractError> {
        assessment_text(&self.timebase_ref, "assessment_interval.timebase_ref")?;
        if self.end.is_some_and(|end| end < self.start) {
            return Err(crate::SecurityContractError::InvalidText {
                field: "assessment_interval.order",
            });
        }
        Ok(())
    }
}

fn validate_assessment_value(value: &AssessmentValue) -> Result<(), crate::SecurityContractError> {
    match value {
        AssessmentValue::AffectedCapability(reference)
        | AssessmentValue::RequiredProbe(reference)
        | AssessmentValue::Limitation(reference) => assessment_text(reference, "assessment.value"),
        _ => Ok(()),
    }
}

/// Narrowed use authority one action may take from an assessed source.
///
/// Every field is a subset of the assurance the current source owner resolved
/// for the operation being admitted. The record carries no standing
/// instruction, tool definition, policy, or credential value, so untrusted
/// source content has no field in which to change them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceUseAuthority {
    /// Source revision and digest this narrowing is bound to, so the decision
    /// names the assessed revision rather than the source in the abstract.
    pub assessed_source: AssessedSourceRevision,
    /// Allowed epistemic uses, intersected with the current assurance.
    pub permitted_uses: Vec<EpistemicUse>,
    /// Allowed effect ceilings, intersected with the current assurance.
    pub permitted_effects: Vec<EffectCeiling>,
    /// Instruction taint carried unchanged from the current assurance, so a
    /// summary, a second model, or a re-diagnosis cannot clear it.
    pub instruction_taint: InstructionTaint,
    /// Fence this narrowing is bound to for the current operation.
    pub state_fence: StateFence,
}

impl SourceUseAuthority {
    /// Intersects this narrowing with a second one over the same source.
    ///
    /// Both records describe the same assessed source revision, so the
    /// intersection is the only use that both admit. Instruction taint takes
    /// the stronger of the two, so intersecting can never clear taint, and the
    /// fence of the receiver is kept.
    #[must_use]
    pub fn narrowed_with(&self, other: &SourceUseAuthority) -> SourceUseAuthority {
        SourceUseAuthority {
            assessed_source: self.assessed_source.clone(),
            permitted_uses: assessment_intersection(&self.permitted_uses, &other.permitted_uses),
            permitted_effects: assessment_intersection(
                &self.permitted_effects,
                &other.permitted_effects,
            ),
            instruction_taint: self.instruction_taint.max(other.instruction_taint),
            state_fence: self.state_fence.clone(),
        }
    }
}

fn assessment_intersection<T: Copy + PartialEq>(left: &[T], right: &[T]) -> Vec<T> {
    let mut narrowed: Vec<T> = Vec::new();
    for value in left {
        if right.contains(value) && !narrowed.contains(value) {
            narrowed.push(*value);
        }
    }
    narrowed
}

fn assessment_value_dimension(value: &AssessmentValue) -> AssessmentDimension {
    match value {
        AssessmentValue::Identity(_) => AssessmentDimension::Identity,
        AssessmentValue::Integrity(_) => AssessmentDimension::Integrity,
        AssessmentValue::InstructionInjectionRisk(_) => {
            AssessmentDimension::InstructionInjectionRisk
        }
        AssessmentValue::DeceptionRisk(_) => AssessmentDimension::DeceptionRisk,
        AssessmentValue::ExfiltrationRisk(_) => AssessmentDimension::ExfiltrationRisk,
        AssessmentValue::PersistenceRisk(_) => AssessmentDimension::PersistenceRisk,
        AssessmentValue::SuspiciousPattern(_) => AssessmentDimension::SuspiciousPattern,
        AssessmentValue::AffectedCapability(_) => AssessmentDimension::AffectedCapability,
        AssessmentValue::SuggestedQuarantine(_) => AssessmentDimension::SuggestedQuarantine,
        AssessmentValue::RequiredProbe(_) => AssessmentDimension::RequiredProbe,
        AssessmentValue::Confidence(_) => AssessmentDimension::Confidence,
        AssessmentValue::Limitation(_) => AssessmentDimension::Limitation,
        AssessmentValue::Unknown(dimension) => *dimension,
    }
}

impl ObservedSourceFeature {
    /// Validates feature shape and dimension-local observation provenance.
    ///
    /// # Errors
    ///
    /// Returns an error when provenance, evidence, interval, or value shape is
    /// malformed.
    pub fn validate(&self) -> Result<(), crate::SecurityContractError> {
        assessment_text(&self.origin.observer_ref, "observed.origin.observer_ref")?;
        assessment_text(
            &self.origin.observation_revision,
            "observed.origin.observation_revision",
        )?;
        if self.origin.rule_ref.is_some() != self.origin.rule_revision.is_some() {
            return Err(crate::SecurityContractError::InvalidText {
                field: "observed.origin.rule_binding",
            });
        }
        if let Some(reference) = &self.origin.rule_ref {
            assessment_text(reference, "observed.origin.rule_ref")?;
        }
        if let Some(revision) = &self.origin.rule_revision {
            assessment_text(revision, "observed.origin.rule_revision")?;
        }
        assessment_refs(&self.evidence_handles, "observed.evidence_handles")?;
        self.observed_interval.validate()?;
        self.applicable_interval.validate()?;
        validate_assessment_value(&self.value)
    }
}

impl ModelProposedInterpretation {
    /// Validates model proposal shape without accepting model-declared rule authority.
    ///
    /// # Errors
    ///
    /// Returns an error when model/profile provenance, evidence, interval, or
    /// value shape is malformed.
    pub fn validate(&self) -> Result<(), crate::SecurityContractError> {
        assessment_text(&self.origin.model_ref, "interpretation.origin.model_ref")?;
        assessment_text(
            &self.origin.model_revision,
            "interpretation.origin.model_revision",
        )?;
        assessment_text(
            &self.origin.profile_revision,
            "interpretation.origin.profile_revision",
        )?;
        assessment_refs(&self.evidence_handles, "interpretation.evidence_handles")?;
        self.observed_interval.validate()?;
        self.applicable_interval.validate()?;
        validate_assessment_value(&self.value)
    }
}

impl SourceSecurityAssessment {
    /// Validates the bounded source identity, scope, assurance, and dimension rows.
    ///
    /// # Errors
    ///
    /// Returns an error when the source digest, scope, assurance binding, or any
    /// per-dimension record is malformed.
    pub fn validate(&self) -> Result<(), crate::SecurityContractError> {
        assessment_text(&self.assessment_ref, "assessment_ref")?;
        self.source.validate()?;
        if self.source_assurance.source_ref != self.source.source_ref {
            return Err(crate::SecurityContractError::InvalidText {
                field: "source_assurance.source_ref",
            });
        }
        self.source_assurance.validate()?;
        let mut dimensions = std::collections::BTreeSet::new();
        for feature in &self.observed_features {
            feature.validate()?;
            dimensions.insert(assessment_value_dimension(&feature.value));
        }
        for interpretation in &self.model_interpretations {
            interpretation.validate()?;
            dimensions.insert(assessment_value_dimension(&interpretation.value));
        }
        // A retained indicator record is validated here, once, so a malformed
        // one is refused at the use boundary instead of being skipped by the
        // resolution that consumes it.
        for record in &self.indicator_observations {
            record.validate()?;
        }
        if REQUIRED_ASSESSMENT_DIMENSIONS
            .iter()
            .any(|dimension| !dimensions.contains(dimension))
        {
            return Err(crate::SecurityContractError::EmptyCollection {
                field: "assessment_dimension_records",
            });
        }
        Ok(())
    }

    /// Resolves one I8.8 indicator for this assessment's exact source revision
    /// and returns the use authority that survives it.
    ///
    /// The finite indicator-to-source map is consulted with this assessment's
    /// own [`AssessedSourceRevision`], so an indicator is always scoped to the
    /// revision it was assessed against. A candidate-only resolution changes
    /// nothing: it returns exactly what [`Self::resolve_source_use`] returns.
    /// A bounded restriction is intersected on top of that, so it can only
    /// remove permitted uses and effects and can never widen them. Instruction
    /// taint always comes from the assurance in force, so a summary, a second
    /// model or a re-diagnosis cannot clear it.
    ///
    /// # Errors
    ///
    /// Returns an error when the assessment shape is malformed, when the
    /// indicator map refuses the class/evidence/observation combination, or
    /// when the fence or source in force is no longer the assessed one.
    pub fn resolve_indicator_use(
        &self,
        indicator: crate::IndicatorClass,
        evidence: &crate::IndicatorEvidence,
        observation: &crate::IndicatorObservation,
        current_assurance: &SourceAssurance,
        state_fence: &StateFence,
        release_condition: Option<&str>,
    ) -> Result<SourceUseAuthority, crate::SecurityContractError> {
        let base = self.resolve_source_use(current_assurance, state_fence)?;
        let resolution = crate::IndicatorSourceMap::resolve(
            indicator,
            evidence,
            observation,
            &self.source,
            state_fence,
            release_condition,
        )?;
        match resolution.restriction() {
            Some(restriction) => Ok(restriction
                .resolve_use(current_assurance, state_fence)?
                .narrowed_with(&base)),
            None => Ok(base),
        }
    }

    /// Resolves every I8.8 indicator observation this assessment retains, and
    /// returns the use authority that survives all of them.
    ///
    /// This is the entry point a use boundary calls: it takes the retained
    /// indicator records, sends each through the finite indicator-to-source map
    /// with this assessment's own [`AssessedSourceRevision`], and intersects the
    /// surviving authorities. Intersection only removes permitted uses and
    /// effects, so no record can widen them, and instruction taint always comes
    /// from the assurance in force, so no record can clear it.
    ///
    /// Nothing here mutates quarantine, Incident state or authority. A
    /// model-proposed record, a record whose comparison inputs were missing, and
    /// every content-shaped class each resolve to
    /// [`crate::IndicatorResolution::CandidateOnly`], which resolves to exactly
    /// the base narrowing; those records are therefore retained inert evidence
    /// here and nowhere else. Any record the map refuses fails the whole
    /// resolution rather than being skipped, so a malformed record cannot make
    /// the source look as though no indicator existed.
    ///
    /// # Errors
    ///
    /// Returns an error when the assessment shape or any retained indicator
    /// record is malformed, when the indicator map refuses a class/evidence/
    /// observation combination, or when the fence or source in force is no
    /// longer the assessed one.
    pub fn resolve_recorded_indicator_uses(
        &self,
        current_assurance: &SourceAssurance,
        state_fence: &StateFence,
    ) -> Result<SourceUseAuthority, crate::SecurityContractError> {
        let mut surviving = self.resolve_source_use(current_assurance, state_fence)?;
        for record in &self.indicator_observations {
            surviving = self
                .resolve_indicator_use(
                    record.indicator,
                    &record.evidence,
                    &record.observation,
                    current_assurance,
                    state_fence,
                    record.release_condition.as_deref(),
                )?
                .narrowed_with(&surviving);
        }
        Ok(surviving)
    }

    /// Resolves what one action may take from this assessed source right now.
    ///
    /// The current source owner supplies the assurance and the fence for the
    /// exact operation; this assessment only ever narrows them. A source, a
    /// profile, or a fence that moved between diagnosis and use is refused
    /// instead of being ignored, so a diagnosis cannot authorize a later
    /// revision. `model_interpretations` is never read here: a model claim
    /// narrows nothing and widens nothing, however confident it is.
    ///
    /// # Errors
    ///
    /// Returns an error when the assessment shape is malformed, when the fence
    /// in force is not the fence it was taken under, or when the source or its
    /// current assurance no longer match the assessed ones.
    pub fn resolve_source_use(
        &self,
        current_assurance: &SourceAssurance,
        state_fence: &StateFence,
    ) -> Result<SourceUseAuthority, crate::SecurityContractError> {
        self.validate()?;
        if self.source_assurance.state_fence != *state_fence {
            return Err(crate::SecurityContractError::FenceMismatch);
        }
        if self.source.source_ref != current_assurance.source_ref {
            return Err(crate::SecurityContractError::StaleSourceAssessment {
                field: "assessed_source.source_ref",
            });
        }
        if &self.source_assurance != current_assurance {
            return Err(crate::SecurityContractError::StaleSourceAssessment {
                field: "assessed_source.source_assurance",
            });
        }
        Ok(SourceUseAuthority {
            assessed_source: self.source.clone(),
            permitted_uses: assessment_intersection(
                &current_assurance.allowed_epistemic_use,
                &self.source_assurance.allowed_epistemic_use,
            ),
            permitted_effects: assessment_intersection(
                &current_assurance.allowed_effects,
                &self.source_assurance.allowed_effects,
            ),
            instruction_taint: current_assurance.instruction_taint,
            state_fence: state_fence.clone(),
        })
    }
}

/// Integrity of the source snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityStatus {
    Verified,
    Unverified,
    Modified,
    Conflicted,
}

/// Freshness of a source relative to a state fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FreshnessStatus {
    Current,
    Stale,
    Unknown,
}

/// Bounded competence classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompetenceLevel {
    DomainVerified,
    Attributed,
    Unknown,
}

/// Whether the source is independent of the evaluated route.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndependenceLevel {
    Independent,
    Related,
    CommonMode,
    Unknown,
}

/// Privacy class attached to a source domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrivacyClass {
    Public,
    Internal,
    Private,
    Secret,
    Licensed,
}

/// Instruction/data taint is independent from epistemic truth.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstructionTaint {
    Cleared,
    DataOnly,
    Untrusted,
    CommandLike,
}

/// Permitted epistemic interpretation of a source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpistemicUse {
    Observation,
    AttributedInput,
    CandidateEvidence,
    VerificationInput,
}

/// Maximum effect class a consumer may propose from a source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectCeiling {
    ReadOnly,
    CandidateOnly,
    NoExternalEffect,
}

/// Reversible source quarantine state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuarantineState {
    None,
    ReviewRequired,
    Quarantined,
    Released,
}

/// Policy-sized observation domain; IDs are opaque and non-revealing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservationDomainRef {
    pub domain_id: String,
    pub kind: ObservationDomainKind,
    pub authority_root: String,
    pub resource_scope: String,
    pub privacy_class: PrivacyClass,
    pub visibility_and_export_rule: String,
    pub model_route_rule: String,
    pub state_fence: StateFence,
}

/// Domain category used by disclosure policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationDomainKind {
    LocalRoot,
    ConnectedResource,
    UserPrivate,
    Tenant,
    SecretClass,
    ProviderRetention,
    LicensedSource,
    Custom,
}

/// Coverage status of a disclosure closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClosureCompleteness {
    Complete,
    Partial,
    Unknown,
}

/// Explicit domain lineage for one subject or derived representation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureDependencyClosure {
    pub closure_id: String,
    pub subject_ref: String,
    pub direct_domain_refs: Vec<ObservationDomainRef>,
    pub inherited_closure_refs: Vec<String>,
    pub derivation_or_transformation_refs: Vec<String>,
    pub completeness: ClosureCompleteness,
    pub declassification_receipt_refs: Vec<String>,
    pub policy_snapshot_id: String,
    pub state_fence: StateFence,
    pub revision: u64,
}

/// Decision made against a closure and recipient capability set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureDecision {
    pub subject_and_closure_ref: String,
    pub recipient_principal_or_route: String,
    pub recipient_capability_set: Vec<String>,
    pub covered_domains: Vec<String>,
    pub uncovered_domains: Vec<String>,
    pub decision: DisclosureDecisionKind,
    pub policy_snapshot_and_state_fence: PolicyFence,
    pub receipt_ref: String,
    pub closure_completeness: ClosureCompleteness,
}

/// Outcome of disclosure admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DisclosureDecisionKind {
    Allow,
    AllowRedacted,
    RecomputeNarrower,
    ForkPrivate,
    RequireAuthority,
    Deny,
}

/// Policy revision and state fence used by a disclosure decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyFence {
    pub policy_snapshot_id: String,
    pub state_fence: StateFence,
}

/// Verified deterministic transformation that may remove a domain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationReceipt {
    pub input_closure_ref: String,
    pub transformation_id_and_version: String,
    pub exact_input_hash: String,
    pub exact_output_hash: String,
    pub removed_or_generalized_domains: Vec<String>,
    pub preserved_domains: Vec<String>,
    pub verifier_and_property: String,
    pub residual_limitations: Vec<String>,
    pub authority_and_policy_ref: String,
    pub state_fence: StateFence,
}

/// Transformation lineage retaining input taint unless explicitly cleared.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransformationLineage {
    pub transformation_id: String,
    pub input_refs: Vec<String>,
    pub output_ref: String,
    pub operation: TransformationKind,
    pub input_taint: InstructionTaint,
    pub output_taint: InstructionTaint,
    pub declassification_receipt_ref: Option<String>,
    pub state_fence: StateFence,
}

/// Structural transform categories relevant to taint laundering.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransformationKind {
    Copy,
    Normalize,
    ModelSummary,
    Redact,
    Declassify,
    Aggregate,
}

/// Explicit influence dependency closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfluenceDependencyClosure {
    pub closure_id: String,
    pub root_ref: String,
    pub dependent_refs: Vec<String>,
    pub invalidation_reason: Option<RevocationReason>,
    pub current_influence: InfluenceState,
    pub state_fence: StateFence,
    pub revision: u64,
}

/// Current support/influence state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceState {
    Active,
    Quarantined,
    Revoked,
    Unknown,
}

/// Why an origin or dependency was invalidated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationReason {
    SourceRevoked,
    WrongScope,
    Poisoned,
    VerifierInvalid,
    PolicyChanged,
    Erasure,
}

/// Explicit purge ledger entry; it carries no deleted content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PurgeLedgerEntry {
    pub purge_id: String,
    pub subject_ref: String,
    pub scope: String,
    pub purged_locations: Vec<PurgeLocation>,
    pub tombstone_digest: String,
    pub state: PurgeState,
    pub state_fence: StateFence,
    pub revision: u64,
}

/// Location to which an erasure obligation applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PurgeLocation {
    CanonicalPayload,
    Projection,
    Index,
    Blob,
    OperationalRecovery,
    ProviderCopy,
    BackupRestorePath,
    RouteContinuation,
}

/// Purge lifecycle; terminal purged state cannot be restored as current data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PurgeState {
    Requested,
    InProgress,
    Purged,
    Blocked,
}

/// Stable schema identity of the versioned selection-integrity receipt family.
pub const SELECTION_INTEGRITY_SCHEMA: &str =
    "eliot.foundation.security-contracts.selection-integrity.v2";
/// Maximum stages one selection-integrity chain may declare.
pub const MAX_SELECTION_STAGES: usize = 64;
/// Maximum members one selection-integrity membership collection may declare.
pub const MAX_SELECTION_MEMBERS: usize = 4_096;
/// One-way disposition for a legacy unversioned selection receipt.
pub const SELECTION_INTEGRITY_LEGACY_V1_DISPOSITION: &str = concat!(
    "imported-as-unknown: a legacy receipt-level untrusted_structure_changed_membership=false ",
    "is absence of the old flag only, never proven absence of stage influence; a legacy stage ",
    "output that was not a legacy stage input is not attributable to any input member and is ",
    "rejected"
);

/// Closed untrusted-influence state of one stage or of the whole chain.
///
/// Declaration order is the claim-ceiling order: `Absent` is the strongest and
/// `Unknown` the weakest statement. I12.13 `Selection integrity` makes `unknown`
/// an admissible finding that lowers the claim ceiling of the dependent packet;
/// it never becomes `Absent` by assumption, and a later deterministic stage
/// cannot erase an earlier `Present` or `Unknown`.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelectionInfluenceState {
    /// Untrusted input provably did not change this membership.
    Absent,
    /// Untrusted input changed this membership and the change is recorded.
    Present,
    /// The producer cannot state whether untrusted input changed this membership.
    Unknown,
}

/// One hashed selection member: identity, revision and representation.
///
/// A membership digest binds these three fields in declared order, so it also
/// preserves the order a ranking or presentation boundary produced. Display
/// labels and counts are never hashed in their place.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionMember {
    /// Opaque member identity.
    pub member_ref: String,
    /// Exact member revision observed at this stage boundary.
    pub member_revision: String,
    /// Exact representation handed to or produced by the transformer.
    pub representation_ref: String,
}

/// What one stage did to one member.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelectionMemberDispositionKind {
    /// Carried forward unchanged into this stage's output membership.
    Retained,
    /// Left the membership; a reason is required.
    Removed,
    /// Folded into a derived output that took its place in the membership.
    Derived,
    /// Introduced during expansion from named admitted source evidence.
    Admitted,
}

/// One per-member disposition row.
///
/// `Removed` requires `reason`; `Derived` requires `derived_output_ref`; and
/// `Admitted` requires `source_evidence_ref`. A field that does not belong to
/// the disposition is absent, never an empty string.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionMemberDisposition {
    /// The input member, or the newly admitted output member, this row accounts for.
    pub member_ref: String,
    /// What the stage did to that member.
    pub disposition: SelectionMemberDispositionKind,
    /// Why the member left the membership.
    pub reason: Option<String>,
    /// Derived output that took the member's place in the membership.
    pub derived_output_ref: Option<String>,
    /// Admitted source evidence that introduced the member.
    pub source_evidence_ref: Option<String>,
}

/// How one stage's input membership was derived from earlier stages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "link", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum SelectionStageLink {
    /// The input is the complete output membership of the named stage.
    FromPredecessor {
        /// Stable identity of the immediately preceding stage.
        predecessor_stage_id: String,
    },
    /// The input is the complete union of the named parents' output memberships.
    FromJoin {
        /// Stable identities of every parent stage of the join.
        parent_stage_ids: Vec<String>,
    },
}

/// One immutable selection-transforming stage.
///
/// A stage appends to the chain and never overwrites an earlier membership
/// decision (I12.13 `Selection integrity`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionStage {
    /// Stable stage identity; content recorded under one identity is immutable.
    pub stage_id: String,
    /// Contiguous zero-based position of this stage in the chain.
    pub ordinal: usize,
    /// Derivation of the input membership; absent exactly at ordinal zero.
    pub input_link: Option<SelectionStageLink>,
    /// Stage category.
    pub stage: SelectionStageKind,
    /// Exact transformer identity and configuration revision.
    pub transformer_identity_and_config_revision: String,
    /// Input membership in the exact order the transformer received it.
    pub input_members: Vec<SelectionMember>,
    /// Lowercase SHA-256 over the canonical input membership.
    pub input_digest: String,
    /// Output membership in the exact order the transformer emitted it.
    pub output_members: Vec<SelectionMember>,
    /// Lowercase SHA-256 over the canonical output membership.
    pub output_digest: String,
    /// Exactly one row per input member, plus one row that explains every
    /// output member this stage introduced through a `Derived` or `Admitted`
    /// relation.
    pub member_dispositions: Vec<SelectionMemberDisposition>,
    /// Counterevidence or minority items this stage suppressed.
    pub suppressed_counterevidence_refs: Vec<String>,
    /// Budget or policy forced omissions this stage made.
    pub budget_or_policy_omission_refs: Vec<String>,
    /// Closed untrusted-influence state of this stage.
    pub untrusted_input_influenced_membership: SelectionInfluenceState,
    /// Evidence backing a `Present` or `Unknown` influence statement.
    pub influence_evidence_refs: Vec<String>,
    pub disclosure_closure_ref: String,
    pub state_fence: StateFence,
}

/// Rebuildable head of one selection chain, advanced with its stages.
///
/// The head is a projection of the immutable stage list, never an independent
/// authority: `chain_head_digest` is recomputed from the stages it points at
/// and compared, so a caller-supplied head value proves nothing on its own
/// (#1728 step 4).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionChainHead {
    /// Chain identity this head belongs to; it equals the receipt `selection_id`.
    pub selection_id: String,
    /// Ordinal of the last immutable stage in the chain.
    pub chain_head_ordinal: usize,
    /// Recomputed digest over the ordered stages up to `chain_head_ordinal`.
    pub chain_head_digest: String,
    /// Chain revision this head was advanced to by its append.
    pub chain_revision: u64,
    /// Stable idempotency identity of the append that produced this head.
    pub append_idempotency_key: String,
}

/// Exact seal between one selection chain and one delivered output.
///
/// Every field names content that must be compared with the chain that
/// produced the output, so a valid unrelated chain, a changed packet with the
/// same member count, or a swapped expansion handle cannot substitute
/// (#1728 step 6). The seal is written by the producer and re-verified by the
/// consumer against the receipt it is handed; a seal that was never verified
/// against this chain proves nothing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionChainSeal {
    /// Chain identity sealed; it must equal the receipt `selection_id`.
    pub selection_id: String,
    /// Chain-head digest this seal was taken against.
    pub chain_head_digest: String,
    /// Exact versioned recipe revision that produced the output.
    pub recipe_revision: String,
    /// Final membership in the exact delivered order, not a set.
    pub final_output_refs: Vec<String>,
    /// Final ordered membership digest recomputed over
    /// `final_output_members`.
    pub final_output_digest: String,
    /// The final ordered membership whose digest is `final_output_digest`.
    pub final_output_members: Vec<SelectionMember>,
    /// Lowercase SHA-256 over the exact packet or export bytes delivered.
    pub packet_bytes_digest: String,
    /// Exact expansion handles delivered alongside the output.
    pub expansion_handle_ids: Vec<String>,
    /// Complete closure over any membership page the chain references.
    ///
    /// A chain that delegates a membership list to a retained immutable page
    /// names that page and its verified complete closure here; a page cap is
    /// never permission to drop an earlier stage or counterevidence.
    pub membership_page_refs: Vec<String>,
}

/// Receipt of candidate-set membership through all selection transformations.
///
/// The receipt records history, not permission. A well-formed record of known or
/// unknown untrusted influence validates so it can be audited; whether that
/// history may be relied on is a separate policy decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionIntegrityReceipt {
    /// Closed schema identity of this receipt family.
    pub schema: String,
    /// Contract version this receipt was written against.
    pub contract_version: eliot_contracts::ContractVersion,
    /// Chain identity of this selection history.
    pub selection_id: String,
    /// Shared root context this chain was compiled for.
    pub root_context_ref: String,
    /// Exact versioned context recipe revision that produced the chain.
    pub recipe_revision: String,
    /// Immutable initial candidate membership in retrieval order.
    pub initial_candidate_members: Vec<SelectionMember>,
    /// Lowercase SHA-256 over the canonical initial candidate membership.
    pub initial_candidate_digest: String,
    pub admitted_candidate_refs: Vec<String>,
    pub rejected_candidate_refs: Vec<String>,
    pub transformation_stages: Vec<SelectionStage>,
    /// Final membership. Empty is a legitimate all-rejected result.
    pub final_output_refs: Vec<String>,
    /// Chain influence ceiling; it may never be weaker than any stage state.
    pub chain_untrusted_influence: SelectionInfluenceState,
    pub state_fence: StateFence,
    pub revision: u64,
}

/// Stage categories for selection-integrity lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelectionStageKind {
    GraphPivot,
    ClusterExpansion,
    Rerank,
    Prune,
    Summary,
    ContextCompile,
    ToolExport,
}

/// Exact pre-migration v1 selection receipt wire.
///
/// v1 carried one receipt-level `untrusted_structure_changed_membership` Boolean
/// and stages with no identity, ordinal, digest, per-member disposition or
/// influence state. Old bytes deserialize here explicitly and are never
/// reinterpreted as a stage-continuous chain; see
/// [`SELECTION_INTEGRITY_LEGACY_V1_DISPOSITION`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegacySelectionIntegrityReceiptV1 {
    pub selection_id: String,
    pub initial_candidate_refs: Vec<String>,
    pub admitted_candidate_refs: Vec<String>,
    pub rejected_candidate_refs: Vec<String>,
    pub transformation_stages: Vec<LegacySelectionStageV1>,
    pub final_output_refs: Vec<String>,
    pub untrusted_structure_changed_membership: bool,
    pub state_fence: StateFence,
    pub revision: u64,
}

/// Exact pre-migration v1 stage wire, which recorded no member relation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegacySelectionStageV1 {
    pub stage: SelectionStageKind,
    pub input_refs: Vec<String>,
    pub output_refs: Vec<String>,
    pub disclosure_closure_ref: String,
    pub state_fence: StateFence,
}
