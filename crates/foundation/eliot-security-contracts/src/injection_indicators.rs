//! Finite indicator-to-source map for the I8.8 injection signals.
//!
//! The inventory is closed: exactly eight named indicator classes, each paired
//! with one exact evidence shape, each mapped to one exact, source-revision
//! scoped outcome. There is no textual classifier, no score and no threshold
//! here. The producer supplies typed evidence; this map only decides which of
//! the eight classes that evidence belongs to and what, if anything, that class
//! is allowed to propose.
//!
//! Three properties are structural rather than documented:
//!
//! - A model-only observation resolves to
//!   [`IndicatorResolution::CandidateOnly`]. That variant has no restriction
//!   payload, so no quarantine, Incident or authority change is expressible
//!   through it at any confidence.
//! - The three content-shaped classes resolve to a candidate only even under a
//!   deterministic rule, because instruction-like text is an observed or
//!   suspected pattern and not proof of malicious intent.
//! - A restriction carries no instruction taint of its own and no field for a
//!   standing instruction, tool definition, policy, credential or Incident, so
//!   no evidence payload and no source content can change one.
//!
//! Quarantine admission adds a fourth, and it is the one that closes the gap
//! between proposing a restriction and mutating state. A
//! [`ProposedSourceRestriction`] is a proposal; [`AdmittedSourceQuarantine`] is
//! the admitted transition, and the two are separated by type rather than by a
//! check: the only ways to build an admission take either that restriction —
//! which this map produces solely for a rule-bound independent observation — or
//! an authorized decision's own identity. A model proposal has no rule field to
//! supply and therefore no restriction to admit, so the path from a model-only
//! judgement to a quarantine mutation does not exist to be closed later.

use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::surface_types::{
    AssessedSourceRevision, EffectCeiling, EpistemicUse, SourceAssurance, SourceUseAuthority,
    assessment_refs, assessment_text,
};
use crate::{InfluenceDependencyClosure, SecurityContractError};

/// Number of indicator classes the I8.8 inventory fixes.
pub const INDICATOR_CLASS_COUNT: usize = 8;

/// The eight named I8.8 indicator classes, in inventory order.
///
/// This is the whole map. An observation belongs to exactly one of these, or it
/// is not classified here.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndicatorClass {
    /// External document attempts to issue system/tool instructions.
    ExternalInstructionAttempt,
    /// Tool Definition changes name/schema/defaults unexpectedly.
    UnexpectedToolDefinitionChange,
    /// Source asks to persist a standing instruction or secret.
    StandingInstructionOrSecretPersistence,
    /// Summary attempts to raise source authority.
    SummaryAuthorityEscalation,
    /// Multiple model outputs repeat one poisoned lineage.
    RepeatedPoisonedLineage,
    /// Remote Dream query attempts broad data extraction.
    OverbroadRemoteDreamExtraction,
    /// Memory transformation drops origin/minority evidence.
    DroppedOriginOrMinorityEvidence,
    /// Procedure candidate introduces an undeclared side effect.
    UndeclaredProcedureEffect,
}

impl IndicatorClass {
    /// Every indicator class, in inventory order.
    pub const ALL: [Self; INDICATOR_CLASS_COUNT] = [
        Self::ExternalInstructionAttempt,
        Self::UnexpectedToolDefinitionChange,
        Self::StandingInstructionOrSecretPersistence,
        Self::SummaryAuthorityEscalation,
        Self::RepeatedPoisonedLineage,
        Self::OverbroadRemoteDreamExtraction,
        Self::DroppedOriginOrMinorityEvidence,
        Self::UndeclaredProcedureEffect,
    ];

    /// What this class is permitted to propose from a matching evidence row.
    ///
    /// I8.8 records that textual instruction-like content is an observed or
    /// suspected pattern, not proof of malicious intent, so the three
    /// content-shaped classes are confined to
    /// [`IndicatorResponse::SuspectedPattern`] and can never produce a
    /// restriction, whatever rule observes them. The five classes whose
    /// evidence is an exact comparison — approved-schema delta, request
    /// scope/effect comparison, or a verified transformation record — may
    /// propose a bounded restriction, and only from an independent
    /// deterministic rule.
    pub const fn response(self) -> IndicatorResponse {
        match self {
            Self::ExternalInstructionAttempt
            | Self::StandingInstructionOrSecretPersistence
            | Self::SummaryAuthorityEscalation => IndicatorResponse::SuspectedPattern,
            Self::UnexpectedToolDefinitionChange
            | Self::RepeatedPoisonedLineage
            | Self::OverbroadRemoteDreamExtraction
            | Self::DroppedOriginOrMinorityEvidence
            | Self::UndeclaredProcedureEffect => IndicatorResponse::BoundedRestriction,
        }
    }

    /// The uses this class may leave admissible, before intersection.
    ///
    /// A suspected-pattern class has no restricted set, because it can never
    /// reach a restriction; the empty slice it returns is what stops a
    /// suspected pattern from ever removing a use.
    pub const fn permitted_uses(self) -> &'static [EpistemicUse] {
        const OBSERVED_CANDIDATE: &[EpistemicUse] =
            &[EpistemicUse::Observation, EpistemicUse::CandidateEvidence];
        const SUSPECTED_PATTERN_NONE: &[EpistemicUse] = &[];
        match self {
            Self::ExternalInstructionAttempt
            | Self::StandingInstructionOrSecretPersistence
            | Self::SummaryAuthorityEscalation => SUSPECTED_PATTERN_NONE,
            Self::UnexpectedToolDefinitionChange
            | Self::RepeatedPoisonedLineage
            | Self::OverbroadRemoteDreamExtraction
            | Self::DroppedOriginOrMinorityEvidence
            | Self::UndeclaredProcedureEffect => OBSERVED_CANDIDATE,
        }
    }

    /// The effect ceilings this class may leave admissible, before
    /// intersection.
    ///
    /// The same rule applies: a suspected-pattern class contributes no effect
    /// ceiling.
    pub const fn permitted_effects(self) -> &'static [EffectCeiling] {
        const READ_ONLY_NO_EXTERNAL: &[EffectCeiling] =
            &[EffectCeiling::ReadOnly, EffectCeiling::NoExternalEffect];
        const READ_ONLY_CANDIDATE: &[EffectCeiling] =
            &[EffectCeiling::ReadOnly, EffectCeiling::CandidateOnly];
        const SUSPECTED_PATTERN_NONE: &[EffectCeiling] = &[];
        match self {
            Self::ExternalInstructionAttempt
            | Self::StandingInstructionOrSecretPersistence
            | Self::SummaryAuthorityEscalation => SUSPECTED_PATTERN_NONE,
            Self::RepeatedPoisonedLineage | Self::DroppedOriginOrMinorityEvidence => {
                READ_ONLY_CANDIDATE
            }
            Self::UnexpectedToolDefinitionChange
            | Self::OverbroadRemoteDreamExtraction
            | Self::UndeclaredProcedureEffect => READ_ONLY_NO_EXTERNAL,
        }
    }

    /// Whether this class accepts exactly the supplied evidence shape.
    ///
    /// This is the closed pairing of the map. A caller that supplies one
    /// class's evidence under another class's name is refused.
    pub fn accepts(self, evidence: &IndicatorEvidence) -> bool {
        evidence.class() == self
    }

    /// Opaque class name, for contract error text and stable cross-owner
    /// reference.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ExternalInstructionAttempt => "EXTERNAL_INSTRUCTION_ATTEMPT",
            Self::UnexpectedToolDefinitionChange => "UNEXPECTED_TOOL_DEFINITION_CHANGE",
            Self::StandingInstructionOrSecretPersistence => {
                "STANDING_INSTRUCTION_OR_SECRET_PERSISTENCE"
            }
            Self::SummaryAuthorityEscalation => "SUMMARY_AUTHORITY_ESCALATION",
            Self::RepeatedPoisonedLineage => "REPEATED_POISONED_LINEAGE",
            Self::OverbroadRemoteDreamExtraction => "OVERBROAD_REMOTE_DREAM_EXTRACTION",
            Self::DroppedOriginOrMinorityEvidence => "DROPPED_ORIGIN_OR_MINORITY_EVIDENCE",
            Self::UndeclaredProcedureEffect => "UNDECLARED_PROCEDURE_EFFECT",
        }
    }
}

/// How much of the eight classes a single class is allowed to propose.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndicatorResponse {
    /// Recorded as an observed or suspected pattern. Never a restriction, and
    /// never by itself a malicious-source finding.
    SuspectedPattern,
    /// May propose a bounded restriction, and only from an independent
    /// deterministic rule over the exact comparison evidence.
    BoundedRestriction,
}

/// What a producer states about a foreign instruction-shaped passage.
///
/// The producer classifies the passage's role in the retained bytes. A quoted
/// example inside otherwise ordinary prose stays retained inert evidence, so a
/// benign example cannot become an admitted malicious-source finding. This is a
/// typed, finite choice, never a text match.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExternalContentRole {
    /// The retained bytes address the reader as system or tool.
    DirectInstruction,
    /// The retained bytes quote an instruction-shaped example inside prose.
    QuotedExample,
    /// The retained bytes describe an instruction without issuing one.
    Narration,
}

/// Which exact approved-schema field a tool definition changed.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolDefinitionDelta {
    Name,
    Schema,
    Default,
}

/// What a source asked to have persisted beyond the current operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PersistenceRequest {
    StandingInstruction,
    Secret,
    StandingInstructionAndSecret,
}

/// Scope a remote Dream request reached for, against what was admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExtractionScope {
    /// Every project rather than the admitted scope.
    AllProjects,
    /// Every source revision rather than the named handles.
    AllSourceRevisions,
    /// Recipient domains outside the admitted disclosure domain.
    CrossDomain,
}

/// Which kind of retained memory evidence a transformation dropped.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DroppedEvidenceKind {
    OriginProvenance,
    MinorityPosition,
    OriginAndMinority,
}

/// Retained foreign material an indicator class cites.
///
/// The instruction-attempt class and the standing-instruction/secret-persistence
/// class cite retained material the same way — an immutable artifact the
/// passage was read from, plus retained handles for the passage inside it — and
/// differ only in what they conclude from it. They therefore share this one
/// shape and are distinguished by their [`IndicatorEvidence`] variant and its
/// class-specific field, rather than by two near-identical payload structs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetainedExternalEvidence {
    /// Retained immutable artifact the passage was read from.
    pub retained_source_ref: String,
    /// Retained handles for the passage itself, in the restricted store.
    pub evidence_handles: Vec<String>,
}

/// An installed tool definition that departs from the approved schema.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolDefinitionChangeEvidence {
    /// Installed tool definition revision observed.
    pub observed_tool_ref: String,
    /// The exact non-empty deltas, compared field by field.
    pub deltas: Vec<ToolDefinitionDelta>,
    /// Approved schema revision the deltas were computed against. Absent means
    /// the comparison baseline is unknown, so the class bounds nothing.
    pub approved_schema_revision: Option<String>,
}

/// A derived summary claiming a use its source owner does not grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryAuthorityEvidence {
    /// The summary revision that made the claim.
    pub summary_ref: String,
    /// The use the summary claimed for its source.
    pub claimed_use: EpistemicUse,
    /// The uses the current source owner actually grants. Absent means the claim
    /// cannot be compared, so the class bounds nothing.
    pub owner_permitted_uses: Option<Vec<EpistemicUse>>,
}

/// Several outputs repeating one lineage a transformation record marks bad.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepeatedLineageEvidence {
    /// The lineage all the outputs repeat.
    pub lineage_ref: String,
    /// The distinct outputs that repeat it; at least two are required.
    pub repeated_output_refs: Vec<String>,
    /// Verified transformation record for the lineage. Absent means the lineage
    /// cannot be verified, so the class bounds nothing.
    pub transformation_ref: Option<String>,
}

/// A remote Dream request reaching beyond its admitted handles and question.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BroadExtractionEvidence {
    /// The bounded request that was issued.
    pub request_ref: String,
    /// The exact handles the request was admitted for.
    pub admitted_handle_refs: Vec<String>,
    /// The scope the request actually reached for.
    pub requested_scope: ExtractionScope,
    /// The admitted-scope handles the request exceeded. Non-empty, or the
    /// request reached nothing beyond its admitted scope.
    pub exceeded_handle_refs: Vec<String>,
}

/// A transformation that dropped retained origin or minority evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DroppedEvidenceRecord {
    /// The transformation that dropped the evidence.
    pub transformation_ref: String,
    /// Which kind of evidence it dropped.
    pub dropped: DroppedEvidenceKind,
    /// Retained handles for the dropped origin provenance.
    pub dropped_origin_refs: Vec<String>,
    /// Retained handles for the dropped minority position.
    pub dropped_minority_refs: Vec<String>,
    /// Verified transformation record. Absent means the drop cannot be
    /// attributed, so the class bounds nothing.
    pub verified_transformation_ref: Option<String>,
}

/// A procedure candidate performing an effect it never declared.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndeclaredEffectEvidence {
    /// The procedure candidate revision.
    pub procedure_ref: String,
    /// The effect observed outside the candidate's declared effects.
    pub observed_effect: EffectCeiling,
    /// The effects the candidate declared. Absent means the declaration cannot
    /// be compared, so the class bounds nothing.
    pub declared_effects: Option<Vec<EffectCeiling>>,
}

/// The exact evidence shape that belongs to each indicator class.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "indicator",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum IndicatorEvidence {
    /// External material that attempts to issue system or tool instructions.
    ExternalInstructionAttempt {
        /// The retained foreign material the passage was read from.
        retained: RetainedExternalEvidence,
        /// The producer's classification of the passage's role.
        content_role: ExternalContentRole,
    },
    UnexpectedToolDefinitionChange(ToolDefinitionChangeEvidence),
    /// A source asking to persist a standing instruction or a secret.
    StandingInstructionOrSecretPersistence {
        /// The retained foreign material the request was read from.
        retained: RetainedExternalEvidence,
        /// Exactly what the source asked to have persisted.
        requested: PersistenceRequest,
    },
    SummaryAuthorityEscalation(SummaryAuthorityEvidence),
    RepeatedPoisonedLineage(RepeatedLineageEvidence),
    OverbroadRemoteDreamExtraction(BroadExtractionEvidence),
    DroppedOriginOrMinorityEvidence(DroppedEvidenceRecord),
    UndeclaredProcedureEffect(UndeclaredEffectEvidence),
}

impl IndicatorEvidence {
    /// The retained foreign material this evidence cites, when it cites any.
    ///
    /// Both retained-material classes carry the same
    /// [`RetainedExternalEvidence`] payload, so this reaches them through one
    /// accessor. That shared type is what lets the two patterns bind the same
    /// name: binding one name across two differently-typed payload variants is
    /// a type error, and giving the two classes one payload shape is both the
    /// true statement and the legal way to dispatch on them together.
    fn retained(&self) -> Option<&RetainedExternalEvidence> {
        match self {
            Self::ExternalInstructionAttempt { retained, .. }
            | Self::StandingInstructionOrSecretPersistence { retained, .. } => Some(retained),
            Self::UnexpectedToolDefinitionChange(_)
            | Self::SummaryAuthorityEscalation(_)
            | Self::RepeatedPoisonedLineage(_)
            | Self::OverbroadRemoteDreamExtraction(_)
            | Self::DroppedOriginOrMinorityEvidence(_)
            | Self::UndeclaredProcedureEffect(_) => None,
        }
    }

    /// The one indicator class this evidence shape belongs to.
    pub const fn class(&self) -> IndicatorClass {
        match self {
            Self::ExternalInstructionAttempt { .. } => IndicatorClass::ExternalInstructionAttempt,
            Self::UnexpectedToolDefinitionChange(_) => {
                IndicatorClass::UnexpectedToolDefinitionChange
            }
            Self::StandingInstructionOrSecretPersistence { .. } => {
                IndicatorClass::StandingInstructionOrSecretPersistence
            }
            Self::SummaryAuthorityEscalation(_) => IndicatorClass::SummaryAuthorityEscalation,
            Self::RepeatedPoisonedLineage(_) => IndicatorClass::RepeatedPoisonedLineage,
            Self::OverbroadRemoteDreamExtraction(_) => {
                IndicatorClass::OverbroadRemoteDreamExtraction
            }
            Self::DroppedOriginOrMinorityEvidence(_) => {
                IndicatorClass::DroppedOriginOrMinorityEvidence
            }
            Self::UndeclaredProcedureEffect(_) => IndicatorClass::UndeclaredProcedureEffect,
        }
    }

    /// Whether every comparison input this class needs was available.
    ///
    /// A missing approved-schema baseline, transformation record, owner
    /// assurance or declared-effect list is reported here, so a caller cannot
    /// record a bounded restriction over a comparison that was never made. An
    /// instruction-shaped passage that the producer classified as a quoted
    /// example or as narration establishes no attempt by this source at all, so
    /// it reports unknown coverage rather than complete.
    ///
    /// The two classes with no optional baseline name the field their
    /// comparison rests on instead of asserting a bare `true`, so each arm
    /// states what it actually depends on.
    pub const fn has_comparison_inputs(&self) -> bool {
        match self {
            Self::ExternalInstructionAttempt { content_role, .. } => {
                matches!(content_role, ExternalContentRole::DirectInstruction)
            }
            Self::StandingInstructionOrSecretPersistence { retained, .. } => {
                !retained.retained_source_ref.is_empty()
            }
            Self::UnexpectedToolDefinitionChange(evidence) => {
                evidence.approved_schema_revision.is_some()
            }
            Self::SummaryAuthorityEscalation(evidence) => evidence.owner_permitted_uses.is_some(),
            Self::RepeatedPoisonedLineage(evidence) => evidence.transformation_ref.is_some(),
            Self::OverbroadRemoteDreamExtraction(evidence) => {
                !evidence.admitted_handle_refs.is_empty()
            }
            Self::DroppedOriginOrMinorityEvidence(evidence) => {
                evidence.verified_transformation_ref.is_some()
            }
            Self::UndeclaredProcedureEffect(evidence) => evidence.declared_effects.is_some(),
        }
    }

    /// Validates the evidence's own shape and the comparisons it claims.
    ///
    /// # Errors
    ///
    /// Returns an error when a reference is blank or duplicated, a required
    /// collection is empty, or the evidence does not actually establish its own
    /// class.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        if let Some(retained) = self.retained() {
            validate_retained(retained)?;
        }
        match self {
            // The retained-material classes share one payload shape, so this is
            // a single arm with nothing to bind.
            Self::ExternalInstructionAttempt { .. }
            | Self::StandingInstructionOrSecretPersistence { .. } => Ok(()),
            Self::UnexpectedToolDefinitionChange(evidence) => {
                validate_tool_definition_change(evidence)
            }
            Self::SummaryAuthorityEscalation(evidence) => validate_summary_authority(evidence),
            Self::RepeatedPoisonedLineage(evidence) => validate_repeated_lineage(evidence),
            Self::OverbroadRemoteDreamExtraction(evidence) => validate_broad_extraction(evidence),
            Self::DroppedOriginOrMinorityEvidence(evidence) => validate_dropped_evidence(evidence),
            Self::UndeclaredProcedureEffect(evidence) => validate_undeclared_effect(evidence),
        }
    }

    /// The retained references this record cites, sorted and de-duplicated.
    fn cited_refs(&self) -> Vec<String> {
        let mut refs = match self {
            // One shared payload shape, so the retained-material classes cite
            // through a single arm.
            Self::ExternalInstructionAttempt { retained, .. }
            | Self::StandingInstructionOrSecretPersistence { retained, .. } => {
                retained.evidence_handles.clone()
            }
            Self::UnexpectedToolDefinitionChange(evidence) => {
                vec![evidence.observed_tool_ref.clone()]
            }
            Self::SummaryAuthorityEscalation(evidence) => vec![evidence.summary_ref.clone()],
            Self::RepeatedPoisonedLineage(evidence) => {
                let mut refs = vec![evidence.lineage_ref.clone()];
                refs.extend(evidence.repeated_output_refs.iter().cloned());
                refs
            }
            Self::OverbroadRemoteDreamExtraction(evidence) => {
                vec![evidence.request_ref.clone()]
            }
            Self::DroppedOriginOrMinorityEvidence(evidence) => {
                vec![evidence.transformation_ref.clone()]
            }
            Self::UndeclaredProcedureEffect(evidence) => vec![evidence.procedure_ref.clone()],
        };
        refs.sort();
        refs.dedup();
        refs
    }
}

/// Coverage of the comparison inputs one indicator resolution used.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum IndicatorCoverage {
    /// Every required baseline, lineage or sensor record was present.
    Complete,
    /// A required comparison input was absent, so the class bounds nothing.
    UnknownComparisonInput,
}

/// Who produced the observation behind a resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "origin",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum IndicatorObservation {
    /// An independent observation, optionally bound to a deterministic rule.
    ///
    /// Without a bound rule revision this observation is still an observation
    /// and not an authority: it resolves to
    /// [`IndicatorResolution::CandidateOnly`].
    Independent {
        /// Opaque observer identity.
        observer_ref: String,
        /// Revision of the observation itself.
        observation_revision: String,
        /// Deterministic rule that produced the comparison.
        rule_ref: Option<String>,
        /// Revision of that rule, required whenever `rule_ref` is present.
        rule_revision: Option<String>,
    },
    /// An optional model-proposed interpretation.
    ///
    /// This shape has no rule identity and no deterministic flag, so a model
    /// cannot supply one. It always resolves to
    /// [`IndicatorResolution::CandidateOnly`].
    ModelProposal {
        /// Opaque model identity.
        model_ref: String,
        /// Revision of that model.
        model_revision: String,
        /// Profile revision the proposal was made under.
        profile_revision: String,
    },
}

impl IndicatorObservation {
    /// The deterministic rule binding, when an independent observation has one.
    pub fn rule_binding(&self) -> Option<(&str, &str)> {
        match self {
            Self::Independent {
                rule_ref: Some(rule_ref),
                rule_revision: Some(rule_revision),
                ..
            } => Some((rule_ref.as_str(), rule_revision.as_str())),
            _ => None,
        }
    }

    /// Validates the observation's own provenance shape.
    ///
    /// # Errors
    ///
    /// Returns an error when a provenance reference is blank, or when a rule
    /// reference is present without its revision.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        match self {
            Self::Independent {
                observer_ref,
                observation_revision,
                rule_ref,
                rule_revision,
            } => {
                assessment_text(observer_ref, "observation.observer_ref")?;
                assessment_text(observation_revision, "observation.observation_revision")?;
                if rule_ref.is_some() != rule_revision.is_some() {
                    return Err(SecurityContractError::InvalidText {
                        field: "observation.rule_binding",
                    });
                }
                if let Some(reference) = rule_ref {
                    assessment_text(reference, "observation.rule_ref")?;
                }
                if let Some(revision) = rule_revision {
                    assessment_text(revision, "observation.rule_revision")?;
                }
                Ok(())
            }
            Self::ModelProposal {
                model_ref,
                model_revision,
                profile_revision,
            } => {
                assessment_text(model_ref, "observation.model_ref")?;
                assessment_text(model_revision, "observation.model_revision")?;
                assessment_text(profile_revision, "observation.profile_revision")
            }
        }
    }
}

/// One classified I8.8 indicator observation, as a source assessment retains it.
///
/// This is the shape a producer writes and the use boundary reads. It names the
/// class the producer classified, the exact evidence supporting that
/// classification, the provenance of whoever produced it, and the discriminating
/// evidence that would release a restriction this record may support. It is
/// retained evidence, not authority: nothing here is resolved until
/// [`IndicatorSourceMap`] decides what the combination may propose, and that
/// decision is a narrowing of use, never a grant.
///
/// A model-proposed observation may be retained here exactly as an independent
/// one may. Retaining it says nothing about it, and the map resolves a model
/// proposal to [`IndicatorResolution::CandidateOnly`] whatever it claims.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordedIndicatorObservation {
    /// The indicator class the producer classified.
    pub indicator: IndicatorClass,
    /// The exact evidence that supports the classification. The map refuses a
    /// record whose evidence belongs to a different class.
    pub evidence: IndicatorEvidence,
    /// The provenance of the observation. A model proposal has no rule identity
    /// to supply here, so it cannot arrive with one.
    pub observation: IndicatorObservation,
    /// The discriminating evidence that would release a restriction this record
    /// may support. Required by the map for a class that may propose one;
    /// ignored for a class that may not, which has no release to describe.
    pub release_condition: Option<String>,
}

impl RecordedIndicatorObservation {
    /// Validates this record's own shape, independently of any resolution.
    ///
    /// A record that is retained malformed is refused at the use boundary
    /// rather than skipped, so a producer cannot store a record the map would
    /// refuse and have the source treated as if no indicator existed.
    ///
    /// # Errors
    ///
    /// Returns an error when the class does not accept the evidence, when the
    /// evidence or the observation provenance is malformed, or when a release
    /// condition is present but blank.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        if !self.indicator.accepts(&self.evidence) {
            return Err(SecurityContractError::SecurityIndicatorMismatch {
                indicator: self.indicator.name(),
                evidence: self.evidence.class().name(),
            });
        }
        self.evidence.validate()?;
        self.observation.validate()?;
        if let Some(condition) = &self.release_condition {
            assessment_text(condition, "indicator.release_condition")?;
        }
        Ok(())
    }
}

/// A bounded, source-revision scoped restriction an indicator may propose.
///
/// Every permitted set here is later intersected with the assurance in force
/// for the same operation, and the resolved instruction taint is taken from
/// that assurance verbatim, so this record can only remove uses and effects. It
/// has no field for a standing instruction, tool definition, policy, credential
/// or Incident.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedSourceRestriction {
    /// The indicator class this restriction came from.
    pub indicator: IndicatorClass,
    /// The exact source revision, digest and scope it is bound to.
    pub assessed_source: AssessedSourceRevision,
    /// Uses this indicator may leave admissible, before intersection.
    pub permitted_uses: &'static [EpistemicUse],
    /// Effect ceilings this indicator may leave admissible, before
    /// intersection.
    pub permitted_effects: &'static [EffectCeiling],
    /// The deterministic rule that supports the restriction.
    pub rule_ref: String,
    /// The revision of that rule.
    pub rule_revision: String,
    /// The condition under which the restriction may later be released.
    pub release_condition: String,
    /// The fence this restriction was prepared under.
    pub state_fence: StateFence,
}

impl ProposedSourceRestriction {
    /// Resolves the restricted use authority for one exact operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the fence in force is not the fence this
    /// restriction was prepared under, or when the source revision no longer
    /// matches the one this restriction names.
    pub fn resolve_use(
        &self,
        current_assurance: &SourceAssurance,
        state_fence: &StateFence,
    ) -> Result<SourceUseAuthority, SecurityContractError> {
        if self.state_fence != *state_fence {
            return Err(SecurityContractError::FenceMismatch);
        }
        if self.assessed_source.source_ref != current_assurance.source_ref {
            return Err(SecurityContractError::StaleSourceAssessment {
                field: "restriction.assessed_source.source_ref",
            });
        }
        Ok(SourceUseAuthority {
            assessed_source: self.assessed_source.clone(),
            permitted_uses: intersect(
                self.permitted_uses,
                &current_assurance.allowed_epistemic_use,
            ),
            permitted_effects: intersect(
                self.permitted_effects,
                &current_assurance.allowed_effects,
            ),
            instruction_taint: current_assurance.instruction_taint,
            state_fence: state_fence.clone(),
        })
    }
}

/// What the map resolved one indicator to, for one exact source revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndicatorResolution {
    /// Candidate evidence only.
    ///
    /// This variant has no restriction payload, so producing it performs zero
    /// quarantine, Incident and authority mutations. A model-only proposal, an
    /// incomplete comparison, and every content-shaped class resolve here.
    CandidateOnly {
        /// The indicator class that was recorded.
        indicator: IndicatorClass,
        /// The exact source revision the record is scoped to.
        assessed_source: AssessedSourceRevision,
        /// Coverage of the comparison inputs that were available.
        coverage: IndicatorCoverage,
        /// Retained evidence references, sorted and de-duplicated.
        cited_refs: Vec<String>,
    },
    /// A bounded restriction a deterministic rule supports.
    BoundedRestriction(ProposedSourceRestriction),
}

impl IndicatorResolution {
    /// The restriction, when this resolution carries one.
    pub fn restriction(&self) -> Option<&ProposedSourceRestriction> {
        match self {
            Self::CandidateOnly { .. } => None,
            Self::BoundedRestriction(restriction) => Some(restriction),
        }
    }
}

/// The bindings an authorized decision supplies for a quarantine.
///
/// Grouping them keeps the two authority arms comparable: the deterministic arm
/// fills this from the restriction the indicator map produced, the authorized
/// arm fills it from the decision, and both then pass through the same checks.
/// It is a borrowed grouping only — it grants nothing on its own, and neither
/// admission path accepts it without the authority that arm requires.
pub struct QuarantineBindings<'a> {
    /// The exact assessed source revision being quarantined.
    pub assessed_source: &'a AssessedSourceRevision,
    /// Uses that may remain admissible, before intersection.
    pub permitted_uses: &'a [EpistemicUse],
    /// Effect ceilings that may remain admissible, before intersection.
    pub permitted_effects: &'a [EffectCeiling],
    /// The release and rebuild condition that must hold before this lifts.
    pub release_condition: &'a str,
    /// The exact influence dependency closure this is bounded to.
    pub dependency_closure: &'a InfluenceDependencyClosure,
    /// The state revision the store will compare-and-swap against.
    pub expected_state_revision: u64,
    /// The named owner of this admission and of its release.
    pub owner: &'a str,
    /// The fence this admission was prepared under.
    pub state_fence: &'a StateFence,
}

/// One admitted source quarantine, bound to everything it may affect.
///
/// This is the admission the Governor prepares and the Kernel/Store validate
/// and receipt. It has exactly two construction paths, and both are authority:
/// [`Self::admit_from_rule`], which takes a [`ProposedSourceRestriction`] that
/// only [`IndicatorSourceMap::resolve`] produces and only for an independent
/// observation carrying a rule binding, and [`Self::admit_from_decision`],
/// which takes an authorized decision's own identity. A model-only judgement
/// resolves to [`IndicatorResolution::CandidateOnly`], which carries no
/// restriction payload, so there is no value it can hand to either path — the
/// guarantee is carried by the shape of the input, not by a confidence check a
/// later edit could remove.
///
/// Every binding below is compared rather than restated, and the closure is the
/// exact affected scope, so an admission can name one source and one closure
/// only.
///
/// It derives the wire traits because it is the record the Governor prepares
/// and the Kernel/Store validate and receipt: `admit_from_rule` and
/// `admit_from_decision` are the only ways to obtain one in Rust, and
/// deserialization is how a prepared admission reaches the store that receipts
/// it. Deserializing does not weaken that, because every binding is re-checked
/// against the live closure, revision, owner and fence by
/// [`Self::validate_against`] before it is admitted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedSourceQuarantine {
    affected_source: AssessedSourceRevision,
    dependency_closure: InfluenceDependencyClosure,
    permitted_uses: Vec<EpistemicUse>,
    permitted_effects: Vec<EffectCeiling>,
    expected_state_revision: u64,
    owner: String,
    release_condition: String,
    state_fence: StateFence,
}

impl AdmittedSourceQuarantine {
    /// Admits the quarantine a deterministic applicable rule supports.
    ///
    /// The permitted sets, the affected source revision and the release
    /// condition all come from the restriction the indicator map produced, so a
    /// caller cannot widen them here. `expected_state_revision` is the revision
    /// the store will compare-and-swap against when it receipts this.
    ///
    /// # Errors
    ///
    /// Returns an error when the exact dependency closure does not name this
    /// restriction's source, when the closure or fence is inconsistent, when
    /// the owner or release condition is blank, or when no non-zero state
    /// revision is expected.
    pub fn admit_from_rule(
        restriction: &ProposedSourceRestriction,
        dependency_closure: &InfluenceDependencyClosure,
        expected_state_revision: u64,
        owner: &str,
    ) -> Result<Self, SecurityContractError> {
        Self::bind(&QuarantineBindings {
            assessed_source: &restriction.assessed_source,
            permitted_uses: restriction.permitted_uses,
            permitted_effects: restriction.permitted_effects,
            release_condition: &restriction.release_condition,
            dependency_closure,
            expected_state_revision,
            owner,
            state_fence: &restriction.state_fence,
        })
    }

    /// Admits the quarantine an authorized decision supports.
    ///
    /// The decision's identity and revision are validated rather than trusted,
    /// so a blank or superseded decision cannot be replayed as a current one.
    /// The affected source revision is still the assessed one, so this path
    /// cannot quarantine a source nobody assessed.
    ///
    /// # Errors
    ///
    /// Returns an error when the decision reference or revision is blank, when
    /// the exact dependency closure does not name the assessed source, or when
    /// any other binding is unusable.
    pub fn admit_from_decision(
        decision_ref: &str,
        decision_revision: &str,
        bindings: &QuarantineBindings<'_>,
    ) -> Result<Self, SecurityContractError> {
        assessment_text(decision_ref, "admission.decision_ref")?;
        assessment_text(decision_revision, "admission.decision_revision")?;
        Self::bind(bindings)
    }

    /// The single binding path both authority arms share.
    ///
    /// Every check is a comparison against a value the closure or the authority
    /// supplied, so an admission cannot be assembled from restated strings that
    /// disagree with the scope it claims to cover.
    fn bind(bindings: &QuarantineBindings<'_>) -> Result<Self, SecurityContractError> {
        let QuarantineBindings {
            assessed_source,
            permitted_uses,
            permitted_effects,
            release_condition,
            dependency_closure,
            expected_state_revision,
            owner,
            state_fence,
        } = bindings;
        // The exact dependency closure is checked by the existing I12.20
        // closure validator rather than restated here, so this admission cannot
        // hold a closure shape that owner would refuse.
        dependency_closure.validate()?;
        // A closure that does not cover the affected source is not this
        // source's quarantine. This comparison is what stops an admission from
        // naming one source while bounding another.
        if dependency_closure.root_ref != assessed_source.source_ref {
            return Err(SecurityContractError::QuarantineClosureScope {
                field: "admission.dependency_closure.root_ref",
            });
        }
        if dependency_closure.state_fence != **state_fence {
            return Err(SecurityContractError::FenceMismatch);
        }
        // An admission that expects revision zero names no committed
        // predecessor, so there is nothing for the store to compare against.
        if *expected_state_revision == 0 {
            return Err(SecurityContractError::QuarantineRevisionUnbound {
                field: "admission.expected_state_revision",
            });
        }
        assessment_text(owner, "admission.owner")?;
        assessment_text(release_condition, "admission.release_condition")?;
        if permitted_uses.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "admission.permitted_uses",
            });
        }
        if permitted_effects.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "admission.permitted_effects",
            });
        }
        Ok(Self {
            affected_source: (*assessed_source).clone(),
            dependency_closure: (*dependency_closure).clone(),
            permitted_uses: permitted_uses.to_vec(),
            permitted_effects: permitted_effects.to_vec(),
            expected_state_revision: *expected_state_revision,
            owner: owner.trim().to_owned(),
            release_condition: release_condition.trim().to_owned(),
            state_fence: (*state_fence).clone(),
        })
    }

    /// The exact source revision this admission quarantines.
    #[must_use]
    pub fn affected_source(&self) -> &AssessedSourceRevision {
        &self.affected_source
    }

    /// The exact dependency closure this admission is bounded to.
    #[must_use]
    pub fn dependency_closure(&self) -> &InfluenceDependencyClosure {
        &self.dependency_closure
    }

    /// The state revision this admission expects to replace.
    #[must_use]
    pub fn expected_state_revision(&self) -> u64 {
        self.expected_state_revision
    }

    /// The named owner of this admission and of its release.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The release and rebuild condition that must hold before this lifts.
    #[must_use]
    pub fn release_condition(&self) -> &str {
        &self.release_condition
    }

    /// The fence this admission was prepared under.
    #[must_use]
    pub fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Validates this admission against the bindings in force now.
    ///
    /// This is the Kernel/Store half of W5: the store compares the presented
    /// closure, the live state revision, the live owner and the live fence
    /// against what the admission committed, and refuses with a typed error
    /// rather than admitting a quarantine whose bindings have moved.
    ///
    /// # Errors
    ///
    /// Returns an error when the live fence differs, when the live closure is
    /// not the one admitted, when the live revision is not the one expected, or
    /// when the owner in force is not the owner this admission named.
    pub fn validate_against(
        &self,
        live_closure: &InfluenceDependencyClosure,
        live_state_revision: u64,
        live_owner: &str,
        live_fence: &StateFence,
    ) -> Result<(), SecurityContractError> {
        if self.state_fence != *live_fence {
            return Err(SecurityContractError::FenceMismatch);
        }
        if self.dependency_closure != *live_closure {
            return Err(SecurityContractError::StaleSourceAssessment {
                field: "admission.dependency_closure",
            });
        }
        if self.expected_state_revision != live_state_revision {
            return Err(SecurityContractError::QuarantineRevisionUnbound {
                field: "admission.expected_state_revision",
            });
        }
        if self.owner != live_owner {
            return Err(SecurityContractError::QuarantineOwnerMismatch {
                field: "admission.owner",
            });
        }
        Ok(())
    }

    /// Resolves the use authority this admission leaves admissible.
    ///
    /// The permitted sets are intersected with the assurance in force and the
    /// instruction taint is taken from that assurance verbatim, so an admitted
    /// quarantine can only remove uses and effects: it never widens them and
    /// never clears taint.
    ///
    /// # Errors
    ///
    /// Returns an error when the fence differs, or when the source in force is
    /// no longer the source this admission was prepared against.
    pub fn resolve_use(
        &self,
        current_assurance: &SourceAssurance,
        state_fence: &StateFence,
    ) -> Result<SourceUseAuthority, SecurityContractError> {
        if self.state_fence != *state_fence {
            return Err(SecurityContractError::FenceMismatch);
        }
        if self.affected_source.source_ref != current_assurance.source_ref {
            return Err(SecurityContractError::StaleSourceAssessment {
                field: "admission.affected_source.source_ref",
            });
        }
        Ok(SourceUseAuthority {
            assessed_source: self.affected_source.clone(),
            permitted_uses: intersect(
                &self.permitted_uses,
                &current_assurance.allowed_epistemic_use,
            ),
            permitted_effects: intersect(
                &self.permitted_effects,
                &current_assurance.allowed_effects,
            ),
            instruction_taint: current_assurance.instruction_taint,
            state_fence: state_fence.clone(),
        })
    }
}

/// The finite indicator-to-source map.
pub struct IndicatorSourceMap;

impl IndicatorSourceMap {
    /// Resolves one indicator against one exact assessed source revision.
    ///
    /// The class and the evidence must be the closed pair the map defines, the
    /// evidence must establish its own class, and the observation must carry
    /// its own provenance. A restriction is produced only when the class may
    /// propose one, every comparison input was present, and an independent
    /// deterministic rule binding exists. Every other combination — a
    /// model-only proposal, an incomplete comparison, or a content-shaped
    /// class — resolves to [`IndicatorResolution::CandidateOnly`], which carries
    /// no restriction and therefore mutates no authority.
    ///
    /// `release_condition` is required for a restriction and must state the
    /// discriminating evidence that would release it. It is ignored for a
    /// candidate-only resolution, which has no release to describe.
    ///
    /// # Errors
    ///
    /// Returns an error when the evidence is malformed, when the class does not
    /// accept it, when the observation provenance is malformed, or when a
    /// restriction would be produced with no usable release condition.
    pub fn resolve(
        class: IndicatorClass,
        evidence: &IndicatorEvidence,
        observation: &IndicatorObservation,
        assessed_source: &AssessedSourceRevision,
        state_fence: &StateFence,
        release_condition: Option<&str>,
    ) -> Result<IndicatorResolution, SecurityContractError> {
        if !class.accepts(evidence) {
            return Err(SecurityContractError::SecurityIndicatorMismatch {
                indicator: class.name(),
                evidence: evidence.class().name(),
            });
        }
        evidence.validate()?;
        observation.validate()?;

        let coverage = if evidence.has_comparison_inputs() {
            IndicatorCoverage::Complete
        } else {
            IndicatorCoverage::UnknownComparisonInput
        };
        let candidate_only = |coverage: IndicatorCoverage| -> Result<_, SecurityContractError> {
            Ok(IndicatorResolution::CandidateOnly {
                indicator: class,
                assessed_source: assessed_source.clone(),
                coverage,
                cited_refs: evidence.cited_refs(),
            })
        };
        if coverage != IndicatorCoverage::Complete
            || class.response() != IndicatorResponse::BoundedRestriction
        {
            return candidate_only(coverage);
        }
        let Some((rule_ref, rule_revision)) = observation.rule_binding() else {
            return candidate_only(coverage);
        };
        let condition = release_condition
            .map(str::trim)
            .filter(|condition| !condition.is_empty())
            .ok_or(SecurityContractError::InvalidText {
                field: "restriction.release_condition",
            })?;
        Ok(IndicatorResolution::BoundedRestriction(
            ProposedSourceRestriction {
                indicator: class,
                assessed_source: assessed_source.clone(),
                permitted_uses: class.permitted_uses(),
                permitted_effects: class.permitted_effects(),
                rule_ref: rule_ref.to_owned(),
                rule_revision: rule_revision.to_owned(),
                release_condition: condition.to_owned(),
                state_fence: state_fence.clone(),
            },
        ))
    }
}

/// Retained foreign material must name its artifact and cite retained handles.
///
/// # Errors
///
/// Returns an error when the artifact reference is blank or when the handle
/// collection is empty or contains duplicates.
fn validate_retained(retained: &RetainedExternalEvidence) -> Result<(), SecurityContractError> {
    assessment_text(&retained.retained_source_ref, "retained_source_ref")?;
    assessment_refs(&retained.evidence_handles, "evidence_handles")
}

/// A tool definition must name the tool, and its deltas must be real and unique.
///
/// # Errors
///
/// Returns an error when the tool reference is blank, the delta list is empty or
/// duplicated, or the approved schema revision is present but blank.
fn validate_tool_definition_change(
    evidence: &ToolDefinitionChangeEvidence,
) -> Result<(), SecurityContractError> {
    assessment_text(
        &evidence.observed_tool_ref,
        "tool_definition.observed_tool_ref",
    )?;
    if evidence.deltas.is_empty() {
        return Err(SecurityContractError::EmptyCollection {
            field: "tool_definition.deltas",
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for delta in &evidence.deltas {
        if !seen.insert(*delta) {
            return Err(SecurityContractError::DuplicateReference {
                field: "tool_definition.deltas",
            });
        }
    }
    if let Some(revision) = &evidence.approved_schema_revision {
        assessment_text(revision, "tool_definition.approved_schema_revision")?;
    }
    Ok(())
}

/// A summary may only claim a use its source owner does not already grant.
///
/// # Errors
///
/// Returns an error when the summary reference is blank, when the owner's
/// permitted-use list is present but empty, or when the claimed use is one the
/// owner already grants, which is not an escalation at all.
fn validate_summary_authority(
    evidence: &SummaryAuthorityEvidence,
) -> Result<(), SecurityContractError> {
    assessment_text(&evidence.summary_ref, "summary.summary_ref")?;
    if let Some(permitted) = &evidence.owner_permitted_uses {
        if permitted.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "summary.owner_permitted_uses",
            });
        }
        if permitted.contains(&evidence.claimed_use) {
            return Err(SecurityContractError::IndicatorEvidenceUnproven {
                field: "summary.claimed_use",
            });
        }
    }
    Ok(())
}

/// A repeated lineage needs at least two distinct outputs and a lineage name.
///
/// # Errors
///
/// Returns an error when the lineage reference is blank, when fewer than two
/// outputs repeat it, when the output references are duplicated, or when the
/// transformation record is present but blank.
fn validate_repeated_lineage(
    evidence: &RepeatedLineageEvidence,
) -> Result<(), SecurityContractError> {
    assessment_text(&evidence.lineage_ref, "lineage.lineage_ref")?;
    if evidence.repeated_output_refs.len() < 2 {
        return Err(SecurityContractError::IndicatorEvidenceUnproven {
            field: "lineage.repeated_output_refs",
        });
    }
    assessment_refs(
        &evidence.repeated_output_refs,
        "lineage.repeated_output_refs",
    )?;
    if let Some(reference) = &evidence.transformation_ref {
        assessment_text(reference, "lineage.transformation_ref")?;
    }
    Ok(())
}

/// A broad extraction must have exceeded something it was admitted for.
///
/// # Errors
///
/// Returns an error when the request reference is blank, when the admitted
/// handles are empty or duplicated, when no handle was exceeded, or when the
/// exceeded handles are duplicated.
fn validate_broad_extraction(
    evidence: &BroadExtractionEvidence,
) -> Result<(), SecurityContractError> {
    assessment_text(&evidence.request_ref, "extraction.request_ref")?;
    assessment_refs(
        &evidence.admitted_handle_refs,
        "extraction.admitted_handle_refs",
    )?;
    if evidence.exceeded_handle_refs.is_empty() {
        return Err(SecurityContractError::IndicatorEvidenceUnproven {
            field: "extraction.exceeded_handle_refs",
        });
    }
    assessment_refs(
        &evidence.exceeded_handle_refs,
        "extraction.exceeded_handle_refs",
    )
}

/// The dropped handles must match the kind of evidence the record declares.
///
/// # Errors
///
/// Returns an error when the transformation reference is blank, when a declared
/// kind has no handles, when the handle lists are duplicated, or when the
/// verified transformation record is present but blank.
fn validate_dropped_evidence(
    evidence: &DroppedEvidenceRecord,
) -> Result<(), SecurityContractError> {
    assessment_text(&evidence.transformation_ref, "dropped.transformation_ref")?;
    // The declared kind must match what was actually dropped, so a record cannot
    // claim one kind while carrying the other's handles.
    let declares_origin = !matches!(evidence.dropped, DroppedEvidenceKind::MinorityPosition);
    let declares_minority = !matches!(evidence.dropped, DroppedEvidenceKind::OriginProvenance);
    if declares_origin {
        if evidence.dropped_origin_refs.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "dropped.dropped_origin_refs",
            });
        }
        assessment_refs(&evidence.dropped_origin_refs, "dropped.dropped_origin_refs")?;
    }
    if declares_minority {
        if evidence.dropped_minority_refs.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "dropped.dropped_minority_refs",
            });
        }
        assessment_refs(
            &evidence.dropped_minority_refs,
            "dropped.dropped_minority_refs",
        )?;
    }
    if let Some(reference) = &evidence.verified_transformation_ref {
        assessment_text(reference, "dropped.verified_transformation_ref")?;
    }
    Ok(())
}

/// An undeclared effect must be absent from the candidate's own declaration.
///
/// # Errors
///
/// Returns an error when the procedure reference is blank, when the declared
/// effect list is present but empty, or when the observed effect is one the
/// candidate already declared, which is not an undeclared effect.
fn validate_undeclared_effect(
    evidence: &UndeclaredEffectEvidence,
) -> Result<(), SecurityContractError> {
    assessment_text(&evidence.procedure_ref, "procedure.procedure_ref")?;
    if let Some(declared) = &evidence.declared_effects {
        if declared.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "procedure.declared_effects",
            });
        }
        if declared.contains(&evidence.observed_effect) {
            return Err(SecurityContractError::IndicatorEvidenceUnproven {
                field: "procedure.observed_effect",
            });
        }
    }
    Ok(())
}

fn intersect<T: Copy + PartialEq>(left: &[T], right: &[T]) -> Vec<T> {
    let mut narrowed: Vec<T> = Vec::new();
    for value in left {
        if right.contains(value) && !narrowed.contains(value) {
            narrowed.push(*value);
        }
    }
    narrowed
}
