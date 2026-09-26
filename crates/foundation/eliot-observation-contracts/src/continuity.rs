//! Governed modality evidence and object/workflow continuity (I12.35).
//!
//! Field-to-owner mapping (map-first, no second record family): source
//! checksum and capture identity reuse [`SourceRevisionHandle`], the exact
//! temporal/spatial/byte/range anchor reuses [`SourceAnchorHandle`], and the
//! capture route reuses [`CaptureRoute`]. Only material without an existing
//! owner is defined here: source modality, per-property modality status,
//! type-relative identity hypotheses, the before/after state diff, the
//! continuity observation itself, the workflow continuity material behind the
//! I12.35 `WorkflowStateView` clauses `artifact lineage` and `unresolved
//! representation gaps`, and the fail-closed ingestion rules.
//!
//! A [`ContinuityObservation`] preserves continuity across code, documents,
//! images, audio/video, GUI state, services and professional workflows
//! without pretending that a text summary is equivalent to the source
//! modality. Ingestion is fail-closed: [`admit_continuity_observation`]
//! enforces type-relative identity — per kind *and* per subject, so a rename,
//! crop, render, export, restart, merge or split never inherits a proof from
//! another kind or another subject — stores competing hypotheses side by
//! side instead of merging by filename or similarity, keeps an unmeasured
//! property unknown or degraded, and rejects prose proof for properties the
//! prose did not measure, binding that refusal to the source modality as well
//! as to the claim's own self-declared modality so neither can be relabelled
//! past the gate.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CaptureRoute, ObservationError, SourceAnchorHandle, SourceRevisionHandle};

/// Maximum identity hypotheses carried by one observation.
pub const MAX_IDENTITY_HYPOTHESES: usize = 16;
/// Maximum representation limits declared by one observation.
pub const MAX_REPRESENTATION_LIMITS: usize = 16;
/// Maximum raw or derived handles carried by one observation.
pub const MAX_CONTINUITY_HANDLES: usize = 32;
/// Maximum loss warnings carried by one observation.
pub const MAX_LOSS_WARNINGS: usize = 32;
/// Maximum relation references of one kind carried by one observation.
pub const MAX_CONTINUITY_RELATIONS: usize = 32;
/// Maximum derived text claims carried by one observation.
pub const MAX_DERIVED_TEXT_CLAIMS: usize = 16;
/// Maximum contrary-evidence references carried by one hypothesis.
pub const MAX_CONTRARY_EVIDENCE: usize = 16;
/// Maximum identity kinds one transform may list as preserved or changed.
///
/// Above the `IdentityKind` variant count on purpose: the bound is an
/// allocation guard on a deserialized list, while repeated kinds inside one
/// list are refused separately as malformed rather than as oversized.
pub const MAX_TRANSFORM_KINDS: usize = 8;
/// Maximum artifact lineage hops carried by one workflow continuity record.
pub const MAX_ARTIFACT_LINEAGE: usize = 32;
/// Maximum unresolved representation gaps carried by one workflow continuity
/// record.
pub const MAX_WORKFLOW_REPRESENTATION_GAPS: usize = 32;

/// Validation and ingestion failures at the continuity boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContinuityError {
    /// A shared observation contract rejected a nested value.
    #[error("observation contract: {0}")]
    Observation(#[from] ObservationError),
    /// A required field is blank, unbounded, or contains control characters.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable validation reason.
        reason: &'static str,
    },
    /// A bounded collection holds too many members.
    #[error("{field} exceeds its bound")]
    Bounds {
        /// Field that exceeded its bound.
        field: &'static str,
    },
    /// Two hypotheses claim the same kind, subject and basis twice.
    #[error("duplicate identity hypothesis for {value}")]
    DuplicateHypothesis {
        /// Duplicated kind/subject/basis triple.
        value: String,
    },
    /// A transform claims to preserve and change the same identity kind.
    #[error("transform preserves and changes the same identity kind")]
    IdentityKindConflict,
    /// A claimed preservation has no per-kind, per-subject hypothesis behind it.
    #[error("preserved identity kind has no supporting hypothesis")]
    UnsupportedPreservation,
    /// Filename or similarity evidence is the sole proof of identity.
    #[error("filename or similarity evidence cannot be the sole proof of identity")]
    FilenameOrSimilarityMerge,
    /// A property is claimed measured by a source or evaluator that is not
    /// modality-competent, including a model-generated derived source.
    #[error("measured property requires a modality-competent evaluator")]
    UnevaluatedMeasurement,
    /// Derived prose claims a property it did not measure.
    #[error("derived prose cannot prove an unmeasured modality property")]
    ProseProof,
    /// A degraded, unknown, or derived property has no loss warning.
    #[error("degraded, unknown, or derived material requires a loss warning")]
    MissingLossWarning,
    /// An artifact lineage hop rests only on filename or similarity evidence.
    #[error("artifact lineage identity rests only on filename or similarity evidence")]
    LineageIdentityWithoutProof {
        /// Subject whose lineage is unproven.
        subject: String,
    },
    /// An unresolved representation gap claims a status its evidence cannot
    /// support.
    #[error("unresolved representation gap claims a status its evidence cannot support")]
    UnsupportedGapStatus {
        /// Subject whose gap is unsupported.
        subject: String,
    },
}

fn text(value: &str, field: &'static str) -> Result<(), ContinuityError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ContinuityError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

/// Source modality of a continuity observation.
///
/// This is the modality of the observed source, not statement normative
/// strength: it decides which evaluator competence a property claim needs.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceModality {
    Code,
    Document,
    Image,
    Audio,
    Video,
    GuiState,
    Service,
    Workflow,
    /// Model-generated text derived from another modality.
    TextDerived,
    /// The source modality was not established at capture.
    Unknown,
}

impl SourceModality {
    /// Returns whether the modality needs a modality-competent evaluator
    /// before any property may be claimed measured rather than derived.
    pub const fn requires_modality_competent_evaluator(self) -> bool {
        match self {
            Self::Image
            | Self::Audio
            | Self::Video
            | Self::GuiState
            | Self::Service
            | Self::Workflow => true,
            Self::Code | Self::Document | Self::TextDerived | Self::Unknown => false,
        }
    }
}

/// Admitted status of one modality property.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModalityPropertyStatus {
    /// Measured by a modality-competent observation or evaluator.
    Measured,
    /// A competent measurement exists but is partial or lossy.
    Degraded,
    /// No competent measurement exists; the property stays unknown.
    Unknown,
}

/// One kind of identity tracked independently of the others.
///
/// Identity is type-relative: a rename, crop, render, export, restart,
/// merge or split may preserve one kind while changing another.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityKind {
    ByteIdentity,
    RenderIdentity,
    SemanticIdentity,
    WorkflowInstanceIdentity,
    ServiceEndpointIdentity,
}

/// Basis on which one identity hypothesis is held.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityBasis {
    /// Exact anchor or checksum comparison.
    ExactAnchor,
    /// Measurement by a modality-competent evaluator.
    EvaluatorMeasurement,
    /// Filename hint only: never sole proof, never a merge key.
    FilenameHint,
    /// Similarity hint only: never sole proof, never a merge key.
    SimilarityHint,
}

impl IdentityBasis {
    const fn is_weak(self) -> bool {
        matches!(self, Self::FilenameHint | Self::SimilarityHint)
    }
}

/// One competing identity hypothesis with confidence and contrary evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityHypothesis {
    /// Stable hypothesis identity.
    pub hypothesis_id: String,
    /// Which kind of identity this hypothesis speaks about.
    pub kind: IdentityKind,
    /// Subject the hypothesis identifies.
    pub subject_ref: String,
    /// Basis on which the hypothesis is held.
    pub basis: IdentityBasis,
    /// Confidence in percent, 0 through 100.
    pub confidence: u8,
    /// Evidence against this hypothesis, retained alongside it.
    pub contrary_evidence: Vec<String>,
}

impl IdentityHypothesis {
    fn validate(&self) -> Result<(), ContinuityError> {
        text(&self.hypothesis_id, "identity_hypotheses.hypothesis_id")?;
        text(&self.subject_ref, "identity_hypotheses.subject_ref")?;
        if self.confidence > 100 {
            return Err(ContinuityError::InvalidField {
                field: "identity_hypotheses.confidence",
                reason: "must be 0 through 100",
            });
        }
        if self.contrary_evidence.len() > MAX_CONTRARY_EVIDENCE {
            return Err(ContinuityError::Bounds {
                field: "identity_hypotheses.contrary_evidence",
            });
        }
        for evidence in &self.contrary_evidence {
            text(evidence, "identity_hypotheses.contrary_evidence")?;
        }
        Ok(())
    }
}

/// Object transform whose identity consequences are declared per kind.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContinuityTransformKind {
    Rename,
    Crop,
    Render,
    Export,
    Restart,
    Merge,
    Split,
}

/// Declared identity consequence of one transform.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityTransform {
    /// Which transform was applied.
    pub kind: ContinuityTransformKind,
    /// Identity kinds the transform preserves.
    pub preserved_kinds: Vec<IdentityKind>,
    /// Identity kinds the transform changes.
    pub changed_kinds: Vec<IdentityKind>,
}

impl ContinuityTransform {
    fn validate(&self) -> Result<(), ContinuityError> {
        // A repeated kind inside one list is malformed input, not a second
        // piece of evidence: the fold that decides preservation is keyed by
        // kind, so a duplicate can only pad the list past a bound or imply a
        // consequence the transform never declared.
        for (kinds, field) in [
            (&self.preserved_kinds, "transform.preserved_kinds"),
            (&self.changed_kinds, "transform.changed_kinds"),
        ] {
            if kinds.len() > MAX_TRANSFORM_KINDS {
                return Err(ContinuityError::Bounds { field });
            }
            let mut declared = std::collections::BTreeSet::new();
            for kind in kinds {
                if !declared.insert(*kind) {
                    return Err(ContinuityError::InvalidField {
                        field,
                        reason: "must not repeat an identity kind",
                    });
                }
            }
        }
        for kind in self.preserved_kinds.iter().chain(self.changed_kinds.iter()) {
            if self.preserved_kinds.contains(kind) && self.changed_kinds.contains(kind) {
                return Err(ContinuityError::IdentityKindConflict);
            }
        }
        Ok(())
    }
}

/// Before/after state diff carried by a continuity observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityStateDiff {
    /// Handle of the state before the observed change.
    pub before_handle: String,
    /// Handle of the state after the observed change.
    pub after_handle: String,
    /// Bounded human-readable summary of the difference.
    pub summary: String,
}

impl ContinuityStateDiff {
    fn validate(&self) -> Result<(), ContinuityError> {
        text(&self.before_handle, "state_diff.before_handle")?;
        text(&self.after_handle, "state_diff.after_handle")?;
        text(&self.summary, "state_diff.summary")
    }
}

/// Competent evaluator behind a measured modality property.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorRef {
    /// Stable evaluator capability identity.
    pub evaluator: String,
    /// Modality the evaluator is competent in.
    pub modality: SourceModality,
}

impl EvaluatorRef {
    fn validate(&self) -> Result<(), ContinuityError> {
        text(&self.evaluator, "modality_evaluators.evaluator")
    }
}

/// A model-generated textual description claiming a modality property.
///
/// A derived candidate like this can never prove a visual, acoustic,
/// spatial, or interaction property it did not measure.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedTextClaim {
    /// Property the derived text claims to establish.
    pub property: String,
    /// Modality the claimed property belongs to.
    pub modality: SourceModality,
}

impl DerivedTextClaim {
    fn validate(&self) -> Result<(), ContinuityError> {
        text(&self.property, "derived_text_claims.property")
    }
}

/// Governed relations of a continuity observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityRelations {
    /// Task the observation was captured for.
    pub task_ref: String,
    /// Artifacts the observation speaks about.
    pub artifact_refs: Vec<String>,
    /// Services the observation speaks about.
    pub service_refs: Vec<String>,
    /// Participants the observation speaks about.
    pub participant_refs: Vec<String>,
    /// Verifier competent in the observed modality, when one exists.
    pub verifier_ref: Option<String>,
}

impl ContinuityRelations {
    fn validate(&self) -> Result<(), ContinuityError> {
        text(&self.task_ref, "relations.task_ref")?;
        for (values, field) in [
            (&self.artifact_refs, "relations.artifact_refs"),
            (&self.service_refs, "relations.service_refs"),
            (&self.participant_refs, "relations.participant_refs"),
        ] {
            if values.len() > MAX_CONTINUITY_RELATIONS {
                return Err(ContinuityError::Bounds { field });
            }
            for value in values {
                text(value, field)?;
            }
        }
        if let Some(verifier) = &self.verifier_ref {
            text(verifier, "relations.verifier_ref")?;
        }
        Ok(())
    }
}

/// One governed continuity observation: modality evidence plus object and
/// workflow continuity, with exact canon fields.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityObservation {
    /// Stable observation identity.
    pub observation_id: String,
    /// Modality of the observed source.
    pub source_modality: SourceModality,
    /// Admitted status of the observed modality property.
    pub property_status: ModalityPropertyStatus,
    /// Source identity and checksum; the checksum lives on the revision.
    pub source: SourceRevisionHandle,
    /// Exact temporal/spatial/byte/range anchor within the source.
    pub anchor: SourceAnchorHandle,
    /// Route the observation was captured through.
    pub capture_route: CaptureRoute,
    /// Declared limits of the captured representation.
    pub representation_limits: Vec<String>,
    /// Competent evaluators behind a measured property, if any.
    pub modality_evaluators: Vec<EvaluatorRef>,
    /// Competing identity hypotheses, stored side by side.
    pub competing_hypotheses: Vec<IdentityHypothesis>,
    /// Transform whose identity consequence is declared, if any.
    pub transform: Option<ContinuityTransform>,
    /// Before/after state diff.
    pub state_diff: ContinuityStateDiff,
    /// Workflow step affected by the observed change, if any.
    pub workflow_step_ref: Option<String>,
    /// Governed relations to task, artifact, service, participant, verifier.
    pub relations: ContinuityRelations,
    /// Handles of the raw captured material.
    pub raw_handles: Vec<String>,
    /// Handles of material derived from the raw capture.
    pub derived_handles: Vec<String>,
    /// Derived textual descriptions claiming modality properties.
    pub derived_text_claims: Vec<DerivedTextClaim>,
    /// Loss warnings for degraded, unknown, or derived material.
    pub loss_warnings: Vec<String>,
}

impl ContinuityObservation {
    /// Validates shape, bounds, and modality-status coherence.
    pub fn validate(&self) -> Result<(), ContinuityError> {
        text(&self.observation_id, "observation_id")?;
        self.source.validate()?;
        self.anchor.validate()?;
        if self.representation_limits.len() > MAX_REPRESENTATION_LIMITS {
            return Err(ContinuityError::Bounds {
                field: "representation_limits",
            });
        }
        for limit in &self.representation_limits {
            text(limit, "representation_limits")?;
        }
        if self.modality_evaluators.len() > MAX_CONTINUITY_RELATIONS {
            return Err(ContinuityError::Bounds {
                field: "modality_evaluators",
            });
        }
        for evaluator in &self.modality_evaluators {
            evaluator.validate()?;
        }
        if self.competing_hypotheses.is_empty()
            || self.competing_hypotheses.len() > MAX_IDENTITY_HYPOTHESES
        {
            return Err(ContinuityError::Bounds {
                field: "competing_hypotheses",
            });
        }
        for hypothesis in &self.competing_hypotheses {
            hypothesis.validate()?;
        }
        check_no_silent_merge(&self.competing_hypotheses)?;
        if let Some(transform) = &self.transform {
            transform.validate()?;
            check_preservation_supported(transform, &self.competing_hypotheses)?;
        }
        self.state_diff.validate()?;
        if let Some(step) = &self.workflow_step_ref {
            text(step, "workflow_step_ref")?;
        }
        self.relations.validate()?;
        for (handles, field) in [
            (&self.raw_handles, "raw_handles"),
            (&self.derived_handles, "derived_handles"),
        ] {
            if handles.len() > MAX_CONTINUITY_HANDLES {
                return Err(ContinuityError::Bounds { field });
            }
            for handle in handles {
                text(handle, field)?;
            }
        }
        if self.derived_text_claims.len() > MAX_DERIVED_TEXT_CLAIMS {
            return Err(ContinuityError::Bounds {
                field: "derived_text_claims",
            });
        }
        for claim in &self.derived_text_claims {
            claim.validate()?;
        }
        if self.loss_warnings.len() > MAX_LOSS_WARNINGS {
            return Err(ContinuityError::Bounds {
                field: "loss_warnings",
            });
        }
        for warning in &self.loss_warnings {
            text(warning, "loss_warnings")?;
        }
        check_modality_status(self)?;
        check_prose_proof(self)?;
        check_loss_warnings(self)?;
        Ok(())
    }

    /// Returns the canonical digest of the validated observation.
    pub fn canonical_sha256(&self) -> Result<String, ContinuityError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self).map_err(|_| ContinuityError::InvalidField {
            field: "continuity_observation",
            reason: "canonical serialization failed",
        })?;
        Ok(sha256_hex(&bytes))
    }
}

/// Rejects silent filename/similarity merges: no kind/subject/basis triple
/// may be recorded twice, and for every subject the recorded hypotheses must
/// include a basis that can actually prove identity.
///
/// Weak-basis hypotheses may compete side by side, but they can never be the
/// sole proof for the subject they identify, and a strong hypothesis about a
/// *different* subject is no proof about this one. Identity is type-relative
/// and every `subject_ref` may name a different object, so the decision is
/// per subject and never per set.
fn check_no_silent_merge(hypotheses: &[IdentityHypothesis]) -> Result<(), ContinuityError> {
    let mut seen = std::collections::BTreeSet::new();
    for hypothesis in hypotheses {
        let key = (
            hypothesis.kind,
            hypothesis.subject_ref.clone(),
            hypothesis.basis,
        );
        if !seen.insert(key) {
            return Err(ContinuityError::DuplicateHypothesis {
                value: hypothesis.subject_ref.clone(),
            });
        }
    }
    // Fold the admitted bases into one verdict per subject. A set-level
    // `all()` was the wrong quantifier: one strong hypothesis about
    // `object:a` proved nothing about `object:b`, so a filename-only
    // identity for a second subject was admitted on its own. A
    // `BTreeMap` also fixes which subject the refusal is decided on, so the
    // outcome does not depend on the caller's hypothesis order.
    let mut proven_by_subject = std::collections::BTreeMap::new();
    for hypothesis in hypotheses {
        let proven = proven_by_subject
            .entry(hypothesis.subject_ref.as_str())
            .or_insert(false);
        *proven |= !hypothesis.basis.is_weak();
    }
    // `ContinuityObservation::validate` already refuses an empty hypothesis
    // set; the explicit emptiness refusal keeps this guard fail-closed on
    // its own rather than silently inheriting that caller's bound.
    if proven_by_subject.is_empty() || proven_by_subject.values().any(|proven| !*proven) {
        return Err(ContinuityError::FilenameOrSimilarityMerge);
    }
    Ok(())
}

/// Requires every preserved identity kind to be backed by a non-weak
/// hypothesis for that kind *and* for every subject that kind speaks about:
/// preservation is declared per kind, never inherited across kinds by rename,
/// crop, render, export, restart, merge, or split, and never inherited across
/// subjects either.
///
/// A set-level `any()` was the wrong quantifier twice over. It let a strong
/// hypothesis about one subject prove a preservation for a different subject,
/// and it let a strong hypothesis about a *different kind* prove a
/// preservation for this kind. Either escape is the silent filename merge the
/// canon forbids: a `SemanticIdentity` checksum on `object:a` says nothing
/// about the semantic identity of `object:b`, and a byte-identity checksum on
/// `object:b` says nothing about its semantic identity either. The fold is
/// therefore keyed per `(subject, kind)`, mirroring
/// [`check_no_silent_merge`], and the refusal is decided deterministically on
/// the first unproven pair regardless of the caller's hypothesis order.
///
/// The asymmetry with `changed_kinds` is deliberate and load-bearing: a
/// *changed* kind needs no support, and a weak basis for a changed kind is
/// competing evidence about what the transform did, not a merge key. A
/// hypothesis that competes with a strong one for the same preserved kind and
/// subject is still admitted — only a subject left with nothing but weak bases
/// for a kind it is said to have kept is refused.
fn check_preservation_supported(
    transform: &ContinuityTransform,
    hypotheses: &[IdentityHypothesis],
) -> Result<(), ContinuityError> {
    for kind in &transform.preserved_kinds {
        let mut proven_by_subject = std::collections::BTreeMap::new();
        for hypothesis in hypotheses.iter().filter(|h| &h.kind == kind) {
            let proven = proven_by_subject
                .entry(hypothesis.subject_ref.as_str())
                .or_insert(false);
            *proven |= !hypothesis.basis.is_weak();
        }
        // An empty fold means no hypothesis of this kind exists at all, so the
        // declared preservation has nothing behind it. The explicit refusal
        // keeps the guard fail-closed on its own instead of silently
        // inheriting a bound checked by an earlier step.
        if proven_by_subject.is_empty() || proven_by_subject.values().any(|proven| !*proven) {
            return Err(ContinuityError::UnsupportedPreservation);
        }
    }
    Ok(())
}

/// Assesses one modality property: without a modality-competent evaluator
/// the property stays unknown or degraded, never measured.
pub fn assess_modality_property(
    modality: SourceModality,
    evaluator_present: bool,
    partial_measurement: bool,
) -> ModalityPropertyStatus {
    if !modality.requires_modality_competent_evaluator() {
        return ModalityPropertyStatus::Measured;
    }
    if !evaluator_present {
        return ModalityPropertyStatus::Unknown;
    }
    if partial_measurement {
        return ModalityPropertyStatus::Degraded;
    }
    ModalityPropertyStatus::Measured
}

fn check_modality_status(observation: &ContinuityObservation) -> Result<(), ContinuityError> {
    if !matches!(
        observation.property_status,
        ModalityPropertyStatus::Measured
    ) {
        // Degraded and unknown are honest by construction; loss warnings are
        // enforced separately by `check_loss_warnings`.
        return Ok(());
    }
    // A source that measured nothing cannot have measured anything. `Unknown`
    // is a modality never established at capture, and `TextDerived` is
    // model-generated prose: prose is a derived candidate, not a measuring
    // instrument, so nothing is modality-competent in it. Refusing the
    // derived source here is what closes the escape in which a visual or
    // acoustic claim is filed as `TextDerived` precisely so that
    // `check_prose_proof` will not bind to it.
    if matches!(
        observation.source_modality,
        SourceModality::Unknown | SourceModality::TextDerived
    ) {
        return Err(ContinuityError::UnevaluatedMeasurement);
    }
    let evaluator_present = observation
        .modality_evaluators
        .iter()
        .any(|evaluator| evaluator.modality == observation.source_modality);
    let honest = assess_modality_property(observation.source_modality, evaluator_present, false);
    if honest != ModalityPropertyStatus::Measured {
        return Err(ContinuityError::UnevaluatedMeasurement);
    }
    Ok(())
}

/// Rejects prose proof: a derived textual description is a derived
/// candidate and cannot prove a visual, acoustic, spatial, or interaction
/// property that it did not measure.
///
/// The refusal binds to two independent signals, because either one alone can
/// be dodged by the producer. A claim's own `modality` is
/// producer-controlled, so a rule reading only that field is defeated by
/// relabelling a visual claim as `TextDerived`. The observation's
/// `source_modality` is the field the rest of this gate already refuses to
/// take on trust, so a claim riding a source that needs a competent evaluator
/// is prose proof of that property whatever the claim calls itself. Refusing
/// on either signal is a superset of refusing on the claim's declaration
/// alone.
fn check_prose_proof(observation: &ContinuityObservation) -> Result<(), ContinuityError> {
    let measured = matches!(
        observation.property_status,
        ModalityPropertyStatus::Measured
    );
    if !measured || observation.derived_text_claims.is_empty() {
        return Ok(());
    }
    let claim_requires_evaluator = observation
        .derived_text_claims
        .iter()
        .any(|claim| claim.modality.requires_modality_competent_evaluator());
    let source_requires_evaluator = observation
        .source_modality
        .requires_modality_competent_evaluator();
    if claim_requires_evaluator || source_requires_evaluator {
        return Err(ContinuityError::ProseProof);
    }
    Ok(())
}

/// Requires loss warnings whenever degraded, unknown, or derived material
/// is admitted.
fn check_loss_warnings(observation: &ContinuityObservation) -> Result<(), ContinuityError> {
    let lossy = !matches!(
        observation.property_status,
        ModalityPropertyStatus::Measured
    ) || !observation.derived_handles.is_empty()
        || !observation.derived_text_claims.is_empty();
    if lossy && observation.loss_warnings.is_empty() {
        return Err(ContinuityError::MissingLossWarning);
    }
    Ok(())
}

/// Enforces the ingestion rules for one continuity observation:
/// type-relative identity, competing hypotheses without filename or
/// similarity merge, unknown-or-degraded without a modality-competent
/// evaluator, and no prose proof for unmeasured properties.
pub fn admit_continuity_observation(
    observation: &ContinuityObservation,
) -> Result<(), ContinuityError> {
    observation.validate()
}

/// One governed workflow step reference.
///
/// The step is the anchor the projection owner binds a
/// [`WorkflowStateView`] against, so it is typed here rather than carried as
/// free text.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowStepRef {
    /// Workflow the step belongs to.
    pub workflow_id: String,
    /// Step identity inside that workflow.
    pub step_id: String,
}

impl WorkflowStepRef {
    fn validate(&self) -> Result<(), ContinuityError> {
        text(&self.workflow_id, "step.workflow_id")?;
        text(&self.step_id, "step.step_id")
    }
}

/// Where one artifact lineage hop's identity comes from.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LineageProvenance {
    /// The hop rests on an admitted identity hypothesis.
    IdentityHypothesis,
    /// The owning workflow step declared the hop without a hypothesis.
    DeclaredByStep,
}

/// One hop of the artifact lineage a workflow position depends on.
///
/// A hop asserts that one artifact came from another, which is exactly the
/// continuity claim I12.35 admits no filename or semantic similarity for, so
/// the hop names the hypothesis it rests on and the basis of that hypothesis.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactLineageEntry {
    /// Subject the hop is about.
    pub subject_ref: String,
    /// Which kind of identity the hop speaks about.
    pub subject_kind: IdentityKind,
    /// Predecessor the subject was produced from.
    pub predecessor_ref: String,
    /// Transform relating the predecessor to the subject.
    pub relation: ContinuityTransformKind,
    /// Admitted hypothesis the hop rests on, when one was proven.
    pub hypothesis_id: Option<String>,
    /// Where the hop's identity comes from.
    pub provenance: LineageProvenance,
    /// Basis of the admitted hypothesis; absent for a step-declared hop.
    pub basis: Option<IdentityBasis>,
}

impl ArtifactLineageEntry {
    fn validate(&self) -> Result<(), ContinuityError> {
        text(&self.subject_ref, "artifact_lineage.subject_ref")?;
        text(&self.predecessor_ref, "artifact_lineage.predecessor_ref")?;
        if let Some(hypothesis) = &self.hypothesis_id {
            text(hypothesis, "artifact_lineage.hypothesis_id")?;
        }
        Ok(())
    }
}

/// One unresolved representation gap a workflow position does not resolve.
///
/// A gap is a property the record does not settle, so it carries the admitted
/// status of that property while the gap stands together with the loss warning
/// the gap itself is.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepresentationGap {
    /// Subject whose representation is unresolved.
    pub subject_ref: String,
    /// Property the representation does not settle.
    pub property: String,
    /// Modality the property belongs to.
    pub modality: SourceModality,
    /// Admitted status of that property while the gap stands.
    pub property_status: ModalityPropertyStatus,
    /// Competent evaluator behind a partial measurement, if any.
    pub evaluator: Option<EvaluatorRef>,
    /// Warning recorded for the unresolved representation.
    pub loss_warning: String,
}

impl RepresentationGap {
    fn validate(&self) -> Result<(), ContinuityError> {
        text(&self.subject_ref, "representation_gaps.subject_ref")?;
        text(&self.property, "representation_gaps.property")?;
        text(&self.loss_warning, "representation_gaps.loss_warning")?;
        if let Some(evaluator) = &self.evaluator {
            evaluator.validate()?;
        }
        Ok(())
    }
}

/// Observation-owner continuity material for a governed workflow state view.
///
/// Field-to-owner mapping: the projection owner
/// (`eliot_memory_projection_contracts::WorkflowStateView`) carries the
/// bounded read shape, and this record supplies the evidence the observation
/// owner governs for the two I12.35 view clauses that are continuity claims
/// rather than workflow bookkeeping, `artifact lineage` and `unresolved
/// representation gaps`, plus the typed step identity that anchors the record
/// to the view's current or previous step. It duplicates no view field and
/// adds no second canonical record family.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowContinuity {
    /// Workflow the record belongs to.
    pub workflow_id: String,
    /// Workflow step the record belongs to.
    pub step: WorkflowStepRef,
    /// Artifact lineage the workflow position depends on.
    pub artifact_lineage: Vec<ArtifactLineageEntry>,
    /// Representation gaps the workflow position does not resolve.
    pub unresolved_representation_gaps: Vec<RepresentationGap>,
}

impl WorkflowContinuity {
    /// Validates shape, bounds, and the fail-closed continuity rules: no
    /// lineage hop may rest on filename or similarity evidence alone, and no
    /// unresolved gap may claim a status its evidence cannot support.
    pub fn validate(&self) -> Result<(), ContinuityError> {
        text(&self.workflow_id, "workflow_continuity.workflow_id")?;
        self.step.validate()?;
        // The step anchor names its own workflow, so a record that points at
        // one workflow while anchored in another would bind to no view at all.
        if self.step.workflow_id != self.workflow_id {
            return Err(ContinuityError::InvalidField {
                field: "workflow_continuity.step.workflow_id",
                reason: "must equal workflow_continuity.workflow_id",
            });
        }
        if self.artifact_lineage.len() > MAX_ARTIFACT_LINEAGE {
            return Err(ContinuityError::Bounds {
                field: "workflow_continuity.artifact_lineage",
            });
        }
        for entry in &self.artifact_lineage {
            entry.validate()?;
            check_lineage_provenance(entry)?;
        }
        if self.unresolved_representation_gaps.len() > MAX_WORKFLOW_REPRESENTATION_GAPS {
            return Err(ContinuityError::Bounds {
                field: "workflow_continuity.unresolved_representation_gaps",
            });
        }
        for gap in &self.unresolved_representation_gaps {
            gap.validate()?;
            check_gap_status(gap)?;
        }
        Ok(())
    }
}

/// Refuses an artifact lineage hop that no proven hypothesis stands behind.
///
/// A hop is a continuity claim, and I12.35 admits none on filename or
/// semantic similarity, so a hop whose only basis is a weak hint is the silent
/// merge the canon forbids. A hop the owning step declared without a
/// hypothesis is admitted as the weaker statement it is, and may not be
/// dressed as an identity proof: it carries neither hypothesis nor basis.
fn check_lineage_provenance(entry: &ArtifactLineageEntry) -> Result<(), ContinuityError> {
    if matches!(entry.provenance, LineageProvenance::DeclaredByStep) {
        if entry.hypothesis_id.is_some() || entry.basis.is_some() {
            return Err(ContinuityError::InvalidField {
                field: "workflow_continuity.artifact_lineage",
                reason: "a step-declared hop carries neither hypothesis nor basis",
            });
        }
        return Ok(());
    }
    if entry.hypothesis_id.is_none() {
        return Err(ContinuityError::LineageIdentityWithoutProof {
            subject: entry.subject_ref.clone(),
        });
    }
    match entry.basis {
        Some(basis) if !basis.is_weak() => Ok(()),
        _ => Err(ContinuityError::LineageIdentityWithoutProof {
            subject: entry.subject_ref.clone(),
        }),
    }
}

/// Refuses an unresolved representation gap whose status its evidence cannot
/// support.
///
/// A gap is by definition a property the record does not resolve, so
/// `Measured` on one is a false proof claim. `Degraded` claims a competent
/// evaluator measured partially, so it must name an evaluator competent in the
/// gap's own modality; without one the honest status is `Unknown`, which
/// [`assess_modality_property`] already draws.
fn check_gap_status(gap: &RepresentationGap) -> Result<(), ContinuityError> {
    if matches!(gap.property_status, ModalityPropertyStatus::Measured) {
        return Err(ContinuityError::UnsupportedGapStatus {
            subject: gap.subject_ref.clone(),
        });
    }
    if matches!(gap.property_status, ModalityPropertyStatus::Degraded) {
        let competent =
            matches!(gap.evaluator.as_ref(), Some(evaluator) if evaluator.modality == gap.modality);
        if !competent {
            return Err(ContinuityError::UnsupportedGapStatus {
                subject: gap.subject_ref.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SourceAnchorHandle, SourceRevisionHandle};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn test_sha256() -> String {
        "a".repeat(64)
    }

    fn observation() -> ContinuityObservation {
        ContinuityObservation {
            observation_id: "continuity:1".to_owned(),
            source_modality: SourceModality::Image,
            property_status: ModalityPropertyStatus::Degraded,
            source: SourceRevisionHandle {
                source_id: "source:image".to_owned(),
                revision: "rev:1".to_owned(),
                content_sha256: test_sha256(),
                byte_length: 4096,
            },
            anchor: SourceAnchorHandle {
                anchor_id: "anchor:1".to_owned(),
                byte_offset: 0,
                byte_length: 1024,
                excerpt_sha256: test_sha256(),
                native_mapping: Some("frame:12 region:(0,0,640,480)".to_owned()),
            },
            capture_route: CaptureRoute::BlobHandle,
            representation_limits: vec!["lossy-thumbnail 640x480".to_owned()],
            modality_evaluators: vec![EvaluatorRef {
                evaluator: "evaluator:vision".to_owned(),
                modality: SourceModality::Image,
            }],
            competing_hypotheses: vec![
                IdentityHypothesis {
                    hypothesis_id: "hypothesis:crop-a".to_owned(),
                    kind: IdentityKind::RenderIdentity,
                    subject_ref: "object:panel".to_owned(),
                    basis: IdentityBasis::EvaluatorMeasurement,
                    confidence: 70,
                    contrary_evidence: vec!["thumbnail-crop-ambiguity".to_owned()],
                },
                IdentityHypothesis {
                    hypothesis_id: "hypothesis:semantic-c".to_owned(),
                    kind: IdentityKind::SemanticIdentity,
                    subject_ref: "object:panel".to_owned(),
                    basis: IdentityBasis::ExactAnchor,
                    confidence: 60,
                    contrary_evidence: Vec::new(),
                },
                IdentityHypothesis {
                    hypothesis_id: "hypothesis:filename-b".to_owned(),
                    kind: IdentityKind::ByteIdentity,
                    subject_ref: "object:panel".to_owned(),
                    basis: IdentityBasis::FilenameHint,
                    confidence: 20,
                    contrary_evidence: Vec::new(),
                },
            ],
            transform: Some(ContinuityTransform {
                kind: ContinuityTransformKind::Crop,
                preserved_kinds: vec![IdentityKind::SemanticIdentity],
                changed_kinds: vec![IdentityKind::RenderIdentity, IdentityKind::ByteIdentity],
            }),
            state_diff: ContinuityStateDiff {
                before_handle: "state:before".to_owned(),
                after_handle: "state:after".to_owned(),
                summary: "panel cropped to detail region".to_owned(),
            },
            workflow_step_ref: Some("workflow:review step:crop".to_owned()),
            relations: ContinuityRelations {
                task_ref: "task:review".to_owned(),
                artifact_refs: vec!["artifact:panel".to_owned()],
                service_refs: Vec::new(),
                participant_refs: vec!["participant:operator".to_owned()],
                verifier_ref: Some("verifier:vision".to_owned()),
            },
            raw_handles: vec!["blob:raw".to_owned()],
            derived_handles: vec!["blob:thumbnail".to_owned()],
            derived_text_claims: Vec::new(),
            loss_warnings: vec!["thumbnail loses sub-pixel detail".to_owned()],
        }
    }

    #[test]
    fn competing_hypotheses_admit_side_by_side() -> TestResult {
        let full = observation();
        admit_continuity_observation(&full)?;
        let encoded = serde_json::to_string(&full)?;
        assert_eq!(
            serde_json::from_str::<ContinuityObservation>(&encoded)?,
            full
        );
        assert!(!full.canonical_sha256()?.is_empty());
        Ok(())
    }

    #[test]
    fn filename_only_identity_is_rejected() {
        let mut weak = observation();
        for hypothesis in &mut weak.competing_hypotheses {
            hypothesis.basis = IdentityBasis::FilenameHint;
        }
        assert_eq!(
            admit_continuity_observation(&weak),
            Err(ContinuityError::FilenameOrSimilarityMerge)
        );
    }

    #[test]
    fn measured_without_evaluator_is_rejected() {
        let mut unevaluated = observation();
        unevaluated.property_status = ModalityPropertyStatus::Measured;
        unevaluated.modality_evaluators.clear();
        unevaluated.derived_text_claims.clear();
        assert_eq!(
            admit_continuity_observation(&unevaluated),
            Err(ContinuityError::UnevaluatedMeasurement)
        );
    }

    #[test]
    fn prose_cannot_prove_an_unmeasured_property() {
        let mut prose = observation();
        prose.property_status = ModalityPropertyStatus::Measured;
        prose.derived_text_claims.push(DerivedTextClaim {
            property: "exact panel hue".to_owned(),
            modality: SourceModality::Image,
        });
        assert_eq!(
            admit_continuity_observation(&prose),
            Err(ContinuityError::ProseProof)
        );
    }

    #[test]
    fn unknown_without_loss_warning_is_rejected() {
        let mut unknown = observation();
        unknown.property_status = ModalityPropertyStatus::Unknown;
        unknown.modality_evaluators.clear();
        unknown.loss_warnings.clear();
        assert_eq!(
            admit_continuity_observation(&unknown),
            Err(ContinuityError::MissingLossWarning)
        );
    }

    #[test]
    fn conflicting_transform_kinds_fail_closed() {
        let mut conflicted = observation();
        conflicted.transform = Some(ContinuityTransform {
            kind: ContinuityTransformKind::Rename,
            preserved_kinds: vec![IdentityKind::ByteIdentity],
            changed_kinds: vec![IdentityKind::ByteIdentity],
        });
        assert_eq!(
            admit_continuity_observation(&conflicted),
            Err(ContinuityError::IdentityKindConflict)
        );
    }
}
