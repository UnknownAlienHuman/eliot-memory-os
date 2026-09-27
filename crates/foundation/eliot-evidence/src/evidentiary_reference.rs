//! Frozen source anchors and transformation evidence shared by semantic records.
//!
//! These are references to immutable source revisions. They do not own source
//! storage, admission, or revalidation lifecycle.

use eliot_contracts::{ArtifactId, ClockReading, SourceId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{EvidenceError, validate_text};

fn validate_fragment(value: &str, field: &'static str) -> Result<(), EvidenceError> {
    if value.trim().is_empty()
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(EvidenceError::InvalidText { field });
    }
    Ok(())
}

/// Immutable source identity and revision used as the basis of a reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrozenSourceRevision {
    /// Stable identity of the source.
    pub source_id: SourceId,
    /// Exact immutable revision identifier supplied by the source owner.
    pub revision: String,
}

impl FrozenSourceRevision {
    /// Validates that both identity components are explicit.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(&self.revision, "frozen_source.revision")
    }
}

/// Exact position within one frozen source revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceAnchor {
    /// Stable source-local locator, not display prose or a guessed citation.
    pub locator: String,
    /// Exact selector within the source, interpreted by its source owner.
    pub selector: String,
    /// Verbatim source text at the anchor, when captured as text.
    pub exact_fragment: Option<String>,
}

impl SourceAnchor {
    /// Validates the immutable location and any retained source fragment.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(&self.locator, "source_anchor.locator")?;
        validate_text(&self.selector, "source_anchor.selector")?;
        if let Some(fragment) = &self.exact_fragment {
            validate_fragment(fragment, "source_anchor.exact_fragment")?;
        }
        Ok(())
    }
}

/// Whether a reference is contextual or contributes to a load-bearing basis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceWeight {
    /// Helpful context that is not used to establish a conclusion.
    Contextual,
    /// Used as evidence for a derived or admitted conclusion.
    LoadBearing,
}

/// How a reference is rendered to a reader.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceRendering {
    /// The source fragment itself is shown verbatim.
    ExactFragment,
    /// A derived paraphrase, with its separately recorded faithfulness check.
    Paraphrase {
        /// Exact paraphrase text shown to the reader.
        text: String,
        /// Independent evaluation record, when an evaluation has been recorded.
        faithfulness: Option<Box<FaithfulnessEvaluationRecord>>,
    },
}

/// Result of the separate evaluation of a paraphrase against its source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FaithfulnessOutcome {
    /// The evaluation found the paraphrase faithful to the anchored source.
    Faithful,
    /// The evaluation found a material mismatch with the anchored source.
    Unfaithful,
    /// Available evidence could not resolve faithfulness.
    Unknown,
}

/// Separately identified evaluation bound to one paraphrase and frozen anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FaithfulnessEvaluationRecord {
    /// Identity of this evaluation record.
    pub evaluation_id: ArtifactId,
    /// Evidentiary reference whose paraphrase was evaluated.
    pub reference_id: ArtifactId,
    /// Exact source revision used by the evaluator.
    pub source: FrozenSourceRevision,
    /// Exact source location used by the evaluator.
    pub anchor: SourceAnchor,
    /// Exact paraphrase text evaluated.
    pub paraphrase: String,
    /// Recorded outcome, including failed and unresolved evaluations.
    pub outcome: FaithfulnessOutcome,
    /// Evaluator/run artifact identity.
    pub evaluator: ArtifactId,
    /// Time the evaluation was recorded.
    pub evaluated_at: ClockReading,
}

impl FaithfulnessEvaluationRecord {
    /// Validates that the evaluation is separately identified and source-bound.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        self.source.validate()?;
        self.anchor.validate()?;
        if self.evaluation_id == self.reference_id {
            return Err(EvidenceError::StatusInvariant {
                field: "faithfulness.evaluation_id",
                reason: "evaluation record must have its own identity",
            });
        }
        validate_fragment(&self.paraphrase, "faithfulness.paraphrase")?;
        self.evaluated_at
            .validate()
            .map_err(|_| EvidenceError::InvalidInterval {
                field: "faithfulness.evaluated_at",
            })
    }
}

/// A source reference carried through a semantic transformation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidentiaryReference {
    /// Identity of this frozen reference.
    pub reference_id: ArtifactId,
    /// Immutable identity and revision of the source.
    pub source: FrozenSourceRevision,
    /// Exact location within that source revision.
    pub anchor: SourceAnchor,
    /// Scope in which the material applies.
    pub scope: String,
    /// Time at which this evidence was observed.
    pub observed_at: ClockReading,
    /// Transformation artifacts traversed from the captured source.
    pub transformation_lineage: Vec<ArtifactId>,
    /// Evidence records supporting the associated proposition.
    pub supports: Vec<ArtifactId>,
    /// Evidence records that counter the associated proposition.
    pub counterevidence: Vec<ArtifactId>,
    /// Exact fragment and reader-facing form.
    pub rendering: EvidenceRendering,
    /// Whether this reference is context or part of a conclusion's basis.
    pub weight: EvidenceWeight,
}

impl EvidentiaryReference {
    /// Validates the frozen anchor, text rendering, and paraphrase linkage.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        self.source.validate()?;
        self.anchor.validate()?;
        validate_text(&self.scope, "evidentiary_reference.scope")?;
        self.observed_at
            .validate()
            .map_err(|_| EvidenceError::InvalidInterval {
                field: "evidentiary_reference.observed_at",
            })?;

        match &self.rendering {
            EvidenceRendering::ExactFragment => {
                if self.anchor.exact_fragment.is_none() {
                    return Err(EvidenceError::StatusInvariant {
                        field: "evidentiary_reference.rendering",
                        reason: "an exact-fragment rendering requires its source fragment",
                    });
                }
            }
            EvidenceRendering::Paraphrase { text, faithfulness } => {
                validate_fragment(text, "evidentiary_reference.paraphrase")?;
                if self.weight == EvidenceWeight::LoadBearing
                    && self.anchor.exact_fragment.is_none()
                {
                    return Err(EvidenceError::StatusInvariant {
                        field: "evidentiary_reference.anchor.exact_fragment",
                        reason: "load-bearing paraphrase requires the exact source fragment",
                    });
                }
                if self.weight == EvidenceWeight::LoadBearing && faithfulness.is_none() {
                    return Err(EvidenceError::StatusInvariant {
                        field: "evidentiary_reference.faithfulness",
                        reason: "load-bearing paraphrase requires a separate faithfulness record",
                    });
                }
                if let Some(evaluation) = faithfulness {
                    evaluation.validate()?;
                    if evaluation.reference_id != self.reference_id
                        || evaluation.source != self.source
                        || evaluation.anchor != self.anchor
                        || evaluation.paraphrase != *text
                    {
                        return Err(EvidenceError::StatusInvariant {
                            field: "evidentiary_reference.faithfulness",
                            reason: "evaluation must bind this paraphrase and frozen anchor",
                        });
                    }
                }
            }
        }

        if self.supports.contains(&self.reference_id)
            || self.counterevidence.contains(&self.reference_id)
        {
            return Err(EvidenceError::StatusInvariant {
                field: "evidentiary_reference.links",
                reason: "a reference cannot support or counter itself",
            });
        }
        Ok(())
    }

    /// Requires a load-bearing paraphrase to have a successful evaluation.
    pub fn validate_load_bearing(&self) -> Result<(), EvidenceError> {
        self.validate()?;
        if self.weight == EvidenceWeight::LoadBearing
            && let EvidenceRendering::Paraphrase {
                faithfulness: Some(evaluation),
                ..
            } = &self.rendering
            && evaluation.outcome != FaithfulnessOutcome::Faithful
        {
            return Err(EvidenceError::StatusInvariant {
                field: "evidentiary_reference.faithfulness.outcome",
                reason: "load-bearing paraphrase must pass its separate faithfulness evaluation",
            });
        }
        Ok(())
    }
}

/// Visible forward review route after a source revision is corrected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DependentReviewRoute {
    /// Identity of this dependent-review route.
    pub route_id: ArtifactId,
    /// Derived record that must be reviewed against the correction.
    pub dependent_record_id: ArtifactId,
    /// Frozen revision of that dependent record.
    pub dependent_revision: String,
    /// Source revision that remains the derived record's original basis.
    pub prior_source: FrozenSourceRevision,
    /// Corrected source revision to review against.
    pub corrected_source: FrozenSourceRevision,
}

impl DependentReviewRoute {
    /// Validates that this route connects distinct revisions of one source.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(
            &self.dependent_revision,
            "dependent_review.dependent_revision",
        )?;
        self.prior_source.validate()?;
        self.corrected_source.validate()?;
        if self.prior_source.source_id != self.corrected_source.source_id
            || self.prior_source.revision == self.corrected_source.revision
        {
            return Err(EvidenceError::StatusInvariant {
                field: "dependent_review.source_revision",
                reason: "correction route must connect different revisions of the same source",
            });
        }
        Ok(())
    }
}
