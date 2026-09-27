//! Common evidentiary-reference contract for derived memory.
//!
//! One shared shape binds a derived conclusion to its frozen source revision
//! and exact supporting anchor. Captured observations, generated candidates,
//! admitted semantic records, Active Views, evaluation results, and reports
//! all reference evidence through [`EvidentiaryReference`]; reports bind a
//! frozen evidence revision through [`FrozenEvidenceProjection`]. A source
//! correction never rewrites a reference; it opens a [`RevalidationRoute`]
//! naming every dependent due for review.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ClockReading, SourceId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{EvidenceError, validate_digest, validate_text};

/// How a supporting fragment relates to source wording (A4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FragmentKind {
    /// Verbatim source wording bound to an exact location.
    Exact,
    /// Generative restatement, useful for navigation and overview only.
    Paraphrase,
}

/// Exact location anchor within one frozen source revision (A4.5).
///
/// Coordinates mirror the governed readback anchor grammar: byte offset and
/// non-empty length over the frozen source bytes plus the excerpt digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAnchor {
    /// Stable anchor identity within the frozen revision.
    pub anchor_id: String,
    /// Byte offset of the excerpt in the frozen source bytes.
    pub byte_offset: u64,
    /// Byte length of the excerpt; must be non-empty to carry weight.
    pub byte_length: u64,
    /// Digest of the exact excerpt bytes.
    pub excerpt_sha256: String,
}

impl EvidenceAnchor {
    /// Validates anchor identity, coordinates, and excerpt digest shape.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(self.anchor_id.as_str(), "anchor.anchor_id")?;
        if self.byte_length == 0 {
            return Err(EvidenceError::StatusInvariant {
                field: "anchor.byte_length",
                reason: "excerpt must be non-empty",
            });
        }
        validate_digest(self.excerpt_sha256.as_str(), "anchor.excerpt_sha256")
    }
}

/// Separate faithfulness check for a paraphrase used with evidentiary weight.
///
/// The check is an independent record: it carries its own evaluation
/// identity and binds the paraphrase digest to the exact fragment digest it
/// was judged against (A4.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FaithfulnessEvaluation {
    /// Stable identity of this separate evaluation record.
    pub evaluation_id: ArtifactId,
    /// Digest of the judged paraphrase text.
    pub paraphrase_sha256: String,
    /// Digest of the exact source fragment it was judged against.
    pub fragment_sha256: String,
    /// Whether the paraphrase was judged faithful to the fragment.
    pub faithful: bool,
    /// Evaluation route that ran the check.
    pub evaluator: String,
    /// Clock reading of the evaluation.
    pub evaluated_at: ClockReading,
}

impl FaithfulnessEvaluation {
    /// Validates digests, evaluator, and clock without rerunning the check.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_digest(
            self.paraphrase_sha256.as_str(),
            "faithfulness.paraphrase_sha256",
        )?;
        validate_digest(
            self.fragment_sha256.as_str(),
            "faithfulness.fragment_sha256",
        )?;
        validate_text(self.evaluator.as_str(), "faithfulness.evaluator")?;
        self.evaluated_at
            .validate()
            .map_err(|_| EvidenceError::InvalidInterval {
                field: "faithfulness.evaluated_at",
            })
    }
}

/// Common evidentiary reference from a derived record to frozen evidence.
///
/// An inspector navigates from the conclusion through this one record to the
/// frozen source revision and exact anchor, sees whether the support is an
/// exact fragment or a paraphrase, and finds the independent faithfulness
/// record when a load-bearing conclusion rests on a paraphrase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidentiaryReference {
    /// Immutable source identity.
    pub source_id: SourceId,
    /// Immutable revision within that source.
    pub source_revision: String,
    /// Content identity of the complete frozen source bytes.
    pub content_sha256: String,
    /// Exact location anchor within the frozen revision.
    pub anchor: EvidenceAnchor,
    /// Whether the support is an exact fragment or a paraphrase.
    pub fragment: FragmentKind,
    /// Verbatim source wording at the anchor, required when evidentiary
    /// weight is claimed. Never the paraphrase text.
    pub excerpt: Option<String>,
    /// Whether this reference is the basis of a load-bearing conclusion.
    pub load_bearing: bool,
    /// Separate faithfulness evaluation; required for a load-bearing
    /// paraphrase and bound to this anchor's fragment.
    pub faithfulness: Option<FaithfulnessEvaluation>,
    /// Transformation lineage: content digests of predecessor references.
    /// Acyclicity is checked by the closure owner, not here.
    pub predecessors: BTreeSet<String>,
    /// Scope in which the support applies.
    pub scope: String,
    /// Clock reading of the support observation.
    pub observed_at: ClockReading,
    /// Supporting record handles.
    pub supporting_evidence: Vec<ArtifactId>,
    /// Counterevidence handles, preserved even when supported.
    pub counterevidence: Vec<ArtifactId>,
}

impl EvidentiaryReference {
    /// Validates the reference and its load-bearing support rules.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(self.source_revision.as_str(), "reference.source_revision")?;
        validate_digest(self.content_sha256.as_str(), "reference.content_sha256")?;
        self.anchor.validate()?;
        let claims_weight = self.fragment == FragmentKind::Exact || self.load_bearing;
        match self.excerpt.as_deref() {
            Some(text) if text.trim().is_empty() => {
                return Err(EvidenceError::StatusInvariant {
                    field: "reference.excerpt",
                    reason: "excerpt must be non-blank source wording",
                });
            }
            None if claims_weight => {
                return Err(EvidenceError::StatusInvariant {
                    field: "reference.excerpt",
                    reason: "evidentiary weight requires the exact source wording",
                });
            }
            _ => {}
        }
        match &self.faithfulness {
            Some(check) => {
                check.validate()?;
                if check.fragment_sha256 != self.anchor.excerpt_sha256 {
                    return Err(EvidenceError::StatusInvariant {
                        field: "faithfulness.fragment_sha256",
                        reason: "faithfulness check does not bind this anchor's fragment",
                    });
                }
            }
            None if self.fragment == FragmentKind::Paraphrase && self.load_bearing => {
                return Err(EvidenceError::StatusInvariant {
                    field: "reference.faithfulness",
                    reason: "load-bearing paraphrase requires a recorded faithfulness evaluation",
                });
            }
            None => {}
        }
        for predecessor in &self.predecessors {
            validate_digest(predecessor.as_str(), "reference.predecessors")?;
        }
        validate_text(self.scope.as_str(), "reference.scope")?;
        self.observed_at
            .validate()
            .map_err(|_| EvidenceError::InvalidInterval {
                field: "reference.observed_at",
            })
    }

    /// Opens the validated inspector projection of this reference.
    ///
    /// An inspector navigates from the derived conclusion through this one
    /// record to the frozen source revision and exact anchor, sees whether
    /// the support is an exact fragment or a paraphrase, and finds the
    /// independent faithfulness record for a load-bearing paraphrase.
    pub fn inspect(&self) -> Result<EvidenceInspection, EvidenceError> {
        self.validate()?;
        Ok(EvidenceInspection {
            source_id: self.source_id.clone(),
            source_revision: self.source_revision.clone(),
            content_sha256: self.content_sha256.clone(),
            anchor: self.anchor.clone(),
            fragment: self.fragment,
            excerpt: self.excerpt.clone(),
            load_bearing: self.load_bearing,
            faithfulness: self.faithfulness.clone(),
        })
    }
}

/// Inspector projection of one validated evidentiary reference (A1).
///
/// The projection carries the frozen source identity and revision, the exact
/// supporting anchor, whether the support is an exact fragment or a
/// paraphrase (A4.6), and the independent faithfulness record when a
/// load-bearing conclusion rests on a paraphrase. It is a read-only view:
/// constructing it validates the reference and never rewrites history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceInspection {
    /// Immutable source identity.
    pub source_id: SourceId,
    /// Immutable revision within that source.
    pub source_revision: String,
    /// Content identity of the complete frozen source bytes.
    pub content_sha256: String,
    /// Exact location anchor within the frozen revision.
    pub anchor: EvidenceAnchor,
    /// Whether the support is an exact fragment or a paraphrase.
    pub fragment: FragmentKind,
    /// Verbatim source wording at the anchor; never paraphrase text.
    pub excerpt: Option<String>,
    /// Whether this reference is the basis of a load-bearing conclusion.
    pub load_bearing: bool,
    /// Separate faithfulness evaluation bound to this anchor's fragment.
    pub faithfulness: Option<FaithfulnessEvaluation>,
}

impl EvidenceInspection {
    /// Whether the projected support may serve as a load-bearing basis.
    ///
    /// An exact fragment with its wording present qualifies directly; a
    /// paraphrase qualifies only with a recorded faithful evaluation (A4.6).
    /// Unfaithful and unevaluated paraphrases stay representable but do not
    /// qualify, so quotation is never silently replaced in a conclusion's
    /// basis.
    pub fn supports_load_bearing_basis(&self) -> bool {
        if self
            .excerpt
            .as_deref()
            .is_none_or(|text| text.trim().is_empty())
        {
            return false;
        }
        match self.fragment {
            FragmentKind::Exact => true,
            FragmentKind::Paraphrase => self.faithfulness.as_ref().is_some_and(|check| {
                check.faithful && check.fragment_sha256 == self.anchor.excerpt_sha256
            }),
        }
    }
}

/// A report as a projection of one frozen evidence revision (A5.7).
///
/// The projection binds report identity to the frozen revision and its
/// anchors. It carries no epistemic status or assertability: report prose
/// never becomes authority, and correcting wording never rewrites history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrozenEvidenceProjection {
    /// Report rendered from the frozen revision.
    pub report_id: ArtifactId,
    /// Frozen admitted-evidence revision the report projects.
    pub frozen_revision: String,
    /// Scope the projection covers.
    pub scope: String,
    /// Anchored references the report rests on; must be non-empty.
    pub references: Vec<EvidentiaryReference>,
}

impl FrozenEvidenceProjection {
    /// Validates the frozen binding and every anchored reference.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(self.frozen_revision.as_str(), "projection.frozen_revision")?;
        validate_text(self.scope.as_str(), "projection.scope")?;
        if self.references.is_empty() {
            return Err(EvidenceError::EmptyCollection {
                field: "projection.references",
            });
        }
        for reference in &self.references {
            reference.validate()?;
        }
        Ok(())
    }
}

/// Forward source correction: a new revision, never a silent rewrite (A4.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceCorrection {
    /// Source whose revision advances.
    pub source_id: SourceId,
    /// Superseded revision still named by existing references.
    pub prior_revision: String,
    /// Content identity of the superseded revision bytes.
    pub prior_content_sha256: String,
    /// New governing revision.
    pub corrected_revision: String,
    /// Content identity of the corrected revision bytes.
    pub corrected_content_sha256: String,
    /// Governed reason for the correction.
    pub reason: String,
}

impl SourceCorrection {
    /// Validates the forward correction without applying it.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(self.prior_revision.as_str(), "correction.prior_revision")?;
        validate_digest(
            self.prior_content_sha256.as_str(),
            "correction.prior_content_sha256",
        )?;
        validate_text(
            self.corrected_revision.as_str(),
            "correction.corrected_revision",
        )?;
        validate_digest(
            self.corrected_content_sha256.as_str(),
            "correction.corrected_content_sha256",
        )?;
        validate_text(self.reason.as_str(), "correction.reason")?;
        if self.prior_revision == self.corrected_revision {
            return Err(EvidenceError::StatusInvariant {
                field: "correction.corrected_revision",
                reason: "correction must advance to a new revision",
            });
        }
        Ok(())
    }

    /// Whether this correction supersedes the frozen basis of a reference.
    ///
    /// A derived record names its frozen basis; a correction never rewrites
    /// that basis (A4.3). When the reference names this correction's source
    /// at the prior revision and content identity, the reference's basis is
    /// superseded and its holder belongs on the dependent-review route
    /// instead of being silently moved to the corrected revision.
    pub fn supersedes(&self, reference: &EvidentiaryReference) -> bool {
        reference.source_id == self.source_id
            && reference.source_revision == self.prior_revision
            && reference.content_sha256 == self.prior_content_sha256
    }
}

/// Disposition of one dependent-review route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevalidationDisposition {
    /// Awaiting dependent review after the correction.
    PendingReview,
    /// Dependent revalidated against the corrected revision.
    Revalidated,
    /// Dependent superseded by a forward revision.
    Superseded,
}

/// Visible dependent-review route opened by a source correction.
///
/// Derived records keep naming the prior frozen revision; this route names
/// every dependent due for review or revalidation instead of silently
/// changing any derived record's basis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevalidationRoute {
    /// Correction that opened the route.
    pub correction: SourceCorrection,
    /// Derived records due for review; must be non-empty.
    pub dependents: Vec<ArtifactId>,
    /// Current disposition of the review.
    pub disposition: RevalidationDisposition,
}

impl RevalidationRoute {
    /// Validates the correction and the dependent set.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        self.correction.validate()?;
        if self.dependents.is_empty() {
            return Err(EvidenceError::EmptyCollection {
                field: "route.dependents",
            });
        }
        Ok(())
    }

    /// Whether a dependent is visibly awaiting review under this route.
    ///
    /// The route stays visible until the canonical owner advances each
    /// dependent by revalidation or supersession; a dependent counts as
    /// awaiting review only while the route disposition is pending.
    pub fn is_pending_for(&self, dependent: &ArtifactId) -> bool {
        self.disposition == RevalidationDisposition::PendingReview
            && self.dependents.contains(dependent)
    }
}

/// Opens the visible dependent-review route for one source correction.
///
/// The route opens as [`RevalidationDisposition::PendingReview`]; the
/// canonical owner advances it as each dependent is revalidated or
/// superseded by a forward revision.
pub fn open_revalidation_route(
    correction: SourceCorrection,
    dependents: Vec<ArtifactId>,
) -> Result<RevalidationRoute, EvidenceError> {
    let route = RevalidationRoute {
        correction,
        dependents,
        disposition: RevalidationDisposition::PendingReview,
    };
    route.validate()?;
    Ok(route)
}
