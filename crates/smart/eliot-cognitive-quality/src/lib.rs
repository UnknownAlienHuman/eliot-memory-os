//! Bounded candidate-only cognitive quality assessments (#223, orders 80-84).
//!
//! This crate projects one bounded quality scope from immutable,
//! owner-produced projections and refs by handle only, and emits
//! [`QualityAssessmentCandidate`] shells with exact per-sub-assessment
//! denominators and no aggregate score:
//!
//! - order 80 `smart.skill.lifecycle`: [`assess_skill_lifecycle`] over a
//!   [`SkillEvidenceProjectionStatus`] plus per-attempt
//!   [`HarnessActivationReceiptCandidate`] refs;
//! - order 81 `smart.tool.surface`: [`assess_tool_surface`] additionally
//!   cites tool-definition version handles (no version type exists upstream,
//!   so handles only);
//! - order 82 `smart.dreamer.job_economics`: [`assess_dreamer_economics`]
//!   over per-attempt receipt refs plus durable-job handles (job bodies are
//!   absent, so handles only);
//! - order 83 `smart.self.quality_view`: [`assess_self_quality`] over the
//!   unit-#4 owner projections ([`JournalProjection`], [`BankProjection`],
//!   [`FeedbackProjection`], opaque refs where bodies do not exist), the
//!   admitted [`CurrentEpistemicPosition`], per-attempt receipt refs, and
//!   obligation-profile handles (the profile type is not frozen, so handles
//!   only);
//! - order 84 `smart.self.intervention_candidate`: [`assess_intervention`]
//!   over problem/improvement/verifier handles with the Mechanism Review
//!   rule for equivalent retries.
//!
//! Skill/tool/job evidence bodies live with their owners (Governor skill
//! execution evidence, protocol durable-job records) and carry no versioned
//! owner-neutral projection status with per-sub-assessment denominators, so
//! they are consumed by handle only. The directly-required owner-neutral
//! projection-status contract is [`SkillEvidenceProjectionStatus`]: a bounded
//! envelope over owner-placed evidence refs (handle, owner, revision cursor,
//! digest) with the declared assessment scope, the carried fence, the exact
//! evidence denominator, per-attempt receipt refs, closed-class omissions,
//! and a frozen digest. It establishes no support, utility, or completeness:
//! like the experience read-aid view, completeness lives with the owners and
//! is rechecked at the consumer edge.
//!
//! A [`QualityAssessmentCandidate`] freezes exactly what was assessed (which
//! frozen inputs, which scope and fence, which denominators were available)
//! for Governor/Human review. It carries no findings, no verdict, no score,
//! and no completeness posture. Equivalent-retry intervention input fails
//! closed with [`QualityError::MechanismReviewRequired`] instead of opening
//! another identical assessment.
//!
//! This crate performs no retrieval, ranking, promotion, admission,
//! compilation, model work, or reactive-path work. Fences are carried, not
//! gated: consumers gate compatibility at their edge.
//!
//! Wire acceptance and edge authority: [`QualityAssessmentCandidate`] carries
//! its own [`CONTRACT_VERSION`] and [`QualityAssessmentCandidate::validate`]
//! rejects an unequal triple before any other check, so a foreign-triple
//! candidate never validates. Self-digests prove shape integrity only.
//! [`recheck_candidate`] is the in-crate owner-bound authority path: the
//! edge supplies the owner inputs whole, every echoed digest, denominator,
//! and cited handle must re-resolve against them exactly, and anything
//! drifted, uncited, or unattested fails closed.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{
    ArtifactId, ContractVersion, SourceId, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_epistemic_contracts::{
    ContractError as EpistemicContractError, CurrentEpistemicPosition, Currentness,
};
use eliot_learning_contracts::{
    HarnessActivationReceiptCandidate, LearningContractError, SourceDenominator,
};
use eliot_observation_contracts::{
    BankProjection, FeedbackProjection, JournalProjection, ObservationError, ObservationScope,
    ProjectionOmission, MAX_PROJECTION_OMISSIONS,
};
use eliot_receipts::WorkScopeId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Freeze identity this package builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22-r5";

/// Contract version of the projection-status and candidate shapes owned here.
///
/// Prototype consumer contract: `0.1.0`. Equality only; a different triple
/// fails closed.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(0, 1, 0);

/// Maximum evidence refs carried by one projection-status envelope.
pub const MAX_STATUS_EVIDENCE: usize = 256;
/// Maximum per-attempt receipt refs named by one projection-status envelope.
pub const MAX_STATUS_RECEIPT_REFS: usize = 256;
/// Maximum per-attempt receipts assessed in one candidate.
pub const MAX_ASSESSMENT_RECEIPTS: usize = 256;
/// Maximum frozen input digests echoed by one candidate.
pub const MAX_CANDIDATE_DIGESTS: usize = 1024;
/// Maximum frozen denominators echoed by one candidate.
pub const MAX_CANDIDATE_DENOMINATORS: usize = 1024;
/// Maximum owner-held handles cited by one candidate.
pub const MAX_EVIDENCE_HANDLES: usize = 1024;
/// Maximum Unicode scalar values accepted for one scope identity.
pub const MAX_SCOPE_CHARS: usize = 256;
/// Maximum Unicode scalar values accepted for one revision cursor.
pub const MAX_REVISION_CHARS: usize = 256;

fn digest(value: &str, field: &'static str) -> Result<(), QualityError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(QualityError::InvalidField {
            field,
            reason: "must be lowercase SHA-256 hex",
        });
    }
    Ok(())
}

fn scope_shape(scope: &WorkScopeId, field: &'static str) -> Result<(), QualityError> {
    if scope.as_str().chars().count() > MAX_SCOPE_CHARS {
        return Err(QualityError::InvalidField {
            field,
            reason: "scope identity exceeds 256 characters",
        });
    }
    Ok(())
}

fn fence_shape(fence: &StateFence, field: &'static str) -> Result<(), QualityError> {
    fence.validate().map_err(|_| QualityError::InvalidField {
        field,
        reason: "fence interval is invalid",
    })
}

fn unique_handles(
    handles: &[ArtifactId],
    field: &'static str,
) -> Result<(), QualityError> {
    let mut seen = BTreeSet::new();
    for handle in handles {
        if !seen.insert(handle.as_str().to_owned()) {
            return Err(QualityError::InvalidField {
                field,
                reason: "duplicate handle",
            });
        }
    }
    Ok(())
}

/// Cognitive-quality assessment failure: every case fails closed.
#[derive(Clone, Debug, Error)]
pub enum QualityError {
    /// An owner observation shape is invalid.
    #[error("cognitive quality: {0}")]
    Observation(#[from] ObservationError),
    /// An owner epistemic shape is invalid.
    #[error("cognitive quality: {0}")]
    Epistemic(#[from] EpistemicContractError),
    /// An owner learning shape is invalid.
    #[error("cognitive quality: {0}")]
    Learning(#[from] LearningContractError),
    /// A shape bound owned here is invalid.
    #[error("cognitive quality: invalid field {field}: {reason}")]
    InvalidField {
        /// Field at fault.
        field: &'static str,
        /// Why it is invalid.
        reason: &'static str,
    },
    /// A bound owned here is exceeded.
    #[error("cognitive quality: out of bounds: {field}")]
    Bounds {
        /// Field at fault.
        field: &'static str,
    },
    /// A per-sub-assessment denominator is missing or does not reconcile.
    #[error("cognitive quality: per-sub-assessment denominator is incomplete: {reason}")]
    IncompleteDenominator {
        /// Why the denominator cannot be established.
        reason: &'static str,
    },
    /// Equivalent retry without a changed hypothesis or discriminator.
    ///
    /// Recurring failure with the same cited handle closure opens Mechanism
    /// Review instead of another identical assessment.
    #[error(
        "cognitive quality: equivalent retry without changed hypothesis or discriminator requires Mechanism Review"
    )]
    MechanismReviewRequired,
    /// A frozen digest does not match its preimage.
    #[error("cognitive quality: digest does not match the assessment preimage")]
    DigestMismatch,
}

/// One owner-placed skill-evidence ref: identity, owner, and revision cursor.
///
/// No body travels: the owner holds the execution evidence behind this
/// handle. The cursor (revision plus content digest) lets the consumer edge
/// revalidate currency against the owner without opening the body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillEvidenceRef {
    /// Exact canonical handle of the owner evidence.
    pub evidence_handle: ArtifactId,
    /// Owner that holds the evidence body.
    pub owner: SourceId,
    /// Owner revision cursor observed for this handle.
    pub revision: String,
    /// Content digest at the revision cursor.
    pub digest: String,
}

impl SkillEvidenceRef {
    /// Validate cursor and digest shape. Handle and owner are valid by
    /// construction.
    pub fn validate(&self) -> Result<(), QualityError> {
        if self.revision.trim().is_empty() {
            return Err(QualityError::InvalidField {
                field: "evidence_ref.revision",
                reason: "must be non-blank",
            });
        }
        if self.revision.chars().count() > MAX_REVISION_CHARS {
            return Err(QualityError::InvalidField {
                field: "evidence_ref.revision",
                reason: "exceeds bounded length",
            });
        }
        digest(&self.digest, "evidence_ref.digest")
    }
}

/// Owner-neutral projection-status envelope over skill evidence refs.
///
/// This is the directly-required status contract for the NOT_FROZEN
/// skill/tool/job evidence legs: it states which owner evidence is available
/// and countable for one assessment scope, with the exact denominator, the
/// per-attempt receipt refs that substantiate per-attempt checks, and
/// closed-class omissions for named gaps. Owner bodies are never carried and
/// no support, utility, score, or completeness is claimed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillEvidenceProjectionStatus {
    /// Contract version of this envelope; must equal [`CONTRACT_VERSION`].
    pub contract_version: ContractVersion,
    /// Stable status identity.
    pub status_id: ArtifactId,
    /// Owner skill-revision handle this status reads.
    pub skill_ref: ArtifactId,
    /// Owner that holds the evidence bodies.
    pub owner: SourceId,
    /// Declared assessment scope governing this status.
    pub scope: WorkScopeId,
    /// Fence this status was read under, carried for edge gating.
    pub fence: StateFence,
    /// Owner-placed evidence refs in deterministic supply order.
    pub evidence: Vec<SkillEvidenceRef>,
    /// Per-attempt receipt handles substantiating per-attempt checks.
    pub receipt_refs: Vec<ArtifactId>,
    /// Exact evidence denominator: declared owner volume and observed
    /// (carried) count.
    pub denominator: SourceDenominator,
    /// Closed-class omissions for named gaps.
    pub omissions: Vec<ProjectionOmission>,
    /// Frozen digest over the status shape, excluding this field.
    pub digest: String,
}

impl SkillEvidenceProjectionStatus {
    /// Assemble a validated status envelope over owner evidence refs.
    pub fn assemble(
        status_id: ArtifactId,
        skill_ref: ArtifactId,
        owner: SourceId,
        scope: WorkScopeId,
        fence: StateFence,
        evidence: Vec<SkillEvidenceRef>,
        receipt_refs: Vec<ArtifactId>,
        denominator: SourceDenominator,
        omissions: Vec<ProjectionOmission>,
    ) -> Result<Self, QualityError> {
        let mut status = Self {
            contract_version: CONTRACT_VERSION,
            status_id,
            skill_ref,
            owner,
            scope,
            fence,
            evidence,
            receipt_refs,
            denominator,
            omissions,
            digest: String::new(),
        };
        status.digest = status.compute_digest()?;
        status.validate()?;
        Ok(status)
    }

    /// Compute the frozen digest over the status shape.
    pub fn compute_digest(&self) -> Result<String, QualityError> {
        if self.evidence.len() > MAX_STATUS_EVIDENCE {
            return Err(QualityError::Bounds {
                field: "status.evidence",
            });
        }
        canonical_json_bytes(&(
            &self.contract_version,
            &self.status_id,
            &self.skill_ref,
            &self.owner,
            &self.scope,
            &self.fence,
            &self.evidence,
            &self.receipt_refs,
            &self.denominator,
            &self.omissions,
        ))
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| QualityError::InvalidField {
            field: "status.digest",
            reason: "status is not canonically encodable",
        })
    }

    /// Validate version, scope, fence, refs, the exact evidence denominator,
    /// omissions, and the frozen digest.
    pub fn validate(&self) -> Result<(), QualityError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(QualityError::InvalidField {
                field: "status.contract_version",
                reason: "unsupported contract version",
            });
        }
        scope_shape(&self.scope, "status.scope")?;
        fence_shape(&self.fence, "status.fence")?;
        if self.evidence.len() > MAX_STATUS_EVIDENCE {
            return Err(QualityError::Bounds {
                field: "status.evidence",
            });
        }
        for reference in &self.evidence {
            reference.validate()?;
        }
        unique_handles(
            &self
                .evidence
                .iter()
                .map(|reference| reference.evidence_handle.clone())
                .collect::<Vec<_>>(),
            "status.evidence",
        )?;
        if self.receipt_refs.len() > MAX_STATUS_RECEIPT_REFS {
            return Err(QualityError::Bounds {
                field: "status.receipt_refs",
            });
        }
        unique_handles(&self.receipt_refs, "status.receipt_refs")?;
        self.denominator.validate()?;
        // Exact accounting: observed equals carried refs. Declared names the
        // owner enumeration volume; the owner rechecks it at the edge.
        let carried = u32::try_from(self.evidence.len()).unwrap_or(u32::MAX);
        if self.denominator.observed != carried {
            return Err(QualityError::IncompleteDenominator {
                reason: "observed count must equal carried evidence refs",
            });
        }
        if self.omissions.len() > MAX_PROJECTION_OMISSIONS {
            return Err(QualityError::Bounds {
                field: "status.omissions",
            });
        }
        for omission in &self.omissions {
            omission.validate()?;
        }
        digest(&self.digest, "status.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(QualityError::DigestMismatch);
        }
        Ok(())
    }

    /// Evidence handles in supply order.
    #[must_use]
    pub fn handles(&self) -> Vec<&ArtifactId> {
        self.evidence
            .iter()
            .map(|reference| &reference.evidence_handle)
            .collect()
    }
}

/// Closed quality-assessment section marker.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssessmentSection {
    /// Order 80 skill-lifecycle section.
    SkillLifecycle,
    /// Order 81 tool-surface section.
    ToolSurface,
    /// Order 82 Dreamer job-economics section.
    DreamerJobEconomics,
    /// Order 83 self-quality-view section.
    SelfQualityView,
    /// Order 84 intervention-candidate section.
    InterventionCandidate,
}

/// Candidate-only quality assessment: a frozen input closure for review.
///
/// The candidate binds one section, one scope, and one fence to the exact
/// frozen digests echoed, the exact per-sub-assessment denominators
/// available, owner-held handles cited by handle only, and closed-class
/// omissions. It carries no findings, no verdict, no score, and no
/// completeness posture: acceptance happens at the consumer edge and product
/// pulse, which re-resolve every cited handle and recheck every denominator
/// through [`recheck_candidate`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityAssessmentCandidate {
    /// Contract version of this candidate; must equal [`CONTRACT_VERSION`].
    ///
    /// Checked first in [`QualityAssessmentCandidate::validate`]: an unequal
    /// triple is rejected before any wire acceptance.
    pub contract_version: ContractVersion,
    /// Stable assessment identity.
    pub assessment_id: ArtifactId,
    /// Which quality section this candidate assesses.
    pub section: AssessmentSection,
    /// Declared assessment scope governing this candidate.
    pub scope: WorkScopeId,
    /// Fence this candidate was assessed under, carried for edge gating.
    pub fence: StateFence,
    /// Frozen digests echoed from assessed inputs, in assessment order.
    pub input_digests: Vec<String>,
    /// Frozen per-sub-assessment denominators echoed from assessed inputs.
    pub denominators: Vec<SourceDenominator>,
    /// Owner-held bodies cited by handle only.
    pub evidence_handles: Vec<ArtifactId>,
    /// Closed-class omissions for named gaps.
    pub omissions: Vec<ProjectionOmission>,
    /// Frozen digest over the candidate shape, excluding this field.
    pub digest: String,
}

impl QualityAssessmentCandidate {
    /// Compute the frozen digest over the candidate shape.
    pub fn compute_digest(&self) -> Result<String, QualityError> {
        if self.input_digests.len() > MAX_CANDIDATE_DIGESTS {
            return Err(QualityError::Bounds {
                field: "candidate.input_digests",
            });
        }
        canonical_json_bytes(&(
            &self.contract_version,
            &self.assessment_id,
            &self.section,
            &self.scope,
            &self.fence,
            &self.input_digests,
            &self.denominators,
            &self.evidence_handles,
            &self.omissions,
        ))
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| QualityError::InvalidField {
            field: "candidate.digest",
            reason: "candidate is not canonically encodable",
        })
    }

    /// Validate version, scope, fence, echoed digests and denominators,
    /// cited handles, omissions, and the frozen digest.
    ///
    /// The version gate runs before any wire acceptance: a candidate written
    /// against a different triple is rejected here, never interpreted.
    pub fn validate(&self) -> Result<(), QualityError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(QualityError::InvalidField {
                field: "candidate.contract_version",
                reason: "unsupported contract version",
            });
        }
        scope_shape(&self.scope, "candidate.scope")?;
        fence_shape(&self.fence, "candidate.fence")?;
        if self.input_digests.len() > MAX_CANDIDATE_DIGESTS {
            return Err(QualityError::Bounds {
                field: "candidate.input_digests",
            });
        }
        let mut seen_digests = BTreeSet::new();
        for echoed in &self.input_digests {
            digest(echoed, "candidate.input_digests")?;
            if !seen_digests.insert(echoed.clone()) {
                return Err(QualityError::InvalidField {
                    field: "candidate.input_digests",
                    reason: "duplicate digest",
                });
            }
        }
        if self.denominators.len() > MAX_CANDIDATE_DENOMINATORS {
            return Err(QualityError::Bounds {
                field: "candidate.denominators",
            });
        }
        for denominator in &self.denominators {
            denominator.validate()?;
        }
        if self.evidence_handles.len() > MAX_EVIDENCE_HANDLES {
            return Err(QualityError::Bounds {
                field: "candidate.evidence_handles",
            });
        }
        unique_handles(&self.evidence_handles, "candidate.evidence_handles")?;
        if self.omissions.len() > MAX_PROJECTION_OMISSIONS {
            return Err(QualityError::Bounds {
                field: "candidate.omissions",
            });
        }
        for omission in &self.omissions {
            omission.validate()?;
        }
        // At least one frozen anchor: an echoed digest, an echoed
        // denominator, or a cited owner handle. A candidate citing nothing
        // assesses nothing. Intervention closures enumerate by handle only,
        // so handles alone suffice there.
        if self.input_digests.is_empty()
            && self.denominators.is_empty()
            && self.evidence_handles.is_empty()
        {
            return Err(QualityError::IncompleteDenominator {
                reason: "candidate cites no frozen input",
            });
        }
        digest(&self.digest, "candidate.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(QualityError::DigestMismatch);
        }
        Ok(())
    }
}

/// Freeze one assessed candidate after section checks ran.
fn finalize(
    section: AssessmentSection,
    assessment_id: ArtifactId,
    scope: WorkScopeId,
    fence: StateFence,
    input_digests: Vec<String>,
    denominators: Vec<SourceDenominator>,
    evidence_handles: Vec<ArtifactId>,
    omissions: Vec<ProjectionOmission>,
) -> Result<QualityAssessmentCandidate, QualityError> {
    let mut candidate = QualityAssessmentCandidate {
        contract_version: CONTRACT_VERSION,
        assessment_id,
        section,
        scope,
        fence,
        input_digests,
        denominators,
        evidence_handles,
        omissions,
        digest: String::new(),
    };
    candidate.digest = candidate.compute_digest()?;
    candidate.validate()?;
    Ok(candidate)
}

/// Check one per-attempt receipt against the assessment scope and fence.
///
/// The receipt's own closed validation runs first; its binding scope must
/// equal the assessment scope and its fence must be compatible with the
/// assessment fence. Incompatible material is the caller's named omission,
/// never silent loss.
fn check_receipt_scope_fence(
    receipt: &HarnessActivationReceiptCandidate,
    scope: &WorkScopeId,
    fence: &StateFence,
) -> Result<(), QualityError> {
    receipt.validate()?;
    if receipt.binding.scope != *scope {
        return Err(QualityError::InvalidField {
            field: "receipt.binding.scope",
            reason: "receipt scope does not match assessment scope",
        });
    }
    if !receipt.binding.state_fence.is_compatible_with(fence) {
        return Err(QualityError::InvalidField {
            field: "receipt.binding.state_fence",
            reason: "receipt fence is not compatible with assessment fence",
        });
    }
    digest(&receipt.canonical_digest, "receipt.canonical_digest")
}

/// Assess one Skill revision lifecycle from its projection status plus
/// per-attempt receipt refs (order 80).
///
/// Delivered/expanded/executed counts live with the Governor owner and are
/// cited through the status denominator; eligibility, activation, and
/// adherence recheck against the supplied per-attempt receipts at the status
/// scope. At least one receipt is required: acknowledgement without attempts
/// assesses nothing.
pub fn assess_skill_lifecycle(
    assessment_id: ArtifactId,
    status: &SkillEvidenceProjectionStatus,
    receipts: &[HarnessActivationReceiptCandidate],
) -> Result<QualityAssessmentCandidate, QualityError> {
    status.validate()?;
    if receipts.is_empty() {
        return Err(QualityError::IncompleteDenominator {
            reason: "skill lifecycle needs at least one per-attempt receipt",
        });
    }
    if receipts.len() > MAX_ASSESSMENT_RECEIPTS {
        return Err(QualityError::Bounds {
            field: "receipts",
        });
    }
    let mut input_digests = Vec::with_capacity(receipts.len() + 1);
    input_digests.push(status.digest.clone());
    let mut denominators = Vec::with_capacity(receipts.len() + 1);
    denominators.push(status.denominator);
    for receipt in receipts {
        check_receipt_scope_fence(receipt, &status.scope, &status.fence)?;
        input_digests.push(receipt.canonical_digest.clone());
        denominators.push(receipt.member_denominator);
    }
    finalize(
        AssessmentSection::SkillLifecycle,
        assessment_id,
        status.scope.clone(),
        status.fence.clone(),
        input_digests,
        denominators,
        Vec::new(),
        // Status-level named gaps travel into the candidate: a candidate
        // reporting zero omissions over a gapped status would lie.
        status.omissions.clone(),
    )
}

/// Assess tool-surface fit from the skill status, per-attempt receipts, and
/// tool-definition version handles (order 81).
///
/// No tool-definition version type exists upstream, so versions travel as
/// handles only. At least one version handle is required: versions pin
/// staleness, and an assessment citing no version cannot mark stale.
pub fn assess_tool_surface(
    assessment_id: ArtifactId,
    status: &SkillEvidenceProjectionStatus,
    receipts: &[HarnessActivationReceiptCandidate],
    tool_definition_handles: &[ArtifactId],
) -> Result<QualityAssessmentCandidate, QualityError> {
    if tool_definition_handles.is_empty() {
        return Err(QualityError::IncompleteDenominator {
            reason: "tool surface needs at least one tool-definition version handle",
        });
    }
    if tool_definition_handles.len() > MAX_EVIDENCE_HANDLES {
        return Err(QualityError::Bounds {
            field: "tool_definition_handles",
        });
    }
    unique_handles(tool_definition_handles, "tool_definition_handles")?;
    let mut candidate = assess_skill_lifecycle(assessment_id, status, receipts)?;
    candidate.section = AssessmentSection::ToolSurface;
    candidate.evidence_handles = tool_definition_handles.to_vec();
    candidate.digest = candidate.compute_digest()?;
    candidate.validate()?;
    Ok(candidate)
}

/// Assess Dreamer job/family economics from per-attempt receipts plus
/// durable-job handles (order 82).
///
/// Job, route-usage, curation, and outcome bodies live with their owners and
/// carry no versioned owner-neutral projection status, so jobs travel as
/// handles only. The full cost ledger and held-out/live outcome refs are
/// rechecked at the consumer edge; this candidate freezes which receipts and
/// which job handles were assessed under one scope and fence.
pub fn assess_dreamer_economics(
    assessment_id: ArtifactId,
    scope: WorkScopeId,
    fence: StateFence,
    receipts: &[HarnessActivationReceiptCandidate],
    job_handles: &[ArtifactId],
) -> Result<QualityAssessmentCandidate, QualityError> {
    scope_shape(&scope, "scope")?;
    fence_shape(&fence, "fence")?;
    if receipts.is_empty() {
        return Err(QualityError::IncompleteDenominator {
            reason: "dreamer economics needs at least one per-attempt receipt",
        });
    }
    if receipts.len() > MAX_ASSESSMENT_RECEIPTS {
        return Err(QualityError::Bounds {
            field: "receipts",
        });
    }
    if job_handles.is_empty() {
        return Err(QualityError::IncompleteDenominator {
            reason: "dreamer economics needs at least one durable-job handle",
        });
    }
    if job_handles.len() > MAX_EVIDENCE_HANDLES {
        return Err(QualityError::Bounds {
            field: "job_handles",
        });
    }
    unique_handles(job_handles, "job_handles")?;
    let mut input_digests = Vec::with_capacity(receipts.len());
    let mut denominators = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        check_receipt_scope_fence(receipt, &scope, &fence)?;
        input_digests.push(receipt.canonical_digest.clone());
        denominators.push(receipt.member_denominator);
    }
    finalize(
        AssessmentSection::DreamerJobEconomics,
        assessment_id,
        scope,
        fence,
        input_digests,
        denominators,
        job_handles.to_vec(),
        // No droppable omission sets exist on this leg: per-attempt receipts
        // carry attrition/confounder handles rather than omissions, and job
        // bodies travel as handles only.
        Vec::new(),
    )
}

/// Owner experience projections cited by one self-quality assessment.
///
/// At least one family must be present. Full journal records travel where
/// the owner carries them; bank and feedback members travel as opaque refs
/// because no record types exist upstream.
pub struct ExperienceProjections<'a> {
    /// Owner journal envelope, when journal evidence is cited.
    pub journal: Option<&'a JournalProjection>,
    /// Owner bank envelope of opaque refs, when bank evidence is cited.
    pub bank: Option<&'a BankProjection>,
    /// Owner feedback envelope of opaque refs, when feedback is cited.
    pub feedback: Option<&'a FeedbackProjection>,
}

/// Assess self-quality and learning bottlenecks from owner experience
/// projections, the admitted epistemic position, per-attempt receipts, and
/// obligation-profile handles (order 83).
///
/// Observation coverage is co-cited with obligation-profile handles (the
/// profile type is not frozen, so comparison executes at the consumer edge,
/// not here). Bottleneck inputs are the per-attempt receipts. The admitted
/// position must be current; a superseded position contributes nothing. No
/// global score is emitted: the candidate freezes the assessed closure for
/// problem-oriented review.
pub fn assess_self_quality(
    assessment_id: ArtifactId,
    scope: WorkScopeId,
    fence: StateFence,
    projections: &ExperienceProjections<'_>,
    position: &CurrentEpistemicPosition,
    receipts: &[HarnessActivationReceiptCandidate],
    obligation_handles: &[ArtifactId],
) -> Result<QualityAssessmentCandidate, QualityError> {
    scope_shape(&scope, "scope")?;
    fence_shape(&fence, "fence")?;
    position.validate()?;
    if position.currentness != Currentness::Current {
        return Err(QualityError::InvalidField {
            field: "position.currentness",
            reason: "position is superseded",
        });
    }
    let present = usize::from(projections.journal.is_some())
        + usize::from(projections.bank.is_some())
        + usize::from(projections.feedback.is_some());
    if present == 0 {
        return Err(QualityError::IncompleteDenominator {
            reason: "self quality needs at least one experience projection",
        });
    }
    let mut input_digests = Vec::new();
    let mut evidence_handles = Vec::new();
    let mut omissions = Vec::new();
    if let Some(journal) = projections.journal {
        journal.validate()?;
        if journal.scope.work_scope != scope {
            return Err(QualityError::InvalidField {
                field: "projection.scope",
                reason: "journal scope does not match assessment scope",
            });
        }
        if !journal.fence.is_compatible_with(&fence) {
            return Err(QualityError::InvalidField {
                field: "projection.fence",
                reason: "journal fence is not compatible with assessment fence",
            });
        }
        input_digests.push(journal.digest.clone());
        input_digests.push(journal.coverage.coverage_digest.clone());
        evidence_handles.push(journal.projection_id.clone());
        omissions.extend(journal.omissions.iter().cloned());
    }
    if let Some(bank) = projections.bank {
        bank.validate()?;
        if bank.scope.work_scope != scope {
            return Err(QualityError::InvalidField {
                field: "projection.scope",
                reason: "bank scope does not match assessment scope",
            });
        }
        if !bank.fence.is_compatible_with(&fence) {
            return Err(QualityError::InvalidField {
                field: "projection.fence",
                reason: "bank fence is not compatible with assessment fence",
            });
        }
        input_digests.push(bank.digest.clone());
        input_digests.push(bank.coverage.coverage_digest.clone());
        evidence_handles.push(bank.projection_id.clone());
        omissions.extend(bank.omissions.iter().cloned());
    }
    if let Some(feedback) = projections.feedback {
        feedback.validate()?;
        if feedback.scope.work_scope != scope {
            return Err(QualityError::InvalidField {
                field: "projection.scope",
                reason: "feedback scope does not match assessment scope",
            });
        }
        if !feedback.fence.is_compatible_with(&fence) {
            return Err(QualityError::InvalidField {
                field: "projection.fence",
                reason: "feedback fence is not compatible with assessment fence",
            });
        }
        input_digests.push(feedback.digest.clone());
        input_digests.push(feedback.coverage.coverage_digest.clone());
        evidence_handles.push(feedback.projection_id.clone());
        omissions.extend(feedback.omissions.iter().cloned());
    }
    input_digests.push(position.digest.clone());
    if receipts.is_empty() {
        return Err(QualityError::IncompleteDenominator {
            reason: "self quality needs at least one per-attempt receipt",
        });
    }
    if receipts.len() > MAX_ASSESSMENT_RECEIPTS {
        return Err(QualityError::Bounds {
            field: "receipts",
        });
    }
    let mut denominators = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        check_receipt_scope_fence(receipt, &scope, &fence)?;
        input_digests.push(receipt.canonical_digest.clone());
        denominators.push(receipt.member_denominator);
    }
    if obligation_handles.is_empty() {
        return Err(QualityError::IncompleteDenominator {
            reason: "self quality needs at least one obligation-profile handle",
        });
    }
    if obligation_handles.len() > MAX_EVIDENCE_HANDLES {
        return Err(QualityError::Bounds {
            field: "obligation_handles",
        });
    }
    evidence_handles.extend(obligation_handles.iter().cloned());
    unique_handles(&evidence_handles, "evidence_handles")?;
    finalize(
        AssessmentSection::SelfQualityView,
        assessment_id,
        scope,
        fence,
        input_digests,
        denominators,
        evidence_handles,
        // Owner-named gaps from every cited envelope travel into the
        // candidate; receipt and position legs carry no omission sets.
        omissions,
    )
}

/// Assess one advisory intervention candidate from problem, improvement, and
/// verifier handles with the Mechanism Review rule (order 84).
///
/// Causal hypothesis, rivals, discriminator content, authority scope, and
/// rollback plans live with their owners and travel as handles only: problem
/// handles name trigger observations, improvement handles name the candidate
/// change with authority and rollback scope, verifier handles name the
/// discriminator and outcome evidence. The affected-capability closure is
/// enumerated by handle: the candidate digest binds the exact cited handle
/// set, so re-enumeration must reproduce it or the digest mismatches.
///
/// A prior candidate over the identical handle closure is an equivalent
/// retry without a changed hypothesis or discriminator: it fails closed with
/// [`QualityError::MechanismReviewRequired`] instead of opening another
/// identical assessment. Content-level hypothesis change is verified at the
/// edge against owner bodies.
pub fn assess_intervention(
    assessment_id: ArtifactId,
    scope: WorkScopeId,
    fence: StateFence,
    problem_handles: &[ArtifactId],
    improvement_handles: &[ArtifactId],
    verifier_handles: &[ArtifactId],
    prior: Option<&QualityAssessmentCandidate>,
) -> Result<QualityAssessmentCandidate, QualityError> {
    scope_shape(&scope, "scope")?;
    fence_shape(&fence, "fence")?;
    if problem_handles.is_empty() {
        return Err(QualityError::IncompleteDenominator {
            reason: "intervention needs at least one problem handle",
        });
    }
    if improvement_handles.is_empty() {
        return Err(QualityError::IncompleteDenominator {
            reason: "intervention needs at least one improvement handle for change, authority, and rollback scope",
        });
    }
    if verifier_handles.is_empty() {
        return Err(QualityError::IncompleteDenominator {
            reason: "intervention needs at least one verifier handle for discriminator and outcome evidence",
        });
    }
    let mut evidence_handles =
        Vec::with_capacity(problem_handles.len() + improvement_handles.len() + verifier_handles.len());
    evidence_handles.extend(problem_handles.iter().cloned());
    evidence_handles.extend(improvement_handles.iter().cloned());
    evidence_handles.extend(verifier_handles.iter().cloned());
    if evidence_handles.len() > MAX_EVIDENCE_HANDLES {
        return Err(QualityError::Bounds {
            field: "evidence_handles",
        });
    }
    unique_handles(&evidence_handles, "evidence_handles")?;
    if let Some(previous) = prior {
        previous.validate()?;
        if previous.section == AssessmentSection::InterventionCandidate
            && same_handle_closure(&previous.evidence_handles, &evidence_handles)
        {
            return Err(QualityError::MechanismReviewRequired);
        }
    }
    finalize(
        AssessmentSection::InterventionCandidate,
        assessment_id,
        scope,
        fence,
        Vec::new(),
        Vec::new(),
        evidence_handles,
        // No droppable omission sets exist on this leg: problem, improvement,
        // and verifier bodies travel as handles only.
        Vec::new(),
    )
}

/// Compare two cited handle closures ignoring order.
fn same_handle_closure(first: &[ArtifactId], second: &[ArtifactId]) -> bool {
    if first.len() != second.len() {
        return false;
    }
    let mut first_sorted: Vec<&str> = first.iter().map(ArtifactId::as_str).collect();
    let mut second_sorted: Vec<&str> = second.iter().map(ArtifactId::as_str).collect();
    first_sorted.sort_unstable();
    second_sorted.sort_unstable();
    first_sorted == second_sorted
}

/// Owner inputs supplied by the consumer edge for candidate re-resolution.
///
/// The edge resolves every cited handle against its owner at the candidate
/// fence and supplies the owner inputs whole. Handles for bodies this crate
/// never opens (tool versions, jobs, obligation profiles, problems,
/// improvements, verifiers) arrive as edge attestation: the edge attests
/// each resolved against its owner. Anything cited but neither owner-held
/// nor attested fails closed.
pub struct OwnerSnapshot<'a> {
    /// Owner skill-evidence statuses read for this recheck.
    pub statuses: Vec<&'a SkillEvidenceProjectionStatus>,
    /// Owner per-attempt receipts read for this recheck.
    pub receipts: Vec<&'a HarnessActivationReceiptCandidate>,
    /// Owner journal envelopes read for this recheck.
    pub journals: Vec<&'a JournalProjection>,
    /// Owner bank envelopes read for this recheck.
    pub banks: Vec<&'a BankProjection>,
    /// Owner feedback envelopes read for this recheck.
    pub feedbacks: Vec<&'a FeedbackProjection>,
    /// Admitted epistemic positions read for this recheck.
    pub positions: Vec<&'a CurrentEpistemicPosition>,
    /// Edge-attested handles for owner-held bodies cited by handle only.
    pub attested_handles: Vec<ArtifactId>,
}

/// Check one supplied projection envelope against the candidate scope and
/// fence, and collect its digests plus its owner-held handles.
fn collect_projection(
    projection_id: &ArtifactId,
    scope: &ObservationScope,
    fence: &StateFence,
    digest: &str,
    coverage_digest: &str,
    member_handles: &[&ArtifactId],
    candidate: &QualityAssessmentCandidate,
    known_digests: &mut BTreeSet<String>,
    owner_held: &mut BTreeSet<String>,
) -> Result<(), QualityError> {
    if scope.work_scope != candidate.scope {
        return Err(QualityError::InvalidField {
            field: "recheck.projection.scope",
            reason: "projection scope does not match candidate scope",
        });
    }
    if !fence.is_compatible_with(&candidate.fence) {
        return Err(QualityError::InvalidField {
            field: "recheck.projection.fence",
            reason: "projection fence is not compatible with candidate fence",
        });
    }
    known_digests.insert(digest.to_owned());
    known_digests.insert(coverage_digest.to_owned());
    owner_held.insert(projection_id.as_str().to_owned());
    for handle in member_handles {
        owner_held.insert(handle.as_str().to_owned());
    }
    Ok(())
}

/// Re-resolve one candidate against owner inputs supplied by the edge.
///
/// This is the in-crate authority path the candidate design requires: the
/// candidate's self-digest proves shape integrity only, never owner truth.
/// Re-resolution runs every supplied owner input through its own closed
/// validation (status observed==carried accounting and digest recompute live
/// there), then requires each echoed digest, each echoed denominator, and
/// each cited handle to resolve exactly: digests and denominators must equal
/// a supplied owner value; scope-carrying inputs must name the candidate
/// scope with a compatible fence; cited handles must be owner-held or
/// edge-attested. Positions contribute digest echoes only: the admission
/// scope vocabulary differs from the assessment scope, so position scope and
/// liveness stay edge-gated. Drifted, uncited, or unattested material fails
/// closed. No score, verdict, or completeness is adjudicated: a passing
/// recheck states that the frozen closure still resolves, nothing more.
pub fn recheck_candidate(
    candidate: &QualityAssessmentCandidate,
    snapshot: &OwnerSnapshot<'_>,
) -> Result<(), QualityError> {
    candidate.validate()?;
    let mut known_digests: BTreeSet<String> = BTreeSet::new();
    let mut known_denominators: BTreeSet<(u32, u32)> = BTreeSet::new();
    let mut owner_held: BTreeSet<String> = BTreeSet::new();
    for status in &snapshot.statuses {
        status.validate()?;
        if status.scope != candidate.scope {
            return Err(QualityError::InvalidField {
                field: "recheck.status.scope",
                reason: "status scope does not match candidate scope",
            });
        }
        if !status.fence.is_compatible_with(&candidate.fence) {
            return Err(QualityError::InvalidField {
                field: "recheck.status.fence",
                reason: "status fence is not compatible with candidate fence",
            });
        }
        known_digests.insert(status.digest.clone());
        known_denominators.insert((status.denominator.declared, status.denominator.observed));
        owner_held.insert(status.status_id.as_str().to_owned());
        owner_held.insert(status.skill_ref.as_str().to_owned());
        for reference in &status.evidence {
            owner_held.insert(reference.evidence_handle.as_str().to_owned());
        }
        for handle in &status.receipt_refs {
            owner_held.insert(handle.as_str().to_owned());
        }
    }
    for receipt in &snapshot.receipts {
        check_receipt_scope_fence(receipt, &candidate.scope, &candidate.fence)?;
        known_digests.insert(receipt.canonical_digest.clone());
        known_denominators.insert((
            receipt.member_denominator.declared,
            receipt.member_denominator.observed,
        ));
        owner_held.insert(receipt.activation_id.as_str().to_owned());
    }
    for journal in &snapshot.journals {
        journal.validate()?;
        // Journal record ids are owner Strings, never cited by candidates,
        // so only the envelope identity resolves here.
        collect_projection(
            &journal.projection_id,
            &journal.scope,
            &journal.fence,
            &journal.digest,
            &journal.coverage.coverage_digest,
            &[],
            candidate,
            &mut known_digests,
            &mut owner_held,
        )?;
    }
    for bank in &snapshot.banks {
        bank.validate()?;
        let members: Vec<&ArtifactId> =
            bank.refs.iter().map(|reference| &reference.handle).collect();
        collect_projection(
            &bank.projection_id,
            &bank.scope,
            &bank.fence,
            &bank.digest,
            &bank.coverage.coverage_digest,
            &members,
            candidate,
            &mut known_digests,
            &mut owner_held,
        )?;
    }
    for feedback in &snapshot.feedbacks {
        feedback.validate()?;
        let members: Vec<&ArtifactId> =
            feedback.refs.iter().map(|reference| &reference.handle).collect();
        collect_projection(
            &feedback.projection_id,
            &feedback.scope,
            &feedback.fence,
            &feedback.digest,
            &feedback.coverage.coverage_digest,
            &members,
            candidate,
            &mut known_digests,
            &mut owner_held,
        )?;
    }
    for position in &snapshot.positions {
        position.validate()?;
        if position.currentness != Currentness::Current {
            return Err(QualityError::InvalidField {
                field: "recheck.position.currentness",
                reason: "position is superseded",
            });
        }
        known_digests.insert(position.digest.clone());
    }
    let mut attested: BTreeSet<String> = BTreeSet::new();
    for handle in &snapshot.attested_handles {
        if !attested.insert(handle.as_str().to_owned()) {
            return Err(QualityError::InvalidField {
                field: "recheck.attested_handles",
                reason: "duplicate handle",
            });
        }
    }
    for echoed in &candidate.input_digests {
        if !known_digests.contains(echoed) {
            return Err(QualityError::InvalidField {
                field: "recheck.input_digests",
                reason: "echoed digest resolves to no supplied owner input",
            });
        }
    }
    for denominator in &candidate.denominators {
        if !known_denominators.contains(&(denominator.declared, denominator.observed)) {
            return Err(QualityError::InvalidField {
                field: "recheck.denominators",
                reason: "echoed denominator matches no supplied owner denominator",
            });
        }
    }
    for handle in &candidate.evidence_handles {
        if !owner_held.contains(handle.as_str()) && !attested.contains(handle.as_str()) {
            return Err(QualityError::InvalidField {
                field: "recheck.evidence_handles",
                reason: "cited handle is neither owner-held nor edge-attested",
            });
        }
    }
    for omission in &candidate.omissions {
        omission.validate()?;
        if !owner_held.contains(omission.handle.as_str())
            && !attested.contains(omission.handle.as_str())
        {
            return Err(QualityError::InvalidField {
                field: "recheck.omissions",
                reason: "omitted handle is neither owner-held nor edge-attested",
            });
        }
    }
    Ok(())
}
