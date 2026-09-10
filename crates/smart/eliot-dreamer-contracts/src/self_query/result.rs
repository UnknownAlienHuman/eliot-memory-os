//! Candidate-only `ArchitectureBrief` result and bounded diagnostic shapes.

#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_epistemic_contracts::{DisclosureClass, PositionAssertability, PrivacyHandling};
use eliot_receipts::{EffectClass, ProofCeiling};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::input::{
    AttemptBinding, SelfQueryInput, SelfQueryOutputProfile, SelfQueryPolicy, SelfQueryProfile,
};
use super::source::{
    ArchitectureAnchor, ArchitectureAnchorClass, ArchitectureDependencyDenominator,
    ArchitectureSourceSnapshot, ArchitectureSourceStatus, ArchitectureStatementModality, MAX_REFS,
    NormativePairBinding, canonical_size, check_canonical_size, check_digest, check_id,
    check_schema, check_source_text, check_text,
};
use crate::{BudgetUsage, JobClass, PreservationReport, RequesterOrigin, check_no_cross_subsidy};

pub(crate) const MAX_SECTIONS: usize = 16;
pub(crate) const MAX_ITEMS: usize = 4096;
pub(crate) const MAX_GAPS: usize = 4096;
const MAX_CANONICAL_PREIMAGE_BYTES: usize = 16 * 1024 * 1024;
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize)]
struct CandidateDigestPreimage<'a> {
    schema_version: u32,
    candidate_id: &'a ArtifactId,
    job_id: &'a str,
    operation_id: &'a str,
    idempotency_key: &'a str,
    task_id: &'a str,
    scope_id: &'a str,
    requester_origin: &'a RequesterOrigin,
    profile: &'a SelfQueryProfile,
    source_bundle_handle: &'a Option<String>,
    pair: &'a Option<NormativePairBinding>,
    source: &'a Option<ArchitectureSourceSnapshot>,
    anchors: &'a Vec<ArchitectureAnchor>,
    denominator: &'a ArchitectureDependencyDenominator,
    sections: &'a Vec<ArchitectureBriefSection>,
    gaps: &'a Vec<ArchitectureBriefGap>,
    omissions: &'a Vec<ArchitectureBriefOmission>,
    frontier: &'a Vec<String>,
    expansion_handles: &'a Vec<ArtifactId>,
    attempt: &'a AttemptBinding,
    state_fence: &'a StateFence,
    policy: &'a SelfQueryPolicy,
    usage: &'a BudgetUsage,
    work_units: u64,
    preservation: &'a PreservationReport,
    authority_ceiling: &'a PositionAssertability,
    privacy: &'a PrivacyHandling,
    disclosure: &'a DisclosureClass,
    effect_ceiling: &'a EffectClass,
    proof_ceiling: &'a ProofCeiling,
    invalidation_conditions: &'a Vec<String>,
    disposition: &'a ArchitectureBriefDisposition,
    input_digest: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_digest: Option<&'a str>,
}

/// Shape and binding failures for the self-query contract namespace.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SelfQueryContractError {
    #[error("{field} is missing")]
    Missing { field: &'static str },
    #[error("{field} exceeds {maximum} bytes/items (got {actual})")]
    Bound {
        field: &'static str,
        maximum: usize,
        actual: usize,
    },
    #[error("{field} has unsupported version {actual}; expected {expected}")]
    UnsupportedVersion {
        field: &'static str,
        expected: u32,
        actual: u32,
    },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} digest does not match its canonical preimage")]
    DigestMismatch { field: &'static str },
    #[error("{field} does not match its governing input")]
    BindingMismatch { field: &'static str },
    #[error("{field} contains a duplicate member")]
    Duplicate { field: &'static str },
    #[error("{field} has an invalid byte range")]
    Range { field: &'static str },
    #[error("{field} contains a conflict")]
    Conflict { field: &'static str },
    #[error("cannot encode {field} canonically")]
    Encoding { field: &'static str },
}

/// Terminal state of a candidate projection. None of these states imply
/// source acceptance, canonical authority, implementation support or Finish.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchitectureBriefDisposition {
    Complete,
    Partial,
    Unsupported,
    Mismatched,
    Incomplete,
    Conflicted,
    Blocked,
    NoSource,
    Abstention,
    Bound,
    Cancelled,
    Internal,
}

/// The semantic output sections owned by the Architecture profile.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchitectureBriefSectionKind {
    IntentAndRationale,
    RequirementsAndTargets,
    InvariantsAndHardBoundaries,
    OwnersAndForbiddenTransfers,
    BehaviorAndFailureConditions,
    NonGoalsAndOpenQuestions,
    PrecedenceAndSupersession,
    CoverageAndGaps,
}

fn section_for_anchor(class: ArchitectureAnchorClass) -> ArchitectureBriefSectionKind {
    match class {
        ArchitectureAnchorClass::Intent | ArchitectureAnchorClass::Rationale => {
            ArchitectureBriefSectionKind::IntentAndRationale
        }
        ArchitectureAnchorClass::Guarantee
        | ArchitectureAnchorClass::HardBoundary
        | ArchitectureAnchorClass::Invariant => {
            ArchitectureBriefSectionKind::InvariantsAndHardBoundaries
        }
        ArchitectureAnchorClass::Owner => ArchitectureBriefSectionKind::OwnersAndForbiddenTransfers,
        ArchitectureAnchorClass::NonGoal | ArchitectureAnchorClass::OpenQuestion => {
            ArchitectureBriefSectionKind::NonGoalsAndOpenQuestions
        }
        ArchitectureAnchorClass::Precedence => {
            ArchitectureBriefSectionKind::PrecedenceAndSupersession
        }
        ArchitectureAnchorClass::FailureBehavior => {
            ArchitectureBriefSectionKind::BehaviorAndFailureConditions
        }
    }
}

/// One statement retained from an exact Architecture anchor.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureBriefStatement {
    pub statement_id: ArtifactId,
    pub class: ArchitectureAnchorClass,
    pub anchor_id: ArtifactId,
    pub source_handle: ArtifactId,
    pub source_revision: String,
    pub source_digest: String,
    pub byte_start: u64,
    pub byte_end: u64,
    pub modality: ArchitectureStatementModality,
    pub text: String,
}

impl ArchitectureBriefStatement {
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_id(self.statement_id.as_str(), "statement.statement_id")?;
        check_id(self.anchor_id.as_str(), "statement.anchor_id")?;
        check_id(self.source_handle.as_str(), "statement.source_handle")?;
        check_text(&self.source_revision, "statement.source_revision", 256)?;
        check_digest(&self.source_digest, "statement.source_digest")?;
        check_source_text(&self.text, "statement.text", 16 * 1024)
    }
}

/// A deterministic section of source-bound statements.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureBriefSection {
    pub kind: ArchitectureBriefSectionKind,
    pub statements: Vec<ArchitectureBriefStatement>,
    pub digest: String,
}

impl ArchitectureBriefSection {
    pub fn compute_digest(&self) -> Result<String, SelfQueryContractError> {
        if self.statements.len() > MAX_ITEMS {
            return Err(SelfQueryContractError::Bound {
                field: "section.statements",
                maximum: MAX_ITEMS,
                actual: self.statements.len(),
            });
        }
        for statement in &self.statements {
            statement.validate()?;
        }
        canonical_json_bytes(&(&self.kind, &self.statements))
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| SelfQueryContractError::Encoding {
                field: "section.digest",
            })
    }

    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_digest(&self.digest, "section.digest")?;
        if self.statements.len() > MAX_ITEMS {
            return Err(SelfQueryContractError::Bound {
                field: "section.statements",
                maximum: MAX_ITEMS,
                actual: self.statements.len(),
            });
        }
        for statement in &self.statements {
            statement.validate()?;
        }
        if self.digest != self.compute_digest()? {
            return Err(SelfQueryContractError::DigestMismatch {
                field: "section.digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchitectureBriefGapClass {
    Architecture,
    Implementation,
    Code,
    Runtime,
    Product,
}

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchitectureBriefGapState {
    Open,
    Partial,
    Unsupported,
    Unknown,
}

/// A gap retains its owner and evidence class without promoting the gap to a
/// conformance, implementation or product verdict.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureBriefGap {
    pub gap_id: ArtifactId,
    pub class: ArchitectureBriefGapClass,
    pub state: ArchitectureBriefGapState,
    pub owner: String,
    pub detail: String,
    pub evidence_refs: Vec<ArtifactId>,
}

impl ArchitectureBriefGap {
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_id(self.gap_id.as_str(), "gap.gap_id")?;
        check_text(&self.owner, "gap.owner", 1024)?;
        check_text(&self.detail, "gap.detail", 16 * 1024)?;
        if self.evidence_refs.len() > MAX_REFS {
            return Err(SelfQueryContractError::Bound {
                field: "gap.evidence_refs",
                maximum: MAX_REFS,
                actual: self.evidence_refs.len(),
            });
        }
        let mut refs = BTreeSet::new();
        for reference in &self.evidence_refs {
            check_id(reference.as_str(), "gap.evidence_ref")?;
            if !refs.insert(reference) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "gap.evidence_refs",
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureBriefOmission {
    pub handle: ArtifactId,
    pub reason: String,
    pub reversible: bool,
}

impl ArchitectureBriefOmission {
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_id(self.handle.as_str(), "omission.handle")?;
        check_text(&self.reason, "omission.reason", 16 * 1024)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureBriefCandidate {
    pub schema_version: u32,
    pub candidate_id: ArtifactId,
    pub job_id: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub task_id: String,
    pub scope_id: String,
    pub requester_origin: RequesterOrigin,
    pub profile: SelfQueryProfile,
    /// Opaque bundle handle bound to the frozen material closure.
    pub source_bundle_handle: Option<String>,
    pub pair: Option<NormativePairBinding>,
    pub source: Option<ArchitectureSourceSnapshot>,
    pub anchors: Vec<ArchitectureAnchor>,
    pub denominator: ArchitectureDependencyDenominator,
    pub sections: Vec<ArchitectureBriefSection>,
    pub gaps: Vec<ArchitectureBriefGap>,
    pub omissions: Vec<ArchitectureBriefOmission>,
    pub frontier: Vec<String>,
    pub expansion_handles: Vec<ArtifactId>,
    pub attempt: AttemptBinding,
    pub state_fence: StateFence,
    pub policy: SelfQueryPolicy,
    /// Measured candidate projection usage, checked against every upstream
    /// budget dimension without cross-subsidy. `reference_width` is the
    /// distinct count of retained `ArtifactIds` in anchor dependency refs,
    /// applicability evidence refs, denominator member/anchor refs, gap
    /// evidence refs, omission handles and expansion handles.
    pub usage: BudgetUsage,
    /// Count of projection work units, distinct from parallel fan-out.
    pub work_units: u64,
    pub preservation: PreservationReport,
    pub authority_ceiling: PositionAssertability,
    pub privacy: PrivacyHandling,
    pub disclosure: DisclosureClass,
    pub effect_ceiling: EffectClass,
    pub proof_ceiling: ProofCeiling,
    pub invalidation_conditions: Vec<String>,
    pub disposition: ArchitectureBriefDisposition,
    pub input_digest: String,
    pub output_digest: String,
}

impl ArchitectureBriefCandidate {
    /// Computes the candidate digest over every output field except itself.
    pub fn compute_output_digest(&self) -> Result<String, SelfQueryContractError> {
        self.preflight_digest()?;
        let preimage = self.digest_preimage(None);
        canonical_json_bytes(&preimage)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| SelfQueryContractError::Encoding {
                field: "candidate.output_digest",
            })
    }

    fn digest_preimage<'a>(
        &'a self,
        output_digest: Option<&'a str>,
    ) -> CandidateDigestPreimage<'a> {
        CandidateDigestPreimage {
            schema_version: self.schema_version,
            candidate_id: &self.candidate_id,
            job_id: &self.job_id,
            operation_id: &self.operation_id,
            idempotency_key: &self.idempotency_key,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            requester_origin: &self.requester_origin,
            profile: &self.profile,
            source_bundle_handle: &self.source_bundle_handle,
            pair: &self.pair,
            source: &self.source,
            anchors: &self.anchors,
            denominator: &self.denominator,
            sections: &self.sections,
            gaps: &self.gaps,
            omissions: &self.omissions,
            frontier: &self.frontier,
            expansion_handles: &self.expansion_handles,
            attempt: &self.attempt,
            state_fence: &self.state_fence,
            policy: &self.policy,
            usage: &self.usage,
            work_units: self.work_units,
            preservation: &self.preservation,
            authority_ceiling: &self.authority_ceiling,
            privacy: &self.privacy,
            disclosure: &self.disclosure,
            effect_ceiling: &self.effect_ceiling,
            proof_ceiling: &self.proof_ceiling,
            invalidation_conditions: &self.invalidation_conditions,
            disposition: &self.disposition,
            input_digest: &self.input_digest,
            output_digest,
        }
    }

    fn preflight_digest(&self) -> Result<(), SelfQueryContractError> {
        check_schema(self.schema_version, "candidate.schema_version")?;
        self.policy.validate()?;
        let output_limit = usize::try_from(
            self.policy
                .max_output_bytes
                .min(MAX_CANONICAL_PREIMAGE_BYTES as u64),
        )
        .map_err(|_| SelfQueryContractError::Bound {
            field: "candidate.output_wire",
            maximum: MAX_CANONICAL_PREIMAGE_BYTES,
            actual: usize::MAX,
        })?;
        let wire_preimage = self.digest_preimage(Some(ZERO_DIGEST));
        check_canonical_size(&wire_preimage, output_limit, "candidate.output_wire")?;
        check_id(self.candidate_id.as_str(), "candidate.candidate_id")?;
        for (value, field, maximum) in [
            (&self.job_id, "candidate.job_id", 256),
            (&self.operation_id, "candidate.operation_id", 128),
            (&self.idempotency_key, "candidate.idempotency_key", 128),
            (&self.task_id, "candidate.task_id", 256),
            (&self.scope_id, "candidate.scope_id", 256),
        ] {
            check_text(value, field, maximum)?;
        }
        if let Some(handle) = &self.source_bundle_handle {
            check_text(handle, "candidate.source_bundle_handle", 128)?;
        } else if self.source.is_some() {
            return Err(SelfQueryContractError::Missing {
                field: "candidate.source_bundle_handle",
            });
        }
        if self.anchors.len() > MAX_ITEMS
            || self.sections.len() > MAX_SECTIONS
            || self.gaps.len() > MAX_GAPS
            || self.omissions.len() > MAX_ITEMS
            || self.frontier.len() > MAX_ITEMS
            || self.expansion_handles.len() > MAX_REFS
            || self.invalidation_conditions.len() > MAX_GAPS
        {
            return Err(SelfQueryContractError::Bound {
                field: "candidate.collections",
                maximum: MAX_ITEMS,
                actual: self
                    .anchors
                    .len()
                    .max(self.sections.len())
                    .max(self.gaps.len()),
            });
        }
        check_digest(&self.input_digest, "candidate.input_digest")?;
        self.profile.validate()?;
        self.pair
            .as_ref()
            .map_or(Ok(()), NormativePairBinding::validate)?;
        if let Some(source) = &self.source {
            source.validate()?;
        }
        self.attempt.validate()?;
        if self.usage.input_bytes > self.policy.max_input_bytes
            || self.usage.output_bytes > self.policy.max_output_bytes
            || self.usage.reference_width > self.policy.max_reference_width
            || self.usage.stu_used > self.policy.max_stu
        {
            return Err(SelfQueryContractError::Conflict {
                field: "candidate.usage",
            });
        }
        if self.work_units > self.policy.max_work {
            return Err(SelfQueryContractError::Conflict {
                field: "candidate.work_units",
            });
        }
        let mut retained_refs = BTreeSet::new();
        for anchor in &self.anchors {
            retained_refs.extend(anchor.dependency_refs.iter());
            retained_refs.extend(anchor.applicability.evidence_refs.iter());
        }
        for member in &self.denominator.members {
            retained_refs.insert(&member.member_id);
            retained_refs.insert(&member.anchor_id);
        }
        for gap in &self.gaps {
            retained_refs.extend(gap.evidence_refs.iter());
        }
        for omission in &self.omissions {
            retained_refs.insert(&omission.handle);
        }
        retained_refs.extend(self.expansion_handles.iter());
        if self.usage.reference_width != u64::try_from(retained_refs.len()).unwrap_or(u64::MAX) {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "candidate.usage.reference_width",
            });
        }
        let item_count = self
            .anchors
            .len()
            .saturating_add(
                self.sections
                    .iter()
                    .map(|section| section.statements.len())
                    .sum(),
            )
            .saturating_add(self.gaps.len())
            .saturating_add(self.omissions.len());
        let max_items = usize::try_from(self.policy.max_items).unwrap_or(usize::MAX);
        if item_count > max_items {
            return Err(SelfQueryContractError::Bound {
                field: "candidate.items",
                maximum: max_items,
                actual: item_count,
            });
        }
        self.denominator.validate()?;
        let mut estimated = self
            .job_id
            .len()
            .saturating_add(self.operation_id.len())
            .saturating_add(self.idempotency_key.len())
            .saturating_add(self.task_id.len())
            .saturating_add(self.scope_id.len());
        if let Some(source) = &self.source {
            estimated = estimated.saturating_add(source.bytes.len());
        }
        if self.anchors.len() > super::source::MAX_ANCHORS {
            return Err(SelfQueryContractError::Bound {
                field: "candidate.anchors",
                maximum: super::source::MAX_ANCHORS,
                actual: self.anchors.len(),
            });
        }
        for anchor in &self.anchors {
            let Some(source) = &self.source else {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "candidate.anchor_without_source",
                });
            };
            anchor.validate_against(source)?;
            estimated = estimated.saturating_add(anchor.text.len());
        }
        for section in &self.sections {
            for statement in &section.statements {
                statement.validate()?;
                estimated = estimated.saturating_add(statement.text.len());
            }
        }
        if self.anchors.iter().any(|anchor| {
            anchor.applicability.basis
                == super::source::ArchitectureApplicabilityBasis::SimilarityRejected
                && anchor.applicability.state
                    == super::source::ArchitectureApplicabilityState::NotApplicable
        }) {
            return Err(SelfQueryContractError::Conflict {
                field: "candidate.similarity_exclusion",
            });
        }
        for gap in &self.gaps {
            gap.validate()?;
            estimated = estimated.saturating_add(gap.detail.len());
        }
        for omission in &self.omissions {
            omission.validate()?;
            estimated = estimated.saturating_add(omission.reason.len());
        }
        for frontier in &self.frontier {
            check_text(frontier, "candidate.frontier", 1024)?;
            estimated = estimated.saturating_add(frontier.len());
        }
        for condition in &self.invalidation_conditions {
            check_text(condition, "candidate.invalidation_condition", 16 * 1024)?;
            estimated = estimated.saturating_add(condition.len());
        }
        self.preservation
            .validate()
            .map_err(|_| SelfQueryContractError::Conflict {
                field: "candidate.preservation",
            })?;
        if estimated > MAX_CANONICAL_PREIMAGE_BYTES {
            return Err(SelfQueryContractError::Bound {
                field: "candidate.canonical_preimage",
                maximum: MAX_CANONICAL_PREIMAGE_BYTES,
                actual: estimated,
            });
        }
        for section in &self.sections {
            section.validate()?;
        }
        Ok(())
    }

    /// Validates source/anchor joins and the candidate-only proof/effect
    /// ceiling. It does not authenticate the external acceptance receipt.
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        self.preflight_digest()?;
        for (value, field, maximum) in [
            (&self.job_id, "candidate.job_id", 256),
            (&self.operation_id, "candidate.operation_id", 128),
            (&self.idempotency_key, "candidate.idempotency_key", 128),
            (&self.task_id, "candidate.task_id", 256),
            (&self.scope_id, "candidate.scope_id", 256),
        ] {
            check_text(value, field, maximum)?;
        }
        if self.profile.job_class != JobClass::ArchitectureSelfQuery
            || self.profile.output_profile
                != super::input::SelfQueryOutputProfile::ArchitectureBrief
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "candidate.profile",
            });
        }
        self.profile.validate()?;
        if let Some(pair) = &self.pair {
            pair.validate()?;
        }
        if let Some(source) = &self.source {
            source.validate()?;
            if self.pair.as_ref() != Some(&source.pair) {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "candidate.pair",
                });
            }
        } else if self.pair.is_some()
            || !self.anchors.is_empty()
            || !self.denominator.members.is_empty()
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "candidate.source_absence_closure",
            });
        }
        if let Some(handle) = &self.source_bundle_handle {
            check_text(handle, "candidate.source_bundle_handle", 128)?;
        } else if self.source.is_some() {
            return Err(SelfQueryContractError::Missing {
                field: "candidate.source_bundle_handle",
            });
        }
        if self
            .source
            .as_ref()
            .is_none_or(|source| source.status != ArchitectureSourceStatus::Accepted)
            && self.disposition == ArchitectureBriefDisposition::Complete
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "candidate.complete_source_status",
            });
        }
        self.denominator.validate()?;

        let mut anchor_ids = BTreeSet::new();
        for anchor in &self.anchors {
            let Some(source) = &self.source else {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "candidate.anchor_without_source",
                });
            };
            anchor.validate_against(source)?;
            if !anchor_ids.insert(&anchor.anchor_id) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "candidate.anchors",
                });
            }
        }
        let mut statement_ids = BTreeSet::new();
        let mut section_kinds = BTreeSet::new();
        for section in &self.sections {
            section.validate()?;
            if !section_kinds.insert(section.kind) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "candidate.sections",
                });
            }
            for statement in &section.statements {
                if !statement_ids.insert(&statement.statement_id) {
                    return Err(SelfQueryContractError::Duplicate {
                        field: "candidate.statements",
                    });
                }
                let Some(anchor) = self
                    .anchors
                    .iter()
                    .find(|a| a.anchor_id == statement.anchor_id)
                else {
                    return Err(SelfQueryContractError::BindingMismatch {
                        field: "statement.anchor_id",
                    });
                };
                if statement.source_handle != anchor.source_handle
                    || statement.source_revision != anchor.revision
                    || statement.source_digest != anchor.source_digest
                    || statement.byte_start != anchor.byte_start
                    || statement.byte_end != anchor.byte_end
                    || statement.text != anchor.text
                    || statement.class != anchor.class
                    || statement.modality != anchor.modality
                {
                    return Err(SelfQueryContractError::BindingMismatch {
                        field: "statement.source_binding",
                    });
                }
            }
        }
        for gap in &self.gaps {
            gap.validate()?;
        }
        let mut gap_ids = BTreeSet::new();
        for gap in &self.gaps {
            if !gap_ids.insert(&gap.gap_id) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "candidate.gaps",
                });
            }
        }
        let mut omission_handles = BTreeSet::new();
        for omission in &self.omissions {
            omission.validate()?;
            if !omission_handles.insert(&omission.handle) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "candidate.omissions",
                });
            }
        }
        if self.frontier.len() > MAX_ITEMS || self.expansion_handles.len() > MAX_REFS {
            return Err(SelfQueryContractError::Bound {
                field: "candidate.frontier",
                maximum: MAX_ITEMS,
                actual: self.frontier.len().max(self.expansion_handles.len()),
            });
        }
        for frontier in &self.frontier {
            check_text(frontier, "candidate.frontier", 1024)?;
        }
        let mut expansion_handles = BTreeSet::new();
        for handle in &self.expansion_handles {
            check_id(handle.as_str(), "candidate.expansion_handle")?;
            if !expansion_handles.insert(handle) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "candidate.expansion_handles",
                });
            }
        }
        self.attempt.validate()?;
        if self.state_fence.validate().is_err() {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "candidate.state_fence",
            });
        }
        self.policy.validate()?;
        if self.authority_ceiling != self.policy.authority_ceiling
            || self.privacy != self.policy.privacy
            || self.disclosure != self.policy.disclosure
            || self.effect_ceiling != self.policy.effect_ceiling
            || self.proof_ceiling != self.policy.proof_ceiling
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "candidate.policy_ceilings",
            });
        }
        let mut denominator_member_ids = BTreeSet::new();
        for member in &self.denominator.members {
            if !denominator_member_ids.insert(&member.member_id)
                || self
                    .source
                    .as_ref()
                    .is_none_or(|source| member.source_handle != source.source_handle)
            {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "candidate.denominator.member",
                });
            }
            if !anchor_ids.contains(&member.anchor_id)
                && (self.disposition == ArchitectureBriefDisposition::Complete
                    || self.frontier.is_empty())
            {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "candidate.denominator.anchor",
                });
            }
        }
        self.preservation
            .validate()
            .map_err(|_| SelfQueryContractError::Conflict {
                field: "candidate.preservation",
            })?;
        check_digest(&self.input_digest, "candidate.input_digest")?;
        check_digest(&self.output_digest, "candidate.output_digest")?;
        if self.effect_ceiling == EffectClass::ReversibleMutation
            || self.effect_ceiling == EffectClass::ExternalEffect
            || self.proof_ceiling > ProofCeiling::CandidateArtifact
        {
            return Err(SelfQueryContractError::Conflict {
                field: "candidate.effect_or_proof_ceiling",
            });
        }
        if self.disposition == ArchitectureBriefDisposition::Complete && !self.denominator.complete
        {
            return Err(SelfQueryContractError::Conflict {
                field: "candidate.complete_denominator",
            });
        }
        if self.denominator.complete && self.disposition == ArchitectureBriefDisposition::Complete {
            let member_anchor_ids: BTreeSet<&ArtifactId> = self
                .denominator
                .members
                .iter()
                .map(|member| &member.anchor_id)
                .collect();
            let anchor_id_set: BTreeSet<&ArtifactId> = self
                .anchors
                .iter()
                .map(|anchor| &anchor.anchor_id)
                .collect();
            let emitted = self
                .sections
                .iter()
                .flat_map(|section| {
                    section
                        .statements
                        .iter()
                        .map(move |statement| (section.kind, statement.anchor_id.clone()))
                })
                .collect::<BTreeSet<_>>();
            let dependency_anchor_ids: BTreeSet<&ArtifactId> = self
                .denominator
                .members
                .iter()
                .map(|member| &member.anchor_id)
                .collect();
            let required_handles: BTreeSet<&ArtifactId> = self
                .denominator
                .members
                .iter()
                .filter(|member| member.required)
                .flat_map(|member| [&member.member_id, &member.anchor_id])
                .collect();
            if self
                .source
                .as_ref()
                .is_none_or(|source| source.status != ArchitectureSourceStatus::Accepted)
                || self.anchors.iter().any(|anchor| {
                    matches!(
                        anchor.applicability.state,
                        super::source::ArchitectureApplicabilityState::Unknown
                    ) || anchor.applicability.basis
                        == super::source::ArchitectureApplicabilityBasis::SimilarityRejected
                })
                || self.denominator.members.len() != self.anchors.len()
                || member_anchor_ids != anchor_id_set
                || self.anchors.iter().any(|anchor| {
                    matches!(
                        anchor.applicability.state,
                        super::source::ArchitectureApplicabilityState::Applicable
                            | super::source::ArchitectureApplicabilityState::Conditional
                    ) && !emitted
                        .contains(&(section_for_anchor(anchor.class), anchor.anchor_id.clone()))
                        && !(matches!(
                            anchor.modality,
                            ArchitectureStatementModality::Must
                                | ArchitectureStatementModality::May
                                | ArchitectureStatementModality::Target
                        ) && emitted.contains(&(
                            ArchitectureBriefSectionKind::RequirementsAndTargets,
                            anchor.anchor_id.clone(),
                        )))
                })
                || self.anchors.iter().any(|anchor| {
                    anchor
                        .dependency_refs
                        .iter()
                        .any(|dependency| !dependency_anchor_ids.contains(dependency))
                })
                || self
                    .omissions
                    .iter()
                    .any(|omission| required_handles.contains(&omission.handle))
                || self.denominator.members.iter().any(|member| {
                    member.required
                        && self
                            .anchors
                            .iter()
                            .find(|anchor| anchor.anchor_id == member.anchor_id)
                            .is_some_and(|anchor| {
                                anchor.applicability.state
                                    == super::source::ArchitectureApplicabilityState::NotApplicable
                                    && anchor.applicability.evidence_refs.is_empty()
                            })
                })
                || !self.frontier.is_empty()
                || self.policy.cancellation_requested
                || self
                    .policy
                    .now_ms
                    .zip(self.policy.deadline_ms)
                    .is_some_and(|(now, deadline)| deadline < now)
                || self.gaps.iter().any(|gap| {
                    matches!(gap.class, ArchitectureBriefGapClass::Architecture)
                        && matches!(
                            gap.state,
                            ArchitectureBriefGapState::Open
                                | ArchitectureBriefGapState::Partial
                                | ArchitectureBriefGapState::Unsupported
                                | ArchitectureBriefGapState::Unknown
                        )
                })
            {
                return Err(SelfQueryContractError::Conflict {
                    field: "candidate.complete_coverage",
                });
            }
            self.preservation
                .overall()
                .map_err(|_| SelfQueryContractError::Conflict {
                    field: "candidate.preservation",
                })?;
        }
        if self.output_digest != self.compute_output_digest()? {
            return Err(SelfQueryContractError::DigestMismatch {
                field: "candidate.output_digest",
            });
        }
        let output_limit = usize::try_from(
            self.policy
                .max_output_bytes
                .min(MAX_CANONICAL_PREIMAGE_BYTES as u64),
        )
        .map_err(|_| SelfQueryContractError::Bound {
            field: "candidate.output_wire",
            maximum: MAX_CANONICAL_PREIMAGE_BYTES,
            actual: usize::MAX,
        })?;
        let output_size = canonical_size(self, output_limit, "candidate.output_wire")?;
        if self.usage.output_bytes != u64::try_from(output_size).unwrap_or(u64::MAX) {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "candidate.usage.output_bytes",
            });
        }
        Ok(())
    }

    /// Checks the candidate against the complete typed input closure. This
    /// binds lifecycle, fence, policy and v1 validated-draft identities while
    /// leaving source acceptance to its external owner.
    pub fn validate_against(&self, input: &SelfQueryInput) -> Result<(), SelfQueryContractError> {
        input.validate()?;
        self.validate()?;
        if self.input_digest != input.input_digest()?
            || self.job_id != input.validated_candidate.bundle.job_id
            || self.operation_id != input.validated_candidate.job.operation_id
            || self.idempotency_key != input.validated_candidate.job.idempotency_key
            || self.task_id != input.validated_candidate.job.task_id
            || self.scope_id != input.validated_candidate.job.scope_id
            || self.requester_origin != input.validated_candidate.job.requester.origin
            || self.profile != input.profile
            || self.source_bundle_handle != input.source_bundle_handle
            || self.pair != input.source.as_ref().map(|source| source.pair.clone())
            || self.source != input.source
            || self.anchors != input.anchors
            || self.denominator != input.denominator
            || self.attempt != input.attempt
            || self.state_fence != input.validated_candidate.job.state_fence
            || self.policy != input.policy
            || self.preservation != input.preservation
            || self.invalidation_conditions != input.invalidation_conditions
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "candidate.input_closure",
            });
        }
        check_no_cross_subsidy(&self.usage, &input.validated_candidate.job.budget).map_err(
            |_| SelfQueryContractError::Conflict {
                field: "candidate.upstream_budget",
            },
        )?;
        let input_limit = usize::try_from(input.policy.max_input_bytes.min(16 * 1024 * 1024))
            .map_err(|_| SelfQueryContractError::Bound {
                field: "candidate.input_wire",
                maximum: MAX_CANONICAL_PREIMAGE_BYTES,
                actual: usize::MAX,
            })?;
        let measured_input = canonical_size(input, input_limit, "candidate.input_wire")?;
        if self.usage.input_bytes != u64::try_from(measured_input).unwrap_or(u64::MAX)
            || self.usage.candidates != 1
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "candidate.usage.input_or_candidates",
            });
        }
        if self.profile.output_profile != SelfQueryOutputProfile::ArchitectureBrief {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "candidate.output_profile",
            });
        }
        Ok(())
    }
}
