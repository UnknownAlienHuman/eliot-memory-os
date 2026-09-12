use eliot_conformance_contracts::EvidenceDomain;
use eliot_dreamer_contracts::{AttemptBinding, SelfQueryProfile};
use serde::{Deserialize, Serialize};

use crate::{
    ImplementationBriefError,
    model::{
        EvidenceAxisSnapshot, ImplementationDenominator, ImplementationSourceStatus, ProofStage,
    },
    validation::{
        MAX_ID_BYTES, MAX_ITEMS, MAX_TEXT_BYTES, MAX_WIRE_BYTES, bounded_canonical_size,
        canonical_digest, check_collection_len, check_digest, check_id, check_text,
        sorted_unique_strings,
    },
};

/// Result of one required stage without collapsing its independent axes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageDisposition {
    CurrentVerified,
    CurrentUnverified,
    Partial,
    Failed,
    Skipped,
    Simulated,
    Missing,
    Unavailable,
    Unknown,
    Stale,
    Conflicted,
    NotApplicable,
}

/// Stage-local evidence/accounting result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageAssessment {
    pub stage: ProofStage,
    pub disposition: StageDisposition,
    pub evidence: Vec<EvidenceAxisSnapshot>,
}

/// Assessment of one declared obligation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObligationAssessment {
    pub obligation_id: String,
    pub mechanism_id: String,
    pub owner: String,
    pub required_domains: Vec<EvidenceDomain>,
    pub stages: Vec<StageAssessment>,
    pub gap_ids: Vec<String>,
    pub complete: bool,
}

/// Mechanism-level status. `Supported` requires every declared obligation/stage
/// to be currently verified or explicitly not applicable.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MechanismDisposition {
    Supported,
    Partial,
    Blocked,
    Absent,
    Deviated,
    Stale,
    Conflicted,
    Unknown,
    NotApplicable,
}

/// Complete assessment of one expected mechanism.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MechanismAssessment {
    pub mechanism_id: String,
    pub owner: Option<String>,
    pub architecture_refs: Vec<String>,
    pub statement_refs: Vec<String>,
    pub obligation_ids: Vec<String>,
    pub dependency_refs: Vec<String>,
    pub obligations: Vec<ObligationAssessment>,
    pub disposition: MechanismDisposition,
}

/// Closed gap classes in an Implementation brief.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationGapClass {
    ArchitectureConflict,
    Source,
    Contract,
    Compile,
    Package,
    Integration,
    Edge,
    Runtime,
    Product,
    Release,
    Coverage,
    Compatibility,
    Stale,
    Conflict,
    Unknown,
}

/// One exact unclosed Implementation gap.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationGap {
    pub gap_id: String,
    pub class: ImplementationGapClass,
    pub owner: String,
    pub mechanism_id: Option<String>,
    pub obligation_id: Option<String>,
    pub stage: Option<ProofStage>,
    pub detail: String,
    pub evidence_refs: Vec<String>,
}

/// Explicit unavailable or omitted input/reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationOmission {
    pub omission_id: String,
    pub owner: String,
    pub detail: String,
    pub reversible: bool,
}

/// Terminal candidate disposition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationBriefDisposition {
    Complete,
    Partial,
    Blocked,
    Unsupported,
    NoSource,
    Cancelled,
    Bound,
}

/// Candidate-only Implementation self-query result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationBriefProjection {
    pub schema_version: u32,
    pub candidate_id: String,
    pub job_id: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub task_id: String,
    pub scope_id: String,
    pub profile: SelfQueryProfile,
    pub attempt: AttemptBinding,
    pub state_fence_digest: String,
    pub question: String,
    pub architecture_source_handle: Option<String>,
    pub architecture_source_digest: Option<String>,
    pub implementation_source_handle: Option<String>,
    pub implementation_source_digest: Option<String>,
    pub implementation_source_status: Option<ImplementationSourceStatus>,
    pub mechanisms: Vec<MechanismAssessment>,
    pub gaps: Vec<ImplementationGap>,
    pub omissions: Vec<ImplementationOmission>,
    pub denominator: ImplementationDenominator,
    pub invalidation_conditions: Vec<String>,
    pub disposition: ImplementationBriefDisposition,
    pub proof_ceiling: String,
    pub work_units: u64,
    pub total_output_bytes: u64,
    pub input_digest: String,
    pub output_digest: String,
}

#[derive(Serialize)]
pub(crate) struct OutputDigestPreimage<'a> {
    schema_version: u32,
    candidate_id: &'a str,
    job_id: &'a str,
    operation_id: &'a str,
    idempotency_key: &'a str,
    task_id: &'a str,
    scope_id: &'a str,
    profile: &'a SelfQueryProfile,
    attempt: &'a AttemptBinding,
    state_fence_digest: &'a str,
    question: &'a str,
    architecture_source_handle: &'a Option<String>,
    architecture_source_digest: &'a Option<String>,
    implementation_source_handle: &'a Option<String>,
    implementation_source_digest: &'a Option<String>,
    implementation_source_status: &'a Option<ImplementationSourceStatus>,
    mechanisms: &'a [MechanismAssessment],
    gaps: &'a [ImplementationGap],
    omissions: &'a [ImplementationOmission],
    denominator: &'a ImplementationDenominator,
    invalidation_conditions: &'a [String],
    disposition: ImplementationBriefDisposition,
    proof_ceiling: &'a str,
    work_units: u64,
    total_output_bytes: u64,
    input_digest: &'a str,
}

impl ImplementationBriefProjection {
    pub(crate) fn digest_preimage(&self) -> OutputDigestPreimage<'_> {
        OutputDigestPreimage {
            schema_version: self.schema_version,
            candidate_id: &self.candidate_id,
            job_id: &self.job_id,
            operation_id: &self.operation_id,
            idempotency_key: &self.idempotency_key,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            profile: &self.profile,
            attempt: &self.attempt,
            state_fence_digest: &self.state_fence_digest,
            question: &self.question,
            architecture_source_handle: &self.architecture_source_handle,
            architecture_source_digest: &self.architecture_source_digest,
            implementation_source_handle: &self.implementation_source_handle,
            implementation_source_digest: &self.implementation_source_digest,
            implementation_source_status: &self.implementation_source_status,
            mechanisms: &self.mechanisms,
            gaps: &self.gaps,
            omissions: &self.omissions,
            denominator: &self.denominator,
            invalidation_conditions: &self.invalidation_conditions,
            disposition: self.disposition,
            proof_ceiling: &self.proof_ceiling,
            work_units: self.work_units,
            total_output_bytes: self.total_output_bytes,
            input_digest: &self.input_digest,
        }
    }

    /// Recomputes the canonical output digest.
    pub fn compute_output_digest(&self) -> Result<String, ImplementationBriefError> {
        canonical_digest(&self.digest_preimage(), "projection.output_digest")
    }

    /// Validates intrinsic output shape, bounds and identity.
    #[expect(
        clippy::too_many_lines,
        reason = "explicit candidate validation preserves every status and lineage field"
    )]
    pub fn validate(&self) -> Result<(), ImplementationBriefError> {
        if self.schema_version != super::IMPLEMENTATION_BRIEF_SCHEMA_VERSION {
            return Err(ImplementationBriefError::Invalid {
                field: "projection.schema_version",
                reason: "unsupported schema version",
            });
        }
        for (field, value) in [
            ("projection.candidate_id", self.candidate_id.as_str()),
            ("projection.job_id", self.job_id.as_str()),
            ("projection.operation_id", self.operation_id.as_str()),
            ("projection.idempotency_key", self.idempotency_key.as_str()),
            ("projection.task_id", self.task_id.as_str()),
            ("projection.scope_id", self.scope_id.as_str()),
        ] {
            check_id(value, field)?;
        }
        self.profile.validate()?;
        self.attempt.validate()?;
        check_digest(&self.state_fence_digest, "projection.state_fence_digest")?;
        check_text(&self.question, "projection.question", MAX_TEXT_BYTES)?;
        for (field, value) in [
            (
                "projection.architecture_source_handle",
                self.architecture_source_handle.as_deref(),
            ),
            (
                "projection.implementation_source_handle",
                self.implementation_source_handle.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                check_text(value, field, MAX_ID_BYTES)?;
            }
        }
        for (field, value) in [
            (
                "projection.architecture_source_digest",
                self.architecture_source_digest.as_deref(),
            ),
            (
                "projection.implementation_source_digest",
                self.implementation_source_digest.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                check_digest(value, field)?;
            }
        }
        check_collection_len(self.mechanisms.len(), MAX_ITEMS, "projection.mechanisms")?;
        check_collection_len(self.gaps.len(), MAX_ITEMS, "projection.gaps")?;
        check_collection_len(self.omissions.len(), MAX_ITEMS, "projection.omissions")?;
        ensure_mechanism_order(&self.mechanisms)?;
        ensure_gap_order(&self.gaps)?;
        ensure_omission_order(&self.omissions)?;
        for mechanism in &self.mechanisms {
            validate_mechanism_assessment(mechanism)?;
        }
        for gap in &self.gaps {
            validate_gap(gap)?;
        }
        for omission in &self.omissions {
            check_id(&omission.omission_id, "projection.omission_id")?;
            check_id(&omission.owner, "projection.omission_owner")?;
            check_text(&omission.detail, "projection.omission_detail", MAX_TEXT_BYTES)?;
        }
        self.denominator.validate()?;
        let invalidation = sorted_unique_strings(
            &self.invalidation_conditions,
            "projection.invalidation_conditions",
        )?;
        if invalidation != self.invalidation_conditions {
            return Err(ImplementationBriefError::Invalid {
                field: "projection.invalidation_conditions",
                reason: "collection is not in canonical order",
            });
        }
        if self.proof_ceiling != super::IMPLEMENTATION_BRIEF_PROOF_CEILING {
            return Err(ImplementationBriefError::BindingMismatch {
                field: "projection.proof_ceiling",
            });
        }
        check_digest(&self.input_digest, "projection.input_digest")?;
        check_digest(&self.output_digest, "projection.output_digest")?;
        if self.output_digest != self.compute_output_digest()? {
            return Err(ImplementationBriefError::DigestMismatch {
                field: "projection.output_digest",
            });
        }
        let measured = bounded_canonical_size(self, MAX_WIRE_BYTES, "projection.output_wire")?;
        if u64::try_from(measured).unwrap_or(u64::MAX) != self.total_output_bytes {
            return Err(ImplementationBriefError::BindingMismatch {
                field: "projection.total_output_bytes",
            });
        }
        Ok(())
    }
}

fn validate_mechanism_assessment(
    mechanism: &MechanismAssessment,
) -> Result<(), ImplementationBriefError> {
    check_id(&mechanism.mechanism_id, "projection.mechanism_id")?;
    if let Some(owner) = &mechanism.owner {
        check_id(owner, "projection.mechanism_owner")?;
    }
    for (field, values) in [
        (
            "projection.mechanism_architecture_refs",
            &mechanism.architecture_refs,
        ),
        (
            "projection.mechanism_statement_refs",
            &mechanism.statement_refs,
        ),
        (
            "projection.mechanism_obligation_ids",
            &mechanism.obligation_ids,
        ),
        (
            "projection.mechanism_dependency_refs",
            &mechanism.dependency_refs,
        ),
    ] {
        let canonical = sorted_unique_strings(values, field)?;
        if canonical != *values {
            return Err(ImplementationBriefError::Invalid {
                field,
                reason: "collection is not in canonical order",
            });
        }
    }
    if !mechanism
        .obligations
        .windows(2)
        .all(|pair| pair[0].obligation_id < pair[1].obligation_id)
    {
        return Err(ImplementationBriefError::Invalid {
            field: "projection.mechanism_obligations",
            reason: "collection is not in canonical order",
        });
    }
    for obligation in &mechanism.obligations {
        check_id(&obligation.obligation_id, "projection.obligation_id")?;
        check_id(&obligation.mechanism_id, "projection.obligation_mechanism")?;
        check_id(&obligation.owner, "projection.obligation_owner")?;
        if obligation.mechanism_id != mechanism.mechanism_id {
            return Err(ImplementationBriefError::BindingMismatch {
                field: "projection.obligation_mechanism",
            });
        }
        if !obligation
            .required_domains
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(ImplementationBriefError::Invalid {
                field: "projection.obligation_domains",
                reason: "collection is not in canonical order",
            });
        }
        if !obligation
            .stages
            .windows(2)
            .all(|pair| pair[0].stage < pair[1].stage)
        {
            return Err(ImplementationBriefError::Invalid {
                field: "projection.obligation_stages",
                reason: "collection is not in canonical order",
            });
        }
        for stage in &obligation.stages {
            if !stage
                .evidence
                .windows(2)
                .all(|pair| pair[0].evidence_id < pair[1].evidence_id)
            {
                return Err(ImplementationBriefError::Invalid {
                    field: "projection.stage_evidence",
                    reason: "collection is not in canonical order",
                });
            }
        }
        let gaps = sorted_unique_strings(&obligation.gap_ids, "projection.obligation_gap_ids")?;
        if gaps != obligation.gap_ids {
            return Err(ImplementationBriefError::Invalid {
                field: "projection.obligation_gap_ids",
                reason: "collection is not in canonical order",
            });
        }
    }
    Ok(())
}

fn validate_gap(gap: &ImplementationGap) -> Result<(), ImplementationBriefError> {
    check_id(&gap.gap_id, "projection.gap_id")?;
    check_id(&gap.owner, "projection.gap_owner")?;
    if let Some(value) = &gap.mechanism_id {
        check_id(value, "projection.gap_mechanism")?;
    }
    if let Some(value) = &gap.obligation_id {
        check_id(value, "projection.gap_obligation")?;
    }
    check_text(&gap.detail, "projection.gap_detail", MAX_TEXT_BYTES)?;
    let evidence = sorted_unique_strings(&gap.evidence_refs, "projection.gap_evidence_refs")?;
    if evidence != gap.evidence_refs {
        return Err(ImplementationBriefError::Invalid {
            field: "projection.gap_evidence_refs",
            reason: "collection is not in canonical order",
        });
    }
    Ok(())
}

fn ensure_mechanism_order(
    mechanisms: &[MechanismAssessment],
) -> Result<(), ImplementationBriefError> {
    if mechanisms
        .windows(2)
        .all(|pair| pair[0].mechanism_id < pair[1].mechanism_id)
    {
        Ok(())
    } else {
        Err(ImplementationBriefError::Invalid {
            field: "projection.mechanisms",
            reason: "collection is not in canonical order",
        })
    }
}

fn ensure_gap_order(gaps: &[ImplementationGap]) -> Result<(), ImplementationBriefError> {
    if gaps.windows(2).all(|pair| pair[0].gap_id < pair[1].gap_id) {
        Ok(())
    } else {
        Err(ImplementationBriefError::Invalid {
            field: "projection.gaps",
            reason: "collection is not in canonical order",
        })
    }
}

fn ensure_omission_order(
    omissions: &[ImplementationOmission],
) -> Result<(), ImplementationBriefError> {
    if omissions
        .windows(2)
        .all(|pair| pair[0].omission_id < pair[1].omission_id)
    {
        Ok(())
    } else {
        Err(ImplementationBriefError::Invalid {
            field: "projection.omissions",
            reason: "collection is not in canonical order",
        })
    }
}
