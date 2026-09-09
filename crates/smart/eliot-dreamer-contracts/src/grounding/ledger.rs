//! Per-claim grounding ledger and explicit dispositions.

use crate::{error::ContractViolation, grounding::claims::ClaimKind};
use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_epistemic_contracts::{
    EvidenceGrade, GradeAssignment, PositionAssertability, SupportResult,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Grounding result uses the canonical epistemic support vocabulary verbatim.
pub type GroundingDisposition = SupportResult;

/// Full outcome for one claim, including rejected material and ceilings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimGroundingRecord {
    pub claim_id: String,
    pub proposition_digest: String,
    pub kind: ClaimKind,
    pub proposed_support: BTreeSet<ArtifactId>,
    pub accepted_support: BTreeSet<ArtifactId>,
    pub rejected_support: BTreeSet<ArtifactId>,
    pub unresolved_support: BTreeSet<ArtifactId>,
    pub proposed_counterevidence: BTreeSet<ArtifactId>,
    pub accepted_counterevidence: BTreeSet<ArtifactId>,
    pub rejected_counterevidence: BTreeSet<ArtifactId>,
    pub unresolved_counterevidence: BTreeSet<ArtifactId>,
    pub witness_assertions: BTreeMap<ArtifactId, BTreeSet<String>>,
    pub component_outcomes: BTreeMap<String, SupportResult>,
    pub disposition: GroundingDisposition,
    pub grade: Option<GradeAssignment>,
    pub grade_ceiling: EvidenceGrade,
    pub assertability_ceiling: PositionAssertability,
    pub coverage_denominator_ids: BTreeSet<String>,
    pub dependence_groups: BTreeSet<String>,
    pub unknowns: BTreeSet<String>,
    pub precision_findings: BTreeSet<String>,
    pub record_digest: String,
}

impl ClaimGroundingRecord {
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        let mut preimage = self.clone();
        preimage.record_digest.clear();
        crate::grounding::encoding::digest(&preimage)
    }
    pub fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.claim_id, "claim_id")?;
        digest(&self.proposition_digest, "proposition_digest")?;
        digest(&self.record_digest, "record_digest")?;
        if self.computed_digest()? != self.record_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "record_digest",
                reason: "record preimage digest mismatch".into(),
            });
        }
        for item in self.component_outcomes.keys() {
            text(item, "component_outcomes")?;
        }
        for item in &self.unknowns {
            text(item, "unknowns")?;
        }
        for item in &self.precision_findings {
            text(item, "precision_findings")?;
        }
        for item in &self.dependence_groups {
            text(item, "dependence_groups")?;
        }
        for item in &self.coverage_denominator_ids {
            text(item, "coverage_denominator_ids")?;
        }
        for (handle, assertions) in &self.witness_assertions {
            if !self.accepted_support.contains(handle)
                && !self.accepted_counterevidence.contains(handle)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "witness_assertions",
                    reason: "witness handle must be accepted evidence".into(),
                });
            }
            for assertion in assertions {
                text(assertion, "witness_assertions")?;
            }
        }
        let mut accounted_support = self.accepted_support.clone();
        accounted_support.extend(self.rejected_support.iter().cloned());
        accounted_support.extend(self.unresolved_support.iter().cloned());
        let mut accounted_counterevidence = self.accepted_counterevidence.clone();
        accounted_counterevidence.extend(self.rejected_counterevidence.iter().cloned());
        accounted_counterevidence.extend(self.unresolved_counterevidence.iter().cloned());
        if !self.accepted_support.is_subset(&self.proposed_support)
            || !self.rejected_support.is_subset(&self.proposed_support)
            || !self
                .accepted_counterevidence
                .is_subset(&self.proposed_counterevidence)
            || !self
                .rejected_counterevidence
                .is_subset(&self.proposed_counterevidence)
            || !self.accepted_support.is_disjoint(&self.rejected_support)
            || !self
                .accepted_counterevidence
                .is_disjoint(&self.rejected_counterevidence)
            || !self.accepted_support.is_disjoint(&self.unresolved_support)
            || !self.rejected_support.is_disjoint(&self.unresolved_support)
            || !self
                .accepted_counterevidence
                .is_disjoint(&self.unresolved_counterevidence)
            || !self
                .rejected_counterevidence
                .is_disjoint(&self.unresolved_counterevidence)
            || accounted_support != self.proposed_support
            || accounted_counterevidence != self.proposed_counterevidence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "record_evidence",
                reason: "accepted and rejected evidence must partition proposed evidence".into(),
            });
        }
        Ok(())
    }
}

/// Ledger with exact material denominator and unprocessed residue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimGroundingLedger {
    pub schema_version: u32,
    pub operation_id: String,
    pub job_id: String,
    pub task_id: TaskId,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub draft_digest: String,
    pub manifest_digest: String,
    pub policy_digest: String,
    pub expected_claim_ids: BTreeSet<String>,
    pub expected_subclaim_ids: BTreeMap<String, BTreeSet<String>>,
    pub records: BTreeMap<String, ClaimGroundingRecord>,
    pub nonmaterial_claim_ids: BTreeSet<String>,
    pub unprocessed_claim_ids: BTreeSet<String>,
    pub unprocessed_reason: Option<String>,
    pub ledger_digest: String,
}

impl ClaimGroundingLedger {
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        let mut preimage = self.clone();
        preimage.ledger_digest.clear();
        crate::grounding::encoding::digest(&preimage)
    }
    pub fn validate(&self) -> Result<(), ContractViolation> {
        crate::error::check_schema_version(self.schema_version, super::GROUNDING_SCHEMA_VERSION)?;
        for (key, record) in &self.records {
            record.validate()?;
            if &record.claim_id != key {
                return Err(ContractViolation::BindingMismatch {
                    field: "records",
                    reason: "record key differs from claim id".into(),
                });
            }
        }
        for id in &self.expected_claim_ids {
            text(id, "expected_claim_ids")?;
        }
        for (claim_id, subclaims) in &self.expected_subclaim_ids {
            text(claim_id, "expected_subclaim_ids")?;
            for subclaim in subclaims {
                text(subclaim, "expected_subclaim_ids")?;
            }
        }
        for id in &self.nonmaterial_claim_ids {
            text(id, "nonmaterial_claim_ids")?;
        }
        for id in &self.unprocessed_claim_ids {
            text(id, "unprocessed_claim_ids")?;
        }
        text(&self.operation_id, "operation_id")?;
        text(&self.job_id, "job_id")?;
        digest(&self.draft_digest, "draft_digest")?;
        digest(&self.manifest_digest, "manifest_digest")?;
        digest(&self.policy_digest, "policy_digest")?;
        digest(&self.ledger_digest, "ledger_digest")?;
        if self.computed_digest()? != self.ledger_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "ledger_digest",
                reason: "ledger preimage digest mismatch".into(),
            });
        }
        crate::error::check_fence(&self.state_fence)?;
        if self
            .records
            .keys()
            .any(|id| !self.expected_claim_ids.contains(id))
            || self.expected_claim_ids.iter().any(|id| {
                !self.records.contains_key(id) && !self.unprocessed_claim_ids.contains(id)
            })
        {
            return Err(ContractViolation::BindingMismatch {
                field: "claim_denominator",
                reason: "records and unprocessed residue must reconcile exactly".into(),
            });
        }
        if !self
            .unprocessed_claim_ids
            .is_subset(&self.expected_claim_ids)
            || (self.unprocessed_claim_ids.is_empty() && self.unprocessed_reason.is_some())
            || (!self.unprocessed_claim_ids.is_empty() && self.unprocessed_reason.is_none())
        {
            return Err(ContractViolation::BindingMismatch {
                field: "unprocessed_claim_ids",
                reason: "unprocessed residue must be an explicit subset with a reason".into(),
            });
        }
        if !self
            .records
            .keys()
            .all(|id| !self.unprocessed_claim_ids.contains(id))
            || !self
                .expected_claim_ids
                .is_disjoint(&self.nonmaterial_claim_ids)
            || !self
                .unprocessed_claim_ids
                .is_disjoint(&self.nonmaterial_claim_ids)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "claim_denominator",
                reason: "material, non-material, and unprocessed identifiers must be disjoint"
                    .into(),
            });
        }
        if let Some(reason) = &self.unprocessed_reason {
            text(reason, "unprocessed_reason")?;
        }
        Ok(())
    }
}
fn text(v: &str, f: &'static str) -> Result<(), ContractViolation> {
    crate::error::check_text(v, f, 4096)
}
fn digest(v: &str, f: &'static str) -> Result<(), ContractViolation> {
    if crate::error::is_hex64_lower(v) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field: f,
            reason: "expected lowercase SHA-256 digest".into(),
        })
    }
}
