//! Per-claim grounding ledger and explicit dispositions.

use crate::{error::ContractViolation, grounding::claims::ClaimKind};
use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_epistemic_contracts::{
    EvidenceGrade, GradeAssignment, PositionAssertability, PropositionId, SupportResult,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_SUPPORT_HANDLES: usize = 64;

/// Grounding result uses the canonical epistemic support vocabulary verbatim.
pub type GroundingDisposition = SupportResult;

/// Explicit link from a retained claim component to one independent typed
/// assertion. The frozen manifest does not need to know future model IDs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionWitness {
    pub claim_id: String,
    pub component: String,
    pub handle: ArtifactId,
    pub assertion_id: String,
}

/// Full outcome for one claim, including rejected material and ceilings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimGroundingRecord {
    pub claim_id: String,
    pub proposition: PropositionId,
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
    pub witnesses: Vec<AssertionWitness>,
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
    #[allow(clippy::items_after_statements)]
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        crate::grounding::encoding::preflight(self)?;
        let mut witnesses: Vec<_> = self.witnesses.iter().collect();
        witnesses.sort_by(|left, right| {
            (
                &left.claim_id,
                &left.component,
                &left.handle,
                &left.assertion_id,
            )
                .cmp(&(
                    &right.claim_id,
                    &right.component,
                    &right.handle,
                    &right.assertion_id,
                ))
        });
        if witnesses.windows(2).any(|pair| {
            (
                &pair[0].claim_id,
                &pair[0].component,
                &pair[0].handle,
                &pair[0].assertion_id,
            ) == (
                &pair[1].claim_id,
                &pair[1].component,
                &pair[1].handle,
                &pair[1].assertion_id,
            )
        }) {
            return Err(ContractViolation::BindingMismatch {
                field: "witnesses",
                reason: "duplicate witness identity cannot be normalized".into(),
            });
        }
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            claim_id: &'a str,
            proposition: &'a PropositionId,
            proposition_digest: &'a str,
            kind: ClaimKind,
            proposed_support: &'a BTreeSet<ArtifactId>,
            accepted_support: &'a BTreeSet<ArtifactId>,
            rejected_support: &'a BTreeSet<ArtifactId>,
            unresolved_support: &'a BTreeSet<ArtifactId>,
            proposed_counterevidence: &'a BTreeSet<ArtifactId>,
            accepted_counterevidence: &'a BTreeSet<ArtifactId>,
            rejected_counterevidence: &'a BTreeSet<ArtifactId>,
            unresolved_counterevidence: &'a BTreeSet<ArtifactId>,
            witnesses: Vec<&'a AssertionWitness>,
            component_outcomes: &'a BTreeMap<String, SupportResult>,
            disposition: GroundingDisposition,
            grade: &'a Option<GradeAssignment>,
            grade_ceiling: EvidenceGrade,
            assertability_ceiling: PositionAssertability,
            coverage_denominator_ids: &'a BTreeSet<String>,
            dependence_groups: &'a BTreeSet<String>,
            unknowns: &'a BTreeSet<String>,
            precision_findings: &'a BTreeSet<String>,
        }
        crate::grounding::encoding::digest(&Preimage {
            schema_version: super::GROUNDING_SCHEMA_VERSION,
            claim_id: &self.claim_id,
            proposition: &self.proposition,
            proposition_digest: &self.proposition_digest,
            kind: self.kind,
            proposed_support: &self.proposed_support,
            accepted_support: &self.accepted_support,
            rejected_support: &self.rejected_support,
            unresolved_support: &self.unresolved_support,
            proposed_counterevidence: &self.proposed_counterevidence,
            accepted_counterevidence: &self.accepted_counterevidence,
            rejected_counterevidence: &self.rejected_counterevidence,
            unresolved_counterevidence: &self.unresolved_counterevidence,
            witnesses,
            component_outcomes: &self.component_outcomes,
            disposition: self.disposition,
            grade: &self.grade,
            grade_ceiling: self.grade_ceiling,
            assertability_ceiling: self.assertability_ceiling,
            coverage_denominator_ids: &self.coverage_denominator_ids,
            dependence_groups: &self.dependence_groups,
            unknowns: &self.unknowns,
            precision_findings: &self.precision_findings,
        })
    }
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.claim_id, "claim_id")?;
        if self.proposition.as_str().is_empty() {
            return Err(ContractViolation::MissingField("proposition"));
        }
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
        if let Some(grade) = &self.grade {
            grade
                .validate()
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "grade",
                    reason: error.to_string(),
                })?;
        }
        for witness in &self.witnesses {
            if witness.claim_id != self.claim_id {
                return Err(ContractViolation::BindingMismatch {
                    field: "witness.claim_id",
                    reason: "witness claim identity differs from record".into(),
                });
            }
            text(&witness.claim_id, "witness.claim_id")?;
            text(&witness.component, "witness.component")?;
            text(&witness.assertion_id, "witness.assertion_id")?;
            if !self.accepted_support.contains(&witness.handle)
                && !self.accepted_counterevidence.contains(&witness.handle)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "witnesses",
                    reason: "witness handle must be accepted evidence".into(),
                });
            }
        }
        if self.proposed_support.len() > MAX_SUPPORT_HANDLES
            || self.proposed_counterevidence.len() > MAX_SUPPORT_HANDLES
            || (!self.rejected_support.is_empty() && self.precision_findings.is_empty())
            || (!self.rejected_counterevidence.is_empty() && self.precision_findings.is_empty())
            || (!self.unresolved_support.is_empty() && self.unknowns.is_empty())
            || (!self.unresolved_counterevidence.is_empty() && self.unknowns.is_empty())
        {
            return Err(ContractViolation::BindingMismatch {
                field: "record_evidence",
                reason: "evidence residue requires bounded explicit reasons".into(),
            });
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
    pub run_id: String,
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
    #[allow(clippy::items_after_statements)]
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        crate::grounding::encoding::preflight(self)?;
        let mut normalized = self.clone();
        for record in normalized.records.values_mut() {
            record.witnesses.sort_by(|left, right| {
                (
                    &left.claim_id,
                    &left.component,
                    &left.handle,
                    &left.assertion_id,
                )
                    .cmp(&(
                        &right.claim_id,
                        &right.component,
                        &right.handle,
                        &right.assertion_id,
                    ))
            });
        }
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            operation_id: &'a str,
            run_id: &'a str,
            job_id: &'a str,
            task_id: &'a TaskId,
            scope_id: &'a str,
            state_fence: &'a StateFence,
            draft_digest: &'a str,
            manifest_digest: &'a str,
            policy_digest: &'a str,
            expected_claim_ids: &'a BTreeSet<String>,
            expected_subclaim_ids: &'a BTreeMap<String, BTreeSet<String>>,
            records: &'a BTreeMap<String, ClaimGroundingRecord>,
            nonmaterial_claim_ids: &'a BTreeSet<String>,
            unprocessed_claim_ids: &'a BTreeSet<String>,
            unprocessed_reason: &'a Option<String>,
        }
        crate::grounding::encoding::digest(&Preimage {
            schema_version: self.schema_version,
            operation_id: &self.operation_id,
            run_id: &self.run_id,
            job_id: &self.job_id,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            state_fence: &self.state_fence,
            draft_digest: &self.draft_digest,
            manifest_digest: &self.manifest_digest,
            policy_digest: &self.policy_digest,
            expected_claim_ids: &self.expected_claim_ids,
            expected_subclaim_ids: &self.expected_subclaim_ids,
            records: &normalized.records,
            nonmaterial_claim_ids: &normalized.nonmaterial_claim_ids,
            unprocessed_claim_ids: &normalized.unprocessed_claim_ids,
            unprocessed_reason: &normalized.unprocessed_reason,
        })
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
        text(&self.run_id, "run_id")?;
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
