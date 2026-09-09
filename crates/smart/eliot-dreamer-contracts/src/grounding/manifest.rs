//! Immutable authority/reference manifest for grounding.

use crate::{error::ContractViolation, grounding::claims::TypedEvidenceAssertion};
use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_epistemic_contracts::{
    CoverageDenominator, CoverageReceipt, EvidenceGrade, PositionAssertability, ProvenanceClosure,
    SourceAssurance, SourceLineage, SupportRecord,
};
use eliot_evidence::{EvidenceAuthority, EvidenceFreshness};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_MANIFEST_BYTES: usize = 1_048_576;
const MAX_REFERENCES: usize = 4_096;

/// One authorized, revision-bound reference. Handles are data, never authority by themselves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedReference {
    pub handle: ArtifactId,
    pub source_lineage: Option<SourceLineage>,
    pub support: Option<SupportRecord>,
    pub provenance: Option<ProvenanceClosure>,
    pub content_digest: String,
    pub source_revision: String,
    pub authority_digest: String,
    pub authority: EvidenceAuthority,
    pub freshness: EvidenceFreshness,
    pub source_assurance: Option<SourceAssurance>,
    pub grade_ceiling: EvidenceGrade,
    pub assertability_ceiling: PositionAssertability,
    pub privacy: eliot_epistemic_contracts::PrivacyHandling,
    pub disclosure: eliot_epistemic_contracts::DisclosureClass,
    pub origin: String,
    pub invalidated: bool,
    pub revocation_reason: Option<String>,
    pub assertions: Vec<TypedEvidenceAssertion>,
    pub stale: bool,
}

impl AuthorizedReference {
    pub fn preflight_bytes(&self) -> Result<usize, ContractViolation> {
        let mut total = 0usize;
        for value in [
            self.handle.as_str(),
            &self.content_digest,
            &self.source_revision,
            &self.authority_digest,
        ] {
            total = total
                .checked_add(value.len())
                .ok_or(ContractViolation::Budget {
                    dimension: "manifest_bytes",
                    reason: "reference preflight overflow".into(),
                })?;
        }
        total = total
            .checked_add(self.assertions.len().checked_mul(256).ok_or(
                ContractViolation::Budget {
                    dimension: "manifest_bytes",
                    reason: "assertion count overflow".into(),
                },
            )?)
            .ok_or(ContractViolation::Budget {
                dimension: "manifest_bytes",
                reason: "reference preflight overflow".into(),
            })?;
        for allowance in [
            if self.source_lineage.is_some() {
                1_024
            } else {
                0
            },
            if self.support.is_some() { 8_192 } else { 0 },
            if self.provenance.is_some() { 32_768 } else { 0 },
        ] {
            total = total
                .checked_add(allowance)
                .ok_or(ContractViolation::Budget {
                    dimension: "manifest_bytes",
                    reason: "reference preflight overflow".into(),
                })?;
        }
        Ok(total)
    }
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if let Some(lineage) = &self.source_lineage {
            lineage
                .validate()
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "source_lineage",
                    reason: error.to_string(),
                })?;
            if lineage.content_digest != self.content_digest
                || lineage.revision != self.source_revision
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "source_lineage",
                    reason: "reference lineage content or revision drift".into(),
                });
            }
        }
        if let Some(support) = &self.support {
            support
                .validate()
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "support",
                    reason: error.to_string(),
                })?;
        }
        if let Some(assurance) = &self.source_assurance {
            assurance
                .validate()
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "source_assurance",
                    reason: error.to_string(),
                })?;
            if assurance.revision != self.source_revision {
                return Err(ContractViolation::BindingMismatch {
                    field: "source_assurance",
                    reason: "assurance revision drift".into(),
                });
            }
        }
        if let Some(provenance) = &self.provenance {
            provenance
                .validate()
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "provenance",
                    reason: error.to_string(),
                })?;
            if !provenance.records.contains(&self.handle)
                || provenance.record_origin.get(&self.handle) != Some(&self.content_digest)
                || !provenance.lineage.iter().any(|lineage| {
                    lineage.content_digest == self.content_digest
                        && lineage.revision == self.source_revision
                })
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "provenance",
                    reason:
                        "closure does not resolve this reference's handle, content, and revision"
                            .into(),
                });
            }
        }
        digest(&self.content_digest, "content_digest")?;
        text(&self.source_revision, "source_revision")?;
        digest(&self.authority_digest, "authority_digest")?;
        text(&self.origin, "origin")?;
        if self.invalidated && self.revocation_reason.is_none() {
            return Err(ContractViolation::MissingField("revocation_reason"));
        }
        if let Some(reason) = &self.revocation_reason {
            text(reason, "revocation_reason")?;
        }
        for assertion in &self.assertions {
            assertion.validate()?;
        }
        let mut assertion_ids = BTreeSet::new();
        for assertion in &self.assertions {
            if !assertion_ids.insert(assertion.assertion_id.clone()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "assertions",
                    reason: "duplicate assertion identity".into(),
                });
            }
        }
        Ok(())
    }
}

/// Frozen allow-list and coverage preimages supplied to A-14b.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedReferenceManifest {
    pub schema_version: u32,
    pub manifest_id: String,
    pub run_id: String,
    pub task_id: TaskId,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub source_snapshot: String,
    pub source_revision: String,
    pub references: BTreeMap<ArtifactId, AuthorizedReference>,
    pub coverage_denominators: BTreeMap<String, CoverageDenominator>,
    pub coverage_receipts: BTreeMap<String, CoverageReceipt>,
    pub dependence_groups: BTreeSet<String>,
    pub digest: String,
}

impl AllowedReferenceManifest {
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        let mut preimage = self.clone();
        preimage.digest.clear();
        crate::grounding::encoding::digest(&preimage)
    }
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ContractViolation> {
        crate::error::check_schema_version(self.schema_version, super::GROUNDING_SCHEMA_VERSION)?;
        text(&self.manifest_id, "manifest_id")?;
        text(&self.run_id, "run_id")?;
        text(&self.scope_id, "scope_id")?;
        text(&self.source_snapshot, "source_snapshot")?;
        text(&self.source_revision, "source_revision")?;
        digest(&self.digest, "digest")?;
        if self.computed_digest()? != self.digest {
            return Err(ContractViolation::BindingMismatch {
                field: "manifest_digest",
                reason: "manifest preimage digest mismatch".into(),
            });
        }
        crate::error::check_fence(&self.state_fence)?;
        crate::error::check_vec_bound(self.references.len(), MAX_REFERENCES, "references")?;
        let mut preflight = 0usize;
        for value in [
            &self.manifest_id,
            &self.run_id,
            &self.scope_id,
            &self.source_snapshot,
            &self.source_revision,
            &self.digest,
        ] {
            preflight = preflight
                .checked_add(value.len())
                .ok_or(ContractViolation::Budget {
                    dimension: "manifest_bytes",
                    reason: "manifest preflight overflow".into(),
                })?;
        }
        for reference in self.references.values() {
            preflight = preflight.checked_add(reference.preflight_bytes()?).ok_or(
                ContractViolation::Budget {
                    dimension: "manifest_bytes",
                    reason: "manifest preflight overflow".into(),
                },
            )?;
            if preflight > MAX_MANIFEST_BYTES {
                return Err(ContractViolation::Budget {
                    dimension: "manifest_bytes",
                    reason: "manifest exceeds contract ceiling".into(),
                });
            }
        }
        for (key, value) in &self.references {
            value.validate()?;
            if let Some(support) = &value.support
                && (support.task_id != self.task_id
                    || support.fence != self.state_fence
                    || support.validity.scope != self.scope_id)
            {
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "support",
                        reason: "support task or fence differs from manifest".into(),
                    });
                }
            }
            if &value.handle != key {
                return Err(ContractViolation::BindingMismatch {
                    field: "references",
                    reason: "manifest map key differs from handle".into(),
                });
            }
        }
        for (key, value) in &self.coverage_denominators {
            text(key, "coverage_denominators")?;
            value
                .validate()
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "coverage_denominators",
                    reason: error.to_string(),
                })?;
            if value.digest != *key
                || value.scope != self.scope_id
                || value.fence != self.state_fence
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "coverage_denominators",
                    reason: "denominator digest, revision, scope, or fence drift".into(),
                });
            }
        }
        for (key, value) in &self.coverage_receipts {
            text(key, "coverage_receipts")?;
            value
                .validate()
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "coverage_receipts",
                    reason: error.to_string(),
                })?;
            if value.denominator != *key
                || value.task_id != self.task_id
                || value.scope != self.scope_id
                || value.fence != self.state_fence
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "coverage_receipts",
                    reason: "receipt denominator, task, policy, scope, or fence drift".into(),
                });
            }
        }
        for group in &self.dependence_groups {
            text(group, "dependence_groups")?;
        }
        Ok(())
    }
    pub fn contains(&self, handle: &ArtifactId) -> bool {
        self.references.get(handle).is_some_and(|r| {
            !r.stale
                && !matches!(
                    r.freshness,
                    EvidenceFreshness::Stale | EvidenceFreshness::Unknown
                )
        })
    }
}
fn text(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    crate::error::check_text(value, field, 4096)
}
fn digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if crate::error::is_hex64_lower(value) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field,
            reason: "expected lowercase SHA-256 digest".into(),
        })
    }
}
