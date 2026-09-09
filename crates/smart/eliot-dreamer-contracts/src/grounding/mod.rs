//! Versioned, lossless Dreamer grounding handoff contracts.
//!
//! This namespace is deliberately separate from the v1 draft/A05 surface. It
//! carries structured claims, an immutable reference manifest, and a complete
//! per-claim ledger. It performs shape and identity checks only; grounding and
//! coverage inference belong to A-14b (#602).

#![forbid(unsafe_code)]

use eliot_contracts::{StateFence, TaskId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{ContractViolation, DreamInputBundle, DreamJobInput, ScreenBinding};

pub mod claims;
pub mod encoding;
pub mod ledger;
pub mod manifest;
pub mod policy;

pub use claims::{
    ClaimKind, MaterialClaim, NonMaterialClaim, PrecisionPayload, ScreenTargetBinding,
    TypedEvidenceAssertion,
};
pub use eliot_epistemic_contracts::{
    CausalClaim, CoverageDenominator, CoverageReceipt, DisclosureClass, EvidenceGrade,
    GradeAssignment, PositionAssertability, PrivacyHandling, ProvenanceClosure, SourceAssurance,
    SourceLineage, SupportRecord, SupportResult, TemporalRecord,
};
pub use ledger::{ClaimGroundingLedger, ClaimGroundingRecord, GroundingDisposition};
pub use manifest::{AllowedReferenceManifest, AuthorizedReference};
pub use policy::GroundingPolicy;

/// Wire revision for the structured grounding handoff.
pub const GROUNDING_SCHEMA_VERSION: u32 = 2;
pub const MAX_CLAIMS: usize = 4_096;
const MAX_HANDOFF_BYTES: usize = 1_048_576;

/// Structured provider output retained before grounding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelDraft {
    pub schema_version: u32,
    pub job_id: String,
    pub task_id: TaskId,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub job: DreamJobInput,
    pub bundle: DreamInputBundle,
    pub raw_output_digest: String,
    pub requester_digest: String,
    pub attempt_digest: String,
    pub route_digest: String,
    pub budget_digest: String,
    pub bundle_digest: String,
    pub input_manifest_digest: String,
    pub claims: Vec<MaterialClaim>,
    pub non_material_claims: Vec<NonMaterialClaim>,
    pub screen: Option<ScreenBinding>,
    pub draft_digest: String,
}

impl ModelDraft {
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        let mut preimage = self.clone();
        preimage.draft_digest.clear();
        encoding::digest(&preimage)
    }
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ContractViolation> {
        crate::error::check_schema_version(self.schema_version, GROUNDING_SCHEMA_VERSION)?;
        check_text(&self.job_id, "job_id")?;
        check_text(&self.scope_id, "scope_id")?;
        check_digest(&self.raw_output_digest, "raw_output_digest")?;
        check_digest(&self.requester_digest, "requester_digest")?;
        check_digest(&self.attempt_digest, "attempt_digest")?;
        check_digest(&self.route_digest, "route_digest")?;
        check_digest(&self.budget_digest, "budget_digest")?;
        check_digest(&self.bundle_digest, "bundle_digest")?;
        check_digest(&self.input_manifest_digest, "input_manifest_digest")?;
        check_digest(&self.draft_digest, "draft_digest")?;
        crate::error::check_fence(&self.state_fence)?;
        self.job
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "job",
                reason: error.to_string(),
            })?;
        self.bundle
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "bundle",
                reason: error.to_string(),
            })?;
        if encoding::digest(&self.bundle)? != self.bundle_digest
            || self.job.frozen_manifest_digest != self.input_manifest_digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "input_context",
                reason: "bundle or job manifest preimage digest mismatch".into(),
            });
        }
        if self.job.task_id != self.task_id.to_string()
            || self.job.scope_id != self.scope_id
            || self.job.state_fence != self.state_fence
            || self.bundle.task_id != self.task_id.to_string()
            || self.bundle.scope_id != self.scope_id
            || self.bundle.state_fence != self.state_fence
            || self.bundle.manifest_digest != self.input_manifest_digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "input_context",
                reason: "retained job or bundle identity drift".into(),
            });
        }
        crate::error::check_vec_bound(self.claims.len(), MAX_CLAIMS, "claims")?;
        crate::error::check_vec_bound(
            self.non_material_claims.len(),
            MAX_CLAIMS,
            "non_material_claims",
        )?;
        let mut retained_bytes = 0usize;
        for value in [
            &self.job_id,
            &self.scope_id,
            &self.raw_output_digest,
            &self.requester_digest,
            &self.attempt_digest,
            &self.route_digest,
            &self.budget_digest,
            &self.bundle_digest,
            &self.input_manifest_digest,
            &self.draft_digest,
        ] {
            add_bytes(&mut retained_bytes, value.len(), "grounding_handoff_bytes")?;
        }
        for claim in &self.claims {
            add_bytes(
                &mut retained_bytes,
                claim.preflight_bytes()?,
                "grounding_handoff_bytes",
            )?;
        }
        for claim in &self.non_material_claims {
            add_bytes(
                &mut retained_bytes,
                claim.preflight_bytes(),
                "grounding_handoff_bytes",
            )?;
        }
        if retained_bytes > MAX_HANDOFF_BYTES {
            return Err(ContractViolation::Budget {
                dimension: "grounding_handoff_bytes",
                reason: "retained structured input exceeds the contract ceiling".into(),
            });
        }
        let mut claim_ids = BTreeSet::new();
        for claim in &self.claims {
            if !claim_ids.insert(claim.claim_id.clone()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "claims",
                    reason: "duplicate material claim identity".into(),
                });
            }
        }
        for claim in &self.non_material_claims {
            if !claim_ids.insert(claim.claim_id.clone()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "claims",
                    reason: "material and non-material claim identities overlap".into(),
                });
            }
        }
        for claim in &self.claims {
            claim.validate()?;
        }
        for claim in &self.non_material_claims {
            claim.validate()?;
        }
        if let Some(screen) = &self.screen {
            screen.validate()?;
        }
        if self.computed_digest()? != self.draft_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "draft_digest",
                reason: "draft preimage digest mismatch".into(),
            });
        }
        Ok(())
    }
}

/// Grounding output retaining the complete input preimage and ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundedDreamDraft {
    pub schema_version: u32,
    pub job_id: String,
    pub task_id: TaskId,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub draft_digest: String,
    pub manifest_digest: String,
    pub policy_digest: String,
    pub input: ModelDraft,
    pub manifest: AllowedReferenceManifest,
    pub policy: GroundingPolicy,
    pub ledger: ClaimGroundingLedger,
    pub screen: Option<ScreenBinding>,
    pub output_digest: String,
}

impl GroundedDreamDraft {
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        let mut preimage = self.clone();
        preimage.output_digest.clear();
        encoding::digest(&preimage)
    }
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ContractViolation> {
        crate::error::check_schema_version(self.schema_version, GROUNDING_SCHEMA_VERSION)?;
        check_text(&self.job_id, "job_id")?;
        check_text(&self.scope_id, "scope_id")?;
        check_digest(&self.draft_digest, "draft_digest")?;
        check_digest(&self.manifest_digest, "manifest_digest")?;
        check_digest(&self.policy_digest, "policy_digest")?;
        check_digest(&self.output_digest, "output_digest")?;
        if self.computed_digest()? != self.output_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "output_digest",
                reason: "grounded draft preimage digest mismatch".into(),
            });
        }
        crate::error::check_fence(&self.state_fence)?;
        self.input.validate()?;
        self.manifest.validate()?;
        self.policy.validate()?;
        self.ledger.validate()?;
        if self.input.draft_digest != self.draft_digest
            || self.manifest.digest != self.manifest_digest
            || self.policy.digest != self.policy_digest
            || self.ledger.draft_digest != self.draft_digest
            || self.ledger.manifest_digest != self.manifest_digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "grounding_handoff",
                reason: "retained preimages and ledger digests must agree".into(),
            });
        }
        if self.input.task_id != self.task_id
            || self.input.job_id != self.job_id
            || self.input.input_manifest_digest != self.manifest_digest
            || self.input.scope_id != self.scope_id
            || self.input.state_fence != self.state_fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "grounding_handoff",
                reason: "task, scope, or fence drift".into(),
            });
        }
        if self.manifest.task_id != self.task_id
            || self.manifest.scope_id != self.scope_id
            || self.manifest.state_fence != self.state_fence
            || self.ledger.task_id != self.task_id
            || self.ledger.scope_id != self.scope_id
            || self.ledger.state_fence != self.state_fence
            || self.ledger.operation_id != self.manifest.run_id
            || self.ledger.job_id != self.job_id
        {
            return Err(ContractViolation::BindingMismatch {
                field: "grounding_handoff",
                reason: "manifest or ledger task, scope, or fence drift".into(),
            });
        }
        let expected_ids: BTreeSet<_> = self
            .input
            .claims
            .iter()
            .map(|claim| claim.claim_id.clone())
            .collect();
        if expected_ids != self.ledger.expected_claim_ids {
            return Err(ContractViolation::BindingMismatch {
                field: "claim_denominator",
                reason: "ledger denominator must equal retained material claim identities".into(),
            });
        }
        let expected_subclaims: std::collections::BTreeMap<_, _> = self
            .input
            .claims
            .iter()
            .map(|claim| (claim.claim_id.clone(), claim.subclaim_ids.clone()))
            .collect();
        if expected_subclaims != self.ledger.expected_subclaim_ids {
            return Err(ContractViolation::BindingMismatch {
                field: "subclaim_denominator",
                reason: "ledger subclaim denominator must equal retained claim subclaims".into(),
            });
        }
        let expected_nonmaterial: BTreeSet<_> = self
            .input
            .non_material_claims
            .iter()
            .map(|claim| claim.claim_id.clone())
            .collect();
        if expected_nonmaterial != self.ledger.nonmaterial_claim_ids {
            return Err(ContractViolation::BindingMismatch {
                field: "nonmaterial_denominator",
                reason: "ledger non-material denominator must equal retained residue".into(),
            });
        }
        for claim in &self.input.claims {
            let Some(record) = self.ledger.records.get(&claim.claim_id) else {
                continue;
            };
            if record.proposition_digest != claim.proposition_digest || record.kind != claim.kind {
                return Err(ContractViolation::BindingMismatch {
                    field: "grounding_handoff",
                    reason: "ledger record does not match retained claim identity".into(),
                });
            }
            if !self.policy.permitted_kinds.contains(&claim.kind) {
                return Err(ContractViolation::BindingMismatch {
                    field: "grounding_policy",
                    reason: "claim kind is not admitted by the retained policy".into(),
                });
            }
            if record.accepted_support.iter().any(|handle| {
                !self.manifest.contains(handle)
                    || !self.manifest.references[handle]
                        .assertions
                        .iter()
                        .any(|assertion| {
                            assertion.claim_id == claim.claim_id
                                && assertion.proposition_digest == claim.proposition_digest
                        })
            }) || record.accepted_counterevidence.iter().any(|handle| {
                !self.manifest.contains(handle)
                    || !self.manifest.references[handle]
                        .assertions
                        .iter()
                        .any(|assertion| {
                            assertion.claim_id == claim.claim_id
                                && assertion.proposition_digest == claim.proposition_digest
                        })
            }) {
                return Err(ContractViolation::BindingMismatch {
                    field: "grounding_handoff",
                    reason: "accepted evidence must resolve in the live manifest".into(),
                });
            }
            let witness_handles = record
                .accepted_support
                .iter()
                .chain(record.accepted_counterevidence.iter());
            for handle in witness_handles {
                let reference = self.manifest.references.get(handle).ok_or(
                    ContractViolation::BindingMismatch {
                        field: "grounding_assertion",
                        reason: "accepted witness handle is absent from the manifest".into(),
                    },
                )?;
                let witness_ids = record.witness_assertions.get(handle).ok_or(
                    ContractViolation::BindingMismatch {
                        field: "grounding_assertion",
                        reason: "accepted witness has no assertion identity".into(),
                    },
                )?;
                if !reference.assertions.iter().any(|assertion| {
                    witness_ids.contains(&assertion.assertion_id)
                        && assertion.claim_id == claim.claim_id
                        && assertion.proposition_digest == claim.proposition_digest
                        && assertion.precision.kind() == claim.kind
                        && (record.component_outcomes.is_empty()
                            || record.component_outcomes.contains_key(&assertion.component))
                }) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "grounding_assertion",
                        reason: "accepted witness lacks a matching typed assertion".into(),
                    });
                }
            }
            if record
                .coverage_denominator_ids
                .iter()
                .any(|id| !self.manifest.coverage_denominators.contains_key(id))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "grounding_coverage",
                    reason: "claim coverage references must resolve in the retained manifest"
                        .into(),
                });
            }
        }
        if let Some(screen) = &self.screen {
            screen.validate()?;
        }
        if self.input.screen != self.screen {
            return Err(ContractViolation::BindingMismatch {
                field: "screen",
                reason: "screen identity must be retained unchanged across the handoff".into(),
            });
        }
        Ok(())
    }
}

fn check_text(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    crate::error::check_text(value, field, 4_096)
}
fn check_digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if crate::error::is_hex64_lower(value) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field,
            reason: "expected lowercase SHA-256 digest".into(),
        })
    }
}

fn add_bytes(
    total: &mut usize,
    amount: usize,
    field: &'static str,
) -> Result<(), ContractViolation> {
    *total = total.checked_add(amount).ok_or(ContractViolation::Budget {
        dimension: field,
        reason: "cumulative preflight overflow".into(),
    })?;
    if *total > MAX_HANDOFF_BYTES {
        return Err(ContractViolation::Budget {
            dimension: field,
            reason: "retained structured input exceeds the contract ceiling".into(),
        });
    }
    Ok(())
}
