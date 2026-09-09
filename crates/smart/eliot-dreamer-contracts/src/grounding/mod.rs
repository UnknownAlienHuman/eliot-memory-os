//! Versioned, lossless Dreamer grounding handoff contracts.
//!
//! This namespace is deliberately separate from the v1 draft/A05 surface. It
//! carries structured claims, an immutable reference manifest, and a complete
//! per-claim ledger. It performs shape and identity checks only; grounding and
//! coverage inference belong to A-14b (#602).

#![forbid(unsafe_code)]

pub use eliot_contracts::{ArtifactId, StateFence, TaskId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    AbsenceClaim, CausalClaim, CoverageDenominator, CoverageReceipt, DisclosureClass,
    EvidenceGrade, GradeAssignment, PositionAssertability, PrivacyHandling, ProvenanceClosure,
    SourceAssurance, SourceLineage, SupportRecord, SupportResult, TemporalRecord,
};
pub use ledger::{
    AssertionWitness, ClaimGroundingLedger, ClaimGroundingRecord, GroundingDisposition,
};
pub use manifest::{AllowedReferenceManifest, AuthorizedReference};
pub use policy::GroundingPolicy;

/// Wire revision for the structured grounding handoff.
pub const GROUNDING_SCHEMA_VERSION: u32 = 2;
pub const MAX_CLAIMS: usize = 4_096;
const MAX_HANDOFF_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptIdentity {
    pub attempt_id: String,
    pub attempt_number: u32,
    pub maximum_attempts: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteIdentity {
    pub provider: String,
    pub model: String,
    pub route_revision: String,
    pub fingerprint: String,
}

pub fn requester_digest(job: &DreamJobInput) -> Result<String, ContractViolation> {
    encoding::digest(&job.requester)
}

pub fn budget_digest(job: &DreamJobInput) -> Result<String, ContractViolation> {
    encoding::digest(&job.budget)
}

pub fn bundle_digest(bundle: &DreamInputBundle) -> Result<String, ContractViolation> {
    encoding::digest(bundle)
}

pub fn route_fingerprint(route: &RouteIdentity) -> Result<String, ContractViolation> {
    #[derive(Serialize)]
    struct RoutePreimage<'a> {
        provider: &'a str,
        model: &'a str,
        route_revision: &'a str,
    }
    encoding::digest(&RoutePreimage {
        provider: &route.provider,
        model: &route.model,
        route_revision: &route.route_revision,
    })
}

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
    pub attempt: AttemptIdentity,
    pub route: RouteIdentity,
    pub budget_digest: String,
    pub bundle_digest: String,
    pub input_manifest_digest: String,
    pub claims: Vec<MaterialClaim>,
    pub non_material_claims: Vec<NonMaterialClaim>,
    pub screen: Option<ScreenBinding>,
    pub draft_digest: String,
}

impl ModelDraft {
    #[allow(clippy::items_after_statements)]
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        encoding::preflight(self)?;
        let claims: BTreeMap<_, _> = self
            .claims
            .iter()
            .map(|claim| (claim.claim_id.as_str(), claim))
            .collect();
        let non_material_claims: BTreeMap<_, _> = self
            .non_material_claims
            .iter()
            .map(|claim| (claim.claim_id.as_str(), claim))
            .collect();
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            job_id: &'a str,
            task_id: &'a TaskId,
            scope_id: &'a str,
            state_fence: &'a StateFence,
            job: &'a DreamJobInput,
            bundle: &'a DreamInputBundle,
            raw_output_digest: &'a str,
            requester_digest: &'a str,
            attempt: &'a AttemptIdentity,
            route: &'a RouteIdentity,
            budget_digest: &'a str,
            bundle_digest: &'a str,
            input_manifest_digest: &'a str,
            claims: BTreeMap<&'a str, &'a MaterialClaim>,
            non_material_claims: BTreeMap<&'a str, &'a NonMaterialClaim>,
            screen: &'a Option<ScreenBinding>,
        }
        encoding::digest(&Preimage {
            schema_version: self.schema_version,
            job_id: &self.job_id,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            state_fence: &self.state_fence,
            job: &self.job,
            bundle: &self.bundle,
            raw_output_digest: &self.raw_output_digest,
            requester_digest: &self.requester_digest,
            attempt: &self.attempt,
            route: &self.route,
            budget_digest: &self.budget_digest,
            bundle_digest: &self.bundle_digest,
            input_manifest_digest: &self.input_manifest_digest,
            claims,
            non_material_claims,
            screen: &self.screen,
        })
    }
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ContractViolation> {
        crate::error::check_schema_version(self.schema_version, GROUNDING_SCHEMA_VERSION)?;
        check_text(&self.job_id, "job_id")?;
        check_text(&self.scope_id, "scope_id")?;
        check_digest(&self.raw_output_digest, "raw_output_digest")?;
        check_digest(&self.requester_digest, "requester_digest")?;
        check_digest(&self.budget_digest, "budget_digest")?;
        check_digest(&self.bundle_digest, "bundle_digest")?;
        check_digest(&self.input_manifest_digest, "input_manifest_digest")?;
        check_digest(&self.draft_digest, "draft_digest")?;
        crate::error::check_fence(&self.state_fence)?;
        encoding::preflight(self)?;
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
        if self.job_id != self.job.canonical_id()
            || self.bundle.job_id != self.job.canonical_id()
            || encoding::digest(&self.bundle)? != self.bundle_digest
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
        check_attempt(&self.attempt, &self.job)?;
        check_route(&self.route)?;
        if self.requester_digest != requester_digest(&self.job)?
            || self.budget_digest != budget_digest(&self.job)?
        {
            return Err(ContractViolation::BindingMismatch {
                field: "job_digests",
                reason: "requester and budget digests must match retained job values".into(),
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
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            job_id: &'a str,
            task_id: &'a TaskId,
            scope_id: &'a str,
            state_fence: &'a StateFence,
            draft_digest: &'a str,
            manifest_digest: &'a str,
            policy_digest: &'a str,
            input: &'a ModelDraft,
            manifest: &'a AllowedReferenceManifest,
            policy: &'a GroundingPolicy,
            ledger: &'a ClaimGroundingLedger,
            screen: &'a Option<ScreenBinding>,
        }
        encoding::digest(&Preimage {
            schema_version: self.schema_version,
            job_id: &self.job_id,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            state_fence: &self.state_fence,
            draft_digest: &self.draft_digest,
            manifest_digest: &self.manifest_digest,
            policy_digest: &self.policy_digest,
            input: &self.input,
            manifest: &self.manifest,
            policy: &self.policy,
            ledger: &self.ledger,
            screen: &self.screen,
        })
    }
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ContractViolation> {
        let retained_bytes = encoding::preflight(self)?;
        let output_ceiling = usize::try_from(self.policy.max_output_bytes).map_err(|_| {
            ContractViolation::Budget {
                dimension: "grounding_output_bytes",
                reason: "policy output ceiling does not fit this platform".into(),
            }
        })?;
        if output_ceiling == 0 || retained_bytes > MAX_HANDOFF_BYTES.min(output_ceiling) {
            return Err(ContractViolation::Budget {
                dimension: "grounding_output_bytes",
                reason: "retained grounded output exceeds the intrinsic or policy ceiling".into(),
            });
        }
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
        if encoding::preflight(self)?
            > usize::try_from(self.policy.max_output_bytes).map_err(|_| {
                ContractViolation::Budget {
                    dimension: "grounding_output_bytes",
                    reason: "policy output ceiling does not fit this platform".into(),
                }
            })?
        {
            return Err(ContractViolation::Budget {
                dimension: "grounding_output_bytes",
                reason: "retained grounded output exceeds the caller policy cap".into(),
            });
        }
        if self.policy.max_output_bytes > self.input.job.budget.output_bytes.unwrap_or(0) {
            return Err(ContractViolation::Budget {
                dimension: "grounding_output_bytes",
                reason: "policy output ceiling exceeds the retained job budget".into(),
            });
        }
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
            || self.ledger.operation_id != self.input.job.operation_id
            || self.ledger.run_id != self.manifest.run_id
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
        let claim_ids: BTreeSet<_> = self
            .input
            .claims
            .iter()
            .map(|c| c.claim_id.as_str())
            .collect();
        for claim in &self.input.claims {
            for subclaim in &claim.subclaim_ids {
                if subclaim == &claim.claim_id || !claim_ids.contains(subclaim.as_str()) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "subclaim_denominator",
                        reason: "subclaim must resolve to a distinct material claim in this draft"
                            .into(),
                    });
                }
            }
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
        if self.input.claims.len() > self.policy.max_claims as usize
            || self.input.claims.iter().any(|claim| {
                claim.subclaim_ids.len() > self.policy.max_subclaims_per_claim as usize
                    || claim.proposed_support.len()
                        > self.policy.max_support_handles_per_claim as usize
                    || claim.proposed_counterevidence.len()
                        > self.policy.max_support_handles_per_claim as usize
            })
            || self.input.non_material_claims.iter().any(|claim| {
                !self
                    .policy
                    .permitted_nonmaterial_classes
                    .contains(&claim.category)
            })
        {
            return Err(ContractViolation::Budget {
                dimension: "grounding_policy",
                reason: "retained claims or non-material classes exceed the policy".into(),
            });
        }
        for claim in &self.input.claims {
            let Some(record) = self.ledger.records.get(&claim.claim_id) else {
                continue;
            };
            if record.proposition_digest != claim.proposition_digest
                || record.kind != claim.kind
                || record.proposed_support != claim.proposed_support
                || record.proposed_counterevidence != claim.proposed_counterevidence
            {
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
            if record.proposed_support.len() > self.policy.max_support_handles_per_claim as usize
                || record.proposed_counterevidence.len()
                    > self.policy.max_support_handles_per_claim as usize
                || record.component_outcomes.keys().collect::<BTreeSet<_>>()
                    != claim.component_digests.keys().collect::<BTreeSet<_>>()
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "grounding_policy",
                    reason: "retained claim exceeds support or component denominator".into(),
                });
            }
            for handle in record
                .accepted_support
                .iter()
                .chain(record.accepted_counterevidence.iter())
            {
                if !self.manifest.contains(handle) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "grounding_handoff",
                        reason: "accepted evidence must resolve in the live manifest".into(),
                    });
                }
                let witness = record
                    .witnesses
                    .iter()
                    .find(|w| &w.handle == handle && w.claim_id == claim.claim_id)
                    .ok_or(ContractViolation::BindingMismatch {
                        field: "grounding_assertion",
                        reason: "every accepted handle requires an explicit witness".into(),
                    })?;
                let reference = &self.manifest.references[handle];
                let assertion = reference
                    .assertions
                    .iter()
                    .find(|a| a.assertion_id == witness.assertion_id)
                    .ok_or(ContractViolation::BindingMismatch {
                        field: "grounding_assertion",
                        reason: "witness assertion ID is unresolved".into(),
                    })?;
                if assertion.proposition_digest != claim.proposition_digest
                    || assertion.precision.kind() != claim.kind
                    || assertion.component != witness.component
                    || !(claim.component_digests.contains_key(&witness.component)
                        || witness.component.is_empty() && claim.component_digests.is_empty())
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "grounding_assertion",
                        reason: "accepted witness lacks a matching typed component assertion"
                            .into(),
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

fn check_attempt(attempt: &AttemptIdentity, job: &DreamJobInput) -> Result<(), ContractViolation> {
    check_text(&attempt.attempt_id, "attempt_id")?;
    if attempt.attempt_number == 0
        || attempt.attempt_number > attempt.maximum_attempts
        || job.budget.attempts != Some(u64::from(attempt.maximum_attempts))
    {
        return Err(ContractViolation::BindingMismatch {
            field: "attempt",
            reason: "attempt identity must bind the job attempts budget".into(),
        });
    }
    Ok(())
}

fn check_route(route: &RouteIdentity) -> Result<(), ContractViolation> {
    check_text(&route.provider, "route.provider")?;
    check_text(&route.model, "route.model")?;
    check_text(&route.route_revision, "route.route_revision")?;
    check_digest(&route.fingerprint, "route.fingerprint")?;
    if route.fingerprint != route_fingerprint(route)? {
        return Err(ContractViolation::BindingMismatch {
            field: "route.fingerprint",
            reason: "route fingerprint does not match retained route identity".into(),
        });
    }
    Ok(())
}
