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
    TypedEvidenceAssertion, component_content_digest, proposition_content_digest,
};
pub use eliot_epistemic_contracts::{
    AbsenceClaim, CausalClaim, CoverageDenominator, CoverageReceipt, DisclosureClass,
    EvidenceGrade, GradeAssignment, PositionAssertability, PrivacyHandling, PropositionId,
    ProvenanceClosure, SourceAssurance, SourceLineage, SupportRecord, SupportResult,
    TemporalRecord,
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
        crate::error::check_vec_bound(self.claims.len(), MAX_CLAIMS, "claims")?;
        crate::error::check_vec_bound(
            self.non_material_claims.len(),
            MAX_CLAIMS,
            "non_material_claims",
        )?;
        let mut claims: Vec<_> = self.claims.iter().collect();
        claims.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
        if claims
            .windows(2)
            .any(|pair| pair[0].claim_id == pair[1].claim_id)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "claims",
                reason: "duplicate claim identity cannot be normalized".into(),
            });
        }
        let mut non_material_claims: Vec<_> = self.non_material_claims.iter().collect();
        non_material_claims.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
        if non_material_claims
            .windows(2)
            .any(|pair| pair[0].claim_id == pair[1].claim_id)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "non_material_claims",
                reason: "duplicate residue identity cannot be normalized".into(),
            });
        }
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
            claims: Vec<&'a MaterialClaim>,
            non_material_claims: Vec<&'a NonMaterialClaim>,
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
        validate_subclaim_forest(&self.claims)?;
        for claim in &self.claims {
            claim.validate()?;
        }
        for claim in &self.non_material_claims {
            claim.validate()?;
        }
        if let Some(screen) = &self.screen {
            screen.validate()?;
            check_screen_context(screen, &self.task_id, &self.scope_id, &self.state_fence)?;
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
    #[allow(clippy::too_many_lines, clippy::items_after_statements)]
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        encoding::preflight(self)?;
        crate::error::check_vec_bound(self.input.claims.len(), MAX_CLAIMS, "claims")?;
        crate::error::check_vec_bound(
            self.input.non_material_claims.len(),
            MAX_CLAIMS,
            "non_material_claims",
        )?;
        crate::error::check_vec_bound(
            self.manifest.references.len(),
            manifest::MAX_REFERENCES,
            "references",
        )?;
        let mut claims: Vec<_> = self.input.claims.iter().collect();
        claims.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
        if claims
            .windows(2)
            .any(|pair| pair[0].claim_id == pair[1].claim_id)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "claims",
                reason: "duplicate claim identity cannot be normalized".into(),
            });
        }
        let mut residues: Vec<_> = self.input.non_material_claims.iter().collect();
        residues.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
        if residues
            .windows(2)
            .any(|pair| pair[0].claim_id == pair[1].claim_id)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "non_material_claims",
                reason: "duplicate residue identity cannot be normalized".into(),
            });
        }
        let mut normalized = self.clone();
        for reference in normalized.manifest.references.values_mut() {
            reference
                .assertions
                .sort_by(|left, right| left.assertion_id.cmp(&right.assertion_id));
        }
        for record in normalized.ledger.records.values_mut() {
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
        struct InputView<'a> {
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
            claims: Vec<&'a MaterialClaim>,
            non_material_claims: Vec<&'a NonMaterialClaim>,
            screen: &'a Option<ScreenBinding>,
            draft_digest: &'a str,
        }
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
            input: InputView<'a>,
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
            input: InputView {
                schema_version: self.input.schema_version,
                job_id: &self.input.job_id,
                task_id: &self.input.task_id,
                scope_id: &self.input.scope_id,
                state_fence: &self.input.state_fence,
                job: &self.input.job,
                bundle: &self.input.bundle,
                raw_output_digest: &self.input.raw_output_digest,
                requester_digest: &self.input.requester_digest,
                attempt: &self.input.attempt,
                route: &self.input.route,
                budget_digest: &self.input.budget_digest,
                bundle_digest: &self.input.bundle_digest,
                input_manifest_digest: &self.input.input_manifest_digest,
                claims,
                non_material_claims: residues,
                screen: &self.input.screen,
                draft_digest: &self.input.draft_digest,
            },
            manifest: &normalized.manifest,
            policy: &normalized.policy,
            ledger: &normalized.ledger,
            screen: &self.screen,
        })
    }
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validate_grounded_preflight_context(self)?;
        validate_grounded_denominators_policy(self)?;
        validate_grounded_records(self)?;
        validate_grounded_screens(self)?;
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

fn check_screen_context(
    screen: &ScreenBinding,
    task: &TaskId,
    scope: &str,
    fence: &StateFence,
) -> Result<(), ContractViolation> {
    if screen.task_id != task.to_string()
        || screen.scope_id != scope
        || screen.state_fence != *fence
    {
        return Err(ContractViolation::BindingMismatch {
            field: "screen",
            reason: "screen task, scope, and fence differ from the handoff context".into(),
        });
    }
    Ok(())
}

fn validate_subclaim_forest(claims: &[MaterialClaim]) -> Result<(), ContractViolation> {
    let ids: BTreeSet<_> = claims.iter().map(|claim| claim.claim_id.as_str()).collect();
    let mut owners = BTreeMap::new();
    for claim in claims {
        for child in &claim.subclaim_ids {
            if child == &claim.claim_id
                || !ids.contains(child.as_str())
                || owners.insert(child, &claim.claim_id).is_some()
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "subclaim_ids",
                    reason: "subclaims must form a resolved single-owner forest".into(),
                });
            }
        }
    }
    let by_id: BTreeMap<_, _> = claims
        .iter()
        .map(|claim| (claim.claim_id.as_str(), claim))
        .collect();
    let mut active = BTreeSet::new();
    let mut done = BTreeSet::new();
    for id in ids {
        if done.contains(id) {
            continue;
        }
        let mut stack = vec![(id, false)];
        while let Some((current, exiting)) = stack.pop() {
            if exiting {
                active.remove(current);
                done.insert(current.to_owned());
                continue;
            }
            if done.contains(current) {
                continue;
            }
            if !active.insert(current.to_owned()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "subclaim_ids",
                    reason: "subclaim cycle detected".into(),
                });
            }
            stack.push((current, true));
            if let Some(claim) = by_id.get(current) {
                for child in claim.subclaim_ids.iter().rev() {
                    if active.contains(child) {
                        return Err(ContractViolation::BindingMismatch {
                            field: "subclaim_ids",
                            reason: "subclaim cycle detected".into(),
                        });
                    }
                    stack.push((child.as_str(), false));
                }
            }
        }
    }
    Ok(())
}

fn validate_grounded_preflight_context(
    self_: &GroundedDreamDraft,
) -> Result<(), ContractViolation> {
    // Phase 1: bounded retained-value preflight and policy ceiling.
    let retained_bytes = encoding::preflight(self_)?;
    let output_ceiling =
        usize::try_from(self_.policy.max_output_bytes).map_err(|_| ContractViolation::Budget {
            dimension: "grounding_output_bytes",
            reason: "policy output ceiling does not fit this platform".into(),
        })?;
    if output_ceiling == 0 || retained_bytes > MAX_HANDOFF_BYTES.min(output_ceiling) {
        return Err(ContractViolation::Budget {
            dimension: "grounding_output_bytes",
            reason: "retained grounded output exceeds the intrinsic or policy ceiling".into(),
        });
    }
    // Phase 2: retained job, manifest, ledger, and fence context.
    crate::error::check_schema_version(self_.schema_version, GROUNDING_SCHEMA_VERSION)?;
    check_text(&self_.job_id, "job_id")?;
    check_text(&self_.scope_id, "scope_id")?;
    check_digest(&self_.draft_digest, "draft_digest")?;
    check_digest(&self_.manifest_digest, "manifest_digest")?;
    check_digest(&self_.policy_digest, "policy_digest")?;
    check_digest(&self_.output_digest, "output_digest")?;
    if self_.computed_digest()? != self_.output_digest {
        return Err(ContractViolation::BindingMismatch {
            field: "output_digest",
            reason: "grounded draft preimage digest mismatch".into(),
        });
    }
    crate::error::check_fence(&self_.state_fence)?;
    self_.input.validate()?;
    self_.manifest.validate()?;
    self_.policy.validate()?;
    self_.ledger.validate()?;
    if encoding::preflight(self_)?
        > usize::try_from(self_.policy.max_output_bytes).map_err(|_| ContractViolation::Budget {
            dimension: "grounding_output_bytes",
            reason: "policy output ceiling does not fit this platform".into(),
        })?
    {
        return Err(ContractViolation::Budget {
            dimension: "grounding_output_bytes",
            reason: "retained grounded output exceeds the caller policy cap".into(),
        });
    }
    if self_.policy.max_output_bytes > self_.input.job.budget.output_bytes.unwrap_or(0) {
        return Err(ContractViolation::Budget {
            dimension: "grounding_output_bytes",
            reason: "policy output ceiling exceeds the retained job budget".into(),
        });
    }
    if self_.input.draft_digest != self_.draft_digest
        || self_.manifest.digest != self_.manifest_digest
        || self_.policy.digest != self_.policy_digest
        || self_.ledger.draft_digest != self_.draft_digest
        || self_.ledger.manifest_digest != self_.manifest_digest
        || self_.ledger.policy_digest != self_.policy_digest
    {
        return Err(ContractViolation::BindingMismatch {
            field: "grounding_handoff",
            reason: "retained preimages and ledger digests must agree".into(),
        });
    }
    if self_.input.task_id != self_.task_id
        || self_.input.job_id != self_.job_id
        || self_.input.input_manifest_digest != self_.manifest_digest
        || self_.input.scope_id != self_.scope_id
        || self_.input.state_fence != self_.state_fence
    {
        return Err(ContractViolation::BindingMismatch {
            field: "grounding_handoff",
            reason: "task, scope, or fence drift".into(),
        });
    }
    if self_.manifest.task_id != self_.task_id
        || self_.manifest.scope_id != self_.scope_id
        || self_.manifest.state_fence != self_.state_fence
        || self_.ledger.task_id != self_.task_id
        || self_.ledger.scope_id != self_.scope_id
        || self_.ledger.state_fence != self_.state_fence
        || self_.ledger.operation_id != self_.input.job.operation_id
        || self_.ledger.run_id != self_.manifest.run_id
        || self_.ledger.job_id != self_.job_id
    {
        return Err(ContractViolation::BindingMismatch {
            field: "grounding_handoff",
            reason: "manifest or ledger task, scope, or fence drift".into(),
        });
    }
    Ok(())
}

fn validate_grounded_denominators_policy(
    self_: &GroundedDreamDraft,
) -> Result<(), ContractViolation> {
    // Phase 3: exact material, subclaim, and coverage denominators.
    let expected_ids: BTreeSet<_> = self_
        .input
        .claims
        .iter()
        .map(|claim| claim.claim_id.clone())
        .collect();
    if expected_ids != self_.ledger.expected_claim_ids {
        return Err(ContractViolation::BindingMismatch {
            field: "claim_denominator",
            reason: "ledger denominator must equal retained material claim identities".into(),
        });
    }
    let expected_subclaims: std::collections::BTreeMap<_, _> = self_
        .input
        .claims
        .iter()
        .map(|claim| (claim.claim_id.clone(), claim.subclaim_ids.clone()))
        .collect();
    if expected_subclaims != self_.ledger.expected_subclaim_ids {
        return Err(ContractViolation::BindingMismatch {
            field: "subclaim_denominator",
            reason: "ledger subclaim denominator must equal retained claim subclaims".into(),
        });
    }
    validate_subclaim_forest(&self_.input.claims)?;
    Ok(())
}

fn validate_grounded_records(self_: &GroundedDreamDraft) -> Result<(), ContractViolation> {
    // Phase 4: per-record witness and typed relation closure.
    for claim in &self_.input.claims {
        let Some(record) = self_.ledger.records.get(&claim.claim_id) else {
            continue;
        };
        validate_grounded_record(self_, claim, record)?;
    }
    Ok(())
}

fn validate_grounded_record(
    self_: &GroundedDreamDraft,
    claim: &MaterialClaim,
    record: &ClaimGroundingRecord,
) -> Result<(), ContractViolation> {
    if record.proposition_digest != claim.proposition_digest
        || record.proposition != claim.proposition
        || record.kind != claim.kind
        || record.proposed_support != claim.proposed_support
        || record.proposed_counterevidence != claim.proposed_counterevidence
    {
        return Err(ContractViolation::BindingMismatch {
            field: "grounding_handoff",
            reason: "ledger record does not match retained claim identity".into(),
        });
    }
    if !self_.policy.permitted_kinds.contains(&claim.kind) {
        return Err(ContractViolation::BindingMismatch {
            field: "grounding_policy",
            reason: "claim kind is not admitted by the retained policy".into(),
        });
    }
    if record.proposed_support.len() > self_.policy.max_support_handles_per_claim as usize
        || record.proposed_counterevidence.len()
            > self_.policy.max_support_handles_per_claim as usize
        || record.component_outcomes.keys().collect::<BTreeSet<_>>()
            != claim.component_digests.keys().collect::<BTreeSet<_>>()
    {
        return Err(ContractViolation::BindingMismatch {
            field: "grounding_policy",
            reason: "retained claim exceeds support or component denominator".into(),
        });
    }
    for witness in &record.witnesses {
        if witness.claim_id != claim.claim_id
            || (!record.accepted_support.contains(&witness.handle)
                && !record.accepted_counterevidence.contains(&witness.handle))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "grounding_assertion",
                reason: "witness tuple is not owned by the exact record partition".into(),
            });
        }
        let reference = self_.manifest.references.get(&witness.handle).ok_or(
            ContractViolation::BindingMismatch {
                field: "grounding_assertion",
                reason: "witness handle is absent from the manifest".into(),
            },
        )?;
        let assertion = reference
            .assertions
            .iter()
            .find(|a| a.assertion_id == witness.assertion_id)
            .ok_or(ContractViolation::BindingMismatch {
                field: "grounding_assertion",
                reason: "witness assertion ID is unresolved".into(),
            })?;
        if assertion.proposition != claim.proposition
            || assertion.proposition_digest != claim.proposition_digest
            || assertion.precision.kind() != claim.kind
            || assertion.component != witness.component
            || !claim.component_digests.contains_key(&witness.component)
            || (matches!(
                record.component_outcomes.get(&witness.component),
                Some(SupportResult::Supported | SupportResult::Contradicted)
            ) && assertion.support.is_none())
        {
            return Err(ContractViolation::BindingMismatch {
                field: "grounding_assertion",
                reason: "witness tuple does not match claim proposition/component".into(),
            });
        }
    }
    for (component, outcome) in &record.component_outcomes {
        if matches!(
            outcome,
            SupportResult::Supported | SupportResult::Contradicted
        ) && !record.witnesses.iter().any(|w| {
            if &w.component != component {
                return false;
            }
            self_
                .manifest
                .references
                .get(&w.handle)
                .and_then(|reference| {
                    reference
                        .assertions
                        .iter()
                        .find(|assertion| assertion.assertion_id == w.assertion_id)
                })
                .and_then(|assertion| assertion.support.as_ref())
                .is_some_and(|support| support.result == *outcome)
        }) {
            return Err(ContractViolation::BindingMismatch {
                field: "grounding_assertion",
                reason: "supported or contradicted component lacks a relation witness".into(),
            });
        }
    }
    for handle in record
        .accepted_support
        .iter()
        .chain(record.accepted_counterevidence.iter())
    {
        if !self_.manifest.contains(handle) {
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
        let reference = &self_.manifest.references[handle];
        let assertion = reference
            .assertions
            .iter()
            .find(|a| a.assertion_id == witness.assertion_id)
            .ok_or(ContractViolation::BindingMismatch {
                field: "grounding_assertion",
                reason: "witness assertion ID is unresolved".into(),
            })?;
        if assertion.proposition != claim.proposition
            || assertion.proposition_digest != claim.proposition_digest
            || assertion.precision.kind() != claim.kind
            || assertion.component != witness.component
            || !(claim.component_digests.contains_key(&witness.component)
                || witness.component.is_empty() && claim.component_digests.is_empty())
        {
            return Err(ContractViolation::BindingMismatch {
                field: "grounding_assertion",
                reason: "accepted witness lacks a matching typed component assertion".into(),
            });
        }
    }
    if record
        .coverage_denominator_ids
        .iter()
        .any(|id| !self_.manifest.coverage_denominators.contains_key(id))
    {
        return Err(ContractViolation::BindingMismatch {
            field: "grounding_coverage",
            reason: "claim coverage references must resolve in the retained manifest".into(),
        });
    }
    Ok(())
}

fn validate_grounded_screens(self_: &GroundedDreamDraft) -> Result<(), ContractViolation> {
    // Phase 5: carried screen identity; eligibility remains owner logic.
    if let Some(screen) = &self_.screen {
        screen.validate()?;
        check_screen_context(screen, &self_.task_id, &self_.scope_id, &self_.state_fence)?;
    }
    if self_.input.screen != self_.screen {
        return Err(ContractViolation::BindingMismatch {
            field: "screen",
            reason: "screen identity must be retained unchanged across the handoff".into(),
        });
    }
    for claim in &self_.input.claims {
        if let Some(binding) = &claim.screen_target {
            binding.validate_for_context(&self_.task_id, &self_.scope_id, &self_.state_fence)?;
        }
    }
    Ok(())
}
