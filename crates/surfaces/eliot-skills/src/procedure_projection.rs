//! Provider-neutral projection of an accepted procedure into inert package candidates.
//!
//! This module deliberately accepts a governed projection rather than a Dreamer
//! candidate. It preserves the evidence and fence that made the procedure
//! acceptable, while leaving admission, materialization, installation, and
//! execution to their existing owners.

use std::collections::BTreeSet;

use eliot_receipts::{ProofCeiling, ReceiptDisposition, ReceiptKind, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    HostProfile, PackageDigests, ReceiptClaim, SkillBehavior, SkillContractError,
    VersionedRequirement, canonical_digest,
};

/// Current wire revision for the governed-procedure projection.
pub const GOVERNED_PROCEDURE_PROJECTION_SCHEMA_VERSION: &str =
    "eliot.governed-procedure-portable-candidate.v1";
/// Source marker for candidates created by this projection.
pub const GENERATED_CANDIDATE_SOURCE: &str = "ELIOT_GENERATED_CANDIDATE";
/// Lifecycle marker for a candidate that has not entered Skill admission.
pub const CANDIDATE_LIFECYCLE_STATE: &str = "QUARANTINED";

/// A failure in the provider-neutral procedure projection boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProcedureProjectionError {
    /// A required value is absent or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    /// The accepted receipt is not the receipt for this exact projection.
    #[error("accepted procedure receipt binding mismatch: {field}")]
    ReceiptBindingMismatch { field: &'static str },
    /// The projection digest does not match its canonical fields.
    #[error("governed procedure identity digest mismatch")]
    IdentityMismatch,
    /// A projection state cannot be mapped into a reusable candidate.
    #[error("procedure is not accepted: {0:?}")]
    NotAccepted(ProcedureState),
    /// A target appears more than once, making its disposition ambiguous.
    #[error("duplicate target identity")]
    DuplicateTarget,
    /// The generated result would claim an effect or lifecycle transition.
    #[error("candidate-only boundary violated: {field}")]
    CandidateOnlyViolation { field: &'static str },
    /// Canonical serialization failed.
    #[error("procedure projection canonicalization failed: {0}")]
    Canonicalization(String),
    /// An existing contract rejected a reused value.
    #[error("Skill contract: {0}")]
    SkillContract(#[from] SkillContractError),
}

fn text(value: &str, field: &'static str) -> Result<(), ProcedureProjectionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ProcedureProjectionError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        })
    } else {
        Ok(())
    }
}

fn digest(value: &str, field: &'static str) -> Result<(), ProcedureProjectionError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ProcedureProjectionError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

fn list(values: &[String], field: &'static str) -> Result<(), ProcedureProjectionError> {
    if values.is_empty() {
        return Err(ProcedureProjectionError::InvalidField {
            field,
            reason: "must contain at least one entry",
        });
    }
    for value in values {
        text(value, field)?;
    }
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        return Err(ProcedureProjectionError::InvalidField {
            field,
            reason: "must not contain duplicate entries",
        });
    }
    Ok(())
}

fn requirement(
    value: &VersionedRequirement,
    field: &'static str,
) -> Result<(), ProcedureProjectionError> {
    text(&value.name, field)?;
    text(&value.version, field)
}

fn requirements(
    values: &[VersionedRequirement],
    field: &'static str,
) -> Result<(), ProcedureProjectionError> {
    if values.is_empty() {
        return Err(ProcedureProjectionError::InvalidField {
            field,
            reason: "must contain at least one exact requirement",
        });
    }
    let mut seen = BTreeSet::new();
    for value in values {
        requirement(value, field)?;
        if !seen.insert((&value.name, &value.version)) {
            return Err(ProcedureProjectionError::InvalidField {
                field,
                reason: "must not contain duplicate exact requirements",
            });
        }
    }
    Ok(())
}

/// Lifecycle state supplied by the accepted-procedure owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcedureState {
    Accepted,
    Stale,
    Superseded,
    Conflicted,
    Quarantined,
    Revoked,
}

/// The procedure's reusable, host-neutral mechanics.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureDefinition {
    pub name: String,
    pub purpose: String,
    pub trigger: String,
    pub action: String,
    pub applies_when: Vec<String>,
    pub where_not_apply: Vec<String>,
    pub required_inputs: Vec<String>,
    pub ordered_steps: Vec<String>,
    pub expected_outputs: Vec<String>,
    pub stop_conditions: Vec<String>,
    pub required_writebacks: Vec<String>,
    pub escalation: String,
    pub challenge: String,
    pub rollback_or_recovery: String,
    pub required_tools: Vec<VersionedRequirement>,
    pub required_capabilities: Vec<VersionedRequirement>,
}

impl ProcedureDefinition {
    fn validate(&self) -> Result<(), ProcedureProjectionError> {
        for (value, field) in [
            (&self.name, "procedure.name"),
            (&self.purpose, "procedure.purpose"),
            (&self.trigger, "procedure.trigger"),
            (&self.action, "procedure.action"),
            (&self.escalation, "procedure.escalation"),
            (&self.challenge, "procedure.challenge"),
            (&self.rollback_or_recovery, "procedure.rollback_or_recovery"),
        ] {
            text(value, field)?;
        }
        for (values, field) in [
            (&self.applies_when, "procedure.applies_when"),
            (&self.where_not_apply, "procedure.where_not_apply"),
            (&self.required_inputs, "procedure.required_inputs"),
            (&self.ordered_steps, "procedure.ordered_steps"),
            (&self.expected_outputs, "procedure.expected_outputs"),
            (&self.stop_conditions, "procedure.stop_conditions"),
            (&self.required_writebacks, "procedure.required_writebacks"),
        ] {
            list(values, field)?;
        }
        if self.action.lines().count() != 1 {
            return Err(ProcedureProjectionError::InvalidField {
                field: "procedure.action",
                reason: "must contain exactly one action line",
            });
        }
        requirements(&self.required_tools, "procedure.required_tools")?;
        requirements(
            &self.required_capabilities,
            "procedure.required_capabilities",
        )
    }

    fn behavior(&self) -> SkillBehavior {
        SkillBehavior {
            intent: self.purpose.clone(),
            trigger: self.trigger.clone(),
            action: self.action.clone(),
            applies_when: self.applies_when.clone(),
            where_not_apply: self.where_not_apply.clone(),
            required_outputs: self.expected_outputs.clone(),
            required_writebacks: self.required_writebacks.clone(),
            stop: self.stop_conditions.join("; "),
            escalation: self.escalation.clone(),
            challenge: self.challenge.clone(),
        }
    }
}

/// Evidence that makes applicability and transfer limits visible.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureEvidence {
    pub source_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub applicability_refs: Vec<String>,
    pub counterexample_refs: Vec<String>,
    pub negative_trigger_refs: Vec<String>,
    pub verifier_artifact_refs: Vec<String>,
    pub rollback_artifact_ref: String,
}

impl ProcedureEvidence {
    fn validate(&self) -> Result<(), ProcedureProjectionError> {
        for (values, field) in [
            (&self.source_refs, "evidence.source_refs"),
            (&self.receipt_refs, "evidence.receipt_refs"),
            (&self.applicability_refs, "evidence.applicability_refs"),
            (&self.counterexample_refs, "evidence.counterexample_refs"),
            (
                &self.negative_trigger_refs,
                "evidence.negative_trigger_refs",
            ),
            (
                &self.verifier_artifact_refs,
                "evidence.verifier_artifact_refs",
            ),
        ] {
            list(values, field)?;
        }
        text(
            &self.rollback_artifact_ref,
            "evidence.rollback_artifact_ref",
        )
    }
}

/// Safety, privacy, and disclosure closure owned by their respective systems.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyPrivacyDisclosure {
    pub safety_owner_ref: String,
    pub safety_evidence_refs: Vec<String>,
    pub privacy_owner_ref: String,
    pub privacy_evidence_refs: Vec<String>,
    pub disclosure_owner_ref: String,
    pub disclosure_evidence_refs: Vec<String>,
}

impl SafetyPrivacyDisclosure {
    fn validate(&self) -> Result<(), ProcedureProjectionError> {
        for (value, field) in [
            (&self.safety_owner_ref, "safety.owner_ref"),
            (&self.privacy_owner_ref, "privacy.owner_ref"),
            (&self.disclosure_owner_ref, "disclosure.owner_ref"),
        ] {
            text(value, field)?;
        }
        for (values, field) in [
            (&self.safety_evidence_refs, "safety.evidence_refs"),
            (&self.privacy_evidence_refs, "privacy.evidence_refs"),
            (&self.disclosure_evidence_refs, "disclosure.evidence_refs"),
        ] {
            list(values, field)?;
        }
        Ok(())
    }
}

/// Exact verifier declaration retained in the candidate; no verifier runs here.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureVerifier {
    pub verifier_ref: String,
    pub verifier_revision: String,
    pub artifact_refs: Vec<String>,
}

impl ProcedureVerifier {
    fn validate(&self, evidence: &ProcedureEvidence) -> Result<(), ProcedureProjectionError> {
        text(&self.verifier_ref, "verifier.verifier_ref")?;
        text(&self.verifier_revision, "verifier.verifier_revision")?;
        list(&self.artifact_refs, "verifier.artifact_refs")?;
        if self.artifact_refs != evidence.verifier_artifact_refs {
            return Err(ProcedureProjectionError::InvalidField {
                field: "verifier.artifact_refs",
                reason: "must exactly match evidence.verifier_artifact_refs",
            });
        }
        Ok(())
    }
}

/// A non-executable asset declaration. Scripts and assets are inventory only.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InertAsset {
    pub asset_ref: String,
    pub sha256: String,
    pub role: String,
    pub executable: bool,
}

impl InertAsset {
    fn validate(&self) -> Result<(), ProcedureProjectionError> {
        text(&self.asset_ref, "asset.asset_ref")?;
        digest(&self.sha256, "asset.sha256")?;
        text(&self.role, "asset.role")?;
        if self.executable {
            return Err(ProcedureProjectionError::CandidateOnlyViolation {
                field: "asset.executable",
            });
        }
        Ok(())
    }
}

/// Exact target capability evidence supplied by the target owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetProfile {
    pub target_id: String,
    pub host: String,
    pub profile: String,
    pub fingerprint: String,
    pub available_tools: Vec<VersionedRequirement>,
    pub available_capabilities: Vec<VersionedRequirement>,
}

impl TargetProfile {
    fn validate(&self) -> Result<(), ProcedureProjectionError> {
        text(&self.target_id, "target.target_id")?;
        text(&self.host, "target.host")?;
        text(&self.profile, "target.profile")?;
        digest(&self.fingerprint, "target.fingerprint")?;
        for (values, field) in [
            (&self.available_tools, "target.available_tools"),
            (
                &self.available_capabilities,
                "target.available_capabilities",
            ),
        ] {
            let mut seen = BTreeSet::new();
            for value in values {
                requirement(value, field)?;
                if !seen.insert((&value.name, &value.version)) {
                    return Err(ProcedureProjectionError::InvalidField {
                        field,
                        reason: "must not contain duplicate exact requirements",
                    });
                }
            }
        }
        Ok(())
    }

    fn missing(&self, procedure: &ProcedureDefinition) -> Vec<String> {
        let has = |available: &[VersionedRequirement], required: &VersionedRequirement| {
            available
                .iter()
                .any(|item| item.name == required.name && item.version == required.version)
        };
        procedure
            .required_tools
            .iter()
            .filter(|required| !has(&self.available_tools, required))
            .map(|item| format!("tool:{}@{}", item.name, item.version))
            .chain(
                procedure
                    .required_capabilities
                    .iter()
                    .filter(|required| !has(&self.available_capabilities, required))
                    .map(|item| format!("capability:{}@{}", item.name, item.version)),
            )
            .collect()
    }

    fn host_profile(&self, procedure: &ProcedureDefinition) -> HostProfile {
        HostProfile {
            host: self.host.clone(),
            profile: self.profile.clone(),
            required_tools: procedure.required_tools.clone(),
            required_capabilities: procedure.required_capabilities.clone(),
            limits: crate::HostLimits {
                max_description_chars: 16_384,
                max_actions: 1,
                max_expansion_handles: 0,
            },
        }
    }
}

/// Per-target result. Unsupported targets are retained, never silently omitted.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCompatibilityDisposition {
    pub target_id: String,
    pub fingerprint: String,
    pub disposition: TargetDisposition,
}

/// Compatibility result for one exact target profile.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "status")]
pub enum TargetDisposition {
    Compatible,
    Unsupported { missing: Vec<String> },
}

/// A complete immutable accepted-procedure projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedProcedureProjection {
    pub schema_version: String,
    pub procedure_id: String,
    pub procedure_revision: String,
    pub procedure_digest: String,
    pub state: ProcedureState,
    pub state_fence: StateFence,
    pub work_scope: eliot_receipts::WorkScopeBinding,
    pub task: eliot_receipts::TaskBinding,
    pub acceptance_receipt: ReceiptClaim,
    pub definition: ProcedureDefinition,
    pub evidence: ProcedureEvidence,
    pub verifier: ProcedureVerifier,
    pub safety_privacy_disclosure: SafetyPrivacyDisclosure,
    pub assets: Vec<InertAsset>,
}

impl GovernedProcedureProjection {
    /// Validates the accepted owner projection and all exact bindings.
    pub fn validate(&self) -> Result<(), ProcedureProjectionError> {
        if self.schema_version != GOVERNED_PROCEDURE_PROJECTION_SCHEMA_VERSION {
            return Err(ProcedureProjectionError::InvalidField {
                field: "schema_version",
                reason: "wrong governed-procedure projection revision",
            });
        }
        for (value, field) in [
            (&self.procedure_id, "procedure_id"),
            (&self.procedure_revision, "procedure_revision"),
        ] {
            text(value, field)?;
        }
        digest(&self.procedure_digest, "procedure_digest")?;
        self.state_fence
            .validate()
            .map_err(|_| ProcedureProjectionError::InvalidField {
                field: "state_fence",
                reason: "fence dependencies must be non-zero",
            })?;
        self.definition.validate()?;
        self.evidence.validate()?;
        self.verifier.validate(&self.evidence)?;
        self.safety_privacy_disclosure.validate()?;
        for asset in &self.assets {
            asset.validate()?;
        }
        if self.work_scope.state_fence != self.state_fence {
            return Err(ProcedureProjectionError::ReceiptBindingMismatch {
                field: "work_scope.state_fence",
            });
        }
        if self.task.state_fence != self.state_fence {
            return Err(ProcedureProjectionError::ReceiptBindingMismatch {
                field: "task.state_fence",
            });
        }
        if self.acceptance_receipt.evidence_ref != self.evidence.receipt_refs[0] {
            return Err(ProcedureProjectionError::ReceiptBindingMismatch {
                field: "acceptance_receipt.evidence_ref",
            });
        }
        self.acceptance_receipt.envelope.validate().map_err(|_| {
            ProcedureProjectionError::ReceiptBindingMismatch {
                field: "acceptance_receipt.envelope",
            }
        })?;
        let core = &self.acceptance_receipt.envelope.core;
        if core.kind != ReceiptKind::Verification
            || !matches!(
                &core.disposition,
                ReceiptDisposition::Success { proof }
                    if *proof >= ProofCeiling::ScopedVerification
            )
        {
            return Err(ProcedureProjectionError::ReceiptBindingMismatch {
                field: "acceptance_receipt.disposition",
            });
        }
        if core.work_scope != self.work_scope || core.task.as_ref() != Some(&self.task) {
            return Err(ProcedureProjectionError::ReceiptBindingMismatch {
                field: "acceptance_receipt.scope_or_task",
            });
        }
        if core.work_scope.state_fence != self.state_fence
            || core.causal.state_fence != self.state_fence
        {
            return Err(ProcedureProjectionError::ReceiptBindingMismatch {
                field: "acceptance_receipt.state_fence",
            });
        }
        if core.verifier.is_none()
            || !core.artifacts.iter().any(|artifact| {
                artifact.source_revision.as_deref() == Some(self.procedure_revision.as_str())
            })
        {
            return Err(ProcedureProjectionError::ReceiptBindingMismatch {
                field: "acceptance_receipt.procedure_artifact",
            });
        }
        if self.expected_digest()? != self.procedure_digest {
            return Err(ProcedureProjectionError::IdentityMismatch);
        }
        Ok(())
    }

    /// Computes the digest of all projection fields except the supplied digest.
    pub fn expected_digest(&self) -> Result<String, ProcedureProjectionError> {
        #[derive(Serialize)]
        struct Identity<'a> {
            schema_version: &'a str,
            procedure_id: &'a str,
            procedure_revision: &'a str,
            state: ProcedureState,
            state_fence: &'a StateFence,
            work_scope: &'a eliot_receipts::WorkScopeBinding,
            task: &'a eliot_receipts::TaskBinding,
            acceptance_receipt: &'a ReceiptClaim,
            definition: &'a ProcedureDefinition,
            evidence: &'a ProcedureEvidence,
            verifier: &'a ProcedureVerifier,
            safety_privacy_disclosure: &'a SafetyPrivacyDisclosure,
            assets: &'a [InertAsset],
        }
        canonical_digest(&Identity {
            schema_version: &self.schema_version,
            procedure_id: &self.procedure_id,
            procedure_revision: &self.procedure_revision,
            state: self.state,
            state_fence: &self.state_fence,
            work_scope: &self.work_scope,
            task: &self.task,
            acceptance_receipt: &self.acceptance_receipt,
            definition: &self.definition,
            evidence: &self.evidence,
            verifier: &self.verifier,
            safety_privacy_disclosure: &self.safety_privacy_disclosure,
            assets: &self.assets,
        })
        .map_err(|error| ProcedureProjectionError::Canonicalization(error.to_string()))
    }
}

/// One inert candidate for one compatible target.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableSkillPackageCandidate {
    pub schema_version: String,
    pub candidate_id: String,
    pub source: String,
    pub lifecycle_state: String,
    pub candidate_only: bool,
    pub activation_applied: bool,
    pub procedure: GovernedProcedureProjection,
    pub target: TargetProfile,
    pub target_fingerprint: String,
    pub behavior: SkillBehavior,
    pub host: HostProfile,
    pub package_digests: Option<PackageDigests>,
    pub assets: Vec<InertAsset>,
}

impl PortableSkillPackageCandidate {
    /// Validates that the candidate has no admission or effect authority.
    pub fn validate(&self) -> Result<(), ProcedureProjectionError> {
        if self.schema_version != GOVERNED_PROCEDURE_PROJECTION_SCHEMA_VERSION
            || self.source != GENERATED_CANDIDATE_SOURCE
            || self.lifecycle_state != CANDIDATE_LIFECYCLE_STATE
        {
            return Err(ProcedureProjectionError::CandidateOnlyViolation {
                field: "candidate identity",
            });
        }
        if !self.candidate_only || self.activation_applied {
            return Err(ProcedureProjectionError::CandidateOnlyViolation {
                field: "candidate_only/activation_applied",
            });
        }
        self.procedure.validate()?;
        self.target.validate()?;
        digest(&self.target_fingerprint, "target_fingerprint")?;
        if self.target.fingerprint != self.target_fingerprint {
            return Err(ProcedureProjectionError::IdentityMismatch);
        }
        if !self.target.missing(&self.procedure.definition).is_empty() {
            return Err(ProcedureProjectionError::InvalidField {
                field: "target",
                reason: "candidate target does not satisfy exact procedure requirements",
            });
        }
        if self.behavior != self.procedure.definition.behavior()
            || self.host != self.target.host_profile(&self.procedure.definition)
            || self.assets != self.procedure.assets
        {
            return Err(ProcedureProjectionError::IdentityMismatch);
        }
        let expected_candidate_id = canonical_digest(&(
            &self.procedure.procedure_digest,
            &self.target.target_id,
            &self.target.fingerprint,
        ))
        .map_err(|error| ProcedureProjectionError::Canonicalization(error.to_string()))?;
        if self.candidate_id != format!("skill-candidate:{expected_candidate_id}") {
            return Err(ProcedureProjectionError::IdentityMismatch);
        }
        self.behavior
            .validate()
            .map_err(ProcedureProjectionError::SkillContract)?;
        self.host
            .validate()
            .map_err(ProcedureProjectionError::SkillContract)?;
        if let Some(digests) = &self.package_digests {
            for (value, field) in [
                (&digests.source_digest, "package_digests.source_digest"),
                (&digests.contract_digest, "package_digests.contract_digest"),
                (
                    &digests.dependency_digest,
                    "package_digests.dependency_digest",
                ),
                (
                    &digests.tool_definition_digest,
                    "package_digests.tool_definition_digest",
                ),
            ] {
                digest(value, field)?;
            }
        }
        for asset in &self.assets {
            asset.validate()?;
        }
        Ok(())
    }
}

/// Results for every target considered by the mapper.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableSkillPackageProjection {
    pub target_dispositions: Vec<TargetCompatibilityDisposition>,
    pub candidates: Vec<PortableSkillPackageCandidate>,
}

impl PortableSkillPackageProjection {
    /// Validates every target disposition and candidate in the result set.
    pub fn validate(&self) -> Result<(), ProcedureProjectionError> {
        let mut target_ids = BTreeSet::new();
        for disposition in &self.target_dispositions {
            text(&disposition.target_id, "target_disposition.target_id")?;
            digest(&disposition.fingerprint, "target_disposition.fingerprint")?;
            if !target_ids.insert(&disposition.target_id) {
                return Err(ProcedureProjectionError::DuplicateTarget);
            }
        }
        let mut candidate_targets = BTreeSet::new();
        for candidate in &self.candidates {
            candidate.validate()?;
            if !candidate_targets.insert(&candidate.target.target_id) {
                return Err(ProcedureProjectionError::DuplicateTarget);
            }
            if !self.target_dispositions.iter().any(|disposition| {
                disposition.target_id == candidate.target.target_id
                    && disposition.fingerprint == candidate.target.fingerprint
                    && disposition.disposition == TargetDisposition::Compatible
            }) {
                return Err(ProcedureProjectionError::InvalidField {
                    field: "candidates",
                    reason: "candidate must have a matching compatible target disposition",
                });
            }
        }
        Ok(())
    }
}

/// Alias emphasizing that this output is a candidate set, not an admitted package.
pub type PortableSkillPackageCandidateSet = PortableSkillPackageProjection;

/// Maps one accepted governed procedure to deterministic inert target candidates.
pub fn project_governed_procedure_to_portable_skill_candidates(
    procedure: &GovernedProcedureProjection,
    targets: &[TargetProfile],
) -> Result<PortableSkillPackageProjection, ProcedureProjectionError> {
    if procedure.state != ProcedureState::Accepted {
        return Err(ProcedureProjectionError::NotAccepted(procedure.state));
    }
    procedure.validate()?;
    if targets.is_empty() {
        return Err(ProcedureProjectionError::InvalidField {
            field: "targets",
            reason: "must contain at least one exact target",
        });
    }

    let mut ordered = targets.to_vec();
    ordered.sort_by(|left, right| left.target_id.cmp(&right.target_id));
    let mut seen = BTreeSet::new();
    for target in &ordered {
        target.validate()?;
        if !seen.insert(&target.target_id) {
            return Err(ProcedureProjectionError::DuplicateTarget);
        }
    }

    let mut target_dispositions = Vec::with_capacity(ordered.len());
    let mut candidates = Vec::new();
    for target in ordered {
        let missing = target.missing(&procedure.definition);
        let disposition = if missing.is_empty() {
            TargetDisposition::Compatible
        } else {
            TargetDisposition::Unsupported { missing }
        };
        target_dispositions.push(TargetCompatibilityDisposition {
            target_id: target.target_id.clone(),
            fingerprint: target.fingerprint.clone(),
            disposition,
        });
        if matches!(
            target_dispositions.last().map(|item| &item.disposition),
            Some(TargetDisposition::Compatible)
        ) {
            let candidate_id = canonical_digest(&(
                &procedure.procedure_digest,
                &target.target_id,
                &target.fingerprint,
            ))
            .map_err(|error| ProcedureProjectionError::Canonicalization(error.to_string()))?;
            let candidate = PortableSkillPackageCandidate {
                schema_version: GOVERNED_PROCEDURE_PROJECTION_SCHEMA_VERSION.to_owned(),
                candidate_id: format!("skill-candidate:{candidate_id}"),
                source: GENERATED_CANDIDATE_SOURCE.to_owned(),
                lifecycle_state: CANDIDATE_LIFECYCLE_STATE.to_owned(),
                candidate_only: true,
                activation_applied: false,
                procedure: procedure.clone(),
                target: target.clone(),
                target_fingerprint: target.fingerprint.clone(),
                behavior: procedure.definition.behavior(),
                host: target.host_profile(&procedure.definition),
                package_digests: None,
                assets: procedure.assets.clone(),
            };
            candidate.validate()?;
            candidates.push(candidate);
        }
    }
    let result = PortableSkillPackageProjection {
        target_dispositions,
        candidates,
    };
    result.validate()?;
    Ok(result)
}
