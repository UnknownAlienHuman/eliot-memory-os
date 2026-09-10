//! Immutable product/context identity carried by a diagnosis contract.
//!
//! This module records supplied identity and evidence claims. It does not
//! authenticate an owner, admit a run, inspect a worktree, or establish that
//! the supplied identity is current.

use eliot_contracts::{ArtifactId, ContractId, ContractVersion, TaskRevision};
use eliot_evaluation_contracts::{
    ProductIdentityRef, RecoveryAcceptanceProfile, UserOutcomeObjectiveState,
};
use eliot_evidence::EvidenceEnvelope;
use eliot_receipts::{ArtifactBinding, WorkScopeBinding};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::validation::{
    MAX_DIAGNOSIS_SEQUENCE_ITEMS, MAX_DIAGNOSIS_TEXT_BYTES, bounded_artifact_refs,
    bounded_contract_id, bounded_digest, bounded_text, canonical_stream_digest,
    preflight_canonical_stream,
};
use crate::error::{check_fence, check_text, check_vec_bound};
use crate::{ContractViolation, FailureEnvironment, is_hex64_lower};

/// Wire revision for the diagnosis product context.
pub const PRODUCT_CONTEXT_SCHEMA_VERSION: u16 = 1;
/// Maximum number of evidence references or availability records on one context.
pub const MAX_DIAGNOSIS_CONTEXT_ITEMS: usize = 256;

/// Closed diagnosis field names that may be explicitly unavailable.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnavailableField {
    Repository,
    Commit,
    Tree,
    Package,
    Cell,
    Component,
    Artifact,
    Binary,
    Config,
    Features,
    Toolchain,
    Environment,
    RuntimeGeneration,
    Scope,
    Attempt,
    RunId,
    VerifierConfigHash,
    VerifierConfigRevision,
    VerifierContractRevision,
    VerifierEnvironmentBinding,
    ContextDigest,
    CurrentProductIdentity,
    Verifier,
    ObservedValue,
    AcceptanceContent,
    Mechanism,
    HistoryDenominator,
    RetainedHistory,
    RunEvidenceAssociation,
}

/// A first-class explanation for information that was not supplied.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnavailableEvidence {
    /// Stable field path whose value is unavailable.
    pub field: UnavailableField,
    /// Bounded reason for the absence.
    pub reason: String,
}

impl UnavailableEvidence {
    pub(super) fn validate(&self) -> Result<(), ContractViolation> {
        check_text(&self.reason, "diagnosis.unavailable.reason", 512)
    }
}

/// Narrow binding between evaluation acceptance and this product context.
///
/// Projection digests identify the canonical imported objective/profile
/// values. `binding_digest` identifies this binding's own canonical claim
/// bytes, while `external_content` is a separately supplied acceptance
/// contract content claim. Neither digest authenticates the issuing owner or
/// external artifact.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceBinding {
    pub schema_version: u16,
    pub contract_owner: ContractId,
    pub contract_ref: ContractId,
    pub contract_revision: ContractVersion,
    pub external_content: Option<ArtifactBinding>,
    pub external_content_unavailable: Option<UnavailableEvidence>,
    pub binding_digest: String,
    pub objective_id: ContractId,
    pub objective_revision: TaskRevision,
    pub profile_id: ContractId,
    pub profile_revision: TaskRevision,
    pub objective_projection_digest: String,
    pub profile_projection_digest: String,
}

/// Wire revision for [`AcceptanceBinding`].
pub const ACCEPTANCE_BINDING_SCHEMA_VERSION: u16 = 1;

impl AcceptanceBinding {
    /// Computes the local binding digest over the bounded claim preimage.
    pub fn canonical_binding_digest(&self) -> Result<String, ContractViolation> {
        preflight_canonical_stream(self)?;
        self.preflight_wire()?;
        let preimage = AcceptanceBindingPreimage {
            schema_version: self.schema_version,
            contract_owner: &self.contract_owner,
            contract_ref: &self.contract_ref,
            contract_revision: self.contract_revision,
            external_content: self.external_content.as_ref(),
            external_content_unavailable: self.external_content_unavailable.as_ref(),
            objective_id: &self.objective_id,
            objective_revision: self.objective_revision,
            profile_id: &self.profile_id,
            profile_revision: self.profile_revision,
            objective_projection_digest: &self.objective_projection_digest,
            profile_projection_digest: &self.profile_projection_digest,
        };
        canonical_stream_digest(&preimage)
    }

    /// Returns this binding with its local canonical digest populated.
    pub fn with_binding_digest(mut self) -> Result<Self, ContractViolation> {
        self.binding_digest = self.canonical_binding_digest()?;
        Ok(self)
    }

    fn preflight_wire(&self) -> Result<(), ContractViolation> {
        if self.schema_version != ACCEPTANCE_BINDING_SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "product_context.acceptance.schema_version",
                min: i64::from(ACCEPTANCE_BINDING_SCHEMA_VERSION),
                max: i64::from(ACCEPTANCE_BINDING_SCHEMA_VERSION),
                got: i64::from(self.schema_version),
            });
        }
        bounded_contract_id(
            &self.contract_owner,
            "product_context.acceptance.contract_owner",
        )?;
        bounded_contract_id(
            &self.contract_ref,
            "product_context.acceptance.contract_ref",
        )?;
        bounded_contract_id(
            &self.objective_id,
            "product_context.acceptance.objective_id",
        )?;
        bounded_contract_id(&self.profile_id, "product_context.acceptance.profile_id")?;
        if !self.binding_digest.is_empty() {
            bounded_digest(
                &self.binding_digest,
                "product_context.acceptance.binding_digest",
            )?;
        }
        bounded_digest(
            &self.objective_projection_digest,
            "product_context.acceptance.objective_projection_digest",
        )?;
        bounded_digest(
            &self.profile_projection_digest,
            "product_context.acceptance.profile_projection_digest",
        )?;
        if let Some(content) = &self.external_content {
            preflight_artifact(content, "product_context.acceptance.external_content")?;
        }
        match (&self.external_content, &self.external_content_unavailable) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(ContractViolation::BindingMismatch {
                    field: "product_context.acceptance.external_content",
                    reason: "external content must be supplied or exactly once unavailable"
                        .to_owned(),
                });
            }
            (None, Some(unavailable)) => {
                if unavailable.field != UnavailableField::AcceptanceContent {
                    return Err(ContractViolation::BindingMismatch {
                        field: "product_context.acceptance.external_content_unavailable",
                        reason: "unavailable field does not describe acceptance content".to_owned(),
                    });
                }
                unavailable.validate()?;
            }
            (Some(_), None) => {}
        }
        Ok(())
    }

    fn validate(
        &self,
        objective: &UserOutcomeObjectiveState,
        recovery: &RecoveryAcceptanceProfile,
    ) -> Result<(), ContractViolation> {
        self.preflight_wire()?;
        if self.objective_id != objective.objective_id
            || self.objective_revision != objective.revision
        {
            return Err(ContractViolation::BindingMismatch {
                field: "product_context.acceptance.objective",
                reason: "acceptance objective id/revision does not match imported objective"
                    .to_owned(),
            });
        }
        if self.profile_id != recovery.profile_id || self.profile_revision != recovery.revision {
            return Err(ContractViolation::BindingMismatch {
                field: "product_context.acceptance.profile",
                reason: "acceptance profile id/revision does not match imported profile".to_owned(),
            });
        }
        let objective_digest = canonical_stream_digest(objective)?;
        let profile_digest = canonical_stream_digest(recovery)?;
        if self.objective_projection_digest != objective_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "product_context.acceptance.objective_projection_digest",
                reason: "objective projection digest does not match imported objective".to_owned(),
            });
        }
        if self.profile_projection_digest != profile_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "product_context.acceptance.profile_projection_digest",
                reason: "profile projection digest does not match imported profile".to_owned(),
            });
        }
        let expected = self.canonical_binding_digest()?;
        if self.binding_digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "product_context.acceptance.binding_digest",
                reason: "acceptance content digest does not match canonical binding".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct AcceptanceBindingPreimage<'a> {
    schema_version: u16,
    contract_owner: &'a ContractId,
    contract_ref: &'a ContractId,
    contract_revision: ContractVersion,
    external_content: Option<&'a ArtifactBinding>,
    external_content_unavailable: Option<&'a UnavailableEvidence>,
    objective_id: &'a ContractId,
    objective_revision: TaskRevision,
    profile_id: &'a ContractId,
    profile_revision: TaskRevision,
    objective_projection_digest: &'a str,
    profile_projection_digest: &'a str,
}

fn bounded_texts(values: &[String], field: &'static str) -> Result<(), ContractViolation> {
    check_vec_bound(values.len(), MAX_DIAGNOSIS_SEQUENCE_ITEMS, field)?;
    for value in values {
        check_text(value, field, MAX_DIAGNOSIS_TEXT_BYTES)?;
    }
    Ok(())
}

fn preflight_product_identity(identity: &ProductIdentityRef) -> Result<(), ContractViolation> {
    bounded_text(
        identity.product_id.as_str(),
        "product_context.product_id",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_text(
        &identity.source_revision,
        "product_context.source_revision",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    check_vec_bound(
        identity.contract_revisions.len(),
        MAX_DIAGNOSIS_SEQUENCE_ITEMS,
        "product_context.contract_revisions",
    )
}

fn preflight_objective(objective: &UserOutcomeObjectiveState) -> Result<(), ContractViolation> {
    bounded_contract_id(&objective.objective_id, "product_context.objective_id")?;
    bounded_text(
        &objective.owner,
        "product_context.objective.owner",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_text(
        &objective.task_family_and_population,
        "product_context.objective.task_family_and_population",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_text(
        &objective.intended_user_outcome,
        "product_context.objective.intended_user_outcome",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_text(
        &objective.primary_outcome_measure,
        "product_context.objective.primary_outcome_measure",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    if let Some(reason) = &objective.comparison_reason {
        bounded_text(
            reason,
            "product_context.objective.comparison_reason",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
    }
    bounded_texts(
        &objective.counter_metrics,
        "product_context.objective.counter_metrics",
    )?;
    bounded_texts(
        &objective.disproof_and_stop_conditions,
        "product_context.objective.disproof_and_stop_conditions",
    )?;
    if let Some(plan) = &objective.evaluation_plan_ref {
        bounded_contract_id(plan, "product_context.objective.evaluation_plan_ref")?;
    }
    bounded_artifact_refs(
        &objective.outcome_evidence_refs,
        "product_context.objective.outcome_evidence_refs",
    )?;
    preflight_product_identity(&objective.product_identity_ref)
}

fn preflight_recovery(recovery: &RecoveryAcceptanceProfile) -> Result<(), ContractViolation> {
    bounded_contract_id(&recovery.profile_id, "product_context.recovery.profile_id")?;
    bounded_contract_id(
        &recovery.objective_ref,
        "product_context.recovery.objective_ref",
    )?;
    check_vec_bound(
        recovery.invariant_gaps.len(),
        MAX_DIAGNOSIS_SEQUENCE_ITEMS,
        "product_context.recovery.invariant_gaps",
    )?;
    for gap in &recovery.invariant_gaps {
        bounded_contract_id(&gap.gap_id, "product_context.recovery.gap_id")?;
        bounded_text(
            &gap.description,
            "product_context.recovery.gap.description",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_text(
            &gap.discriminator,
            "product_context.recovery.gap.discriminator",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
    }
    bounded_texts(
        &recovery.affected_owners,
        "product_context.recovery.affected_owners",
    )?;
    bounded_texts(
        &recovery.discriminators,
        "product_context.recovery.discriminators",
    )?;
    bounded_text(
        &recovery.enablement_condition,
        "product_context.recovery.enablement_condition",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )
}

fn preflight_environment(environment: &FailureEnvironment) -> Result<(), ContractViolation> {
    for (value, field) in [
        (
            &environment.environment_id,
            "product_context.environment.environment_id",
        ),
        (
            &environment.environment_revision,
            "product_context.environment.environment_revision",
        ),
        (
            &environment.platform,
            "product_context.environment.platform",
        ),
        (
            &environment.tool_revision,
            "product_context.environment.tool_revision",
        ),
        (
            &environment.config_revision,
            "product_context.environment.config_revision",
        ),
        (
            &environment.capability_revision,
            "product_context.environment.capability_revision",
        ),
        (
            &environment.policy_revision,
            "product_context.environment.policy_revision",
        ),
    ] {
        bounded_text(value, field, MAX_DIAGNOSIS_TEXT_BYTES)?;
    }
    if let Some(model) = &environment.model_revision {
        bounded_text(
            model,
            "product_context.environment.model_revision",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
    }
    check_fence(&environment.state_fence)
}

fn preflight_evidence(evidence: &EvidenceEnvelope) -> Result<(), ContractViolation> {
    bounded_text(
        evidence.provenance.source_id.as_str(),
        "product_context.evidence.provenance.source_id",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_text(
        &evidence.provenance.capture_route,
        "product_context.evidence.provenance.capture_route",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_text(
        &evidence.provenance.scope,
        "product_context.evidence.provenance.scope",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    for (value, field) in [
        (
            &evidence.provenance.raw_handle,
            "product_context.evidence.provenance.raw_handle",
        ),
        (
            &evidence.provenance.revision,
            "product_context.evidence.provenance.revision",
        ),
    ] {
        if let Some(value) = value {
            bounded_text(value, field, MAX_DIAGNOSIS_TEXT_BYTES)?;
        }
    }
    if let Some(verification) = &evidence.verification {
        bounded_contract_id(
            &verification.contract_id,
            "product_context.evidence.verification.contract_id",
        )?;
        bounded_text(
            verification.run_id.as_str(),
            "product_context.evidence.verification.run_id",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_text(
            &verification.revision,
            "product_context.evidence.verification.revision",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
    }
    check_fence(&evidence.state_fence)
}

fn preflight_artifact(
    binding: &ArtifactBinding,
    field: &'static str,
) -> Result<(), ContractViolation> {
    bounded_text(
        binding.artifact_id.as_str(),
        field,
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_digest(&binding.sha256, field)?;
    if let Some(revision) = &binding.source_revision {
        bounded_text(revision, field, MAX_DIAGNOSIS_TEXT_BYTES)?;
    }
    Ok(())
}

/// Supplied product and execution-context evidence for a diagnosis.
///
/// Optional identity members are intentionally not filled by inference. A
/// missing member is represented by `unavailable`, while `evidence` retains
/// the existing coverage and freshness dimensions for the supplied claim.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductContext {
    /// Exact diagnosis contract revision.
    pub schema_version: u16,
    /// User-owned objective and its canonical product identity.
    pub objective: UserOutcomeObjectiveState,
    /// Recovery gaps and enablement conditions for the objective.
    pub recovery: RecoveryAcceptanceProfile,
    /// Feature, workflow and user-outcome binding supplied by the caller.
    pub feature_ref: String,
    pub workflow_ref: String,
    pub user_outcome_ref: String,
    pub acceptance: AcceptanceBinding,
    /// Canonical source/product identity.
    pub product_identity: ProductIdentityRef,
    /// Optional source and package lineage. Absence must be explicit in
    /// `unavailable` when it matters to a downstream claim.
    pub repository: Option<String>,
    pub commit: Option<String>,
    pub tree: Option<String>,
    pub package: Option<String>,
    pub cell: Option<String>,
    pub component: Option<String>,
    /// Optional artifact and binary receipt bindings.
    pub artifact: Option<ArtifactBinding>,
    pub binary: Option<ArtifactBinding>,
    pub config: Option<ArtifactBinding>,
    pub features: Option<ArtifactBinding>,
    pub toolchain: Option<ArtifactBinding>,
    /// Existing failure/environment primitive; no diagnosis-specific copy is
    /// introduced for platform, tool, config or capability revisions.
    pub environment: Option<FailureEnvironment>,
    /// Runtime generation is opaque diagnosis evidence and is separate from
    /// the foundation `ResourceGeneration` carried by `scope`.
    pub runtime_generation: Option<String>,
    /// Optional scope/fence binding supplied by the caller.
    pub scope: Option<WorkScopeBinding>,
    /// Existing evidence dimensions, including coverage, freshness and fence.
    pub evidence: EvidenceEnvelope,
    /// Direct supporting citations for this context; these are not an
    /// exhaustive transitive denominator or an independence/authentication
    /// proof.
    pub evidence_refs: Vec<ArtifactId>,
    pub unavailable: Vec<UnavailableEvidence>,
    /// SHA-256 over the same record with this field set to an empty string.
    pub digest: String,
}

impl ProductContext {
    /// Computes the identity digest without treating it as authentication.
    pub fn canonical_digest(&self) -> Result<String, ContractViolation> {
        self.preflight_wire()?;
        let mut unsigned = self.clone();
        unsigned.digest.clear();
        canonical_stream_digest(&unsigned)
    }

    /// Performs allocation-free local wire preflight before any digest clone
    /// or canonical-byte allocation.
    pub fn preflight_wire(&self) -> Result<(), ContractViolation> {
        if !self.digest.is_empty() && !is_hex64_lower(&self.digest) {
            return Err(ContractViolation::Malformed {
                field: "product_context.digest",
                reason: "digest must be empty or lowercase SHA-256".to_owned(),
            });
        }
        preflight_canonical_stream(self)?;
        if self.schema_version != PRODUCT_CONTEXT_SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "product_context.schema_version",
                min: i64::from(PRODUCT_CONTEXT_SCHEMA_VERSION),
                max: i64::from(PRODUCT_CONTEXT_SCHEMA_VERSION),
                got: i64::from(self.schema_version),
            });
        }
        preflight_objective(&self.objective)?;
        preflight_recovery(&self.recovery)?;
        preflight_product_identity(&self.product_identity)?;
        self.acceptance.preflight_wire()?;
        for (value, field) in [
            (&self.feature_ref, "product_context.feature_ref"),
            (&self.workflow_ref, "product_context.workflow_ref"),
            (&self.user_outcome_ref, "product_context.user_outcome_ref"),
        ] {
            bounded_text(value, field, MAX_DIAGNOSIS_TEXT_BYTES)?;
        }
        for (value, field) in [
            (&self.repository, "product_context.repository"),
            (&self.commit, "product_context.commit"),
            (&self.tree, "product_context.tree"),
            (&self.package, "product_context.package"),
            (&self.cell, "product_context.cell"),
            (&self.component, "product_context.component"),
            (
                &self.runtime_generation,
                "product_context.runtime_generation",
            ),
        ] {
            if let Some(value) = value {
                bounded_text(value, field, MAX_DIAGNOSIS_TEXT_BYTES)?;
            }
        }
        preflight_evidence(&self.evidence)?;
        if let Some(environment) = &self.environment {
            preflight_environment(environment)?;
        }
        if let Some(scope) = &self.scope {
            bounded_text(
                scope.scope_id.as_str(),
                "product_context.scope.scope_id",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
            bounded_text(
                scope.product_id.as_str(),
                "product_context.scope.product_id",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
            check_fence(&scope.state_fence)?;
            if scope.resource_generation != scope.state_fence.resource_generation {
                return Err(ContractViolation::BindingMismatch {
                    field: "product_context.scope.resource_generation",
                    reason: "scope resource generation must equal its state fence generation"
                        .to_owned(),
                });
            }
        }
        for (binding, field) in [
            (&self.artifact, "product_context.artifact"),
            (&self.binary, "product_context.binary"),
            (&self.config, "product_context.config"),
            (&self.features, "product_context.features"),
            (&self.toolchain, "product_context.toolchain"),
        ] {
            if let Some(binding) = binding {
                preflight_artifact(binding, field)?;
            }
        }
        bounded_artifact_refs(&self.evidence_refs, "product_context.evidence_refs")?;
        check_vec_bound(
            self.unavailable.len(),
            MAX_DIAGNOSIS_CONTEXT_ITEMS,
            "product_context.unavailable",
        )?;
        for item in &self.unavailable {
            item.validate()?;
        }
        self.check_optional_availability()?;
        self.check_source_joins()?;
        Ok(())
    }

    fn check_optional_availability(&self) -> Result<(), ContractViolation> {
        let mut seen = [None; 14];
        for item in &self.unavailable {
            let known = matches!(
                item.field,
                UnavailableField::Repository
                    | UnavailableField::Commit
                    | UnavailableField::Tree
                    | UnavailableField::Package
                    | UnavailableField::Cell
                    | UnavailableField::Component
                    | UnavailableField::Artifact
                    | UnavailableField::Binary
                    | UnavailableField::Config
                    | UnavailableField::Features
                    | UnavailableField::Toolchain
                    | UnavailableField::Environment
                    | UnavailableField::RuntimeGeneration
                    | UnavailableField::Scope
            );
            if !known {
                return Err(ContractViolation::BindingMismatch {
                    field: "product_context.unavailable.field",
                    reason: "field is not valid for ProductContext".to_owned(),
                });
            }
            let slot = match item.field {
                UnavailableField::Repository => 0,
                UnavailableField::Commit => 1,
                UnavailableField::Tree => 2,
                UnavailableField::Package => 3,
                UnavailableField::Cell => 4,
                UnavailableField::Component => 5,
                UnavailableField::Artifact => 6,
                UnavailableField::Binary => 7,
                UnavailableField::Config => 8,
                UnavailableField::Features => 9,
                UnavailableField::Toolchain => 10,
                UnavailableField::Environment => 11,
                UnavailableField::RuntimeGeneration => 12,
                UnavailableField::Scope => 13,
                _ => unreachable!("closed field set checked above"),
            };
            if seen[slot].is_some() {
                return Err(ContractViolation::BindingMismatch {
                    field: "product_context.unavailable",
                    reason: "availability fields must be unique".to_owned(),
                });
            }
            seen[slot] = Some(());
        }
        for pair in self.unavailable.windows(2) {
            if pair[0].field >= pair[1].field {
                return Err(ContractViolation::BindingMismatch {
                    field: "product_context.unavailable",
                    reason: "availability fields must be unique and in canonical order".to_owned(),
                });
            }
        }
        let checks = [
            (self.repository.is_some(), 0, UnavailableField::Repository),
            (self.commit.is_some(), 1, UnavailableField::Commit),
            (self.tree.is_some(), 2, UnavailableField::Tree),
            (self.package.is_some(), 3, UnavailableField::Package),
            (self.cell.is_some(), 4, UnavailableField::Cell),
            (self.component.is_some(), 5, UnavailableField::Component),
            (self.artifact.is_some(), 6, UnavailableField::Artifact),
            (self.binary.is_some(), 7, UnavailableField::Binary),
            (self.config.is_some(), 8, UnavailableField::Config),
            (self.features.is_some(), 9, UnavailableField::Features),
            (self.toolchain.is_some(), 10, UnavailableField::Toolchain),
            (
                self.environment.is_some(),
                11,
                UnavailableField::Environment,
            ),
            (
                self.runtime_generation.is_some(),
                12,
                UnavailableField::RuntimeGeneration,
            ),
            (self.scope.is_some(), 13, UnavailableField::Scope),
        ];
        for (present, slot, field) in checks {
            if present == seen[slot].is_some() {
                return Err(ContractViolation::BindingMismatch {
                    field: "product_context.unavailable",
                    reason: format!(
                        "field {field:?} must be either present or exactly once unavailable"
                    ),
                });
            }
        }
        Ok(())
    }

    fn check_source_joins(&self) -> Result<(), ContractViolation> {
        if let Some(commit) = &self.commit
            && commit != &self.product_identity.source_revision
        {
            return Err(ContractViolation::BindingMismatch {
                field: "product_context.commit",
                reason: "known commit must equal product source_revision".to_owned(),
            });
        }
        let bindings = [
            (&self.artifact, "product_context.artifact.source_revision"),
            (&self.binary, "product_context.binary.source_revision"),
        ];
        for (binding, field) in bindings {
            if let Some(binding) = binding
                && let Some(revision) = &binding.source_revision
                && revision != &self.product_identity.source_revision
            {
                return Err(ContractViolation::BindingMismatch {
                    field,
                    reason: "known artifact source_revision must equal product source_revision"
                        .to_owned(),
                });
            }
        }
        let bindings = [
            self.artifact.as_ref(),
            self.binary.as_ref(),
            self.config.as_ref(),
            self.features.as_ref(),
            self.toolchain.as_ref(),
            self.acceptance.external_content.as_ref(),
        ];
        for (left_index, left) in bindings.iter().enumerate() {
            let Some(left) = left else { continue };
            for right in bindings.iter().skip(left_index + 1).flatten() {
                if left.artifact_id == right.artifact_id && left.sha256 != right.sha256 {
                    return Err(ContractViolation::BindingMismatch {
                        field: "product_context.artifact_bindings",
                        reason: "one artifact id cannot carry different content".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Performs intrinsic bounded shape and binding checks, excluding digest.
    fn validate_shape(&self) -> Result<(), ContractViolation> {
        self.preflight_wire()?;
        self.validate_owner_payloads()?;
        self.validate_identity_joins()?;
        self.validate_context_text()?;
        self.validate_environment_and_scope()?;
        self.validate_artifacts_and_unavailable()?;
        self.check_optional_availability()?;
        self.check_source_joins()
    }

    fn validate_owner_payloads(&self) -> Result<(), ContractViolation> {
        self.objective
            .validate()
            .map_err(|error| ContractViolation::Malformed {
                field: "product_context.objective",
                reason: error.to_string(),
            })?;
        self.recovery
            .validate()
            .map_err(|error| ContractViolation::Malformed {
                field: "product_context.recovery",
                reason: error.to_string(),
            })?;
        self.evidence
            .validate()
            .map_err(|error| ContractViolation::Malformed {
                field: "product_context.evidence",
                reason: error.to_string(),
            })?;
        self.product_identity
            .validate()
            .map_err(|error| ContractViolation::Malformed {
                field: "product_context.product_identity",
                reason: error.to_string(),
            })?;
        Ok(())
    }

    fn validate_identity_joins(&self) -> Result<(), ContractViolation> {
        if self.objective.product_identity_ref != self.product_identity {
            return Err(ContractViolation::BindingMismatch {
                field: "product_context.objective.product_identity_ref",
                reason: "objective product identity does not match product context identity"
                    .to_owned(),
            });
        }
        if self.recovery.objective_ref != self.objective.objective_id {
            return Err(ContractViolation::BindingMismatch {
                field: "product_context.recovery.objective_ref",
                reason: "recovery objective reference does not match objective id".to_owned(),
            });
        }
        self.acceptance.validate(&self.objective, &self.recovery)?;
        Ok(())
    }

    fn validate_context_text(&self) -> Result<(), ContractViolation> {
        for (value, field) in [
            (&self.feature_ref, "product_context.feature_ref"),
            (&self.workflow_ref, "product_context.workflow_ref"),
            (&self.user_outcome_ref, "product_context.user_outcome_ref"),
        ] {
            check_text(value, field, 512)?;
        }
        for (value, field) in [
            (&self.repository, "product_context.repository"),
            (&self.commit, "product_context.commit"),
            (&self.tree, "product_context.tree"),
            (&self.package, "product_context.package"),
            (&self.cell, "product_context.cell"),
            (&self.component, "product_context.component"),
            (
                &self.runtime_generation,
                "product_context.runtime_generation",
            ),
        ] {
            if let Some(value) = value {
                check_text(value, field, 512)?;
            }
        }
        Ok(())
    }

    fn validate_environment_and_scope(&self) -> Result<(), ContractViolation> {
        if let Some(environment) = &self.environment {
            preflight_environment(environment)?;
            environment.validate()?;
        }
        if let Some(scope) = &self.scope
            && scope.product_id != self.product_identity.product_id
        {
            return Err(ContractViolation::BindingMismatch {
                field: "product_context.scope.product_id",
                reason: "scope product id does not match product identity".to_owned(),
            });
        }
        if let Some(scope) = &self.scope
            && scope.resource_generation != scope.state_fence.resource_generation
        {
            return Err(ContractViolation::BindingMismatch {
                field: "product_context.scope.resource_generation",
                reason: "scope resource generation must equal its state fence generation"
                    .to_owned(),
            });
        }
        if let Some(scope) = &self.scope {
            scope
                .state_fence
                .validate()
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "product_context.scope.state_fence",
                    reason: error.to_string(),
                })?;
        }
        if let Some(scope) = &self.scope
            && self.evidence.state_fence != scope.state_fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "product_context.evidence.state_fence",
                reason: "evidence and scope fences must match exactly".to_owned(),
            });
        }
        if let Some(environment) = &self.environment
            && environment.state_fence != self.evidence.state_fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "product_context.environment.state_fence",
                reason: "environment and evidence fences must match exactly".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_artifacts_and_unavailable(&self) -> Result<(), ContractViolation> {
        for (binding, field) in [
            (&self.artifact, "product_context.artifact"),
            (&self.binary, "product_context.binary"),
            (&self.config, "product_context.config"),
            (&self.features, "product_context.features"),
            (&self.toolchain, "product_context.toolchain"),
        ] {
            if let Some(binding) = binding {
                preflight_artifact(binding, field)?;
            }
        }
        bounded_artifact_refs(&self.evidence_refs, "product_context.evidence_refs")?;
        check_vec_bound(
            self.unavailable.len(),
            MAX_DIAGNOSIS_CONTEXT_ITEMS,
            "product_context.unavailable",
        )?;
        for item in &self.unavailable {
            item.validate()?;
        }
        Ok(())
    }

    /// Performs intrinsic shape, binding and digest checks only.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.validate_shape()?;
        bounded_digest(&self.digest, "product_context.digest")?;
        let expected = self.canonical_digest()?;
        if self.digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "product_context.digest",
                reason: "supplied digest does not match canonical bytes".to_owned(),
            });
        }
        Ok(())
    }
}

/// Returns the contract version used by the diagnosis context family.
#[must_use]
pub const fn product_context_contract_version() -> ContractVersion {
    ContractVersion::new(1, 0, 0)
}
