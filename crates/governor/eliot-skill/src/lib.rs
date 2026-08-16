//! Governor-owned lifecycle contracts for short Skills.
//!
//! The generated surface is a projection and delivery boundary. This crate
//! owns lifecycle evidence, conflict state, reversible proposals, and
//! evidence-gated promotion. Skill text remains advisory; tools, leases and
//! gates provide enforcement.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{
    ContractVersion, RequestMetadata, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_skills::RegistrationIdentity;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.governor.skill";
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

fn text(value: &str, field: &'static str) -> Result<(), SkillError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SkillError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), SkillError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(SkillError::InvalidField {
            field,
            reason: "must be lowercase SHA-256 hex",
        });
    }
    Ok(())
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, SkillError> {
    canonical_json_bytes(value).map_err(|error| SkillError::Serialization(error.to_string()))
}

fn value_digest<T: Serialize>(value: &T) -> Result<String, SkillError> {
    Ok(sha256_hex(&canonical(value)?))
}

fn unique<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<(), SkillError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(SkillError::Duplicate { field });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum SkillError {
    #[error("invalid Skill lifecycle field {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("duplicate Skill lifecycle value in {field}")]
    Duplicate { field: &'static str },
    #[error("Skill lifecycle state fence mismatch")]
    FenceMismatch,
    #[error("Skill lifecycle revision conflict")]
    RevisionConflict,
    #[error("Skill lifecycle view not found")]
    NotFound,
    #[error("Skill lifecycle identity mismatch")]
    IdentityMismatch,
    #[error("Skill lifecycle requires independent route evidence")]
    IndependentEvidenceRequired,
    #[error("Skill lifecycle promotion is not reversible")]
    NonReversiblePromotion,
    #[error("Skill lifecycle serialization failed: {0}")]
    Serialization(String),
    #[error("Skill surface contract failed: {0}")]
    Surface(String),
}

/// Stable identity of a generated Skill revision and its materialized package.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillRef {
    pub registration: RegistrationIdentity,
    pub package_digest: String,
}

impl SkillRef {
    pub fn new(
        skill_id: impl Into<String>,
        revision: impl Into<String>,
        name: impl Into<String>,
        package_digest: impl Into<String>,
    ) -> Result<Self, SkillError> {
        let registration = RegistrationIdentity::new(skill_id, revision, name)
            .map_err(|error| SkillError::Surface(error.to_string()))?;
        let value = Self {
            registration,
            package_digest: package_digest.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), SkillError> {
        let expected = self
            .registration
            .expected_digest()
            .map_err(|error| SkillError::Surface(error.to_string()))?;
        if expected != self.registration.registration_digest {
            return Err(SkillError::IdentityMismatch);
        }
        digest(&self.package_digest, "package_digest")?;
        text(&self.registration.skill_id, "skill_id")?;
        text(&self.registration.revision, "revision")?;
        text(&self.registration.name, "name")?;
        Ok(())
    }

    #[must_use]
    pub fn skill_id(&self) -> &str {
        &self.registration.skill_id
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyVersion {
    pub name: String,
    pub version: String,
    pub contract_digest: String,
}

impl DependencyVersion {
    pub fn validate(&self) -> Result<(), SkillError> {
        text(&self.name, "dependency.name")?;
        text(&self.version, "dependency.version")?;
        digest(&self.contract_digest, "dependency.contract_digest")
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillScope {
    pub task_scope: String,
    pub host: String,
    pub route: String,
    pub governance_scope: String,
}

impl SkillScope {
    pub fn validate(&self) -> Result<(), SkillError> {
        for value in [
            (&self.task_scope, "scope.task_scope"),
            (&self.host, "scope.host"),
            (&self.route, "scope.route"),
            (&self.governance_scope, "scope.governance_scope"),
        ] {
            text(value.0, value.1)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillStatus {
    Current,
    Provisional,
    Stale,
    Suppressed,
    Archived,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    Keep,
    Patch,
    Split,
    Merge,
    Suppress,
    Archive,
    Quarantine,
    Restore,
}

impl LifecycleAction {
    #[must_use]
    pub const fn is_reversible(self) -> bool {
        !matches!(self, Self::Keep)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCounters {
    pub installed: u64,
    pub delivered: u64,
    pub expanded: u64,
    pub executed: u64,
    pub verified: u64,
    pub failed: u64,
    pub uncertain: u64,
    pub useful: u64,
}

impl LifecycleCounters {
    pub fn validate(&self) -> Result<(), SkillError> {
        if self.delivered > self.installed
            || self.expanded > self.delivered
            || self.executed > self.delivered
            || self.verified > self.executed
            || self.useful > self.verified
            || self.failed + self.uncertain > self.executed
        {
            return Err(SkillError::InvalidField {
                field: "counters",
                reason: "lifecycle counts violate evidence ordering",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Observed,
    Failed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalCredit {
    NoCausalCredit,
    ObservedAssociation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillExecutionEvidence {
    pub execution_ref: String,
    pub exact_step_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub verifier_refs: Vec<String>,
    pub outcome: ExecutionOutcome,
    pub causal_credit: CausalCredit,
}

impl SkillExecutionEvidence {
    pub fn validate(&self) -> Result<(), SkillError> {
        text(&self.execution_ref, "execution.execution_ref")?;
        for (values, field) in [
            (&self.exact_step_refs, "execution.exact_step_refs"),
            (&self.artifact_refs, "execution.artifact_refs"),
            (&self.verifier_refs, "execution.verifier_refs"),
        ] {
            unique(values.iter().cloned(), field)?;
            for value in values {
                text(value, field)?;
            }
        }
        if self.outcome == ExecutionOutcome::Observed && self.exact_step_refs.is_empty() {
            return Err(SkillError::InvalidField {
                field: "execution.exact_step_refs",
                reason: "observed execution requires exact step evidence",
            });
        }
        if self.causal_credit != CausalCredit::NoCausalCredit {
            return Err(SkillError::InvalidField {
                field: "execution.causal_credit",
                reason: "Skill execution cannot claim causal credit",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillInteractionView {
    pub conflict_refs: Vec<String>,
    pub ordering_refs: Vec<String>,
    pub mutual_exclusion_refs: Vec<String>,
}

impl SkillInteractionView {
    pub fn validate(&self) -> Result<(), SkillError> {
        for (values, field) in [
            (&self.conflict_refs, "interaction.conflict_refs"),
            (&self.ordering_refs, "interaction.ordering_refs"),
            (
                &self.mutual_exclusion_refs,
                "interaction.mutual_exclusion_refs",
            ),
        ] {
            unique(values.iter().cloned(), field)?;
            for value in values {
                text(value, field)?;
            }
        }
        let conflicts: BTreeSet<_> = self.conflict_refs.iter().collect();
        if self
            .mutual_exclusion_refs
            .iter()
            .any(|reference| conflicts.contains(reference))
        {
            return Err(SkillError::InvalidField {
                field: "interaction",
                reason: "a conflict cannot also be an unqualified mutual exclusion",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleReview {
    pub evidence_refs: Vec<String>,
    pub review_ref: String,
    pub owner_ref: String,
    pub rollback_ref: String,
    pub rollback_artifact_digest: String,
    pub approval_ref: Option<String>,
    pub independent_route_count: u32,
}

impl LifecycleReview {
    pub fn validate(&self) -> Result<(), SkillError> {
        unique(self.evidence_refs.iter().cloned(), "review.evidence_refs")?;
        if self.evidence_refs.is_empty() {
            return Err(SkillError::InvalidField {
                field: "review.evidence_refs",
                reason: "promotion evidence is required",
            });
        }
        for reference in &self.evidence_refs {
            text(reference, "review.evidence_ref")?;
        }
        for (value, field) in [
            (&self.review_ref, "review.review_ref"),
            (&self.owner_ref, "review.owner_ref"),
            (&self.rollback_ref, "review.rollback_ref"),
        ] {
            text(value, field)?;
        }
        digest(
            &self.rollback_artifact_digest,
            "review.rollback_artifact_digest",
        )?;
        if self.independent_route_count == 0 {
            return Err(SkillError::IndependentEvidenceRequired);
        }
        if let Some(approval) = &self.approval_ref {
            text(approval, "review.approval_ref")?;
        }
        Ok(())
    }
}

/// One derived lifecycle view. It never asserts that the Skill caused an
/// outcome; it records exact evidence and bounded curation advice.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillLifecycleView {
    pub skill_ref: SkillRef,
    pub scope: SkillScope,
    pub applies_when: Vec<String>,
    pub does_not_apply_when: Vec<String>,
    pub dependencies: Vec<DependencyVersion>,
    pub counters: LifecycleCounters,
    pub execution_evidence: Vec<SkillExecutionEvidence>,
    pub observed_decision_or_verifier_delta: Option<String>,
    pub false_activation_refs: Vec<String>,
    pub interactions: SkillInteractionView,
    pub status: SkillStatus,
    pub stale_or_quarantine_reason: Option<String>,
    pub proposed_action: LifecycleAction,
    pub review: Option<LifecycleReview>,
    pub state_fence: StateFence,
    pub lifecycle_revision: u64,
}

impl SkillLifecycleView {
    /// Returns the stable skill identity carried by this view.
    pub fn skill_id(&self) -> &str {
        self.skill_ref.skill_id()
    }

    pub fn validate(&self) -> Result<(), SkillError> {
        self.skill_ref.validate()?;
        self.scope.validate()?;
        if self.applies_when.is_empty() || self.does_not_apply_when.is_empty() {
            return Err(SkillError::InvalidField {
                field: "applicability",
                reason: "both trigger and where-not-apply clauses are required",
            });
        }
        for (values, field) in [
            (&self.applies_when, "applies_when"),
            (&self.does_not_apply_when, "does_not_apply_when"),
            (&self.false_activation_refs, "false_activation_refs"),
        ] {
            unique(values.iter().cloned(), field)?;
            for value in values {
                text(value, field)?;
            }
        }
        unique(self.dependencies.iter().cloned(), "dependencies")?;
        for dependency in &self.dependencies {
            dependency.validate()?;
        }
        self.counters.validate()?;
        for evidence in &self.execution_evidence {
            evidence.validate()?;
        }
        let observed = self
            .execution_evidence
            .iter()
            .filter(|evidence| evidence.outcome == ExecutionOutcome::Observed)
            .count() as u64;
        let failed = self
            .execution_evidence
            .iter()
            .filter(|evidence| evidence.outcome == ExecutionOutcome::Failed)
            .count() as u64;
        let uncertain = self
            .execution_evidence
            .iter()
            .filter(|evidence| evidence.outcome == ExecutionOutcome::Uncertain)
            .count() as u64;
        let verified = self
            .execution_evidence
            .iter()
            .filter(|evidence| {
                evidence.outcome == ExecutionOutcome::Observed && !evidence.verifier_refs.is_empty()
            })
            .count() as u64;
        if self.counters.executed != observed
            || self.counters.failed != failed
            || self.counters.uncertain != uncertain
            || self.counters.verified != verified
        {
            return Err(SkillError::InvalidField {
                field: "counters",
                reason: "execution counters do not match exact evidence",
            });
        }
        if let Some(delta) = &self.observed_decision_or_verifier_delta {
            text(delta, "observed_decision_or_verifier_delta")?;
        }
        self.interactions.validate()?;
        self.state_fence
            .validate()
            .map_err(|error| SkillError::Surface(error.to_string()))?;
        if self.lifecycle_revision == 0 {
            return Err(SkillError::InvalidField {
                field: "lifecycle_revision",
                reason: "must be non-zero",
            });
        }
        match self.status {
            SkillStatus::Stale | SkillStatus::Quarantined
                if self
                    .stale_or_quarantine_reason
                    .as_deref()
                    .is_none_or(str::is_empty) =>
            {
                return Err(SkillError::InvalidField {
                    field: "stale_or_quarantine_reason",
                    reason: "stale and quarantined Skills require a reason",
                });
            }
            _ => {}
        }
        if self.proposed_action.is_reversible() {
            self.review
                .as_ref()
                .ok_or(SkillError::InvalidField {
                    field: "review",
                    reason: "lifecycle action requires a review and rollback binding",
                })?
                .validate()?;
        } else if self.review.is_some() {
            return Err(SkillError::InvalidField {
                field: "review",
                reason: "Keep cannot carry a mutation review",
            });
        }
        Ok(())
    }

    pub fn identity_digest(&self) -> Result<String, SkillError> {
        self.validate()?;
        value_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillCandidate {
    pub base_view_digest: String,
    pub base_skill_ref: SkillRef,
    pub candidate_package_digest: String,
    pub proposed_action: LifecycleAction,
    pub evidence_refs: Vec<String>,
    pub dependency_versions: Vec<DependencyVersion>,
    pub candidate_scope: SkillScope,
    pub candidate_digest: String,
    pub state_fence: StateFence,
}

impl SkillCandidate {
    pub fn new(
        base_view: &SkillLifecycleView,
        candidate_package_digest: String,
        proposed_action: LifecycleAction,
        evidence_refs: Vec<String>,
        dependency_versions: Vec<DependencyVersion>,
        candidate_scope: SkillScope,
        state_fence: StateFence,
    ) -> Result<Self, SkillError> {
        let base_view_digest = base_view.identity_digest()?;
        let mut value = Self {
            base_view_digest,
            base_skill_ref: base_view.skill_ref.clone(),
            candidate_package_digest,
            proposed_action,
            evidence_refs,
            dependency_versions,
            candidate_scope,
            candidate_digest: String::new(),
            state_fence,
        };
        value.candidate_digest = value.identity_digest()?;
        value.validate()?;
        Ok(value)
    }

    fn identity_digest(&self) -> Result<String, SkillError> {
        value_digest(&(
            &self.base_view_digest,
            &self.base_skill_ref,
            &self.candidate_package_digest,
            self.proposed_action,
            &self.evidence_refs,
            &self.dependency_versions,
            &self.candidate_scope,
            &self.state_fence,
        ))
    }

    pub fn validate(&self) -> Result<(), SkillError> {
        digest(&self.base_view_digest, "candidate.base_view_digest")?;
        self.base_skill_ref.validate()?;
        digest(
            &self.candidate_package_digest,
            "candidate.candidate_package_digest",
        )?;
        if !self.proposed_action.is_reversible() {
            return Err(SkillError::InvalidField {
                field: "candidate.proposed_action",
                reason: "a candidate must describe a governed lifecycle change",
            });
        }
        unique(
            self.evidence_refs.iter().cloned(),
            "candidate.evidence_refs",
        )?;
        if self.evidence_refs.is_empty() {
            return Err(SkillError::InvalidField {
                field: "candidate.evidence_refs",
                reason: "candidate evidence is required",
            });
        }
        for reference in &self.evidence_refs {
            text(reference, "candidate.evidence_ref")?;
        }
        unique(
            self.dependency_versions.iter().cloned(),
            "candidate.dependencies",
        )?;
        for dependency in &self.dependency_versions {
            dependency.validate()?;
        }
        self.candidate_scope.validate()?;
        self.state_fence
            .validate()
            .map_err(|error| SkillError::Surface(error.to_string()))?;
        digest(&self.candidate_digest, "candidate.candidate_digest")?;
        if self.identity_digest()? != self.candidate_digest {
            return Err(SkillError::IdentityMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionGate {
    pub candidate_digest: String,
    pub base_view_digest: String,
    pub verifier_ref: String,
    pub evidence_refs: Vec<String>,
    pub independent_route_count: u32,
    pub human_approval_ref: Option<String>,
    pub reversible: bool,
    pub state_fence: StateFence,
}

impl PromotionGate {
    pub fn validate_for(&self, candidate: &SkillCandidate) -> Result<(), SkillError> {
        candidate.validate()?;
        digest(&self.candidate_digest, "gate.candidate_digest")?;
        digest(&self.base_view_digest, "gate.base_view_digest")?;
        if self.candidate_digest != candidate.candidate_digest
            || self.base_view_digest != candidate.base_view_digest
        {
            return Err(SkillError::IdentityMismatch);
        }
        text(&self.verifier_ref, "gate.verifier_ref")?;
        unique(self.evidence_refs.iter().cloned(), "gate.evidence_refs")?;
        if self.evidence_refs.is_empty() || self.independent_route_count == 0 {
            return Err(SkillError::IndependentEvidenceRequired);
        }
        if self.state_fence != candidate.state_fence {
            return Err(SkillError::FenceMismatch);
        }
        if !self.reversible {
            return Err(SkillError::NonReversiblePromotion);
        }
        if (candidate.proposed_action == LifecycleAction::Merge
            || candidate.proposed_action == LifecycleAction::Split
            || self.independent_route_count > 1)
            && (self.independent_route_count < 2 || self.human_approval_ref.is_none())
        {
            return Err(SkillError::IndependentEvidenceRequired);
        }
        if let Some(approval) = &self.human_approval_ref {
            text(approval, "gate.human_approval_ref")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillPromotionReceipt {
    pub candidate_digest: String,
    pub base_view_digest: String,
    pub promoted_skill_ref: SkillRef,
    pub action: LifecycleAction,
    pub verifier_ref: String,
    pub evidence_refs: Vec<String>,
    pub state_fence: StateFence,
    pub receipt_digest: String,
}

impl SkillPromotionReceipt {
    fn identity_digest(&self) -> Result<String, SkillError> {
        value_digest(&(
            &self.candidate_digest,
            &self.base_view_digest,
            &self.promoted_skill_ref,
            self.action,
            &self.verifier_ref,
            &self.evidence_refs,
            &self.state_fence,
        ))
    }

    pub fn validate(&self) -> Result<(), SkillError> {
        digest(&self.candidate_digest, "receipt.candidate_digest")?;
        digest(&self.base_view_digest, "receipt.base_view_digest")?;
        self.promoted_skill_ref.validate()?;
        text(&self.verifier_ref, "receipt.verifier_ref")?;
        unique(self.evidence_refs.iter().cloned(), "receipt.evidence_refs")?;
        if self.evidence_refs.is_empty() {
            return Err(SkillError::InvalidField {
                field: "receipt.evidence_refs",
                reason: "promotion evidence is required",
            });
        }
        self.state_fence
            .validate()
            .map_err(|error| SkillError::Surface(error.to_string()))?;
        digest(&self.receipt_digest, "receipt.receipt_digest")?;
        if self.identity_digest()? != self.receipt_digest {
            return Err(SkillError::IdentityMismatch);
        }
        Ok(())
    }
}

/// Governor lifecycle owner. Persistence and delivery are delegated to the
/// canonical store; this state machine never treats installation as usefulness.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillRegistry {
    views: BTreeMap<String, SkillLifecycleView>,
}

impl SkillRegistry {
    /// Rebuilds the registry from its canonical lifecycle views.
    pub fn from_snapshot(
        views: impl IntoIterator<Item = SkillLifecycleView>,
    ) -> Result<Self, SkillError> {
        let mut registry = Self::default();
        for view in views {
            registry.record_view(view)?;
        }
        Ok(registry)
    }

    pub fn record_view(&mut self, view: SkillLifecycleView) -> Result<(), SkillError> {
        view.validate()?;
        let key = view.skill_id().to_owned();
        if let Some(previous) = self.views.get(&key) {
            if previous.state_fence != view.state_fence {
                return Err(SkillError::FenceMismatch);
            }
            if view.lifecycle_revision <= previous.lifecycle_revision {
                return Err(SkillError::RevisionConflict);
            }
        }
        self.views.insert(key, view);
        Ok(())
    }

    pub fn view(&self, skill_id: &str) -> Option<&SkillLifecycleView> {
        self.views.get(skill_id)
    }

    /// Explicit fields mirror the public lifecycle/API contract.
    #[allow(clippy::too_many_arguments)]
    pub fn propose(
        &self,
        base_skill_id: &str,
        candidate_package_digest: String,
        action: LifecycleAction,
        evidence_refs: Vec<String>,
        dependencies: Vec<DependencyVersion>,
        candidate_scope: SkillScope,
        state_fence: StateFence,
    ) -> Result<SkillCandidate, SkillError> {
        let base = self.views.get(base_skill_id).ok_or(SkillError::NotFound)?;
        if base.state_fence != state_fence {
            return Err(SkillError::FenceMismatch);
        }
        SkillCandidate::new(
            base,
            candidate_package_digest,
            action,
            evidence_refs,
            dependencies,
            candidate_scope,
            state_fence,
        )
    }

    pub fn promote(
        &mut self,
        candidate: &SkillCandidate,
        gate: &PromotionGate,
        promoted_view: SkillLifecycleView,
    ) -> Result<SkillPromotionReceipt, SkillError> {
        candidate.validate()?;
        gate.validate_for(candidate)?;
        promoted_view.validate()?;
        let base = self
            .views
            .get(candidate.base_skill_ref.skill_id())
            .ok_or(SkillError::NotFound)?;
        if base.identity_digest()? != candidate.base_view_digest
            || promoted_view.skill_id() != candidate.base_skill_ref.skill_id()
            || promoted_view.state_fence != candidate.state_fence
            || promoted_view.skill_ref.package_digest != candidate.candidate_package_digest
            || promoted_view.lifecycle_revision <= base.lifecycle_revision
        {
            return Err(SkillError::IdentityMismatch);
        }
        let receipt = SkillPromotionReceipt {
            candidate_digest: candidate.candidate_digest.clone(),
            base_view_digest: candidate.base_view_digest.clone(),
            promoted_skill_ref: promoted_view.skill_ref.clone(),
            action: candidate.proposed_action,
            verifier_ref: gate.verifier_ref.clone(),
            evidence_refs: gate.evidence_refs.clone(),
            state_fence: candidate.state_fence.clone(),
            receipt_digest: String::new(),
        };
        let mut receipt = receipt;
        receipt.receipt_digest = receipt.identity_digest()?;
        receipt.validate()?;
        self.views
            .insert(promoted_view.skill_id().to_owned(), promoted_view);
        Ok(receipt)
    }
}

#[derive(Debug, Error)]
pub enum SkillRegistryLookupError {
    #[error("Skill lifecycle view not found")]
    NotFound,
    #[error(transparent)]
    Lifecycle(#[from] SkillError),
}

#[allow(async_fn_in_trait)]
pub trait SkillLifecycleApi: Send + Sync {
    async fn view(
        &self,
        ctx: &RequestMetadata,
        skill_id: String,
    ) -> Result<Option<SkillLifecycleView>, SkillError>;

    /// Explicit fields mirror the public lifecycle/API contract.
    #[allow(clippy::too_many_arguments)]
    async fn propose(
        &self,
        ctx: &RequestMetadata,
        skill_id: String,
        candidate_package_digest: String,
        action: LifecycleAction,
        evidence_refs: Vec<String>,
        dependencies: Vec<DependencyVersion>,
        scope: SkillScope,
    ) -> Result<SkillCandidate, SkillError>;

    async fn promote(
        &self,
        ctx: &RequestMetadata,
        candidate: SkillCandidate,
        gate: PromotionGate,
        promoted_view: SkillLifecycleView,
    ) -> Result<SkillPromotionReceipt, SkillError>;
}
