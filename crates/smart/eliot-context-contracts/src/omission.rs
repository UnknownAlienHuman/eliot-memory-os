//! Reversible omission handles bound to the complete decision identity.

use eliot_contracts::{ArtifactId, TaskRevision};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContextBinding, ContextError, DecisionRevision, LossPolicy, ProviderRole, validate_digest,
    validate_text,
};

/// Why an atom was omitted, including the competing constraint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OmissionReason {
    Capacity,
    ProtectedReserve,
    Stale,
    Blocked,
    Privacy,
    Authority,
    Unavailable,
    Policy,
}

/// Typed explanation for an omission that cannot be reopened.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NonRecoverableReason {
    Privacy,
    Authority,
    SourceUnavailable,
    Expired,
    PolicyDisallows,
}

/// Exact handle allowing a permitted omitted unit to be reopened.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpansionHandle {
    pub handle_id: ArtifactId,
    pub atom_id: ArtifactId,
    pub source_id: ArtifactId,
    pub source_revision: String,
    pub context: ContextBinding,
    pub decision: DecisionRevision,
    pub policy: LossPolicy,
    pub provider_role: ProviderRole,
    pub handle_digest: String,
    pub expires: Option<ArtifactId>,
    pub invalidation: Option<ArtifactId>,
}

impl ExpansionHandle {
    /// Validate all replay boundaries.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.context.validate()?;
        self.decision.validate()?;
        self.provider_role.validate()?;
        validate_text(&self.source_revision, "handle.source_revision")?;
        validate_digest(&self.handle_digest, "handle.handle_digest")
    }
}

/// A complete omission record with cost, policy and reconstruction evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OmissionRecord {
    pub atom_id: ArtifactId,
    pub source_id: ArtifactId,
    pub provider_role: ProviderRole,
    pub decision: DecisionRevision,
    pub task_revision: TaskRevision,
    pub reason: OmissionReason,
    pub competing_constraint: String,
    pub measured_cost: u64,
    pub allowed_representation: LossPolicy,
    pub expansion: Option<ExpansionHandle>,
    pub non_recoverable_reason: Option<NonRecoverableReason>,
    pub authorization_requirement: String,
    pub privacy_requirement: String,
    pub proof_requirement: String,
    pub expires: Option<ArtifactId>,
    pub invalidation: Option<ArtifactId>,
    pub digest: String,
}

impl OmissionRecord {
    /// Enforce reversible versus explicitly non-recoverable semantics.
    pub fn validate(&self, context: &ContextBinding) -> Result<(), ContextError> {
        if self.measured_cost == 0 {
            return Err(ContextError::InvalidField("omission.measured_cost"));
        }
        validate_text(&self.competing_constraint, "omission.competing_constraint")?;
        validate_text(
            &self.authorization_requirement,
            "omission.authorization_requirement",
        )?;
        validate_text(&self.privacy_requirement, "omission.privacy_requirement")?;
        validate_text(&self.proof_requirement, "omission.proof_requirement")?;
        validate_digest(&self.digest, "omission.digest")?;
        if context.state_fence.task_revision != Some(self.task_revision) {
            return Err(ContextError::OmissionHandleInvalid);
        }
        if self.decision.decision_id != context.decision_id {
            return Err(ContextError::OmissionHandleInvalid);
        }
        match (&self.expansion, &self.non_recoverable_reason) {
            (Some(handle), None) => {
                handle.validate()?;
                if &handle.context != context
                    || handle.decision != self.decision
                    || handle.atom_id != self.atom_id
                    || handle.source_id != self.source_id
                    || handle.provider_role != self.provider_role
                    || handle.policy != self.allowed_representation
                    || handle.expires != self.expires
                    || handle.invalidation != self.invalidation
                {
                    return Err(ContextError::OmissionHandleInvalid);
                }
            }
            (None, Some(_reason)) => {}
            _ => return Err(ContextError::OmissionHandleInvalid),
        }
        Ok(())
    }
}
