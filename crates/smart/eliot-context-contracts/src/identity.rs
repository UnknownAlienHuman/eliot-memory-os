//! Canonical identity and source lineage used by every Context stage.

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, ContractVersion, DecisionId, OperationId, StateFence, TaskId, TaskRevision,
};
use eliot_receipts::{ProofCeiling, WorkScopeId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContextError, validate_digest, validate_text};

/// Stable identity of the Context contract family.
pub const CONTEXT_CONTRACT_NAME: &str = "eliot.smart.context-contracts";
/// Current closed wire version.
pub const CONTEXT_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// A validated provider identity. Providers are labels in this contract; they
/// do not receive authority or become mutable owners.
#[derive(
    Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(try_from = "String")]
pub struct ProviderId(String);

impl ProviderId {
    /// Construct a bounded provider identity.
    pub fn new(value: impl Into<String>) -> Result<Self, ContextError> {
        let value = value.into();
        validate_text(&value, "provider_id")?;
        if value.chars().count() > 128 {
            return Err(ContextError::Bounds {
                field: "provider_id",
            });
        }
        Ok(Self(value))
    }

    /// Return the canonical provider text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProviderId {
    type Error = ContextError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Semantic role of a whole Context unit.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SemanticRole {
    Authority,
    Goal,
    Scope,
    Acceptance,
    Source,
    Verifier,
    MaterialUnknown,
    Negative,
    Security,
    Evidence,
    Instruction,
    Optional,
    Conflict,
    Constraint,
    DecisionTail,
}

/// Provider/semantic-role slot in the exact requested denominator.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderRole {
    /// Provider that owns the projection.
    pub provider: ProviderId,
    /// Semantic role supplied by that provider.
    pub role: SemanticRole,
}

impl ProviderRole {
    /// Validate the slot identity.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(self.provider.as_str(), "provider_role.provider")
    }
}

/// Canonical foundation identity binding shared by packet, candidate, set,
/// view and receipts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextBinding {
    /// Durable task identity.
    pub task_id: TaskId,
    /// Attempt identity owned by the agent contract.
    pub attempt_id: AgentAttemptId,
    /// Exact work scope.
    pub scope_id: WorkScopeId,
    /// Fence that all material must satisfy.
    pub state_fence: StateFence,
    /// Decision identity for this compilation.
    pub decision_id: DecisionId,
    /// Idempotent operation identity, when a request is being observed.
    pub operation_id: Option<OperationId>,
}

impl ContextBinding {
    /// Validate all identity-bearing dependencies.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(self.scope_id.as_str(), "scope_id")?;
        validate_text(self.attempt_id.as_str(), "attempt_id")?;
        validate_text(self.task_id.as_str(), "task_id")?;
        validate_text(self.decision_id.as_str(), "decision_id")?;
        if let Some(operation) = &self.operation_id {
            validate_text(operation.as_str(), "operation_id")?;
        }
        self.state_fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        if self.scope_id.as_str().chars().count() > 256 {
            return Err(ContextError::Bounds { field: "scope_id" });
        }
        Ok(())
    }
}

/// Immutable source snapshot lineage for a whole atom.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshot {
    /// Stable source owner identity.
    pub source_id: eliot_contracts::SourceId,
    /// Source owner/provider label.
    pub owner: ProviderId,
    /// Snapshot identity within the source owner.
    pub snapshot_id: ArtifactId,
    /// Source revision used for this snapshot.
    pub revision: String,
    /// Content digest of the complete source snapshot.
    pub content_sha256: String,
    /// Prior snapshot in the immutable lineage.
    pub predecessor: Option<ArtifactId>,
}

impl SourceSnapshot {
    /// Validate source lineage and canonical digest shape.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(&self.revision, "source.revision")?;
        validate_digest(&self.content_sha256, "source.content_sha256")?;
        validate_text(self.owner.as_str(), "source.owner")?;
        if self.predecessor.as_ref() == Some(&self.snapshot_id) {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

/// A reference to a decision revision used by an omission or measurement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionRevision {
    /// Context decision binding.
    pub decision_id: DecisionId,
    /// Recipe revision under which it was admitted.
    pub recipe_revision: TaskRevision,
    /// Canonical digest of the decision policy.
    pub policy_sha256: String,
}

impl DecisionRevision {
    /// Validate decision revision identity.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_digest(&self.policy_sha256, "decision.policy_sha256")
    }
}

/// A compact identity/proof ceiling reference used by contract records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProofBinding {
    /// Source evidence identity.
    pub evidence_id: ArtifactId,
    /// Maximum claim this package can support.
    pub ceiling: ProofCeiling,
}
