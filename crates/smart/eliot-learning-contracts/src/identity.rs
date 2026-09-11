//! Shared typed identities and the single cross-record binding.

pub use eliot_agent_contracts::{AgentAttemptId, TargetId};
use eliot_contracts::{
    ArtifactId, ContractError, OperationId, PolicyRevision, ProductId, RequestId, SourceId,
    StateFence, TaskId, TaskRevision, canonical_json_bytes, sha256_hex,
};
pub use eliot_receipts::{ProofCeiling, WorkScopeId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::LearningContractError;

/// Current wire revision for this contract family.
pub const LEARNING_SCHEMA_VERSION: u16 = 1;

macro_rules! artifact_wrapper {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
        #[serde(transparent)]
        #[schemars(transparent)]
        pub struct $name(ArtifactId);

        impl $name {
            /// Wrap an existing foundation artifact identity.
            pub const fn from_artifact(value: ArtifactId) -> Self { Self(value) }
            /// Return the underlying stable identity.
            pub const fn as_artifact(&self) -> &ArtifactId { &self.0 }
            /// Return the canonical identity text.
            pub fn as_str(&self) -> &str { self.0.as_str() }
            /// Validate that the wrapper carries a nonblank foundation identity.
            pub fn validate(&self) -> Result<(), LearningContractError> {
                if self.0.as_str().trim().is_empty() {
                    Err(LearningContractError::Missing { field: $field })
                } else { Ok(()) }
            }
        }
    };
}

artifact_wrapper!(/// Campaign identity, kept separate from task identity.
    CampaignId, "campaign_id");
artifact_wrapper!(/// Target identity used where a semantic name is required.
    LearningTargetId, "learning_target_id");
artifact_wrapper!(/// Overlay candidate identity.
    OverlayId, "overlay_id");
artifact_wrapper!(/// Declared recipe slot identity.
    SlotId, "slot_id");
artifact_wrapper!(/// Declared source/member identity.
    MemberId, "member_id");
artifact_wrapper!(/// Owner identity for a projection or receipt.
    OwnerId, "owner_id");

/// Source owner, snapshot and revision clock kept together for lineage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceLineage {
    /// Source owner identity.
    pub owner: SourceId,
    /// Immutable source snapshot identity.
    pub snapshot: ArtifactId,
    /// Source-local revision clock.
    pub revision: TaskRevision,
    /// Content digest of the source snapshot.
    pub digest: String,
}

impl SourceLineage {
    /// Validate source identities and digest shape without inspecting content.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        if self.owner.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "source.owner",
            });
        }
        if self.snapshot.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "source.snapshot",
            });
        }
        validate_digest(&self.digest, "source.digest")
    }
}

/// Request, operation, task, scope and fence shared by every durable candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContractBinding {
    /// Current wire revision.
    pub schema_version: u16,
    /// Policy snapshot used to interpret the contract.
    pub policy_revision: PolicyRevision,
    /// Caller request identity.
    pub request_id: RequestId,
    /// Operation identity, distinct from request idempotency.
    pub operation_id: OperationId,
    /// Product identity.
    pub product_id: ProductId,
    /// Task identity.
    pub task_id: TaskId,
    /// Task-local work scope.
    pub scope: WorkScopeId,
    /// Foundation state fence.
    pub state_fence: StateFence,
    /// Source revision lineage.
    pub source: SourceLineage,
    /// This package never emits a higher ceiling.
    pub proof_ceiling: ProofCeiling,
}

impl ContractBinding {
    /// Validate all identity and boundary fields.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        if self.schema_version != LEARNING_SCHEMA_VERSION {
            return Err(LearningContractError::ScopeMismatch {
                field: "schema_version",
            });
        }
        for (value, field) in [
            (self.request_id.as_str(), "request_id"),
            (self.operation_id.as_str(), "operation_id"),
            (self.product_id.as_str(), "product_id"),
            (self.task_id.as_str(), "task_id"),
        ] {
            if value.trim().is_empty() {
                return Err(LearningContractError::Missing { field });
            }
        }
        if self.scope.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing { field: "scope" });
        }
        self.state_fence
            .validate()
            .map_err(|_: ContractError| LearningContractError::Foundation)?;
        self.source.validate()?;
        if self.proof_ceiling != ProofCeiling::CandidateArtifact {
            return Err(LearningContractError::CandidateCeiling);
        }
        Ok(())
    }
}

/// Validate a digest without returning the supplied value in diagnostics.
pub fn validate_digest(value: &str, field: &'static str) -> Result<(), LearningContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(LearningContractError::InvalidDigest { field });
    }
    Ok(())
}

/// Validate a foundation identity imported from an owner contract.
pub fn validate_external_id(value: &str, field: &'static str) -> Result<(), LearningContractError> {
    if value.trim().is_empty() {
        Err(LearningContractError::Missing { field })
    } else if value.chars().any(char::is_control) {
        Err(LearningContractError::ScopeMismatch { field })
    } else {
        Ok(())
    }
}

/// Compute a canonical digest after removing the record's own digest field.
pub fn digest_without_field<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<String, LearningContractError> {
    let mut json =
        serde_json::to_value(value).map_err(|_| LearningContractError::Canonicalization)?;
    if let Some(object) = json.as_object_mut() {
        object.remove(field);
    }
    let bytes = canonical_json_bytes(&json).map_err(|_| LearningContractError::Canonicalization)?;
    Ok(sha256_hex(&bytes))
}
