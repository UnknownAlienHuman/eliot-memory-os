//! Shared identity for one admitted attempt's stop boundary.
//!
//! This lower-layer value is carried unchanged by Governor, Kernel, ORS, and
//! the protocol. It contains owner-issued identifiers and the full State Fence
//! but owns no admission, stop, or Finish decision policy.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContractError, StateFence, TaskId};

/// Exact owner-issued association between a Governor admission, its frozen
/// Task Controller definition, and one operationally admitted task attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StopBoundaryAdmissionBinding {
    /// Governor-issued semantic admission identity.
    pub admission_id: String,
    /// Store-owned revision of the exact Governor admission record.
    pub admission_owner_revision: u64,
    /// Exact opaque Governor receipt bound by the admitted semantic record.
    pub admission_receipt: String,
    /// Task Controller definition identity admitted by Governor.
    pub definition_id: String,
    /// Digest of the exact frozen definition bytes.
    pub definition_digest: String,
    /// Task identity from the exact frozen definition.
    pub task_id: TaskId,
    /// Task revision from the exact frozen definition.
    pub task_revision: String,
    /// Concrete attempt identity registered by the canonical admission.
    pub attempt_id: String,
    /// Full fence carried by the exact admission and activation receipts.
    pub state_fence: StateFence,
}

impl StopBoundaryAdmissionBinding {
    /// Validates identity shape and the canonical positive task revision.
    pub fn validate(&self) -> Result<(), ContractError> {
        for (value, field) in [
            (&self.admission_id, "stop_boundary.admission_id"),
            (&self.admission_receipt, "stop_boundary.admission_receipt"),
            (&self.definition_id, "stop_boundary.definition_id"),
            (&self.definition_digest, "stop_boundary.definition_digest"),
            (&self.task_revision, "stop_boundary.task_revision"),
            (&self.attempt_id, "stop_boundary.attempt_id"),
        ] {
            crate::validate_text(value, field)?;
        }
        if self.admission_owner_revision == 0 {
            return Err(ContractError::Zero {
                field: "stop_boundary.admission_owner_revision",
            });
        }
        if self
            .task_revision
            .parse::<u64>()
            .ok()
            .filter(|revision| revision.to_string() == self.task_revision)
            .filter(|revision| *revision > 0)
            .is_none()
        {
            return Err(ContractError::InvalidField {
                field: "stop_boundary.task_revision",
                reason: "must be a canonical positive decimal TaskRevision",
            });
        }
        self.state_fence.validate()?;
        Ok(())
    }
}
