//! Shared context, provenance, lifecycle, privacy and proof closure.

use eliot_contracts::{StateFence, TaskId};
use eliot_evidence::{EvidenceEnvelope, EvidenceError, LifecycleState};
use eliot_receipts::{ProofCeiling, WorkScopeId};
use eliot_security_contracts::PrivacyClass;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::CueContractError;

/// Exact context in which an observation or derived cue is usable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CueContext {
    /// Task that owns the observation.
    pub task_id: TaskId,
    /// Work scope in which the observation is valid.
    pub scope_id: WorkScopeId,
    /// State fence captured with the observation.
    pub state_fence: StateFence,
    /// Independent authority, freshness, coverage, epistemic and provenance
    /// envelope for the observation.
    pub evidence: EvidenceEnvelope,
    /// Physical lifecycle of the referenced material.
    pub lifecycle: LifecycleState,
    /// Disclosure class of the referenced material.
    pub privacy: PrivacyClass,
    /// Maximum proof interpretation available at this boundary.
    pub proof_ceiling: ProofCeiling,
}

impl CueContext {
    /// Constructs the complete context closure.
    #[must_use]
    pub const fn new(
        task_id: TaskId,
        scope_id: WorkScopeId,
        state_fence: StateFence,
        evidence: EvidenceEnvelope,
        lifecycle: LifecycleState,
        privacy: PrivacyClass,
        proof_ceiling: ProofCeiling,
    ) -> Self {
        Self {
            task_id,
            scope_id,
            state_fence,
            evidence,
            lifecycle,
            privacy,
            proof_ceiling,
        }
    }

    /// Validates all lower-level context owners without promoting the record.
    pub fn validate(&self) -> Result<(), CueContractError> {
        crate::bounds::text(self.task_id.as_str(), "context.task_id")?;
        crate::bounds::text(self.scope_id.as_str(), "context.scope_id")?;
        let provenance = &self.evidence.provenance;
        crate::bounds::provenance(provenance, "context.evidence.provenance")?;
        if let Some(binding) = self.evidence.verification.as_ref() {
            crate::bounds::text(
                binding.contract_id.as_str(),
                "context.verification.contract_id",
            )?;
            crate::bounds::text(binding.run_id.as_str(), "context.verification.run_id")?;
            crate::bounds::text(&binding.revision, "context.verification.revision")?;
        }
        self.state_fence
            .validate()
            .map_err(|_| CueContractError::Foundation {
                field: "context.state_fence",
            })?;
        self.evidence.validate().map_err(|error| match error {
            EvidenceError::InvalidText { field } => CueContractError::InvalidText { field },
            _ => CueContractError::Foundation {
                field: "context.evidence",
            },
        })?;
        if self.evidence.state_fence != self.state_fence {
            return Err(CueContractError::Foundation {
                field: "context.state_fence",
            });
        }
        Ok(())
    }
}
