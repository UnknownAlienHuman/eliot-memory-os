//! Neutral binding projections for index construction.

use eliot_contracts::{StateFence, TaskId};
use eliot_receipts::{ReceiptIdentity, WorkScopeId};
use serde::{Deserialize, Serialize};

use crate::{BindingCandidateId, CueBindingCandidate, CueContractError, Digest, NormalizedCue};

/// An opaque external assertion that a candidate was admitted by an external
/// Governor. A-10 checks joins and shape; it neither authenticates nor issues
/// admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CueBindingAdmissionRef {
    pub receipt: ReceiptIdentity,
    pub candidate_id: BindingCandidateId,
    pub candidate_digest: Digest,
    pub task_id: TaskId,
    pub scope_id: WorkScopeId,
    pub state_fence: StateFence,
}

impl CueBindingAdmissionRef {
    /// Creates an opaque externally supplied admission assertion.
    #[must_use]
    pub const fn new(
        receipt: ReceiptIdentity,
        candidate_id: BindingCandidateId,
        candidate_digest: Digest,
        task_id: eliot_contracts::TaskId,
        scope_id: WorkScopeId,
        state_fence: StateFence,
    ) -> Self {
        Self {
            receipt,
            candidate_id,
            candidate_digest,
            task_id,
            scope_id,
            state_fence,
        }
    }

    pub fn validate_against(
        &self,
        candidate: &CueBindingCandidate,
        normalized: &NormalizedCue,
    ) -> Result<(), CueContractError> {
        let mut measured = 0;
        crate::index_bounds::candidate_and_normalized(&mut measured, candidate, normalized)?;
        crate::bounds::text(self.candidate_id.as_str(), "admission.candidate_id")?;
        crate::bounds::text(self.task_id.as_str(), "admission.task_id")?;
        crate::bounds::text(self.scope_id.as_str(), "admission.scope_id")?;
        crate::bounds::text(
            normalized.observed.context.task_id.as_str(),
            "admission.context.task_id",
        )?;
        crate::bounds::text(
            normalized.observed.context.scope_id.as_str(),
            "admission.context.scope_id",
        )?;
        crate::bounds::text(self.receipt.receipt_id.as_str(), "admission.receipt_id")?;
        crate::bounds::text(&self.receipt.canonical_sha256, "admission.receipt_digest")?;
        if Digest::new(self.receipt.canonical_sha256.clone()).is_err()
            || self.receipt.receipt_id.as_str()
                != format!("receipt-{}", self.receipt.canonical_sha256)
            || self.candidate_id != candidate.binding_candidate_id
            || self.candidate_digest != candidate.digest
        {
            return Err(CueContractError::Foundation {
                field: "admission.candidate",
            });
        }
        if self.task_id != normalized.observed.context.task_id
            || self.scope_id != normalized.observed.context.scope_id
            || self.state_fence != normalized.observed.context.state_fence
        {
            return Err(CueContractError::Foundation {
                field: "admission.context",
            });
        }
        candidate.validate()?;
        normalized.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| CueContractError::Foundation {
                field: "admission.state_fence",
            })
    }
}

/// A candidate plus the exact normalized source and external admission join.
/// The original A-12 proposal, including a `Withheld` disposition and its
/// digest, remains unchanged; the separate admission reference is only an
/// external assertion. This crate does not authenticate or publish it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AdmittedCueBindingProjection {
    pub candidate: CueBindingCandidate,
    pub normalized: NormalizedCue,
    pub admission: CueBindingAdmissionRef,
}

impl AdmittedCueBindingProjection {
    /// Creates a projection retaining its proposal, source and external join.
    #[must_use]
    pub const fn new(
        candidate: CueBindingCandidate,
        normalized: NormalizedCue,
        admission: CueBindingAdmissionRef,
    ) -> Self {
        Self {
            candidate,
            normalized,
            admission,
        }
    }

    pub fn validate(&self) -> Result<(), CueContractError> {
        let mut measured = 0;
        crate::index_bounds::projection(&mut measured, self)?;
        self.candidate.validate()?;
        self.normalized.validate()?;
        if matches!(
            self.candidate.disposition,
            crate::BindingDisposition::Rejected
        ) {
            return Err(CueContractError::Foundation {
                field: "projection.rejected",
            });
        }
        if self.normalized.canonical.as_ref() != Some(&self.candidate.canonical) {
            return Err(CueContractError::Foundation {
                field: "projection.canonical",
            });
        }
        self.admission
            .validate_against(&self.candidate, &self.normalized)
    }
}
