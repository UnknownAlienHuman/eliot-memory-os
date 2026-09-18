//! Typed Governor/caller projection for closed Store failures.
//!
//! The Store bridge, Kernel, and ORS already carry the closed owner
//! [`StoreFailure`] envelope. This module is the Governor (`eliotd`, issue
//! #18) caller-side read-only projection: it consumes that exact envelope and
//! exposes its bounded reason, disposition, mutation, retry, recovery, and
//! evidence identity plus the next safe Store action, without creating a
//! second failure taxonomy and without deciding task, `Problem`, or `Finish`
//! state.
//!
//! Control meaning comes only from the typed [`StoreFailureDisposition`],
//! [`StoreMutationDisposition`], [`StoreRetryDirective`],
//! [`StoreRecoveryAction`], and [`StoreReasonCode`] fields. The optional
//! `human_detail` prose is exposed for diagnostics only and never steers
//! retry, reconciliation, or task state. No `Display`, `Debug`, provider, or
//! transport text is parsed for control, and no provider database types cross
//! this boundary.
//!
//! A retained ORS [`StoreFailureRetentionRecord`](eliot_ors_note) envelope is
//! projected by passing its `failure` field to [`GovernorStoreFailureProjection::from_failure`];
//! ORS binding digests stay owned by ORS and are never reinterpreted here.
//! A `Committed` mutation is never representable as a failure: it requires a
//! verified [`WriteReceipt`] bound to the exact operation, never this
//! projection, and never task promotion or authority.
//!
//! An [`UnknownOutcome`](StoreFailureDisposition::UnknownOutcome) projection
//! is always reconciling: it keeps the exact operation identity, requires an
//! exact-operation receipt query or reconciliation before any retry, and is
//! never reported as unavailable, failed, absent, or safe-to-retry. Blind
//! retry and alternate-operation substitution after a possible commit are
//! forbidden.
//!
//! [eliot_ors_note]: https://github.com/UnknownAlienHuman/eliot-memory-os/issues/451

use eliot_contracts::RequestId;
use eliot_store_api::{
    OperationId, STORE_FAILURE_CONTRACT_REVISION, StateFence, StoreConflictObservation,
    StoreFailure, StoreFailureDisposition, StoreMutationDisposition, StoreReasonCode,
    StoreRecoveryAction, StoreRetryDirective, WriteReceipt,
};

/// Bounded construction error for the Governor Store failure projection.
///
/// Variants use fixed strings only. Owner [`StoreFailure`] prose, provider
/// text, and transport status are discarded on mapping and can never change
/// control meaning.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GovernorStoreProjectionError {
    /// The envelope carries an unknown Store failure contract revision.
    #[error("unsupported store failure contract revision")]
    UnsupportedContractRevision,
    /// The owner Store failure contract rejected the envelope.
    #[error("owner store failure contract rejected the envelope")]
    OwnerContractRejected,
    /// The retained failure carries another operation identity.
    #[error("retained failure must bind the exact retained operation")]
    OperationMismatch,
    /// A reconciling receipt does not bind the exact projected operation.
    #[error("reconciling receipt does not bind the exact projected operation")]
    ReceiptOperationMismatch,
    /// A reconciling receipt envelope is invalid.
    #[error("reconciling receipt envelope is invalid")]
    InvalidReceipt,
}

/// Typed Governor/caller projection over one closed [`StoreFailure`].
///
/// The envelope is retained verbatim. All control queries branch only on its
/// typed disposition, mutation, retry, and recovery fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernorStoreFailureProjection {
    failure: StoreFailure,
}

impl GovernorStoreFailureProjection {
    /// Projects one closed [`StoreFailure`] after owner validation.
    ///
    /// Rejects unknown contract revisions before adopting control meaning,
    /// rejects `Committed` mutations (which require a verified
    /// [`WriteReceipt` instead), and maps owner prose to a fixed error.
    pub fn from_failure(failure: &StoreFailure) -> Result<Self, GovernorStoreProjectionError> {
        if failure.contract_revision != STORE_FAILURE_CONTRACT_REVISION {
            return Err(GovernorStoreProjectionError::UnsupportedContractRevision);
        }
        failure
            .validate()
            .map_err(|_| GovernorStoreProjectionError::OwnerContractRejected)?;
        if failure.mutation_disposition == StoreMutationDisposition::Committed {
            return Err(GovernorStoreProjectionError::OwnerContractRejected);
        }
        Ok(Self {
            failure: failure.clone(),
        })
    }

    /// Projects one closed [`StoreFailure`] pinned to the exact admitted operation.
    ///
    /// A failure carrying another operation identity is rejected; a failure
    /// carrying no operation identity is accepted because it asserts no
    /// conflicting identity. Request, fence, and idempotency pinning stay
    /// owned by the Kernel exchange and ORS retention and are not re-decided
    /// here.
    pub fn from_failure_for_operation(
        failure: &StoreFailure,
        operation_id: &OperationId,
    ) -> Result<Self, GovernorStoreProjectionError> {
        let projected = Self::from_failure(failure)?;
        if let Some(observed) = projected.failure.operation_id.as_ref()
            && observed != operation_id
        {
            return Err(GovernorStoreProjectionError::OperationMismatch);
        }
        Ok(projected)
    }

    /// Returns the retained closed envelope.
    #[must_use]
    pub fn failure(&self) -> &StoreFailure {
        &self.failure
    }

    /// Returns the typed failure disposition.
    #[must_use]
    pub fn disposition(&self) -> StoreFailureDisposition {
        self.failure.disposition
    }

    /// Returns the additive provider-neutral reason token.
    #[must_use]
    pub fn reason_code(&self) -> &StoreReasonCode {
        &self.failure.reason_code
    }

    /// Returns what is known about the mutation when the failure was reported.
    #[must_use]
    pub fn mutation_disposition(&self) -> StoreMutationDisposition {
        self.failure.mutation_disposition
    }

    /// Returns the next safe retry or reconciliation operation.
    ///
    /// Together with [`Self::recovery_action`] and
    /// [`Self::requires_exact_operation_reconcile`], this is the complete
    /// next safe Store action. It never grants task promotion, `Finish`,
    /// success, or authority.
    #[must_use]
    pub fn retry_directive(&self) -> StoreRetryDirective {
        self.failure.retry_directive
    }

    /// Returns the bounded recovery action, granting no authority.
    #[must_use]
    pub fn recovery_action(&self) -> StoreRecoveryAction {
        self.failure.recovery_action
    }

    /// Returns the exact operation identity when the envelope carries one.
    #[must_use]
    pub fn operation_id(&self) -> Option<&OperationId> {
        self.failure.operation_id.as_ref()
    }

    /// Returns the exact request identity when the envelope carries one.
    #[must_use]
    pub fn request_id(&self) -> Option<&RequestId> {
        self.failure.request_id.as_ref()
    }

    /// Returns the exact fence projection when the envelope carries one.
    #[must_use]
    pub fn state_fence(&self) -> Option<&StateFence> {
        self.failure
            .state_fence_ref_or_exact_safe_projection
            .as_ref()
    }

    /// Returns the idempotency key reference or digest when present.
    #[must_use]
    pub fn idempotency_key_ref_or_digest(&self) -> Option<&str> {
        self.failure.idempotency_key_ref_or_digest.as_deref()
    }

    /// Returns the immutable safe evidence handle when present.
    ///
    /// The handle is redacted by construction: provider payloads, queries,
    /// credentials, and private records never cross this boundary.
    #[must_use]
    pub fn evidence_ref(&self) -> Option<&str> {
        self.failure.evidence_ref.as_deref()
    }

    /// Returns the safe provider-neutral conflict observation when present.
    #[must_use]
    pub fn conflict(&self) -> Option<&StoreConflictObservation> {
        self.failure.conflict.as_ref()
    }

    /// Returns the bounded retry delay when the typed directive allows it.
    #[must_use]
    pub fn retry_after_ms(&self) -> Option<u64> {
        self.failure.retry_after_ms
    }

    /// Returns the exact failure contract revision.
    #[must_use]
    pub fn contract_revision(&self) -> &str {
        self.failure.contract_revision.as_str()
    }

    /// Returns diagnostic prose only.
    ///
    /// This text is never used for retry, reconciliation, or task-state
    /// control. Callers must not parse it.
    #[must_use]
    pub fn human_detail(&self) -> Option<&str> {
        self.failure.human_detail.as_deref()
    }

    /// Reports whether this projection is the reconciling unknown-outcome state.
    ///
    /// A reconciling projection is neither unavailable, failed, absent, nor
    /// safe-to-retry.
    #[must_use]
    pub fn is_reconciling(&self) -> bool {
        self.failure.disposition == StoreFailureDisposition::UnknownOutcome
    }

    /// Reports whether the caller must reconcile the exact operation before
    /// any retry, route change, or new semantic decision.
    ///
    /// This branches only on the typed [`StoreRetryDirective`]; the optional
    /// `human_detail` prose never participates.
    #[must_use]
    pub fn requires_exact_operation_reconcile(&self) -> bool {
        matches!(
            self.failure.retry_directive,
            StoreRetryDirective::QueryReceipt | StoreRetryDirective::ReconcileExactOperation
        )
    }

    /// Returns the exact operation that must be reconciled when one is required.
    ///
    /// Returns `None` when no reconciliation is required. A reconciling
    /// projection without an operation identity cannot be reconciled and must
    /// be escalated; it must never be blind-retried.
    #[must_use]
    pub fn reconcile_operation_id(&self) -> Option<&OperationId> {
        if self.requires_exact_operation_reconcile() {
            self.failure.operation_id.as_ref()
        } else {
            None
        }
    }

    /// Reports whether the same identity may be retried after backoff.
    ///
    /// True only for the typed retryable directive. Unknown-outcome
    /// projections always report `false` here: they must reconcile first and
    /// are never safe-to-retry.
    #[must_use]
    pub fn may_retry_same_identity(&self) -> bool {
        self.failure.retry_directive == StoreRetryDirective::RetrySameIdentityAfterBackoff
    }

    /// Verifies a candidate reconciling [`WriteReceipt`] against the exact
    /// projected operation.
    ///
    /// The receipt envelope is validated by its own contract; owner and
    /// receipt prose are mapped to fixed errors. A receipt for another
    /// operation, an invalid envelope, or a receipt offered for a
    /// non-reconciling projection is rejected. This never fabricates a
    /// `Committed` outcome and never promotes task state.
    pub fn verify_reconciled_receipt(
        &self,
        receipt: &WriteReceipt,
    ) -> Result<(), GovernorStoreProjectionError> {
        let Some(operation_id) = self.reconcile_operation_id() else {
            return Err(GovernorStoreProjectionError::ReceiptOperationMismatch);
        };
        receipt
            .validate()
            .map_err(|_| GovernorStoreProjectionError::InvalidReceipt)?;
        if receipt.operation_id != *operation_id {
            return Err(GovernorStoreProjectionError::ReceiptOperationMismatch);
        }
        Ok(())
    }
}
