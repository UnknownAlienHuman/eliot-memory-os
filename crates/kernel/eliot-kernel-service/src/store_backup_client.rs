//! Kernel-owned Store backup edge client (issue #975).
//!
//! This module carries the #975 glue on [`super::EbpCanonicalStoreClient`]:
//! one typed method per #950 capture/page/end, isolated-restore, validation,
//! status and reconciliation operation, sent exactly once through the
//! existing bounded `execute_raw` machinery over the existing authenticated
//! transport. It opens no provider connection, performs no retry of an
//! uncertain mutation, and never re-derives a digest: digests carried in the
//! #950 types are compared for equality only.
//!
//! Before-send refusal is distinct from possible effect after send: every
//! method validates the closed request shape and pins the fence to the
//! Host-approved requirement before the frame is built, so a typed refusal
//! there means nothing was sent. Anything observed after the single send is
//! bound to the exact admitted operation: a wrong-kind response, a foreign
//! operation/fence/consistency binding, or an unknown outcome reconciles by
//! exact identity and never becomes success.

use eliot_store_api::{
    OperationId, OperationIdentity, StoreBackupBeginRequest, StoreBackupCompletionReceipt,
    StoreBackupConsistency, StoreBackupEndRequest, StoreBackupEnvelope,
    StoreBackupEnvelopeResponse, StoreBackupOperation, StoreBackupOutcome, StoreBackupPage,
    StoreBackupPageRequest, StoreBackupReconcileRequest, StoreBackupReconciliation,
    StoreBackupScope, StoreBackupStatusReport, StoreBackupStatusRequest,
    StoreBackupValidationReceipt, StoreBackupValidationRequest, StoreError,
    StoreIsolatedRestoreRequest, StoreRequest, StoreRestoreAdmissionInputs, StoreResponse,
};

use super::store_exchange::RequestFailure;
use super::{EbpCanonicalStoreClient, EbpStoreTransport};

fn backup_identity_for_operation(
    operation: &StoreBackupOperation,
    canonical_request_hash: &str,
) -> OperationIdentity {
    OperationIdentity {
        operation_id: operation.operation_id().clone(),
        idempotency_key: operation.idempotency_key(),
        canonical_request_hash: canonical_request_hash.to_owned(),
    }
}

impl<T: EbpStoreTransport + 'static> EbpCanonicalStoreClient<T> {
    /// Assembles one closed isolated-restore request from pre-verified
    /// Governor bindings for the paired restore callers (issues #959/#960
    /// Kernel restore adapter, #963 caller).
    ///
    /// Mechanical request mapping (issue #975 T2): the provisional Store
    /// admission is built through `StoreRestoreAdmission::map_inputs` —
    /// the real mapping invocation — and bound with the scope, source
    /// reference, and batch bounds into a fully validated request. The
    /// caller (paired Restore lane) pre-verified every binding against
    /// live owner state; this function performs zero owner judgment:
    /// admission mapping plus closed request validation only. The
    /// returned request is ready for
    /// [`EbpCanonicalStoreClient::backup_isolated_restore`] transport.
    /// Associated function (no transport needed): pure request assembly
    /// on the client type the paired callers already drive.
    pub fn assemble_restore_request(
        identity: OperationIdentity,
        source_operation_id: OperationId,
        source_snapshot_digest: String,
        scope: StoreBackupScope,
        admission_inputs: StoreRestoreAdmissionInputs,
        expected_member_count: u64,
        max_members_per_batch: u32,
    ) -> Result<StoreIsolatedRestoreRequest, StoreError> {
        let admission =
            eliot_store_api::StoreRestoreAdmission::map_inputs(admission_inputs)?;
        let request = StoreIsolatedRestoreRequest {
            identity,
            source_operation_id,
            source_snapshot_digest,
            scope,
            admission,
            expected_member_count,
            max_members_per_batch,
        };
        request.validate()?;
        Ok(request)
    }

    fn check_backup_fence(&self, fence: &eliot_contracts::StateFence) -> Result<(), StoreError> {
        if fence != &self.requirement().state_fence {
            return Err(StoreError::FenceMismatch);
        }
        Ok(())
    }

    fn backup_envelope(
        &self,
        operation: StoreBackupOperation,
        canonical_request_hash: &str,
        fence: eliot_contracts::StateFence,
    ) -> Result<(StoreBackupEnvelope, String), StoreError> {
        self.check_backup_fence(&fence)?;
        let envelope = StoreBackupEnvelope {
            identity: backup_identity_for_operation(&operation, canonical_request_hash),
            state_fence: fence,
            operation,
        };
        envelope.validate()?;
        let idempotency_key = envelope.identity.idempotency_key.clone();
        Ok((envelope, idempotency_key))
    }

    async fn send_backup(
        &self,
        envelope: StoreBackupEnvelope,
        idempotency_key: &str,
    ) -> Result<StoreBackupEnvelopeResponse, StoreError> {
        let operation_id = envelope.operation.operation_id().clone();
        let result = self
            .execute_raw(
                StoreRequest::Backup { request: envelope },
                None,
                idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Backup { response }) => {
                if response.operation_id != operation_id {
                    return Err(StoreError::IdentityConflict);
                }
                Ok(response)
            }
            // Once a backup mutation has crossed the transport boundary, a
            // valid response of the wrong kind is itself an uncertain
            // observation: it reconciles by exact identity and never becomes
            // success. Reads cross no effect boundary and stay fail-closed.
            Ok(_) | Err(RequestFailure::Unknown { .. }) => Err(StoreError::MissingReceiptEnvelope),
            Err(error) if error.is_unknown_outcome_failure() => {
                Err(StoreError::MissingReceiptEnvelope)
            }
            Err(error) => Err(error.into_store_error()),
        }
    }

    /// Opens one bounded coherent canonical snapshot through the existing
    /// authenticated Store path.
    ///
    /// The closed #950 begin request is validated and fenced before the
    /// single send. The returned consistency handle is accepted only when
    /// its operation and fence match the admitted request; anything else
    /// observed after the send stays unknown for the exact admitted
    /// operation and never becomes success.
    pub async fn backup_begin(
        &self,
        request: StoreBackupBeginRequest,
    ) -> Result<StoreBackupConsistency, StoreError> {
        request.validate()?;
        let canonical_request_hash = request.identity.canonical_request_hash.clone();
        let fence = request.scope.state_fence.clone();
        let (envelope, idempotency_key) = self.backup_envelope(
            StoreBackupOperation::Begin { request },
            &canonical_request_hash,
            fence,
        )?;
        let response = self.send_backup(envelope, &idempotency_key).await?;
        let StoreBackupOutcome::Begun { consistency } = response.outcome else {
            return Err(StoreError::InvalidReceipt);
        };
        consistency.validate()?;
        if consistency.state_fence != response.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        Ok(consistency)
    }

    /// Reads one page of an open capture under its consistency point.
    ///
    /// A page is an observation: it crosses no effect boundary, so a
    /// wrong-kind or misbound answer stays fail-closed and never reconciles
    /// into a mutation. Continuation binding (one consistency point,
    /// advancing cursors, cumulative bounds) is checked here; the wire
    /// never re-derives a digest.
    pub async fn backup_page(
        &self,
        request: StoreBackupPageRequest,
        expected_fence: &eliot_contracts::StateFence,
    ) -> Result<StoreBackupPage, StoreError> {
        request.validate()?;
        self.check_backup_fence(expected_fence)?;
        // Observations carry no caller-minted mutation digest: the envelope
        // reuses the page request's operation binding with an empty digest
        // field, which the wire treats as opaque correlation.
        let operation = StoreBackupOperation::Page {
            request: request.clone(),
        };
        let (envelope, idempotency_key) =
            self.backup_envelope(operation, &"0".repeat(64), expected_fence.clone())?;
        let response = self.send_backup(envelope, &idempotency_key).await?;
        let StoreBackupOutcome::Page { page } = response.outcome else {
            return Err(StoreError::InvalidReceipt);
        };
        page.validate()?;
        if page.operation_id != request.operation_id
            || page.consistency_point != request.consistency_point
            || page.state_fence != *expected_fence
        {
            return Err(StoreError::IdentityConflict);
        }
        Ok(page)
    }

    /// Closes one capture and returns its owner-issued completion receipt.
    ///
    /// An echoed payload or a matching member count is not a receipt: the
    /// completion is accepted only as the closed `Completion` outcome bound
    /// to the exact admitted operation and fence.
    pub async fn backup_end(
        &self,
        request: StoreBackupEndRequest,
        expected_fence: &eliot_contracts::StateFence,
    ) -> Result<StoreBackupCompletionReceipt, StoreError> {
        request.validate()?;
        self.check_backup_fence(expected_fence)?;
        let operation = StoreBackupOperation::End {
            request: request.clone(),
        };
        let (envelope, idempotency_key) =
            self.backup_envelope(operation, &"0".repeat(64), expected_fence.clone())?;
        let response = self.send_backup(envelope, &idempotency_key).await?;
        let StoreBackupOutcome::Completion { receipt } = response.outcome else {
            return Err(StoreError::InvalidReceipt);
        };
        receipt.validate()?;
        if receipt.operation_id != request.operation_id
            || receipt.consistency_point != request.consistency_point
        {
            return Err(StoreError::IdentityConflict);
        }
        Ok(receipt)
    }

    /// Restores validated canonical records into the admitted isolated
    /// destination only.
    ///
    /// The destination isolation and purge/reference verification stay owned
    /// by the Store backend: this client only binds the answer to the exact
    /// admitted restore identity. Verify/status answers can never satisfy
    /// this call.
    pub async fn backup_isolated_restore(
        &self,
        request: StoreIsolatedRestoreRequest,
    ) -> Result<StoreBackupCompletionReceipt, StoreError> {
        request.validate()?;
        let canonical_request_hash = request.identity.canonical_request_hash.clone();
        let fence = request.scope.state_fence.clone();
        let (envelope, idempotency_key) = self.backup_envelope(
            StoreBackupOperation::IsolatedRestore { request },
            &canonical_request_hash,
            fence,
        )?;
        let response = self.send_backup(envelope, &idempotency_key).await?;
        let StoreBackupOutcome::Completion { receipt } = response.outcome else {
            return Err(StoreError::InvalidReceipt);
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates one captured snapshot without restoring it.
    ///
    /// Validation is an observation: it can never import, cut over, or
    /// unblock effects, and an unavailable validation never returns
    /// success.
    pub async fn backup_validate(
        &self,
        request: StoreBackupValidationRequest,
        expected_fence: &eliot_contracts::StateFence,
    ) -> Result<StoreBackupValidationReceipt, StoreError> {
        request.validate()?;
        self.check_backup_fence(expected_fence)?;
        let operation = StoreBackupOperation::Validate {
            request: request.clone(),
        };
        let (envelope, idempotency_key) =
            self.backup_envelope(operation, &"0".repeat(64), expected_fence.clone())?;
        let response = self.send_backup(envelope, &idempotency_key).await?;
        let StoreBackupOutcome::Validation { receipt } = response.outcome else {
            return Err(StoreError::InvalidReceipt);
        };
        receipt.validate()?;
        if receipt.operation_id != request.operation_id
            || receipt.snapshot_digest != request.snapshot_digest
        {
            return Err(StoreError::IdentityConflict);
        }
        Ok(receipt)
    }

    /// Observes the status of one backup operation.
    pub async fn backup_status(
        &self,
        request: StoreBackupStatusRequest,
        expected_fence: &eliot_contracts::StateFence,
    ) -> Result<StoreBackupStatusReport, StoreError> {
        request.validate()?;
        self.check_backup_fence(expected_fence)?;
        let operation = StoreBackupOperation::Status {
            request: request.clone(),
        };
        let (envelope, idempotency_key) =
            self.backup_envelope(operation, &"0".repeat(64), expected_fence.clone())?;
        let response = self.send_backup(envelope, &idempotency_key).await?;
        let StoreBackupOutcome::Status { report } = response.outcome else {
            return Err(StoreError::InvalidReceipt);
        };
        report.validate()?;
        if report.operation_id != request.operation_id {
            return Err(StoreError::IdentityConflict);
        }
        Ok(report)
    }

    /// Reconciles one uncertain backup mutation by exact identity.
    ///
    /// Reconciliation changes request correlation, not the original
    /// operation: the admitted operation id and canonical digest pin the
    /// lookup, and a fresh transport correlation carries it. Unknown stays
    /// unknown; it never triggers a new operation or an automatic retry.
    pub async fn backup_reconcile(
        &self,
        request: StoreBackupReconcileRequest,
        expected_fence: &eliot_contracts::StateFence,
    ) -> Result<StoreBackupReconciliation, StoreError> {
        request.validate()?;
        self.check_backup_fence(expected_fence)?;
        let operation = StoreBackupOperation::Reconcile {
            request: request.clone(),
        };
        let (envelope, idempotency_key) = self.backup_envelope(
            operation,
            &request.canonical_request_hash,
            expected_fence.clone(),
        )?;
        let response = self.send_backup(envelope, &idempotency_key).await?;
        let StoreBackupOutcome::Reconciliation { reconciliation } = response.outcome else {
            return Err(StoreError::InvalidReceipt);
        };
        Ok(reconciliation)
    }
}
