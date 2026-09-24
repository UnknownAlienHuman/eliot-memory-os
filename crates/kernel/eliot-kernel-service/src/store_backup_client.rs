//! Kernel-owned Store backup edge client (issue #975).
//!
//! This module carries the #975 glue on [`super::EbpCanonicalStoreClient`]:
//! one typed method per #950 capture/page/end, isolated-restore, validation,
//! status and reconciliation operation, sent exactly once through the
//! existing bounded `execute_raw` machinery over the existing authenticated
//! transport. It opens no provider connection, performs no retry of an
//! uncertain mutation, and never falls back to `Apply` or any other
//! operation.
//!
//! Wire shapes are owned by `wire.rs` (Writer-WIRE lane); this module binds
//! the actual symbols: `StoreRequest::Backup { request: StoreBackupRequest }`
//! with `StoreBackupRequest { context, identity, operation }`,
//! `StoreResponse::Backup { response: StoreBackupResponse }`, and capability
//! `CAPABILITY_STORE_BACKUP`. `StoreBackupResponse` is a closed outcome
//! enum over #950 types verbatim — it carries no operation/fence envelope,
//! so each method binds the answer through the exact admitted identity it
//! carried explicitly (operation id, handle digest, archive digest,
//! destination identity, or digest pair) plus the outcome-carried fence
//! where one exists (`Status`). An echoed payload or a matching row count
//! is never a receipt.
//!
//! Every send carries the coherent envelope identity demanded by
//! `StoreBackupRequest::validate()`: `Begin`/`RestoreBatch`/`Validate` copy
//! the payload's admitted `OperationIdentity` verbatim;
//! `Page`/`End` project the owner-issued handle's `operation_id` plus
//! `idempotency_key` with a canonical hash honestly bound over the exact
//! operation payload (a handle carries no canonical hash);
//! `Status` pins the queried `operation_id` with a hash over the status
//! operation; `Reconcile` copies `first` verbatim; `PrepareDestination`
//! derives a deterministic identity over the admitted destination (the
//! `IsolatedDestination` payload carries none, so the envelope is the sole
//! binding). The idempotency key handed to `execute_raw` always equals
//! `identity.idempotency_key`, matching the transport binding enforced by
//! `validate_for_identity`.
//!
//! Discipline (mirrors `apply_reserved_write` in `store_client.rs`):
//! validate inputs and pin the fence to the Host-approved requirement before
//! the frame is built (before-send refusal means nothing was sent); take the
//! one-shot production fault hook (`PreCommitCrash` fails closed with zero
//! sends; backup mutations additionally honor `PostCommitResponseLoss` on an
//! observed success); one `execute_raw` send; strict response binding. A
//! wrong-kind response is a typed contract defect (`InvalidReceipt`); a
//! right-kind response misbound to another operation is `IdentityConflict`;
//! an unknown outcome projects through `into_store_error`
//! (`MissingReceiptEnvelope`) with no second send and no retry.
//!
//! Reads (`backup_page`, `backup_validate`, `backup_status`) cross no effect
//! boundary: they keep the pre-commit refusal but skip the post-commit hook,
//! and they observe (never consume) the one-shot write hook, so an armed
//! write fault survives a read for the write it was armed for.
//!
//! Idempotency keys are derived deterministically from the stable admitted
//! identity of each operation (documented per method); reconciliation changes
//! request correlation only, never the admitted operation.
//!
//! The wire `Validation` outcome carries `RestoreValidationReceipt` (the
//! accepted `IsolatedRestorePort::validate_restore` backend yields no
//! `SnapshotValidationReceipt` from restore-batch inputs), so
//! `backup_validate` returns the wire type verbatim.

use eliot_store_api::{
    BackupOperationReconciliation, CanonicalRestoreBatch, IsolatedDestination, IsolationEvidence,
    OperationId, OperationIdentity, RequestMeta, RestoreValidationReceipt, SnapshotBeginRequest,
    SnapshotCursor, SnapshotEndReceipt, SnapshotHandle, SnapshotPage, StoreBackupOperation,
    StoreBackupRequest, StoreBackupResponse, StoreBackupStatus, StoreError, StoreRequest,
    StoreResponse, canonical_json_bytes, reconcile_same_operation, sha256_hex,
};

use super::store_exchange::RequestFailure;
use super::{EbpCanonicalStoreClient, EbpStoreTransport, StoreClientFault};

/// Builds the envelope identity for a backup operation whose payload carries
/// no admitted canonical hash (issue #975).
///
/// The `operation_id` and `idempotency_key` are projected from the admitted
/// owner-issued material, while `canonical_request_hash` honestly binds the
/// exact operation payload via `sha256_hex(canonical_json_bytes(operation))`.
/// A canonical-serialization failure is a pre-send contract refusal: the
/// caller must surface it with zero sends.
fn backup_derived_envelope_identity(
    operation: &StoreBackupOperation,
    operation_id: &OperationId,
    idempotency_key: &str,
) -> Result<OperationIdentity, StoreError> {
    let bytes = canonical_json_bytes(operation)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(OperationIdentity {
        operation_id: operation_id.clone(),
        idempotency_key: idempotency_key.to_owned(),
        canonical_request_hash: sha256_hex(&bytes),
    })
}

impl<T: EbpStoreTransport + 'static> EbpCanonicalStoreClient<T> {
    /// Opens one bounded coherent snapshot capture through the existing
    /// authenticated Store path (issue #975).
    ///
    /// Idempotency key: the admitted begin identity
    /// (`request.operation.idempotency_key`) — stable across resubmission of
    /// the same admitted capture.
    pub(super) async fn backup_begin_inner(
        &self,
        ctx: &RequestMeta,
        request: SnapshotBeginRequest,
    ) -> Result<SnapshotHandle, StoreError> {
        request.validate()?;
        ctx.validate().map_err(StoreError::Foundation)?;
        self.validate_requirement_fence(&ctx.state_fence)?;
        // Production fault hook (issue #2030): same contract as
        // `apply_prepared` — validation first, pre-commit crash with zero
        // provider effects, post-commit loss discarding the observed answer
        // into unknown.
        let fault = self.take_fault();
        if fault == StoreClientFault::PreCommitCrash {
            return Err(StoreError::MissingReceiptEnvelope);
        }
        let expected_digest = request.compute_digest()?;
        // Coherence rule: `Begin` requires the envelope identity to equal the
        // payload's admitted `OperationIdentity` — copied verbatim, never
        // re-derived.
        let identity = request.operation.clone();
        let admitted_operation_id = identity.operation_id.clone();
        let idempotency_key = identity.idempotency_key.clone();
        let envelope = StoreBackupRequest {
            context: ctx.clone(),
            identity,
            operation: StoreBackupOperation::Begin(request),
        };
        envelope.validate()?;
        let result = self
            .execute_raw(
                StoreRequest::Backup { request: envelope },
                Some(ctx),
                &idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Backup { response }) => {
                if fault == StoreClientFault::PostCommitResponseLoss {
                    return Err(StoreError::MissingReceiptEnvelope);
                }
                Self::check_backup_begin(&admitted_operation_id, &expected_digest, &response)
            }
            // Once the backup mutation has crossed the transport boundary, a
            // valid response of the wrong kind is itself a typed contract
            // defect: no second send, no retry, no fallback to `Apply`.
            Ok(_) => Err(StoreError::InvalidReceipt),
            // Unknown outcomes (transport loss, a peer `Unknown`, or a typed
            // unknown-outcome failure already bound to the admitted operation)
            // project to the typed unknown-outcome error. The peer identity is
            // mismatch evidence only; the admitted operation stays unknown.
            Err(RequestFailure::Unknown {
                operation_id: observed,
            }) => {
                let _ = observed;
                Err(StoreError::MissingReceiptEnvelope)
            }
            Err(error) if error.is_unknown_outcome_failure() => Err(error.into_store_error()),
            Err(error) => Err(error.into_store_error()),
        }
    }

    fn check_backup_begin(
        admitted_operation_id: &OperationId,
        expected_digest: &str,
        response: &StoreBackupResponse,
    ) -> Result<SnapshotHandle, StoreError> {
        let StoreBackupResponse::Handle { handle } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        handle.validate()?;
        if handle.operation_id != *admitted_operation_id {
            return Err(StoreError::IdentityConflict);
        }
        // The handle digest binds the exact admitted begin request; compare
        // against the digest recomputed from our admitted input (verification
        // of the binding, never a minted identity).
        if handle.snapshot_digest != expected_digest {
            return Err(StoreError::IdentityConflict);
        }
        Ok(handle.clone())
    }

    /// Reads one bounded page of an open capture under its owner-issued
    /// consistency point (issue #975).
    ///
    /// A page is an observation: it crosses no effect boundary, so a
    /// wrong-kind or misbound answer stays fail-closed and never reconciles
    /// into a mutation. Idempotency key: the admitted handle's
    /// `idempotency_key` — stable for the capture the page belongs to.
    pub(super) async fn backup_page_inner(
        &self,
        ctx: &RequestMeta,
        handle: SnapshotHandle,
        cursor: SnapshotCursor,
    ) -> Result<SnapshotPage, StoreError> {
        handle.validate()?;
        cursor.validate()?;
        ctx.validate().map_err(StoreError::Foundation)?;
        self.validate_requirement_fence(&ctx.state_fence)?;
        if cursor.handle_digest != handle.snapshot_digest {
            return Err(StoreError::InvalidField {
                field: "snapshot.cursor",
                reason: "cursor does not belong to this snapshot handle",
            });
        }
        // Reads observe the hook without consuming it: a pre-commit crash
        // still refuses before any send, while an armed write fault survives
        // for the admitted write it was armed for.
        if self.armed_fault() == StoreClientFault::PreCommitCrash {
            return Err(StoreError::MissingReceiptEnvelope);
        }
        let admitted_operation_id = handle.operation_id.clone();
        let admitted_digest = handle.snapshot_digest.clone();
        let idempotency_key = handle.idempotency_key.clone();
        // Coherence rule: `Page` requires the envelope `operation_id` and
        // `idempotency_key` to equal the handle's (a handle carries no
        // canonical hash, so the hash honestly binds the exact page
        // operation payload instead).
        let operation = StoreBackupOperation::Page { handle, cursor };
        let envelope = StoreBackupRequest {
            context: ctx.clone(),
            identity: backup_derived_envelope_identity(
                &operation,
                &admitted_operation_id,
                &idempotency_key,
            )?,
            operation,
        };
        envelope.validate()?;
        let result = self
            .execute_raw(
                StoreRequest::Backup { request: envelope },
                Some(ctx),
                &idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Backup { response }) => {
                Self::check_backup_page(&admitted_operation_id, &admitted_digest, &response)
            }
            Ok(_) => Err(StoreError::InvalidReceipt),
            Err(error) => Err(error.into_store_error()),
        }
    }

    fn check_backup_page(
        admitted_operation_id: &OperationId,
        admitted_digest: &str,
        response: &StoreBackupResponse,
    ) -> Result<SnapshotPage, StoreError> {
        let StoreBackupResponse::Page { page } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        page.validate()?;
        if page.handle.operation_id != *admitted_operation_id
            || page.handle.snapshot_digest != admitted_digest
            || page.cursor.handle_digest != admitted_digest
        {
            return Err(StoreError::IdentityConflict);
        }
        Ok(page.clone())
    }

    /// Closes one capture with its owner-issued end receipt (issue #975).
    ///
    /// An echoed payload or a matching member count is not a receipt: the
    /// close is accepted only as the closed `EndReceipt` outcome bound to the
    /// exact admitted handle. Idempotency key: the admitted handle's
    /// `idempotency_key`.
    pub(super) async fn backup_end_inner(
        &self,
        ctx: &RequestMeta,
        handle: SnapshotHandle,
    ) -> Result<SnapshotEndReceipt, StoreError> {
        handle.validate()?;
        ctx.validate().map_err(StoreError::Foundation)?;
        self.validate_requirement_fence(&ctx.state_fence)?;
        let fault = self.take_fault();
        if fault == StoreClientFault::PreCommitCrash {
            return Err(StoreError::MissingReceiptEnvelope);
        }
        let admitted_operation_id = handle.operation_id.clone();
        let admitted_digest = handle.snapshot_digest.clone();
        let idempotency_key = handle.idempotency_key.clone();
        // Coherence rule: `End` requires the envelope `operation_id` and
        // `idempotency_key` to equal the handle's (a handle carries no
        // canonical hash, so the hash honestly binds the exact end operation
        // payload instead).
        let operation = StoreBackupOperation::End { handle };
        let envelope = StoreBackupRequest {
            context: ctx.clone(),
            identity: backup_derived_envelope_identity(
                &operation,
                &admitted_operation_id,
                &idempotency_key,
            )?,
            operation,
        };
        envelope.validate()?;
        let result = self
            .execute_raw(
                StoreRequest::Backup { request: envelope },
                Some(ctx),
                &idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Backup { response }) => {
                if fault == StoreClientFault::PostCommitResponseLoss {
                    return Err(StoreError::MissingReceiptEnvelope);
                }
                Self::check_backup_end(&admitted_operation_id, &admitted_digest, &response)
            }
            Ok(_) => Err(StoreError::InvalidReceipt),
            Err(RequestFailure::Unknown {
                operation_id: observed,
            }) => {
                let _ = observed;
                Err(StoreError::MissingReceiptEnvelope)
            }
            Err(error) if error.is_unknown_outcome_failure() => Err(error.into_store_error()),
            Err(error) => Err(error.into_store_error()),
        }
    }

    fn check_backup_end(
        admitted_operation_id: &OperationId,
        admitted_digest: &str,
        response: &StoreBackupResponse,
    ) -> Result<SnapshotEndReceipt, StoreError> {
        let StoreBackupResponse::EndReceipt { receipt } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        receipt.validate()?;
        if receipt.handle.snapshot_digest != admitted_digest
            || receipt.operation.operation_id != *admitted_operation_id
        {
            return Err(StoreError::IdentityConflict);
        }
        Ok(receipt.clone())
    }

    /// Prepares one isolated restore destination from externally admitted
    /// evidence (issue #975).
    ///
    /// #950's `IsolatedDestination` carries no caller operation identity, so
    /// the envelope identity is the sole mutation binding, derived
    /// deterministically from the admitted destination: the idempotency key
    /// projects the destination coordinates (`destination_id`,
    /// `target_schema`, purge policy revision) — stable for the same
    /// admitted destination, never authority; the canonical hash honestly
    /// binds the exact operation payload; the operation id names that
    /// binding. The answer binds by the closed `Isolation` outcome kind over
    /// the exact admitted destination correlation; destination admission
    /// itself stays owned by the Store backend.
    pub(super) async fn backup_prepare_destination_inner(
        &self,
        ctx: &RequestMeta,
        destination: IsolatedDestination,
    ) -> Result<IsolationEvidence, StoreError> {
        destination.validate()?;
        ctx.validate().map_err(StoreError::Foundation)?;
        self.validate_requirement_fence(&ctx.state_fence)?;
        let fault = self.take_fault();
        if fault == StoreClientFault::PreCommitCrash {
            return Err(StoreError::MissingReceiptEnvelope);
        }
        let idempotency_projection = format!(
            "store-backup-prepare-destination:{}:{}:{}",
            destination.destination_id,
            destination.target_schema,
            destination.evidence.purge_policy_revision,
        );
        let operation = StoreBackupOperation::PrepareDestination(destination);
        let payload_bytes = canonical_json_bytes(&operation)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let canonical_request_hash = sha256_hex(&payload_bytes);
        let identity = OperationIdentity {
            operation_id: OperationId::new(format!(
                "store-backup-prepare-destination:{canonical_request_hash}"
            ))
            .map_err(StoreError::Foundation)?,
            idempotency_key: idempotency_projection,
            canonical_request_hash,
        };
        let idempotency_key = identity.idempotency_key.clone();
        let envelope = StoreBackupRequest {
            context: ctx.clone(),
            identity,
            operation,
        };
        envelope.validate()?;
        let result = self
            .execute_raw(
                StoreRequest::Backup { request: envelope },
                Some(ctx),
                &idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Backup { response }) => {
                if fault == StoreClientFault::PostCommitResponseLoss {
                    return Err(StoreError::MissingReceiptEnvelope);
                }
                Self::check_backup_prepare(&response)
            }
            Ok(_) => Err(StoreError::InvalidReceipt),
            Err(RequestFailure::Unknown {
                operation_id: observed,
            }) => {
                let _ = observed;
                Err(StoreError::MissingReceiptEnvelope)
            }
            Err(error) if error.is_unknown_outcome_failure() => Err(error.into_store_error()),
            Err(error) => Err(error.into_store_error()),
        }
    }

    fn check_backup_prepare(
        response: &StoreBackupResponse,
    ) -> Result<IsolationEvidence, StoreError> {
        let StoreBackupResponse::Isolation { evidence } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        evidence.validate()?;
        Ok(evidence.clone())
    }

    /// Restores one bounded canonical batch into its admitted isolated
    /// destination (issue #975).
    ///
    /// Idempotency key: the admitted batch identity
    /// (`batch.operation.idempotency_key`). A validate/status answer can
    /// never satisfy this call: only the closed `Restored` outcome bound to
    /// the exact batch identity, archive digest and destination is accepted.
    pub(super) async fn backup_restore_batch_inner(
        &self,
        ctx: &RequestMeta,
        batch: CanonicalRestoreBatch,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        batch.validate()?;
        ctx.validate().map_err(StoreError::Foundation)?;
        self.validate_requirement_fence(&ctx.state_fence)?;
        let fault = self.take_fault();
        if fault == StoreClientFault::PreCommitCrash {
            return Err(StoreError::MissingReceiptEnvelope);
        }
        let admitted_operation_id = batch.operation.operation_id.clone();
        let admitted_archive_digest = batch.archive_member_digest.clone();
        let admitted_destination_id = batch.destination.destination_id.clone();
        // Coherence rule: `RestoreBatch` requires the envelope identity to
        // equal the payload's admitted `OperationIdentity` — copied verbatim.
        let identity = batch.operation.clone();
        let idempotency_key = identity.idempotency_key.clone();
        let envelope = StoreBackupRequest {
            context: ctx.clone(),
            identity,
            operation: StoreBackupOperation::RestoreBatch(batch),
        };
        envelope.validate()?;
        let result = self
            .execute_raw(
                StoreRequest::Backup { request: envelope },
                Some(ctx),
                &idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Backup { response }) => {
                if fault == StoreClientFault::PostCommitResponseLoss {
                    return Err(StoreError::MissingReceiptEnvelope);
                }
                Self::check_backup_restore(
                    &admitted_operation_id,
                    &admitted_archive_digest,
                    &admitted_destination_id,
                    &response,
                )
            }
            Ok(_) => Err(StoreError::InvalidReceipt),
            Err(RequestFailure::Unknown {
                operation_id: observed,
            }) => {
                let _ = observed;
                Err(StoreError::MissingReceiptEnvelope)
            }
            Err(error) if error.is_unknown_outcome_failure() => Err(error.into_store_error()),
            Err(error) => Err(error.into_store_error()),
        }
    }

    /// Validates one canonical restore batch without applying it (issue
    /// #975).
    ///
    /// Validation is an observation: it can never import, cut over, or
    /// unblock effects. Idempotency key: the admitted batch identity
    /// (`batch.operation.idempotency_key`). Only the closed wire `Validation`
    /// outcome (`RestoreValidationReceipt`) bound to the exact admitted
    /// batch operation, archive digest, and destination is accepted.
    pub(super) async fn backup_validate_inner(
        &self,
        ctx: &RequestMeta,
        batch: CanonicalRestoreBatch,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        batch.validate()?;
        ctx.validate().map_err(StoreError::Foundation)?;
        self.validate_requirement_fence(&ctx.state_fence)?;
        if self.armed_fault() == StoreClientFault::PreCommitCrash {
            return Err(StoreError::MissingReceiptEnvelope);
        }
        let admitted_operation_id = batch.operation.operation_id.clone();
        let admitted_archive_digest = batch.archive_member_digest.clone();
        let admitted_destination_id = batch.destination.destination_id.clone();
        // Coherence rule: `Validate` requires the envelope identity to equal
        // the payload's admitted `OperationIdentity` — copied verbatim.
        let identity = batch.operation.clone();
        let idempotency_key = identity.idempotency_key.clone();
        let envelope = StoreBackupRequest {
            context: ctx.clone(),
            identity,
            operation: StoreBackupOperation::Validate(batch),
        };
        envelope.validate()?;
        let result = self
            .execute_raw(
                StoreRequest::Backup { request: envelope },
                Some(ctx),
                &idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Backup { response }) => Self::check_backup_validate(
                &admitted_operation_id,
                &admitted_archive_digest,
                &admitted_destination_id,
                &response,
            ),
            Ok(_) => Err(StoreError::InvalidReceipt),
            Err(error) => Err(error.into_store_error()),
        }
    }

    fn check_backup_restore(
        admitted_operation_id: &OperationId,
        admitted_archive_digest: &str,
        admitted_destination_id: &str,
        response: &StoreBackupResponse,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        let StoreBackupResponse::Restored { receipt } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        receipt.validate()?;
        if receipt.operation.operation_id != *admitted_operation_id
            || receipt.archive_member_digest != admitted_archive_digest
            || receipt.destination.destination_id != admitted_destination_id
        {
            return Err(StoreError::IdentityConflict);
        }
        Ok(receipt.clone())
    }

    fn check_backup_validate(
        admitted_operation_id: &OperationId,
        admitted_archive_digest: &str,
        admitted_destination_id: &str,
        response: &StoreBackupResponse,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        let StoreBackupResponse::Validation { receipt } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        receipt.validate()?;
        if receipt.operation.operation_id != *admitted_operation_id
            || receipt.archive_member_digest != admitted_archive_digest
            || receipt.destination.destination_id != admitted_destination_id
        {
            return Err(StoreError::IdentityConflict);
        }
        Ok(receipt.clone())
    }

    /// Observes the status of one backup operation (issue #975).
    ///
    /// Status is an observation: it can never restore, cut over, or unblock
    /// effects. Coherence rule: `Status` requires the envelope
    /// `operation_id` to equal the queried operation. The idempotency key is
    /// deterministic read correlation for the admitted operation
    /// (`store-backup-status:{operation_id}`) — transport correlation only,
    /// never a mutation identity — and the canonical hash honestly binds the
    /// exact status operation payload.
    pub(super) async fn backup_status_inner(
        &self,
        ctx: &RequestMeta,
        operation_id: OperationId,
    ) -> Result<StoreBackupStatus, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        self.validate_requirement_fence(&ctx.state_fence)?;
        if self.armed_fault() == StoreClientFault::PreCommitCrash {
            return Err(StoreError::MissingReceiptEnvelope);
        }
        let idempotency_key = format!("store-backup-status:{operation_id}");
        let operation = StoreBackupOperation::Status {
            operation_id: operation_id.clone(),
        };
        let envelope = StoreBackupRequest {
            context: ctx.clone(),
            identity: backup_derived_envelope_identity(
                &operation,
                &operation_id,
                &idempotency_key,
            )?,
            operation,
        };
        envelope.validate()?;
        let result = self
            .execute_raw(
                StoreRequest::Backup { request: envelope },
                Some(ctx),
                &idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Backup { response }) => {
                self.check_backup_status(&operation_id, &response)
            }
            Ok(_) => Err(StoreError::InvalidReceipt),
            Err(error) => Err(error.into_store_error()),
        }
    }

    fn check_backup_status(
        &self,
        admitted_operation_id: &OperationId,
        response: &StoreBackupResponse,
    ) -> Result<StoreBackupStatus, StoreError> {
        let StoreBackupResponse::Status { report } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        report.validate()?;
        if report.operation_id != *admitted_operation_id {
            return Err(StoreError::IdentityConflict);
        }
        self.validate_requirement_fence(&report.state_fence)?;
        Ok(report.clone())
    }

    /// Reconciles one uncertain backup mutation by exact identity (issue
    /// #975).
    ///
    /// Reconciliation changes request correlation, not the original
    /// operation: the envelope identity equals `first` verbatim (the
    /// reconciled operation; `second` is only the compared identity), and
    /// the transport idempotency key is the admitted identity's own key.
    /// Unknown stays unknown; it never triggers a new operation or an
    /// automatic retry.
    pub(super) async fn backup_reconcile_inner(
        &self,
        ctx: &RequestMeta,
        first: OperationIdentity,
        second: OperationIdentity,
    ) -> Result<BackupOperationReconciliation, StoreError> {
        // Same-operation gate before any send: cross-operation input is a
        // typed before-send refusal, never a new operation.
        reconcile_same_operation(&first, &second)?;
        ctx.validate().map_err(StoreError::Foundation)?;
        self.validate_requirement_fence(&ctx.state_fence)?;
        let fault = self.take_fault();
        if fault == StoreClientFault::PreCommitCrash {
            return Err(StoreError::MissingReceiptEnvelope);
        }
        let admitted_operation_id = first.operation_id.clone();
        let admitted_first_digest = first.canonical_request_hash.clone();
        let admitted_second_digest = second.canonical_request_hash.clone();
        // Coherence rule: `Reconcile` requires the envelope identity to equal
        // `first` — copied verbatim, so the transport key is the admitted
        // identity's own idempotency key.
        let identity = first.clone();
        let idempotency_key = identity.idempotency_key.clone();
        let envelope = StoreBackupRequest {
            context: ctx.clone(),
            identity,
            operation: StoreBackupOperation::Reconcile { first, second },
        };
        envelope.validate()?;
        let result = self
            .execute_raw(
                StoreRequest::Backup { request: envelope },
                Some(ctx),
                &idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Backup { response }) => {
                if fault == StoreClientFault::PostCommitResponseLoss {
                    return Err(StoreError::MissingReceiptEnvelope);
                }
                Self::check_backup_reconcile(
                    &admitted_operation_id,
                    &admitted_first_digest,
                    &admitted_second_digest,
                    &response,
                )
            }
            Ok(_) => Err(StoreError::InvalidReceipt),
            Err(RequestFailure::Unknown {
                operation_id: observed,
            }) => {
                let _ = observed;
                Err(StoreError::MissingReceiptEnvelope)
            }
            Err(error) if error.is_unknown_outcome_failure() => Err(error.into_store_error()),
            Err(error) => Err(error.into_store_error()),
        }
    }

    fn check_backup_reconcile(
        admitted_operation_id: &OperationId,
        admitted_first_digest: &str,
        admitted_second_digest: &str,
        response: &StoreBackupResponse,
    ) -> Result<BackupOperationReconciliation, StoreError> {
        let StoreBackupResponse::Reconciled { reconciliation } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        reconciliation.validate()?;
        if reconciliation.operation.operation_id != *admitted_operation_id
            || reconciliation.first_digest != admitted_first_digest
            || reconciliation.second_digest != admitted_second_digest
        {
            return Err(StoreError::IdentityConflict);
        }
        Ok(reconciliation.clone())
    }
}

// Adaptation table: assumed-brief symbol -> actual `wire.rs` symbol
// (wire.rs is authority; this module was rewritten against it):
//
// - `StoreRequest::Backup { request: StoreBackupRequest }`: exact match.
// - `StoreBackupRequest { context, operation }` -> `StoreBackupRequest
//   { context, identity, operation }`: the envelope carries the stable
//   admitted `OperationIdentity` beside the payload, bound per-variant by
//   `StoreBackupRequest::validate()` (`backup.identity` coherence).
// - `Begin { request }` -> `Begin(SnapshotBeginRequest)` (tuple variant);
//   envelope identity copies `request.operation` verbatim.
// - `Page { handle, cursor }`: exact match; envelope identity projects the
//   handle's `operation_id` + `idempotency_key` with an honest canonical
//   hash over the page operation.
// - `End { handle }`: exact match; envelope identity projects the handle's
//   `operation_id` + `idempotency_key` with an honest canonical hash over
//   the end operation.
// - `PrepareDestination { destination }` ->
//   `PrepareDestination(IsolatedDestination)` (tuple variant); the payload
//   carries no identity, so the envelope identity is derived
//   deterministically from the admitted destination (sole binding).
// - `RestoreBatch { batch }` -> `RestoreBatch(CanonicalRestoreBatch)`
//   (tuple variant); envelope identity copies `batch.operation` verbatim.
// - `Validate { batch }` -> `Validate(CanonicalRestoreBatch)` (tuple
//   variant); envelope identity copies `batch.operation` verbatim; outcome
//   is `Validation { receipt: RestoreValidationReceipt }`, so
//   `backup_validate` returns `RestoreValidationReceipt`.
// - `Status { operation_id }`: exact match; envelope identity pins the
//   queried `operation_id` with an honest canonical hash over the status
//   operation.
// - `Reconcile { first, second }`: exact match; envelope identity copies
//   `first` verbatim.
// - Assumed `StoreBackupResponse { operation_id, state_fence, outcome }`
//   struct + `StoreBackupOutcome` enum do NOT exist: the actual
//   `StoreBackupResponse` is a closed outcome enum (`Handle`, `Page`,
//   `EndReceipt`, `Isolation`, `Restored`, `Validation`, `Status`,
//   `Reconciled`). Binding is per-outcome payload identity; the fence is
//   checked where the outcome carries one (`Status.report.state_fence`).
// - `StoreBackupStatus { operation_id, state_fence, outcome }`: exact match.
// - `CAPABILITY_STORE_BACKUP`: exact match.
// - Delegation note: the exact public `backup_*` surface lives in
//   `store_client.rs` (same type, identical signatures, no logic) and forwards
//   to the `*_inner` logic methods above, because Rust forbids duplicate
//   inherent method names on one type (E0592).
