//! Live Governor authority for one source-artifact effect.
//!
//! This value deliberately has no Serde implementation. A serialized request
//! identity, capability selector, or binding projection is not a transferable
//! effect grant; the live caller keeps this value beside the process request
//! and the source owner consumes it in the same request stack.

use eliot_authority::{
    ActionContract, ActionLease, AuthorityError, AuthorizedEffect, EffectiveCapabilitySnapshot,
    GrantId, LeaseId, LogicalTime, PrincipalRef, ReceiptObligation, SnapshotId,
};
use eliot_contracts::RequestMetadata;
use eliot_contracts::canonical_json_bytes;
use eliot_ors::{ActiveAdmissionReservation, AdmissionReservationState, OperationIdentity};
use eliot_protocol::{HostRequestEnvelope, LocalReadAttempt, RequestIdentity};
use eliot_read::ReadIdentity;
use eliot_receipts::{
    AuthorityBinding, CausalBinding, EffectClass, OperationBinding, RequestBinding, SessionBinding,
    TaskBinding, WorkScopeBinding,
};
use eliot_store_api::CapturedBlobPayloadRefV1;
use thiserror::Error;

use crate::AuthorityOwner;

type OriginalReservationBindings = (
    Option<OperationIdentity>,
    Option<eliot_receipts::ReceiptIdentity>,
    Option<eliot_receipts::ReceiptIdentity>,
);

/// Exact evidence needed to admit the retained LSP Blob read under an
/// already-admitted context-reconstruction request.
///
/// The caller supplies the original host envelope/attempt, the existing
/// `ReadApi` metadata and task-frame identity, the Kernel-authenticated
/// principal, Store-issued causal readback, and the pointer already retained
/// with the captured observation. The composition re-reads the
/// `TaskLifecycleOwner`, `SessionLifecycleOwner`, `WorkScopeBindingOwner`, and
/// `AuthorityOwner` before issuing the `Read` effect.
#[derive(Clone, Debug)]
pub struct SourceArtifactReadRequest {
    pub envelope: HostRequestEnvelope,
    pub attempt: LocalReadAttempt,
    pub request_metadata: RequestMetadata,
    pub holder: PrincipalRef,
    pub task_frame_readback: ReadIdentity,
    pub causal_binding: CausalBinding,
    pub payload_ref: CapturedBlobPayloadRefV1,
    pub now: LogicalTime,
}

/// Exact inputs already read from the original Governor, `WorkScope`, request,
/// and ORS owners. This request is not authority and cannot issue without a
/// live [`AuthorityOwner`] whose `GrantGraph` snapshot admits the exact effect.
#[derive(Clone, Debug)]
pub struct SourceArtifactAdmissionRequest {
    pub snapshot_id: SnapshotId,
    pub holder: PrincipalRef,
    pub work_scope: WorkScopeBinding,
    pub task: TaskBinding,
    pub session: SessionBinding,
    pub causal: CausalBinding,
    pub request: RequestBinding,
    pub request_identity: RequestIdentity,
    pub operation: OperationBinding,
    pub operation_name: String,
    pub resource_ref: String,
    pub executor_boundary: String,
    pub lease_id: LeaseId,
    pub receipt_obligations: Vec<ReceiptObligation>,
    pub contract: ActionContract,
    /// Exact active ORS reservation for a canonical mutation; `None` for a
    /// pure `Read` admission, which does not stage a write in ORS.
    pub active_reservation: Option<ActiveAdmissionReservation>,
    /// Work-item identity paired with the active reservation on mutation.
    /// Absent only when `operation.effect` is `Read`.
    pub expected_work_item_id: Option<OperationIdentity>,
    /// Proposed-attempt identity paired with the active reservation on
    /// mutation. Absent only when `operation.effect` is `Read`.
    pub expected_proposed_attempt_id: Option<OperationIdentity>,
    pub now: LogicalTime,
}

/// Same-stack, one-effect admission. The lease and authorized effect are the
/// exact values produced by the original `GrantGraph` and `EffectAuthorizer`;
/// binding accessors are projections of those same values.
#[derive(Debug)]
pub struct SourceArtifactAdmission {
    action_lease: ActionLease,
    authorized_effect: AuthorizedEffect,
    holder: PrincipalRef,
    work_scope: WorkScopeBinding,
    task: TaskBinding,
    session: SessionBinding,
    causal: CausalBinding,
    request: RequestBinding,
    operation: OperationBinding,
    resource_ref: String,
    request_identity: RequestIdentity,
    authority: AuthorityBinding,
    supporting_grant_path: Vec<GrantId>,
    grant_graph_revision: u64,
    reservation_id: Option<OperationIdentity>,
    canonical_admission_receipt: Option<eliot_receipts::ReceiptIdentity>,
    activation_receipt: Option<eliot_receipts::ReceiptIdentity>,
}

impl SourceArtifactAdmission {
    pub fn action_lease(&self) -> &ActionLease {
        &self.action_lease
    }

    pub fn authorized_effect(&self) -> &AuthorizedEffect {
        &self.authorized_effect
    }

    /// Original admitted principal whose exact `GrantGraph` path authorized
    /// this effect. Policy-owned source profiles bind their access context to
    /// this retained value rather than to a caller label.
    pub fn holder(&self) -> &PrincipalRef {
        &self.holder
    }

    pub fn work_scope(&self) -> &WorkScopeBinding {
        &self.work_scope
    }

    pub fn task(&self) -> &TaskBinding {
        &self.task
    }

    pub fn session(&self) -> &SessionBinding {
        &self.session
    }

    pub fn causal(&self) -> &CausalBinding {
        &self.causal
    }

    pub fn request(&self) -> &RequestBinding {
        &self.request
    }

    pub fn operation(&self) -> &OperationBinding {
        &self.operation
    }

    /// Exact resource reference admitted through the original `GrantGraph`.
    /// For a captured LSP payload this is the original Blob ready-receipt ID.
    pub fn resource_ref(&self) -> &str {
        &self.resource_ref
    }

    pub fn request_identity(&self) -> &RequestIdentity {
        &self.request_identity
    }

    pub fn authority(&self) -> &AuthorityBinding {
        &self.authority
    }

    pub fn supporting_grant_path(&self) -> &[GrantId] {
        &self.supporting_grant_path
    }

    pub const fn grant_graph_revision(&self) -> u64 {
        self.grant_graph_revision
    }

    /// Stable original Governor `ActionLease` identity for constructing the
    /// Kernel P-03 `ActionLeaseRef` in this same admitted request stack.
    pub fn action_lease_id(&self) -> &LeaseId {
        &self.action_lease.lease_id
    }

    pub fn reservation_id(&self) -> Option<&OperationIdentity> {
        self.reservation_id.as_ref()
    }

    pub fn canonical_admission_receipt(&self) -> Option<&eliot_receipts::ReceiptIdentity> {
        self.canonical_admission_receipt.as_ref()
    }

    pub fn activation_receipt(&self) -> Option<&eliot_receipts::ReceiptIdentity> {
        self.activation_receipt.as_ref()
    }

    /// Digest of the canonical `ActionContract` already admitted by the
    /// `EffectAuthorizer`. A source owner may compare this to its own immutable
    /// source snapshot commitment; it does not prove that arbitrary bytes are
    /// that snapshot.
    pub fn action_payload_sha256(&self) -> &str {
        &self.authorized_effect.proposal.canonical_payload_sha256
    }
}

#[derive(Debug, Error)]
pub enum SourceArtifactAdmissionError {
    #[error("source effect admission refused: {0}")]
    Authority(#[from] AuthorityError),
    #[error(transparent)]
    Protocol(#[from] eliot_protocol::ProtocolError),
    #[error(transparent)]
    Store(#[from] eliot_store_api::StoreError),
    #[error(transparent)]
    WorkScope(#[from] eliot_workscope::WorkScopeError),
    #[error(transparent)]
    Receipt(#[from] eliot_receipts::ReceiptError),
    #[error(transparent)]
    Contract(#[from] eliot_contracts::ContractError),
    #[error(transparent)]
    ContractEncoding(#[from] serde_json::Error),
    #[error(transparent)]
    TextEncoding(#[from] std::string::FromUtf8Error),
    #[error("source effect admission binding refused: {0}")]
    Binding(&'static str),
    #[error("source effect admission could not encode the current State Fence")]
    FenceEncoding,
    #[error("source effect admission could not read an original Governor owner: {0}")]
    Owner(String),
    #[error("source mutation admission lacks an exact active ORS reservation")]
    MissingReservation,
    #[error(
        "source mutation admission lacks the original canonical ADMITTED or ORS activation receipt"
    )]
    MissingReservationReceipt,
}

/// Admits a source effect through one exact currently-active `GrantGraph` path,
/// compiles it through the original `EffectAuthorizer`, and retains the live
/// `ActionLease`/`AuthorizedEffect` together with the exact request. A `Read`
/// keeps the same authority bindings but carries no write-reservation or
/// canonical-write receipts; a reversible mutation still requires all three.
pub(crate) fn issue_source_artifact_admission(
    authority: &mut AuthorityOwner,
    input: SourceArtifactAdmissionRequest,
) -> Result<SourceArtifactAdmission, SourceArtifactAdmissionError> {
    validate_request(&input)?;
    let (reservation_id, canonical_receipt, activation_receipt) =
        validate_original_reservation_bindings(&input)?;

    let snapshot: EffectiveCapabilitySnapshot = authority.grants.snapshot(
        input.snapshot_id,
        &input.holder,
        &input.work_scope,
        &input.session,
        input.now,
    )?;
    snapshot.validate_context(&input.work_scope, &input.session)?;
    let supporting_path = snapshot
        .supporting_path(
            &input.operation_name,
            &input.resource_ref,
            input.operation.effect,
        )?
        .grant_path
        .clone();
    let grant_graph_revision = snapshot.grant_graph_revision();
    let mut action_lease = snapshot.issue_action_lease(
        input.lease_id,
        input.operation.idempotency_key.clone(),
        input.operation_name.clone(),
        input.resource_ref.clone(),
        input.operation.effect,
        input.receipt_obligations,
    )?;
    let compiled = authority.effects.compile_effectful_action(
        &input.contract,
        input.operation.clone(),
        input.operation_name,
        input.resource_ref.clone(),
        input.executor_boundary,
        &mut action_lease,
        &input.work_scope,
        &input.session,
        input.now,
    )?;

    let authority_binding = action_lease.authority_binding.clone();
    Ok(SourceArtifactAdmission {
        action_lease,
        authorized_effect: compiled.authorized().clone(),
        holder: input.holder,
        work_scope: input.work_scope,
        task: input.task,
        session: input.session,
        causal: input.causal,
        request: input.request,
        operation: input.operation,
        resource_ref: input.resource_ref,
        request_identity: input.request_identity,
        authority: authority_binding,
        supporting_grant_path: supporting_path,
        grant_graph_revision,
        reservation_id,
        canonical_admission_receipt: canonical_receipt,
        activation_receipt,
    })
}

fn validate_original_reservation_bindings(
    input: &SourceArtifactAdmissionRequest,
) -> Result<OriginalReservationBindings, SourceArtifactAdmissionError> {
    match input.operation.effect {
        EffectClass::Read => {
            if input.active_reservation.is_some()
                || input.expected_work_item_id.is_some()
                || input.expected_proposed_attempt_id.is_some()
            {
                return Err(SourceArtifactAdmissionError::Binding(
                    "Read admission cannot carry a write reservation or its identity",
                ));
            }
            Ok((None, None, None))
        }
        EffectClass::ReversibleMutation => {
            let active_reservation = input
                .active_reservation
                .as_ref()
                .ok_or(SourceArtifactAdmissionError::MissingReservation)?;
            let expected_work_item_id = input
                .expected_work_item_id
                .as_ref()
                .ok_or(SourceArtifactAdmissionError::MissingReservation)?;
            let expected_proposed_attempt_id = input
                .expected_proposed_attempt_id
                .as_ref()
                .ok_or(SourceArtifactAdmissionError::MissingReservation)?;
            let active = active_reservation.record();
            if active.state != AdmissionReservationState::Active
                || &active.work_item_id != expected_work_item_id
                || &active.proposed_attempt_id != expected_proposed_attempt_id
            {
                return Err(SourceArtifactAdmissionError::Binding(
                    "reservation is not the exact active work-item/attempt pair",
                ));
            }
            let canonical_receipt = active
                .canonical_admission_receipt
                .clone()
                .ok_or(SourceArtifactAdmissionError::MissingReservationReceipt)?;
            let activation_receipt = active
                .activation_receipt
                .clone()
                .ok_or(SourceArtifactAdmissionError::MissingReservationReceipt)?;
            let fence_json = canonical_json_bytes(&input.work_scope.state_fence)
                .map_err(|_| SourceArtifactAdmissionError::FenceEncoding)?;
            if active.state_fence.canonical_json.as_bytes() != fence_json.as_slice()
                || active.state_fence.observed_authority_epoch
                    != input.work_scope.state_fence.authority_epoch.sequence.get()
            {
                return Err(SourceArtifactAdmissionError::Binding(
                    "active reservation fence or epoch differs from the current WorkScope",
                ));
            }
            Ok((
                Some(active.reservation_id.clone()),
                Some(canonical_receipt),
                Some(activation_receipt),
            ))
        }
        EffectClass::Candidate | EffectClass::ExternalEffect => {
            Err(SourceArtifactAdmissionError::Binding(
                "source artifact operations admit only Read or reversible-mutation effects",
            ))
        }
    }
}

fn validate_request(
    input: &SourceArtifactAdmissionRequest,
) -> Result<(), SourceArtifactAdmissionError> {
    let fence = &input.work_scope.state_fence;
    if input.contract.work_scope != input.work_scope {
        return Err(SourceArtifactAdmissionError::Binding(
            "ActionContract differs from the owner-resolved WorkScope",
        ));
    }
    if input.task.state_fence != *fence
        || input.session.state_fence != *fence
        || input.causal.state_fence != *fence
        || input.request.state_fence != *fence
        || input.operation.state_fence != *fence
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "source request bindings do not share the exact WorkScope fence",
        ));
    }
    if input.task.task_id.to_string() != input.contract.task_id
        || input.request.metadata.task_id.as_ref() != Some(&input.task.task_id)
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "source task differs from the ActionContract task",
        ));
    }
    if input.request_identity.validate().is_err()
        || input.request_identity.request != input.request
        || input.operation.request_id != input.request.metadata.request_id
        || input.operation.idempotency_key != input.request_identity.idempotency_key
        || input.operation.operation_kind != input.operation_name
        || input.request.metadata.session_id.as_ref() != Some(&input.session.session_id)
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "operation does not match the original request metadata",
        ));
    }
    if input.operation.effect != EffectClass::Read
        && input.operation.effect != EffectClass::ReversibleMutation
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "source artifact operations admit only read or reversible-mutation effects",
        ));
    }
    if input.resource_ref.trim().is_empty()
        || input.operation_name.trim().is_empty()
        || input.executor_boundary.trim().is_empty()
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "source operation identity is incomplete",
        ));
    }
    Ok(())
}
