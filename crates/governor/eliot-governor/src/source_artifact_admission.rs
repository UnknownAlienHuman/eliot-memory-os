//! Live Governor authority for one source-artifact effect.
//!
//! This value deliberately has no Serde implementation. A serialized request
//! identity, capability selector, or binding projection is not a transferable
//! effect grant; the live caller keeps this value beside the process request
//! and the source owner consumes it in the same request stack.

use eliot_authority::{
    ActionContract, ActionLease, AuthorizedEffect, AuthorityError,
    EffectiveCapabilitySnapshot, GrantId, LeaseId, LogicalTime, PrincipalRef, ReceiptObligation,
    SnapshotId,
};
use eliot_contracts::canonical_json_bytes;
use eliot_ors::{
    ActiveAdmissionReservation, AdmissionReservationState, OperationIdentity,
};
use eliot_receipts::{
    AuthorityBinding, CausalBinding, EffectClass, OperationBinding, RequestBinding,
    SessionBinding, TaskBinding, WorkScopeBinding,
};
use eliot_protocol::RequestIdentity;
use thiserror::Error;

use crate::AuthorityOwner;

/// Exact inputs already read from the original Governor, WorkScope, request,
/// and ORS owners. This request is not authority and cannot issue without a
/// live [`AuthorityOwner`] whose GrantGraph snapshot admits the exact effect.
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
    pub active_reservation: ActiveAdmissionReservation,
    pub expected_work_item_id: OperationIdentity,
    pub expected_proposed_attempt_id: OperationIdentity,
    pub now: LogicalTime,
}

/// Same-stack, one-effect admission. The lease and authorized effect are the
/// exact values produced by the original GrantGraph and EffectAuthorizer;
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
    request_identity: RequestIdentity,
    authority: AuthorityBinding,
    supporting_grant_path: Vec<GrantId>,
    grant_graph_revision: u64,
    reservation_id: OperationIdentity,
    canonical_admission_receipt: eliot_receipts::ReceiptIdentity,
    activation_receipt: eliot_receipts::ReceiptIdentity,
}

impl SourceArtifactAdmission {
    pub fn action_lease(&self) -> &ActionLease {
        &self.action_lease
    }

    pub fn authorized_effect(&self) -> &AuthorizedEffect {
        &self.authorized_effect
    }

    /// Original admitted principal whose exact GrantGraph path authorized
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

    /// Stable original Governor ActionLease identity for constructing the
    /// Kernel P-03 `ActionLeaseRef` in this same admitted request stack.
    pub fn action_lease_id(&self) -> &LeaseId {
        &self.action_lease.lease_id
    }

    pub fn reservation_id(&self) -> &OperationIdentity {
        &self.reservation_id
    }

    pub fn canonical_admission_receipt(&self) -> &eliot_receipts::ReceiptIdentity {
        &self.canonical_admission_receipt
    }

    pub fn activation_receipt(&self) -> &eliot_receipts::ReceiptIdentity {
        &self.activation_receipt
    }

    /// Digest of the canonical ActionContract already admitted by the
    /// EffectAuthorizer. A source owner may compare this to its own immutable
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
    #[error("source effect admission binding refused: {0}")]
    Binding(&'static str),
    #[error("source effect admission could not encode the current State Fence")]
    FenceEncoding,
    #[error("source effect admission could not read an original Governor owner: {0}")]
    Owner(String),
    #[error("source effect admission lacks the original canonical ADMITTED or ORS activation receipt")]
    MissingReservationReceipt,
}

/// Admits a source effect through one exact currently-active GrantGraph path,
/// compiles it through the original EffectAuthorizer, and retains the live
/// ActionLease/AuthorizedEffect together with the exact request and ORS
/// receipt references.
pub fn issue_source_artifact_admission(
    authority: &mut AuthorityOwner,
    input: SourceArtifactAdmissionRequest,
) -> Result<SourceArtifactAdmission, SourceArtifactAdmissionError> {
    validate_request(&input)?;
    let active = input.active_reservation.record();
    if active.state != AdmissionReservationState::Active
        || active.work_item_id != input.expected_work_item_id
        || active.proposed_attempt_id != input.expected_proposed_attempt_id
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
    let reservation_id = active.reservation_id.clone();
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
        input.resource_ref,
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
        request_identity: input.request_identity,
        authority: authority_binding,
        supporting_grant_path: supporting_path,
        grant_graph_revision,
        reservation_id,
        canonical_admission_receipt: canonical_receipt,
        activation_receipt,
    })
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
