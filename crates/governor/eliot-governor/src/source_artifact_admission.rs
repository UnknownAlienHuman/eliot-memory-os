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
use std::future::Future;
use std::pin::Pin;

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
    /// Exact original Kernel HostRequest selector retained by the caller.
    pub host_request_operation_id: OperationIdentity,
    /// Digest of the exact original HostRequest envelope.
    pub host_request_digest: String,
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

/// Exact ORS bindings that the current Kernel owner must re-read immediately
/// before a remote source mutation is semantically admitted.
#[derive(Clone, Debug)]
pub struct ActiveReservationUseRequest {
    pub reservation_id: OperationIdentity,
    pub work_item_id: OperationIdentity,
    pub proposed_attempt_id: OperationIdentity,
    pub work_scope_id: String,
    /// LSP-specific claims the current owner was asked to stage. Every
    /// reference and digest is compared with the original persisted ORS row.
    pub claims: eliot_ors::AdmissionReservationClaims,
    pub host_request_operation_id: OperationIdentity,
    pub host_request_digest: String,
    pub identity: RequestIdentity,
}

/// Original typed owner row returned by the authenticated Kernel read port.
/// This is evidence carried beside the live port, never authority by itself.
#[derive(Clone, Debug)]
pub struct ActiveReservationOwnerReadback {
    pub record: eliot_ors::AdmissionReservationRecord,
    pub receipt: eliot_ors::OperationalMutationReceipt,
    pub record_revision: u64,
    pub state_fence: eliot_ors::StateFenceSnapshot,
    pub work_scope_id: String,
    /// Exact `ACTIVE` discriminant projected from the existing ORS verifier.
    pub owner_disposition: String,
    /// Original ORS validator output preserved as opaque owner evidence. It
    /// is never deserialized into `ActiveAdmissionReservation` authority.
    pub owner_verification: serde_json::Value,
}

/// Live authenticated capability for asking Kernel/ORS to recheck one current
/// reservation at use. Implementations retain the authenticated Kernel client
/// and original request binding; they do not return cached projection data.
pub trait ActiveReservationUsePort: Send + Sync {
    fn read_current_active<'a>(
        &'a self,
        request: &'a ActiveReservationUseRequest,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ActiveReservationOwnerReadback, String>> + Send + 'a,
        >,
    >;
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
    /// A typed Governor composition guard refused an owner binding during
    /// source-effect admission. Boxing keeps the refusal typed and inspectable
    /// instead of flattening it into an owner-error string.
    #[error("source effect admission owner guard failed: {0}")]
    OwnerComposition(#[source] Box<crate::composition::CompositionError>),
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
/// canonical-write receipts. Every mutation uses its own reservation-backed
/// issuer path; a source snapshot publication cannot borrow a later LSP
/// reservation or proceed without its own active reservation.
pub(crate) fn issue_source_artifact_admission(
    authority: &mut AuthorityOwner,
    input: SourceArtifactAdmissionRequest,
) -> Result<SourceArtifactAdmission, SourceArtifactAdmissionError> {
    validate_request(&input)?;
    let (reservation_id, canonical_receipt, activation_receipt) =
        validate_original_reservation_bindings(&input)?;

    issue_source_artifact_admission_with_bindings(
        authority,
        input,
        (reservation_id, canonical_receipt, activation_receipt),
    )
}

/// Remote-owner sibling of [`issue_source_artifact_admission`]. It queries the
/// original Kernel ORS owner immediately before the Governor effect decision,
/// then compares the returned record, current receipt, revision, fence and
/// every source request binding before it enters the same GrantGraph and
/// EffectAuthorizer path as local-store callers.
pub async fn issue_source_artifact_admission_with_use_port(
    authority: &mut AuthorityOwner,
    input: SourceArtifactAdmissionRequest,
    reservation_identity: Option<&RequestIdentity>,
    reservation_id: OperationIdentity,
    claims: eliot_ors::AdmissionReservationClaims,
    port: &dyn ActiveReservationUsePort,
) -> Result<SourceArtifactAdmission, SourceArtifactAdmissionError> {
    validate_request(&input)?;
    if input.operation.effect != EffectClass::ReversibleMutation
        || input.active_reservation.is_some()
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "remote current-reservation admission requires a reversible mutation without a deserialized Active typestate",
        ));
    }
    let work_item_id = input
        .expected_work_item_id
        .clone()
        .ok_or(SourceArtifactAdmissionError::MissingReservation)?;
    let proposed_attempt_id = input
        .expected_proposed_attempt_id
        .clone()
        .ok_or(SourceArtifactAdmissionError::MissingReservation)?;
    let query = ActiveReservationUseRequest {
        reservation_id: reservation_id.clone(),
        work_item_id: work_item_id.clone(),
        proposed_attempt_id: proposed_attempt_id.clone(),
        work_scope_id: input.work_scope.scope_id.as_str().to_owned(),
        claims,
        host_request_operation_id: input.host_request_operation_id.clone(),
        host_request_digest: input.host_request_digest.clone(),
        // Current-use remains tied to the original HostRequest/saga identity
        // S. A source effect may use a distinct Governor-issued identity E in
        // `input.request_identity`; substituting E here would change the ORS
        // row being checked.
        identity: reservation_identity
            .cloned()
            .unwrap_or_else(|| input.request_identity.clone()),
    };
    let current = port
        .read_current_active(&query)
        .await
        .map_err(SourceArtifactAdmissionError::Owner)?;
    let bindings = validate_remote_reservation_readback(
        &input,
        &query,
        current,
    )?;
    issue_source_artifact_admission_with_bindings(authority, input, bindings)
}

/// Completes a prepared source mutation with its own active E reservation.
/// The pre-reservation action lease is retained from the same current
/// AuthorityOwner and is compiled only after the Kernel has re-read the exact
/// ACTIVE E row against the original S HostRequest lineage.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn issue_source_artifact_admission_with_prepared_lease(
    authority: &mut AuthorityOwner,
    input: SourceArtifactAdmissionRequest,
    reservation_identity: &RequestIdentity,
    reservation_id: OperationIdentity,
    claims: eliot_ors::AdmissionReservationClaims,
    port: &dyn ActiveReservationUsePort,
    mut action_lease: ActionLease,
    supporting_grant_path: Vec<GrantId>,
    grant_graph_revision: u64,
) -> Result<SourceArtifactAdmission, SourceArtifactAdmissionError> {
    validate_request(&input)?;
    if input.operation.effect != EffectClass::ReversibleMutation
        || input.active_reservation.is_some()
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "prepared source mutation must use a distinct active E reservation",
        ));
    }
    let work_item_id = input
        .expected_work_item_id
        .clone()
        .ok_or(SourceArtifactAdmissionError::MissingReservation)?;
    let proposed_attempt_id = input
        .expected_proposed_attempt_id
        .clone()
        .ok_or(SourceArtifactAdmissionError::MissingReservation)?;
    let query = ActiveReservationUseRequest {
        reservation_id: reservation_id.clone(),
        work_item_id: work_item_id.clone(),
        proposed_attempt_id: proposed_attempt_id.clone(),
        work_scope_id: input.work_scope.scope_id.as_str().to_owned(),
        claims,
        host_request_operation_id: input.host_request_operation_id.clone(),
        host_request_digest: input.host_request_digest.clone(),
        identity: reservation_identity.clone(),
    };
    let current = port
        .read_current_active(&query)
        .await
        .map_err(SourceArtifactAdmissionError::Owner)?;
    let bindings = validate_remote_reservation_readback(&input, &query, current)?;

    let capability = authority.grants.snapshot(
        input.snapshot_id.clone(),
        &input.holder,
        &input.work_scope,
        &input.session,
        input.now,
    )?;
    capability.validate_context(&input.work_scope, &input.session)?;
    let current_path = capability
        .supporting_path(
            &input.operation_name,
            &input.resource_ref,
            input.operation.effect,
        )?
        .grant_path
        .clone();
    if capability.grant_graph_revision() != grant_graph_revision
        || current_path != supporting_grant_path
        || action_lease.lease_id != input.lease_id
        || action_lease.holder != input.holder
        || action_lease.exact_idempotency_key != input.operation.idempotency_key
        || action_lease.work_scope != input.work_scope
        || action_lease.session != input.session
        || action_lease.authority_binding.state_fence != input.work_scope.state_fence
        || action_lease.authority_binding.authority_epoch != input.session.authority_epoch
        || action_lease.remaining_uses == 0
        || action_lease.expires_at <= input.now
        || !action_lease.authority_set.allows(
            &input.operation_name,
            &input.resource_ref,
            input.operation.effect,
        )
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "prepared source E ActionLease or original GrantGraph changed before current use",
        ));
    }
    let compiled = authority.effects.compile_effectful_action(
        &input.contract,
        input.operation.clone(),
        input.operation_name.clone(),
        input.resource_ref.clone(),
        input.executor_boundary.clone(),
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
        supporting_grant_path,
        grant_graph_revision,
        reservation_id: bindings.0,
        canonical_admission_receipt: bindings.1,
        activation_receipt: bindings.2,
    })
}

fn issue_source_artifact_admission_with_bindings(
    authority: &mut AuthorityOwner,
    input: SourceArtifactAdmissionRequest,
    (reservation_id, canonical_receipt, activation_receipt): OriginalReservationBindings,
) -> Result<SourceArtifactAdmission, SourceArtifactAdmissionError> {

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

fn validate_remote_reservation_readback(
    input: &SourceArtifactAdmissionRequest,
    query: &ActiveReservationUseRequest,
    current: ActiveReservationOwnerReadback,
) -> Result<OriginalReservationBindings, SourceArtifactAdmissionError> {
    let record = &current.record;
    record
        .validate()
        .map_err(|_| SourceArtifactAdmissionError::Binding(
            "current Kernel ORS reservation failed the original record validator",
        ))?;
    let expected_work_item = input
        .expected_work_item_id
        .as_ref()
        .ok_or(SourceArtifactAdmissionError::MissingReservation)?;
    let expected_attempt = input
        .expected_proposed_attempt_id
        .as_ref()
        .ok_or(SourceArtifactAdmissionError::MissingReservation)?;
    let fence_json = canonical_json_bytes(&input.work_scope.state_fence)
        .map_err(|_| SourceArtifactAdmissionError::FenceEncoding)?;
    let receipt = &current.receipt;
    if current.owner_disposition != "ACTIVE"
        || current.record_revision == 0
        || current.record_revision != receipt.operation_order()
        || current.state_fence != record.state_fence
        || record.reservation_id != query.reservation_id
        || record.work_item_id != *expected_work_item
        || record.work_item_id != query.work_item_id
        || record.proposed_attempt_id != *expected_attempt
        || record.proposed_attempt_id != query.proposed_attempt_id
        || record.claims != query.claims
        || current.work_scope_id != query.work_scope_id
        || record.state != AdmissionReservationState::Active
        || record.state_fence.canonical_json.as_bytes() != fence_json.as_slice()
        || record.state_fence.observed_authority_epoch
            != input.work_scope.state_fence.authority_epoch.sequence.get()
        || record.canonical_admission_receipt.is_none()
        || record.activation_receipt.is_none()
        || receipt.subject_id() != &record.reservation_id
        || receipt.record_id() != &record.operation_id
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "current Kernel ORS owner readback differs from the exact source operation, WorkScope, work item, attempt, fence, revision, or receipt",
        ));
    }
    let canonical_receipt = record
        .canonical_admission_receipt
        .clone()
        .ok_or(SourceArtifactAdmissionError::MissingReservationReceipt)?;
    let activation_receipt = record
        .activation_receipt
        .clone()
        .ok_or(SourceArtifactAdmissionError::MissingReservationReceipt)?;
    Ok((
        Some(record.reservation_id.clone()),
        Some(canonical_receipt),
        Some(activation_receipt),
    ))
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
    if input.host_request_digest.len() != 64
        || !input
            .host_request_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || input.host_request_operation_id.as_str()
            != format!("hostreq:{}", input.host_request_digest)
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "source admission lacks the exact original HostRequest operation and digest",
        ));
    }
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
