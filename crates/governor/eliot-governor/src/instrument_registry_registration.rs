//! Governor owner for authenticated instrument-registry registration.
//!
//! Registration is a mutation admitted by the original Governor
//! `AuthorityOwner`/`GrantGraph` and its explicit `instrument_registry.register`
//! action. Stage use is read-only: it consumes the original write receipt and
//! the exact-fence registry readback returned here. A source-read grant cannot
//! enter this mutation path.

use std::collections::BTreeMap;

use eliot_authority::{
    ActionContract, ActionLease, AuthorityError, AuthorizedEffect, LogicalTime, SealedEffectDispatch,
};
use eliot_canonical::{CanonicalWriteEnvelope, supported_admission_contract_set_digest};
use eliot_protocol::RequestIdentity;
use eliot_receipts::EffectClass as ReceiptEffectClass;
use eliot_store_api::{
    CanonicalReadClient, EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, NamedReadOperation, NamedReadRequest, NamedReadResponse,
    ReadConsistency, ScopeId, SecurityContext, StoreError, TransitionClass, WriteReceipt,
    WriteReceiptStatus, generated_operation_manifests, operation_manifest_set_digest,
};
use serde_json::Value;
use thiserror::Error;

use crate::authority_recovery::AuthorityOwner;
use crate::composition::{CompositionError, GovernorComposition, KernelGenerationPort};

/// Exact operation kind that the original Governor GrantGraph must admit.
pub const INSTRUMENT_REGISTRY_REGISTER_OPERATION: &str = "instrument_registry.register";
const REGISTRATION_PAYLOAD_WIRE_ID: &str = "eliot.instrument-registry-registration";

/// Non-serializable registration authority issued from the current Governor
/// effect owner. The carrier retains the original request/action/effect and
/// exact selected owner bindings; callers cannot construct it from a host
/// payload, source-read grant, or serialized claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstrumentRegistryRegistrationAdmission {
    identity: RequestIdentity,
    action_contract: ActionContract,
    effect_dispatch: SealedEffectDispatch,
    current_work_scope: eliot_receipts::WorkScopeBinding,
    snapshot_json: String,
    action_payload_sha256: String,
}

impl InstrumentRegistryRegistrationAdmission {
    /// Original authenticated request identity used for registration.
    pub fn request_identity(&self) -> &RequestIdentity {
        &self.identity
    }

    /// Exact registry snapshot bytes admitted by the action contract.
    pub fn snapshot_json(&self) -> &str {
        &self.snapshot_json
    }

    /// Digest of the exact admitted registry action payload.
    pub fn action_payload_sha256(&self) -> &str {
        &self.action_payload_sha256
    }
}

/// Durable owner proof returned by the original registration commit.
///
/// Keep this value with the live registry composition. Stage launch never
/// makes a replacement write or manufactures a receipt from a revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstrumentRegistryRegistrationProof {
    snapshot_json: String,
    action_payload_sha256: String,
    receipt: WriteReceipt,
    readback: NamedReadResponse,
}

impl InstrumentRegistryRegistrationProof {
    /// Exact original WriteReceipt returned by the canonical registration
    /// mutation.
    pub fn receipt(&self) -> &WriteReceipt {
        &self.receipt
    }

    /// Exact same-fence named registry read observed after that commit.
    pub fn readback(&self) -> &NamedReadResponse {
        &self.readback
    }

    /// Verbatim registry snapshot bytes covered by the original receipt.
    pub fn snapshot_json(&self) -> &str {
        &self.snapshot_json
    }

    /// Digest of the admitted registration action payload.
    pub fn action_payload_sha256(&self) -> &str {
        &self.action_payload_sha256
    }
}

/// Canonical request body the original Governor action must authorize.
pub fn instrument_registry_registration_action_payload(
    identity: &RequestIdentity,
    snapshot_json: &str,
) -> Value {
    serde_json::json!({
        "wire_id": REGISTRATION_PAYLOAD_WIRE_ID,
        "wire_version": 1,
        "request_identity": identity,
        "snapshot_json": snapshot_json,
    })
}

/// Issues sealed registration authority after the existing EffectAuthorizer
/// accepts the exact current lease, owner bindings, action, and payload.
#[allow(clippy::too_many_arguments)]
pub fn admit_instrument_registry_registration(
    authority: &AuthorityOwner,
    identity: RequestIdentity,
    action_contract: ActionContract,
    authorized_effect: AuthorizedEffect,
    action_lease: &ActionLease,
    current_work_scope: &eliot_receipts::WorkScopeBinding,
    current_session: &eliot_receipts::SessionBinding,
    now: LogicalTime,
    snapshot_json: String,
) -> Result<InstrumentRegistryRegistrationAdmission, InstrumentRegistryRegistrationError> {
    identity
        .validate()
        .map_err(|_| InstrumentRegistryRegistrationError::Binding("original request is invalid"))?;
    if snapshot_json.is_empty() || snapshot_json.len() > 1_048_576 {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "registry snapshot is empty or exceeds the closed registration limit",
        ));
    }
    let payload = instrument_registry_registration_action_payload(&identity, &snapshot_json);
    let action_payload_sha256 = eliot_contracts::sha256_hex(
        &eliot_contracts::canonical_json_bytes(&payload)
            .map_err(|error| InstrumentRegistryRegistrationError::Payload(error.to_string()))?,
    );
    let operation = &authorized_effect.proposal.operation;
    if operation.operation_kind != INSTRUMENT_REGISTRY_REGISTER_OPERATION
        || operation.effect != ReceiptEffectClass::ReversibleMutation
        || operation.request_id != identity.request.metadata.request_id
        || operation.idempotency_key != identity.idempotency_key
        || operation.state_fence != identity.request.state_fence
        || authorized_effect.proposal.canonical_payload_sha256 != action_payload_sha256
        || authorized_effect.proposal.action_id != action_contract.action_id
        || authorized_effect.proposal.operation_name != INSTRUMENT_REGISTRY_REGISTER_OPERATION
        || !action_contract
            .effect_set
            .contains(INSTRUMENT_REGISTRY_REGISTER_OPERATION)
        || action_contract.task_id
            != identity
                .request
                .metadata
                .task_id
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default()
        || identity.request.metadata.task_id.is_none()
        || identity.request.metadata.product_id != current_work_scope.product_id
        || action_contract.work_scope != *current_work_scope
        || action_contract.work_scope.state_fence != identity.request.state_fence
        || current_session.state_fence != identity.request.state_fence
        || identity.request.metadata.session_id.as_ref() != Some(&current_session.session_id)
    {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "current action, request, effect, task, product, WorkScope, session, payload or fence does not bind this registration",
        ));
    }
    let effect_dispatch = authority.effects.admit_effect_execution(
        &authorized_effect,
        action_lease,
        current_work_scope,
        current_session,
        authorized_effect.executor_boundary.as_str(),
        now,
    )?;
    Ok(InstrumentRegistryRegistrationAdmission {
        identity,
        action_contract,
        effect_dispatch,
        current_work_scope: current_work_scope.clone(),
        snapshot_json,
        action_payload_sha256,
    })
}

/// Admits and commits the exact registry snapshot under the original
/// registration action, then returns that original receipt plus its exact
/// named readback for the stage owner to retain.
pub async fn commit_instrument_registry_registration<
    P: KernelGenerationPort + ?Sized,
    R: CanonicalReadClient + ?Sized,
>(
    composition: &GovernorComposition<P>,
    admitted: &InstrumentRegistryRegistrationAdmission,
    read: &R,
) -> Result<InstrumentRegistryRegistrationProof, InstrumentRegistryRegistrationError> {
    let identity = &admitted.identity;
    let authorized = admitted.effect_dispatch.authorized();
    let operation = &authorized.proposal.operation;
    let snapshot_json = admitted.snapshot_json.clone();
    let action_payload_sha256 = admitted.action_payload_sha256.clone();
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "snapshot_json".to_owned(),
        Value::String(snapshot_json.clone()),
    );
    let command = NamedMutationRequest {
        operation: NamedMutationOperation::ApplyInstrumentRegistryState,
        parameters,
    };
    command.validate()?;
    let scope_id = ScopeId::new(admitted.current_work_scope.scope_id.to_string())
        .map_err(|_| InstrumentRegistryRegistrationError::Binding("WorkScope ID is invalid"))?;
    let envelope = CanonicalWriteEnvelope {
        operation_id: eliot_store_api::OperationIdentity::new(
            operation.operation_id.as_str().to_owned(),
        )
        .map_err(|_| InstrumentRegistryRegistrationError::Binding("operation ID is invalid"))?,
        request: identity.request.metadata.clone(),
        idempotency_key: operation.idempotency_key.clone(),
        scope_id: scope_id.clone(),
        task_id: Some(admitted.action_contract.task_id.clone()),
        transition_class: TransitionClass::InstrumentRegistry,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: supported_admission_contract_set_digest()?,
        operation_manifest_digest: operation_manifest_set_digest(
            &generated_operation_manifests()?,
        )?,
        semantic_commands: vec![command],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    };
    let receipt = composition.commit_canonical(identity, envelope).await?;
    receipt.validate().map_err(StoreError::Receipt)?;
    if receipt.status != WriteReceiptStatus::Committed
        || receipt.commit_id.is_none()
        || receipt.operation_id.as_str() != operation.operation_id.as_str()
        || receipt.idempotency_key != operation.idempotency_key
        || receipt.state_fence != identity.request.state_fence
    {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "canonical registration receipt does not bind the original admitted operation",
        ));
    }
    let readback = read
        .execute_named(NamedReadRequest {
            operation: NamedReadOperation::GetInstrumentRegistryState,
            scope_id: Some(scope_id),
            consistency: ReadConsistency::ExactFence,
            state_fence: identity.request.state_fence.clone(),
            parameters: BTreeMap::new(),
        })
        .await?;
    readback.validate()?;
    let stored_snapshot = readback
        .payload
        .get("snapshot_json")
        .and_then(Value::as_str);
    let revision = readback
        .payload
        .get("revision")
        .and_then(Value::as_u64);
    let payload_fence: Option<eliot_contracts::StateFence> = readback
        .payload
        .get("state_fence")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok());
    if readback.operation != NamedReadOperation::GetInstrumentRegistryState
        || readback.state_fence != receipt.state_fence
        || stored_snapshot != Some(snapshot_json.as_str())
        || revision.is_none_or(|value| value == 0)
        || payload_fence.as_ref() != Some(&readback.state_fence)
        || !readback.revision_heads.iter().any(|head| {
            Some(head.revision) == revision && head.state_fence == receipt.state_fence
        })
    {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "named registry readback does not prove the original committed snapshot and fence",
        ));
    }
    Ok(InstrumentRegistryRegistrationProof {
        snapshot_json,
        action_payload_sha256,
        receipt,
        readback,
    })
}

/// Typed rejection from registry registration or its original readback.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum InstrumentRegistryRegistrationError {
    /// Original live Governor action did not bind this snapshot and context.
    #[error("instrument registry registration binding refused: {0}")]
    Binding(&'static str),
    /// Current ActionLease or effect authorization refused registration.
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    /// Canonical mutation owner refused the exact registration.
    #[error(transparent)]
    Composition(#[from] CompositionError),
    /// Canonical store read/write boundary refused or malformed a response.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Registration action bytes could not be encoded canonically.
    #[error("instrument registry registration payload encoding failed: {0}")]
    Payload(String),
}
