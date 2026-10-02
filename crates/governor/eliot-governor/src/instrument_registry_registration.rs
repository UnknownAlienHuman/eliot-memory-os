//! Governor owner for authenticated instrument-registry registration.
//!
//! Registration is a mutation admitted by the original Governor
//! `AuthorityOwner`/`GrantGraph` and its explicit `instrument_registry.register`
//! action. Stage use is read-only: it consumes the original write receipt and
//! the exact-fence registry readback returned here. A source-read grant cannot
//! enter this mutation path.

use std::collections::BTreeMap;

use eliot_authority::{ActionContract, AuthorityError, LogicalTime, SealedEffectDispatch};
use eliot_canonical::{CanonicalWriteEnvelope, supported_admission_contract_set_digest};
use eliot_observation::{CurrentTaskSelection, TaskSelectionEvidence};
use eliot_protocol::RequestIdentity;
use eliot_receipts::EffectClass as ReceiptEffectClass;
use eliot_store_api::{
    CanonicalReadClient, EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, NamedReadOperation, NamedReadRequest, NamedReadResponse, ReadConsistency,
    RevisionKey, ScopeId, SecurityContext, StoreError, TransitionClass, WriteReceipt,
    WriteReceiptStatus, generated_operation_manifests, named_mutation_operation_name,
    operation_manifest_set_digest,
};
use serde_json::Value;
use thiserror::Error;

use crate::action_lease_admission::{
    ActionLeaseAdmissionCandidate, RegistrationActionLeaseRecord, RegistrationAuthorityLedger,
    RegistrationAuthorityOwnerReadRecord,
};
use crate::composition::{CompositionError, GovernorComposition, KernelGenerationPort};

/// Exact operation kind that the original Governor GrantGraph must admit.
pub(crate) const INSTRUMENT_REGISTRY_REGISTER_OPERATION: &str = "instrument_registry.register";
const REGISTRATION_PAYLOAD_WIRE_ID: &str = "eliot.instrument-registry-registration";

/// Non-serializable registration authority issued from the current Governor
/// effect owner. The carrier retains the original request/action/effect and
/// exact selected owner bindings; callers cannot construct it from a host
/// payload, source-read grant, or serialized claim.
#[derive(Clone, Debug)]
pub(crate) struct InstrumentRegistryRegistrationAdmission {
    identity: RequestIdentity,
    action_contract: ActionContract,
    candidate: ActionLeaseAdmissionCandidate,
    effect_dispatch: SealedEffectDispatch,
    current_work_scope: eliot_receipts::WorkScopeBinding,
    current_session: eliot_receipts::SessionBinding,
    task_selection: TaskSelectionEvidence,
    current_task_selection: CurrentTaskSelection,
    snapshot_json: String,
    action_payload_sha256: String,
    expected_registry_revision: u64,
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

    /// Exact authority ledger committed atomically with the original snapshot.
    pub fn registration_authority_json(&self) -> &str {
        self.candidate.registration_authority_json()
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
    identity: RequestIdentity,
    action_contract: ActionContract,
    current_work_scope: eliot_receipts::WorkScopeBinding,
    current_session: eliot_receipts::SessionBinding,
    task_selection: TaskSelectionEvidence,
    current_task_selection: CurrentTaskSelection,
    snapshot_json: String,
    action_payload_sha256: String,
    registration_authority_json: String,
    receipt: WriteReceipt,
    readback: NamedReadResponse,
    registry_revision: u64,
}

impl InstrumentRegistryRegistrationProof {
    /// Original authenticated request identity used for registration.
    pub fn request_identity(&self) -> &RequestIdentity {
        &self.identity
    }

    /// Original ActionContract admitted for this registration.
    pub fn action_contract(&self) -> &ActionContract {
        &self.action_contract
    }

    /// Exact WorkScope binding admitted for this registration.
    pub fn work_scope(&self) -> &eliot_receipts::WorkScopeBinding {
        &self.current_work_scope
    }

    /// Exact session binding admitted for this registration.
    pub fn session(&self) -> &eliot_receipts::SessionBinding {
        &self.current_session
    }

    /// Exact task-selection evidence rechecked against the original claim and
    /// the live Kernel task-contract acceptance set before registration.
    pub fn task_selection(&self) -> &TaskSelectionEvidence {
        &self.task_selection
    }

    /// Live task binding returned by the Kernel acceptance-set owner at
    /// registration time.
    pub fn current_task_selection(&self) -> &CurrentTaskSelection {
        &self.current_task_selection
    }

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

    /// Exact authority ledger committed atomically with the original snapshot.
    pub fn registration_authority_json(&self) -> &str {
        &self.registration_authority_json
    }

    /// Digest of the admitted registration action payload.
    pub fn action_payload_sha256(&self) -> &str {
        &self.action_payload_sha256
    }

    /// Store-local registry revision captured when this original proof was
    /// committed. Current reads must retain this exact row revision even if
    /// unrelated writes advance the generic scope head.
    pub const fn registry_revision(&self) -> u64 {
        self.registry_revision
    }

    /// Validates a fresh owner read against the immutable original registration
    /// pins retained in this proof. The caller cannot choose replacement
    /// identity, scope, task, snapshot, or action-digest values.
    pub fn validate_current_readback(
        &self,
        current: &NamedReadResponse,
    ) -> Result<(), InstrumentRegistryRegistrationError> {
        let refuse = |detail| InstrumentRegistryRegistrationError::Binding(detail);
        current.validate()?;
        let receipt_envelope = self
            .receipt
            .require_reconciliation_envelope()
            .map_err(InstrumentRegistryRegistrationError::Store)?;
        let [scope_revision] = self.receipt.revision_before_after.as_slice() else {
            return Err(refuse(
                "original registration receipt must carry one scope revision delta",
            ));
        };
        let row = &current.payload;
        let operation_id = row.get("operation_id").and_then(Value::as_str);
        let canonical_request_hash = row.get("canonical_request_hash").and_then(Value::as_str);
        let scope_id = row.get("scope_id").and_then(Value::as_str);
        let task_id = row.get("task_id").and_then(Value::as_str);
        let snapshot_json = row.get("snapshot_json").and_then(Value::as_str);
        let registration_authority_json = row
            .get("registration_authority_json")
            .and_then(Value::as_str);
        let local_revision = row.get("revision").and_then(Value::as_u64);
        let payload_fence: Option<eliot_contracts::StateFence> = row
            .get("state_fence")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok());
        if current.operation != NamedReadOperation::GetInstrumentRegistryState
            || current.state_fence != self.identity.request.state_fence
            || current.state_fence != self.current_work_scope.state_fence
            || snapshot_json != Some(self.snapshot_json.as_str())
            || registration_authority_json != Some(self.registration_authority_json.as_str())
            || local_revision != Some(self.registry_revision)
            || payload_fence.as_ref() != Some(&current.state_fence)
            || operation_id != Some(self.receipt.operation_id.as_str())
            || canonical_request_hash != Some(self.receipt.canonical_request_hash.as_str())
            || scope_id != Some(self.current_work_scope.scope_id.as_str())
            || task_id != Some(self.action_contract.task_id.as_str())
            || receipt_envelope.core.work_scope != self.current_work_scope
            || receipt_envelope.core.request.metadata != self.identity.request.metadata
            || receipt_envelope.core.session.as_ref() != Some(&self.current_session)
            || receipt_envelope.core.operation.operation_id.as_str()
                != self.receipt.operation_id.as_str()
            || receipt_envelope.core.operation.request_id
                != self.identity.request.metadata.request_id
            || receipt_envelope.core.operation.idempotency_key != self.identity.idempotency_key
            || receipt_envelope.core.operation.operation_kind != "store.apply.instrument_registry"
            || receipt_envelope.core.operation.effect != EffectClass::ReversibleMutation
            || self.receipt.transition_class != TransitionClass::InstrumentRegistry
            || self.action_contract.work_scope != self.current_work_scope
            || self.task_selection.task_ref != self.action_contract.task_id
            || self.task_selection.work_scope_ref != self.current_work_scope.scope_id.as_str()
            || self.current_task_selection.task_ref != self.action_contract.task_id
            || self.current_task_selection.work_scope_ref
                != self.current_work_scope.scope_id.as_str()
            || self.current_task_selection.state_fence != self.identity.request.state_fence
            || receipt_envelope
                .core
                .task
                .as_ref()
                .map(|task| task.task_id.to_string())
                != Some(self.action_contract.task_id.clone())
            || !current.revision_heads.iter().any(|head| {
                head.key == scope_revision.key
                    && head.revision >= scope_revision.after
                    && head.state_fence == self.receipt.state_fence
            })
        {
            return Err(refuse(
                "fresh registry read differs from the original registration receipt, action, scope, task, snapshot or local revision",
            ));
        }
        Ok(())
    }
}

/// Canonical request body the original Governor action must authorize.
pub(crate) fn instrument_registry_registration_action_payload(
    identity: &RequestIdentity,
    snapshot_json: &str,
    expected_registry_revision: u64,
) -> Value {
    serde_json::json!({
        "wire_id": REGISTRATION_PAYLOAD_WIRE_ID,
        "wire_version": 1,
        "request_identity": identity,
        "snapshot_json": snapshot_json,
        "expected_registry_revision": expected_registry_revision,
    })
}

/// Computes the canonical payload commitment shared by the lease producer and
/// the original receipt verifier.
pub(crate) fn registration_action_payload_sha256(
    identity: &RequestIdentity,
    snapshot_json: &str,
    expected_registry_revision: u64,
) -> Result<String, InstrumentRegistryRegistrationError> {
    let payload = instrument_registry_registration_action_payload(
        identity,
        snapshot_json,
        expected_registry_revision,
    );
    let bytes = eliot_contracts::canonical_json_bytes(&payload)
        .map_err(|error| InstrumentRegistryRegistrationError::Payload(error.to_string()))?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

fn validate_registration_action_digest(
    approved_payload_sha256: &str,
    identity: &RequestIdentity,
    snapshot_json: &str,
    expected_registry_revision: u64,
) -> Result<String, InstrumentRegistryRegistrationError> {
    let expected =
        registration_action_payload_sha256(identity, snapshot_json, expected_registry_revision)?;
    if approved_payload_sha256 != expected {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "approved registration action does not bind this exact Registry revision",
        ));
    }
    Ok(expected)
}

/// Issues sealed registration authority after the existing EffectAuthorizer
/// accepts the exact current lease, owner bindings, action, and payload.
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_instrument_registry_registration(
    candidate: ActionLeaseAdmissionCandidate,
    identity: RequestIdentity,
    action_contract: ActionContract,
    current_work_scope: &eliot_receipts::WorkScopeBinding,
    current_session: &eliot_receipts::SessionBinding,
    now: LogicalTime,
    snapshot_json: String,
    task_selection: TaskSelectionEvidence,
    current_task_selection: CurrentTaskSelection,
) -> Result<InstrumentRegistryRegistrationAdmission, InstrumentRegistryRegistrationError> {
    identity
        .validate()
        .map_err(|_| InstrumentRegistryRegistrationError::Binding("original request is invalid"))?;
    if snapshot_json.is_empty() || snapshot_json.len() > 1_048_576 {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "registry snapshot is empty or exceeds the closed registration limit",
        ));
    }
    task_selection
        .recheck_against_current(&current_task_selection, &identity.request.state_fence)?;
    if task_selection.is_contaminated()
        || task_selection.task_ref != action_contract.task_id
        || task_selection.work_scope_ref != current_work_scope.scope_id.as_str()
        || current_task_selection.task_ref != action_contract.task_id
        || current_task_selection.work_scope_ref != current_work_scope.scope_id.as_str()
    {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "original claim task-selection evidence does not bind this registration task and WorkScope",
        ));
    }
    let authorized_effect = candidate.authorized_effect();
    let action_payload_sha256 = validate_registration_action_digest(
        &authorized_effect.proposal.canonical_payload_sha256,
        &identity,
        &snapshot_json,
        candidate.expected_registry_revision(),
    )?;
    let operation = &authorized_effect.proposal.operation;
    let executor_boundary =
        named_mutation_operation_name(NamedMutationOperation::ApplyInstrumentRegistryState);
    if operation.operation_kind != INSTRUMENT_REGISTRY_REGISTER_OPERATION
        || candidate.operation_identity().as_str() != operation.operation_id.as_str()
        || operation.effect != ReceiptEffectClass::ReversibleMutation
        || operation.request_id != identity.request.metadata.request_id
        || operation.idempotency_key != identity.idempotency_key
        || operation.state_fence != identity.request.state_fence
        || authorized_effect.proposal.action_id != action_contract.action_id
        || authorized_effect.proposal.operation_name != INSTRUMENT_REGISTRY_REGISTER_OPERATION
        || authorized_effect.proposal.resource_ref != current_work_scope.scope_id.as_str()
        || authorized_effect.executor_boundary != executor_boundary
        || !action_contract
            .effect_set
            .contains(current_work_scope.scope_id.as_str())
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
    let effect_dispatch = candidate.next_effect_authorizer().admit_effect_execution(
        authorized_effect,
        candidate.action_lease(),
        current_work_scope,
        current_session,
        executor_boundary,
        now,
    )?;
    Ok(InstrumentRegistryRegistrationAdmission {
        identity,
        action_contract,
        expected_registry_revision: candidate.expected_registry_revision(),
        candidate,
        effect_dispatch,
        current_work_scope: current_work_scope.clone(),
        current_session: current_session.clone(),
        task_selection,
        current_task_selection,
        snapshot_json,
        action_payload_sha256,
    })
}

/// Admits and commits the exact registry snapshot under the original
/// registration action, then returns that original receipt plus its exact
/// named readback for the stage owner to retain.
pub(crate) async fn commit_instrument_registry_registration<
    P: KernelGenerationPort + ?Sized,
    R: CanonicalReadClient + ?Sized,
>(
    composition: &GovernorComposition<P>,
    admitted: &InstrumentRegistryRegistrationAdmission,
    read: &R,
) -> Result<InstrumentRegistryRegistrationProof, InstrumentRegistryRegistrationError> {
    let identity = &admitted.identity;
    admitted.task_selection.recheck_against_current(
        &admitted.current_task_selection,
        &identity.request.state_fence,
    )?;
    if admitted.task_selection.is_contaminated()
        || admitted.task_selection.task_ref != admitted.action_contract.task_id
        || admitted.task_selection.work_scope_ref != admitted.current_work_scope.scope_id.as_str()
        || admitted.current_task_selection.task_ref != admitted.action_contract.task_id
        || admitted.current_task_selection.work_scope_ref
            != admitted.current_work_scope.scope_id.as_str()
    {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "original task-selection evidence changed before registry commit",
        ));
    }
    let authorized = admitted.effect_dispatch.authorized();
    let operation = &authorized.proposal.operation;
    let snapshot_json = admitted.snapshot_json.clone();
    let action_payload_sha256 = admitted.action_payload_sha256.clone();
    let registration_authority_json = admitted.candidate.registration_authority_json().to_owned();
    let expected_registry_revision = admitted.expected_registry_revision;
    let scope_id = ScopeId::new(admitted.current_work_scope.scope_id.to_string())
        .map_err(|_| InstrumentRegistryRegistrationError::Binding("WorkScope ID is invalid"))?;
    let owner_readback = read
        .execute_named(NamedReadRequest {
            operation: NamedReadOperation::GetInstrumentRegistryState,
            scope_id: Some(scope_id.clone()),
            consistency: ReadConsistency::ExactFence,
            state_fence: identity.request.state_fence.clone(),
            parameters: BTreeMap::new(),
        })
        .await?;
    let (owner_read, owner_revision) = parse_registration_owner_readback(
        &owner_readback,
        admitted.current_work_scope.scope_id.as_str(),
        &identity.request.state_fence,
    )?;
    if &owner_read != admitted.candidate.source_registration_authority_read() {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "canonical registry owner read changed after action-lease admission",
        ));
    }
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "snapshot_json".to_owned(),
        Value::String(snapshot_json.clone()),
    );
    parameters.insert(
        "registration_authority_json".to_owned(),
        Value::String(registration_authority_json.clone()),
    );
    parameters.insert(
        "expected_registry_revision".to_owned(),
        Value::from(expected_registry_revision),
    );
    let command = NamedMutationRequest {
        operation: NamedMutationOperation::ApplyInstrumentRegistryState,
        parameters,
    };
    command.validate()?;
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
        operation_manifest_digest: operation_manifest_set_digest(&generated_operation_manifests()?)?,
        semantic_commands: vec![command],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: vec![admitted.task_selection.evidence_ref.clone()],
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    };
    let request_metadata = identity.request.metadata.clone();
    let prepared_transition = envelope.prepare()?;
    let exact_retry = owner_revision
        .checked_sub(1)
        .is_some_and(|prior_revision| prior_revision == expected_registry_revision)
        && owner_readback
            .payload
            .get("operation_id")
            .and_then(Value::as_str)
            == Some(operation.operation_id.as_str())
        && owner_readback
            .payload
            .get("canonical_request_hash")
            .and_then(Value::as_str)
            == Some(prepared_transition.identity.canonical_request_hash.as_str())
        && owner_readback
            .payload
            .get("snapshot_json")
            .and_then(Value::as_str)
            == Some(snapshot_json.as_str())
        && owner_readback
            .payload
            .get("registration_authority_json")
            .and_then(Value::as_str)
            == Some(registration_authority_json.as_str())
        && owner_readback
            .payload
            .get("scope_id")
            .and_then(Value::as_str)
            == Some(admitted.current_work_scope.scope_id.as_str())
        && owner_readback
            .payload
            .get("task_id")
            .and_then(Value::as_str)
            == Some(admitted.action_contract.task_id.as_str())
        && owner_readback
            .payload
            .get("state_fence")
            .cloned()
            .and_then(|value| serde_json::from_value::<eliot_contracts::StateFence>(value).ok())
            .as_ref()
            == Some(&identity.request.state_fence);
    let resolved_receipt = resolve_original_registration_receipt(
        read,
        operation.operation_id.as_str(),
        &identity.request.state_fence,
    )
    .await?;
    let receipt = if exact_retry {
        let Some(receipt) = resolved_receipt else {
            let operation_id = eliot_store_api::OperationId::new(operation.operation_id.as_str())
                .map_err(StoreError::Foundation)?;
            return Err(StoreError::UnknownOutcome { operation_id }.into());
        };
        receipt
    } else if let Some(_receipt) = resolved_receipt {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "original operation already has a receipt but the current registry row is not its exact committed result",
        ));
    } else if owner_revision != expected_registry_revision {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "canonical registry local revision changed after action-lease admission",
        ));
    } else {
        composition.commit_canonical(identity, envelope).await?
    };
    receipt.validate().map_err(StoreError::Receipt)?;
    eliot_store_api::validate_store_receipt_envelope(
        &request_metadata,
        &prepared_transition,
        &receipt,
    )?;
    if receipt.status != WriteReceiptStatus::Committed
        || receipt.commit_id.is_none()
        || receipt.transition_class != TransitionClass::InstrumentRegistry
        || receipt.operation_id.as_str() != operation.operation_id.as_str()
        || receipt.idempotency_key != operation.idempotency_key
        || receipt.state_fence != identity.request.state_fence
    {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "canonical registration receipt does not bind the original admitted operation",
        ));
    }
    let receipt_envelope = receipt
        .require_reconciliation_envelope()
        .map_err(InstrumentRegistryRegistrationError::Store)?;
    let expected_scope_key = RevisionKey::new(format!("scope:{}", scope_id))
        .map_err(InstrumentRegistryRegistrationError::Store)?;
    let [scope_revision] = receipt.revision_before_after.as_slice() else {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "canonical registration receipt must carry its single original scope revision delta",
        ));
    };
    if scope_revision.key != expected_scope_key
        || scope_revision.after <= scope_revision.before
        || receipt_envelope.core.work_scope != admitted.current_work_scope
        || receipt_envelope.core.request.metadata != identity.request.metadata
        || receipt_envelope.core.operation.operation_id.as_str() != operation.operation_id.as_str()
        || receipt_envelope.core.operation.request_id != identity.request.metadata.request_id
        || receipt_envelope.core.operation.idempotency_key != operation.idempotency_key
        || receipt_envelope.core.operation.operation_kind != "store.apply.instrument_registry"
        || receipt_envelope.core.operation.effect != EffectClass::ReversibleMutation
        || receipt_envelope
            .core
            .task
            .as_ref()
            .map(|task| task.task_id.to_string())
            != Some(admitted.action_contract.task_id.clone())
        || receipt_envelope.core.session.as_ref() != Some(&admitted.current_session)
    {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "canonical registration receipt envelope does not bind the original request, operation, action task and current WorkScope",
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
    let stored_registration_authority_json = readback
        .payload
        .get("registration_authority_json")
        .and_then(Value::as_str);
    let revision = readback.payload.get("revision").and_then(Value::as_u64);
    let stored_operation_id = readback.payload.get("operation_id").and_then(Value::as_str);
    let stored_request_hash = readback
        .payload
        .get("canonical_request_hash")
        .and_then(Value::as_str);
    let stored_scope_id = readback.payload.get("scope_id").and_then(Value::as_str);
    let stored_task_id = readback.payload.get("task_id").and_then(Value::as_str);
    let payload_fence: Option<eliot_contracts::StateFence> = readback
        .payload
        .get("state_fence")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok());
    if readback.operation != NamedReadOperation::GetInstrumentRegistryState
        || readback.state_fence != receipt.state_fence
        || stored_snapshot != Some(snapshot_json.as_str())
        || stored_registration_authority_json != Some(registration_authority_json.as_str())
        || revision.is_none_or(|value| value == 0)
        || stored_operation_id != Some(receipt.operation_id.as_str())
        || stored_request_hash != Some(receipt.canonical_request_hash.as_str())
        || stored_scope_id != Some(admitted.current_work_scope.scope_id.as_str())
        || stored_task_id != Some(admitted.action_contract.task_id.as_str())
        || payload_fence.as_ref() != Some(&readback.state_fence)
        || !readback.revision_heads.iter().any(|head| {
            head.key == scope_revision.key
                && head.revision >= scope_revision.after
                && head.state_fence == receipt.state_fence
        })
    {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "named registry readback does not prove the original committed snapshot and fence",
        ));
    }
    let registry_revision = revision.ok_or(InstrumentRegistryRegistrationError::Binding(
        "named registry readback omitted its store-local registry revision",
    ))?;
    Ok(InstrumentRegistryRegistrationProof {
        identity: admitted.identity.clone(),
        action_contract: admitted.action_contract.clone(),
        current_work_scope: admitted.current_work_scope.clone(),
        current_session: admitted.current_session.clone(),
        task_selection: admitted.task_selection.clone(),
        current_task_selection: admitted.current_task_selection.clone(),
        snapshot_json,
        action_payload_sha256,
        registration_authority_json,
        receipt,
        readback,
        registry_revision,
    })
}

/// Resolves the immutable receipt for an original operation ID. A row hash or
/// a newly recomputed digest is never substituted for this receipt.
pub(crate) async fn resolve_original_registration_receipt<R: CanonicalReadClient + ?Sized>(
    read: &R,
    operation_id: &str,
    state_fence: &eliot_contracts::StateFence,
) -> Result<Option<WriteReceipt>, InstrumentRegistryRegistrationError> {
    let response = read
        .execute_named(NamedReadRequest {
            operation: NamedReadOperation::ResolveWriteReceipt,
            scope_id: None,
            consistency: ReadConsistency::ExactFence,
            state_fence: state_fence.clone(),
            parameters: BTreeMap::from([(
                "operation_id".to_owned(),
                Value::String(operation_id.to_owned()),
            )]),
        })
        .await?;
    response.validate()?;
    if response.operation != NamedReadOperation::ResolveWriteReceipt
        || response.state_fence != *state_fence
    {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "original receipt lookup returned the wrong operation or fence",
        ));
    }
    serde_json::from_value(response.payload).map_err(|_| {
        InstrumentRegistryRegistrationError::Binding(
            "original receipt lookup returned an invalid receipt payload",
        )
    })
}

/// Reconstructs the original prepared transition from the closed retained
/// lease record, then binds its canonical receipt to the exact current owner
/// read. This is the read-only recovery path for an already committed retry;
/// it performs no new authorization, Apply, or revision CAS.
pub(crate) fn prove_original_registration_from_readback(
    registration_authority_json: &str,
    operation_id: &str,
    task_selection: TaskSelectionEvidence,
    current_task_selection: CurrentTaskSelection,
    current_session: eliot_receipts::SessionBinding,
    receipt: WriteReceipt,
    readback: NamedReadResponse,
) -> Result<InstrumentRegistryRegistrationProof, InstrumentRegistryRegistrationError> {
    let ledger = RegistrationAuthorityLedger::from_current_owner_json(registration_authority_json)
        .map_err(|_| {
            InstrumentRegistryRegistrationError::Binding("current registry owner ledger is invalid")
        })?;
    let mut matching_records = ledger
        .leases
        .iter()
        .filter(|record| record.operation.operation_id.as_str() == operation_id);
    let record = matching_records
        .next()
        .ok_or(InstrumentRegistryRegistrationError::Binding(
            "current registry owner ledger does not retain this original operation",
        ))?;
    if matching_records.next().is_some() {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "current registry owner ledger repeats this operation identity",
        ));
    }
    let identity = &record.request_identity;
    let action_contract = &record.action_contract;
    let current_work_scope = &action_contract.work_scope;
    let expected_committed_registry_revision = record
        .expected_registry_revision
        .checked_add(1)
        .ok_or(InstrumentRegistryRegistrationError::Binding(
            "retained original registry revision cannot advance",
        ))?;
    identity
        .validate()
        .map_err(|_| InstrumentRegistryRegistrationError::Binding("original request is invalid"))?;
    task_selection
        .recheck_against_current(&current_task_selection, &identity.request.state_fence)?;
    if task_selection.is_contaminated()
        || task_selection.task_ref != action_contract.task_id
        || task_selection.work_scope_ref != current_work_scope.scope_id.as_str()
        || current_task_selection.task_ref != action_contract.task_id
        || current_task_selection.work_scope_ref != current_work_scope.scope_id.as_str()
        || current_task_selection.state_fence != identity.request.state_fence
        || current_session.state_fence != identity.request.state_fence
        || identity.request.metadata.session_id.as_ref() != Some(&current_session.session_id)
        || identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(ToString::to_string)
            != Some(action_contract.task_id.clone())
        || identity.request.metadata.product_id != current_work_scope.product_id
        || record.executor_boundary
            != named_mutation_operation_name(NamedMutationOperation::ApplyInstrumentRegistryState)
        || record.operation.operation_kind != INSTRUMENT_REGISTRY_REGISTER_OPERATION
        || record.operation.effect != ReceiptEffectClass::ReversibleMutation
        || record.operation.request_id != identity.request.metadata.request_id
        || record.operation.idempotency_key != identity.idempotency_key
        || record.operation.state_fence != identity.request.state_fence
        || record.operation_name != INSTRUMENT_REGISTRY_REGISTER_OPERATION
        || record.resource_ref != current_work_scope.scope_id.as_str()
        || !action_contract
            .effect_set
            .contains(current_work_scope.scope_id.as_str())
    {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "retained original action, task, scope, session or operation does not bind this receipt",
        ));
    }
    readback.validate()?;
    let (owner_read, registry_revision) = parse_registration_owner_readback(
        &readback,
        current_work_scope.scope_id.as_str(),
        &identity.request.state_fence,
    )?;
    if owner_read
        != RegistrationAuthorityOwnerReadRecord::Present(registration_authority_json.to_owned())
    {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "current owner read differs from the retained registration ledger",
        ));
    }
    let snapshot_json = readback
        .payload
        .get("snapshot_json")
        .and_then(Value::as_str)
        .ok_or(InstrumentRegistryRegistrationError::Binding(
            "current owner read omitted its registry snapshot",
        ))?
        .to_owned();
    let action_payload_sha256 = registration_action_payload_sha256(
        identity,
        &snapshot_json,
        record.expected_registry_revision,
    )?;
    if action_payload_sha256 != record.canonical_payload_sha256 {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "current registry snapshot differs from the retained original action payload",
        ));
    }
    let command = NamedMutationRequest {
        operation: NamedMutationOperation::ApplyInstrumentRegistryState,
        parameters: BTreeMap::from([
            (
                "snapshot_json".to_owned(),
                Value::String(snapshot_json.clone()),
            ),
            (
                "registration_authority_json".to_owned(),
                Value::String(registration_authority_json.to_owned()),
            ),
            (
                "expected_registry_revision".to_owned(),
                Value::from(record.expected_registry_revision),
            ),
        ]),
    };
    command.validate()?;
    let scope_id = ScopeId::new(current_work_scope.scope_id.to_string())
        .map_err(|_| InstrumentRegistryRegistrationError::Binding("WorkScope ID is invalid"))?;
    let envelope = CanonicalWriteEnvelope {
        operation_id: eliot_store_api::OperationIdentity::new(
            record.operation.operation_id.as_str().to_owned(),
        )
        .map_err(|_| InstrumentRegistryRegistrationError::Binding("operation ID is invalid"))?,
        request: identity.request.metadata.clone(),
        idempotency_key: record.operation.idempotency_key.clone(),
        scope_id,
        task_id: Some(action_contract.task_id.clone()),
        transition_class: TransitionClass::InstrumentRegistry,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: supported_admission_contract_set_digest()?,
        operation_manifest_digest: operation_manifest_set_digest(&generated_operation_manifests()?)?,
        semantic_commands: vec![command],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: vec![task_selection.evidence_ref.clone()],
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    };
    let prepared_transition = envelope.prepare()?;
    receipt.validate().map_err(StoreError::Receipt)?;
    eliot_store_api::validate_store_receipt_envelope(
        &identity.request.metadata,
        &prepared_transition,
        &receipt,
    )?;
    let receipt_envelope = receipt
        .require_reconciliation_envelope()
        .map_err(InstrumentRegistryRegistrationError::Store)?;
    let [scope_revision] = receipt.revision_before_after.as_slice() else {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "original receipt does not carry its exact scope revision delta",
        ));
    };
    if receipt.status != WriteReceiptStatus::Committed
        || receipt.commit_id.is_none()
        || receipt.transition_class != TransitionClass::InstrumentRegistry
        || receipt.operation_id.as_str() != record.operation.operation_id.as_str()
        || receipt.idempotency_key != record.operation.idempotency_key
        || receipt.state_fence != identity.request.state_fence
        || scope_revision.key.as_str() != format!("scope:{}", current_work_scope.scope_id)
        || scope_revision.after <= scope_revision.before
        || registry_revision != expected_committed_registry_revision
        || receipt_envelope.core.work_scope != *current_work_scope
        || receipt_envelope.core.request.metadata != identity.request.metadata
        || receipt_envelope.core.operation.operation_id.as_str()
            != record.operation.operation_id.as_str()
        || receipt_envelope.core.operation.request_id != identity.request.metadata.request_id
        || receipt_envelope.core.operation.idempotency_key != record.operation.idempotency_key
        || receipt_envelope.core.operation.operation_kind != "store.apply.instrument_registry"
        || receipt_envelope.core.operation.effect != EffectClass::ReversibleMutation
        || receipt_envelope
            .core
            .task
            .as_ref()
            .map(|task| task.task_id.to_string())
            != Some(action_contract.task_id.clone())
        || receipt_envelope.core.session.as_ref() != Some(&current_session)
        || readback.operation != NamedReadOperation::GetInstrumentRegistryState
        || readback.state_fence != receipt.state_fence
        || readback.payload.get("operation_id").and_then(Value::as_str)
            != Some(receipt.operation_id.as_str())
        || readback
            .payload
            .get("canonical_request_hash")
            .and_then(Value::as_str)
            != Some(receipt.canonical_request_hash.as_str())
        || readback.payload.get("scope_id").and_then(Value::as_str)
            != Some(current_work_scope.scope_id.as_str())
        || readback.payload.get("task_id").and_then(Value::as_str)
            != Some(action_contract.task_id.as_str())
        || !readback.revision_heads.iter().any(|head| {
            head.key == scope_revision.key
                && head.revision >= scope_revision.after
                && head.state_fence == receipt.state_fence
        })
    {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "original receipt or current registry read does not prove the retained committed registration",
        ));
    }
    Ok(InstrumentRegistryRegistrationProof {
        identity: identity.clone(),
        action_contract: action_contract.clone(),
        current_work_scope: current_work_scope.clone(),
        current_session,
        task_selection,
        current_task_selection,
        snapshot_json,
        action_payload_sha256,
        registration_authority_json: registration_authority_json.to_owned(),
        receipt,
        readback,
        registry_revision,
    })
}

/// Interprets the canonical owner read without inventing an empty ledger. The
/// only valid `Absent` representation is the explicit zero-revision response
/// with no row fields; an existing row must carry its complete owner ledger.
pub(crate) fn parse_registration_owner_readback(
    response: &NamedReadResponse,
    expected_scope_id: &str,
    expected_state_fence: &eliot_contracts::StateFence,
) -> Result<(RegistrationAuthorityOwnerReadRecord, u64), InstrumentRegistryRegistrationError> {
    response.validate()?;
    if response.operation != NamedReadOperation::GetInstrumentRegistryState {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "registry owner pre-read returned the wrong named operation",
        ));
    }
    if response.state_fence != *expected_state_fence {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "registry owner pre-read returned a different state fence",
        ));
    }
    let revision = response
        .payload
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or(InstrumentRegistryRegistrationError::Binding(
            "registry owner pre-read omitted its local revision",
        ))?;
    let snapshot = response.payload.get("snapshot_json");
    let ledger = response.payload.get("registration_authority_json");
    if revision == 0 {
        if snapshot.is_some_and(Value::is_null)
            && ledger.is_some_and(Value::is_null)
            && response.payload.get("scope_id").is_some_and(Value::is_null)
            && response.payload.get("task_id").is_some_and(Value::is_null)
            && response
                .payload
                .get("operation_id")
                .is_some_and(Value::is_null)
            && response
                .payload
                .get("canonical_request_hash")
                .is_some_and(Value::is_null)
            && response
                .payload
                .get("state_fence")
                .cloned()
                .and_then(|value| serde_json::from_value::<eliot_contracts::StateFence>(value).ok())
                .as_ref()
                == Some(expected_state_fence)
        {
            return Ok((RegistrationAuthorityOwnerReadRecord::Absent, revision));
        }
        return Err(InstrumentRegistryRegistrationError::Binding(
            "zero-revision registry read contains partial owner data",
        ));
    }
    let snapshot =
        snapshot
            .and_then(Value::as_str)
            .ok_or(InstrumentRegistryRegistrationError::Binding(
                "existing registry owner read omitted its snapshot",
            ))?;
    if snapshot.is_empty() {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "existing registry owner read has an empty snapshot",
        ));
    }
    let ledger =
        ledger
            .and_then(Value::as_str)
            .ok_or(InstrumentRegistryRegistrationError::Binding(
                "existing registry owner read omitted its authority ledger",
            ))?;
    RegistrationAuthorityLedger::from_current_owner_json(ledger).map_err(|_| {
        InstrumentRegistryRegistrationError::Binding(
            "existing registry owner read has an invalid authority ledger",
        )
    })?;
    let row_fence = response
        .payload
        .get("state_fence")
        .cloned()
        .and_then(|value| serde_json::from_value::<eliot_contracts::StateFence>(value).ok());
    if response.payload.get("scope_id").and_then(Value::as_str) != Some(expected_scope_id)
        || row_fence.as_ref() != Some(expected_state_fence)
        || response
            .payload
            .get("operation_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || response
            .payload
            .get("canonical_request_hash")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || response
            .payload
            .get("task_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(InstrumentRegistryRegistrationError::Binding(
            "existing registry owner row is outside the selected scope or fence",
        ));
    }
    Ok((
        RegistrationAuthorityOwnerReadRecord::Present(ledger.to_owned()),
        revision,
    ))
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
    /// Original task-selection evidence did not match the live task owner.
    #[error(transparent)]
    TaskSelection(#[from] eliot_observation::GovernorObservationError),
    /// Canonical envelope preparation or its digest binding was refused.
    #[error(transparent)]
    Canonical(#[from] eliot_canonical::CanonicalError),
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::num::NonZeroU64;

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SessionId, SourceId, StateFence,
    };
    use eliot_protocol::RequestIdentity;
    use eliot_receipts::RequestBinding;

    use super::{
        InstrumentRegistryRegistrationError, registration_action_payload_sha256,
        validate_registration_action_digest,
    };

    fn identity() -> RequestIdentity {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            NonZeroU64::new(1).expect("epoch sequence"),
        )
        .expect("epoch");
        let fence = StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"));
        let metadata = RequestMetadata {
            request_id: RequestId::new("request-registry-revision-test").expect("request id"),
            session_id: Some(SessionId::new("session-registry-revision-test").expect("session")),
            task_id: None,
            product_id: ProductId::new("product-registry-revision-test").expect("product"),
            source_id: SourceId::new("source-registry-revision-test").expect("source"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        };
        RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence,
            },
            idempotency_key: "idem-registry-revision-test".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-registry-revision-test".to_owned(),
        }
    }

    #[test]
    fn approved_registration_action_binds_exact_owner_revision() {
        let identity = identity();
        let snapshot = r#"{"schema":"eliot.instrument.registry-snapshot","version":"1.0.0"}"#;
        let original = registration_action_payload_sha256(&identity, snapshot, 0)
            .expect("original action digest");
        assert_eq!(
            validate_registration_action_digest(&original, &identity, snapshot, 0)
                .expect("same revision remains approved"),
            original
        );
        assert_ne!(
            original,
            registration_action_payload_sha256(&identity, snapshot, 1)
                .expect("changed-revision action digest")
        );
        assert!(matches!(
            validate_registration_action_digest(&original, &identity, snapshot, 1),
            Err(InstrumentRegistryRegistrationError::Binding(_))
        ));
    }
}
