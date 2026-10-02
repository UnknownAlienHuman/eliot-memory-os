//! Read-only currentness bridge for the canonical instrument-registry owner.
//!
//! The composition supplies a Kernel-bound [`CanonicalReadClient`] and the
//! exact-fence registry read metadata it already owns. This adapter reads and
//! freezes the registration row and its durable original receipt once, then
//! performs only a fresh named registry read for each stage admission check.
//! It never authors a receipt, commits a replacement registration, or trusts
//! caller-provided receipt JSON.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use eliot_store_api::{
    CanonicalReadClient, EffectClass, NamedReadOperation, NamedReadRequest, NamedReadResponse,
    ReadConsistency, TransitionClass, WriteReceipt, WriteReceiptStatus,
};
use serde_json::{Value, json};

use crate::admission_submission::AdmissionSubmission;
use crate::profile_run::{
    AdmissionSubmissionOwnerReadback, AdmissionSubmissionProofPort, RunnerError,
};

/// Composition-retained proof reader over the exact registration that
/// admitted the current instrument registry snapshot.
///
/// Construct this with the owner-bound canonical read capability and the
/// registration read metadata retained by the composition. The constructor
/// fetches both original durable facts itself; callers cannot supply receipt
/// or row JSON.
pub struct CanonicalRegistryProofPort<C: CanonicalReadClient> {
    client: Arc<C>,
    registry_read: NamedReadRequest,
    receipt: WriteReceipt,
    original_readback: NamedReadResponse,
}

impl<C: CanonicalReadClient + 'static> CanonicalRegistryProofPort<C> {
    /// Reads and freezes the original receipt/readback through the
    /// composition's canonical read capability.
    pub async fn retain_original(
        client: Arc<C>,
        registry_read: NamedReadRequest,
    ) -> Result<Self, RunnerError> {
        registry_read
            .validate()
            .map_err(|error| canonical_read_error("registry registration read request", error))?;
        if registry_read.operation != NamedReadOperation::GetInstrumentRegistryState
            || registry_read.scope_id.is_none()
            || registry_read.consistency != ReadConsistency::ExactFence
            || !registry_read.parameters.is_empty()
        {
            return Err(RunnerError::Binding(
                "owner proof requires the exact-fence scoped registry read request".to_owned(),
            ));
        }
        let original_readback = client
            .execute_named(registry_read.clone())
            .await
            .map_err(|error| canonical_read_error("original registry readback", error))?;
        original_readback
            .validate()
            .map_err(|error| canonical_read_error("original registry readback", error))?;
        if original_readback.operation != NamedReadOperation::GetInstrumentRegistryState
            || original_readback.state_fence != registry_read.state_fence
        {
            return Err(RunnerError::Binding(
                "canonical owner returned a registry readback at a different operation/fence"
                    .to_owned(),
            ));
        }
        let operation_id = original_readback
            .payload
            .get("operation_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                RunnerError::Binding(
                    "original canonical registry row omitted its registration operation id"
                        .to_owned(),
                )
            })?;
        let receipt_read = NamedReadRequest {
            operation: NamedReadOperation::ResolveWriteReceipt,
            scope_id: None,
            consistency: ReadConsistency::ExactFence,
            state_fence: registry_read.state_fence.clone(),
            parameters: BTreeMap::from([("operation_id".to_owned(), json!(operation_id))]),
        };
        receipt_read.validate().map_err(|error| {
            canonical_read_error("original registration receipt request", error)
        })?;
        let receipt_response = client
            .execute_named(receipt_read)
            .await
            .map_err(|error| canonical_read_error("original registration receipt", error))?;
        receipt_response
            .validate()
            .map_err(|error| canonical_read_error("original registration receipt", error))?;
        if receipt_response.operation != NamedReadOperation::ResolveWriteReceipt
            || receipt_response.state_fence != registry_read.state_fence
        {
            return Err(RunnerError::Binding(
                "canonical owner returned the registration receipt at a different operation/fence"
                    .to_owned(),
            ));
        }
        let receipt: Option<WriteReceipt> = serde_json::from_value(receipt_response.payload)
            .map_err(|error| {
                RunnerError::Binding(format!(
                    "canonical owner returned a malformed original registration receipt: {error}"
                ))
            })?;
        let receipt = receipt.ok_or_else(|| {
            RunnerError::Binding(
                "canonical owner has no final receipt for the registry registration".to_owned(),
            )
        })?;
        receipt
            .validate()
            .map_err(|error| canonical_read_error("original registration receipt", error))?;
        if receipt.status != WriteReceiptStatus::Committed
            || receipt.commit_id.is_none()
            || receipt.transition_class != TransitionClass::InstrumentRegistry
            || receipt.operation_id.as_str() != operation_id
            || receipt.state_fence != registry_read.state_fence
        {
            return Err(RunnerError::Binding(
                "resolved write receipt does not identify the committed registry registration"
                    .to_owned(),
            ));
        }
        let receipt_envelope = receipt
            .require_reconciliation_envelope()
            .map_err(|error| canonical_read_error("original registration receipt", error))?;
        let [scope_revision] = receipt.revision_before_after.as_slice() else {
            return Err(RunnerError::Binding(
                "original registration receipt omitted its single scope revision delta".to_owned(),
            ));
        };
        let scope_id = registry_read
            .scope_id
            .as_ref()
            .map(|scope| scope.as_str())
            .ok_or_else(|| {
                RunnerError::Binding("owner proof requires a scoped registry read".to_owned())
            })?;
        let original_payload = &original_readback.payload;
        let row_revision = original_payload.get("revision").and_then(Value::as_u64);
        let row_fence: Option<eliot_contracts::StateFence> = original_payload
            .get("state_fence")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok());
        let row_scope = original_payload.get("scope_id").and_then(Value::as_str);
        let row_task = original_payload.get("task_id").and_then(Value::as_str);
        let row_hash = original_payload
            .get("canonical_request_hash")
            .and_then(Value::as_str);
        let snapshot = original_payload
            .get("snapshot_json")
            .and_then(Value::as_str);
        let authority_ledger = original_payload
            .get("registration_authority_json")
            .and_then(Value::as_str);
        let scope_head = original_readback
            .revision_heads
            .iter()
            .find(|head| head.key == scope_revision.key);
        if scope_revision.key.as_str() != format!("scope:{scope_id}")
            || scope_revision.after <= scope_revision.before
            || receipt_envelope.core.work_scope.scope_id.as_str() != scope_id
            || receipt_envelope.core.work_scope.product_id
                != receipt_envelope.core.request.metadata.product_id
            || receipt_envelope.core.work_scope.state_fence != registry_read.state_fence
            || receipt_envelope.core.request.metadata.state_fence != registry_read.state_fence
            || receipt_envelope.core.operation.operation_id.as_str() != operation_id
            || receipt_envelope.core.operation.request_id
                != receipt_envelope.core.request.metadata.request_id
            || receipt_envelope.core.operation.idempotency_key != receipt.idempotency_key
            || receipt_envelope.core.operation.state_fence != registry_read.state_fence
            || receipt_envelope.core.operation.operation_kind != "store.apply.instrument_registry"
            || receipt_envelope.core.operation.effect != EffectClass::ReversibleMutation
            || receipt_envelope
                .core
                .task
                .as_ref()
                .map(|task| task.task_id.as_str())
                != row_task
            || receipt_envelope
                .core
                .request
                .metadata
                .task_id
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
                != row_task
            || row_revision.is_none_or(|revision| revision == 0)
            || row_fence.as_ref() != Some(&registry_read.state_fence)
            || row_scope != Some(scope_id)
            || row_task.is_none_or(str::is_empty)
            || row_hash != Some(receipt.canonical_request_hash.as_str())
            || snapshot.is_none_or(str::is_empty)
            || authority_ledger.is_none_or(str::is_empty)
            || authority_ledger.is_some_and(|ledger| {
                serde_json::from_str::<Value>(ledger)
                    .map(|value| !value.is_object())
                    .unwrap_or(true)
            })
            || scope_head.is_none_or(|head| {
                head.revision < scope_revision.after || head.state_fence != receipt.state_fence
            })
        {
            return Err(RunnerError::Binding(
                "original registry row, owner scope head, and committed receipt do not bind"
                    .to_owned(),
            ));
        }
        Ok(Self {
            client,
            registry_read,
            receipt,
            original_readback,
        })
    }

    /// The exact-fence registry request retained with the original proof.
    #[must_use]
    pub fn registry_read_request(&self) -> &NamedReadRequest {
        &self.registry_read
    }

    /// The canonical committed receipt returned by the owner at construction.
    #[must_use]
    pub fn original_registration_receipt(&self) -> &WriteReceipt {
        &self.receipt
    }

    /// The registry row read in the same proof-retention step as the receipt.
    #[must_use]
    pub fn original_registry_readback(&self) -> &NamedReadResponse {
        &self.original_readback
    }
}

impl<C: CanonicalReadClient + 'static> AdmissionSubmissionProofPort
    for CanonicalRegistryProofPort<C>
{
    fn read_admission<'a>(
        &'a self,
        _submission: &'a AdmissionSubmission,
    ) -> Pin<
        Box<dyn Future<Output = Result<AdmissionSubmissionOwnerReadback, RunnerError>> + Send + 'a>,
    > {
        Box::pin(async move { self.current_owner_readback().await })
    }

    fn read_pure_admission<'a>(
        &'a self,
        _submission: &'a crate::admission_submission::PureTransformSubmission,
    ) -> Pin<
        Box<dyn Future<Output = Result<AdmissionSubmissionOwnerReadback, RunnerError>> + Send + 'a>,
    > {
        Box::pin(async move { self.current_owner_readback().await })
    }
}

impl<C: CanonicalReadClient> crate::profile_run::admission_proof_port_sealed::Sealed
    for CanonicalRegistryProofPort<C>
{
}

impl<C: CanonicalReadClient + 'static> CanonicalRegistryProofPort<C> {
    /// Rechecks the retained registration against the current canonical row.
    ///
    /// The result carries the original receipt and original row alongside the
    /// current row, so callers can preserve the exact owner evidence without
    /// reconstructing any receipt or registry metadata.
    pub async fn current_owner_readback(
        &self,
    ) -> Result<AdmissionSubmissionOwnerReadback, RunnerError> {
        let current_readback = self
            .client
            .execute_named(self.registry_read.clone())
            .await
            .map_err(|error| canonical_read_error("fresh current registry readback", error))?;
        current_readback
            .validate()
            .map_err(|error| canonical_read_error("fresh current registry readback", error))?;
        if current_readback.operation != NamedReadOperation::GetInstrumentRegistryState
            || current_readback.state_fence != self.registry_read.state_fence
        {
            return Err(RunnerError::Binding(
                "canonical owner returned a current registry readback at a different operation/fence"
                    .to_owned(),
            ));
        }
        let current_operation = current_readback
            .payload
            .get("operation_id")
            .and_then(Value::as_str);
        let original_operation = self.receipt.operation_id.as_str();
        let original_hash = self.receipt.canonical_request_hash.as_str();
        let current_hash = current_readback
            .payload
            .get("canonical_request_hash")
            .and_then(Value::as_str);
        if current_operation != Some(original_operation) || current_hash != Some(original_hash) {
            return Err(RunnerError::Binding(
                "current registry owner row no longer identifies the original registration"
                    .to_owned(),
            ));
        }
        let original_payload = &self.original_readback.payload;
        let current_payload = &current_readback.payload;
        let original_revision = original_payload.get("revision").and_then(Value::as_u64);
        let original_scope = original_payload.get("scope_id").and_then(Value::as_str);
        let original_task = original_payload.get("task_id").and_then(Value::as_str);
        let original_fence = original_payload
            .get("state_fence")
            .cloned()
            .and_then(|value| serde_json::from_value::<eliot_contracts::StateFence>(value).ok());
        let original_head = self.receipt.revision_before_after.first();
        let current_has_original_head = original_head.is_some_and(|revision| {
            current_readback.revision_heads.iter().any(|head| {
                head.key == revision.key
                    && head.revision >= revision.after
                    && head.state_fence == self.receipt.state_fence
            })
        });
        if current_payload.get("snapshot_json") != original_payload.get("snapshot_json")
            || current_payload.get("registration_authority_json")
                != original_payload.get("registration_authority_json")
            || current_payload.get("revision") != original_payload.get("revision")
            || current_payload.get("state_fence") != original_payload.get("state_fence")
            || current_payload.get("scope_id") != original_payload.get("scope_id")
            || current_payload.get("task_id") != original_payload.get("task_id")
            || current_payload.get("operation_id") != original_payload.get("operation_id")
            || current_payload.get("canonical_request_hash")
                != original_payload.get("canonical_request_hash")
            || original_revision.is_none_or(|revision| revision == 0)
            || original_scope.is_none_or(str::is_empty)
            || original_task.is_none_or(str::is_empty)
            || original_fence.as_ref() != Some(&self.receipt.state_fence)
            || !current_has_original_head
        {
            return Err(RunnerError::Binding(
                "current registry owner row differs from the original receipt, authority, scope, task, fence or local revision"
                    .to_owned(),
            ));
        }
        Ok((
            self.receipt.clone(),
            self.original_readback.clone(),
            current_readback,
        ))
    }
}

fn canonical_read_error(context: &str, error: impl std::fmt::Display) -> RunnerError {
    RunnerError::Binding(format!("{context} refused: {error}"))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision,
    };
    use eliot_store_api::{
        CanonicalReadClient, CommitId, EffectClass, EventProjectionRelationIntents,
        NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
        NamedReadResponse, OperationIdentity, OrderingScopeId, ReadConsistency, RevisionDelta,
        RevisionHead, RevisionKey, ScopeId, SecurityContext, StoreError, TransitionClass,
        WriteReceipt, WriteReceiptStatus, bind_issue18_digests, bind_issue18_receipt,
        bind_policy_config_schema_versions, generated_operation_manifests,
        issue_store_receipt_envelope, operation_manifest_set_digest,
        supported_admission_contract_set_digest,
    };
    use serde_json::{Value, json};

    use super::CanonicalRegistryProofPort;
    use crate::profile::{InstrumentRegistry, builtin_specs};
    use crate::profile_run::RunnerError;

    const SCOPE: &str = "scope:instrument-registry-1814";
    const TASK: &str = "task:instrument-registry-1814";
    const OPERATION: &str = "operation:instrument-registry-registration-1814";

    struct ImmediateWake;

    impl Wake for ImmediateWake {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(ImmediateWake));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match Pin::as_mut(&mut future).poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn state_fence() -> StateFence {
        let mut fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("registry owner test lineage"),
                std::num::NonZeroU64::new(1).expect("nonzero owner epoch"),
            )
            .expect("registry owner test epoch"),
            ResourceGeneration::genesis(),
        );
        fence.task_revision = Some(TaskRevision::genesis());
        fence
    }

    fn registration_authority_json() -> String {
        // This is the Governor-owned wire shape already used by the real
        // Surreal acceptance path. It is a valid empty initial ledger and
        // grants no action lease or instrument admission.
        serde_json::to_string(&json!({
            "schema": "eliot.governor.registration-authority-ledger",
            "version": 1,
            "grant_uses": [],
            "leases": [],
        }))
        .expect("serialize registration authority ledger")
    }

    fn registry_snapshot() -> String {
        InstrumentRegistry::build(
            builtin_specs().expect("built-in instrument specs"),
            Vec::new(),
            1,
            Vec::new(),
        )
        .expect("built-in instrument registry")
        .persist()
        .expect("persist instrument registry")
    }

    fn committed_registration(
        snapshot_json: &str,
        authority_json: &str,
        fence: &StateFence,
    ) -> WriteReceipt {
        let metadata = RequestMetadata {
            request_id: RequestId::new(OPERATION).expect("request identity"),
            session_id: None,
            task_id: Some(TaskId::new(TASK).expect("registration task")),
            product_id: ProductId::new("instrument-registry-store-fixture")
                .expect("registration product"),
            source_id: SourceId::new("instrument-registry-store-fixture")
                .expect("registration source"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        };
        let manifests = generated_operation_manifests().expect("operation manifests");
        let mut transition = eliot_store_api::PreparedTransition {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            identity: OperationIdentity {
                operation_id: OperationId::new(OPERATION).expect("operation identity"),
                idempotency_key: OPERATION.to_owned(),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence: fence.clone(),
            scope_id: ScopeId::new(SCOPE).expect("work scope"),
            task_id: Some(TASK.to_owned()),
            ordering_scopes: vec![OrderingScopeId::new(SCOPE).expect("ordering scope")],
            transition_class: TransitionClass::InstrumentRegistry,
            requested_effect_ceiling: EffectClass::ReversibleMutation,
            admission_contract_set_digest: supported_admission_contract_set_digest()
                .expect("admission contract digest"),
            operation_manifest_digest: operation_manifest_set_digest(&manifests)
                .expect("operation manifest digest"),
            admission_digest: String::new(),
            mutation_plan_digest: String::new(),
            semantic_source_revisions: Vec::new(),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::ApplyInstrumentRegistryState,
                parameters: BTreeMap::from([
                    ("snapshot_json".to_owned(), json!(snapshot_json)),
                    (
                        "registration_authority_json".to_owned(),
                        json!(authority_json),
                    ),
                    ("expected_registry_revision".to_owned(), json!(0)),
                ]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        };
        bind_issue18_digests(&mut transition).expect("bind canonical transition digests");
        let mut receipt = WriteReceipt {
            operation_id: transition.identity.operation_id.clone(),
            idempotency_key: transition.identity.idempotency_key.clone(),
            canonical_request_hash: transition.identity.canonical_request_hash.clone(),
            transition_class: TransitionClass::InstrumentRegistry,
            status: WriteReceiptStatus::Committed,
            commit_id: Some(
                CommitId::new("commit:instrument-registry-registration-1814")
                    .expect("commit identity"),
            ),
            state_fence: fence.clone(),
            ordering_sequences: Vec::new(),
            revision_before_after: vec![RevisionDelta {
                key: RevisionKey::new(format!("scope:{SCOPE}"))
                    .expect("registration scope revision key"),
                before: 1,
                after: 2,
            }],
            applied_command_ids: vec!["ApplyInstrumentRegistryState".to_owned()],
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: transition.operation_manifest_digest.clone(),
            admission_digest: transition.admission_digest.clone(),
            mutation_plan_digest: transition.mutation_plan_digest.clone(),
            semantic_source_revisions: Vec::new(),
            policy_config_schema_versions: eliot_store_api::PolicyConfigSchemaVersions::bound_to(
                &transition,
            ),
            error_code: None,
            resubmission: eliot_store_api::Resubmission::None,
            committed_at: Some("commit-sequence-0000000000000001".to_owned()),
            envelope: None,
        };
        bind_issue18_receipt(&transition, &mut receipt, &[]);
        bind_policy_config_schema_versions(&transition, &mut receipt);
        receipt.envelope = Some(
            issue_store_receipt_envelope(&metadata, &transition, &receipt, 1)
                .expect("issue canonical registration receipt envelope"),
        );
        receipt
            .validate()
            .expect("valid committed registry receipt");
        receipt
    }

    fn registry_readback(payload: Value, fence: &StateFence) -> NamedReadResponse {
        NamedReadResponse {
            operation: NamedReadOperation::GetInstrumentRegistryState,
            state_fence: fence.clone(),
            revision_heads: vec![RevisionHead {
                key: RevisionKey::new(format!("scope:{SCOPE}"))
                    .expect("registration scope revision key"),
                revision: 2,
                state_fence: fence.clone(),
            }],
            payload,
        }
    }

    fn owner_payload(
        receipt: &WriteReceipt,
        snapshot_json: &str,
        authority_json: &str,
        fence: &StateFence,
    ) -> Value {
        json!({
            "snapshot_json": snapshot_json,
            "registration_authority_json": authority_json,
            "revision": 1,
            "state_fence": fence,
            "scope_id": SCOPE,
            "task_id": TASK,
            "operation_id": receipt.operation_id.as_str(),
            "canonical_request_hash": receipt.canonical_request_hash,
        })
    }

    struct OwnerReadClient {
        responses: Mutex<VecDeque<NamedReadResponse>>,
    }

    impl CanonicalReadClient for OwnerReadClient {
        async fn revision_heads(
            &self,
            _keys: Vec<RevisionKey>,
        ) -> Result<Vec<RevisionHead>, StoreError> {
            Ok(Vec::new())
        }

        async fn execute_named(
            &self,
            request: NamedReadRequest,
        ) -> Result<NamedReadResponse, StoreError> {
            let response = self
                .responses
                .lock()
                .map_err(|_| StoreError::Unavailable)?
                .pop_front()
                .ok_or(StoreError::Unavailable)?;
            if response.operation != request.operation
                || response.state_fence != request.state_fence
            {
                return Err(StoreError::FenceMismatch);
            }
            Ok(response)
        }
    }

    fn proof_client(
        current_authority: Option<String>,
    ) -> (Arc<OwnerReadClient>, NamedReadRequest, Value, WriteReceipt) {
        let fence = state_fence();
        let snapshot = registry_snapshot();
        let authority = registration_authority_json();
        let receipt = committed_registration(&snapshot, &authority, &fence);
        let original_payload = owner_payload(&receipt, &snapshot, &authority, &fence);
        let original = registry_readback(original_payload.clone(), &fence);
        let mut current_payload = original_payload.clone();
        if let Some(authority) = current_authority {
            current_payload["registration_authority_json"] = json!(authority);
        }
        let current = registry_readback(current_payload, &fence);
        let receipt_response = NamedReadResponse {
            operation: NamedReadOperation::ResolveWriteReceipt,
            state_fence: fence.clone(),
            revision_heads: original.revision_heads.clone(),
            payload: serde_json::to_value(Some(receipt)).expect("serialize original receipt"),
        };
        let client = Arc::new(OwnerReadClient {
            responses: Mutex::new(VecDeque::from([original, receipt_response, current])),
        });
        let request = NamedReadRequest {
            operation: NamedReadOperation::GetInstrumentRegistryState,
            scope_id: Some(ScopeId::new(SCOPE).expect("registry WorkScope")),
            consistency: ReadConsistency::ExactFence,
            state_fence: fence,
            parameters: BTreeMap::new(),
        };
        (client, request, original_payload, receipt)
    }

    #[test]
    fn canonical_registry_proof_accepts_original_row_and_unchanged_current_read() {
        let (client, request, _, _) = proof_client(None);
        let proof = block_on(CanonicalRegistryProofPort::retain_original(client, request))
            .expect("retain canonical original registration proof");
        assert_eq!(
            proof.registry_read_request().operation,
            NamedReadOperation::GetInstrumentRegistryState
        );
        assert_eq!(
            proof.original_registration_receipt().operation_id.as_str(),
            OPERATION
        );
        assert_eq!(
            proof.original_registry_readback().payload["operation_id"],
            OPERATION
        );

        let (receipt, original_readback, current_readback) =
            block_on(proof.current_owner_readback()).expect("unchanged owner row remains current");
        assert_eq!(receipt.operation_id.as_str(), OPERATION);
        assert_eq!(
            current_readback.payload, original_readback.payload,
            "current row must retain every original owner binding"
        );
    }

    #[test]
    fn canonical_registry_proof_refuses_changed_authority_ledger() {
        let changed_authority = serde_json::to_string_pretty(&json!({
            "schema": "eliot.governor.registration-authority-ledger",
            "version": 1,
            "grant_uses": [],
            "leases": [],
        }))
        .expect("serialize same-schema changed ledger bytes");
        let (client, request, _, _) = proof_client(Some(changed_authority));
        let proof = block_on(CanonicalRegistryProofPort::retain_original(client, request))
            .expect("retain canonical original registration proof");

        assert!(matches!(
            block_on(proof.current_owner_readback()),
            Err(RunnerError::Binding(_))
        ));
    }
}
