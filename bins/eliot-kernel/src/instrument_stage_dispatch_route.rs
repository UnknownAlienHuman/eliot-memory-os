//! Authenticated Kernel admission for one exact external instrument stage.
//!
//! The caller supplies typed selection and intent material only. The Kernel
//! rereads the canonical registry at the original request fence, re-observes
//! the executable named by the typed intent, validates the exact stage through
//! the shared instrument API, then returns the existing Kernel dispatch grant
//! bound to `ProcessIntent::effect_digest`.

#[cfg(windows)]
use eliot_contracts::sha256_hex;
use eliot_instrument_api::registry::{
    EnvironmentInheritanceBinding, EnvironmentProjectionBinding, EnvironmentSecretReference,
    ExternalExecutableObservation, InstrumentRegistrySnapshot, ProcessExecutionProjection,
    validate_external_stage,
};
use eliot_ipc::{RequestIdentity, Session, TransportError};
pub(crate) use eliot_kernel_service::INSTRUMENT_STAGE_GRANT_OPERATION;
#[cfg(windows)]
use eliot_kernel_service::{
    InstrumentStageGrantRequest, InstrumentStageGrantResponse, InstrumentStageStartedRequest,
    InstrumentStageStartedResponse, InstrumentStageTerminalRequest,
    InstrumentStageTerminalResponse,
};
#[cfg(windows)]
use eliot_store_api::{NamedReadOperation, NamedReadRequest, ReadConsistency};
#[cfg(windows)]
use eliot_workscope::{ScopeKind, WorkScopeBindingSnapshot};
use serde_json::Value;
#[cfg(windows)]
use serde_json::json;
#[cfg(windows)]
use std::io::Read;

#[cfg(windows)]
fn runtime_refusal(error: eliot_kernel_service::InstrumentStageRuntimeError) -> TransportError {
    match error {
        eliot_kernel_service::InstrumentStageRuntimeError::Capacity => TransportError::Backpressure,
        eliot_kernel_service::InstrumentStageRuntimeError::Binding
        | eliot_kernel_service::InstrumentStageRuntimeError::Physical
        | eliot_kernel_service::InstrumentStageRuntimeError::Unavailable => {
            TransportError::SessionFenced
        }
    }
}

impl super::KernelComposition {
    /// Validates a typed external-stage intent against the current canonical
    /// registry and returns the existing dispatch grant bound to its exact
    /// process-intent digest.
    #[cfg(windows)]
    pub(crate) async fn instrument_stage_grant_operation(
        &self,
        session: &Session,
        identity: &RequestIdentity,
        payload: Value,
    ) -> Result<Value, TransportError> {
        use eliot_ipc::{PeerIdentity, SessionState};

        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if session.state != SessionState::Open
            || !matches!(&session.peer, PeerIdentity::Authenticated { .. })
            || session.peer.validate().is_err()
            || identity.request.state_fence != session.module_generation.state_fence
            || identity.request.metadata.task_id.is_none()
        {
            return Err(TransportError::SessionFenced);
        }
        let request: InstrumentStageGrantRequest =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        request
            .intent
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        request
            .invocation
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if request.invocation.request != identity.request.metadata
            || request.invocation.request.state_fence != identity.request.state_fence
            || request.invocation.target != request.intent.working_directory()
            || request.intent.operation_id().as_str()
                != request.invocation.request.request_id.as_str()
            || request.intent.generation().get()
                != identity.request.state_fence.resource_generation.value()
            || identity.deadline_unix_ms < super::dispatch_launch::unix_ms()
        {
            return Err(TransportError::SessionFenced);
        }

        let executable_path = std::path::Path::new(request.intent.executable());
        let canonical_path =
            std::fs::canonicalize(executable_path).map_err(|_| TransportError::SessionFenced)?;
        if canonical_path != executable_path || !canonical_path.is_file() {
            return Err(TransportError::SessionFenced);
        }
        let pinned_file = eliot_platform_windows::PinnedRuntimeFile::open(&canonical_path)
            .map_err(|_| TransportError::SessionFenced)?;
        let file_identity = pinned_file.file_identity();
        if request.intent.executable_file_identity() != Some(&file_identity) {
            return Err(TransportError::SessionFenced);
        }
        let mut read_handle = pinned_file
            .try_clone_file()
            .map_err(|_| TransportError::SessionFenced)?;
        let mut bytes = Vec::new();
        read_handle
            .read_to_end(&mut bytes)
            .map_err(|_| TransportError::SessionFenced)?;
        let content_digest = sha256_hex(&bytes);
        if content_digest != request.intent.executable_sha256() {
            return Err(TransportError::SessionFenced);
        }
        let file_name = canonical_path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or(TransportError::SessionFenced)?
            .to_ascii_lowercase();
        let executable_file_name = file_name
            .strip_suffix(".exe")
            .unwrap_or(&file_name)
            .to_owned();
        let mut observation = ExternalExecutableObservation {
            canonical_path: canonical_path.to_string_lossy().into_owned(),
            executable_file_name,
            content_digest,
            file_identity: file_identity.clone(),
            tool_version: None,
        };

        let registry_read = NamedReadRequest {
            operation: NamedReadOperation::GetInstrumentRegistryState,
            scope_id: Some(request.scope_id.clone()),
            consistency: ReadConsistency::ExactFence,
            state_fence: identity.request.state_fence.clone(),
            parameters: Default::default(),
        };
        let state = self
            .instrument_registry_read_operation(
                session,
                identity,
                json!({"scope_id": request.scope_id.clone(), "request": registry_read}),
            )
            .await?;
        let state: eliot_store_api::NamedReadResponse =
            serde_json::from_value(state).map_err(|_| TransportError::SessionFenced)?;
        state
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let snapshot_json = state
            .payload
            .get("snapshot_json")
            .and_then(Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        let snapshot: InstrumentRegistrySnapshot<Value> =
            serde_json::from_str(snapshot_json).map_err(|_| TransportError::SessionFenced)?;
        if snapshot.generation != request.pin.registry_generation {
            return Err(TransportError::SessionFenced);
        }
        let profile = snapshot
            .profiles
            .iter()
            .find(|profile| {
                profile.name == request.pin.profile
                    && profile.revision == request.pin.profile_revision
            })
            .ok_or(TransportError::SessionFenced)?;
        let stage = profile
            .dag
            .iter()
            .find(|stage| stage.stage_id == request.pin.stage_id)
            .ok_or(TransportError::SessionFenced)?;
        let spec = snapshot
            .specs
            .iter()
            .find(|spec| spec.kind == stage.spec)
            .ok_or(TransportError::SessionFenced)?;
        let operation_id = state
            .payload
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        observation.tool_version = super::dispatch_launch::recorded_tool_version(
            &snapshot,
            spec,
            &observation.executable_file_name,
            &observation.content_digest,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let receipt_response = self
            .instrument_registry_read_operation(
                session,
                identity,
                json!({"scope_id": request.scope_id.clone(), "request": {
                    "operation": NamedReadOperation::ResolveWriteReceipt,
                    "scope_id": Value::Null,
                    "consistency": ReadConsistency::ExactFence,
                    "state_fence": identity.request.state_fence,
                    "parameters": {"operation_id": operation_id}
                }}),
            )
            .await?;
        let receipt_response: eliot_store_api::NamedReadResponse =
            serde_json::from_value(receipt_response).map_err(|_| TransportError::SessionFenced)?;
        let receipt: Option<eliot_store_api::WriteReceipt> =
            serde_json::from_value(receipt_response.payload)
                .map_err(|_| TransportError::SessionFenced)?;
        let receipt = receipt.ok_or(TransportError::SessionFenced)?;
        eliot_store_api::validate_instrument_registry_registration_readback(&state, &receipt)
            .map_err(|_| TransportError::SessionFenced)?;
        receipt
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        validate_registered_work_scope(
            &state.payload,
            identity,
            operation_id,
            &receipt,
            &request.scope_id,
            request.intent.working_directory(),
        )?;

        let admission = validate_external_stage(
            &snapshot,
            &request.pin,
            &request.invocation,
            &observation,
            request.intent.argv(),
            &request.resolution,
            &ProcessExecutionProjection {
                working_directory: request.intent.working_directory().to_owned(),
                environment_digest: eliot_process_executor::environment_projection_digest(
                    request.intent.environment(),
                ),
                environment_projection: process_environment_binding(request.intent.environment()),
                executable_file_identity: file_identity,
                authority_epoch: identity.request.state_fence.authority_epoch.clone(),
                resource_generation: request.intent.generation().get(),
                wall_timeout_ms: request.intent.resource_limits().wall_timeout_ms(),
                stdout_bytes: request.intent.resource_limits().stdout_bytes(),
                stderr_bytes: request.intent.resource_limits().stderr_bytes(),
            },
        )
        .map_err(|_| TransportError::SessionFenced)?;
        request
            .validate_admission_binding(&admission)
            .map_err(|_| TransportError::SessionFenced)?;
        if request.intent.executable() != observation.canonical_path
            || request.intent.executable_sha256() != observation.content_digest
            || receipt.state_fence != identity.request.state_fence
            || receipt.operation_id.as_str() != operation_id
            || receipt.status != eliot_store_api::WriteReceiptStatus::Committed
            || receipt.commit_id.is_none()
        {
            return Err(TransportError::SessionFenced);
        }
        let (epoch, generation) = {
            let service = self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let authenticated = super::dispatch_launch::bind_testd_owner_session(&service)
                .map_err(|_| TransportError::SessionFenced)?;
            (
                authenticated.authority_epoch().clone(),
                authenticated.generation(),
            )
        };
        if !epoch.is_same_authority(&identity.request.state_fence.authority_epoch)
            || generation != request.intent.generation()
        {
            return Err(TransportError::SessionFenced);
        }
        let owner_path = super::dispatch_launch::testd_owner_store_path(&self.work_root);
        let dispatch_grant = super::dispatch_launch::dispatch_grant_for(
            super::dispatch_launch::DispatchedWorkerKind::Testd,
            request.intent.effect_digest(),
            &epoch,
            generation,
            super::unix_ms().saturating_mul(1_000_000),
            Some(&owner_path),
        )
        .map_err(|_| TransportError::SessionFenced)?;
        self.instrument_stage_runtime
            .reserve(
                identity,
                &session.peer,
                &request,
                &admission,
                &dispatch_grant,
            )
            .map_err(runtime_refusal)?;
        serde_json::to_value(InstrumentStageGrantResponse {
            admission,
            dispatch_grant,
        })
        .map_err(|_| TransportError::SessionFenced)
    }

    /// Retains and verifies the actual suspended process Job before the
    /// executor is authorized to resume it.
    #[cfg(windows)]
    pub(crate) fn instrument_stage_started_operation(
        &self,
        session: &Session,
        identity: &RequestIdentity,
        payload: Value,
    ) -> Result<Value, TransportError> {
        use eliot_ipc::{PeerIdentity, SessionState};

        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if session.state != SessionState::Open
            || !matches!(&session.peer, PeerIdentity::Authenticated { .. })
            || session.peer.validate().is_err()
            || identity.request.state_fence != session.module_generation.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        let request: InstrumentStageStartedRequest =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        let response: InstrumentStageStartedResponse = self
            .instrument_stage_runtime
            .started(identity, &session.peer, request)
            .map_err(runtime_refusal)?;
        serde_json::to_value(response).map_err(|_| TransportError::SessionFenced)
    }

    /// Releases the retained instrument slot only after the original Job
    /// handle proves that the process tree is physically empty.
    #[cfg(windows)]
    pub(crate) fn instrument_stage_terminal_operation(
        &self,
        session: &Session,
        identity: &RequestIdentity,
        payload: Value,
    ) -> Result<Value, TransportError> {
        use eliot_ipc::{PeerIdentity, SessionState};

        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let request: InstrumentStageTerminalRequest =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        let historical_terminal = identity.request.state_fence
            != session.module_generation.state_fence
            && self.instrument_stage_runtime.matches_terminal_binding(
                identity,
                &session.peer,
                &request,
            );
        if session.state != SessionState::Open
            || !matches!(&session.peer, PeerIdentity::Authenticated { .. })
            || session.peer.validate().is_err()
            || (identity.request.state_fence != session.module_generation.state_fence
                && !historical_terminal)
        {
            return Err(TransportError::SessionFenced);
        }
        let response: InstrumentStageTerminalResponse = self
            .instrument_stage_runtime
            .terminal(identity, &session.peer, request)
            .map_err(runtime_refusal)?;
        serde_json::to_value(response).map_err(|_| TransportError::SessionFenced)
    }

    #[cfg(not(windows))]
    pub(crate) fn instrument_stage_started_operation(
        &self,
        _session: &Session,
        _identity: &RequestIdentity,
        _payload: Value,
    ) -> Result<Value, TransportError> {
        Err(TransportError::SessionFenced)
    }

    #[cfg(not(windows))]
    pub(crate) fn instrument_stage_terminal_operation(
        &self,
        _session: &Session,
        _identity: &RequestIdentity,
        _payload: Value,
    ) -> Result<Value, TransportError> {
        Err(TransportError::SessionFenced)
    }

    #[cfg(not(windows))]
    pub(crate) async fn instrument_stage_grant_operation(
        &self,
        _session: &Session,
        _identity: &RequestIdentity,
        _payload: Value,
    ) -> Result<Value, TransportError> {
        Err(TransportError::SessionFenced)
    }
}

fn process_environment_binding(
    projection: &eliot_process::EnvironmentProjection,
) -> EnvironmentProjectionBinding {
    EnvironmentProjectionBinding {
        non_secret: projection.non_secret().clone(),
        secret_refs: projection
            .secret_refs()
            .iter()
            .map(|reference| EnvironmentSecretReference {
                provider: reference.provider().to_owned(),
                key: reference.key().to_owned(),
            })
            .collect(),
        inheritance: match projection.inheritance() {
            eliot_process::EnvironmentInheritance::None => EnvironmentInheritanceBinding::None,
            eliot_process::EnvironmentInheritance::Allowlisted => {
                EnvironmentInheritanceBinding::Allowlisted
            }
        },
    }
}

/// Validates the original admitted filesystem WorkScope attached to the
/// canonical registration against the unchanged authenticated identity and
/// independently canonicalized source directory. The opaque owner root
/// reference is compared verbatim; it is never parsed or treated as a path.
#[cfg(windows)]
pub(crate) fn validate_registered_work_scope(
    row: &Value,
    identity: &RequestIdentity,
    registration_operation_id: &str,
    receipt: &eliot_store_api::WriteReceipt,
    scope_id: &eliot_store_api::ScopeId,
    source_root: &str,
) -> Result<WorkScopeBindingSnapshot, TransportError> {
    let ledger_json = row
        .get("registration_authority_json")
        .and_then(Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    let ledger: Value =
        serde_json::from_str(ledger_json).map_err(|_| TransportError::SessionFenced)?;
    if ledger.get("schema").and_then(Value::as_str)
        != Some("eliot.governor.registration-authority-ledger")
        || ledger.get("version").and_then(Value::as_u64) != Some(2)
    {
        return Err(TransportError::SessionFenced);
    }
    if receipt.operation_id.as_str() != registration_operation_id
        || receipt.state_fence != identity.request.state_fence
    {
        return Err(TransportError::SessionFenced);
    }
    let envelope = receipt
        .envelope
        .as_ref()
        .ok_or(TransportError::SessionFenced)?;
    if envelope.core.operation.operation_id != receipt.operation_id
        || envelope.core.operation.idempotency_key != receipt.idempotency_key
        || envelope.core.operation.state_fence != receipt.state_fence
        || envelope.core.request.state_fence != receipt.state_fence
        || envelope.core.work_scope.scope_id.as_str() != scope_id.as_str()
        || envelope.core.work_scope.product_id != identity.request.metadata.product_id
        || envelope.core.work_scope.resource_generation
            != identity.request.state_fence.resource_generation
        || envelope.core.work_scope.state_fence != identity.request.state_fence
    {
        return Err(TransportError::SessionFenced);
    }
    let leases = ledger
        .get("leases")
        .and_then(Value::as_array)
        .ok_or(TransportError::SessionFenced)?;
    let mut matching = leases.iter().filter(|lease| {
        lease
            .get("operation")
            .and_then(|operation| operation.get("request_id"))
            .and_then(Value::as_str)
            == Some(envelope.core.request.metadata.request_id.as_str())
            && lease
                .get("operation")
                .and_then(|operation| operation.get("operation_id"))
                .and_then(Value::as_str)
                == Some(registration_operation_id)
            && lease
                .get("operation")
                .and_then(|operation| operation.get("idempotency_key"))
                .and_then(Value::as_str)
                == Some(receipt.idempotency_key.as_str())
            && lease
                .get("operation")
                .and_then(|operation| operation.get("state_fence"))
                .and_then(|fence| {
                    serde_json::from_value::<eliot_contracts::StateFence>(fence.clone()).ok()
                })
                .as_ref()
                == Some(&receipt.state_fence)
    });
    let lease = matching.next().ok_or(TransportError::SessionFenced)?;
    if matching.next().is_some() {
        return Err(TransportError::SessionFenced);
    }
    let original_identity: RequestIdentity = serde_json::from_value(
        lease
            .get("request_identity")
            .cloned()
            .ok_or(TransportError::SessionFenced)?,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    original_identity
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    if original_identity.request.metadata != envelope.core.request.metadata
        || original_identity.request.state_fence != receipt.state_fence
        || original_identity.idempotency_key != receipt.idempotency_key
        || original_identity.request.metadata.task_id != identity.request.metadata.task_id
        || original_identity.request.metadata.product_id != identity.request.metadata.product_id
    {
        return Err(TransportError::SessionFenced);
    }
    let snapshot: WorkScopeBindingSnapshot = serde_json::from_value(
        lease
            .get("work_scope_binding_snapshot")
            .cloned()
            .ok_or(TransportError::SessionFenced)?,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    snapshot
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    let scope = &snapshot.binding.scope;
    let source = std::path::Path::new(source_root);
    let canonical = std::fs::canonicalize(source).map_err(|_| TransportError::SessionFenced)?;
    if canonical != source
        || !canonical.is_dir()
        || snapshot.state_fence != receipt.state_fence
        || scope.scope_ref != scope_id.as_str()
        || scope.generation != identity.request.state_fence.resource_generation.value()
        || !matches!(scope.kind, ScopeKind::GitRepo | ScopeKind::Directory)
        || scope.root_identity != canonical.to_string_lossy().as_ref()
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(snapshot)
}
