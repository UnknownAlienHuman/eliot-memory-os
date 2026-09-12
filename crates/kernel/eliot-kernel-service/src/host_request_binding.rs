//! Closed Kernel host-request bind, dispatch, and cancel operation.
//!
//! This module implements the existing [`KernelHostRequestPort`] trait from
//! `eliot-mcp` using only inert host DTOs at the boundary. The Kernel derives
//! request identity, principal, session, authority epoch, state fence,
//! absolute deadline, idempotency identity, and cancellation target from
//! authenticated current state. Host correlation is routing-only and never
//! becomes authority.
//!
//! Binding follows the reconcile pattern from `store_exchange.rs` without
//! copying Store semantics: per-connection request-identity allocation,
//! canonical payload digest, exact operation-handle receipt, unknown outcome
//! retained for exact reconciliation, and misbound peer data treated as a
//! defect. Semantic fan-out uses only [`McpCore::execute`] and
//! [`McpCore::execute_compat`] over an injected [`KernelGovernorPort`]; no
//! second dispatcher or generic JSON command exists here.
//!
//! `HostRequestGateway` remains the sole validation and correlation layer.
//! This port calls `request.validate()` as a fail-closed guard and restores
//! no correlation itself; the gateway echoes correlation on every result.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    AuthorityEpoch, ClockReading, ProductId, RequestId, RequestMetadata, ResourceGeneration,
    SessionId, SourceId, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_mcp::{
    ApplicationRequest, CompatibilityCorrelation, HostCancellationPortOutcome,
    HostCancellationRequest, HostInvocationPortOutcome, HostInvocationRequest, HostOperationHandle,
    KernelGovernorPort, KernelHostRequestPort, MAX_HOST_DEADLINE_PREFERENCE_MS, McpCore,
    McpProtocolVersion, McpResponse, PortFailure, RequestSecurityContext, ResponseKind,
    ToolRequest, TransportRequestContext,
};
use eliot_protocol::RequestIdentity;
use eliot_receipts::{RequestBinding, SessionBinding};
use eliot_security_contracts::{EffectCeiling, InstructionTaint, PrivacyClass};

use crate::protocol::AgentBridgeAdmissionDescriptor;
use crate::{KernelService, KernelServiceState};

/// Default relative deadline when the host supplies no preference, in milliseconds.
///
/// Mirrors the bounded store-exchange default without copying Store semantics.
const DEFAULT_HOST_DEADLINE_MS: u64 = 30_000;

/// Prefix for opaque Kernel-issued host operation handles.
const HOST_OPERATION_PREFIX: &str = "host-op";

/// Authenticated bridge session derived from Kernel Ready state.
///
/// All fields come from the Kernel service lineage, the Host-approved
/// admission descriptor, and OS-observed transport facts. No host DTO field
/// contributes authority. `host_session_hint` and other observed-context
/// values remain correlation-only and are ignored here.
#[derive(Clone, Debug)]
pub struct AuthenticatedHostSession {
    principal_ref: String,
    session: SessionBinding,
    transport: TransportRequestContext,
    state_fence: StateFence,
    authority_epoch: AuthorityEpoch,
    generation: ResourceGeneration,
    connection_id: String,
}

impl AuthenticatedHostSession {
    /// Binds one authenticated session from live Kernel state.
    ///
    /// Validates Ready admission, activation lineage, generation fence,
    /// admission descriptor, authority epoch, state fence, and transport
    /// generation. Wrong or stale values return typed recovery guidance.
    pub fn bind(
        service: &KernelService,
        admission: &AgentBridgeAdmissionDescriptor,
        transport: TransportRequestContext,
    ) -> Result<Self, PortFailure> {
        if service.generation_fenced() {
            return Err(PortFailure::FenceMismatch);
        }
        if service.state() != KernelServiceState::Ready {
            return Err(PortFailure::PlanGap {
                missing_capability: "kernel.host-request.bind-dispatch".to_owned(),
                reason: "kernel is not in READY admission; re-attach after readiness".to_owned(),
            });
        }
        let candidate = service.candidate_binding().ok_or(PortFailure::PlanGap {
            missing_capability: "kernel.host-request.bind-dispatch".to_owned(),
            reason: "no admitted candidate lineage; re-attach after reconcile".to_owned(),
        })?;
        let activation = service.activation_receipt().ok_or(PortFailure::PlanGap {
            missing_capability: "kernel.host-request.bind-dispatch".to_owned(),
            reason: "no consumed activation receipt; re-attach after activation".to_owned(),
        })?;
        admission
            .validate()
            .map_err(|_| PortFailure::TransportBindingRejected {
                reason: "bridge admission descriptor is invalid; reinstall the approved profile"
                    .to_owned(),
            })?;
        check_transport(&transport)?;
        let authority_epoch = service.authority_epoch();
        let generation = activation.generation;
        if admission.authority_epoch != authority_epoch || admission.generation != generation {
            return Err(PortFailure::FenceMismatch);
        }
        let expected_fence = StateFence::new(authority_epoch, generation);
        if admission.state_fence != expected_fence {
            return Err(PortFailure::FenceMismatch);
        }
        if transport.transport_generation != generation.value() {
            return Err(PortFailure::TransportBindingRejected {
                reason: "stale transport generation; re-attach with the current generation"
                    .to_owned(),
            });
        }
        let principal_ref = format!(
            "sid:{}:profile:{}",
            admission.approved_user_sid,
            admission.profile_id.as_str()
        );
        if principal_ref.trim().is_empty() || principal_ref.chars().any(char::is_control) {
            return Err(PortFailure::TransportBindingRejected {
                reason: "authenticated principal binding is invalid; reinstall the profile"
                    .to_owned(),
            });
        }
        let session_text = format!(
            "agent-bridge:{}:{}",
            admission.profile_id.as_str(),
            candidate.activation_id.as_str()
        );
        let session_id =
            SessionId::new(session_text).map_err(|_| PortFailure::TransportBindingRejected {
                reason: "authenticated session binding is invalid; re-attach".to_owned(),
            })?;
        let session = SessionBinding {
            session_id,
            authority_epoch,
            state_fence: expected_fence.clone(),
        };
        let connection_id = transport.connection_id.clone();
        Ok(Self {
            principal_ref,
            session,
            transport,
            state_fence: expected_fence,
            authority_epoch,
            generation,
            connection_id,
        })
    }

    /// Returns the authenticated principal reference.
    #[must_use]
    pub fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    /// Returns the authenticated session binding.
    #[must_use]
    pub const fn session(&self) -> &SessionBinding {
        &self.session
    }

    /// Returns the authenticated transport context.
    #[must_use]
    pub const fn transport(&self) -> &TransportRequestContext {
        &self.transport
    }

    /// Returns the authenticated state fence.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the authenticated authority epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the authenticated resource generation.
    #[must_use]
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    /// Returns the authenticated connection identity text.
    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }
}

/// Stored outcome for one exact Kernel-bound host operation.
#[derive(Clone, Debug)]
enum StoredOutcome {
    /// The operation completed with one bounded MCP response.
    Completed { response: McpResponse },
    /// Delivery was uncertain; retry must reconcile this exact operation first.
    Unknown { reason: String },
    /// The exact operation was cancelled by its owning session.
    Cancelled,
}

/// One exact operation record keyed by Kernel-derived idempotency identity.
#[derive(Clone, Debug)]
struct StoredOperation {
    operation_handle: String,
    request_id: String,
    payload_digest: String,
    session_id: String,
    state_fence: StateFence,
    authority_epoch: AuthorityEpoch,
    outcome: StoredOutcome,
}

/// Closed Kernel binder implementing [`KernelHostRequestPort`].
///
/// Holds one authenticated session, a reference to the real Governor/MCP
/// owner, and per-connection exact-replay ledgers. The binder is
/// per-connection and near-stateless: ledgers live only for the connection
/// lifetime, so no durable retry ledger is created.
pub struct KernelHostRequestBinder<'a, P: KernelGovernorPort + ?Sized> {
    session: AuthenticatedHostSession,
    governor: &'a P,
    core: McpCore,
    next_counter: u64,
    correlation_digests: BTreeMap<String, String>,
    operations: BTreeMap<String, StoredOperation>,
    handles: BTreeMap<String, String>,
}

impl<'a, P: KernelGovernorPort + ?Sized> KernelHostRequestBinder<'a, P> {
    /// Creates one binder from an authenticated session and the real owner port.
    pub const fn new(session: AuthenticatedHostSession, governor: &'a P) -> Self {
        Self {
            session,
            governor,
            core: McpCore,
            next_counter: 1,
            correlation_digests: BTreeMap::new(),
            operations: BTreeMap::new(),
            handles: BTreeMap::new(),
        }
    }

    /// Returns the authenticated session bound by this binder.
    #[must_use]
    pub const fn session(&self) -> &AuthenticatedHostSession {
        &self.session
    }

    fn alloc_request_id(&mut self) -> Result<RequestId, PortFailure> {
        let counter = self.next_counter;
        let next = counter
            .checked_add(1)
            .ok_or(PortFailure::TransportBindingRejected {
                reason: "request counter overflowed; re-attach with a fresh connection".to_owned(),
            })?;
        self.next_counter = next;
        let text = format!("{}:host-request:{counter}", self.session.connection_id());
        RequestId::new(text).map_err(|_| PortFailure::TransportBindingRejected {
            reason: "kernel request identity is invalid; re-attach".to_owned(),
        })
    }

    fn check_correlation(
        &self,
        correlation: &str,
        payload_digest: &str,
    ) -> Result<(), PortFailure> {
        if let Some(known) = self.correlation_digests.get(correlation) {
            if known != payload_digest {
                return Err(PortFailure::IdempotencyConflict);
            }
        }
        Ok(())
    }

    fn lookup_replay(
        &self,
        idempotency_key: &str,
        payload_digest: &str,
        fence: &StateFence,
        epoch: AuthorityEpoch,
        session_id: &str,
    ) -> Result<Option<StoredOperation>, PortFailure> {
        if let Some(stored) = self.operations.get(idempotency_key) {
            if stored.payload_digest != payload_digest {
                return Err(PortFailure::IdempotencyConflict);
            }
            if stored.session_id != session_id {
                return Err(PortFailure::TransportBindingRejected {
                    reason: "operation handle is not owned by this session; use the owning session"
                        .to_owned(),
                });
            }
            if stored.state_fence != *fence || stored.authority_epoch != epoch {
                return Err(PortFailure::FenceMismatch);
            }
            return Ok(Some(stored.clone()));
        }
        Ok(None)
    }

    fn build_identity(
        &self,
        request_id: RequestId,
        idempotency_key: String,
        deadline_unix_ms: u64,
        now_ms: u64,
    ) -> Result<RequestIdentity, PortFailure> {
        let session_id = self.session.session().session_id.clone();
        let clock = ClockReading {
            valid_time_ms: None,
            known_time_ms: i64::try_from(now_ms).ok(),
            transaction_sequence: None,
            monotonic_ns: None,
        };
        let product_id = ProductId::new("eliot-kernel").map_err(|_| PortFailure::PlanGap {
            missing_capability: "kernel.host-request.bind-dispatch".to_owned(),
            reason: "kernel product binding is unavailable".to_owned(),
        })?;
        let source_id =
            SourceId::new("eliot-kernel-host-request").map_err(|_| PortFailure::PlanGap {
                missing_capability: "kernel.host-request.bind-dispatch".to_owned(),
                reason: "kernel source binding is unavailable".to_owned(),
            })?;
        let metadata = RequestMetadata {
            request_id,
            session_id: Some(session_id),
            task_id: None,
            product_id,
            source_id,
            state_fence: self.session.state_fence().clone(),
            clock,
        };
        metadata
            .validate()
            .map_err(|_| PortFailure::TransportBindingRejected {
                reason: "kernel request metadata is invalid; re-attach".to_owned(),
            })?;
        let identity = RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: self.session.state_fence().clone(),
            },
            idempotency_key,
            deadline_unix_ms,
            cancellation_id: String::new(),
        };
        Ok(identity)
    }

    fn dispatch_once(
        &self,
        transport: TransportRequestContext,
        application: ApplicationRequest,
        compat_hint: Option<String>,
    ) -> Result<McpResponse, PortFailure> {
        let result = if application.protocol_version == McpProtocolVersion::Final2026_07_28
            && compat_hint.is_none()
        {
            self.core.execute(self.governor, transport, application)
        } else {
            let correlation = CompatibilityCorrelation {
                transport_session_hint: compat_hint,
            };
            self.core
                .execute_compat(self.governor, transport, application, correlation)
        };
        match result {
            Ok(response) => Ok(response),
            Err(eliot_mcp::BridgeError::Port(failure)) => Err(failure),
            Err(eliot_mcp::BridgeError::InvalidArgument { field, reason }) => {
                Err(PortFailure::TransportBindingRejected {
                    reason: format!("kernel binding rejected at {field}: {reason}"),
                })
            }
            Err(eliot_mcp::BridgeError::Serialization(reason)) => {
                Err(PortFailure::TransportBindingRejected {
                    reason: format!("kernel binding serialization failed: {reason}"),
                })
            }
            Err(eliot_mcp::BridgeError::ResourceRequired { actual, maximum }) => {
                Err(PortFailure::TransportBindingRejected {
                    reason: format!(
                        "response requires a resource route: {actual} exceeds {maximum}"
                    ),
                })
            }
            Err(eliot_mcp::BridgeError::ResourceBindingMismatch) => {
                Err(PortFailure::TransportBindingRejected {
                    reason: "resource binding does not match canonical content".to_owned(),
                })
            }
            Err(eliot_mcp::BridgeError::SourceAssuranceRejected { reason }) => {
                Err(PortFailure::TransportBindingRejected { reason })
            }
        }
    }

    fn record_success(
        &mut self,
        correlation: &str,
        idempotency_key: &str,
        handle_text: &str,
        request_id_text: &str,
        payload_digest: &str,
        response: McpResponse,
    ) {
        self.correlation_digests
            .insert(correlation.to_owned(), payload_digest.to_owned());
        let stored = StoredOperation {
            operation_handle: handle_text.to_owned(),
            request_id: request_id_text.to_owned(),
            payload_digest: payload_digest.to_owned(),
            session_id: self.session.session().session_id.as_str().to_owned(),
            state_fence: self.session.state_fence().clone(),
            authority_epoch: self.session.authority_epoch(),
            outcome: StoredOutcome::Completed { response },
        };
        self.operations.insert(idempotency_key.to_owned(), stored);
        self.handles
            .insert(handle_text.to_owned(), idempotency_key.to_owned());
    }

    fn record_unknown(
        &mut self,
        correlation: &str,
        idempotency_key: &str,
        handle_text: &str,
        request_id_text: &str,
        payload_digest: &str,
        reason: String,
    ) {
        self.correlation_digests
            .insert(correlation.to_owned(), payload_digest.to_owned());
        let stored = StoredOperation {
            operation_handle: handle_text.to_owned(),
            request_id: request_id_text.to_owned(),
            payload_digest: payload_digest.to_owned(),
            session_id: self.session.session().session_id.as_str().to_owned(),
            state_fence: self.session.state_fence().clone(),
            authority_epoch: self.session.authority_epoch(),
            outcome: StoredOutcome::Unknown { reason },
        };
        self.operations.insert(idempotency_key.to_owned(), stored);
        self.handles
            .insert(handle_text.to_owned(), idempotency_key.to_owned());
    }
}

impl<P: KernelGovernorPort + ?Sized> KernelHostRequestPort for KernelHostRequestBinder<'_, P> {
    fn invoke(
        &mut self,
        request: &HostInvocationRequest,
    ) -> Result<HostInvocationPortOutcome, PortFailure> {
        request.validate().map_err(|error| PortFailure::PlanGap {
            missing_capability: "kernel.host-request.bind-dispatch".to_owned(),
            reason: format!("host contract is invalid: {error}"),
        })?;
        if matches!(request.tool, ToolRequest::Finish(_)) {
            return Err(PortFailure::Unsupported {
                capability: "kernel.host-request.finish-task-binding".to_owned(),
                reason: "finish requires Governor task admission; no Kernel task binding exists"
                    .to_owned(),
            });
        }
        let payload_digest = canonical_payload_digest(&request.tool)?;
        let correlation = request.correlation_id.as_str().to_owned();
        self.check_correlation(&correlation, &payload_digest)?;
        let fence = self.session.state_fence().clone();
        let epoch = self.session.authority_epoch();
        let session_text = self.session.session().session_id.as_str().to_owned();
        let idempotency_key = derive_idempotency_key(&session_text, &payload_digest, &fence)?;
        if let Some(stored) = self.lookup_replay(
            &idempotency_key,
            &payload_digest,
            &fence,
            epoch,
            &session_text,
        )? {
            match stored.outcome {
                StoredOutcome::Completed { response } => {
                    let handle =
                        HostOperationHandle::new(stored.operation_handle).map_err(|_| {
                            PortFailure::TransportBindingRejected {
                                reason: "stored operation handle is invalid".to_owned(),
                            }
                        })?;
                    return Ok(HostInvocationPortOutcome::Responded {
                        operation_handle: handle,
                        response: Box::new(response),
                    });
                }
                StoredOutcome::Cancelled => {
                    return Err(PortFailure::Cancelled);
                }
                StoredOutcome::Unknown { ref reason } => {
                    let _ = reason;
                    return Err(PortFailure::TransportBindingRejected {
                        reason: "unknown outcome requires exact reconciliation before retry"
                            .to_owned(),
                    });
                }
            }
        }
        let now_ms = unix_ms();
        let deadline_unix_ms = absolute_deadline(request.deadline_preference_ms, now_ms)?;
        let request_id = self.alloc_request_id()?;
        let request_id_text = request_id.as_str().to_owned();
        let mut identity = self.build_identity(
            request_id,
            idempotency_key.clone(),
            deadline_unix_ms,
            now_ms,
        )?;
        identity.cancellation_id = format!("{request_id_text}:cancel");
        identity
            .validate()
            .map_err(|_| PortFailure::TransportBindingRejected {
                reason: "kernel request identity is invalid".to_owned(),
            })?;
        let expected_tool = request.tool.canonical_name().to_owned();
        let application = ApplicationRequest {
            protocol_version: request.protocol_version,
            session: self.session.session().clone(),
            identity: identity.clone(),
            security: RequestSecurityContext {
                privacy_class: PrivacyClass::Internal,
                instruction_taint: InstructionTaint::DataOnly,
                effect_ceiling: EffectCeiling::CandidateOnly,
            },
            client_capabilities: request.client_capabilities,
            tool: request.tool.clone(),
        };
        let transport = self.session.transport().clone();
        let compat_hint = if request.protocol_version == McpProtocolVersion::Compat2025_11_25 {
            request.observed_context.host_session_hint.clone()
        } else {
            None
        };
        let response = self.dispatch_once(transport, application, compat_hint)?;
        let handle_text = derive_operation_handle(&request_id_text, &payload_digest)?;
        if let Err(binding) = check_response_binding(
            &response,
            &request_id_text,
            &idempotency_key,
            &expected_tool,
        ) {
            self.record_unknown(
                &correlation,
                &idempotency_key,
                &handle_text,
                &request_id_text,
                &payload_digest,
                "misbound response; reconcile the exact operation".to_owned(),
            );
            return Err(binding);
        }
        let gap = plan_gap_from_response(&response).map_err(|defect| {
            self.record_unknown(
                &correlation,
                &idempotency_key,
                &handle_text,
                &request_id_text,
                &payload_digest,
                "misbound gap response; reconcile the exact operation".to_owned(),
            );
            defect
        })?;
        if let Some(failure) = gap {
            return Err(failure);
        }
        let handle = HostOperationHandle::new(handle_text.clone()).map_err(|_| {
            PortFailure::TransportBindingRejected {
                reason: "kernel operation handle is invalid".to_owned(),
            }
        })?;
        self.record_success(
            &correlation,
            &idempotency_key,
            &handle_text,
            &request_id_text,
            &payload_digest,
            response.clone(),
        );
        Ok(HostInvocationPortOutcome::Responded {
            operation_handle: handle,
            response: Box::new(response),
        })
    }

    fn cancel(
        &mut self,
        request: &HostCancellationRequest,
    ) -> Result<HostCancellationPortOutcome, PortFailure> {
        request.validate().map_err(|error| PortFailure::PlanGap {
            missing_capability: "kernel.host-request.cancel".to_owned(),
            reason: format!("host contract is invalid: {error}"),
        })?;
        let now_ms = unix_ms();
        let _deadline = absolute_deadline(request.deadline_preference_ms, now_ms)?;
        let handle_text = request.operation_handle.as_str().to_owned();
        let key = self.handles.get(&handle_text).cloned().ok_or_else(|| {
            PortFailure::TransportBindingRejected {
                reason: "unknown operation handle; use the exact handle from admission".to_owned(),
            }
        })?;
        let stored = self.operations.get(&key).cloned().ok_or_else(|| {
            PortFailure::TransportBindingRejected {
                reason: "unknown operation handle; use the exact handle from admission".to_owned(),
            }
        })?;
        if stored.operation_handle != handle_text {
            return Err(PortFailure::TransportBindingRejected {
                reason: "cancellation target does not match the exact operation".to_owned(),
            });
        }
        if stored.session_id != self.session.session().session_id.as_str() {
            return Err(PortFailure::TransportBindingRejected {
                reason: "operation handle is not owned by this session".to_owned(),
            });
        }
        if stored.state_fence != *self.session.state_fence()
            || stored.authority_epoch != self.session.authority_epoch()
        {
            return Err(PortFailure::FenceMismatch);
        }
        let expected_prefix = format!("{HOST_OPERATION_PREFIX}-{}-", stored.request_id);
        if !handle_text.starts_with(&expected_prefix) {
            return Err(PortFailure::TransportBindingRejected {
                reason: "cancellation target does not match the exact operation".to_owned(),
            });
        }
        let entry = self
            .operations
            .get_mut(&key)
            .ok_or(PortFailure::TransportBindingRejected {
                reason: "unknown operation handle; use the exact handle from admission".to_owned(),
            })?;
        match &entry.outcome {
            StoredOutcome::Cancelled => Ok(HostCancellationPortOutcome::AlreadyTerminal),
            StoredOutcome::Completed { response } if response.job.is_none() => {
                Ok(HostCancellationPortOutcome::AlreadyTerminal)
            }
            StoredOutcome::Completed { .. } => {
                entry.outcome = StoredOutcome::Cancelled;
                Ok(HostCancellationPortOutcome::Accepted)
            }
            StoredOutcome::Unknown { .. } => Err(PortFailure::TransportBindingRejected {
                reason: "unknown outcome requires exact reconciliation before cancel".to_owned(),
            }),
        }
    }
}

fn check_transport(transport: &TransportRequestContext) -> Result<(), PortFailure> {
    if transport.connection_id.trim().is_empty()
        || transport.connection_id.chars().any(char::is_control)
    {
        return Err(PortFailure::TransportBindingRejected {
            reason: "wrong connection identity; re-attach with a fresh credential".to_owned(),
        });
    }
    if transport.scoped_credential_ref.trim().is_empty()
        || transport
            .scoped_credential_ref
            .chars()
            .any(char::is_control)
    {
        return Err(PortFailure::TransportBindingRejected {
            reason: "scoped credential binding was rejected; re-attach".to_owned(),
        });
    }
    if transport.transport_generation == 0 {
        return Err(PortFailure::TransportBindingRejected {
            reason: "stale transport generation; re-attach".to_owned(),
        });
    }
    if let eliot_mcp::TransportProfile::LoopbackHttp(profile) = &transport.profile {
        if profile.credential_ref != transport.scoped_credential_ref {
            return Err(PortFailure::TransportBindingRejected {
                reason: "credential reference does not match the loopback profile".to_owned(),
            });
        }
        if profile.bind_address != "127.0.0.1" && profile.bind_address != "::1" {
            return Err(PortFailure::TransportBindingRejected {
                reason: "loopback bind address is not admitted".to_owned(),
            });
        }
    }
    Ok(())
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn absolute_deadline(preference_ms: Option<u64>, now_ms: u64) -> Result<u64, PortFailure> {
    let relative = preference_ms.unwrap_or(DEFAULT_HOST_DEADLINE_MS);
    if relative == 0 || relative > MAX_HOST_DEADLINE_PREFERENCE_MS {
        return Err(PortFailure::TransportBindingRejected {
            reason: "deadline preference is outside the admitted range".to_owned(),
        });
    }
    let deadline = now_ms.saturating_add(relative);
    if deadline <= now_ms {
        return Err(PortFailure::DeadlineExceeded);
    }
    Ok(deadline)
}

fn canonical_payload_digest(tool: &ToolRequest) -> Result<String, PortFailure> {
    let bytes = canonical_json_bytes(tool).map_err(|_| PortFailure::TransportBindingRejected {
        reason: "tool payload cannot be canonicalized".to_owned(),
    })?;
    Ok(sha256_hex(&bytes))
}

fn derive_idempotency_key(
    session_id: &str,
    payload_digest: &str,
    fence: &StateFence,
) -> Result<String, PortFailure> {
    let fence_bytes =
        canonical_json_bytes(fence).map_err(|_| PortFailure::TransportBindingRejected {
            reason: "state fence cannot be canonicalized".to_owned(),
        })?;
    let fence_digest = sha256_hex(&fence_bytes);
    let joined = format!("{session_id}:{payload_digest}:{fence_digest}");
    Ok(sha256_hex(joined.as_bytes()))
}

fn derive_operation_handle(request_id: &str, payload_digest: &str) -> Result<String, PortFailure> {
    let suffix: String = payload_digest.chars().take(16).collect();
    if suffix.len() != 16 {
        return Err(PortFailure::TransportBindingRejected {
            reason: "payload digest is malformed".to_owned(),
        });
    }
    Ok(format!("{HOST_OPERATION_PREFIX}-{request_id}-{suffix}"))
}

fn check_response_binding(
    response: &McpResponse,
    request_id: &str,
    idempotency_key: &str,
    expected_tool: &str,
) -> Result<(), PortFailure> {
    if response.request_id != request_id {
        return Err(PortFailure::TransportBindingRejected {
            reason: "response request identity does not match the admitted request".to_owned(),
        });
    }
    if response.idempotency_key != idempotency_key {
        return Err(PortFailure::TransportBindingRejected {
            reason: "response idempotency binding does not match the admitted key".to_owned(),
        });
    }
    if response.canonical_tool_name != expected_tool {
        return Err(PortFailure::TransportBindingRejected {
            reason: "response tool binding does not match the requested tool".to_owned(),
        });
    }
    if !is_lower_hex64(&response.canonical_request_sha256) {
        return Err(PortFailure::TransportBindingRejected {
            reason: "response digest does not bind the canonical request".to_owned(),
        });
    }
    Ok(())
}

fn plan_gap_from_response(response: &McpResponse) -> Result<Option<PortFailure>, PortFailure> {
    match response.kind {
        ResponseKind::Candidate | ResponseKind::Projection => Ok(None),
        ResponseKind::PlanGap => {
            let (capability, reason) = plan_gap_fields(response)?;
            Ok(Some(PortFailure::PlanGap {
                missing_capability: capability,
                reason,
            }))
        }
        ResponseKind::Unsupported => {
            let (capability, reason) = unsupported_fields(response)?;
            Ok(Some(PortFailure::Unsupported { capability, reason }))
        }
    }
}

fn plan_gap_fields(response: &McpResponse) -> Result<(String, String), PortFailure> {
    let object = response
        .content
        .as_object()
        .ok_or(PortFailure::TransportBindingRejected {
            reason: "typed gap response does not bind its capability".to_owned(),
        })?;
    let capability = object
        .get("missing_capability")
        .and_then(|value| value.as_str())
        .ok_or(PortFailure::TransportBindingRejected {
            reason: "typed gap response does not bind its capability".to_owned(),
        })?;
    let reason = object
        .get("reason")
        .and_then(|value| value.as_str())
        .ok_or(PortFailure::TransportBindingRejected {
            reason: "typed gap response does not bind its reason".to_owned(),
        })?;
    if capability.trim().is_empty() || reason.trim().is_empty() {
        return Err(PortFailure::TransportBindingRejected {
            reason: "typed gap response does not bind its capability".to_owned(),
        });
    }
    Ok((capability.to_owned(), reason.to_owned()))
}

fn unsupported_fields(response: &McpResponse) -> Result<(String, String), PortFailure> {
    let object = response
        .content
        .as_object()
        .ok_or(PortFailure::TransportBindingRejected {
            reason: "typed unsupported response does not bind its capability".to_owned(),
        })?;
    let capability = object
        .get("capability")
        .and_then(|value| value.as_str())
        .ok_or(PortFailure::TransportBindingRejected {
            reason: "typed unsupported response does not bind its capability".to_owned(),
        })?;
    let reason = object
        .get("reason")
        .and_then(|value| value.as_str())
        .ok_or(PortFailure::TransportBindingRejected {
            reason: "typed unsupported response does not bind its reason".to_owned(),
        })?;
    if capability.trim().is_empty() || reason.trim().is_empty() {
        return Err(PortFailure::TransportBindingRejected {
            reason: "typed unsupported response does not bind its capability".to_owned(),
        });
    }
    Ok((capability.to_owned(), reason.to_owned()))
}

fn is_lower_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
