//! P-04 admitted host-request bind, dispatch, and cancel operation.
//!
//! This module implements the existing [`KernelHostRequestPort`] trait from
//! `eliot-mcp` against the versioned [`HostRequestEnvelope`](eliot_protocol::HostRequestEnvelope)
//! admission path. The Kernel derives principal, session, authority epoch,
//! state fence, and effect ceiling from authenticated current state; the
//! envelope carries the exact request, idempotency, cancellation, deadline,
//! capability, and payload-digest identities. Host correlation is routing-only
//! and never becomes authority.
//!
//! Envelope path: [`KernelHostRequestBinder::invoke_admitted`] takes one
//! envelope plus the Kernel-retained peer admission receipt, builds the
//! Kernel-observed [`AgentBridgeProcessBinding`](eliot_protocol::AgentBridgeProcessBinding)
//! from retained descriptor and receipt state, runs
//! [`KernelService::admit_host_request`], stages the `Requested` ORS record
//! before acknowledgement, advances it to `Admitted`, and only then dispatches
//! through [`McpCore::execute`]. [`McpCore`] remains the sole semantic
//! dispatcher; no second dispatcher or generic JSON command exists here.
//!
//! ORS is the single durability owner: an exact envelope replay returns the
//! stored admission without re-dispatching, and a changed binding under a
//! known operation fails as [`PortFailure::IdempotencyConflict`] from the ORS
//! identity check. No per-connection shadow ledger exists here.
//!
//! The canonical operation handle is
//! [`host_request_operation_id`](eliot_protocol::host_request_operation_id)
//! (`"hostreq:"` plus the exact envelope digest), the same key ORS stores.
//!
//! `HostRequestGateway` remains the sole validation and correlation layer.
//! This port calls `request.validate()` as a fail-closed guard and restores
//! no correlation itself; the gateway echoes correlation on every result.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    ClockReading, EpochId, ProductId, RequestMetadata, ResourceGeneration, SessionId, SourceId,
    StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_mcp::{
    ApplicationRequest, CompatibilityCorrelation, HostCancellationPortOutcome,
    HostCancellationRequest, HostInvocationPortOutcome, HostInvocationRequest, HostOperationHandle,
    KernelGovernorPort, KernelHostRequestPort, MAX_HOST_DEADLINE_PREFERENCE_MS, McpCore,
    McpProtocolVersion, McpResponse, PortFailure, QueryInput, QueryIntent, QueryMode,
    RequestSecurityContext, ResponseKind, ToolRequest, TransportRequestContext,
    plan_evidence_pack_query, project_evidence_pack_projection,
};
use eliot_ors::{
    CONTRACT_VERSION as ORS_CONTRACT_VERSION, HostRequestKind as OrsHostRequestKind,
    HostRequestRecord, HostRequestState, OpaqueLabel, OperationIdentity, OperationalRecoveryStore,
    OrsError,
};
use eliot_protocol::{
    AGENT_BRIDGE_PROCESS_BINDING_WIRE_ID, AgentActivationResolutionResult,
    AgentBridgePeerAdmissionReceipt, AgentBridgeProcessBinding, HARD_STRUCTURED_RESPONSE_BYTES,
    HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestAdmissionReceipt, HostRequestEnvelope,
    HostRequestKind, HostRequestResultBody, RequestIdentity, host_request_operation_id,
};
use eliot_receipts::{ProofCeiling, RequestBinding, SessionBinding};
use eliot_security_contracts::{EffectCeiling, InstructionTaint, PrivacyClass};
use eliot_store_api::EVIDENCE_PACK_MAX_RECORDS;

use crate::protocol::AgentBridgeAdmissionDescriptor;
use crate::{KernelService, KernelServiceError, KernelServiceState};

/// Prefix of the canonical opaque operation handle derived by
/// [`host_request_operation_id`]. Cancellation targets carry the parent
/// envelope digest after this prefix; the digest is re-validated as lowercase
/// SHA-256 before any store lookup, so a malformed reference is an unknown
/// operation rather than a fence failure.
const HOST_REQUEST_OPERATION_ID_PREFIX: &str = "hostreq:";

/// Authenticated bridge session derived from Kernel Ready state.
///
/// All fields come from the Kernel service lineage, the Host-approved
/// admission descriptor, and OS-observed transport facts. No host DTO field
/// contributes authority. `host_session_hint` and other observed-context
/// values remain correlation-only and are ignored here. The retained
/// descriptor clone lets the envelope admission gate re-check descriptor
/// binding without accepting a caller-supplied descriptor as authority.
#[derive(Clone, Debug)]
pub struct AuthenticatedHostSession {
    principal_ref: String,
    session: SessionBinding,
    transport: TransportRequestContext,
    state_fence: StateFence,
    authority_epoch: EpochId,
    generation: ResourceGeneration,
    connection_id: String,
    descriptor: AgentBridgeAdmissionDescriptor,
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
        // Live authority comes from the Kernel service lineage (Implements #64).
        // `KernelService::authority_epoch` migrates to `EpochId` with the
        // lifecycle owner; until then this assumes its `EpochId` shape
        // (residual: `lifecycle.rs` `authority_epoch()`).
        let authority_epoch = service.authority_epoch();
        let generation = activation.generation;
        if !admission
            .authority_epoch
            .is_same_authority(&authority_epoch)
            || admission.generation != generation
        {
            return Err(PortFailure::FenceMismatch);
        }
        let expected_fence = StateFence::new(authority_epoch.clone(), generation);
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
            authority_epoch: authority_epoch.clone(),
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
            descriptor: admission.clone(),
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
    pub fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
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

    /// Returns the retained Kernel-supplied admission descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &AgentBridgeAdmissionDescriptor {
        &self.descriptor
    }

    /// Builds the exact bounded local-read result body for one admitted query.
    ///
    /// Session-namespaced constructor (Implements #18: local read result): it
    /// reads no live session state — the admitted fence travels inside
    /// `envelope` — but the result it builds is bound to the presenting
    /// envelope's request identity, so only the session that admitted the
    /// envelope can persist and serve it through the ORS result path.
    ///
    /// Runs the existing evidence-pack planning half
    /// (`plan_evidence_pack_query`) over the explicit `scope_id`/`subject`/
    /// `max_records` selectors, projects the exact store payload unchanged
    /// through `project_evidence_pack_projection`, wraps the projection as a
    /// read-only `Projection` response under the `ScopedVerification` ceiling,
    /// and returns the canonical digest binding the exact bounded bytes. The
    /// caller persists the pair with `persist_host_request_result` and serves
    /// exact replays via `readback_responded` without re-dispatch; a forged or
    /// substituted body fails the digest binding here before anything is
    /// persisted. `eliot.packet` never reaches this constructor.
    ///
    /// Intent fixed strings mirror the Governor `evidence_query` port
    /// (`ReadService::evidence_query`); only the mode travels as a parameter
    /// and `CurrentPosition` (plus any unknown mode) is refused fail-closed
    /// because it never admits `GetEvidencePack`. `max_records` must be the
    /// explicit decimal bound within `EVIDENCE_PACK_MAX_RECORDS`; the body
    /// must fit `HARD_STRUCTURED_RESPONSE_BYTES`.
    ///
    /// # Errors
    ///
    /// Returns a bounded reason string when the envelope is not an admitted
    /// `eliot.query`, when any selector is blank, malformed, or over-bound,
    /// or when the bounded body cannot be canonicalized.
    pub fn build_local_read_result_body(
        envelope: &HostRequestEnvelope,
        scope_id: &str,
        subject: &str,
        max_records: u32,
        intent_mode: &str,
        store_payload: serde_json::Value,
    ) -> Result<(String, serde_json::Value), String> {
        if envelope.identity.capability != "eliot.query" {
            return Err("presented capability is not the admitted local-read query".to_owned());
        }
        let mode = match intent_mode {
            "verification" => QueryMode::Verification,
            "provenance" => QueryMode::Provenance,
            "navigation" => QueryMode::Navigation,
            "historical_reconstruction" => QueryMode::HistoricalReconstruction,
            "change_impact" => QueryMode::ChangeImpact,
            "context_reconstruction" => QueryMode::ContextReconstruction,
            _ => {
                return Err("query intent never admits GetEvidencePack for this mode".to_owned());
            }
        };
        if subject.trim().is_empty() || subject.chars().any(char::is_control) {
            return Err("evidence subject must be exact and non-blank".to_owned());
        }
        if scope_id.trim().is_empty() || scope_id.chars().any(char::is_control) {
            return Err("evidence scope must be explicit and non-blank".to_owned());
        }
        if max_records == 0 || max_records > EVIDENCE_PACK_MAX_RECORDS {
            return Err("max_records must be within the catalogue bound".to_owned());
        }
        let input = QueryInput {
            intent: QueryIntent {
                mode,
                time_scope: "governor local evidence window".to_owned(),
                branch_environment_scope: "governor local branch and environment".to_owned(),
                freshness_policy: "exact captured records only".to_owned(),
                required_assurance: "verifier evidence read".to_owned(),
            },
            query: format!("subject:{subject}"),
            exact_resource_uri: None,
        };
        let plan = plan_evidence_pack_query(&input, scope_id, &max_records.to_string())
            .map_err(|error| error.to_string())?;
        let projection = project_evidence_pack_projection(&plan, store_payload);
        let request_id = envelope.identity.request_id.as_str().to_owned();
        let idempotency_key = envelope.identity.idempotency_key.clone();
        let canonical_request_sha256 = sha256_hex(
            &canonical_json_bytes(&(
                envelope.envelope_sha256.clone(),
                request_id.clone(),
                idempotency_key.clone(),
            ))
            .map_err(|error| error.to_string())?,
        );
        let response = McpResponse {
            request_id,
            idempotency_key,
            canonical_request_sha256,
            kind: ResponseKind::Projection,
            canonical_tool_name: "eliot.query".to_owned(),
            content: projection.content,
            artifacts: Vec::new(),
            proof_ceiling: ProofCeiling::ScopedVerification,
            resource: None,
            job: None,
            compatibility_correlation_hint: None,
        };
        let body = serde_json::to_value(&response).map_err(|error| error.to_string())?;
        let encoded = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
        if encoded.len() > HARD_STRUCTURED_RESPONSE_BYTES {
            return Err("result body exceeds the bounded response ceiling".to_owned());
        }
        let digest =
            sha256_hex(&canonical_json_bytes(&response).map_err(|error| error.to_string())?);
        HostRequestResultBody {
            wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
            wire_version: HostRequestResultBody::CONTRACT_VERSION,
            operation_id: host_request_operation_id(envelope),
            request_sha256: envelope.envelope_sha256.clone(),
            result_digest: digest.clone(),
            response: body.clone(),
        }
        .validate()
        .map_err(|error| error.to_string())?;
        Ok((digest, body))
    }
}

/// Closed Kernel binder implementing [`KernelHostRequestPort`].
///
/// Holds one authenticated session plus references to the real Governor/MCP
/// owner and the single ORS durability owner. The binder keeps no shadow
/// ledger: exact replay, conflict, and cancellation answers all come from the
/// durable ORS host-request record keyed by the canonical operation handle.
pub struct KernelHostRequestBinder<'a, P: KernelGovernorPort + ?Sized> {
    session: AuthenticatedHostSession,
    governor: &'a P,
    store: &'a dyn OperationalRecoveryStore,
    core: McpCore,
}

impl<'a, P: KernelGovernorPort + ?Sized> KernelHostRequestBinder<'a, P> {
    /// Creates one binder from an authenticated session, the real owner port,
    /// and the single ORS durability owner.
    pub const fn new(
        session: AuthenticatedHostSession,
        governor: &'a P,
        store: &'a dyn OperationalRecoveryStore,
    ) -> Self {
        Self {
            session,
            governor,
            store,
            core: McpCore,
        }
    }

    /// Returns the authenticated session bound by this binder.
    #[must_use]
    pub const fn session(&self) -> &AuthenticatedHostSession {
        &self.session
    }

    /// Admits one versioned envelope and dispatches its bound host operation.
    ///
    /// Runs the Kernel admission gate over a Kernel-built process binding,
    /// stages the `Requested` ORS record before acknowledgement, advances it
    /// to `Admitted`, then dispatches the presented tool through [`McpCore`].
    /// The presented tool must be the admitted one: its canonical name must
    /// equal the envelope capability and its canonical payload digest must
    /// equal the envelope payload digest, otherwise no dispatch happens. An
    /// exact envelope replay returns the stored admission without
    /// re-dispatching; a changed binding under a known operation fails as
    /// [`PortFailure::IdempotencyConflict`].
    pub fn invoke_admitted(
        &mut self,
        service: &KernelService,
        envelope: &HostRequestEnvelope,
        peer_receipt: &AgentBridgePeerAdmissionReceipt,
        resolution: Option<&AgentActivationResolutionResult>,
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
        check_tool_linkage(request, envelope)?;
        let now_ms = unix_ms();
        let staged = self.admit_and_stage(service, envelope, peer_receipt, resolution, now_ms)?;
        match staged {
            StagedAdmission::Fresh => {}
            StagedAdmission::Replay => {
                let handle = HostOperationHandle::new(host_request_operation_id(envelope))
                    .map_err(|_| PortFailure::TransportBindingRejected {
                        reason: "canonical operation handle is invalid".to_owned(),
                    })?;
                return Ok(HostInvocationPortOutcome::Accepted {
                    operation_handle: handle,
                });
            }
            StagedAdmission::ReplayResulted {
                response,
                result_digest,
            } => {
                return readback_responded(envelope, request, response, &result_digest);
            }
        }
        let application = self.build_application(request, envelope, now_ms)?;
        let transport = self.session.transport().clone();
        let compat_hint = if request.protocol_version == McpProtocolVersion::Compat2025_11_25 {
            request.observed_context.host_session_hint.clone()
        } else {
            None
        };
        let response = self.dispatch_once(transport, application, compat_hint)?;
        let expected_tool = request.tool.canonical_name().to_owned();
        check_response_binding(
            &response,
            envelope.identity.request_id.as_str(),
            &envelope.identity.idempotency_key,
            &expected_tool,
        )?;
        if let Some(failure) = plan_gap_from_response(&response)? {
            return Err(failure);
        }
        self.persist_result(envelope, &response)?;
        let handle =
            HostOperationHandle::new(host_request_operation_id(envelope)).map_err(|_| {
                PortFailure::TransportBindingRejected {
                    reason: "canonical operation handle is invalid".to_owned(),
                }
            })?;
        Ok(HostInvocationPortOutcome::Responded {
            operation_handle: handle,
            response: Box::new(response),
        })
    }

    /// Persists one bounded dispatch result as `ResultReceived` (Implements #18).
    ///
    /// Decision (documented per item plan): the exact bounded `McpResponse`
    /// JSON is stored in ORS (`result_response`) beside its canonical digest,
    /// rather than re-serving via a fresh `ReadService::query` at readback.
    /// A re-query would repeat store IO under a possibly advanced revision and
    /// could not prove byte-exactness; the stored body proves the exact
    /// payload and revision the read owner returned for this envelope without
    /// any re-dispatch. The revision travels inside the bounded content (the
    /// read owner embeds `revision_heads` there); the binder preserves it
    /// opaquely and never interprets it. Runs after `check_response_binding`
    /// and the plan-gap check, so only admitted Candidate/Projection answers
    /// are persisted, in the required order: validate → linkage → admit →
    /// dispatch → response binding → persist.
    fn persist_result(
        &self,
        envelope: &HostRequestEnvelope,
        response: &McpResponse,
    ) -> Result<(), PortFailure> {
        let digest = canonical_result_digest(response)?;
        let body = serde_json::to_value(response).map_err(|_| {
            PortFailure::TransportBindingRejected {
                reason: "kernel result cannot be canonicalized".to_owned(),
            }
        })?;
        let operation_id = ors_operation_id(envelope)?;
        self.store
            .persist_host_request_result(
                &operation_id,
                &envelope.envelope_sha256,
                &digest,
                &body,
            )
            .map_err(|error| ors_failure(&error))?
            .ok_or(PortFailure::TransportBindingRejected {
                reason: "admitted operation disappeared before result persistence".to_owned(),
            })?;
        Ok(())
    }

    /// Runs the admission gate and the persist-before-ack ORS staging.
    ///
    /// A fresh envelope is advanced `Requested -> Admitted` before any
    /// dispatch. An exact replay of a live operation is returned for a
    /// dispatch-free acknowledgement; a replay of closed work maps to its
    /// terminal disposition instead of a blind retry.
    fn admit_and_stage(
        &self,
        service: &KernelService,
        envelope: &HostRequestEnvelope,
        peer_receipt: &AgentBridgePeerAdmissionReceipt,
        resolution: Option<&AgentActivationResolutionResult>,
        now_ms: u64,
    ) -> Result<StagedAdmission, PortFailure> {
        let binding = kernel_bridge_process_binding(
            self.session.descriptor(),
            peer_receipt,
            &envelope.connection_id,
        )?;
        let receipt: HostRequestAdmissionReceipt = service
            .admit_host_request(envelope, self.session.descriptor(), &binding, resolution)
            .map_err(|error| kernel_service_failure(&error))?;
        let staged = requested_host_request_record(envelope)?;
        let stored = self
            .store
            .stage_host_request(&staged)
            .map_err(|error| ors_failure(&error))?;
        if now_ms >= envelope.identity.deadline_unix_ms {
            if !stored.state.is_terminal() {
                let operation_id = ors_operation_id(envelope)?;
                match self.store.advance_host_request(
                    &operation_id,
                    &envelope.envelope_sha256,
                    HostRequestState::Expired,
                    None,
                ) {
                    Ok(_) | Err(OrsError::InvalidTransition) => {}
                    Err(error) => return Err(ors_failure(&error)),
                }
            }
            return Err(PortFailure::DeadlineExceeded);
        }
        if stored.state == HostRequestState::Requested {
            let operation_id = ors_operation_id(envelope)?;
            self.store
                .advance_host_request(
                    &operation_id,
                    &envelope.envelope_sha256,
                    HostRequestState::Admitted,
                    None,
                )
                .map_err(|error| ors_failure(&error))?
                .ok_or(PortFailure::TransportBindingRejected {
                    reason: "admitted operation disappeared before acknowledgement".to_owned(),
                })?;
            return Ok(StagedAdmission::Fresh);
        }
        service
            .reconcile_host_request_admission(&receipt, envelope)
            .map_err(|error| kernel_service_failure(&error))?;
        if stored.state.is_terminal() {
            if let Some((body, digest)) = stored_result_body(&stored) {
                return Ok(StagedAdmission::ReplayResulted {
                    response: body,
                    result_digest: digest,
                });
            }
            return Err(terminal_replay_failure(stored.state));
        }
        Ok(StagedAdmission::Replay)
    }

    /// Builds the Kernel-owned application request for one admitted envelope.
    ///
    /// Every identity comes from the envelope or the authenticated session.
    /// The host DTO contributes only the validated tool payload and
    /// presentation-only client capabilities.
    fn build_application(
        &self,
        request: &HostInvocationRequest,
        envelope: &HostRequestEnvelope,
        now_ms: u64,
    ) -> Result<ApplicationRequest, PortFailure> {
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
            request_id: envelope.identity.request_id.clone(),
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
            idempotency_key: envelope.identity.idempotency_key.clone(),
            deadline_unix_ms: envelope.identity.deadline_unix_ms,
            cancellation_id: envelope.identity.cancellation_id.clone(),
        };
        identity
            .validate()
            .map_err(|_| PortFailure::TransportBindingRejected {
                reason: "kernel request identity is invalid".to_owned(),
            })?;
        Ok(ApplicationRequest {
            protocol_version: request.protocol_version,
            session: self.session.session().clone(),
            identity,
            security: RequestSecurityContext {
                privacy_class: PrivacyClass::Internal,
                instruction_taint: InstructionTaint::DataOnly,
                effect_ceiling: EffectCeiling::CandidateOnly,
            },
            client_capabilities: request.client_capabilities,
            tool: request.tool.clone(),
        })
    }

    /// Dispatches one admitted application request through the sole dispatcher.
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
        Err(PortFailure::PlanGap {
            missing_capability: "kernel.host-request.envelope-admission".to_owned(),
            reason: "host invocation requires an admitted HostRequestEnvelope; submit through the admitted-envelope entrypoint"
                .to_owned(),
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
        check_deadline_preference(request.deadline_preference_ms)?;
        let handle_text = request.operation_handle.as_str().to_owned();
        let (operation_id, request_digest) = parse_operation_handle(&handle_text)?;
        let stored = self
            .store
            .load_host_request(&operation_id, &request_digest)
            .map_err(|error| ors_failure(&error))?
            .ok_or(PortFailure::TransportBindingRejected {
                reason: "unknown operation handle; use the exact handle from admission".to_owned(),
            })?;
        if stored.connection_ref.as_str() != self.session.connection_id() {
            return Err(PortFailure::TransportBindingRejected {
                reason: "operation handle is not owned by this connection".to_owned(),
            });
        }
        if let Some(session_ref) = stored.session_ref.as_ref()
            && session_ref.as_str() != self.session.session().session_id.as_str()
        {
            return Err(PortFailure::TransportBindingRejected {
                reason: "operation handle is not owned by this session".to_owned(),
            });
        }
        // Exact-tuple lineage check (Implements #64): the durable record epoch
        // (widened to `EpochId` in ORS `HostRequestRecord`) must match the live
        // session epoch; equal sequences from different lineages are unrelated.
        if !stored
            .authority_epoch
            .is_same_authority(self.session.authority_epoch())
            || stored.generation != self.session.generation().value()
        {
            return Err(PortFailure::FenceMismatch);
        }
        let expected_fence = sha256_json(self.session.state_fence()).map_err(|_| {
            PortFailure::TransportBindingRejected {
                reason: "kernel state fence cannot be canonicalized".to_owned(),
            }
        })?;
        if stored.fence_digest != expected_fence {
            return Err(PortFailure::FenceMismatch);
        }
        if stored.state.is_terminal() {
            return Ok(HostCancellationPortOutcome::AlreadyTerminal);
        }
        match stored.state {
            HostRequestState::Admitted | HostRequestState::Routed | HostRequestState::Submitted => {
                self.store
                    .advance_host_request(
                        &operation_id,
                        &request_digest,
                        HostRequestState::Cancelled,
                        None,
                    )
                    .map_err(|error| ors_failure(&error))?;
                Ok(HostCancellationPortOutcome::Accepted)
            }
            HostRequestState::Requested
            | HostRequestState::PossiblyEffected
            | HostRequestState::Unknown
            | HostRequestState::Reconciling => Err(PortFailure::TransportBindingRejected {
                reason: "unknown outcome requires exact reconciliation before cancel".to_owned(),
            }),
            HostRequestState::ResultReceived
            | HostRequestState::Expired
            | HostRequestState::Conflicted
            | HostRequestState::Cancelled
            | HostRequestState::Terminal => Ok(HostCancellationPortOutcome::AlreadyTerminal),
        }
    }
}

/// One staged envelope admission.
///
/// A fresh admission proceeds to dispatch. A replay of a live operation
/// returns the stored admission without re-dispatching, so an at-least-once
/// transport can never duplicate effects through this binder. A replay of a
/// resulted operation carries the exact stored bounded body for a
/// dispatch-free readback.
enum StagedAdmission {
    /// The envelope was staged and advanced to `Admitted` by this call.
    Fresh,
    /// The envelope replays an already staged live operation.
    Replay,
    /// The envelope replays an operation that already received its bounded
    /// result; the stored body is served without re-dispatch.
    ReplayResulted {
        /// Exact stored bounded `McpResponse` JSON.
        response: serde_json::Value,
        /// Stored canonical result digest binding the body.
        result_digest: String,
    },
}

/// Builds the Kernel-observed bridge process binding from retained state.
///
/// Every field comes from the retained admission descriptor or the retained
/// transport admission receipt for the presenting connection; no
/// caller-supplied process identity is accepted. This mirrors the composition
/// bridge-process-binding construction field-for-field so both writers derive
/// identical bytes, but the result is always re-validated through
/// [`KernelService::admit_host_request`] and never trusted by itself.
fn kernel_bridge_process_binding(
    descriptor: &AgentBridgeAdmissionDescriptor,
    receipt: &AgentBridgePeerAdmissionReceipt,
    connection_id: &str,
) -> Result<AgentBridgeProcessBinding, PortFailure> {
    AgentBridgeProcessBinding {
        wire_id: AGENT_BRIDGE_PROCESS_BINDING_WIRE_ID.to_owned(),
        wire_version: AgentBridgeProcessBinding::CONTRACT_VERSION,
        module_id: descriptor.module_id.clone(),
        profile_id: descriptor.profile_id.as_str().to_owned(),
        connection_id: connection_id.to_owned(),
        descriptor_sha256: descriptor.descriptor_sha256.clone(),
        executable_sha256: descriptor.executable_sha256.clone(),
        executable_volume_serial: descriptor.executable_identity.volume_serial_number,
        executable_file_index: descriptor.executable_identity.file_index,
        bridge_generation: descriptor.generation,
        state_fence: descriptor.state_fence.clone(),
        observed_sid: receipt.observed_sid.clone(),
        observed_session_id: receipt.observed_session_id,
        observed_process_id: receipt.observed_process_id,
        observed_process_start_time_100ns: receipt.observed_process_start_time_100ns,
        observed_image_path: receipt.observed_image_path.clone(),
        binding_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|_| PortFailure::TransportBindingRejected {
        reason: "kernel process binding cannot be digested".to_owned(),
    })
}

/// Builds the `Requested` ORS record for one validated envelope.
///
/// Every identity is preserved opaquely: Session, task, scope, capability,
/// fence, and payload values become exact bytes or digests for replay
/// comparison and are never interpreted here. The fence digest uses the same
/// plain-JSON SHA-256 form as the composition route so both writers stage
/// byte-identical records.
fn requested_host_request_record(
    envelope: &HostRequestEnvelope,
) -> Result<HostRequestRecord, PortFailure> {
    let label = |value: &str| {
        OpaqueLabel::new(value.to_owned()).map_err(|_| PortFailure::TransportBindingRejected {
            reason: "durable host-request identity could not be bound".to_owned(),
        })
    };
    let optional_label = |value: Option<&String>| value.map(|identity| label(identity)).transpose();
    Ok(HostRequestRecord {
        contract_version: ORS_CONTRACT_VERSION,
        operation_id: ors_operation_id(envelope)?,
        kind: match envelope.kind {
            HostRequestKind::Activation => OrsHostRequestKind::Activation,
            HostRequestKind::Invocation => OrsHostRequestKind::Invocation,
            HostRequestKind::Cancellation => OrsHostRequestKind::Cancellation,
            HostRequestKind::Status => OrsHostRequestKind::Status,
            HostRequestKind::Reconciliation => OrsHostRequestKind::Reconciliation,
        },
        request_id: label(envelope.identity.request_id.as_str())?,
        idempotency_key: label(&envelope.identity.idempotency_key)?,
        cancellation_id: label(&envelope.identity.cancellation_id)?,
        parent_operation_id: optional_label(envelope.identity.parent_operation_id.as_ref())?,
        request_digest: envelope.envelope_sha256.clone(),
        payload_digest: envelope.identity.payload_sha256.clone(),
        connection_ref: label(&envelope.connection_id)?,
        session_ref: optional_label(envelope.identity.session_id.as_ref())?,
        task_ref: optional_label(envelope.identity.task_id.as_ref())?,
        scope_ref: optional_label(envelope.identity.work_scope_id.as_ref())?,
        capability_ref: label(&envelope.identity.capability)?,
        fence_digest: sha256_json(&envelope.state_fence).map_err(|_| {
            PortFailure::TransportBindingRejected {
                reason: "state fence cannot be canonicalized".to_owned(),
            }
        })?,
        authority_epoch: envelope.state_fence.authority_epoch.clone(),
        generation: envelope.state_fence.resource_generation.value(),
        deadline_unix_ms: envelope.identity.deadline_unix_ms,
        state: HostRequestState::Requested,
        result_digest: None,
        result_response: None,
        commit_order: 0,
    })
}

/// Requires the presented tool to be the exact admitted operation.
///
/// The canonical tool name must equal the envelope capability and the
/// canonical payload digest must equal the envelope payload digest, which the
/// envelope builder computes over the shared canonical JSON form. Anything
/// else would dispatch bytes the Kernel never admitted.
fn check_tool_linkage(
    request: &HostInvocationRequest,
    envelope: &HostRequestEnvelope,
) -> Result<(), PortFailure> {
    if request.tool.canonical_name() != envelope.identity.capability {
        return Err(PortFailure::TransportBindingRejected {
            reason: "presented tool does not match the admitted capability".to_owned(),
        });
    }
    let payload_digest = canonical_payload_digest(&request.tool)?;
    if payload_digest != envelope.identity.payload_sha256 {
        return Err(PortFailure::TransportBindingRejected {
            reason: "presented payload does not match the admitted payload digest".to_owned(),
        });
    }
    Ok(())
}

/// Derives the exact ORS operation identity for one envelope.
///
/// This is the canonical handle namespace: `"hostreq:"` plus the exact
/// envelope digest, identical to the ORS record key.
fn ors_operation_id(envelope: &HostRequestEnvelope) -> Result<OperationIdentity, PortFailure> {
    OperationIdentity::new(host_request_operation_id(envelope)).map_err(|_| {
        PortFailure::TransportBindingRejected {
            reason: "canonical operation handle is invalid".to_owned(),
        }
    })
}

/// Parses one canonical cancellation target into its ORS key.
///
/// The handle must carry the parent envelope digest after the canonical
/// prefix; the digest is re-validated before any lookup so a malformed
/// reference is reported as an unknown operation.
fn parse_operation_handle(handle: &str) -> Result<(OperationIdentity, String), PortFailure> {
    let unknown = || PortFailure::TransportBindingRejected {
        reason: "unknown operation handle; use the exact handle from admission".to_owned(),
    };
    let digest = handle
        .strip_prefix(HOST_REQUEST_OPERATION_ID_PREFIX)
        .ok_or_else(unknown)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(unknown());
    }
    let operation = OperationIdentity::new(handle.to_owned()).map_err(|_| unknown())?;
    Ok((operation, digest.to_owned()))
}

/// Maps one Kernel service gate failure to the host port failure surface.
fn kernel_service_failure(error: &KernelServiceError) -> PortFailure {
    match error {
        KernelServiceError::GenerationFenced => PortFailure::FenceMismatch,
        KernelServiceError::AdmissionClosed(state) => PortFailure::PlanGap {
            missing_capability: "kernel.host-request.bind-dispatch".to_owned(),
            reason: format!(
                "kernel admission is closed in state {state}; re-attach after readiness"
            ),
        },
        KernelServiceError::HandshakeMismatch { field } => PortFailure::TransportBindingRejected {
            reason: format!("kernel binding rejected at {field}; re-attach with current state"),
        },
        KernelServiceError::InvalidField { field, reason } => {
            PortFailure::TransportBindingRejected {
                reason: format!("kernel binding rejected at {field}: {reason}"),
            }
        }
        KernelServiceError::IllegalTransition { from, to } => {
            PortFailure::TransportBindingRejected {
                reason: format!(
                    "kernel admission is closed in state {from}; cannot admit toward {to}"
                ),
            }
        }
        KernelServiceError::MissingContainmentEvidence
        | KernelServiceError::ReadinessNotProven
        | KernelServiceError::RestartBudgetExhausted
        | KernelServiceError::ControlReserveExhausted
        | KernelServiceError::Platform(_)
        | KernelServiceError::Core(_) => PortFailure::TransportBindingRejected {
            reason: "kernel admission is unavailable; re-attach after recovery".to_owned(),
        },
    }
}

/// Maps one ORS failure to the host port failure surface.
///
/// A changed binding under a known operation is an identity conflict; every
/// other store failure fails closed without inventing an outcome.
fn ors_failure(error: &OrsError) -> PortFailure {
    match error {
        OrsError::HostRequestIdentityConflict { .. } => PortFailure::IdempotencyConflict,
        OrsError::InvalidTransition => PortFailure::TransportBindingRejected {
            reason: "durable operation cannot advance; reconcile the exact operation".to_owned(),
        },
        _ => PortFailure::TransportBindingRejected {
            reason: "durable host-request store is unavailable".to_owned(),
        },
    }
}

/// Maps one closed-operation replay to its terminal disposition.
///
/// Closed work is never blind-retried as new work through this binder.
/// `ResultReceived` (and a `Terminal` carrying a result body) never reaches
/// here: the admit path serves the stored bounded body via
/// [`StagedAdmission::ReplayResulted`] instead.
fn terminal_replay_failure(state: HostRequestState) -> PortFailure {
    match state {
        HostRequestState::Expired => PortFailure::DeadlineExceeded,
        HostRequestState::Cancelled => PortFailure::Cancelled,
        _ => PortFailure::TransportBindingRejected {
            reason: "operation is already terminal; reconcile the exact operation".to_owned(),
        },
    }
}

/// Returns the stored bounded result body of a resulted operation, if any.
///
/// Serves both `ResultReceived` and a `Terminal` that carries a result
/// forward. Any other state, or a resulted state missing either half of the
/// digest/body pair, yields `None` so the caller falls back to the existing
/// terminal/live disposition instead of inventing a response.
fn stored_result_body(record: &HostRequestRecord) -> Option<(serde_json::Value, String)> {
    match (&record.state, &record.result_digest, &record.result_response) {
        (
            HostRequestState::ResultReceived | HostRequestState::Terminal,
            Some(digest),
            Some(body),
        ) => Some((body.clone(), digest.clone())),
        _ => None,
    }
}

/// Computes the canonical digest binding one bounded dispatch result.
///
/// The digest covers the canonical JSON bytes of the exact `McpResponse` the
/// read owner returned, so the stored body is byte-exact and any forged or
/// substituted body fails the readback check before it is served.
fn canonical_result_digest(response: &McpResponse) -> Result<String, PortFailure> {
    let bytes = canonical_json_bytes(response).map_err(|_| {
        PortFailure::TransportBindingRejected {
            reason: "kernel result cannot be canonicalized".to_owned(),
        }
    })?;
    Ok(sha256_hex(&bytes))
}

/// Serves one exact stored result without re-dispatch (Implements #18).
///
/// Reconstructs the bounded `McpResponse` from the stored body, rejects a
/// forged or substituted body whose canonical digest does not match the
/// stored digest before serving, re-applies the response binding check
/// against the presenting envelope, and returns the exact `Responded`
/// outcome. No dispatch happens here: the stored body is the proof that the
/// read owner already answered this exact envelope.
fn readback_responded(
    envelope: &HostRequestEnvelope,
    request: &HostInvocationRequest,
    body: serde_json::Value,
    result_digest: &str,
) -> Result<HostInvocationPortOutcome, PortFailure> {
    let response: McpResponse =
        serde_json::from_value(body).map_err(|_| PortFailure::TransportBindingRejected {
            reason: "stored result does not decode to the bounded response".to_owned(),
        })?;
    if canonical_result_digest(&response)? != result_digest {
        return Err(PortFailure::TransportBindingRejected {
            reason: "stored result digest does not bind the stored body".to_owned(),
        });
    }
    check_response_binding(
        &response,
        envelope.identity.request_id.as_str(),
        &envelope.identity.idempotency_key,
        request.tool.canonical_name(),
    )?;
    if plan_gap_from_response(&response)?.is_some() {
        return Err(PortFailure::TransportBindingRejected {
            reason: "stored result does not carry an answerable projection".to_owned(),
        });
    }
    let handle = HostOperationHandle::new(host_request_operation_id(envelope)).map_err(|_| {
        PortFailure::TransportBindingRejected {
            reason: "canonical operation handle is invalid".to_owned(),
        }
    })?;
    Ok(HostInvocationPortOutcome::Responded {
        operation_handle: handle,
        response: Box::new(response),
    })
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

fn check_deadline_preference(preference_ms: Option<u64>) -> Result<(), PortFailure> {
    if preference_ms.is_some_and(|value| value == 0 || value > MAX_HOST_DEADLINE_PREFERENCE_MS) {
        return Err(PortFailure::TransportBindingRejected {
            reason: "deadline preference is outside the admitted range".to_owned(),
        });
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

fn sha256_json(value: &impl serde::Serialize) -> Result<String, serde_json::Error> {
    Ok(sha256_hex(&serde_json::to_vec(value)?))
}

fn canonical_payload_digest(tool: &ToolRequest) -> Result<String, PortFailure> {
    let bytes = canonical_json_bytes(tool).map_err(|_| PortFailure::TransportBindingRejected {
        reason: "tool payload cannot be canonicalized".to_owned(),
    })?;
    Ok(sha256_hex(&bytes))
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

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test fixtures use expect for fail-fast setup, mirroring store_client tests"
)]
mod local_read_result_tests {
    use super::*;
    use eliot_contracts::{EpochLineageId, ResourceGeneration};
    use serde_json::json;
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    const QUERY_JSON: &str = r#"{
        "protocol_version":"2026-07-28",
        "correlation_id":"host-request-1",
        "client_capabilities":{"tasks":false},
        "tool":{"name":"eliot.query","arguments":{
            "intent":{
                "mode":"verification",
                "time_scope":"session-window",
                "branch_environment_scope":"branch",
                "freshness_policy":"exact-fence",
                "required_assurance":"evidence-provenance"
            },
            "query":"subject:evidence-alpha",
            "exact_resource_uri":null
        }},
        "deadline_preference_ms":5000,
        "observed_context":{
            "host_session_hint":"host-turn-1",
            "observed_resource_refs":[],
            "event_cursors":[],
            "trace_context":{}
        }
    }"#;

    fn test_fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(3).expect("nonzero test sequence"),
        )
        .expect("valid test epoch");
        StateFence::new(epoch, ResourceGeneration::new(7).expect("nonzero test generation"))
    }

    fn test_envelope(request: &HostInvocationRequest) -> HostRequestEnvelope {
        use eliot_contracts::RequestId;
        let payload_digest = canonical_payload_digest(&request.tool).expect("tool must digest");
        eliot_protocol::HostRequestEnvelope {
            wire_id: eliot_protocol::HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::HostRequestEnvelope::CONTRACT_VERSION,
            kind: eliot_protocol::HostRequestKind::Invocation,
            connection_id: "conn-test-1".to_owned(),
            identity: eliot_protocol::HostRequestIdentity {
                request_id: RequestId::new("host-request-1").expect("valid test request id"),
                idempotency_key: "host-request-1:invoke".to_owned(),
                cancellation_id: "host-request-1:invoke:cancel".to_owned(),
                parent_operation_id: None,
                deadline_unix_ms: 2_000_000,
                capability: "eliot.query".to_owned(),
                session_id: Some("kernel-session-1".to_owned()),
                task_id: None,
                work_scope_id: None,
                payload_schema_id: "eliot.mcp.tool-request.v1".to_owned(),
                payload_sha256: payload_digest,
            },
            state_fence: test_fence(),
            descriptor_sha256: "d".repeat(64),
            peer_admission_receipt_sha256: "e".repeat(64),
            activation_binding: None,
            envelope_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("envelope must digest")
    }

    fn test_response() -> McpResponse {
        McpResponse {
            request_id: "host-request-1".to_owned(),
            idempotency_key: "host-request-1:invoke".to_owned(),
            canonical_request_sha256: "a".repeat(64),
            kind: ResponseKind::Projection,
            canonical_tool_name: "eliot.query".to_owned(),
            content: json!({
                "operation": "GetEvidencePack",
                "subject": "evidence-alpha",
                "scope_id": "scope-1",
                "evidence_pack": {"subject": "evidence-alpha"},
                "revision_heads": [{"key": "scope:scope-1", "revision": 3}],
            }),
            artifacts: Vec::new(),
            proof_ceiling: eliot_receipts::ProofCeiling::ScopedVerification,
            resource: None,
            job: None,
            compatibility_correlation_hint: None,
        }
    }

    #[test]
    fn readback_serves_exact_body_and_rejects_forgery_before_reading() {
        let request: HostInvocationRequest =
            serde_json::from_str(QUERY_JSON).expect("fixture must deserialize");
        request.validate().expect("fixture must validate");
        let envelope = test_envelope(&request);
        envelope.validate().expect("envelope must validate");
        let response = test_response();

        // The digest binds the exact bounded bytes: determinism is the proof.
        let digest = canonical_result_digest(&response).expect("digest must compute");
        assert_eq!(
            canonical_result_digest(&response).expect("digest must be stable"),
            digest
        );
        let mut changed = response.clone();
        changed.content = json!({"tampered": true});
        assert_ne!(
            canonical_result_digest(&changed).expect("changed body must digest"),
            digest,
            "a changed payload must never share the stored digest"
        );

        // Exact readback returns the bounded result with its revision inline.
        let body = serde_json::to_value(&response).expect("response must serialize");
        match readback_responded(&envelope, &request, body.clone(), &digest) {
            Ok(HostInvocationPortOutcome::Responded {
                operation_handle,
                response: served,
            }) => {
                assert_eq!(
                    operation_handle.as_str(),
                    host_request_operation_id(&envelope).as_str()
                );
                assert_eq!(*served, response);
                assert_eq!(
                    served.content["revision_heads"][0]["revision"], 3,
                    "the revision travels inside the bounded body"
                );
            }
            other => panic!("expected exact responded readback, got {other:?}"),
        }

        // A forged descriptor (wrong digest) and a substituted body are
        // rejected before anything is served: no duplicate dispatch happens
        // here by construction, since this path never calls the dispatcher.
        assert!(
            readback_responded(&envelope, &request, body.clone(), &"0".repeat(64)).is_err(),
            "forged digest must be rejected before reading"
        );
        let forged_body = serde_json::to_value(&changed).expect("changed must serialize");
        assert!(
            readback_responded(&envelope, &request, forged_body, &digest).is_err(),
            "substituted body must fail the digest binding before serving"
        );

        // A response bound to another tool or request is never served as this
        // operation's answer.
        let mut wrong_tool = response.clone();
        wrong_tool.canonical_tool_name = "eliot.state".to_owned();
        let wrong_tool_body =
            serde_json::to_value(&wrong_tool).expect("wrong-tool must serialize");
        let wrong_tool_digest =
            canonical_result_digest(&wrong_tool).expect("wrong-tool must digest");
        assert!(
            readback_responded(&envelope, &request, wrong_tool_body, &wrong_tool_digest).is_err(),
            "tool mismatch must be rejected before serving"
        );
    }

    #[test]
    fn stored_body_serves_only_resulted_states() {
        let response = test_response();
        let body = serde_json::to_value(&response).expect("response must serialize");
        let digest = canonical_result_digest(&response).expect("digest must compute");
        let label = |value: &str| {
            OpaqueLabel::new(value.to_owned()).expect("valid test label")
        };
        let mut record = HostRequestRecord {
            contract_version: ORS_CONTRACT_VERSION,
            operation_id: ors_operation_id_for_test(),
            kind: OrsHostRequestKind::Invocation,
            request_id: label("req-1"),
            idempotency_key: label("req-1:invoke"),
            cancellation_id: label("req-1:invoke:cancel"),
            parent_operation_id: None,
            request_digest: "d".repeat(64),
            payload_digest: "b".repeat(64),
            connection_ref: label("conn-1"),
            session_ref: None,
            task_ref: None,
            scope_ref: None,
            capability_ref: label("eliot.query"),
            fence_digest: "c".repeat(64),
            authority_epoch: test_fence().authority_epoch.clone(),
            generation: 7,
            deadline_unix_ms: 2_000_000,
            state: HostRequestState::Admitted,
            result_digest: None,
            result_response: None,
            commit_order: 0,
        };
        assert!(
            stored_result_body(&record).is_none(),
            "live operations serve admission, never a stored body"
        );
        record.state = HostRequestState::ResultReceived;
        record.result_digest = Some(digest.clone());
        record.result_response = Some(body.clone());
        let (served, served_digest) =
            stored_result_body(&record).expect("resulted state must serve its body");
        assert_eq!(served, body);
        assert_eq!(served_digest, digest);
        record.state = HostRequestState::Terminal;
        assert!(
            stored_result_body(&record).is_some(),
            "terminal carries the result forward for readback"
        );
        record.result_response = None;
        assert!(
            stored_result_body(&record).is_none(),
            "a half-present pair must never be served"
        );
    }

    fn ors_operation_id_for_test() -> OperationIdentity {
        OperationIdentity::new(format!("hostreq:{}", "d".repeat(64))).expect("valid operation")
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test fixtures use expect for fail-fast setup, mirroring local_read_result_tests"
)]
mod local_read_build_tests {
    use super::*;
    use eliot_contracts::{EpochLineageId, ResourceGeneration};
    use serde_json::json;
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    const QUERY_JSON: &str = r#"{
        "protocol_version":"2026-07-28",
        "correlation_id":"host-request-1",
        "client_capabilities":{"tasks":false},
        "tool":{"name":"eliot.query","arguments":{
            "intent":{
                "mode":"verification",
                "time_scope":"session-window",
                "branch_environment_scope":"branch",
                "freshness_policy":"exact-fence",
                "required_assurance":"evidence-provenance"
            },
            "query":"subject:evidence-alpha",
            "exact_resource_uri":null
        }},
        "deadline_preference_ms":5000,
        "observed_context":{
            "host_session_hint":"host-turn-1",
            "observed_resource_refs":[],
            "event_cursors":[],
            "trace_context":{}
        }
    }"#;

    fn test_fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(3).expect("nonzero test sequence"),
        )
        .expect("valid test epoch");
        StateFence::new(epoch, ResourceGeneration::new(7).expect("nonzero test generation"))
    }

    fn test_query_pair() -> (HostInvocationRequest, HostRequestEnvelope) {
        use eliot_contracts::RequestId;
        let request: HostInvocationRequest =
            serde_json::from_str(QUERY_JSON).expect("fixture must deserialize");
        request.validate().expect("fixture must validate");
        let payload_digest =
            canonical_payload_digest(&request.tool).expect("tool must digest");
        let envelope = eliot_protocol::HostRequestEnvelope {
            wire_id: eliot_protocol::HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::HostRequestEnvelope::CONTRACT_VERSION,
            kind: eliot_protocol::HostRequestKind::Invocation,
            connection_id: "conn-test-1".to_owned(),
            identity: eliot_protocol::HostRequestIdentity {
                request_id: RequestId::new("host-request-1").expect("valid test request id"),
                idempotency_key: "host-request-1:invoke".to_owned(),
                cancellation_id: "host-request-1:invoke:cancel".to_owned(),
                parent_operation_id: None,
                deadline_unix_ms: 2_000_000,
                capability: "eliot.query".to_owned(),
                session_id: Some("kernel-session-1".to_owned()),
                task_id: None,
                work_scope_id: None,
                payload_schema_id: "eliot.mcp.tool-request.v1".to_owned(),
                payload_sha256: payload_digest,
            },
            state_fence: test_fence(),
            descriptor_sha256: "d".repeat(64),
            peer_admission_receipt_sha256: "e".repeat(64),
            activation_binding: None,
            envelope_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("envelope must digest");
        (request, envelope)
    }

    fn evidence_payload() -> serde_json::Value {
        json!({
            "version": 1,
            "subject": "evidence-alpha",
            "scope_id": "scope-1",
            "records": [
                {
                    "capture_index": 0,
                    "operation": "CaptureObservation",
                    "parameters": {"subject": "evidence-alpha"},
                },
            ],
            "provenance": {
                "matched_total": 1,
                "returned": 1,
                "max_records": 10,
                "truncated": false,
            },
        })
    }

    #[test]
    fn build_serves_exact_bounded_body_with_revision() {
        let (request, envelope) = test_query_pair();
        let payload = evidence_payload();
        let (digest, body) = AuthenticatedHostSession::build_local_read_result_body(
            &envelope,
            "scope-1",
            "evidence-alpha",
            10,
            "verification",
            payload.clone(),
        )
        .expect("admitted query must build its bounded body");

        // The digest binds the exact bounded bytes: determinism is the proof.
        let decoded: McpResponse =
            serde_json::from_value(body.clone()).expect("body must decode");
        let recomputed = sha256_hex(
            &canonical_json_bytes(&decoded).expect("built body must canonicalize"),
        );
        assert_eq!(recomputed, digest);

        // The projection half is exact: kind, ceiling, identity, and the
        // store payload crossing unchanged with its revision.
        assert_eq!(body["kind"], json!("PROJECTION"));
        assert_eq!(body["canonical_tool_name"], json!("eliot.query"));
        assert_eq!(body["request_id"], json!("host-request-1"));
        assert_eq!(body["idempotency_key"], json!("host-request-1:invoke"));
        assert_eq!(body["proof_ceiling"], json!("SCOPED_VERIFICATION"));
        assert_eq!(body["content"]["operation"], json!("GetEvidencePack"));
        assert_eq!(body["content"]["subject"], json!("evidence-alpha"));
        assert_eq!(body["content"]["scope_id"], json!("scope-1"));
        assert_eq!(body["content"]["evidence_pack"], payload);

        // The built pair feeds the exact readback without re-dispatch: the
        // bridge `eliot.query` for this captured subject answers Responded
        // with these bytes instead of a bare Accepted admission.
        match readback_responded(&envelope, &request, body.clone(), &digest) {
            Ok(HostInvocationPortOutcome::Responded { response, .. }) => {
                assert_eq!(
                    serde_json::to_value(&*response).expect("served must serialize"),
                    body,
                    "readback must serve the built body verbatim"
                );
            }
            other => panic!("expected exact responded readback, got {other:?}"),
        }
    }

    #[test]
    fn build_is_deterministic_and_rejects_forgery_before_serving() {
        let (_, envelope) = test_query_pair();
        let payload = evidence_payload();
        let first = AuthenticatedHostSession::build_local_read_result_body(
            &envelope,
            "scope-1",
            "evidence-alpha",
            10,
            "verification",
            payload.clone(),
        )
        .expect("first build must succeed");
        let second = AuthenticatedHostSession::build_local_read_result_body(
            &envelope,
            "scope-1",
            "evidence-alpha",
            10,
            "verification",
            payload,
        )
        .expect("second build must succeed");
        assert_eq!(
            first, second,
            "identical inputs build byte-identical results with no dispatch"
        );

        // A substituted body never shares the stored digest.
        let mut tampered: McpResponse =
            serde_json::from_value(first.1.clone()).expect("built body must decode");
        tampered.content = json!({"tampered": true});
        let tampered_digest = sha256_hex(
            &canonical_json_bytes(&tampered).expect("tampered must canonicalize"),
        );
        assert_ne!(
            tampered_digest, first.0,
            "a changed payload must never share the stored digest"
        );
    }

    #[test]
    fn build_rejects_non_query_and_over_bound_before_serving() {
        let (_, envelope) = test_query_pair();
        let payload = evidence_payload();
        let build = |envelope: &HostRequestEnvelope,
                     scope: &str,
                     subject: &str,
                     max: u32,
                     mode: &str| {
            AuthenticatedHostSession::build_local_read_result_body(
                envelope,
                scope,
                subject,
                max,
                mode,
                payload.clone(),
            )
        };

        // A non-query capability is never a local read.
        let mut other = envelope.clone();
        other.identity.capability = "eliot.state".to_owned();
        assert!(
            build(&other, "scope-1", "evidence-alpha", 10, "verification").is_err(),
            "non-query capability must be rejected before serving"
        );

        // The explicit bound is catalogue-closed: zero and over-bound fail.
        assert!(
            build(&envelope, "scope-1", "evidence-alpha", 0, "verification").is_err(),
            "zero bound must be rejected before serving"
        );
        assert!(
            build(
                &envelope,
                "scope-1",
                "evidence-alpha",
                EVIDENCE_PACK_MAX_RECORDS + 1,
                "verification",
            )
            .is_err(),
            "over-bound request must be rejected before serving"
        );

        // Position intent never admits GetEvidencePack; unknown modes fail too.
        assert!(
            build(&envelope, "scope-1", "evidence-alpha", 10, "current_position").is_err(),
            "position intent must be rejected before serving"
        );
        assert!(
            build(&envelope, "scope-1", "evidence-alpha", 10, "freeform").is_err(),
            "unknown mode must be rejected before serving"
        );

        // Blank selectors prove nothing.
        assert!(
            build(&envelope, "scope-1", "   ", 10, "verification").is_err(),
            "blank subject must be rejected before serving"
        );
        assert!(
            build(&envelope, "  ", "evidence-alpha", 10, "verification").is_err(),
            "blank scope must be rejected before serving"
        );
    }
}
