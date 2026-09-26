//! Authenticated Kernel client transport for `eliotd`.
//!
//! Architecture: A13.2 (Governor/Kernel authenticated IPC boundary), A13.8
//! (process-receipt-gated pre-admission).
//! Implementation: I1.8 (artifact-bound session), I2.16 (generation fencing),
//! I2.23 (typed contract payloads).
//! This module owns only the EBP transport/session proof; Kernel remains the
//! sole process, Store, and canonical authority owner.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use eliot_contracts::{
    ClockReading, OperationId, ProductId, RequestId, RequestMetadata, SessionId, SourceId,
};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_governor::{GovernorLaunchConfig, KernelGenerationSnapshot, KernelPortError};
use eliot_learning_contracts::LearningStateViewRecipe;
use eliot_protocol::{
    AgentActivationClaimRequest, AgentActivationKernelOwnerReadback, AgentActivationOwnerReadback,
    AgentActivationResolutionResult, AgentActivationResultAck, AgentActivationResultReconcile,
    AgentActivationResultSubmit, EncodingProfile, Frame, FrameKind,
    HOST_REQUEST_INVOKE_READ_WIRE_ID, HostRequestEnvelope, HostRequestInvokeReadPayload,
    HostRequestResultBody, LocalReadAttempt, MessageType, ProtocolPayload, ProtocolVersion,
    RequestIdentity, TaskControllerAttempt, TaskControllerInvocation, TaskControllerResultBody,
    host_request_operation_id,
};
use eliot_receipts::RequestBinding;
use eliot_store_api::{NamedReadRequest, NamedReadResponse, WriteReceipt};
use eliot_testd_core::{
    TestdPendingVerifierDispatch, TestdTerminalCompletionEvidence, TestdVerifierDispatchBinding,
};
use serde::{Deserialize, Serialize};

#[cfg(windows)]
use eliot_ipc::{DeliveryOutcome, NamedPipeTransport, TransportLimits};
#[cfg(windows)]
use eliot_platform_windows::{KernelFrontDoorAclMode, KernelFrontDoorServerExpectation};

mod handshake;

#[cfg(windows)]
use handshake::client_hello;
use handshake::expected_snapshot;
pub(super) use handshake::{KernelClientError, WireOutcome, kernel_port_error, operation_payload};
#[cfg(windows)]
pub(super) use handshake::{is_pre_admission_pending_rejection, validate_server_hello};

use super::{
    KERNEL_OPERATION_TIMEOUT, KernelLaunchBinding, PRE_ADMISSION_RETRY_DELAY, SERVICE_NAME,
    unix_ms, unix_ms_i64,
};

/// #791 (W4/W17): the typed detail reported when the daemon's shutdown request
/// abandons a front-door exchange whose outcome this client cannot observe.
#[cfg(windows)]
const SHUTDOWN_ABANDONED_EXCHANGE: &str =
    "Kernel front-door exchange abandoned by the daemon shutdown request";

/// #791 (W4/W17): the cancellation future a cancel-aware front-door send
/// observes. It resolves only when the daemon's shutdown request is published
/// or when the client is released and its shutdown sender is dropped — the two
/// real observations of "this write is no longer required". It never resolves
/// on a timer, so a send with no shutdown request keeps the transport's own
/// `operation_timeout` as its only deadline.
#[cfg(windows)]
struct FrontDoorCancellation {
    /// Polled only for a request already published before this send started.
    observed: tokio::sync::watch::Receiver<bool>,
    /// Resolves once a shutdown request is published, and also once the
    /// sending half is dropped because this client is being released.
    changed: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
}

#[cfg(windows)]
impl std::future::Future for FrontDoorCancellation {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        // A request already published before the send started is observed
        // immediately, so a shutdown racing a just-connected exchange still
        // cancels that send. `changed` then resolves for a request published
        // later, and also for a dropped sender — the client being released.
        if *this.observed.borrow_and_update() {
            return std::task::Poll::Ready(());
        }
        this.changed.as_mut().poll(context)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerBundleReadbackWire {
    bound: bool,
    revision: Option<u64>,
    digest: Option<String>,
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationSubmitResponse {
    accepted: bool,
    #[serde(default)]
    expired: bool,
    #[serde(default)]
    ack: Option<AgentActivationResultAck>,
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationReconcileResponse {
    ack: AgentActivationResultAck,
}

pub struct DaemonKernelClient {
    launch: GovernorLaunchConfig,
    pub(super) kernel_binding: KernelLaunchBinding,
    pub(super) connection_id: String,
    pub(super) snapshot: KernelGenerationSnapshot,
    request_counter: Arc<AtomicU64>,
    /// Literal Kernel-issued `sid=..;session=..` binding string retained only
    /// after a successful [`validate_server_hello`](handshake::validate_server_hello)
    /// in this process (AUD-C02-B, Implements #1187). Never the whole
    /// `ServerHello`, never a constant, no secret: identity refs only. `None`
    /// until the first validated handshake, so pre-handshake reads stay
    /// fail-closed to "no live session".
    validated_session_binding: Mutex<Option<String>>,
    /// #791 (W4/W17): the daemon's own shutdown request, carried as the
    /// broadcast a cancel-aware front-door send can observe. The only writer
    /// is [`request_shutdown`](Self::request_shutdown), which the production
    /// `ctrl_c` shutdown path calls; dropping this client drops the sender,
    /// and a dropped sender is observed as cancellation too. Never a local
    /// literal and never a per-send reinterpretation of a timeout: a pending
    /// send that observes it settles as `UnknownOutcome`, never as a
    /// delivered frame.
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Receiving half of [`shutdown_tx`](Self::shutdown_tx), cloned per send
    /// so one in-flight exchange never consumes the shutdown request.
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
}

/// Already-validated Kernel-issued owner session facts for the single live
/// owner session (AUD-C02-B, Implements #1187; single-owner decision #1376).
///
/// Every field is cloned from state this client already holds after the
/// authenticated handshake: the validated `sid=..;session=..` binding string,
/// the Kernel snapshot principal and receipt-relevant artifact digests, the
/// local connection correlation id, and the descriptor launch nonce carried
/// in [`KernelLaunchBinding::launch_nonce`]. No re-handshake, no secret, no
/// constant, no parsing of constants.
#[derive(Clone, Debug)]
pub struct OwnerSessionFacts {
    pub(crate) session_binding: String,
    pub(crate) kernel_principal: String,
    pub(crate) connection_id: String,
    pub(crate) launch_nonce: String,
    pub(crate) artifact_digest: String,
    pub(crate) protected_snapshot_digest: String,
}

impl OwnerSessionFacts {
    /// Returns the validated `sid=..;session=..` binding string: the daemon's
    /// transport-session evidence for supervision progress (identity refs
    /// only, never a secret).
    #[must_use]
    pub fn session_binding(&self) -> &str {
        &self.session_binding
    }

    /// Returns the local connection correlation id: diagnostic transport
    /// evidence only, never renewal identity.
    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }
}

#[cfg(windows)]
pub(super) async fn retry_pre_admission<T, F, Fut>(
    timeout: Duration,
    mut operation: F,
    deadline_error: &'static str,
) -> Result<T, KernelClientError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, KernelClientError>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match operation().await {
            Err(
                KernelClientError::PreAdmissionPending
                | KernelClientError::PreAdmissionTransport(_),
            ) => {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err(KernelClientError::Transport(deadline_error.to_owned()));
                }
                tokio::time::sleep(PRE_ADMISSION_RETRY_DELAY.min(deadline - now)).await;
            }
            outcome => return outcome,
        }
    }
}

/// Typed outcome of one `local_read_result` submit (Implements #18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalReadSubmitOutcome {
    /// Kernel persisted the body through the ORS result path. An exact replay
    /// of an already-resulted operation reports here too — idempotent, even
    /// across deadline expiry.
    Accepted,
    /// The absolute deadline elapsed before the body could persist. This is
    /// the expected claim/submit race, projected as a known outcome — never
    /// as a transport error.
    Expired,
    /// The presented attempt is not the current fencing generation: lease
    /// replacement, reassignment, disconnect, restart, epoch rotation, or
    /// revocation quarantined the submission as a noncanonical observation.
    /// The waiter never observes the stale result; the poller idles and the
    /// current attempt can still complete through its own bound capability.
    /// Never a transport error, never retried with the same capability.
    StaleAttempt,
}

/// Kernel-derived Task Controller claim. The duplicated invocation, envelope,
/// tool and identity are checked for exact binding before it reaches Governor.
#[derive(Clone, Debug)]
pub struct TaskControllerClaimedInvocation {
    pub invocation: TaskControllerInvocation,
    pub envelope: HostRequestEnvelope,
    pub tool: serde_json::Value,
    pub request_identity: RequestIdentity,
    pub operation_id: OperationId,
    pub attempt: TaskControllerAttempt,
}

/// Typed outcome of one `task_controller_result` submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskControllerSubmitOutcome {
    /// Kernel persisted the result body or recognized an exact replay.
    Accepted,
    /// The admitted attempt expired before the result was committed.
    Expired,
    /// The attempt was replaced, revoked or otherwise stale.
    StaleAttempt,
}

fn derive_task_controller_request_identity(
    invocation: &TaskControllerInvocation,
    envelope: &HostRequestEnvelope,
) -> Result<RequestIdentity, String> {
    let recipe: LearningStateViewRecipe =
        serde_json::from_value(invocation.learning_state_view_recipe.clone())
            .map_err(|error| format!("Task Controller learning recipe does not decode: {error}"))?;
    recipe
        .validate()
        .map_err(|error| format!("Task Controller learning recipe is invalid: {error}"))?;
    if recipe.binding.task_id != invocation.task_id
        || recipe.binding.scope.as_str()
            != envelope
                .identity
                .work_scope_id
                .as_deref()
                .unwrap_or_default()
        || recipe.binding.state_fence != envelope.state_fence
        || recipe.binding.request_id.as_str() != envelope.identity.request_id.as_str()
    {
        return Err(
            "Task Controller invocation is not bound to the admitted recipe/envelope".to_owned(),
        );
    }
    let session_id = envelope
        .identity
        .session_id
        .clone()
        .map(|value| SessionId::new(value).map_err(|error| error.to_string()))
        .transpose()?;
    let metadata = RequestMetadata {
        request_id: recipe.binding.request_id.clone(),
        session_id,
        task_id: Some(recipe.binding.task_id.clone()),
        product_id: recipe.binding.product_id.clone(),
        source_id: recipe.binding.source.owner.clone(),
        state_fence: envelope.state_fence.clone(),
        clock: ClockReading::default(),
    };
    let identity = RequestIdentity {
        request: RequestBinding {
            metadata,
            state_fence: envelope.state_fence.clone(),
        },
        idempotency_key: envelope.identity.idempotency_key.clone(),
        deadline_unix_ms: envelope.identity.deadline_unix_ms,
        cancellation_id: envelope.identity.cancellation_id.clone(),
    };
    identity
        .validate()
        .map_err(|error| format!("derived Task Controller identity is invalid: {error}"))?;
    Ok(identity)
}

/// Parses one unwrapped Task Controller poll answer into its exact admitted
/// invocation and Kernel-issued attempt.
pub fn parse_task_controller_claimed_pair(
    value: &serde_json::Value,
) -> Result<Option<TaskControllerClaimedInvocation>, String> {
    let pair = value
        .get("pair")
        .ok_or_else(|| "Kernel task_controller_claim answer omits pair".to_owned())?;
    if pair.is_null() {
        return Ok(None);
    }
    if !pair.is_object() {
        return Err("Kernel task_controller_claim pair is neither an object nor null".to_owned());
    }
    let decode = |field: &str| {
        pair.get(field)
            .cloned()
            .ok_or_else(|| format!("Kernel task_controller_claim pair omits {field}"))
    };
    let invocation: TaskControllerInvocation = serde_json::from_value(decode("invocation")?)
        .map_err(|error| format!("Kernel Task Controller invocation does not decode: {error}"))?;
    invocation
        .validate()
        .map_err(|error| format!("Kernel Task Controller invocation is invalid: {error}"))?;
    let envelope: HostRequestEnvelope = serde_json::from_value(decode("envelope")?)
        .map_err(|error| format!("Kernel Task Controller envelope does not decode: {error}"))?;
    envelope
        .validate()
        .map_err(|error| format!("Kernel Task Controller envelope is invalid: {error}"))?;
    let tool = decode("tool")?;
    let request_identity: RequestIdentity = match pair.get("identity") {
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|error| format!("Kernel Task Controller identity does not decode: {error}"))?,
        None => derive_task_controller_request_identity(&invocation, &envelope)?,
    };
    request_identity
        .validate()
        .map_err(|error| format!("Kernel Task Controller identity is invalid: {error}"))?;
    let operation_id: OperationId = serde_json::from_value(decode("operation_id")?)
        .map_err(|error| format!("Kernel Task Controller operation id does not decode: {error}"))?;
    let attempt: TaskControllerAttempt = serde_json::from_value(decode("attempt")?)
        .map_err(|error| format!("Kernel Task Controller attempt does not decode: {error}"))?;
    attempt
        .validate()
        .map_err(|error| format!("Kernel Task Controller attempt is invalid: {error}"))?;

    let tool_name = tool.get("name").and_then(serde_json::Value::as_str);
    let tool_invocation = tool
        .get("arguments")
        .cloned()
        .and_then(|arguments| serde_json::from_value::<TaskControllerInvocation>(arguments).ok());
    let expected_operation = host_request_operation_id(&envelope);
    if envelope.kind != eliot_protocol::HostRequestKind::Invocation
        || envelope.identity.capability != "eliot.task-controller"
        || envelope.identity.payload_schema_id != "eliot.task-controller.invoke.v1"
        || tool_name != Some("eliot.task-controller")
        || tool_invocation.as_ref() != Some(&invocation)
        || invocation.task_id.as_str() != envelope.identity.task_id.as_deref().unwrap_or_default()
        || invocation.work_scope_id
            != envelope
                .identity
                .work_scope_id
                .as_deref()
                .unwrap_or_default()
        || request_identity.request.state_fence != envelope.state_fence
        || request_identity.request.metadata.state_fence != envelope.state_fence
        || request_identity.request.metadata.task_id.as_ref() != Some(&invocation.task_id)
        || operation_id.as_str() != expected_operation
        || attempt.operation_id != expected_operation
        || attempt.task_id != invocation.task_id
        || attempt.scope_id != invocation.work_scope_id
        || attempt.state_fence != envelope.state_fence
        || attempt.authority_epoch != envelope.state_fence.authority_epoch
        || attempt.expires_at_unix_ms != envelope.identity.deadline_unix_ms
    {
        return Err("Kernel Task Controller pair does not bind its admitted envelope".to_owned());
    }
    Ok(Some(TaskControllerClaimedInvocation {
        invocation,
        envelope,
        tool,
        request_identity,
        operation_id,
        attempt,
    }))
}

/// Parses one unwrapped Task Controller result submit answer.
pub fn parse_task_controller_submit_outcome(
    value: &serde_json::Value,
) -> Result<TaskControllerSubmitOutcome, String> {
    let accepted = value
        .get("accepted")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| "Kernel task_controller_result answer omits accepted outcome".to_owned())?;
    if accepted {
        return Ok(TaskControllerSubmitOutcome::Accepted);
    }
    if value
        .get("expired")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(TaskControllerSubmitOutcome::Expired);
    }
    if value
        .get("stale")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(TaskControllerSubmitOutcome::StaleAttempt);
    }
    Err("Kernel task_controller_result answer is not accepted, expired, or stale".to_owned())
}

/// Parses one unwrapped `local_read_claim` answer value into the claimed
/// admitted pair plus its fenced attempt capability.
///
/// The Kernel arm
/// (`bins/eliot-kernel/src/daemon_request_dispatch.rs::local_read_claim`)
/// answers the single-`operation`-key poll with `{"pair": {"envelope",
/// "tool", "attempt"}}` or `{"pair": null}`. `None` is the empty-queue
/// backoff signal, not an error — exactly like the activation ticket `None`
/// case. The claimed envelope must already decode as admitted shape and the
/// attempt must already decode as a bound capability (operation handle equal
/// to the envelope handle); their closed linkage and fence binding are
/// re-proved inside
/// [`forward_admitted_local_read`](super::forward_admitted_local_read) before
/// any read or submit touches them. A pair without an attempt fails closed:
/// absent authority is never invented.
pub fn parse_local_read_claimed_pair(
    value: &serde_json::Value,
) -> Result<Option<(HostRequestEnvelope, serde_json::Value, LocalReadAttempt)>, String> {
    // #740: receipt span. Records pair presence/absence by identity; the
    // tool payload value never enters the sink.
    let _span = tracing::info_span!("eliotd.request_receipt").entered();
    let pair = value
        .get("pair")
        .ok_or_else(|| "Kernel local_read_claim answer omits the pair".to_owned())?;
    match pair {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Object(_) => {
            let envelope_value = pair
                .get("envelope")
                .cloned()
                .ok_or_else(|| "Kernel local_read_claim pair omits the envelope".to_owned())?;
            let tool = pair
                .get("tool")
                .cloned()
                .ok_or_else(|| "Kernel local_read_claim pair omits the tool".to_owned())?;
            let attempt_value = pair
                .get("attempt")
                .cloned()
                .ok_or_else(|| "Kernel local_read_claim pair omits the attempt".to_owned())?;
            let envelope: HostRequestEnvelope =
                serde_json::from_value(envelope_value).map_err(|error| {
                    format!("Kernel local_read_claim pair envelope does not decode: {error}")
                })?;
            envelope.validate().map_err(|error| {
                format!("Kernel local_read_claim pair envelope is not admitted shape: {error}")
            })?;
            let attempt: LocalReadAttempt =
                serde_json::from_value(attempt_value).map_err(|error| {
                    format!("Kernel local_read_claim pair attempt does not decode: {error}")
                })?;
            attempt.validate().map_err(|error| {
                format!("Kernel local_read_claim pair attempt is not bound shape: {error}")
            })?;
            if attempt.operation_id != host_request_operation_id(&envelope) {
                return Err(
                    "Kernel local_read_claim pair attempt does not bind the envelope".to_owned(),
                );
            }
            Ok(Some((envelope, tool, attempt)))
        }
        _ => Err("Kernel local_read_claim pair is neither an admitted pair nor null".to_owned()),
    }
}

/// Parses one unwrapped `local_read_result` answer value into the typed
/// submit outcome.
///
/// The Kernel arm
/// (`bins/eliot-kernel/src/daemon_request_dispatch.rs::local_read_result`)
/// answers `{"accepted": true}` on persist (exact replays included),
/// `{"accepted": false, "expired": true}` when the absolute deadline elapsed
/// first, and `{"accepted": false, "stale": true, ...}` when the presented
/// attempt is not the current fencing generation. Anything else is a contract
/// violation, never a silent accept.
pub fn parse_local_read_submit_outcome(
    value: &serde_json::Value,
) -> Result<LocalReadSubmitOutcome, String> {
    // #740: submit-outcome span. Accepted/expired/stale stay distinct;
    // anything else is a contract violation, never a silent accept.
    let _span = tracing::info_span!("eliotd.local_read_submit").entered();
    let accepted = value
        .get("accepted")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| "Kernel local_read_result answer omits the accepted outcome".to_owned())?;
    if accepted {
        return Ok(LocalReadSubmitOutcome::Accepted);
    }
    if value
        .get("expired")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(LocalReadSubmitOutcome::Expired);
    }
    if value
        .get("stale")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(LocalReadSubmitOutcome::StaleAttempt);
    }
    Err("Kernel local_read_result answer is neither accepted, expired, nor stale".to_owned())
}

/// Typed outcome of one `semantic_observe_result` submit (issue #2565).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveSubmitOutcome {
    /// Kernel persisted the body through the ORS result path. An exact replay
    /// of an already-resulted operation reports here too — idempotent, even
    /// across deadline expiry.
    Accepted,
    /// The absolute deadline elapsed before the body could persist. This is
    /// the expected claim/submit race, projected as a known outcome — never
    /// as a transport error.
    Expired,
    /// The presented attempt is not the current fencing generation: lease
    /// replacement, reassignment, disconnect, restart, epoch rotation, or
    /// revocation quarantined the submission as a noncanonical observation.
    /// The waiter never observes the stale result; the poller idles and the
    /// current attempt can still complete through its own bound capability.
    /// Never a transport error, never retried with the same capability.
    StaleAttempt,
}

/// Typed outcome of one `semantic_observe_deferred` deferral (issue #2565).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveDeferOutcome {
    /// Kernel retired the queue pair and advanced the durable record
    /// `Admitted -> Routed`: the pending handle stays live with its exact
    /// resume condition. No effect was produced and none was claimed.
    Deferred,
    /// The durable record already closed the operation: consult it through
    /// the waiter path instead of deferring.
    Settled,
    /// The absolute deadline elapsed before the deferral could record. This
    /// is the expected claim/defer race, projected as a known outcome.
    Expired,
    /// The presented attempt is not the current fencing generation. The
    /// waiter never observes the stale deferral; the poller idles.
    StaleAttempt,
}

/// Parses one unwrapped `semantic_observe_claim` answer value into the
/// claimed admitted pair plus its fenced attempt capability.
///
/// The Kernel arm
/// (`bins/eliot-kernel/src/daemon_request_dispatch.rs::semantic_observe_claim`)
/// answers the single-`operation`-key poll with `{"pair": {"envelope",
/// "tool", "attempt"}}` or `{"pair": null}`. `None` is the empty-queue
/// backoff signal, not an error — exactly like the local-read claim. The
/// claimed envelope must already decode as admitted shape, name the
/// `eliot.observe` capability, and bind the attempt; their closed linkage
/// and fence binding are re-proved inside the observe flight before any
/// submit or defer touches them. A pair without an attempt fails closed:
/// absent authority is never invented.
pub fn parse_observe_claimed_pair(
    value: &serde_json::Value,
) -> Result<Option<(HostRequestEnvelope, serde_json::Value, LocalReadAttempt)>, String> {
    // #740: receipt span. Records pair presence/absence by identity; the
    // tool payload value never enters the sink.
    let _span = tracing::info_span!("eliotd.request_receipt").entered();
    let pair = value
        .get("pair")
        .ok_or_else(|| "Kernel semantic_observe_claim answer omits the pair".to_owned())?;
    match pair {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Object(_) => {
            let envelope_value = pair.get("envelope").cloned().ok_or_else(|| {
                "Kernel semantic_observe_claim pair omits the envelope".to_owned()
            })?;
            let tool = pair
                .get("tool")
                .cloned()
                .ok_or_else(|| "Kernel semantic_observe_claim pair omits the tool".to_owned())?;
            let attempt_value = pair
                .get("attempt")
                .cloned()
                .ok_or_else(|| "Kernel semantic_observe_claim pair omits the attempt".to_owned())?;
            let envelope: HostRequestEnvelope =
                serde_json::from_value(envelope_value).map_err(|error| {
                    format!("Kernel semantic_observe_claim pair envelope does not decode: {error}")
                })?;
            envelope.validate().map_err(|error| {
                format!(
                    "Kernel semantic_observe_claim pair envelope is not admitted shape: {error}"
                )
            })?;
            if envelope.identity.capability != "eliot.observe" {
                return Err(
                    "Kernel semantic_observe_claim pair is not the admitted observe capability"
                        .to_owned(),
                );
            }
            let attempt: LocalReadAttempt =
                serde_json::from_value(attempt_value).map_err(|error| {
                    format!("Kernel semantic_observe_claim pair attempt does not decode: {error}")
                })?;
            attempt.validate().map_err(|error| {
                format!("Kernel semantic_observe_claim pair attempt is not bound shape: {error}")
            })?;
            if attempt.operation_id != host_request_operation_id(&envelope) {
                return Err(
                    "Kernel semantic_observe_claim pair attempt does not bind the envelope"
                        .to_owned(),
                );
            }
            Ok(Some((envelope, tool, attempt)))
        }
        _ => Err(
            "Kernel semantic_observe_claim pair is neither an admitted pair nor null".to_owned(),
        ),
    }
}

/// Parses one unwrapped `semantic_observe_result` answer value into the
/// typed submit outcome.
///
/// The Kernel arm
/// (`bins/eliot-kernel/src/daemon_request_dispatch.rs::semantic_observe_result`)
/// answers `{"accepted": true}` on persist (exact replays included),
/// `{"accepted": false, "expired": true}` when the absolute deadline elapsed
/// first, and `{"accepted": false, "stale": true, ...}` when the presented
/// attempt is not the current fencing generation. Anything else is a contract
/// violation, never a silent accept.
pub fn parse_observe_submit_outcome(
    value: &serde_json::Value,
) -> Result<ObserveSubmitOutcome, String> {
    // #740: submit-outcome span. Accepted/expired/stale stay distinct;
    // anything else is a contract violation, never a silent accept.
    let _span = tracing::info_span!("eliotd.observe_submit").entered();
    let accepted = value
        .get("accepted")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            "Kernel semantic_observe_result answer omits the accepted outcome".to_owned()
        })?;
    if accepted {
        return Ok(ObserveSubmitOutcome::Accepted);
    }
    if value
        .get("expired")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(ObserveSubmitOutcome::Expired);
    }
    if value
        .get("stale")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(ObserveSubmitOutcome::StaleAttempt);
    }
    Err("Kernel semantic_observe_result answer is neither accepted, expired, nor stale".to_owned())
}

/// Parses one unwrapped `semantic_observe_deferred` answer value into the
/// typed defer outcome.
///
/// The Kernel arm
/// (`bins/eliot-kernel/src/daemon_request_dispatch.rs::semantic_observe_deferred`)
/// answers `{"accepted": true, "deferred": true, ...}` when the pair retired
/// and the durable record advanced to `Routed`,
/// `{"accepted": true, "settled": true, ...}` when the record already
/// closed, `{"accepted": false, "expired": true}` on the deadline race, and
/// `{"accepted": false, "stale": true, ...}` on a superseded attempt.
/// Anything else is a contract violation, never a silent accept.
pub fn parse_observe_defer_outcome(
    value: &serde_json::Value,
) -> Result<ObserveDeferOutcome, String> {
    let _span = tracing::info_span!("eliotd.observe_defer").entered();
    let accepted = value
        .get("accepted")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            "Kernel semantic_observe_deferred answer omits the accepted outcome".to_owned()
        })?;
    if accepted {
        if value
            .get("deferred")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(ObserveDeferOutcome::Deferred);
        }
        if value
            .get("settled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(ObserveDeferOutcome::Settled);
        }
        return Err(
            "Kernel semantic_observe_deferred answer is accepted but neither deferred nor settled"
                .to_owned(),
        );
    }
    if value
        .get("expired")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(ObserveDeferOutcome::Expired);
    }
    if value
        .get("stale")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(ObserveDeferOutcome::StaleAttempt);
    }
    Err(
        "Kernel semantic_observe_deferred answer is neither deferred, settled, expired, nor stale"
            .to_owned(),
    )
}

impl DaemonKernelClient {
    #[cfg(windows)]
    pub async fn claim_agent_activation_ticket(
        &self,
        dependency_revision: &str,
    ) -> Result<super::ActivationClaim, super::DaemonError> {
        let claim = AgentActivationClaimRequest::new(
            "governor.readiness".to_owned(),
            dependency_revision.to_owned(),
            unix_ms(),
        )
        .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = self
            .transact_async(
                "agent_activation_claim",
                serde_json::json!({ "claim": claim }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let ticket = value.get("ticket").cloned().ok_or_else(|| {
            super::DaemonError::Kernel("Kernel claim response omitted ticket".to_owned())
        })?;
        // Thread the raw claim bytes before any typed decode: the classifier
        // decodes inside and carries these exact bytes verbatim on Invalid.
        // Encoding here fails closed through the existing Kernel error; no
        // fallback bytes are ever fabricated. `b"null"` still classifies to
        // the Empty null-poll backoff inside.
        let ticket_bytes = serde_json::to_vec(&ticket)
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        Ok(super::classify_claimed_ticket_value(&ticket_bytes))
    }

    /// Reads the exact P-07 owner projection currently retained by Kernel.
    /// An unbound owner is represented as `None`; a bound owner must carry
    /// both its monotonic revision and canonical bundle digest.
    pub async fn query_owner_bundle_readback(
        &self,
    ) -> Result<Option<AgentActivationKernelOwnerReadback>, super::DaemonError> {
        let value = self
            .transact_async("query_owner_bundle", serde_json::json!({}))
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = super::kind_value(&value, "owner_bundle_readback")
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let wire: OwnerBundleReadbackWire = serde_json::from_value(value)
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        match (wire.bound, wire.revision, wire.digest) {
            (false, None, None) => Ok(None),
            (true, Some(revision), Some(bundle_sha256)) => {
                AgentActivationKernelOwnerReadback::new(revision, bundle_sha256)
                    .map(Some)
                    .map_err(|error| super::DaemonError::Kernel(error.to_string()))
            }
            _ => Err(super::DaemonError::Kernel(
                "Kernel owner readback has an incoherent bound/revision/digest shape".to_owned(),
            )),
        }
    }

    #[cfg(windows)]
    pub async fn submit_agent_activation_result(
        &self,
        result: &AgentActivationResolutionResult,
        owner_readback: Option<AgentActivationOwnerReadback>,
    ) -> Result<AgentActivationResultAck, super::DaemonError> {
        if matches!(
            result.disposition,
            eliot_protocol::AgentActivationResolutionDisposition::Resolved { .. }
        ) && owner_readback
            .as_ref()
            .and_then(|readback| readback.kernel_owner.as_ref())
            .is_none()
        {
            return Err(super::DaemonError::Kernel(
                "Resolved activation submission requires the current Kernel owner readback"
                    .to_owned(),
            ));
        }
        let submit =
            AgentActivationResultSubmit::new_with_owner_readback(result.clone(), owner_readback)
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = self
            .transact_async(
                "agent_activation_submit",
                serde_json::json!({ "result": submit }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let response: ActivationSubmitResponse = serde_json::from_value(value)
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        if response.expired {
            return Err(super::DaemonError::ActivationExpired);
        }
        if !response.accepted {
            return Err(super::DaemonError::Kernel(
                "Kernel submit response was not accepted".to_owned(),
            ));
        }
        let ack = response.ack.ok_or_else(|| {
            super::DaemonError::Kernel("Kernel submit response omitted acknowledgement".to_owned())
        })?;
        ack.validate_against_result(result)
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        Ok(ack)
    }

    #[cfg(windows)]
    pub async fn reconcile_agent_activation_result(
        &self,
        query: &AgentActivationResultReconcile,
    ) -> Result<AgentActivationResultAck, super::DaemonError> {
        query
            .validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = self
            .transact_async(
                "agent_activation_reconcile",
                serde_json::json!({ "reconcile": query }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let response: ActivationReconcileResponse = serde_json::from_value(value)
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        response
            .ack
            .validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        if response.ack.replay_key() != (query.ticket_id.as_str(), query.result_sha256.as_str()) {
            return Err(super::DaemonError::Kernel(
                "Kernel reconcile response identity mismatch".to_owned(),
            ));
        }
        Ok(response.ack)
    }

    pub fn connect(config: &super::DaemonConfig) -> Result<Arc<Self>, super::DaemonError> {
        // #740: handshake span. Transport connect/session validation is not
        // semantic readiness; readiness is reported separately.
        let _span = tracing::info_span!("eliotd.kernel_handshake").entered();
        // #791 (W4/W17): one shutdown broadcast per client. The sending half
        // is retained so `request_shutdown` can publish; the receiving half is
        // cloned per exchange so a cancel-aware send observes the same signal.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let client = Self {
            launch: config.launch.clone(),
            connection_id: format!(
                "eliotd:{}:{}:{}:{}",
                config.launch.instance_id,
                config.launch.kernel.generation.value(),
                config.launch.kernel.authority_epoch.lineage_id.as_str(),
                config.launch.kernel.authority_epoch.sequence.get()
            ),
            snapshot: expected_snapshot(&config.launch)?,
            kernel_binding: config.kernel_binding.clone(),
            request_counter: Arc::new(AtomicU64::new(1)),
            validated_session_binding: Mutex::new(None),
            shutdown_tx,
            shutdown_rx,
        };
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
            let snapshot = runtime
                .block_on(client.snapshot_request_with_pre_admission_retry())
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
            let mut client = client;
            client.snapshot = snapshot;
            Ok(Arc::new(client))
        }
        #[cfg(not(windows))]
        {
            let _ = client;
            Err(super::DaemonError::Kernel(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    /// #791 (W4/W17): publishes the daemon's shutdown request so any pending
    /// front-door send observes it and settles as `UnknownOutcome` rather than
    /// holding the process open until its per-operation transport timeout.
    ///
    /// Broadcast, not a one-shot consume: every in-flight and future send reads
    /// the same request, so a cancellation racing an already-completed write is
    /// still never reported as a delivered frame. The production caller is the
    /// `ctrl_c` shutdown arm of `daemon_runtime::run_loop`.
    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// #791 (W4/W17): the per-exchange cancellation future handed to the
    /// cancel-aware front-door send.
    ///
    /// A fresh clone is taken per send so concurrent and subsequent exchanges
    /// all observe the same shutdown request, and a dropped sender — the client
    /// being released — is observed as cancellation by `changed()`. Completes
    /// only on a shutdown request; never a timeout stand-in and never a
    /// fabricated success.
    fn front_door_cancellation(&self) -> FrontDoorCancellation {
        // Two independent clones of the same broadcast: one is polled only to
        // observe a request published before this send started, the other is
        // owned by the pending-change future. Neither consumes the request, so
        // concurrent and subsequent sends each observe it.
        let observed = self.shutdown_rx.clone();
        let mut shutdown = self.shutdown_rx.clone();
        let changed = Box::pin(async move {
            let _ = shutdown.changed().await;
        });
        FrontDoorCancellation { observed, changed }
    }

    /// #791 (W4/W17): one cancel-aware front-door request send.
    ///
    /// Identical to the former `send_frame` call apart from the cancellation
    /// signal: the frame, the negotiated limits, the delivery assertion and
    /// every error mapping are unchanged, so a send that completes before any
    /// shutdown request is byte-identical to the old write. Only a send still
    /// pending when the daemon's shutdown is requested now settles as
    /// `UnknownOutcome` — the outcome the write may already have reached the
    /// peer, never a `Delivered` claim this client cannot prove.
    #[cfg(windows)]
    async fn send_frame_with_shutdown(
        &self,
        transport: &mut NamedPipeTransport,
        frame: &Frame,
        limits: TransportLimits,
    ) -> Result<DeliveryOutcome, KernelClientError> {
        transport
            .send_frame_with_cancel(frame, limits, self.front_door_cancellation())
            .await
            .map_err(|error| KernelClientError::Transport(error.to_string()))
    }

    /// #791 (W4/W17): receives one front-door response, abandoning the
    /// exchange on the same shutdown request the send observes.
    ///
    /// Without this leg a send could observe shutdown while the following
    /// receive still waited for the peer, so the cancellation would not
    /// actually end the exchange. The frame itself is unchanged; the abandoned
    /// exchange reports the daemon's existing unknown-outcome error, never a
    /// response and never a decoded claim.
    #[cfg(windows)]
    async fn receive_frame_or_shutdown(
        &self,
        transport: &mut NamedPipeTransport,
        limits: TransportLimits,
    ) -> Result<Frame, KernelClientError> {
        let mut shutdown = self.shutdown_rx.clone();
        if *shutdown.borrow() {
            return Err(KernelClientError::Unknown(
                SHUTDOWN_ABANDONED_EXCHANGE.to_owned(),
            ));
        }
        tokio::select! {
            result = transport.receive_frame(limits) => {
                result.map_err(|error| KernelClientError::Unknown(error.to_string()))
            }
            changed = shutdown.changed() => {
                // A dropped sender is the same observation: this client is
                // being released, so the exchange is abandoned rather than
                // left to block. A request racing a completed receive is
                // discarded, never reported as a Kernel response.
                let _ = changed;
                Err(KernelClientError::Unknown(
                    SHUTDOWN_ABANDONED_EXCHANGE.to_owned(),
                ))
            }
        }
    }

    /// Returns the already-validated Kernel-issued owner session facts for
    /// the single live owner session (AUD-C02-B, Implements #1187).
    ///
    /// Read-only over held fields: the retained `sid=..;session=..` binding
    /// string (set only on successful `validate_server_hello`, never a
    /// constant), the snapshot principal and artifact digests, the connection
    /// id, and the descriptor launch nonce. No re-handshake, no secret.
    /// `None` until a handshake in this process has validated a `ServerHello`,
    /// so daemon composition without a live session keeps the empty
    /// (unadmitted) controlboard behaviour.
    #[must_use]
    pub fn owner_session_facts(&self) -> Option<OwnerSessionFacts> {
        Some(OwnerSessionFacts {
            session_binding: self.validated_session_binding()?,
            kernel_principal: self.snapshot.principal.clone(),
            connection_id: self.connection_id.clone(),
            launch_nonce: self.kernel_binding.launch_nonce.clone(),
            artifact_digest: self.snapshot.artifact_digest.clone(),
            protected_snapshot_digest: self.snapshot.protected_snapshot_digest.clone(),
        })
    }

    /// Clones the retained validated binding string, if any. A poisoned slot
    /// reads as absent (fail-closed to "no live session"), never invented.
    fn validated_session_binding(&self) -> Option<String> {
        self.validated_session_binding
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Returns the live Kernel fence from the retained connection snapshot
    /// for startup evidence binding (I1.11 steps 8/9). Read-only over held
    /// fields via the snapshot owner's fence projection; never synthesized
    /// here.
    pub fn kernel_fence(&self) -> eliot_contracts::StateFence {
        self.snapshot.state_fence()
    }

    /// Mints the transport operation binding for one startup evidence
    /// publish. The identity is minted by the authenticated channel owner
    /// for this exact publish (same contour as `daemon_ready`) and
    /// correlated by [`Self::send_startup_evidence`]; the producer never
    /// mints identities.
    pub fn mint_startup_evidence_identity(&self) -> Result<RequestIdentity, super::DaemonError> {
        self.next_identity(super::startup_evidence_producer::DAEMON_STARTUP_EVIDENCE_OPERATION)
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))
    }

    /// Publishes one validated Governor startup evidence payload on the
    /// authenticated daemon channel for the Kernel step 8/9 consumer,
    /// correlated to the minted `identity`. The payload is validated before
    /// transport; Kernel rejection of the not-yet-served operation is
    /// fail-closed and expected until the consumer lands.
    pub fn send_startup_evidence(
        &self,
        evidence: &super::startup_evidence_producer::EliotdStartupEvidence,
        identity: RequestIdentity,
    ) -> Result<(), super::DaemonError> {
        evidence
            .validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let payload = serde_json::to_value(evidence)
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
            runtime
                .block_on(self.transact_async_with_identity(
                    super::startup_evidence_producer::DAEMON_STARTUP_EVIDENCE_OPERATION,
                    payload,
                    identity,
                ))
                .map(|_| ())
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))
        }
        #[cfg(not(windows))]
        {
            let _ = (payload, identity);
            Err(super::DaemonError::Kernel(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    pub fn report_ready(&self) -> Result<super::DaemonReadySupervision, super::DaemonError> {
        // #740: readiness span, distinct from the handshake span above.
        let _span = tracing::info_span!("eliotd.daemon_readiness").entered();
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
            let value = runtime
                .block_on(self.report_ready_with_pre_admission_retry())
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
            // Issue #88, wave 3: the Kernel answers `daemon_ready` with the
            // once-per-generation supervision bundle (authority lineage plus
            // the exact current lease head). The per-tick producer cites this
            // bundle verbatim; a missing bundle fails readiness closed.
            super::parse_daemon_ready_supervision(&value).map_err(super::DaemonError::Kernel)
        }
        #[cfg(not(windows))]
        {
            Err(super::DaemonError::Kernel(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    /// Submits one per-tick supervision-progress renewal request on the
    /// authenticated daemon channel (Implements #88, wave 3).
    ///
    /// The request carries only daemon-observed evidence plus the last
    /// Kernel-answered predecessor; the Kernel decides renewal and always
    /// answers with its exact durable head so the producer converges after
    /// renewals on any path. Typed refusals arrive as parsed answers, never
    /// as transport errors; only delivery/contract failures error here.
    #[cfg(windows)]
    pub async fn submit_supervision_progress(
        &self,
        request: &eliot_runtime_contracts::DaemonSupervisionRenewalRequest,
    ) -> Result<super::SupervisionProgressAnswer, super::DaemonError> {
        request
            .validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = self
            .transact_async(
                super::DAEMON_SUPERVISION_PROGRESS_OPERATION,
                super::progress_submit_payload(request),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        super::parse_progress_answer(&value).map_err(super::DaemonError::Kernel)
    }

    pub fn report_degraded(&self, reason: impl Into<String>) -> Result<(), super::DaemonError> {
        let reason = reason.into();
        // #740: owning error record at the degraded-report boundary.
        let _span = tracing::info_span!("eliotd.kernel_degraded").entered();
        if reason.trim().is_empty() || reason.chars().any(char::is_control) || reason.len() > 512 {
            return Err(super::DaemonError::Kernel(
                "daemon degradation reason is blank, unbounded, or contains control characters"
                    .to_owned(),
            ));
        }
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
            runtime
                .block_on(self.transact_async(
                    "daemon_degraded",
                    serde_json::json!({
                        "reason": reason,
                    }),
                ))
                .map(|_| ())
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))
        }
        #[cfg(not(windows))]
        {
            let _ = reason;
            Err(super::DaemonError::Kernel(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    pub fn report_fatal(&self, reason: impl Into<String>) -> Result<(), super::DaemonError> {
        let reason = reason.into();
        // #740: owning error record at the fatal-report boundary.
        let _span = tracing::info_span!("eliotd.kernel_fatal").entered();
        if reason.trim().is_empty() || reason.chars().any(char::is_control) || reason.len() > 512 {
            return Err(super::DaemonError::Kernel(
                "daemon fatal reason is blank, unbounded, or contains control characters"
                    .to_owned(),
            ));
        }
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
            runtime
                .block_on(
                    self.transact_async("daemon_fatal", serde_json::json!({ "reason": reason })),
                )
                .map(|_| ())
                .map_err(|error| super::DaemonError::Kernel(error.to_string()))
        }
        #[cfg(not(windows))]
        {
            let _ = reason;
            Err(super::DaemonError::Kernel(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    #[cfg(windows)]
    async fn snapshot_request_with_pre_admission_retry(
        &self,
    ) -> Result<KernelGenerationSnapshot, KernelClientError> {
        retry_pre_admission(
            KERNEL_OPERATION_TIMEOUT,
            || self.snapshot_request(),
            "exact launched process receipt was not published before the Kernel operation deadline",
        )
        .await
    }

    #[cfg(windows)]
    async fn report_ready_with_pre_admission_retry(
        &self,
    ) -> Result<serde_json::Value, KernelClientError> {
        retry_pre_admission(
            KERNEL_OPERATION_TIMEOUT,
            || {
                self.transact_async(
                    "daemon_ready",
                    serde_json::json!({
                        "generation": self.snapshot.generation.value(),
                        "authority_epoch": self.snapshot.authority_epoch.clone(),
                    }),
                )
            },
            "exact launched process receipt was not published before daemon ready deadline",
        )
        .await
    }

    #[cfg(windows)]
    pub(super) async fn transact_async(
        &self,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, KernelClientError> {
        let identity = self.next_identity(operation)?;
        self.transact_async_with_identity(operation, payload, identity)
            .await
    }

    #[cfg(windows)]
    pub(super) async fn transact_async_with_identity(
        &self,
        operation: &str,
        payload: serde_json::Value,
        identity: RequestIdentity,
    ) -> Result<serde_json::Value, KernelClientError> {
        let (mut transport, limits) = self.connect_transport().await?;
        let request_id = identity.request.metadata.request_id.clone();
        let frame = Frame {
            protocol_version: ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: self.connection_id.clone(),
            request_id: Some(request_id.clone()),
            kind: FrameKind::Request,
            message_type: MessageType::Execute,
            request_identity: Some(identity),
            payload: ProtocolPayload::Json(operation_payload(operation, payload)?),
            trace_context: BTreeMap::new(),
        };
        if self
            .send_frame_with_shutdown(&mut transport, &frame, limits)
            .await?
            != DeliveryOutcome::Delivered
        {
            return Err(KernelClientError::Unknown(
                "Kernel request delivery was not proven".to_owned(),
            ));
        }
        let response = self
            .receive_frame_or_shutdown(&mut transport, limits)
            .await?;
        response
            .validate()
            .map_err(|error| KernelClientError::Unknown(error.to_string()))?;
        if response.connection_id != self.connection_id
            || response.request_id.as_ref() != Some(&request_id)
            || response.kind != FrameKind::Response
            || response.message_type != MessageType::Result
            || response.request_identity.is_some()
        {
            return Err(KernelClientError::Unknown(
                "Kernel response correlation is invalid".to_owned(),
            ));
        }
        let ProtocolPayload::Json(value) = response.payload else {
            return Err(KernelClientError::Unknown(
                "Kernel response is not JSON".to_owned(),
            ));
        };
        match serde_json::from_value::<WireOutcome>(value)
            .map_err(|error| KernelClientError::Unknown(error.to_string()))?
        {
            WireOutcome::Known { value, recovery } => {
                let _ = recovery;
                Ok(value)
            }
            WireOutcome::Error { code, reason } => {
                Err(KernelClientError::Contract(format!("{code}: {reason}")))
            }
            WireOutcome::Partial { reason, value } => {
                let _ = value;
                Err(KernelClientError::Unknown(reason))
            }
            WireOutcome::Unknown { reason } => Err(KernelClientError::Unknown(reason)),
        }
    }

    #[cfg(not(windows))]
    pub(super) async fn transact_async(
        &self,
        _operation: &str,
        _payload: serde_json::Value,
    ) -> Result<serde_json::Value, KernelClientError> {
        Err(KernelClientError::Unsupported)
    }

    #[cfg(not(windows))]
    pub(super) async fn transact_async_with_identity(
        &self,
        _operation: &str,
        _payload: serde_json::Value,
        _identity: RequestIdentity,
    ) -> Result<serde_json::Value, KernelClientError> {
        Err(KernelClientError::Unsupported)
    }

    #[cfg(windows)]
    async fn connect_transport(
        &self,
    ) -> Result<(NamedPipeTransport, TransportLimits), KernelClientError> {
        let expectation = KernelFrontDoorServerExpectation::new(
            self.kernel_binding.expected_kernel_sid.as_str(),
            self.kernel_binding.expected_kernel_session_id,
            self.kernel_binding.kernel_artifact_sha256.as_str(),
            KernelFrontDoorAclMode::SystemAndLocalServiceWithOptionalUserClient,
        )
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        let mut transport = NamedPipeTransport::connect_authenticated_kernel_front_door(
            self.kernel_binding.kernel_pipe_name.as_str(),
            Duration::from_secs(5),
            &expectation,
        )
        .await
        .map_err(|error| KernelClientError::PreAdmissionTransport(error.to_string()))?;
        match transport.peer_identity() {
            eliot_ipc::PeerIdentity::Authenticated {
                process_id,
                user_identity,
                session_identity,
                ..
            } if *process_id != 0
                && user_identity == self.kernel_binding.expected_kernel_sid.as_str()
                && session_identity
                    == &self.kernel_binding.expected_kernel_session_id.to_string() => {}
            _ => {
                return Err(KernelClientError::Contract(
                    "Kernel pipe peer identity did not match the protected daemon declaration"
                        .to_owned(),
                ));
            }
        }
        let limits = TransportLimits::default();
        let hello = client_hello(&self.kernel_binding)?;
        let frame = eliot_ipc::client_hello_frame(&self.connection_id, &hello)
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        if self
            .send_frame_with_shutdown(&mut transport, &frame, limits)
            .await?
            != DeliveryOutcome::Delivered
        {
            return Err(KernelClientError::Unknown(
                "Kernel hello delivery was not proven".to_owned(),
            ));
        }
        let response = self
            .receive_frame_or_shutdown(&mut transport, limits)
            .await?;
        if is_pre_admission_pending_rejection(&response, &self.connection_id) {
            return Err(KernelClientError::PreAdmissionPending);
        }
        let server = eliot_ipc::decode_server_hello_frame(&response, &self.connection_id)
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        validate_server_hello(&self.launch, &self.kernel_binding, &server)?;
        // Retain the literal Kernel-issued binding string only now that it
        // validated: the owner session facts reader forwards these exact
        // bytes, never a locally minted session. A lock failure keeps the
        // previous value, so admission stays fail-closed, never invented.
        if let Ok(mut slot) = self.validated_session_binding.lock() {
            *slot = Some(server.session_principal_binding.clone());
        }
        Ok((transport, limits))
    }

    fn next_identity(&self, operation: &str) -> Result<RequestIdentity, KernelClientError> {
        let sequence = self.request_counter.fetch_add(1, Ordering::Relaxed);
        let request_id =
            RequestId::new(format!("{}:{}:{}", self.connection_id, operation, sequence))
                .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        let fence = self.snapshot.state_fence();
        let metadata = RequestMetadata {
            request_id: request_id.clone(),
            session_id: None,
            task_id: None,
            product_id: ProductId::new(SERVICE_NAME)
                .map_err(|error| KernelClientError::Contract(error.to_string()))?,
            source_id: SourceId::new(SERVICE_NAME)
                .map_err(|error| KernelClientError::Contract(error.to_string()))?,
            state_fence: fence.clone(),
            clock: ClockReading {
                valid_time_ms: Some(unix_ms_i64()),
                known_time_ms: Some(unix_ms_i64()),
                transaction_sequence: None,
                monotonic_ns: None,
            },
        };
        Ok(RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence,
            },
            idempotency_key: format!("{SERVICE_NAME}:{operation}:{sequence}"),
            deadline_unix_ms: unix_ms().saturating_add(30_000),
            cancellation_id: format!("{SERVICE_NAME}:{operation}:{sequence}:cancel"),
        })
    }

    fn blocking<T, F>(future: F) -> Result<T, KernelPortError>
    where
        T: Send + 'static,
        F: std::future::Future<Output = Result<T, KernelClientError>> + Send + 'static,
    {
        #[cfg(windows)]
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| KernelPortError::NotAdmitted(error.to_string()))?;
            runtime.block_on(future).map_err(kernel_port_error)
        }
        #[cfg(not(windows))]
        {
            let _ = future;
            Err(KernelPortError::NotAdmitted(
                KernelClientError::Unsupported.to_string(),
            ))
        }
    }

    pub(super) fn request_blocking(
        &self,
        operation: &'static str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, KernelPortError> {
        let client = self.clone_for_future();
        Self::blocking(async move { client.transact_async(operation, payload).await })
    }

    pub(super) fn request_blocking_with_identity(
        &self,
        operation: &'static str,
        payload: serde_json::Value,
        identity: RequestIdentity,
    ) -> Result<serde_json::Value, KernelPortError> {
        let client = self.clone_for_future();
        Self::blocking(async move {
            client
                .transact_async_with_identity(operation, payload, identity)
                .await
        })
    }

    /// Executes one closed named read through the authenticated Kernel route.
    ///
    /// Mirrors the `receipt` / `store_recovery` transport template: the
    /// request validates before any transport is touched, the call travels as
    /// the `"store_named"` operation with a fresh operation-bound identity,
    /// and the typed response is decoded through the closed
    /// `"store_named"` kind before exact validation. Kernel remains the route
    /// and fence authority; this method performs no consistency algorithm and
    /// no catalogue widening — callers enforce the operation/scope
    /// capability (T11.1 activates `GetEvidencePack` only at the
    /// `CanonicalReadClient` boundary).
    ///
    /// Errors: `Contract` when the request is malformed, the admitted fence
    /// does not bind the request, the Kernel kind is unexpected, the payload
    /// does not decode, the response does not validate, or the response
    /// substitutes the operation or fence; `NotAdmitted` / `Unknown` for
    /// transport outcomes via [`kernel_port_error`].
    pub(super) async fn store_named_async(
        &self,
        request: NamedReadRequest,
    ) -> Result<NamedReadResponse, KernelPortError> {
        request
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if self.snapshot.state_fence() != request.state_fence {
            return Err(KernelPortError::Contract(
                "daemon named read fence does not match the admitted snapshot".to_owned(),
            ));
        }
        let value = self
            .transact_async(
                "store_named",
                serde_json::json!({
                    "request": request,
                }),
            )
            .await
            .map_err(kernel_port_error)?;
        let value = super::kind_value(&value, "store_named")?;
        let response: NamedReadResponse = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        response
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if response.operation != request.operation || response.state_fence != request.state_fence {
            return Err(KernelPortError::Contract(
                "daemon named read response does not match the requested operation and active state fence"
                    .to_owned(),
            ));
        }
        Ok(response)
    }

    /// Claims one queued admitted `eliot.query` pair for the outbound-only
    /// local-read poller (Implements #18).
    ///
    /// Mirrors
    /// [`claim_agent_activation_ticket`](Self::claim_agent_activation_ticket):
    /// the call travels as the single-`operation`-key `"local_read_claim"`
    /// payload and a null `pair` is the empty-queue backoff signal, not an
    /// error. The claimed pair carries the Kernel-minted fenced attempt
    /// capability, which the caller must present back on the read leg and the
    /// submit leg. The claimed pair still proves its closed linkage and fence
    /// binding inside
    /// [`forward_admitted_local_read`](super::forward_admitted_local_read)
    /// before any read or submit touches it.
    #[cfg(windows)]
    pub async fn claim_local_read_pair_async(
        &self,
    ) -> Result<
        Option<(HostRequestEnvelope, serde_json::Value, LocalReadAttempt)>,
        super::DaemonError,
    > {
        let value = self
            .transact_async(
                "local_read_claim",
                serde_json::json!({ "operation": "local_read_claim" }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let pair = parse_local_read_claimed_pair(&value).map_err(super::DaemonError::Kernel)?;
        if pair.as_ref().is_some_and(|(envelope, tool, _)| {
            envelope.identity.capability != "eliot.query"
                || tool.get("name").and_then(serde_json::Value::as_str) != Some("eliot.query")
        }) {
            return Err(super::DaemonError::Kernel(
                "Kernel local_read_claim returned a non-query pair".to_owned(),
            ));
        }
        Ok(pair)
    }

    /// Claims one queued admitted `eliot.packet` pair from the dedicated
    /// campaign-packet queue. The query poller cannot consume this claim.
    #[cfg(windows)]
    pub async fn claim_campaign_packet_pair_async(
        &self,
    ) -> Result<
        Option<(HostRequestEnvelope, serde_json::Value, LocalReadAttempt)>,
        super::DaemonError,
    > {
        let value = self
            .transact_async(
                "campaign_packet_claim",
                serde_json::json!({ "operation": "campaign_packet_claim" }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let pair = parse_local_read_claimed_pair(&value).map_err(super::DaemonError::Kernel)?;
        if pair.as_ref().is_some_and(|(envelope, tool, _)| {
            envelope.identity.capability != "eliot.packet"
                || tool.get("name").and_then(serde_json::Value::as_str) != Some("eliot.packet")
        }) {
            return Err(super::DaemonError::Kernel(
                "Kernel campaign_packet_claim returned a non-packet pair".to_owned(),
            ));
        }
        Ok(pair)
    }

    /// Claims one queued admitted Task Controller invocation and its distinct
    /// Kernel-issued attempt capability.
    #[cfg(windows)]
    pub async fn claim_task_controller_pair_async(
        &self,
    ) -> Result<Option<TaskControllerClaimedInvocation>, super::DaemonError> {
        let value = self
            .transact_async(
                "task_controller_claim",
                serde_json::json!({ "operation": "task_controller_claim" }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_task_controller_claimed_pair(&value).map_err(super::DaemonError::Kernel)
    }

    /// Submits one daemon-produced local-read result body for its waiting
    /// host request (Implements #18).
    ///
    /// The body travels as the single-`result`-key `"local_read_result"`
    /// payload and is validated before any transport is touched. Kernel
    /// persists through the ORS result path: an exact replay stays idempotent
    /// (even across deadline expiry); an elapsed absolute deadline is the
    /// expected race and projects as
    /// [`LocalReadSubmitOutcome::Expired`], never as a transport error.
    #[cfg(windows)]
    pub async fn submit_local_read_result_async(
        &self,
        body: &HostRequestResultBody,
    ) -> Result<LocalReadSubmitOutcome, super::DaemonError> {
        body.validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = self
            .transact_async("local_read_result", serde_json::json!({ "result": body }))
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_local_read_submit_outcome(&value).map_err(super::DaemonError::Kernel)
    }

    /// Claims one queued admitted `eliot.observe` pair for the outbound-only
    /// observe poller (issue #2565).
    ///
    /// Mirrors [`claim_local_read_pair_async`](Self::claim_local_read_pair_async):
    /// the call travels as the single-`operation`-key
    /// `"semantic_observe_claim"` payload and a null `pair` is the
    /// empty-queue backoff signal, not an error. The claimed pair carries the
    /// Kernel-minted fenced attempt capability, which the caller must present
    /// back on the submit and defer legs. The claimed pair still proves its
    /// closed linkage and fence binding inside the observe flight before any
    /// submit or defer touches it.
    #[cfg(windows)]
    pub async fn claim_observe_pair_async(
        &self,
    ) -> Result<
        Option<(HostRequestEnvelope, serde_json::Value, LocalReadAttempt)>,
        super::DaemonError,
    > {
        let value = self
            .transact_async(
                "semantic_observe_claim",
                serde_json::json!({ "operation": "semantic_observe_claim" }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_observe_claimed_pair(&value).map_err(super::DaemonError::Kernel)
    }

    /// Submits one daemon-produced observe result body for its waiting host
    /// request (issue #2565).
    ///
    /// The body travels as the single-`result`-key
    /// `"semantic_observe_result"` payload and is validated before any
    /// transport is touched. Kernel persists through the ORS result path: an
    /// exact replay stays idempotent (even across deadline expiry); an
    /// elapsed absolute deadline is the expected race and projects as
    /// [`ObserveSubmitOutcome::Expired`], never as a transport error.
    #[cfg(windows)]
    pub async fn submit_observe_result_async(
        &self,
        body: &HostRequestResultBody,
    ) -> Result<ObserveSubmitOutcome, super::DaemonError> {
        body.validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = self
            .transact_async(
                "semantic_observe_result",
                serde_json::json!({ "result": body }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_observe_submit_outcome(&value).map_err(super::DaemonError::Kernel)
    }

    /// Defers one claimed observe pair the daemon flight cannot execute yet
    /// (issue #2565).
    ///
    /// The presenting attempt must be the live Kernel-minted triple the claim
    /// returned. Kernel retires the queue pair and advances the durable
    /// record `Admitted -> Routed`, so the pending handle stays live with its
    /// exact resume condition while no queue entry spins. No effect is
    /// produced and none is claimed by this leg.
    #[cfg(windows)]
    pub async fn defer_observe_claim_async(
        &self,
        operation_id: &str,
        request_digest: &str,
        attempt: &LocalReadAttempt,
    ) -> Result<ObserveDeferOutcome, super::DaemonError> {
        attempt
            .validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = self
            .transact_async(
                "semantic_observe_deferred",
                serde_json::json!({
                    "operation_id": operation_id,
                    "request_digest": request_digest,
                    "attempt": attempt,
                }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_observe_defer_outcome(&value).map_err(super::DaemonError::Kernel)
    }

    /// Submits one result for the exact admitted Task Controller attempt.
    /// Submits a compiled campaign-packet result through its dedicated queue
    /// route. The query result operation cannot consume this body.
    #[cfg(windows)]
    pub async fn submit_campaign_packet_result_async(
        &self,
        body: &HostRequestResultBody,
    ) -> Result<LocalReadSubmitOutcome, super::DaemonError> {
        body.validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = self
            .transact_async(
                "campaign_packet_result",
                serde_json::json!({ "result": body }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_local_read_submit_outcome(&value).map_err(super::DaemonError::Kernel)
    }

    #[cfg(windows)]
    pub async fn submit_task_controller_result_async(
        &self,
        body: &TaskControllerResultBody,
    ) -> Result<TaskControllerSubmitOutcome, super::DaemonError> {
        body.validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = self
            .transact_async(
                "task_controller_result",
                serde_json::json!({ "result": body }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_task_controller_submit_outcome(&value).map_err(super::DaemonError::Kernel)
    }

    /// Executes one closed local read through the authenticated Kernel route.
    ///
    /// Twin of [`store_named_async`](Self::store_named_async): the admitted
    /// envelope+tool pair proves its closed linkage before any transport is
    /// touched, the call travels as the `"local_read"` operation with a fresh
    /// operation-bound identity plus the Kernel-issued attempt capability, and
    /// the persisted result body behind the admitted receipt+record is rebuilt
    /// through its closed body contract with exact envelope binding before
    /// return. The returned body carries the presented attempt verbatim, so
    /// the poller's submit completes under the same fencing generation the
    /// read ran under. Kernel remains the
    /// admission, read, and persistence authority; this method performs no
    /// admission decision and no consistency algorithm.
    ///
    /// Wire note: the `local_read` leg answers the documented admission
    /// shape (`accepted` plus receipt plus record); the `{kind: local_read}`
    /// wrapper exists only on the error envelope, which never decodes past
    /// the frame outcome (surfacing as `Unknown`, never as a body).
    ///
    /// Errors: `Contract` when the pair is malformed or unlinked, the attempt
    /// does not bind the envelope, the admitted fence does not bind the
    /// envelope, the admitted answer does not bind this envelope, or the
    /// persisted body is absent (a packet admission carries no result body by
    /// design) or fails its own digest binding; `NotAdmitted` / `Unknown` for
    /// transport outcomes via [`kernel_port_error`].
    ///
    /// Production caller:
    /// [`forward_admitted_local_read`](super::forward_admitted_local_read),
    /// driven per claimed pair by the daemon runtime poller.
    pub(crate) async fn local_read_async(
        &self,
        envelope: HostRequestEnvelope,
        tool: serde_json::Value,
        attempt: LocalReadAttempt,
    ) -> Result<HostRequestResultBody, KernelPortError> {
        let pair = HostRequestInvokeReadPayload {
            wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
            wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
            envelope,
            tool,
        };
        pair.validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if pair.envelope.identity.capability != "eliot.query" {
            return Err(KernelPortError::Contract(
                "campaign packets cannot use the query-only local_read leg".to_owned(),
            ));
        }
        attempt
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if attempt.operation_id != host_request_operation_id(&pair.envelope) {
            return Err(KernelPortError::Contract(
                "daemon local read attempt does not bind the admitted envelope".to_owned(),
            ));
        }
        if self.snapshot.state_fence() != pair.envelope.state_fence {
            return Err(KernelPortError::Contract(
                "daemon local read fence does not match the admitted snapshot".to_owned(),
            ));
        }
        let value = self
            .transact_async(
                "local_read",
                serde_json::json!({
                    "envelope": pair.envelope,
                    "tool": pair.tool,
                    "attempt": attempt,
                }),
            )
            .await
            .map_err(kernel_port_error)?;
        let admitted = value.as_object().ok_or_else(|| {
            KernelPortError::Contract("Kernel local read answer is not an object".to_owned())
        })?;
        if admitted.get("accepted") != Some(&serde_json::Value::Bool(true)) {
            return Err(KernelPortError::Contract(
                "Kernel local read answer is not an admission".to_owned(),
            ));
        }
        let operation_id = admitted
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                KernelPortError::Contract(
                    "Kernel local read admission omits the operation handle".to_owned(),
                )
            })?;
        if operation_id != host_request_operation_id(&pair.envelope) {
            return Err(KernelPortError::Contract(
                "Kernel local read admission does not bind the admitted envelope".to_owned(),
            ));
        }
        let body_digest = admitted
            .get("record")
            .and_then(|record| record.get("result_digest"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                KernelPortError::Contract(
                    "Kernel local read admission carries no result digest; the campaign packet poller must submit its compiled result"
                        .to_owned(),
                )
            })?;
        let body_response = admitted
            .get("record")
            .and_then(|record| record.get("result_response"))
            .cloned()
            .ok_or_else(|| {
                KernelPortError::Contract(
                    "Kernel local read admission carries no result body; the campaign packet poller must submit its compiled result"
                        .to_owned(),
                )
            })?;
        // Rebuilt, never decoded: the ORS record carries the digest-bound
        // response halves, while the operation handle, envelope binding, and
        // attempt capability are proven here from the admitted answer. The
        // body carries the presented attempt verbatim so submit completes
        // under the generation the read ran under.
        let body = HostRequestResultBody {
            wire_id: eliot_protocol::HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
            wire_version: HostRequestResultBody::CONTRACT_VERSION,
            operation_id: operation_id.to_owned(),
            request_sha256: pair.envelope.envelope_sha256.clone(),
            result_digest: body_digest.to_owned(),
            response: body_response,
            attempt: Some(attempt),
        };
        body.validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if body.request_sha256 != pair.envelope.envelope_sha256
            || body.operation_id != host_request_operation_id(&pair.envelope)
        {
            return Err(KernelPortError::Contract(
                "Kernel local read result does not bind the admitted envelope".to_owned(),
            ));
        }
        Ok(body)
    }

    fn clone_for_future(&self) -> Arc<Self> {
        Arc::new(Self {
            launch: self.launch.clone(),
            kernel_binding: self.kernel_binding.clone(),
            connection_id: self.connection_id.clone(),
            snapshot: self.snapshot.clone(),
            request_counter: Arc::clone(&self.request_counter),
            validated_session_binding: Mutex::new(self.validated_session_binding()),
            // #791 (W4/W17): the clone shares the same shutdown broadcast, so
            // a request published on the owning client is observed by a
            // transport this clone drives, exactly as on the original.
            shutdown_tx: self.shutdown_tx.clone(),
            shutdown_rx: self.shutdown_rx.clone(),
        })
    }
}

/// Authenticated `TestD` owner operation names served by the Kernel owner
/// (`bins/eliot-kernel/src/testd_terminal_completion_route.rs`). The daemon
/// mirrors the exact wire strings; the Kernel remains the route and fence
/// authority and validates every payload shape, version, and digest.
pub(super) const TESTD_OWNER_PENDING_DISPATCHES_OPERATION: &str =
    "eliot.kernel.testd-owner-pending-dispatches";
pub(super) const TESTD_OWNER_BIND_DISPATCH_OPERATION: &str =
    "eliot.kernel.testd-owner-bind-dispatch";
pub(super) const TESTD_OWNER_PENDING_TERMINALS_OPERATION: &str =
    "eliot.kernel.testd-owner-pending-terminals";
pub(super) const TESTD_OWNER_ACK_TERMINAL_OPERATION: &str = "eliot.kernel.testd-owner-ack-terminal";
pub(super) const TESTD_OWNER_WIRE_VERSION: u16 = 1;
/// Bound for one owner poll. Matches the Kernel owner limit exactly; a wider
/// poll is refused before any transport is touched.
pub(super) const TESTD_OWNER_POLL_LIMIT: u16 = 8;

/// Daemon mirror of the Kernel pending-dispatch poll request. The Kernel
/// owns validation; this mirror only constructs well-formed wire bytes.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestdOwnerPendingDispatchesRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub limit: u16,
}

/// Daemon mirror of the Kernel pending-terminal poll request.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestdOwnerPendingTerminalsRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub limit: u16,
}

/// Daemon mirror of the Kernel bind-dispatch request. The digest binds the
/// wire, job, and canonical binding bytes exactly as the Kernel recomputes.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestdOwnerBindDispatchRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub job_id: String,
    pub binding: TestdVerifierDispatchBinding,
    pub request_digest: String,
}

/// Daemon mirror of the Kernel ack-terminal request. The digest binds the
/// wire, job, and canonical receipt bytes exactly as the Kernel recomputes.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestdOwnerAckTerminalRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub job_id: String,
    pub receipt: WriteReceipt,
    pub request_digest: String,
}

/// Daemon mirror of the Kernel pending-dispatch poll response.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestdOwnerPendingDispatchesResponse {
    pub pending: Vec<TestdPendingVerifierDispatch>,
}

/// Daemon mirror of the Kernel bind-dispatch response.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestdOwnerBindDispatchResponse {
    pub job_id: String,
    pub binding_sha256: String,
}

/// Daemon mirror of the Kernel pending-terminal poll response.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestdOwnerPendingTerminalsResponse {
    pub evidence: Vec<TestdTerminalCompletionEvidence>,
}

/// Daemon mirror of the Kernel ack-terminal response.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestdOwnerAckTerminalResponse {
    pub job_id: String,
    pub receipt: WriteReceipt,
}

fn testd_owner_limit(limit: u16) -> Result<u16, KernelPortError> {
    if limit == 0 || limit > 64 {
        return Err(KernelPortError::Contract(
            "TestD owner poll limit must be between one and 64".to_owned(),
        ));
    }
    Ok(limit)
}

fn testd_owner_job_id(job_id: &str) -> Result<(), KernelPortError> {
    if job_id.trim().is_empty() || job_id.chars().any(char::is_control) {
        return Err(KernelPortError::Contract(
            "TestD owner job id must be non-blank and control-free".to_owned(),
        ));
    }
    Ok(())
}

fn testd_owner_binding_sha256(
    binding: &TestdVerifierDispatchBinding,
) -> Result<String, KernelPortError> {
    let bytes = canonical_json_bytes(binding)
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn testd_owner_receipt_sha256(receipt: &WriteReceipt) -> Result<String, KernelPortError> {
    let bytes = canonical_json_bytes(receipt)
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn testd_owner_bind_request_digest(
    job_id: &str,
    binding_sha256: &str,
) -> Result<String, KernelPortError> {
    #[derive(Serialize)]
    struct Canonical<'a> {
        wire_id: &'a str,
        wire_version: u16,
        job_id: &'a str,
        binding_sha256: &'a str,
    }
    let bytes = canonical_json_bytes(&Canonical {
        wire_id: TESTD_OWNER_BIND_DISPATCH_OPERATION,
        wire_version: TESTD_OWNER_WIRE_VERSION,
        job_id,
        binding_sha256,
    })
    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn testd_owner_ack_request_digest(
    job_id: &str,
    receipt_sha256: &str,
) -> Result<String, KernelPortError> {
    #[derive(Serialize)]
    struct Canonical<'a> {
        wire_id: &'a str,
        wire_version: u16,
        job_id: &'a str,
        receipt_sha256: &'a str,
    }
    let bytes = canonical_json_bytes(&Canonical {
        wire_id: TESTD_OWNER_ACK_TERMINAL_OPERATION,
        wire_version: TESTD_OWNER_WIRE_VERSION,
        job_id,
        receipt_sha256,
    })
    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

impl DaemonKernelClient {
    /// Polls the Kernel-owned pending verifier dispatches. The response
    /// carries the full durable job plus the exact admitted frame identity;
    /// the daemon computes the canonical plan binding from its Governor
    /// read and persists it through the bind leg below.
    ///
    /// Kernel remains the route and fence authority; this method performs
    /// no admission decision and never opens the `TestD` database.
    pub(super) async fn query_testd_pending_dispatches_async(
        &self,
        limit: u16,
    ) -> Result<Vec<TestdPendingVerifierDispatch>, KernelPortError> {
        let limit = testd_owner_limit(limit)?;
        let request = TestdOwnerPendingDispatchesRequest {
            wire_id: TESTD_OWNER_PENDING_DISPATCHES_OPERATION.to_owned(),
            wire_version: TESTD_OWNER_WIRE_VERSION,
            limit,
        };
        let value = self
            .transact_async(
                TESTD_OWNER_PENDING_DISPATCHES_OPERATION,
                serde_json::json!({ "request": request }),
            )
            .await
            .map_err(kernel_port_error)?;
        let value = super::kind_value(&value, "testd_owner_pending_dispatches")?;
        let response: TestdOwnerPendingDispatchesResponse = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        Ok(response.pending)
    }

    /// Persists one daemon-computed verifier-dispatch binding through the
    /// Kernel owner. The binding must reuse the exact admitted identity the
    /// Kernel retained at job admission; anything else fails closed
    /// owner-side as a binding conflict.
    pub(super) async fn acknowledge_testd_verifier_dispatch_async(
        &self,
        job_id: &str,
        binding: TestdVerifierDispatchBinding,
    ) -> Result<String, KernelPortError> {
        testd_owner_job_id(job_id)?;
        let binding_sha256 = testd_owner_binding_sha256(&binding)?;
        let request_digest = testd_owner_bind_request_digest(job_id, &binding_sha256)?;
        let request = TestdOwnerBindDispatchRequest {
            wire_id: TESTD_OWNER_BIND_DISPATCH_OPERATION.to_owned(),
            wire_version: TESTD_OWNER_WIRE_VERSION,
            job_id: job_id.to_owned(),
            binding,
            request_digest,
        };
        let value = self
            .transact_async(
                TESTD_OWNER_BIND_DISPATCH_OPERATION,
                serde_json::json!({ "request": request }),
            )
            .await
            .map_err(kernel_port_error)?;
        let value = super::kind_value(&value, "testd_owner_bind_dispatch")?;
        let response: TestdOwnerBindDispatchResponse = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if response.job_id != job_id || response.binding_sha256 != binding_sha256 {
            return Err(KernelPortError::Contract(
                "Kernel bind-dispatch response does not bind the requested job and binding"
                    .to_owned(),
            ));
        }
        Ok(response.binding_sha256)
    }

    /// Polls the Kernel-owned pending terminal evidence. Each entry is a
    /// complete identity-joined productive terminal row still missing its
    /// canonical `WriteReceipt`; worker exit alone never qualifies.
    pub(super) async fn query_testd_terminal_evidence_async(
        &self,
        limit: u16,
    ) -> Result<Vec<TestdTerminalCompletionEvidence>, KernelPortError> {
        let limit = testd_owner_limit(limit)?;
        let request = TestdOwnerPendingTerminalsRequest {
            wire_id: TESTD_OWNER_PENDING_TERMINALS_OPERATION.to_owned(),
            wire_version: TESTD_OWNER_WIRE_VERSION,
            limit,
        };
        let value = self
            .transact_async(
                TESTD_OWNER_PENDING_TERMINALS_OPERATION,
                serde_json::json!({ "request": request }),
            )
            .await
            .map_err(kernel_port_error)?;
        let value = super::kind_value(&value, "testd_owner_pending_terminals")?;
        let response: TestdOwnerPendingTerminalsResponse = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        Ok(response.evidence)
    }

    /// Records one committed canonical `WriteReceipt` through the Kernel
    /// owner. The receipt must be the exact canonical bytes advertised by
    /// the terminal publication; anything else fails closed owner-side.
    pub(super) async fn acknowledge_testd_terminal_completion_async(
        &self,
        job_id: &str,
        receipt: WriteReceipt,
    ) -> Result<WriteReceipt, KernelPortError> {
        testd_owner_job_id(job_id)?;
        receipt
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        let receipt_sha256 = testd_owner_receipt_sha256(&receipt)?;
        let request_digest = testd_owner_ack_request_digest(job_id, &receipt_sha256)?;
        let request = TestdOwnerAckTerminalRequest {
            wire_id: TESTD_OWNER_ACK_TERMINAL_OPERATION.to_owned(),
            wire_version: TESTD_OWNER_WIRE_VERSION,
            job_id: job_id.to_owned(),
            receipt,
            request_digest,
        };
        let value = self
            .transact_async(
                TESTD_OWNER_ACK_TERMINAL_OPERATION,
                serde_json::json!({ "request": request }),
            )
            .await
            .map_err(kernel_port_error)?;
        let value = super::kind_value(&value, "testd_owner_ack_terminal")?;
        let response: TestdOwnerAckTerminalResponse = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if response.job_id != job_id {
            return Err(KernelPortError::Contract(
                "Kernel ack-terminal response does not bind the requested job".to_owned(),
            ));
        }
        Ok(response.receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_governor::{
        GovernorLaunchConfig, KernelGenerationExpectation, KernelGenerationSnapshot,
        KernelPortError,
    };
    use eliot_protocol::{
        HOST_REQUEST_WIRE_ID, HostRequestEnvelope, HostRequestIdentity, HostRequestKind,
    };
    use eliot_read::{
        ProvenanceDisposition, ReadError, ReadProvenance, ReadService, StoreReadFailure,
    };
    use eliot_store_api::{
        CanonicalReadClient, EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, RevisionHead,
        RevisionKey, StoreError,
    };
    use serde_json::{Value, json};

    use crate::KernelLaunchBinding;
    use crate::forward_admitted_local_read;
    use crate::kernel_context_read_client::KernelContextReadClient;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> Result<EpochId, Box<dyn std::error::Error>> {
        let lineage =
            EpochLineageId::new(TEST_LINEAGE).map_err(|error| format!("lineage: {error}"))?;
        let sequence = NonZeroU64::new(sequence).ok_or("non-zero test sequence")?;
        EpochId::new(lineage, sequence).map_err(|error| format!("epoch: {error}").into())
    }

    fn test_fence(generation: u64) -> Result<StateFence, Box<dyn std::error::Error>> {
        Ok(StateFence::new(
            test_epoch(1)?,
            ResourceGeneration::new(generation).map_err(|error| format!("generation: {error}"))?,
        ))
    }

    fn tool_digest(tool: &Value) -> Result<String, Box<dyn std::error::Error>> {
        let bytes = eliot_contracts::canonical_json_bytes(tool)
            .map_err(|error| format!("canonical tool bytes: {error}"))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    fn query_tool() -> Value {
        json!({"name":"eliot.query","arguments":{
            "intent":{
                "mode":"verification",
                "time_scope":"session-window",
                "branch_environment_scope":"branch",
                "freshness_policy":"exact-fence",
                "required_assurance":"evidence-provenance"
            },
            "query":"subject:evidence-alpha",
            "exact_resource_uri": null
        }})
    }

    fn packet_tool() -> Value {
        json!({"name":"eliot.packet","arguments":{
            "packet_ref": null,
            "material_refs": []
        }})
    }

    fn test_envelope(
        capability: &str,
        fence: &StateFence,
        payload_sha256: &str,
    ) -> Result<HostRequestEnvelope, Box<dyn std::error::Error>> {
        HostRequestEnvelope {
            wire_id: HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: HostRequestEnvelope::CONTRACT_VERSION,
            kind: HostRequestKind::Invocation,
            connection_id: "conn-test-1".to_owned(),
            identity: HostRequestIdentity {
                request_id: eliot_contracts::RequestId::new("host-request-1")
                    .map_err(|error| format!("request id: {error}"))?,
                idempotency_key: "host-request-1:invoke".to_owned(),
                cancellation_id: "host-request-1:invoke:cancel".to_owned(),
                parent_operation_id: None,
                deadline_unix_ms: 2_000_000,
                capability: capability.to_owned(),
                session_id: Some("kernel-session-1".to_owned()),
                task_id: None,
                work_scope_id: None,
                payload_schema_id: "eliot.mcp.tool-request.v1".to_owned(),
                payload_sha256: payload_sha256.to_owned(),
            },
            state_fence: fence.clone(),
            descriptor_sha256: "d".repeat(64),
            peer_admission_receipt_sha256: "e".repeat(64),
            activation_binding: None,
            envelope_sha256: String::new(),
        }
        .with_computed_digest()
        .map_err(|error| format!("envelope digest: {error}").into())
    }

    fn test_attempt(
        envelope: &HostRequestEnvelope,
        generation: u64,
    ) -> Result<LocalReadAttempt, Box<dyn std::error::Error>> {
        let operation_id = host_request_operation_id(envelope);
        let attempt = LocalReadAttempt {
            wire_id: eliot_protocol::LOCAL_READ_ATTEMPT_WIRE_ID.to_owned(),
            wire_version: LocalReadAttempt::CONTRACT_VERSION,
            operation_id: operation_id.clone(),
            attempt_id: format!("{operation_id}:attempt:test-boot:7:{generation}"),
            fencing_generation: generation,
            session_id: "kernel-session-1".to_owned(),
            authority_epoch: envelope.state_fence.authority_epoch.clone(),
            scope_id: "kernel-session-1".to_owned(),
            facet_method: "eliot.query".to_owned(),
            expires_at_unix_ms: envelope.identity.deadline_unix_ms,
            use_budget: 1,
        };
        attempt
            .validate()
            .map_err(|error| format!("attempt must validate: {error}"))?;
        Ok(attempt)
    }

    fn test_client(fence: &StateFence) -> Result<DaemonKernelClient, Box<dyn std::error::Error>> {
        let epoch = test_epoch(1)?;
        let generation =
            ResourceGeneration::new(1).map_err(|error| format!("generation: {error}"))?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        Ok(DaemonKernelClient {
            launch: GovernorLaunchConfig {
                instance_id: "test-eliotd".to_owned(),
                kernel: KernelGenerationExpectation {
                    service: "eliot-kernel".to_owned(),
                    protocol: "test".to_owned(),
                    artifact_digest: "a".repeat(64),
                    protected_snapshot_digest: "b".repeat(64),
                    principal: "test-principal".to_owned(),
                    generation,
                    authority_epoch: epoch.clone(),
                },
                protected_snapshot_digest: "b".repeat(64),
            },
            kernel_binding: KernelLaunchBinding {
                kernel_pipe_name: r"\\.\pipe\eliot\test".to_owned(),
                expected_kernel_sid: "S-1-5-18".to_owned(),
                expected_kernel_session_id: 0,
                module_generation: generation,
                authority_epoch: epoch.clone(),
                state_fence: fence.clone(),
                launch_nonce: "test-nonce".to_owned(),
                kernel_artifact_sha256: "a".repeat(64),
                daemon_artifact_sha256: "c".repeat(64),
            },
            connection_id: "test-connection".to_owned(),
            snapshot: KernelGenerationSnapshot {
                service: "eliot-kernel".to_owned(),
                protocol: "test".to_owned(),
                generation,
                authority_epoch: epoch,
                artifact_digest: "a".repeat(64),
                protected_snapshot_digest: "b".repeat(64),
                principal: "test-principal".to_owned(),
            },
            request_counter: Arc::new(AtomicU64::new(1)),
            validated_session_binding: Mutex::new(None),
            shutdown_tx: shutdown_tx.clone(),
            shutdown_rx: shutdown_rx.clone(),
        })
    }

    /// Minimal in-test evidence table. It stores captured subjects in capture
    /// order and derives every response field from the incoming request: real
    /// request validation, the closed evidence operation, exact fence
    /// equality, the declared `subject` / `max_records` selectors, and the
    /// catalogue bound. Nothing is canned.
    struct EvidenceTable {
        fence: StateFence,
        captured: Vec<String>,
    }

    impl EvidenceTable {
        fn new(fence: StateFence) -> Self {
            Self {
                fence,
                captured: Vec::new(),
            }
        }

        fn capture(&mut self, subject: &str) {
            self.captured.push(subject.to_owned());
        }

        fn selectors(parameters: &BTreeMap<String, Value>) -> Result<(String, u32), StoreError> {
            let subject = parameters
                .get("subject")
                .and_then(Value::as_str)
                .filter(|subject| !subject.trim().is_empty())
                .ok_or(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "evidence subject must be exact",
                })?;
            let bound = parameters
                .get("max_records")
                .and_then(Value::as_str)
                .ok_or(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "max_records must ride as an exact decimal string",
                })?;
            let bound: u32 = bound.parse().map_err(|_| StoreError::InvalidField {
                field: "operation.parameter",
                reason: "max_records must ride as an exact decimal string",
            })?;
            if bound == 0 || bound > EVIDENCE_PACK_MAX_RECORDS {
                return Err(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "max_records must be within the catalogue bound",
                });
            }
            Ok((subject.to_owned(), bound))
        }
    }

    #[allow(async_fn_in_trait)]
    impl CanonicalReadClient for EvidenceTable {
        async fn revision_heads(
            &self,
            _keys: Vec<RevisionKey>,
        ) -> Result<Vec<RevisionHead>, StoreError> {
            Ok(Vec::new())
        }

        async fn execute_named(
            &self,
            query: NamedReadRequest,
        ) -> Result<NamedReadResponse, StoreError> {
            query.validate()?;
            if query.operation != NamedReadOperation::GetEvidencePack {
                return Err(StoreError::UnknownOperation);
            }
            if query.scope_id.is_none() {
                return Err(StoreError::InvalidField {
                    field: "scope_id",
                    reason: "GetEvidencePack requires an exact scope",
                });
            }
            if query.state_fence != self.fence {
                return Err(StoreError::FenceMismatch);
            }
            let (subject, bound) = Self::selectors(&query.parameters)?;
            let limit = usize::try_from(bound).map_err(|_| StoreError::InvalidField {
                field: "operation.parameter",
                reason: "max_records must be within the catalogue bound",
            })?;
            let records: Vec<Value> = self
                .captured
                .iter()
                .filter(|captured| *captured == &subject)
                .take(limit)
                .map(|captured| json!({"subject": captured}))
                .collect();
            let response = NamedReadResponse {
                operation: query.operation,
                state_fence: query.state_fence.clone(),
                revision_heads: Vec::new(),
                payload: json!({
                    "version": 1,
                    "subject": subject,
                    "max_records": bound,
                    "records": records,
                }),
            };
            response.validate()?;
            Ok(response)
        }
    }

    #[test]
    fn local_read_bridge_serves_captured_evidence_and_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fence = test_fence(1)?;
        let client = test_client(&fence)?;
        assert_eq!(
            client.snapshot.state_fence(),
            fence,
            "the test client must bind the admitted fence or every leg fails before reading"
        );

        let tool = query_tool();
        let envelope = test_envelope("eliot.query", &fence, &tool_digest(&tool)?)?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("test runtime: {error}"))?;

        // Capture an observation, then bridge eliot.query for the captured
        // subject: the exact evidence record, provenance, and fence return.
        let mut table = EvidenceTable::new(fence.clone());
        table.capture("evidence-alpha");
        let service = ReadService::new(table);
        let result = runtime.block_on(KernelContextReadClient::execute_local_read(
            &service, &fence, &envelope, &tool,
        ))?;
        assert_eq!(result.operation, NamedReadOperation::GetEvidencePack);
        assert_eq!(result.state_fence, fence);
        let records = result
            .payload
            .get("records")
            .and_then(Value::as_array)
            .ok_or("evidence records must ride the payload")?;
        assert_eq!(
            records.len(),
            1,
            "the captured subject reads back exactly once"
        );
        assert_eq!(
            records[0].get("subject").and_then(Value::as_str),
            Some("evidence-alpha"),
            "the readback record is the captured evidence, never a substitute"
        );
        assert_eq!(
            result.provenance,
            ReadProvenance {
                handles: Vec::new(),
                disposition: ProvenanceDisposition::Unavailable,
            },
            "the readback provenance is the exact facade lineage"
        );

        // A wrong fence fails closed before any read: FenceMismatch, never
        // Ok-empty.
        let wrong = test_fence(2)?;
        let wrong_envelope = test_envelope("eliot.query", &wrong, &tool_digest(&tool)?)?;
        let fenced = runtime.block_on(KernelContextReadClient::execute_local_read(
            &service,
            &fence,
            &wrong_envelope,
            &tool,
        ));
        assert!(
            matches!(
                fenced,
                Err(ReadError::Store(StoreReadFailure::FenceMismatch))
            ),
            "a wrong fence must fail closed as FenceMismatch, got {fenced:?}"
        );

        // The query-only twin refuses packets; the production campaign poller
        // owns packet claim, owner reads, compilation, and result submit.
        let packet = packet_tool();
        let packet_envelope = test_envelope("eliot.packet", &fence, &tool_digest(&packet)?)?;
        let query_twin_result = runtime.block_on(KernelContextReadClient::execute_local_read(
            &service,
            &fence,
            &packet_envelope,
            &packet,
        ));
        assert!(
            matches!(
                query_twin_result,
                Err(ReadError::Store(StoreReadFailure::Unavailable))
            ),
            "the query-only twin must refuse a packet, got {query_twin_result:?}"
        );

        // The production forwarding bridge fails closed before transport: a
        // wrong fence is Contract (not a Kernel round-trip), never Ok-empty.
        let transport_fenced = runtime.block_on(forward_admitted_local_read(
            &client,
            wrong_envelope.clone(),
            tool.clone(),
            test_attempt(&wrong_envelope, 1)?,
        ));
        assert!(
            matches!(transport_fenced, Err(KernelPortError::Contract(_))),
            "a wrong fence must fail the local_read transport closed as Contract, got {transport_fenced:?}"
        );

        // A malformed pair is Contract before transport is touched.
        let malformed = runtime.block_on(forward_admitted_local_read(
            &client,
            envelope.clone(),
            json!("not-an-object"),
            test_attempt(&envelope, 1)?,
        ));
        assert!(
            matches!(malformed, Err(KernelPortError::Contract(_))),
            "a malformed pair must fail the local_read transport closed as Contract, got {malformed:?}"
        );
        Ok(())
    }

    #[test]
    fn local_read_claim_submit_wire_shapes_parse_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::{parse_local_read_claimed_pair, parse_local_read_submit_outcome};
        use crate::LocalReadSubmitOutcome;

        // A null pair is the empty-queue backoff signal, not an error.
        let empty = serde_json::json!({ "pair": null });
        assert_eq!(
            parse_local_read_claimed_pair(&empty)
                .map_err(|error| format!("empty claim must not fail: {error}"))?,
            None,
            "an empty claim must poll null"
        );

        // A claimed pair round-trips the exact admitted envelope, tool, and
        // fenced attempt capability.
        let fence = test_fence(1)?;
        let tool = query_tool();
        let envelope = test_envelope("eliot.query", &fence, &tool_digest(&tool)?)?;
        let attempt = test_attempt(&envelope, 1)?;
        let answer = serde_json::json!({
            "pair": {
                "envelope": envelope.clone(),
                "tool": tool.clone(),
                "attempt": attempt.clone(),
            }
        });
        let (claimed_envelope, claimed_tool, claimed_attempt) =
            parse_local_read_claimed_pair(&answer)
                .map_err(|error| format!("queued pair must parse: {error}"))?
                .ok_or("a queued pair must claim")?;
        assert_eq!(
            claimed_envelope.envelope_sha256, envelope.envelope_sha256,
            "the claim returns the exact admitted envelope"
        );
        assert_eq!(claimed_tool, tool, "the claim returns the exact tool bytes");
        assert_eq!(
            claimed_attempt, attempt,
            "the claim returns the exact fenced attempt"
        );

        // A pair omitting the envelope, the tool, or the attempt, a non-pair
        // value, an attempt bound to another operation, and an answer omitting
        // the pair all fail closed — never Ok-empty, never invented.
        let mut foreign_attempt = serde_json::to_value(&attempt)
            .map_err(|error| format!("attempt must encode: {error}"))?;
        foreign_attempt["operation_id"] = serde_json::json!(
            "hostreq:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        for bad in [
            serde_json::json!({ "pair": { "tool": tool.clone(), "attempt": attempt.clone() } }),
            serde_json::json!({ "pair": { "envelope": envelope.clone(), "tool": tool.clone() } }),
            serde_json::json!({ "pair": {
                "envelope": envelope.clone(),
                "tool": tool.clone(),
                "attempt": foreign_attempt.clone(),
            } }),
            serde_json::json!({ "pair": "not-a-pair" }),
            serde_json::json!({ "operation": "local_read_claim" }),
        ] {
            assert!(
                parse_local_read_claimed_pair(&bad).is_err(),
                "a malformed claim answer must fail closed, got {bad}"
            );
        }

        // Accepted persists (exact replays included); expired is the expected
        // deadline race; stale quarantines a replaced or revoked attempt —
        // never a transport error.
        assert_eq!(
            parse_local_read_submit_outcome(&serde_json::json!({ "accepted": true }))
                .map_err(|error| format!("accepted must parse: {error}"))?,
            LocalReadSubmitOutcome::Accepted,
        );
        assert_eq!(
            parse_local_read_submit_outcome(
                &serde_json::json!({ "accepted": false, "expired": true })
            )
            .map_err(|error| format!("expired must parse: {error}"))?,
            LocalReadSubmitOutcome::Expired,
        );
        assert_eq!(
            parse_local_read_submit_outcome(
                &serde_json::json!({ "accepted": false, "stale": true, "reason": "superseded" })
            )
            .map_err(|error| format!("stale must parse: {error}"))?,
            LocalReadSubmitOutcome::StaleAttempt,
        );
        for bad in [
            serde_json::json!({}),
            serde_json::json!({ "accepted": false }),
            serde_json::json!({ "accepted": "yes" }),
        ] {
            assert!(
                parse_local_read_submit_outcome(&bad).is_err(),
                "an unknown submit answer must fail closed, got {bad}"
            );
        }
        Ok(())
    }
}
