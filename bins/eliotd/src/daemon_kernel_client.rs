//! Authenticated Kernel client transport for `eliotd`.
//!
//! Architecture: A13.2 (Governor/Kernel authenticated IPC boundary), A13.8
//! (process-receipt-gated pre-admission).
//! Implementation: I1.8 (artifact-bound session), I2.16 (generation fencing),
//! I2.23 (typed contract payloads).
//! This module owns only the EBP transport/session proof; Kernel remains the
//! sole process, Store, and canonical authority owner.
//!
//! Issue #1742 W4/W6 (caller STITCH, no fake consumer): this client owns one
//! live claim/submit pair per lane — agent-activation, local-read,
//! campaign-packet, task-controller, observe, finish — and there is no act
//! claim pair and no retained-checkpoint resume pair, so neither gate below
//! has a daemon-side call site yet:
//!
//! - W4: the daemon-side `eliot-context-admission::admit_material_decision`
//!   invocation over Governor owner-resolved inputs, with the dispatch
//!   binding (`bind_material_dispatch`) and dispatch-time revalidation
//!   (`revalidate_material_dispatch`) through a live act claim/flight, runs
//!   at the Governor owner's future live act claim, never here. The Kernel
//!   submit arm owns only the mechanical binding
//!   (`bins/eliot-kernel/src/host_request_route.rs::check_act_submit_binding`)
//!   and the bridge owns only linkage revalidation
//!   (`bins/eliot-agent-bridge/src/kernel_host_request_client.rs::revalidate_act_dispatch`);
//!   both live in sibling-writer files and are not touched here. Refusals
//!   stay typed (`DECISION_CONTEXT_INCOMPLETE` / `MaterialDecisionRefusal`).
//! - W6: the resume-dispatch `admit_material_resume` invocation over #1730's
//!   retained checkpoint runs at the resume owner's join, never here: no
//!   `RetainedHandoffCheckpoint` consumer exists under `bins/`, so there is
//!   no resume path to weaken — unavailable/erased originals stay explicit
//!   and derived summaries never replace originals by construction. That
//!   call site is the resume owner's to write, and is named here rather than
//!   faked with a consumer in this crate.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use eliot_agent_coordinator::OwnerLoadedClaimRow;
#[cfg(windows)]
use eliot_contracts::{ArtifactId, ContractId};
use eliot_contracts::{
    ClockReading, OperationId, ProductId, RequestId, RequestMetadata, SessionId, SourceId,
};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_governor::{GovernorLaunchConfig, KernelGenerationSnapshot, KernelPortError};
use eliot_kernel_service::PROVIDER_CAPABILITY_WIRE_VERSION;
use eliot_learning_contracts::LearningStateViewRecipe;
use eliot_ors::OperationIdentity;
use eliot_protocol::{
    AgentActivationClaimRequest, AgentActivationKernelOwnerReadback, AgentActivationOwnerReadback,
    AgentActivationResolutionResult, AgentActivationResultAck, AgentActivationResultReconcile,
    AgentActivationResultSubmit, EncodingProfile, FinishResultBody, Frame, FrameKind,
    HOST_REQUEST_INVOKE_READ_WIRE_ID, HostRequestEnvelope, HostRequestInvokeReadPayload,
    HostRequestResultBody, HostRequestResultLineage, LocalReadAttempt, LocalReadExecutionEvidence,
    MessageType, ProtocolPayload, ProtocolVersion, RequestIdentity, TaskControllerAttempt,
    SelectedSourceCaptureInvocation, SELECTED_SOURCE_CAPTURE_CAPABILITY,
    SELECTED_SOURCE_CAPTURE_PAYLOAD_SCHEMA_ID, TaskControllerInvocation,
    TaskControllerResultBody, host_request_operation_id,
};
use eliot_receipts::RequestBinding;
#[cfg(windows)]
use eliot_ors::{AdmissionReservationRecord, AdmissionReservationState, OperationalMutationReceipt};
#[cfg(windows)]
use eliot_store_api::ProposedAttemptRecord;
#[cfg(windows)]
use eliot_runtime_contracts::{MODULE_MANIFEST_SCHEMA_VERSION, ModuleManifest};
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
pub use handshake::admitted_daemon_module_contract;
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

const PROVIDER_CAPABILITY_VERIFY_OPERATION: &str = "native_worker.provider_capability.verify";

/// Reads the sealed durable claim-row projection bound to one exact claim
/// identity (issue #1108, A4/A5 daemon row source).
///
/// Daemon-target operation of the Kernel claim-row read arm
/// (`bins/eliot-kernel/src/provider_capability_route.rs::handle_provider_capability_claim_row_read`):
/// the request carries only `wire_version` plus `claim_id`, and every
/// projected field is loaded from the Kernel-held ORS row, never echoed from
/// presented values.
const PROVIDER_CAPABILITY_CLAIM_ROW_READ_OPERATION: &str =
    "native_worker.provider_capability.claim_row.read";

/// Expected `kind` of the sealed claim-row read reply body (issue #1108).
const PROVIDER_CAPABILITY_CLAIM_ROW_KIND: &str = "native_worker_provider_capability_claim_row";

/// Renders the release builder's `eliotd` manifest from the exact contract
/// constructor used by the live Kernel handshake.
///
/// This is a build-only export seam. It creates no admission or runtime
/// authority; the caller supplies the artifact digest produced by the release
/// build, and the running daemon later re-admits the retained sibling bytes
/// against that same digest before publishing its contract.
#[cfg(windows)]
pub fn render_build_module_manifest(artifact_sha256: &str) -> Result<String, crate::DaemonError> {
    let artifact_id = ArtifactId::new(artifact_sha256)
        .map_err(|error| crate::DaemonError::LaunchConfig(error.to_string()))?;
    let module_id = ContractId::new(SERVICE_NAME)
        .map_err(|error| crate::DaemonError::LaunchConfig(error.to_string()))?;
    let contract = handshake::declared_module_contract(module_id, artifact_id);
    ModuleManifest {
        schema_version: MODULE_MANIFEST_SCHEMA_VERSION,
        contract,
    }
    .render_toml()
    .map_err(|error| crate::DaemonError::LaunchConfig(error.to_string()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderCapabilityReceiptWire {
    kind: String,
    wire_version: String,
    claim_id: String,
    attempt_id: String,
    operation_id: String,
    proof_kind: String,
    route_revision: String,
    capacity_revision: String,
    governor_route_revision: String,
    governor_capacity_revision: String,
    worker_generation: u64,
    fence_digest: String,
    verified_at_unix_ms: u64,
    receipt_digest: String,
}

/// Sealed durable claim-row projection for one exact claim identity (issue
/// #1108, A4/A5 daemon row source).
///
/// Mirrors the Kernel claim-row read reply body
/// (`bins/eliot-kernel/src/provider_capability_route.rs::ProviderCapabilityContext::read_claim_row`,
/// sealed by `seal_capability_receipt`): the `kind` discriminator, the
/// capability wire version, the exact durable fields shaped for
/// [`OwnerLoadedClaimRow::new`], the read timestamp, and the seal digest.
/// `deny_unknown_fields` keeps a widened reply a typed failure, never a
/// silently accepted row.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderClaimRowReadWire {
    kind: String,
    wire_version: String,
    claim_id: String,
    attempt_id: String,
    operation_id: String,
    binding_digest: String,
    executable_binding_digest: String,
    worker_generation: u64,
    fence_digest: String,
    read_at_unix_ms: u64,
    receipt_digest: String,
}

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

/// Typed failure of one `agent_activation_submit`, preserving *why* the submit
/// did not produce an acknowledgement instead of erasing that provenance into
/// one opaque string (issue #839, W14/A3).
///
/// The issue requires that "not attempted" stay distinct from "possibly
/// submitted / unknown": only the latter obliges the daemon to reconcile the
/// retained ticket/result identity before any other semantic resolution, and a
/// failure that never reached the transport must not be reported as an
/// ambiguous commit. Each variant names the exact point at which the attempt
/// stopped, so the dispatcher classifies a real transport fact rather than
/// guessing from a diagnostic message. A raw transport error is never recovered
/// by parsing its text.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationSubmitError {
    /// Kernel linearized a result-less deadline expiry. The daemon retires
    /// this ticket without retry and without reconciliation: no result was
    /// accepted and no Apply progress exists.
    Expired,
    /// The daemon refused or failed to build the request, so no frame was
    /// written and Kernel provably holds nothing for this ticket. There is
    /// nothing to reconcile; the failure is reported as-is and fails closed.
    NotAttempted {
        /// Bounded diagnostic detail. Carries no protected field and no whole
        /// payload or error dump.
        detail: String,
    },
    /// The request reached the transport and Kernel answered that it did not
    /// accept the result. The attempt is recorded and definitively not
    /// committed, so reconciliation is not required for this failure.
    Rejected {
        /// Bounded diagnostic detail.
        detail: String,
    },
    /// The request reached the transport and its commit is unknown. Kernel may
    /// already hold this exact result, so the retained ticket/result identity
    /// must be reconciled before any other semantic resolution.
    PossiblySubmitted {
        /// Bounded diagnostic detail.
        detail: String,
    },
}

#[cfg(windows)]
impl ActivationSubmitError {
    /// The bounded diagnostic detail of this failure, whatever its provenance.
    pub fn detail(&self) -> &str {
        match self {
            ActivationSubmitError::Expired => "Kernel expired the activation result deadline",
            ActivationSubmitError::NotAttempted { detail }
            | ActivationSubmitError::Rejected { detail }
            | ActivationSubmitError::PossiblySubmitted { detail } => detail,
        }
    }
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

/// The exact halves one admitted `local_read` answer carries for a completed
/// operation: the operation handle, the recorded result digest, the recorded
/// bounded response, and the retained result lineage the owner bound to THAT
/// result. The lineage is `None` only for a row that carries none, which stays
/// an honest unknown (issue #1809 item 2).
type AdmittedLocalReadHalves<'a> = (
    &'a str,
    &'a str,
    serde_json::Value,
    Option<HostRequestResultLineage>,
);

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

/// Kernel-claimed selected-source mutation request. The host envelope and
/// original EBP `RequestIdentity` are retained exactly; this lane carries no
/// LocalReadAttempt or Task Controller attempt.
#[derive(Clone, Debug)]
pub struct SelectedSourceCaptureClaimedInvocation {
    pub host_request_envelope: HostRequestEnvelope,
    pub invocation: SelectedSourceCaptureInvocation,
    pub request_identity: RequestIdentity,
}

/// Exact Kernel-owned inactive ORS stage returned for one selected-source
/// claim. The receipt and staged row are returned as typed original owner
/// readback, not reconstructed authority.
#[cfg(windows)]
#[derive(Clone, Debug)]
pub struct SelectedSourceCaptureStagedAdmission {
    pub record: ProposedAttemptRecord,
    pub stage_receipt_id: String,
    pub staged_record: AdmissionReservationRecord,
    pub stage_receipt: OperationalMutationReceipt,
}

/// Parses one `source_capture.claim` answer into its exact typed request.
pub fn parse_selected_source_capture_claimed_pair(
    value: &serde_json::Value,
) -> Result<Option<SelectedSourceCaptureClaimedInvocation>, String> {
    let pair = value
        .get("pair")
        .ok_or_else(|| "Kernel source_capture.claim answer omits pair".to_owned())?;
    if pair.is_null() {
        return Ok(None);
    }
    if !pair.is_object() {
        return Err("Kernel source_capture.claim pair is neither an object nor null".to_owned());
    }
    let decode = |field: &str| {
        pair.get(field)
            .cloned()
            .ok_or_else(|| format!("Kernel source_capture.claim pair omits {field}"))
    };
    let envelope: HostRequestEnvelope = serde_json::from_value(decode("envelope")?)
        .map_err(|error| format!("Kernel source_capture.claim envelope does not decode: {error}"))?;
    envelope
        .validate_for_admission()
        .map_err(|error| format!("Kernel source_capture.claim envelope is invalid: {error}"))?;
    let invocation: SelectedSourceCaptureInvocation =
        serde_json::from_value(decode("invocation")?).map_err(|error| {
            format!("Kernel source_capture.claim invocation does not decode: {error}")
        })?;
    invocation
        .validate()
        .map_err(|error| format!("Kernel source_capture.claim invocation is invalid: {error}"))?;
    let request_identity: RequestIdentity = serde_json::from_value(decode("request_identity")?)
        .map_err(|error| {
            format!("Kernel source_capture.claim RequestIdentity does not decode: {error}")
        })?;
    request_identity
        .validate()
        .map_err(|error| format!("Kernel source_capture.claim RequestIdentity is invalid: {error}"))?;
    if envelope.kind != eliot_protocol::HostRequestKind::SelectedSourceCapture
        || envelope.identity.capability != SELECTED_SOURCE_CAPTURE_CAPABILITY
        || envelope.identity.payload_schema_id != SELECTED_SOURCE_CAPTURE_PAYLOAD_SCHEMA_ID
        || envelope.identity.parent_operation_id.is_some()
        || envelope.identity.request_id != request_identity.request.metadata.request_id
        || envelope.identity.idempotency_key != request_identity.idempotency_key
        || envelope.identity.cancellation_id != request_identity.cancellation_id
        || envelope.identity.deadline_unix_ms != request_identity.deadline_unix_ms
        || request_identity.request.state_fence != envelope.state_fence
        || request_identity.request.metadata.state_fence != envelope.state_fence
        || request_identity.request.metadata.task_id.as_ref().map(ToString::to_string)
            != envelope.identity.task_id
        || request_identity.request.metadata.session_id.as_ref().map(ToString::to_string)
            != envelope.identity.session_id
    {
        return Err(
            "Kernel source_capture.claim pair does not bind the typed invocation to its authenticated envelope and original RequestIdentity".to_owned(),
        );
    }
    Ok(Some(SelectedSourceCaptureClaimedInvocation {
        host_request_envelope: envelope,
        invocation,
        request_identity,
    }))
}

/// Parses the original Kernel `source_capture.stage` response and compares
/// every echoed record, ORS snapshot, and receipt binding with its retained
/// claim and Governor owner selection.
#[cfg(windows)]
pub fn parse_selected_source_capture_staged_admission(
    value: &serde_json::Value,
    claimed: &SelectedSourceCaptureClaimedInvocation,
    selected: &eliot_governor::TaskSelectionAdmissionBinding,
    intent: &eliot_kernel_service::source_capture_mutation::SelectedSourceCaptureStageIntent,
) -> Result<SelectedSourceCaptureStagedAdmission, String> {
    let stage = value
        .get("stage")
        .ok_or_else(|| "Kernel source_capture.stage answer omits stage".to_owned())?;
    let decode = |field: &str| {
        stage
            .get(field)
            .cloned()
            .ok_or_else(|| format!("Kernel source_capture.stage answer omits {field}"))
    };
    let result = SelectedSourceCaptureStagedAdmission {
        record: serde_json::from_value(decode("record")?)
            .map_err(|error| format!("staged ProposedAttempt record does not decode: {error}"))?,
        stage_receipt_id: decode("stage_receipt_id")?
            .as_str()
            .ok_or_else(|| "source_capture.stage receipt id is not a string".to_owned())?
            .to_owned(),
        staged_record: serde_json::from_value(decode("staged_record")?)
            .map_err(|error| format!("inactive ORS record does not decode: {error}"))?,
        stage_receipt: serde_json::from_value(decode("stage_receipt")?)
            .map_err(|error| format!("inactive ORS receipt does not decode: {error}"))?,
    };
    let record = &result.record;
    let staged = &result.staged_record;
    record
        .validate()
        .map_err(|error| format!("Kernel staged ProposedAttempt record is invalid: {error}"))?;
    staged
        .validate()
        .map_err(|error| format!("Kernel inactive ORS staged row is invalid: {error}"))?;
    let invocation = &claimed.invocation;
    let envelope = &claimed.host_request_envelope;
    let identity = &claimed.request_identity;
    let request_identity = serde_json::to_value(identity)
        .map_err(|error| format!("original request identity cannot be encoded: {error}"))?;
    let reservation_claims = serde_json::to_value(&intent.claims)
        .map_err(|error| format!("typed ORS claims cannot be encoded: {error}"))?;
    let authority_epoch = serde_json::to_value(&staged.authority_epoch)
        .map_err(|error| format!("staged ORS epoch cannot be encoded: {error}"))?;
    let expected_operation = match invocation.operation {
        eliot_protocol::SelectedSourceCaptureOperation::Diagnostics => "Diagnostics",
        eliot_protocol::SelectedSourceCaptureOperation::ProbeVersion => "ProbeVersion",
    };
    if record.work_item_id != selected.evidence_ref()
        || record.proposed_attempt_id == record.work_item_id
        || record.reservation_id == record.work_item_id
        || record.reservation_id == record.proposed_attempt_id
        || record.reservation_stage_receipt_id != result.stage_receipt_id
        || record.request_identity != request_identity
        || record.task_id != selected.task_ref()
        || record.session_id != selected.session_ref()
        || record.work_scope_id != selected.work_scope().binding.scope.scope_ref
        || record.work_lease_id != selected.selection_source_ref()
        || record.principal_id != selected.principal_ref()
        || record.operation != expected_operation
        || record.operation != intent.operation
        || record.selected_relative_path != invocation.selected_relative_path
        || record.selected_relative_path != intent.selected_relative_path
        || record.selector != invocation.selector
        || record.selector != intent.selector
        || record.source_digest != intent.source_digest
        || record.configuration_digest != intent.configuration_digest
        || record.action_contract_digest != intent.action_contract_digest
        || record.disposition != "ADMITTED"
        || record.reservation_claims != reservation_claims
        || record.authority_epoch != authority_epoch
        || record.state_fence != envelope.state_fence
        || staged.reservation_id != record.reservation_id
        || staged.work_item_id != record.work_item_id
        || staged.proposed_attempt_id != record.proposed_attempt_id
        || staged.operation_id != staged.stage_operation_id
        || staged.claims != intent.claims
        || staged.state_fence.generation != envelope.state_fence.resource_generation.value()
        || staged.state_fence.observed_authority_epoch != envelope.state_fence.authority_epoch
        || staged.state != AdmissionReservationState::StagedInactive
        || result.stage_receipt.record_id().as_str() != result.stage_receipt_id
        || result.stage_receipt.subject_id() != &staged.reservation_id
    {
        return Err(
            "source_capture.stage response differs from the retained claim, current owner selection, intent, or exact inactive ORS evidence".to_owned(),
        );
    }
    Ok(result)
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

/// Version of the canonical Kernel request identity encoding this module
/// mints. I5.27 requires the canonical encoding to be deterministic AND
/// versioned; the version is bound into the digest input so a future encoding
/// change cannot silently re-key a receipt already admitted under this one.
const KERNEL_REQUEST_IDENTITY_ENCODING_VERSION: u16 = 1;

/// Domain separator for the canonical Kernel request identity digest. Keeps
/// this digest disjoint from every other digest in the system, so a request
/// identity can never be reproduced from an unrelated material.
const KERNEL_REQUEST_IDENTITY_DOMAIN: &str = "eliot.kernel_request_identity";

/// The caller-admitted inputs one Kernel request identity is derived from.
///
/// I5.27's `CanonicalOperationIdentity`: the semantic command kind, the
/// principal and operation scope, and the canonical request bytes. Every field
/// here is supplied by the caller as operation content or as the admitted
/// scope; none of them is an attempt counter, nonce, clock or ambient state.
/// Two byte-identical presentations of one operation therefore bind to the
/// same identity, and a changed payload binds to a different one.
///
/// This is the ONLY place the operation name and the scope are declared for a
/// transport identity, so the digest input and the emitted key labels cannot
/// be given different values.
struct CanonicalKernelRequest<'a> {
    /// The semantic command kind. Not caller spelling of a retry: it is the
    /// closed operation this request actually executes.
    operation: &'a str,
    /// The admitted principal and operation scope: the installation,
    /// generation and authority epoch this connection is bound to. A different
    /// installation or generation really is a different operation scope, so
    /// this belongs in the identity; it is not an attempt discriminator.
    scope: &'a str,
    /// The exact canonical request bytes this transport is about to send.
    request: &'a serde_json::Value,
}

/// Computes the canonical request digest for one Kernel request.
///
/// Reuses the repository's single canonicalization and digest owner
/// (`eliot_contracts::canonical_json_bytes`, which sorts every object key
/// recursively, and `eliot_contracts::sha256_hex`). This introduces no second
/// hash or canonicalization scheme, and the domain separator plus encoding
/// version follow the same shape as the existing `testd_owner_*_request_digest`
/// helpers in this module.
fn canonical_kernel_request_digest(
    request: &CanonicalKernelRequest<'_>,
) -> Result<String, serde_json::Error> {
    // Named `DigestInput` rather than `Canonical` so the field names below can
    // keep I5.27's exact canonical spelling: those names ARE the declared
    // identity shape, so they are not renamed to satisfy a lint.
    #[derive(Serialize)]
    struct DigestInput<'a> {
        domain_separator: &'a str,
        canonical_encoding_version: u16,
        semantic_command_kind: &'a str,
        principal_and_scope: &'a str,
        canonical_request: &'a serde_json::Value,
    }
    let bytes = canonical_json_bytes(&DigestInput {
        domain_separator: KERNEL_REQUEST_IDENTITY_DOMAIN,
        canonical_encoding_version: KERNEL_REQUEST_IDENTITY_ENCODING_VERSION,
        semantic_command_kind: request.operation,
        principal_and_scope: request.scope,
        canonical_request: request.request,
    })?;
    Ok(sha256_hex(&bytes))
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

/// Exact legacy proof member spelling rejected from `eliot.finish` arguments
/// (issue #1741, I7.9/I7.20).
///
/// This mirrors the `completion_proof` spelling pinned by
/// `eliot_mcp::contract::LEGACY_FINISH_PROOF_MEMBER`: the strict
/// `FinishAttemptDraft` contract has no such member. Only this exact spelling
/// is recognized here — no aliases are invented. The spelling is cited, not
/// imported, because the daemon has no dependency on the MCP surface crate.
pub(crate) const LEGACY_FINISH_PROOF_MEMBER: &str = "completion_proof";

/// Exact typed diagnostic for a caller-supplied finish proof member.
///
/// The text carries the pinned `LEGACY_FINISH_INPUT_REJECTED` reason code
/// first so the typed reason survives even the string error channel, and it
/// echoes only the static member spelling — never caller bytes. It mirrors
/// the ingress message shape so every lane reports one identical rejection.
pub(crate) const LEGACY_FINISH_PROOF_REJECTION: &str = "LEGACY_FINISH_INPUT_REJECTED: caller-supplied finish proof member `completion_proof` is not accepted; submit only the strict FinishAttemptDraft fields";

/// Typed outcome of one `finish_result` submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishSubmitOutcome {
    /// Kernel persisted the result body or recognized an exact replay.
    Accepted,
    /// The admitted attempt expired before the result was committed.
    Expired,
    /// The attempt was replaced, revoked or otherwise stale.
    StaleAttempt,
}

/// Kernel-derived finish claim. The duplicated envelope, tool, attempt and
/// identity are checked for exact binding before they reach the Governor.
#[derive(Clone, Debug)]
pub struct FinishClaimedInvocation {
    pub envelope: HostRequestEnvelope,
    pub tool: serde_json::Value,
    pub request_identity: RequestIdentity,
    pub operation_id: OperationId,
    pub attempt: eliot_protocol::FinishAttempt,
}

/// Derives the Governor request identity for one admitted finish candidate.
///
/// The task binding comes exclusively from the digest-bound admitted draft
/// plus the admitted envelope fence: the task id from the draft and the
/// envelope's live fence unchanged.
///
/// The fence deliberately carries no `task_revision`. It is the Kernel
/// generation fence (`KernelGenerationSnapshot::state_fence` is
/// `StateFence::new(authority_epoch, resource_generation)`), so it is `None`
/// there by construction, and every Governor owner read on this lane compares
/// that fence for exact equality — a fence restating a caller-captured
/// revision could never match one. `StateFence::I45_KEY_OMISSIONS` gives the
/// task-revision dimension to the operation's own owner record, so the draft's
/// `expected_task_revision` is re-proved by the Governor finish owner against
/// its live task-lifecycle `TaskRecord` instead: an owner-held value, strictly
/// stronger than a restated caller claim.
fn derive_finish_request_identity(
    draft: &eliot_governor::FinishAttemptDraft,
    envelope: &HostRequestEnvelope,
) -> Result<RequestIdentity, String> {
    draft
        .validate()
        .map_err(|error| format!("claimed finish draft is invalid: {error}"))?;
    let fence = envelope.state_fence.clone();
    let session_id = envelope
        .identity
        .session_id
        .clone()
        .map(|value| SessionId::new(value).map_err(|error| error.to_string()))
        .transpose()?;
    let metadata = RequestMetadata {
        request_id: envelope.identity.request_id.clone(),
        session_id,
        task_id: Some(
            eliot_contracts::TaskId::new(draft.task_id.clone())
                .map_err(|error| format!("claimed finish task id is invalid: {error}"))?,
        ),
        product_id: ProductId::new("eliotd").map_err(|error| error.to_string())?,
        source_id: SourceId::new("eliotd-finish-lane").map_err(|error| error.to_string())?,
        state_fence: fence.clone(),
        clock: ClockReading::default(),
    };
    let identity = RequestIdentity {
        request: RequestBinding {
            metadata,
            state_fence: fence,
        },
        idempotency_key: envelope.identity.idempotency_key.clone(),
        deadline_unix_ms: envelope.identity.deadline_unix_ms,
        cancellation_id: envelope.identity.cancellation_id.clone(),
    };
    identity
        .validate()
        .map_err(|error| format!("derived finish identity is invalid: {error}"))?;
    Ok(identity)
}

fn validate_finish_claim_request_identity(
    envelope: &HostRequestEnvelope,
    draft: &eliot_governor::FinishAttemptDraft,
    request_identity: &RequestIdentity,
    expected_identity: &RequestIdentity,
) -> Result<(), String> {
    if !envelope
        .state_fence
        .is_compatible_with(&request_identity.request.state_fence)
        || request_identity.request.state_fence != expected_identity.request.state_fence
        || request_identity.request.metadata.request_id != envelope.identity.request_id
        || request_identity.request.metadata.session_id
            != expected_identity.request.metadata.session_id
        || request_identity
            .request
            .metadata
            .task_id
            .as_ref()
            .is_none_or(|task| task.as_str() != draft.task_id.as_str())
        || envelope
            .identity
            .task_id
            .as_deref()
            .is_some_and(|task| task != draft.task_id)
        || request_identity.idempotency_key != envelope.identity.idempotency_key
        || request_identity.deadline_unix_ms != envelope.identity.deadline_unix_ms
        || request_identity.cancellation_id != envelope.identity.cancellation_id
        || request_identity.request.metadata.product_id
            != expected_identity.request.metadata.product_id
        || request_identity.request.metadata.source_id
            != expected_identity.request.metadata.source_id
        || request_identity.request.metadata.state_fence != envelope.state_fence
    {
        return Err("Kernel finish identity does not bind its admitted envelope".to_owned());
    }
    Ok(())
}

/// Parses one unwrapped finish poll answer into its exact admitted envelope,
/// tool, Kernel-issued attempt and derived owner request identity.
pub fn parse_finish_claimed_pair(
    value: &serde_json::Value,
) -> Result<Option<FinishClaimedInvocation>, String> {
    let pair = value
        .get("pair")
        .ok_or_else(|| "Kernel finish_claim answer omits pair".to_owned())?;
    if pair.is_null() {
        return Ok(None);
    }
    if !pair.is_object() {
        return Err("Kernel finish_claim pair is neither an object nor null".to_owned());
    }
    let decode = |field: &str| {
        pair.get(field)
            .cloned()
            .ok_or_else(|| format!("Kernel finish_claim pair omits {field}"))
    };
    let envelope: HostRequestEnvelope = serde_json::from_value(decode("envelope")?)
        .map_err(|error| format!("Kernel finish envelope does not decode: {error}"))?;
    envelope
        .validate()
        .map_err(|error| format!("Kernel finish envelope is invalid: {error}"))?;
    let tool = decode("tool")?;
    HostRequestInvokeReadPayload {
        wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
        wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
        envelope: envelope.clone(),
        tool: tool.clone(),
    }
    .validate()
    .map_err(|error| format!("Kernel finish tool bytes are not envelope-bound: {error}"))?;
    let arguments = tool
        .get("arguments")
        .cloned()
        .ok_or_else(|| "Kernel finish pair omits the admitted draft".to_owned())?;
    // A legacy caller-supplied proof is rejected with its pinned reason code
    // before strict typed decoding, which would otherwise report only a
    // generic unknown-field failure. This mirrors the protected-ingress order
    // (`decode_protected_request_bytes`); only the exact legacy spelling is
    // recognized and no caller bytes are echoed.
    if arguments.get(LEGACY_FINISH_PROOF_MEMBER).is_some() {
        return Err(LEGACY_FINISH_PROOF_REJECTION.to_owned());
    }
    let draft: eliot_governor::FinishAttemptDraft = serde_json::from_value(arguments)
        .map_err(|error| format!("admitted finish draft does not decode: {error}"))?;
    draft
        .validate()
        .map_err(|error| format!("admitted finish draft is invalid: {error}"))?;
    let attempt: eliot_protocol::FinishAttempt = serde_json::from_value(decode("attempt")?)
        .map_err(|error| format!("Kernel finish attempt does not decode: {error}"))?;
    attempt
        .validate()
        .map_err(|error| format!("Kernel finish attempt is invalid: {error}"))?;
    let operation_id: OperationId = serde_json::from_value(decode("operation_id")?)
        .map_err(|error| format!("Kernel finish operation id does not decode: {error}"))?;
    let expected_operation = host_request_operation_id(&envelope);
    let expected_identity = derive_finish_request_identity(&draft, &envelope)?;
    let request_identity = match pair.get("identity") {
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|error| format!("Kernel finish identity does not decode: {error}"))?,
        None => expected_identity.clone(),
    };
    request_identity
        .validate()
        .map_err(|error| format!("Kernel finish identity is invalid: {error}"))?;
    validate_finish_claim_request_identity(
        &envelope,
        &draft,
        &request_identity,
        &expected_identity,
    )?;
    let tool_name = tool.get("name").and_then(serde_json::Value::as_str);
    if envelope.kind != eliot_protocol::HostRequestKind::Invocation
        || envelope.identity.capability != "eliot.finish"
        || envelope.identity.payload_schema_id != eliot_protocol::FINISH_INVOKE_PAYLOAD_SCHEMA_ID
        || tool_name != Some("eliot.finish")
        || operation_id.as_str() != expected_operation
        || attempt.operation_id != expected_operation
        || attempt.session_id != envelope.identity.session_id.as_deref().unwrap_or_default()
        || attempt.expires_at_unix_ms != envelope.identity.deadline_unix_ms
        || attempt.authority_epoch != envelope.state_fence.authority_epoch
    {
        return Err("Kernel finish pair does not bind its admitted envelope".to_owned());
    }
    Ok(Some(FinishClaimedInvocation {
        envelope,
        tool,
        request_identity,
        operation_id,
        attempt,
    }))
}

/// Parses one unwrapped finish result submit answer.
pub fn parse_finish_submit_outcome(
    value: &serde_json::Value,
) -> Result<FinishSubmitOutcome, String> {
    let accepted = value
        .get("accepted")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| "Kernel finish_result answer omits accepted outcome".to_owned())?;
    if accepted {
        return Ok(FinishSubmitOutcome::Accepted);
    }
    if value
        .get("expired")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(FinishSubmitOutcome::Expired);
    }
    if value
        .get("stale")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(FinishSubmitOutcome::StaleAttempt);
    }
    Err("Kernel finish_result answer is not accepted, expired, or stale".to_owned())
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
/// absent authority is never invented. This shared parser preserves the
/// decoded tool shape; [`DaemonKernelClient::claim_local_read_pair_async`]
/// accepts `eliot.query` and exactly the Skill names recognized by
/// `eliot_agent_bridge_core::skill_tool_kind`, each only when its name equals
/// the envelope capability. `eliot.packet` remains on the separate campaign
/// packet claim.
pub fn parse_local_read_claimed_pair(
    value: &serde_json::Value,
) -> Result<Option<(HostRequestEnvelope, serde_json::Value, LocalReadAttempt)>, String> {
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

/// Parses one unwrapped `watchdog_export_claim` answer into the owner-neutral
/// export window the Watchdog submitted.
///
/// The value arrives already unwrapped from the shared `{status, value,
/// recovery}` outcome envelope, so this reads exactly the `batch` member the
/// Kernel arm writes, matching [`parse_observe_claimed_pair`]'s shape. The
/// batch decodes as the exact typed closed payload the Kernel admitted, is
/// re-validated against its own contract here, and is projected onto the
/// owner-neutral batch the Governor admission consumes. Every field is the
/// Watchdog's own recorded value: nothing is defaulted, synthesized, or
/// recomputed, so the admission runs against the same digests, ranges, and
/// freshness window the spool owner exported. A null `batch` is an empty-queue
/// backoff, not a failure.
pub fn parse_watchdog_export_claimed_batch(
    value: &serde_json::Value,
) -> Result<Option<eliot_watchdog_core::WatchdogSpoolExportBatch>, String> {
    use eliot_protocol::{WatchdogSpoolEntryKind, WatchdogSpoolExportBatchPayload};
    let _span = tracing::info_span!("eliotd.watchdog_export_claim").entered();
    let batch = match value.get("batch") {
        None | Some(serde_json::Value::Null) => return Ok(None),
        Some(batch) => batch.clone(),
    };
    let payload: WatchdogSpoolExportBatchPayload = serde_json::from_value(batch)
        .map_err(|error| format!("Kernel watchdog export claim does not decode: {error}"))?;
    payload.validate().map_err(|error| {
        format!("Kernel watchdog export claim is not the admitted contract: {error}")
    })?;
    let entries = payload
        .entries
        .iter()
        .map(|entry| eliot_watchdog_core::WatchdogSpoolExportEntry {
            sequence: entry.sequence,
            schema_version: entry.schema_version,
            observed_at_ms: entry.observed_at_ms,
            payload_kind: match entry.entry_kind {
                WatchdogSpoolEntryKind::Heartbeat => {
                    eliot_watchdog_core::WatchdogSpoolPayloadKind::Heartbeat
                }
                WatchdogSpoolEntryKind::Gap => eliot_watchdog_core::WatchdogSpoolPayloadKind::Gap,
                WatchdogSpoolEntryKind::Recovery => {
                    eliot_watchdog_core::WatchdogSpoolPayloadKind::Recovery
                }
            },
            payload_digest: entry.payload_digest.clone(),
            record_digest: entry.record_digest.clone(),
        })
        .collect::<Vec<_>>();
    Ok(Some(eliot_watchdog_core::WatchdogSpoolExportBatch {
        schema_version: payload.schema_version,
        batch_id: payload.batch_id.clone(),
        installation_id: payload.installation_id.clone(),
        watchdog_generation: payload.watchdog_generation,
        watchdog_epoch: payload.watchdog_epoch,
        predecessor_cursor: eliot_watchdog_core::WatchdogSpoolCursor {
            schema_version: payload.schema_version,
            acknowledged_sequence: payload.predecessor_sequence,
            watchdog_generation: payload.watchdog_generation,
            watchdog_epoch: payload.watchdog_epoch,
            installation_id: payload.installation_id.clone(),
            sink_id: payload.sink_id.clone(),
        },
        first_sequence: payload.first_sequence,
        last_sequence: payload.last_sequence,
        high_water_sequence: payload.high_water_sequence,
        item_count: entries.len(),
        byte_size: payload.byte_size,
        entries,
        batch_digest: payload.batch_digest.clone(),
        is_empty_batch: false,
        created_at_ms: payload.created_at_ms,
        expires_at_ms: payload.expires_at_ms,
    }))
}

/// Builds the typed terminal-disposition result for one admitted drain window.
///
/// Only a disposition that actually terminates an entry appears: a receipt-less
/// or otherwise undecided entry is simply absent, because the closed result
/// vocabulary has no "not yet" value. That absence is what keeps the Watchdog's
/// cursor exactly where the spool owner left it instead of letting an undecided
/// entry be counted as applied.
pub fn watchdog_export_result_for_acknowledgement(
    batch: &eliot_watchdog_core::WatchdogSpoolExportBatch,
    acknowledgement: &eliot_watchdog_core::WatchdogSpoolAcknowledgement,
) -> Result<Option<eliot_protocol::WatchdogSpoolExportResultPayload>, String> {
    use eliot_protocol::{
        WatchdogSpoolEntryOutcome, WatchdogSpoolExportOutcomeSubmission,
        WatchdogSpoolExportResultPayload, watchdog_export_reconciliation_idempotency_key,
    };
    let _span = tracing::info_span!("eliotd.watchdog_export_result").entered();
    // The acknowledgement must answer this exact window before any of its
    // dispositions can be projected onto a result: a sink that echoed a
    // different batch identity would otherwise bind decisions to foreign
    // records.
    if acknowledgement.batch_id != batch.batch_id
        || acknowledgement.batch_digest != batch.batch_digest
        || acknowledgement.predecessor_sequence != batch.predecessor_cursor.acknowledged_sequence
        || acknowledgement.first_sequence != batch.first_sequence
        || acknowledgement.last_sequence != batch.last_sequence
        || acknowledgement.installation_id != batch.installation_id
        || acknowledgement.sink_id != batch.predecessor_cursor.sink_id
        || acknowledgement.dispositions.len() != batch.entries.len()
    {
        return Err(
            "Watchdog export acknowledgement does not answer the claimed drain window".to_owned(),
        );
    }
    let mut outcomes = Vec::with_capacity(acknowledgement.dispositions.len());
    for (entry, line) in batch.entries.iter().zip(&acknowledgement.dispositions) {
        if line.sequence != entry.sequence || line.record_digest != entry.record_digest {
            return Err(
                "Watchdog export acknowledgement does not answer the exact retained record"
                    .to_owned(),
            );
        }
        let outcome = match &line.disposition {
            eliot_watchdog_core::WatchdogSpoolSinkDisposition::Applied => {
                WatchdogSpoolEntryOutcome::Applied
            }
            eliot_watchdog_core::WatchdogSpoolSinkDisposition::Rejected { reason } => {
                WatchdogSpoolEntryOutcome::Rejected {
                    reason: reason.clone(),
                }
            }
            eliot_watchdog_core::WatchdogSpoolSinkDisposition::GapRequiresRecovery => {
                WatchdogSpoolEntryOutcome::GapRequiresRecovery
            }
            // No terminal disposition: the Governor has not decided this entry,
            // so it stays pending and is deliberately not submitted.
            eliot_watchdog_core::WatchdogSpoolSinkDisposition::Received
            | eliot_watchdog_core::WatchdogSpoolSinkDisposition::Durable
            | eliot_watchdog_core::WatchdogSpoolSinkDisposition::AdmittedCandidate
            | eliot_watchdog_core::WatchdogSpoolSinkDisposition::Unknown => continue,
        };
        outcomes.push(WatchdogSpoolExportOutcomeSubmission {
            sequence: entry.sequence,
            record_digest: entry.record_digest.clone(),
            idempotency_key: watchdog_export_reconciliation_idempotency_key(
                &batch.installation_id,
                entry.sequence,
                &entry.record_digest,
            ),
            outcome,
        });
    }
    if outcomes.is_empty() {
        return Ok(None);
    }
    WatchdogSpoolExportResultPayload {
        wire_id: eliot_protocol::WATCHDOG_SPOOL_EXPORT_BATCH_WIRE_ID.to_owned(),
        wire_version: WatchdogSpoolExportResultPayload::CONTRACT_VERSION,
        route: eliot_protocol::WATCHDOG_SPOOL_EXPORT_ROUTE.to_owned(),
        installation_id: batch.installation_id.clone(),
        batch_id: batch.batch_id.clone(),
        batch_digest: batch.batch_digest.clone(),
        outcomes,
        payload_sha256: String::new(),
    }
    .with_computed_digest()
    .map(Some)
    .map_err(|error| format!("Watchdog export result is not the closed contract: {error}"))
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

    /// Submits one already-resolved v2 result through the existing authenticated
    /// transport. Every valid disposition is submitted; no disposition is
    /// coerced to success and none is silently discarded.
    ///
    /// #839 (W14/A3): each failure below is reported with its real transport
    /// provenance instead of one erased string. The two pre-send failures are
    /// [`ActivationSubmitError::NotAttempted`] because no frame was written; a
    /// definitive non-acceptance is [`ActivationSubmitError::Rejected`]; and
    /// every failure observed at or after the exchange — a transport error, an
    /// undecodable response, a missing acknowledgement, an ack that does not
    /// validate, or an ack that does not bind the submitted result — is
    /// [`ActivationSubmitError::PossiblySubmitted`], because Kernel may already
    /// hold this exact result. The transport itself is unchanged.
    ///
    /// #1115: a well-formed acknowledgement is returned with its own
    /// `AgentActivationResultAckOutcome` intact, including `Unknown`, so the
    /// caller classifies the outcome Kernel actually reported instead of an
    /// accepted-payload mismatch. This leg is symmetric with
    /// [`Self::reconcile_agent_activation_result`].
    #[cfg(windows)]
    pub async fn submit_agent_activation_result(
        &self,
        result: &AgentActivationResolutionResult,
        owner_readback: Option<AgentActivationOwnerReadback>,
    ) -> Result<AgentActivationResultAck, ActivationSubmitError> {
        if matches!(
            result.disposition,
            eliot_protocol::AgentActivationResolutionDisposition::Resolved { .. }
        ) && owner_readback
            .as_ref()
            .and_then(|readback| readback.kernel_owner.as_ref())
            .is_none()
        {
            return Err(ActivationSubmitError::NotAttempted {
                detail: "Resolved activation submission requires the current Kernel owner readback"
                    .to_owned(),
            });
        }
        let submit =
            AgentActivationResultSubmit::new_with_owner_readback(result.clone(), owner_readback)
                .map_err(|error| ActivationSubmitError::NotAttempted {
                    detail: format!("activation result submit does not bind: {error}"),
                })?;
        let value = self
            .transact_async(
                "agent_activation_submit",
                serde_json::json!({ "result": submit }),
            )
            .await
            .map_err(|error| ActivationSubmitError::PossiblySubmitted {
                detail: format!("Kernel activation result submit: {error}"),
            })?;
        let response: ActivationSubmitResponse =
            serde_json::from_value(value).map_err(|error| {
                ActivationSubmitError::PossiblySubmitted {
                    detail: format!("Kernel activation submit response does not decode: {error}"),
                }
            })?;
        if response.expired {
            return Err(ActivationSubmitError::Expired);
        }
        if !response.accepted {
            return Err(ActivationSubmitError::Rejected {
                detail: "Kernel submit response was not accepted".to_owned(),
            });
        }
        let ack = response
            .ack
            .ok_or_else(|| ActivationSubmitError::PossiblySubmitted {
                detail: "Kernel submit response omitted acknowledgement".to_owned(),
            })?;
        // #1115: this leg validates the recorded acknowledgement and its
        // replay identity only, exactly as `reconcile_agent_activation_result`
        // already does below. The accepted-payload validator
        // (`validate_against_result`) rejects `AgentActivationResultAckOutcome::Unknown`
        // unconditionally, so applying it here diverted a typed Unknown into a
        // generic `PossiblySubmitted` before `classify_submit_ack` could report
        // it. A closed Unknown keeps its ticket id, result digest and
        // reconciliation detail and reaches the classifier; accepted-payload
        // validation stays where an accepted payload is actually accepted.
        ack.validate()
            .map_err(|error| ActivationSubmitError::PossiblySubmitted {
                detail: format!("Kernel activation result ack does not validate: {error}"),
            })?;
        if ack.replay_key() != (result.ticket_id.as_str(), result.result_sha256.as_str()) {
            return Err(ActivationSubmitError::PossiblySubmitted {
                detail: "Kernel activation result ack identity mismatch".to_owned(),
            });
        }
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
        // #740 A2/A14: the span above renders nothing under the installed
        // subscriber, so the handshake state and the owning failure record
        // are real records emitted once per operation outcome beside it.
        let outcome = (|| -> Result<Arc<Self>, super::DaemonError> {
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
        })();
        match &outcome {
            Ok(client) => {
                let _ = crate::diagnostics::emit_kernel_handshake(&client.connection_id, true);
            }
            Err(error) => {
                let _ = crate::diagnostics::ErrorRecord::of_daemon_error(error).emit();
            }
        }
        outcome
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
                result.map_err(|error| {
                    // #740 A17: only proven connection loss emits the
                    // disconnect record under the original connection id.
                    // Timeouts, shutdown abandonment, correlation mismatches
                    // and wire-decode failures stay Unknown without one, and
                    // the emit itself performs no Kernel operation.
                    if matches!(
                        error,
                        eliot_ipc::TransportError::Io(_)
                            | eliot_ipc::TransportError::UnknownOutcome
                    ) {
                        let _ =
                            crate::diagnostics::KernelDisconnect::of(&self.connection_id).emit();
                    }
                    KernelClientError::Unknown(error.to_string())
                })
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

    /// Asks the authenticated Kernel owner to verify one exact provider
    /// binding before daemon composition may consider constructing an
    /// admitted capability.
    ///
    /// The transport handshake and correlated response are owner-authenticated;
    /// the response seal and every field it actually echoes are checked here.
    /// Route and capacity currentness in `material` came from serialized intake
    /// data, not a live Governor read; the Kernel response echoes those
    /// presented values and this method does not promote them to owner evidence.
    /// This is only a provider-binding probe. The current Kernel/ORS claim row
    /// does not retain an independently verified executable-binding digest,
    /// so this response must never be treated as admitted execution capability.
    pub(super) async fn verify_provider_binding_async(
        &self,
        material: &super::agent_fabric::VerifiedProviderMaterial,
    ) -> Result<(), KernelClientError> {
        use eliot_contracts::{canonical_json_bytes, fences_match_exact, sha256_hex};

        material
            .expectation
            .validate()
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        let owner_session = self.owner_session_facts().ok_or_else(|| {
            KernelClientError::Contract(
                "provider binding requires an already validated Kernel owner session".to_owned(),
            )
        })?;
        let live_fence = self.kernel_fence();
        if !fences_match_exact(&material.presented_fence, &live_fence)
            || !material
                .expectation
                .live_authority_epoch
                .is_same_authority(&live_fence.authority_epoch)
        {
            return Err(KernelClientError::Contract(
                "provider binding presentation is stale under the live Kernel fence".to_owned(),
            ));
        }
        if material.expectation.revoked {
            return Err(KernelClientError::Contract(
                "provider binding presentation is marked revoked".to_owned(),
            ));
        }
        let fence_bytes = canonical_json_bytes(&material.presented_fence)
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        let fence_digest = sha256_hex(&fence_bytes);
        let payload = serde_json::json!({
            "wire_version": PROVIDER_CAPABILITY_WIRE_VERSION,
            "claim_id": material.claim_id,
            "attempt_id": material.attempt_id,
            "operation_id": material.operation_id,
            "proof_kind": "Binding",
            "proof_ref": owner_session.session_binding(),
            "canonical_payload_sha256": fence_digest,
            "binding_digest": material.binding_digest,
            "executable_binding_digest": material.executable_digest,
            "route_revision": material.route_revision,
            "capacity_revision": material.capacity_revision,
            "governor_route_revision": material.expectation.current_route_revision,
            "governor_capacity_revision": material.expectation.current_capacity_revision,
            "worker_generation": material.worker_generation,
            "fence_digest": fence_digest,
        });
        let response = self
            .transact_async(PROVIDER_CAPABILITY_VERIFY_OPERATION, payload)
            .await?;
        let mut body = response.clone();
        let receipt_digest = body
            .as_object_mut()
            .and_then(|object| object.remove("receipt_digest"))
            .and_then(|digest| digest.as_str().map(str::to_owned))
            .ok_or_else(|| {
                KernelClientError::Unknown(
                    "Kernel provider capability reply has no sealed digest".to_owned(),
                )
            })?;
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|error| KernelClientError::Unknown(error.to_string()))?;
        if sha256_hex(&body_bytes) != receipt_digest {
            return Err(KernelClientError::Unknown(
                "Kernel provider capability reply digest is invalid".to_owned(),
            ));
        }
        let receipt: ProviderCapabilityReceiptWire = serde_json::from_value(response)
            .map_err(|error| KernelClientError::Unknown(error.to_string()))?;
        if receipt.kind != "native_worker_provider_capability"
            || receipt.wire_version != PROVIDER_CAPABILITY_WIRE_VERSION
            || receipt.receipt_digest != receipt_digest
            || receipt.claim_id != material.claim_id
            || receipt.attempt_id != material.attempt_id
            || receipt.operation_id != material.operation_id
            || receipt.proof_kind != "Binding"
            || receipt.route_revision != material.route_revision
            || receipt.capacity_revision != material.capacity_revision
            || receipt.governor_route_revision != material.expectation.current_route_revision
            || receipt.governor_capacity_revision != material.expectation.current_capacity_revision
            || receipt.worker_generation != material.worker_generation
            || receipt.fence_digest != fence_digest
            || receipt.verified_at_unix_ms == 0
        {
            return Err(KernelClientError::Unknown(
                "Kernel provider capability reply does not match the presented binding".to_owned(),
            ));
        }
        Ok(())
    }

    /// Loads the sealed durable claim row bound to one exact claim identity
    /// (issue #1108, A4/A5 daemon row source).
    ///
    /// Sends [`PROVIDER_CAPABILITY_CLAIM_ROW_READ_OPERATION`] with only
    /// `wire_version` plus `claim_id` over the existing [`transact_async`](Self::transact_async)
    /// path, then parses the sealed reply into the seven
    /// [`OwnerLoadedClaimRow::new`] arguments (claim, attempt, operation,
    /// binding and executable digests, claiming-worker generation, fence
    /// digest). The claim identity is validated pre-transport with the same
    /// owner the Kernel read arm enforces (`eliot_ors::OperationIdentity`),
    /// and the call requires an already-validated Kernel owner session, so a
    /// row never loads without live session evidence. The transport identity
    /// minted inside `transact_async` already binds the live State Fence, so
    /// no fence bytes travel in the payload.
    ///
    /// Fail-closed, never synthesized: a missing or invalid seal digest, a
    /// reply that does not decode under `deny_unknown_fields`, a wrong kind
    /// or wire version, a claim echo that does not equal the requested lookup
    /// key, a zero read timestamp, or loaded fields that fail
    /// [`OwnerLoadedClaimRow::new`] shape validation all return typed
    /// [`KernelClientError`] failures. No row is invented from presented
    /// values — this method takes none — and no freshness or generation gate
    /// is applied here: the Kernel returns the row verbatim and those gates
    /// stay with the verifier and the downstream
    /// `AdmittedProviderFactory`, which fail closed on the exact loaded
    /// evidence.
    ///
    /// Production callers: the drive seam
    /// (`DaemonComposition::agent_fabric_new_verified_async`) and the async
    /// restore seam (`DaemonComposition::agent_fabric_restore_verified_async`)
    /// via `build_production_provider_capability` into
    /// `crate::provider_capability::admit_provider_capability`, which feeds
    /// the loaded row to `AdmittedProviderFactory::new`.
    pub(super) async fn load_provider_claim_row_async(
        &self,
        claim_id: &str,
    ) -> Result<OwnerLoadedClaimRow, KernelClientError> {
        let claim = OperationIdentity::new(claim_id)
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        self.owner_session_facts().ok_or_else(|| {
            KernelClientError::Contract(
                "provider claim-row read requires an already validated Kernel owner session"
                    .to_owned(),
            )
        })?;
        let payload = serde_json::json!({
            "wire_version": PROVIDER_CAPABILITY_WIRE_VERSION,
            "claim_id": claim.as_str(),
        });
        let response = self
            .transact_async(PROVIDER_CAPABILITY_CLAIM_ROW_READ_OPERATION, payload)
            .await?;
        let mut body = response.clone();
        let receipt_digest = body
            .as_object_mut()
            .and_then(|object| object.remove("receipt_digest"))
            .and_then(|digest| digest.as_str().map(str::to_owned))
            .ok_or_else(|| {
                KernelClientError::Unknown("Kernel claim-row reply has no sealed digest".to_owned())
            })?;
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|error| KernelClientError::Unknown(error.to_string()))?;
        if sha256_hex(&body_bytes) != receipt_digest {
            return Err(KernelClientError::Unknown(
                "Kernel claim-row reply digest is invalid".to_owned(),
            ));
        }
        let row: ProviderClaimRowReadWire = serde_json::from_value(response)
            .map_err(|error| KernelClientError::Unknown(error.to_string()))?;
        if row.kind != PROVIDER_CAPABILITY_CLAIM_ROW_KIND
            || row.wire_version != PROVIDER_CAPABILITY_WIRE_VERSION
            || row.receipt_digest != receipt_digest
            || row.claim_id != claim.as_str()
            || row.read_at_unix_ms == 0
        {
            return Err(KernelClientError::Unknown(
                "Kernel claim-row reply does not bind the requested claim".to_owned(),
            ));
        }
        OwnerLoadedClaimRow::new(
            row.claim_id,
            row.attempt_id,
            row.operation_id,
            row.binding_digest,
            row.executable_binding_digest,
            row.worker_generation,
            row.fence_digest,
        )
        .map_err(|error| KernelClientError::Unknown(error.to_string()))
    }

    /// Clones the retained validated binding string, if any. A poisoned slot
    /// reads as absent (fail-closed to "no live session"), never invented.
    pub(super) fn validated_session_binding(&self) -> Option<String> {
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
    ///
    /// I5.27: "fields affecting authority, scope, ordering, privacy or
    /// effect cannot be omitted/defaulted silently". The digest input is
    /// therefore `content` — the evaluated
    /// [`StartupEvidenceContent`](super::startup_evidence_producer::StartupEvidenceContent),
    /// which is the published payload minus exactly one field. Two
    /// publishes under the same generation that differ in any
    /// `config_mirror_digest`, `policy_mirror_digest`, capability
    /// evaluation, evidence ref or bound fence now derive different
    /// `request_id`, `idempotency_key` and `cancellation_id` values, so the
    /// Kernel can no longer resolve a second, different publish to the first
    /// one's receipt.
    ///
    /// `content` deliberately excludes `transport_binding`: the payload
    /// carries this very identity, so a digest over the full payload would
    /// be a fixed point nobody can compute. That is the one field the
    /// digest cannot cover, and it is covered by construction instead — the
    /// caller binds the identity to the same `content` value it was
    /// derived from (`bind_startup_evidence`), so the identity determines
    /// every other byte of the payload and a different payload cannot be
    /// presented under it. The bound `state_fence` is inside `content`, so
    /// a different generation or authority epoch is still a different
    /// publish, and `principal_and_scope` still carries this connection.
    /// No counter, nonce, salt, clock or hidden state participates.
    pub fn mint_startup_evidence_identity(
        &self,
        content: &super::startup_evidence_producer::StartupEvidenceContent,
    ) -> Result<RequestIdentity, super::DaemonError> {
        let canonical_content = serde_json::to_value(content)
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        self.next_identity(&CanonicalKernelRequest {
            operation: super::startup_evidence_producer::DAEMON_STARTUP_EVIDENCE_OPERATION,
            scope: &self.connection_id,
            request: &canonical_content,
        })
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
        let outcome = (|| -> Result<super::DaemonReadySupervision, super::DaemonError> {
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
        })();
        // #740 A14: owning error record at the readiness boundary, once per
        // failed operation. The pre-admission retry inside stays silent; only
        // the operation outcome records.
        if let Err(error) = &outcome {
            let _ = crate::diagnostics::ErrorRecord::of_daemon_error(error).emit();
        }
        outcome
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
        let identity = self.next_identity(&CanonicalKernelRequest {
            operation,
            scope: &self.connection_id,
            request: &payload,
        })?;
        self.transact_async_with_identity(operation, payload, identity)
            .await
    }

    /// Sends one original P-03 operation through the authenticated
    /// current-source Kernel route. The process request stays nested so its
    /// serde `operation` tag cannot collide with the daemon routing key; the
    /// original `RequestIdentity` is carried by the EBP frame and is never
    /// reconstructed from the process selector.
    #[cfg(windows)]
    pub(super) async fn execute_current_source_process(
        &self,
        request: eliot_kernel_service::ProcessExecutionRequest,
        identity: RequestIdentity,
        admitted_task_id: eliot_contracts::TaskId,
    ) -> Result<eliot_kernel_service::ProcessExecutionResponse, KernelClientError> {
        request
            .validate()
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        identity
            .validate()
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        let operation_id = request.operation_id().ok_or_else(|| {
            KernelClientError::Contract(
                "current-source process request omitted its operation identity".to_owned(),
            )
        })?;
        let binding = &identity.request;
        let current = &self.snapshot;
        if binding.metadata.task_id.as_ref() != Some(&admitted_task_id)
            || binding.metadata.request_id.as_str() != operation_id.as_str()
            || binding.state_fence != current.state_fence()
        {
            return Err(KernelClientError::Contract(
                "original request identity does not bind the current process operation and Kernel fence".to_owned(),
            ));
        }
        if let eliot_kernel_service::ProcessExecutionRequest::Start(admission) = &request
            && (admission.recipient_module_id() != current.service.as_str()
                || admission.deadline_unix_ms() != identity.deadline_unix_ms
                || admission.intent().operation_id().as_str() != operation_id.as_str()
                || !admission
                    .state_fence()
                    .authority_epoch()
                    .is_same_authority(&binding.state_fence.authority_epoch)
                || admission.state_fence().generation().get()
                    != binding.state_fence.resource_generation.value())
        {
            return Err(KernelClientError::Contract(
                "original process admission differs from its request identity".to_owned(),
            ));
        }

        let value = self
            .transact_async_with_identity(
                "execute_current_source_process",
                serde_json::json!({
                    "request": request,
                    "admitted_task_id": admitted_task_id,
                }),
                identity,
            )
            .await?;
        serde_json::from_value(value).map_err(|error| KernelClientError::Unknown(error.to_string()))
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

    /// Mints the transport operation binding for one Kernel request from the
    /// canonical request bytes plus the caller-admitted identity inputs.
    ///
    /// I5.27 requires idempotency to be defined over canonical bytes, never
    /// over a per-attempt discriminator. The binding below is therefore a
    /// pure function of `canonical_request` and `scope`: two byte-identical
    /// presentations of one operation derive the same `request_id`, the same
    /// `idempotency_key` and the same `cancellation_id`, so the Kernel binds
    /// both attempts to the one admitted operation and a retry resolves to the
    /// first attempt's receipt instead of opening a second operation. A
    /// changed payload derives a different binding, so it is never mistaken
    /// for a replay of the original.
    ///
    /// The operation name and scope are read from `canonical_request` alone,
    /// so the digest input and the emitted key labels can never disagree. No
    /// counter, nonce, salt, clock or hidden state participates.
    fn next_identity(
        &self,
        canonical_request: &CanonicalKernelRequest<'_>,
    ) -> Result<RequestIdentity, KernelClientError> {
        let operation = canonical_request.operation;
        let digest = canonical_kernel_request_digest(canonical_request)
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        let request_id = RequestId::new(format!("{}:{}:{}", self.connection_id, operation, digest))
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
            idempotency_key: format!("{SERVICE_NAME}:{operation}:{digest}"),
            deadline_unix_ms: unix_ms().saturating_add(30_000),
            // A cancellation handle addresses the admitted operation, not one
            // transport attempt, so it is derived from the same canonical
            // bytes. Deriving it from a counter would make a cancelled attempt
            // unreachable by the next attempt's cancel, which is exactly the
            // per-attempt identity I5.27 forbids.
            cancellation_id: format!("{SERVICE_NAME}:{operation}:{digest}:cancel"),
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

    /// Blocking sibling of [`store_named_async`](Self::store_named_async), for
    /// the synchronous startup attach sites that already hold the concrete
    /// client and the composition (issue #1773).
    ///
    /// Same request validation, same `"store_named"` operation, same typed
    /// response binding; only the await is bridged through the same
    /// [`Self::blocking`] helper the `receipt` / `store_recovery` templates
    /// use. This opens no second transport and no second write path: it is the
    /// one authenticated Kernel named-read route, driven synchronously.
    pub(super) fn store_named_blocking(
        &self,
        request: NamedReadRequest,
    ) -> Result<NamedReadResponse, KernelPortError> {
        let client = self.clone_for_future();
        request
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if self.snapshot.state_fence() != request.state_fence {
            return Err(KernelPortError::Contract(
                "daemon named read fence does not match the admitted snapshot".to_owned(),
            ));
        }
        let value = Self::blocking(async move {
            client
                .transact_async(
                    "store_named",
                    serde_json::json!({
                        "request": request,
                    }),
                )
                .await
        })?;
        let value = super::kind_value(&value, "store_named")?;
        let response: NamedReadResponse = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        response
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        Ok(response)
    }

    /// Claims one queued admitted `eliot.query` or Skill pair for the
    /// outbound local-read poller and local Skill dispatch (issue #1882).
    /// Skill names are exactly those recognized by
    /// `eliot_agent_bridge_core::skill_tool_kind`; every pair must have an
    /// exact tool-name/envelope-capability match.
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
            let tool_name = tool.get("name").and_then(serde_json::Value::as_str);
            !tool_name.is_some_and(|name| {
                (name == "eliot.query" || eliot_agent_bridge_core::skill_tool_kind(name).is_some())
                    && envelope.identity.capability == name
            })
        }) {
            // Issue #1839: structured route-mismatch evidence for the live
            // claim. The pair is rejected closed without execution.
            let _ = crate::diagnostics::RejectionRecord::of(
                crate::diagnostics::RejectionReason::RouteMismatch,
                crate::diagnostics::OwningComponent::Kernel,
                "Kernel local_read_claim returned a non-query pair",
            )
            .emit();
            return Err(super::DaemonError::Kernel(
                "Kernel local_read_claim returned a pair outside the local-read tools".to_owned(),
            ));
        }
        if let Some((envelope, _, attempt)) = pair.as_ref() {
            let _ = crate::diagnostics::RequestReceipt::of(
                envelope.identity.request_id.as_str(),
                &attempt.operation_id,
            )
            .emit();
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
            // Issue #1839: structured route-mismatch evidence for the live
            // claim. The pair is rejected closed without execution.
            let _ = crate::diagnostics::RejectionRecord::of(
                crate::diagnostics::RejectionReason::RouteMismatch,
                crate::diagnostics::OwningComponent::Kernel,
                "Kernel campaign_packet_claim returned a non-packet pair",
            )
            .emit();
            return Err(super::DaemonError::Kernel(
                "Kernel campaign_packet_claim returned a non-packet pair".to_owned(),
            ));
        }
        if let Some((envelope, _, attempt)) = pair.as_ref() {
            let _ = crate::diagnostics::RequestReceipt::of(
                envelope.identity.request_id.as_str(),
                &attempt.operation_id,
            )
            .emit();
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

    /// Claims one admitted selected-source capture invocation from its
    /// dedicated Kernel queue. It returns the exact original host envelope and
    /// EBP request identity without borrowing either the evidence-query or
    /// Task Controller attempt capability.
    #[cfg(windows)]
    pub async fn claim_selected_source_capture_pair_async(
        &self,
    ) -> Result<Option<SelectedSourceCaptureClaimedInvocation>, super::DaemonError> {
        let value = self
            .transact_async(
                "source_capture.claim",
                serde_json::json!({ "operation": "source_capture.claim" }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_selected_source_capture_claimed_pair(&value)
            .map_err(super::DaemonError::Kernel)
    }

    /// Stages one distinct inactive ORS reservation for the exact claimed
    /// source mutation and current Governor selection. The original request
    /// identity rides the authenticated frame unchanged; Kernel binds it to
    /// the retained HostRequest and derives proposal/reservation identities.
    #[cfg(windows)]
    pub async fn stage_selected_source_capture_async(
        &self,
        claimed: &SelectedSourceCaptureClaimedInvocation,
        selected: &eliot_governor::TaskSelectionAdmissionBinding,
        intent: eliot_kernel_service::source_capture_mutation::SelectedSourceCaptureStageIntent,
    ) -> Result<SelectedSourceCaptureStagedAdmission, super::DaemonError> {
        let expected_operation = match claimed.invocation.operation {
            eliot_protocol::SelectedSourceCaptureOperation::Diagnostics => "Diagnostics",
            eliot_protocol::SelectedSourceCaptureOperation::ProbeVersion => "ProbeVersion",
        };
        if intent.operation != expected_operation
            || intent.selected_relative_path != claimed.invocation.selected_relative_path
            || intent.selector != claimed.invocation.selector
            || intent.work_item_id.as_str() != selected.evidence_ref()
            || intent.work_lease_id != selected.selection_source_ref()
            || intent.principal_id != selected.principal_ref()
            || claimed.request_identity.request.metadata.task_id.as_ref().map(ToString::to_string)
                .as_deref()
                != Some(selected.task_ref())
            || claimed.request_identity.request.metadata.session_id.as_ref().map(ToString::to_string)
                .as_deref()
                != Some(selected.session_ref())
            || claimed.host_request_envelope.identity.work_scope_id.as_deref()
                != Some(selected.work_scope().binding.scope.scope_ref.as_str())
            || claimed.host_request_envelope.state_fence != *selected.state_fence()
        {
            return Err(super::DaemonError::Kernel(
                "source_capture.stage intent differs from the exact claim or current Governor owner selection"
                    .to_owned(),
            ));
        }
        let operation_id = eliot_protocol::host_request_operation_id(
            &claimed.host_request_envelope,
        );
        let staged_intent = intent.clone();
        let value = self
            .transact_async_with_identity(
                "source_capture.stage",
                serde_json::json!({
                    "operation_id": operation_id,
                    "request_digest": claimed.host_request_envelope.envelope_sha256,
                    "intent": intent,
                }),
                claimed.request_identity.clone(),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_selected_source_capture_staged_admission(
            &value,
            claimed,
            selected,
            &staged_intent,
        )
        .map_err(super::DaemonError::Kernel)
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
        let pair = parse_observe_claimed_pair(&value).map_err(super::DaemonError::Kernel)?;
        if let Some((envelope, _, attempt)) = pair.as_ref() {
            let _ = crate::diagnostics::RequestReceipt::of(
                envelope.identity.request_id.as_str(),
                &attempt.operation_id,
            )
            .emit();
        }
        Ok(pair)
    }

    /// Claims the next Watchdog spool export window this Kernel admitted
    /// through the authenticated `watchdog_export_submit` front-door route
    /// (issue #2899).
    ///
    /// Mirrors [`claim_observe_pair_async`](Self::claim_observe_pair_async): the
    /// call travels as the single-`operation`-key `"watchdog_export_claim"`
    /// payload and a null `batch` is the empty-queue backoff signal, not an
    /// error. The claimed window carries the Watchdog's own submitted content
    /// and every entry was re-proved against its own durable ORS row by Kernel
    /// before it was served, so `None` means "nothing pending" and never "nothing
    /// to admit".
    #[cfg(windows)]
    pub async fn claim_watchdog_export_batch_async(
        &self,
    ) -> Result<Option<eliot_watchdog_core::WatchdogSpoolExportBatch>, super::DaemonError> {
        let value = self
            .transact_async(
                "watchdog_export_claim",
                serde_json::json!({ "operation": "watchdog_export_claim" }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_watchdog_export_claimed_batch(&value).map_err(super::DaemonError::Kernel)
    }

    /// Records the Governor's own terminal dispositions for one claimed Watchdog
    /// spool export window (issue #2899).
    ///
    /// The result travels as the single-`result`-key `"watchdog_export_result"`
    /// payload and Kernel persists it through the owner's ORS result path: an
    /// identical resubmission replays to the same durable record, and a changed
    /// disposition under the same identity conflicts instead of writing a second
    /// decision. Only terminal dispositions can be submitted at all, so an
    /// undecided entry is never reported as applied.
    #[cfg(windows)]
    pub async fn submit_watchdog_export_result_async(
        &self,
        result: &eliot_protocol::WatchdogSpoolExportResultPayload,
    ) -> Result<(), super::DaemonError> {
        result
            .validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        self.transact_async(
            "watchdog_export_result",
            serde_json::json!({
                "operation": "watchdog_export_result",
                "export_result": result,
            }),
        )
        .await
        .map(|_| ())
        .map_err(|error| super::DaemonError::Kernel(error.to_string()))
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

    /// Claims one queued admitted `eliot.finish` pair and its distinct
    /// Kernel-issued attempt capability (issue #1741).
    ///
    /// Mirrors [`claim_task_controller_pair_async`](Self::claim_task_controller_pair_async):
    /// the call travels as the single-`operation`-key `"finish_claim"` payload
    /// and a null `pair` is the empty-queue backoff signal, not an error. The
    /// claimed pair carries the Kernel-minted fenced attempt capability,
    /// which the caller must present back on the submit leg.
    #[cfg(windows)]
    pub async fn claim_finish_pair_async(
        &self,
    ) -> Result<Option<FinishClaimedInvocation>, super::DaemonError> {
        let value = self
            .transact_async(
                "finish_claim",
                serde_json::json!({ "operation": "finish_claim" }),
            )
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_finish_claimed_pair(&value).map_err(super::DaemonError::Kernel)
    }

    /// Submits one daemon-produced finish result body for its waiting host
    /// request (issue #1741).
    ///
    /// Mirrors [`submit_task_controller_result_async`](Self::submit_task_controller_result_async):
    /// the body travels as the single-`result`-key `"finish_result"` payload
    /// and is validated before any transport is touched.
    #[cfg(windows)]
    pub async fn submit_finish_result_async(
        &self,
        body: &FinishResultBody,
    ) -> Result<FinishSubmitOutcome, super::DaemonError> {
        body.validate()
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        let value = self
            .transact_async("finish_result", serde_json::json!({ "result": body }))
            .await
            .map_err(|error| super::DaemonError::Kernel(error.to_string()))?;
        parse_finish_submit_outcome(&value).map_err(super::DaemonError::Kernel)
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
    /// The rebuilt body carries the daemon-observed execution evidence
    /// (issue #1838) built by [`Self::forward_local_read_evidence`].
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
        let (operation_id, body_digest, body_response, body_lineage) =
            Self::admitted_local_read_halves(admitted, &pair.envelope)?;
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
            // The retained result lineage the owner bound to this exact result
            // travels with the rebuild (issue #1809 W2). It is decoded from the
            // OWNER'S OWN retained record and re-bound here by comparing its
            // recorded `output_digest` with this row's recorded `result_digest`;
            // nothing is recomputed over the bytes in hand, which would replace
            // the owner's proof with a fresh checksum. A row that carries no
            // lineage keeps the honest `None` — unknown, never clean.
            lineage: body_lineage,
            evidence: Some(Self::forward_local_read_evidence(
                admitted,
                operation_id,
                &self.connection_id,
                &self.kernel_binding.daemon_artifact_sha256,
                &pair.envelope.envelope_sha256,
                body_digest,
            )),
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

    /// Reads the operation handle plus the digest-bound response halves from
    /// one admitted `local_read` answer, proving the admission binds the
    /// admitted envelope.
    fn admitted_local_read_halves<'a>(
        admitted: &'a serde_json::Map<String, serde_json::Value>,
        envelope: &HostRequestEnvelope,
    ) -> Result<AdmittedLocalReadHalves<'a>, KernelPortError> {
        let operation_id = admitted
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                KernelPortError::Contract(
                    "Kernel local read admission omits the operation handle".to_owned(),
                )
            })?;
        if operation_id != host_request_operation_id(envelope) {
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
        // The retained lineage is carried only when the owner actually recorded
        // one, and only when it passes the shared retained-lineage rule against
        // THIS row's recorded result digest. A lineage that names a different
        // output, claims a class its own evidence does not support, or cannot be
        // decoded at all is refused rather than adopted, and a row with no
        // lineage stays `None`.
        let body_lineage = match admitted
            .get("record")
            .and_then(|record| record.get("result_lineage"))
        {
            None | Some(serde_json::Value::Null) => None,
            Some(lineage_value) => {
                let lineage: HostRequestResultLineage =
                    serde_json::from_value(lineage_value.clone()).map_err(|error| {
                        KernelPortError::Contract(format!(
                            "Kernel local read admission carries an undecodable retained lineage: {error}"
                        ))
                    })?;
                // The SHARED retained-lineage rule, not a local digest compare:
                // it binds the recorded `output_digest` to this row's recorded
                // result digest AND refuses a class the row's own evidence does
                // not support, so an unrelated receipt reference cannot ride in
                // on a lineage whose bytes check out.
                lineage.validate_retained(body_digest).map_err(|error| {
                    KernelPortError::Contract(format!(
                        "Kernel local read admission carries a retained lineage \
that does not describe this result: {error}"
                    ))
                })?;
                Some(lineage)
            }
        };
        Ok((operation_id, body_digest, body_response, body_lineage))
    }

    /// Builds the daemon-observed execution evidence for one forwarded
    /// local read (issue #1838).
    ///
    /// Reports the invoked `local_read` operation, the actual-route receipt
    /// digest from the admission answer, the presenting connection and daemon
    /// artifact identities, the immutable input/output handles, and the
    /// observed side-effect declaration for the sealed trace manifest. A
    /// missing admission receipt leaves the actual route honestly absent
    /// instead of inventing one.
    fn forward_local_read_evidence(
        admitted: &serde_json::Map<String, serde_json::Value>,
        operation_id: &str,
        connection_id: &str,
        daemon_artifact: &str,
        envelope_digest: &str,
        result_digest: &str,
    ) -> LocalReadExecutionEvidence {
        let actual_route = admitted
            .get("receipt")
            .and_then(|receipt| receipt.get("receipt_sha256"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        LocalReadExecutionEvidence {
            wire_id: eliot_protocol::LOCAL_READ_EXECUTION_EVIDENCE_WIRE_ID.to_owned(),
            wire_version: LocalReadExecutionEvidence::CONTRACT_VERSION,
            operation_id: operation_id.to_owned(),
            invoked_operation: Some("local_read".to_owned()),
            actual_route,
            adapter_identity: Some(connection_id.to_owned()),
            executor_identity: Some(daemon_artifact.to_owned()),
            input_handle: Some(envelope_digest.to_owned()),
            output_handle: Some(result_digest.to_owned()),
            side_effects: Some(eliot_protocol::LOCAL_READ_EXECUTION_NO_SIDE_EFFECTS.to_owned()),
        }
    }

    fn clone_for_future(&self) -> Arc<Self> {
        Arc::new(Self {
            launch: self.launch.clone(),
            kernel_binding: self.kernel_binding.clone(),
            connection_id: self.connection_id.clone(),
            snapshot: self.snapshot.clone(),
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
                "mode":"verification"
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
                correlation_projection: None,
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
