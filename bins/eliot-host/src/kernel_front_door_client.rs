//! Authenticated Kernel front-door client closure.
//!
//! Architecture: `A2.2` (`docs/architecture/A02-02-roles.md`) and `A2.3`
//! (`docs/architecture/A02-03-modular-architecture.md`), plus Decision Anchors
//! `ARCH-AUTH-01`, `ARCH-SEC-02`, and `ARCH-RES-01`
//! (`docs/architecture/A16-01-decision-anchors.md`). Implementation: `I1.2`
//! (`docs/architecture/I01-02-required-processes-of-the-first-complete-runtime.md`),
//! `I1.4` (`docs/architecture/I01-04-supervision-tree.md`), and `I2.23`
//! (`docs/architecture/I02-23-capability-family-topology-and-crate-extraction-decisions.md`).
//! Normative precedence remains in `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! Host owns physical Kernel process lifecycle and authenticated connection
//! mechanics only. This module never owns Kernel or Governor semantic
//! acceptance, transition, or authority; it preserves those decisions in the
//! existing Host composition root.

use std::path::Path;
use std::time::Duration;

use eliot_contracts::{
    ArtifactId, ContractId, ContractVersion, RequestMetadata, ResourceGeneration,
};
use eliot_ipc::{NamedPipeTransport, PeerIdentity};
use eliot_kernel_service::{
    HostKernelCandidateBinding, KernelActivationReceipt, KernelControlCommand,
    KernelControlRequest, KernelControlResponse, USER_AUTOMATION_KERNEL_CAPABILITY,
    USER_AUTOMATION_KERNEL_MODULE_ID, USER_AUTOMATION_KERNEL_OPERATION,
    USER_AUTOMATION_KERNEL_PRINCIPAL_BINDING, USER_AUTOMATION_KERNEL_PRIVACY_CLASS,
    UserAutomationHostOwnerBinding,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{ProcessIdentity, observe_named_pipe_peer_process_in_job};

#[cfg(windows)]
use eliot_contracts::{canonical_json_bytes, sha256_hex};
#[cfg(windows)]
use eliot_host_service::{HostDurableJobOwner, HostDurableJobOwnerError};
#[cfg(windows)]
use eliot_ipc::{DeliveryOutcome, TransportLimits, client_hello_frame, decode_server_hello_frame};
#[cfg(windows)]
use eliot_protocol::dreamer_job::{DurableJobRequest, DurableJobResponse};
#[cfg(windows)]
use eliot_protocol::{
    ClientHello, EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
};
#[cfg(windows)]
use eliot_runtime_contracts::{
    HealthVector, ModuleContract, ModuleGeneration, ModuleGenerationState,
};

use super::{HostError, LOCAL_SERVICE_SID};
use crate::host_job_launch::LaunchPhaseCorrelation;

// F-LOG-HOST-3 (#978) Kernel front-door observation helpers.
//
// Through the #889 facade only
// (`super::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`super::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open). No terminal is owned here: the single terminal for a
// failed front-door/activation stays with the outermost #891 contour.
//
// Bounded identities, not stage order alone (audit 5910159678 defects 3 and
// 5): a call site passes a static phase token plus a `LaunchPhaseCorrelation`
// built only from identities this closure already holds — the candidate
// activation, installation and approved artifact handles, and the retained
// Kernel process start identity (PID plus start time) at handshake and
// authentication time. Nothing is re-derived, re-read or probed to obtain a
// field: an absent identity renders as the renderer's own explicit absence
// marker instead of being invented.
//
// Each key means exactly one identity across this file and its activation
// sibling. `fence` is the candidate activation identity on every call site that
// binds it — the same value `kernel_activation_driver.rs` binds from
// `record_fence(host, activation_id, activation_generation)` — and no other
// identity is ever bound into it in these two files. `operation` names the
// canonical KernelRecord operation identity, the labelled-UUID handle the driver
// binds at every transition. This file HOLDS such an identity — the owner reads
// `self.activation.operation_id` — but binds it to no slot on any path, because
// none of the closures that build a correlation is the one that holds it, and
// naming it anywhere else would mean re-deriving it. So `operation` renders as
// the explicit absence marker on EVERY call site here rather than being filled
// with the nearest identity the closure happens to hold.
//
// The Kernel authority epoch reaches no slot in these two files either, and this
// claim is deliberately SCOPED. `host_job_launch.rs`, a third instrumented file,
// binds a lineage id into `fence` at its own launch call sites, and it binds TWO
// of them: the authority-epoch lineage at some sites and the Host installation
// epoch's lineage at others. So `fence` is one identity across the activation
// pair and two different ones in the launch cell - which is a real residual
// collision and is escalated rather than papered over. The epoch is never bound
// here in ANY form: what this file used to render was the epoch as its owner's
// own lineage id PLUS sequence pair, and putting that composite into `fence` is
// exactly what made this key mean two identities. The epoch stays compared for
// real wherever it decides an owner proof.
//
// Handshake, authentication, admission and activation stay distinct phases,
// and `reason` carries the stable secret-free name of the classification this
// file already computed by branch, so a before-start refusal never shares a
// record with an unusable delivered response or an unknown binding. A `reason`
// names only what its own branch established: the `Err` arm receives an
// already-erased `HostError`, so it can name neither a disconnect nor a
// transport failure kind. Only that kind name is bound — never the Kernel's
// rejection text, a pipe or connection identity, a peer address, credential
// material, the activation nonce, an evidence handle, or arbitrary error text.
// A path is not an identity: neither the candidate pipe identity nor the
// approved or observed image path is ever bound (case 978/12). A process start
// identity is rendered as the owner's own pid/start pair, so a record
// distinguishes this process incarnation from a reusable PID. Bounding limits
// size, not sensitivity (I15.4). Sink outcome never alters
// result/order/status/cleanup. There is no mutable global dedup cache.
#[cfg(windows)]
fn kernel_front_door_note_event_log_unavailable() {
    let _ = super::windows_event_log::event_log_sink_status();
}

/// Renders one held process start identity in the owner's own `pid`/`start`
/// shape.
#[cfg(windows)]
fn front_door_process_start_identity(process_id: u32, start_time_100ns: u64) -> String {
    format!("pid:{process_id}:start:{start_time_100ns}")
}

/// The bounded identity of one reconcile decision: the secret-free kind name of
/// the outcome this file already computed, and nothing else. `None` marks a
/// decision that has not computed an outcome yet, and no outcome kind is then
/// invented for it.
///
/// The `operation` slot stays explicitly absent on every reconcile record, so
/// it renders as the renderer's own `operation=missing` marker. This helper is
/// handed nothing but a reason kind; its caller
/// `activation_response_or_reconcile` receives `expected_message_id`, which is
/// the activation id plus a sequence suffix - a per-message wire identity.
/// Across the corpus `operation` names the
/// canonical `KernelRecord` operation identity - the handle
/// `kernel_activation_driver.rs` mints as a labelled UUID pair at every
/// transition - and no closure that builds one of these correlations holds that
/// identity. Binding either the wire id or the activation id here would give the
/// key a second identity, and recovering the activation id by parsing the suffix
/// would be exactly the re-derivation this file forbids.
///
/// RECORDED LOSS, stated rather than glossed: this helper binds NO identity at
/// all - its body is `NONE` plus an optional `reason`, so these reconcile records
/// render `installation=missing generation=missing operation=missing
/// artifact=missing process_start=missing fence=missing`. The wire message
/// identity these records used to name under `operation` is therefore no longer
/// rendered anywhere, and nothing substitutes for it: `activation_response_or_reconcile`
/// receives only `expected_message_id`, never the candidate binding, so the
/// activation id cannot be bound to `fence` here either. These records are
/// identified by their phase token and typed `reason` kind alone. That is the
/// honest consequence of a frozen eight-key vocabulary that has no slot for a
/// per-message wire identity, and it is not a claim that the identity is
/// unavailable or unimportant.
#[cfg(windows)]
fn front_door_reconcile_correlation(
    reason: Option<&'static str>,
) -> LaunchPhaseCorrelation<'static> {
    let correlation = LaunchPhaseCorrelation::NONE;
    match reason {
        Some(kind) => correlation.with_reason(kind),
        None => correlation,
    }
}

#[cfg(windows)]
fn kernel_front_door_observe(phase: &str, correlation: &LaunchPhaseCorrelation<'_>) {
    kernel_front_door_note_event_log_unavailable();
    let detail = correlation.render(phase);
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::ScmDispatch,
        &detail,
    );
}

#[cfg(windows)]
pub(super) fn kernel_control_request(
    candidate: &HostKernelCandidateBinding,
    generation: ResourceGeneration,
    command: KernelControlCommand,
    sequence: u64,
) -> Result<KernelControlRequest, HostError> {
    // WORK_UNIT_CASE: 978/7 — control request built; handshake/auth material
    // stays distinct from activation, no secrets observed. The candidate
    // activation, installation and approved artifact are already in hand, and
    // the requested generation is named; the command variant has no stable name
    // accessor in its owner, so no reason kind is claimed for it. `fence` names
    // the activation identity, exactly as the activation driver binds it, so the
    // key means one identity across both files. `operation` stays ABSENT here:
    // across the corpus that key names the canonical KernelRecord operation
    // identity - the `{label}-{uuid4}` handle the driver binds at every
    // transition - and this closure is never handed one. Binding the activation
    // id under it would give the key a second identity; the activation id is
    // already carried, under `fence`.
    let correlation = LaunchPhaseCorrelation::NONE
        .with_installation(candidate.installation_id.as_str())
        .with_generation(generation.value())
        .with_artifact(candidate.artifact_hash.as_str())
        .with_fence(candidate.activation_id.as_str());
    kernel_front_door_observe("host.kernel-front-door control requested", &correlation);
    KernelControlRequest {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: PlatformHandle::new(format!("{}:{sequence}", candidate.activation_id.as_str()))
            .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        sequence,
        peer_process_id: std::process::id(),
        generation,
        candidate: candidate.clone(),
        command,
        payload_digest: String::new(),
    }
    .with_computed_digest()
    .map_err(|error| HostError::ProcessContour(error.to_string()))
}

#[cfg(windows)]
pub(super) fn activation_response_or_reconcile(
    response: Result<KernelControlResponse, HostError>,
    expected_message_id: &PlatformHandle,
    expected_request_digest: &str,
) -> Result<Option<KernelActivationReceipt>, HostError> {
    // WORK_UNIT_CASE: 978/9 - reconcile decision requested; every unsettled
    // decision reconciles as None without inventing evidence, distinct from a
    // before-start rejection below. The only identity in hand is the wire
    // message identity, and neither it nor the activation id may fill
    // `operation`, which names the canonical KernelRecord operation identity
    // corpus-wide, so the slot stays explicitly absent (see
    // `front_door_reconcile_correlation`); no outcome exists yet, so no reason
    // kind is claimed.
    kernel_front_door_observe(
        "host.kernel-front-door reconcile requested",
        &front_door_reconcile_correlation(None),
    );
    let Ok(response) = response else {
        // WORK_UNIT_CASE: 978/9 — an unusable delivered response observed as an
        // unsettled reconcile; no invented receipt, exact None propagates. The
        // only production caller (`lib.rs`) reaches this arm only after
        // `send_frame` returned `Ok(DeliveryOutcome::Delivered)`, so what
        // actually failed is the receive/decode into a typed control response,
        // and a genuine disconnect or unknown outcome never gets here — the
        // caller maps both to `None` before calling. The specific transport
        // failure kind is not recoverable either: the caller erased it into
        // `HostError::RecoveryRequired(error.to_string())`. So this arm names
        // only what it established and claims no disconnect, no timeout and no
        // transport loss.
        //
        // RETIRED here: `host.kernel-front-door disconnect observed` with
        // `reason=transport-lost`. That pair claimed a disconnect this arm can
        // never observe, which is the same false-claim class as audit defect 1.
        // The fixture pins both retired tokens under `retired_phase_tokens` so
        // the retirement is never silent, and this name survives only as prose:
        // the code below emits the honest pair instead.
        kernel_front_door_observe(
            "host.kernel-front-door unusable-response observed",
            &front_door_reconcile_correlation(Some("delivered-response-unusable")),
        );
        return Ok(None);
    };
    if response.message_id != *expected_message_id
        || response.request_digest != expected_request_digest
    {
        // WORK_UNIT_CASE: 978/9 — unknown binding observed as reconcile;
        // mismatched identity never promotes into activation.
        kernel_front_door_observe(
            "host.kernel-front-door unknown observed",
            &front_door_reconcile_correlation(Some("unknown-binding")),
        );
        return Ok(None);
    }
    if let Some(error) = response.error {
        // WORK_UNIT_CASE: 978/9 — before-start rejection observed; exact
        // rejection propagates, no secrets observed. This refusal happened
        // before any possible start, which is why it never shares a record with
        // the unusable-response arm above; the Kernel's rejection text stays out
        // of the record.
        kernel_front_door_observe(
            "host.kernel-front-door before-start observed",
            &front_door_reconcile_correlation(Some("before-start-refusal")),
        );
        return Err(HostError::ProcessContour(format!(
            "Kernel rejected Activate: {error}"
        )));
    }
    // WORK_UNIT_CASE: 978/9 — a response that carries no activation receipt is
    // observed as an unsettled reconcile, NOT as a timeout. The only condition
    // on this arm is `activation_receipt.is_none()`, so an exactly-bound,
    // error-free response that legitimately carries no receipt must not produce
    // a record claiming a failure kind the branch never observed - the same
    // mislabeling class as audit defect 1. No arm in this closure can name a
    // transport failure kind: the `Err` arm above is only reachable for a
    // delivered-but-undecodable response, and its own `TransportError` variant
    // was already erased into one `HostError` variant by the caller.
    if response.activation_receipt.is_none() {
        kernel_front_door_observe(
            "host.kernel-front-door no-receipt reconcile observed",
            &front_door_reconcile_correlation(Some("no-receipt-carried")),
        );
    } else {
        kernel_front_door_observe(
            "host.kernel-front-door activation observed",
            &front_door_reconcile_correlation(Some("activation-receipt-carried")),
        );
    }
    Ok(response.activation_receipt)
}

#[cfg(windows)]
pub(super) fn validate_authenticated_kernel_peer(
    peer: &PeerIdentity,
    expected_pid: u32,
    expected_start_time_100ns: u64,
    expected_image: &Path,
) -> Result<(), HostError> {
    // WORK_UNIT_CASE: 978/7 — auth requested; peer authentication stays
    // distinct from nonce/handshake/activation, no secrets observed. The
    // retained expected process start identity is already in hand and is named;
    // the expected image is a path, not an identity, so it is never bound.
    let expected_process_start =
        front_door_process_start_identity(expected_pid, expected_start_time_100ns);
    let correlation = LaunchPhaseCorrelation::NONE.with_process_start(&expected_process_start);
    kernel_front_door_observe("host.kernel-front-door auth requested", &correlation);
    let peer = peer.process_binding().ok_or_else(|| {
        HostError::ProcessContour("Kernel peer identity is unavailable".to_owned())
    })?;
    let observed_image = std::fs::canonicalize(peer.image_path())
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let approved_image = std::fs::canonicalize(expected_image)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if peer.process_id() != expected_pid
        || peer.start_time_100ns() != expected_start_time_100ns
        || observed_image != approved_image
    {
        return Err(HostError::ProcessContour(
            "authenticated Kernel peer is not the retained approved process".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 978/7 — authenticated peer observed; start-identity
    // (PID + start-time + image) matched, distinct from activation. The image
    // comparison proved the same retained process start identity, so the
    // record names that identity and never the image path itself.
    kernel_front_door_observe(
        "host.kernel-front-door authenticated peer observed",
        &correlation,
    );
    Ok(())
}

#[cfg(windows)]
fn kernel_front_door_expectation(
    candidate: &HostKernelCandidateBinding,
    kernel_process: &ProcessIdentity,
) -> Result<eliot_platform_windows::KernelFrontDoorServerExpectation, HostError> {
    let binding = observe_named_pipe_peer_process_in_job(
        candidate.job_object_id.as_str(),
        kernel_process.process_id,
    )
    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let observed = binding.process_binding().identity();
    if observed != kernel_process {
        return Err(HostError::ProcessContour(
            "Kernel Job observation is not the retained process identity".to_owned(),
        ));
    }
    if binding
        .process_binding()
        .executable_file_identity()
        .is_none()
    {
        return Err(HostError::ProcessContour(
            "Kernel process executable FileIdentity is unavailable".to_owned(),
        ));
    }
    let expected_extra_sid = candidate
        .agent_bridge_admission
        .as_ref()
        .map(|descriptor| descriptor.approved_user_sid.clone());
    let acl_mode = kernel_front_door_acl_mode(expected_extra_sid.as_deref());
    eliot_platform_windows::KernelFrontDoorServerExpectation::new(
        LOCAL_SERVICE_SID,
        0,
        candidate.artifact_hash.as_str(),
        acl_mode,
    )
    .map(|expectation| expectation.with_process_and_job_binding(binding))
    .map_err(|error| HostError::ProcessContour(error.to_string()))
}

#[cfg(windows)]
pub(super) fn kernel_front_door_acl_mode(
    approved_user_sid: Option<&str>,
) -> eliot_platform_windows::KernelFrontDoorAclMode {
    match approved_user_sid {
        None => eliot_platform_windows::KernelFrontDoorAclMode::ServiceOnly,
        Some(client_sid) => {
            eliot_platform_windows::KernelFrontDoorAclMode::SystemAndLocalServiceWithClient {
                client_sid: client_sid.to_owned(),
            }
        }
    }
}

#[cfg(windows)]
pub(super) async fn connect_authenticated_kernel_front_door(
    candidate: &HostKernelCandidateBinding,
    kernel_process: &ProcessIdentity,
) -> Result<NamedPipeTransport, HostError> {
    // WORK_UNIT_CASE: 978/7 — handshake requested; authenticated connect is
    // distinct from nonce issuance and activation, no secrets observed. The
    // candidate activation, installation and approved artifact plus the
    // retained Kernel process start identity are in hand and named; `fence` is
    // the activation identity, as in the activation driver, and the pipe
    // identity is a name, not an identity, so it is never bound.
    //
    // RECORDED LOSS at THIS site, one of the two places that used to bind the
    // activation id under `operation`: it does so no longer, and the slot
    // renders the renderer's explicit `operation=missing` marker. The reason is
    // the same as at the control site — `operation` names the canonical
    // KernelRecord operation identity across the corpus, and binding the
    // activation id under it gave one key two identities. Nothing is lost: the
    // activation id is carried here by `fence`, on the line below. Stated at
    // this site as well as at `kernel_control_request` so a reader of an
    // actual `host.kernel-front-door handshake requested` line meets the
    // accounting where the record is built, not only in a file header.
    let kernel_process_start = front_door_process_start_identity(
        kernel_process.process_id,
        kernel_process.start_time_100ns,
    );
    let correlation = LaunchPhaseCorrelation::NONE
        .with_installation(candidate.installation_id.as_str())
        .with_artifact(candidate.artifact_hash.as_str())
        .with_process_start(&kernel_process_start)
        .with_fence(candidate.activation_id.as_str());
    kernel_front_door_observe("host.kernel-front-door handshake requested", &correlation);
    let expected_extra_sid = candidate
        .agent_bridge_admission
        .as_ref()
        .map(|descriptor| descriptor.approved_user_sid.as_str());
    let expectation = kernel_front_door_expectation(candidate, kernel_process)?;
    let transport = NamedPipeTransport::connect_authenticated_kernel_front_door(
        candidate.pipe_identity.as_str(),
        Duration::from_secs(5),
        &expectation,
    )
    .await
    .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    match (
        transport.kernel_front_door_observed_extra_sid(),
        expected_extra_sid,
    ) {
        (None, None) => {
            // WORK_UNIT_CASE: 978/7 — handshake observed; exact transport
            // propagates unchanged.
            kernel_front_door_observe("host.kernel-front-door handshake observed", &correlation);
            Ok(transport)
        }
        (Some(observed), Some(expected)) if observed == expected => {
            // WORK_UNIT_CASE: 978/7 — handshake observed; exact transport
            // propagates unchanged. The observed extra SID matched the retained
            // bridge policy; the SID itself stays out of the record.
            kernel_front_door_observe("host.kernel-front-door handshake observed", &correlation);
            Ok(transport)
        }
        _ => Err(HostError::ProcessContour(
            "Kernel front-door extra SID does not match the retained bridge policy".to_owned(),
        )),
    }
}

/// Host-side Durable Job owner joined to the live Kernel front door.
///
/// The owner retains only the Host-approved candidate, the Kernel-authored
/// activation receipt, and the OS-observed Kernel process. Each operation
/// opens the existing authenticated front door, proves the generation-bound
/// Host session, and sends one typed Dreamer request. It never opens Store,
/// derives a job, or retries an uncertain mutation.
///
/// Task Scheduler may wake Host only from the admitted intent; the `WakeIntent`
/// itself grants no task, route, tool, effect or delivery authority.
#[cfg(windows)]
pub(super) struct HostKernelUserAutomationOwner {
    candidate: HostKernelCandidateBinding,
    activation: KernelActivationReceipt,
    kernel_process: ProcessIdentity,
    activation_digest: String,
}

#[cfg(windows)]
impl HostKernelUserAutomationOwner {
    pub(super) fn new(
        candidate: HostKernelCandidateBinding,
        activation: KernelActivationReceipt,
        kernel_process: ProcessIdentity,
    ) -> Result<Self, HostError> {
        candidate
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let candidate_digest = candidate
            .compute_digest()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if activation.candidate_binding_digest != candidate_digest
            || activation.authority_epoch != candidate.kernel_epoch
            || activation.generation.value() == 0
            || kernel_process.process_id != candidate.job_binding.root.process.process_id
            || kernel_process.start_time_100ns
                != candidate.job_binding.root.process.start_time_100ns
            || !kernel_process
                .image_path
                .eq_ignore_ascii_case(&candidate.job_binding.root.process.image_path)
        {
            return Err(HostError::ProcessContour(
                "Kernel UserAutomation owner is not bound to the retained active contour"
                    .to_owned(),
            ));
        }
        let activation_digest = sha256_hex(
            &canonical_json_bytes(&activation)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        );
        Ok(Self {
            candidate,
            activation,
            kernel_process,
            activation_digest,
        })
    }

    pub(super) fn owner_binding(&self) -> Result<UserAutomationHostOwnerBinding, HostError> {
        let candidate_binding_sha256 = self
            .candidate
            .compute_digest()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let state_fence = eliot_contracts::StateFence::new(
            self.candidate.kernel_epoch.clone(),
            self.activation.generation,
        );
        let binding = UserAutomationHostOwnerBinding {
            candidate_binding_sha256,
            activation_receipt_sha256: self.activation_digest.clone(),
            state_fence,
            expected_peer_process_id: self.kernel_process.process_id,
            expected_peer_start_time_100ns: self.kernel_process.start_time_100ns,
            expected_peer_image_path: self.kernel_process.image_path.clone(),
        };
        binding
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        Ok(binding)
    }

    fn client_hello(&self) -> Result<ClientHello, HostDurableJobOwnerError> {
        let module_id = ContractId::new(USER_AUTOMATION_KERNEL_MODULE_ID)
            .map_err(|error| owner_unavailable(error.to_string()))?;
        let artifact_id = ArtifactId::new(self.candidate.artifact_hash.as_str())
            .map_err(|error| owner_unavailable(error.to_string()))?;
        let state_fence = eliot_contracts::StateFence::new(
            self.candidate.kernel_epoch.clone(),
            self.activation.generation,
        );
        let module_contract = ModuleContract {
            module_id: module_id.clone(),
            version: ContractVersion::new(1, 0, 0),
            artifact_id: artifact_id.clone(),
            protocols: vec![
                "eliot.s03.ebp.v1".to_owned(),
                "eliot.kernel.dreamer-job.v1".to_owned(),
            ],
            capabilities: Vec::new(),
            required_capabilities: vec![USER_AUTOMATION_KERNEL_CAPABILITY.to_owned()],
            optional_capabilities: Vec::new(),
            advisory_capabilities: Vec::new(),
            state_owner: "eliot-host".to_owned(),
            failure_domain: "eliot-host-user-automation".to_owned(),
            owner: "eliot-host".to_owned(),
            hot_replace: false,
            startup_after: vec![USER_AUTOMATION_KERNEL_CAPABILITY.to_owned()],
            drain_before: vec![USER_AUTOMATION_KERNEL_CAPABILITY.to_owned()],
            invalidation_triggers: Vec::new(),
            supervision_plan: "one_for_one".to_owned(),
            child_restart: "transient".to_owned(),
            restart_intensity: "3/10m".to_owned(),
            resource_profile: "background-medium".to_owned(),
            privacy_classes: vec![USER_AUTOMATION_KERNEL_PRIVACY_CLASS.to_owned()],
            permissions: Vec::new(),
            health_contract: "health/user-automation-v1".to_owned(),
            checkpoint_contract: "checkpoint/user-automation-v1".to_owned(),
            compatibility_state: "rebuildable".to_owned(),
            independent_test_profile: "module/user-automation".to_owned(),
            contract_fixture_set: "eliot.kernel.dreamer-job.v1/user-automation".to_owned(),
            affected_test_tags: vec!["user-automation".to_owned(), "process".to_owned()],
            architecture: Vec::new(),
            telemetry: "telemetry/user-automation-v1".to_owned(),
            removal_boundary: "eliot-host-user-automation".to_owned(),
        };
        Ok(ClientHello {
            protocol_range: eliot_protocol::ProtocolRange {
                minimum: ProtocolVersion::CURRENT,
                maximum: ProtocolVersion::CURRENT,
            },
            module_bridge_identity: USER_AUTOMATION_KERNEL_MODULE_ID.to_owned(),
            artifact_hash: artifact_id.clone(),
            module_contract,
            module_generation: ModuleGeneration {
                module_id,
                generation: self.activation.generation,
                artifact_id,
                state: ModuleGenerationState::Active,
                health: HealthVector::healthy(),
                state_fence,
            },
            launch_nonce: self.activation_digest.clone(),
            capabilities: vec![USER_AUTOMATION_KERNEL_CAPABILITY.to_owned()],
            privacy_classes: vec![USER_AUTOMATION_KERNEL_PRIVACY_CLASS.to_owned()],
            max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES)
                .map_err(|error| owner_unavailable(error.to_string()))?,
            authority_epoch: self.candidate.kernel_epoch.clone(),
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_dreamer_job(
        &self,
        context: &RequestMetadata,
        request: DurableJobRequest,
    ) -> Result<DurableJobResponse, HostDurableJobOwnerError> {
        request
            .validate()
            .map_err(|error| HostDurableJobOwnerError::Rejected(error.to_string()))?;
        let request_id = request
            .request_identity
            .request
            .request
            .metadata
            .request_id
            .clone();
        let connection_id = format!(
            "host-user-automation:{}:{}",
            self.activation.operation_id.as_str(),
            request_id.as_str()
        );
        let mut transport =
            connect_authenticated_kernel_front_door(&self.candidate, &self.kernel_process)
                .await
                .map_err(|error| owner_unavailable(error.to_string()))?;
        validate_authenticated_kernel_peer(
            transport.peer_identity(),
            self.kernel_process.process_id,
            self.kernel_process.start_time_100ns,
            Path::new(self.kernel_process.image_path.as_str()),
        )
        .map_err(|error| owner_unavailable(error.to_string()))?;
        let limits = TransportLimits::default();
        let hello = self.client_hello()?;
        let hello_frame = client_hello_frame(&connection_id, &hello)
            .map_err(|error| owner_unavailable(error.to_string()))?;
        match transport
            .send_frame(&hello_frame, limits)
            .await
            .map_err(|error| owner_unavailable(error.to_string()))?
        {
            DeliveryOutcome::Delivered => {}
            DeliveryOutcome::UnknownOutcome => {
                return Err(owner_unknown(
                    "Kernel Host UserAutomation handshake delivery is unknown",
                ));
            }
        }
        let server_frame = transport
            .receive_frame(limits)
            .await
            .map_err(|error| owner_unavailable(error.to_string()))?;
        let server = decode_server_hello_frame(&server_frame, &connection_id)
            .map_err(|error| owner_unavailable(error.to_string()))?;
        let projection = server
            .config_snapshot
            .get("eliot.user_automation")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation server projection is missing")
            })?;
        let projected_privacy = projection
            .get("privacy_classes")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation privacy projection is missing")
            })?;
        let projected_capability = projection
            .get("capability")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation capability projection is missing")
            })?;
        let projected_effects = projection
            .get("effects")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation effects projection is missing")
            })?;
        let projected_candidate = projection
            .get("candidate_binding_sha256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation candidate projection is missing")
            })?;
        let projected_activation = projection
            .get("activation_receipt_sha256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation activation projection is missing")
            })?;
        let projected_connection = projection
            .get("connection_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                owner_unavailable("Kernel UserAutomation connection projection is missing")
            })?;
        let candidate_digest = self
            .candidate
            .compute_digest()
            .map_err(|error| owner_unavailable(error.to_string()))?;
        let projected_privacy_exact = projected_privacy.len() == 1
            && projected_privacy[0].as_str() == Some(USER_AUTOMATION_KERNEL_PRIVACY_CLASS);
        let projected_effects_empty = projected_effects.is_empty();
        if server.authority_epoch != self.candidate.kernel_epoch
            || server.session_principal_binding != USER_AUTOMATION_KERNEL_PRINCIPAL_BINDING
            || server.allowed_capabilities.len() != 1
            || server.allowed_capabilities[0] != USER_AUTOMATION_KERNEL_CAPABILITY
            || !server.allowed_effects.is_empty()
            || projected_capability != USER_AUTOMATION_KERNEL_CAPABILITY
            || !projected_privacy_exact
            || !projected_effects_empty
            || projected_candidate != candidate_digest
            || projected_activation != self.activation_digest
            || projected_connection != connection_id
        {
            return Err(owner_unavailable(
                "Kernel Host UserAutomation session binding is not exact",
            ));
        }

        let frame = Frame {
            protocol_version: server.selected_protocol,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: connection_id.clone(),
            request_id: Some(request_id.clone()),
            kind: FrameKind::Request,
            message_type: MessageType::Execute,
            request_identity: Some(request.request_identity.request.clone()),
            payload: ProtocolPayload::Json(serde_json::json!({
                "operation": USER_AUTOMATION_KERNEL_OPERATION,
                "context": context,
                "request": request,
            })),
            trace_context: std::collections::BTreeMap::new(),
        };
        frame
            .validate()
            .map_err(|error| HostDurableJobOwnerError::Rejected(error.to_string()))?;
        match transport
            .send_frame(&frame, limits)
            .await
            .map_err(|error| owner_unknown(error.to_string()))?
        {
            DeliveryOutcome::Delivered => {}
            DeliveryOutcome::UnknownOutcome => {
                return Err(owner_unknown(
                    "Kernel Durable Job delivery crossed an unknown boundary",
                ));
            }
        }
        let response_frame = transport
            .receive_frame(limits)
            .await
            .map_err(|error| owner_unknown(error.to_string()))?;
        if response_frame.connection_id != connection_id
            || response_frame.kind != FrameKind::Response
            || response_frame.message_type != MessageType::Result
            || response_frame.request_id.as_ref() != Some(&request_id)
        {
            return Err(owner_unknown(
                "Kernel Durable Job response correlation is not exact",
            ));
        }
        let ProtocolPayload::Json(payload) = response_frame.payload else {
            return Err(owner_unknown(
                "Kernel Durable Job response payload is invalid",
            ));
        };
        if payload.get("status").and_then(serde_json::Value::as_str) == Some("error") {
            let reason = payload
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Kernel Durable Job rejected the request")
                .to_owned();
            return Err(classify_kernel_owner_error(reason));
        }
        let response: DurableJobResponse =
            serde_json::from_value(payload).map_err(|error| owner_unknown(error.to_string()))?;
        response
            .validate_for(&request)
            .map_err(|error| HostDurableJobOwnerError::Rejected(error.to_string()))?;
        Ok(response)
    }
}

#[cfg(windows)]
impl HostDurableJobOwner for HostKernelUserAutomationOwner {
    async fn dreamer_job(
        &self,
        context: &RequestMetadata,
        request: DurableJobRequest,
    ) -> Result<DurableJobResponse, eliot_host_service::HostDurableJobOwnerError> {
        self.execute_dreamer_job(context, request).await
    }
}

#[cfg(windows)]
fn owner_unavailable(reason: impl Into<String>) -> HostDurableJobOwnerError {
    HostDurableJobOwnerError::Unavailable(reason.into())
}

#[cfg(windows)]
fn owner_unknown(reason: impl Into<String>) -> HostDurableJobOwnerError {
    HostDurableJobOwnerError::UnknownOutcome(reason.into())
}

#[cfg(windows)]
fn classify_kernel_owner_error(reason: String) -> HostDurableJobOwnerError {
    let folded = reason.to_ascii_lowercase();
    if folded.contains("unknown")
        || folded.contains("outcome")
        || folded.contains("timeout")
        || folded.contains("timed out")
        || folded.contains("fenced")
    {
        owner_unknown(reason)
    } else if folded.contains("unavailable") || folded.contains("not ready") {
        owner_unavailable(reason)
    } else {
        HostDurableJobOwnerError::Rejected(reason)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::io::Write;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use eliot_contracts::{AuthorityEpoch, EpochId, EpochLineageId, ResourceGeneration};
    use eliot_ipc::{PeerIdentity, PeerIdentityUnavailable};
    use eliot_kernel_service::{
        HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot, HostKernelCandidateBinding,
        HostProcessBinding, KERNEL_CONTROL_PIPE, KernelActivationPermit, KernelActivationReceipt,
        KernelControlCommand, KernelControlResponse, KernelServiceState, RestartBudget,
    };
    use eliot_platform::KernelActivationNonce;
    use eliot_runtime_contracts::{
        SupervisionJournalEpoch, SupervisionLeaseIncarnationBinding, canonical_observation_scope,
        canonical_wake_policy,
    };

    use super::{
        HostError, PlatformHandle, activation_response_or_reconcile, kernel_control_request,
        validate_authenticated_kernel_peer,
    };
    use crate::{TestError, TestResult};

    /// Non-sensitive marker the Kernel would have returned as its rejection
    /// text; it must never reach a diagnostic record.
    const REJECTION_CANARY: &str = "canary-rejection-payload-978";
    /// Non-sensitive marker carried by the erased transport error text of a
    /// delivered-but-unusable response.
    const TRANSPORT_CANARY: &str = "canary-transport-payload-978";

    /// Bounded facade output captured from the live instrumented closure.
    #[derive(Clone, Default)]
    struct CapturedRecords {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CapturedRecords {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `closure` under a scoped subscriber and returns what the #889
    /// facade actually emitted while it executed.
    fn captured(closure: impl FnOnce()) -> String {
        let records = CapturedRecords::default();
        let writer = records.clone();
        let bytes = {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, closure);
            records
                .bytes
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .clone()
        };
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
    }

    /// One authenticated Kernel control response carrying no optional receipt.
    fn response(
        message_id: PlatformHandle,
        request_digest: &str,
        error: Option<String>,
    ) -> KernelControlResponse {
        KernelControlResponse {
            wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
            message_id,
            request_digest: request_digest.to_owned(),
            state: KernelServiceState::Activating,
            receipt: None,
            runtime_health: None,
            activation_receipt: None,
            store_rebind_receipt: None,
            supervision_lease: None,
            runtime_lease_census: None,
            introduction_rows: None,
            error,
            payload_digest: String::new(),
        }
    }

    /// Bounded identities the launch contour really retains before it opens the
    /// front door: typed handles, epoch lineages and process facts. No secret
    /// lives here, and no path is ever used as an identity.
    const INSTALLATION: &str = "front-door-installation-978";
    const ACTIVATION: &str = "front-door-activation-978";
    const OTHER_ACTIVATION: &str = "front-door-concurrent-978";
    const ACTIVATION_OPERATION: &str = "front-door-activation-operation-978";
    const NONCE_APPEND: &str = "front-door-nonce-append-978";
    const ACTIVATION_MESSAGE: &str = "front-door-activation-message-978";
    const OTHER_ACTIVATION_MESSAGE: &str = "front-door-activation-message-978b";
    const RECONCILE_REQUESTED: &str = "phase=host.kernel-front-door reconcile requested";
    /// The honest phase the delivered-but-unusable response arm emits.
    const UNUSABLE_RESPONSE_PHASE: &str = "phase=host.kernel-front-door unusable-response observed";
    const JOB_NAME: &str = r"Local\Eliot-Host-Kernel-front-door-978";
    const HOST_IMAGE: &str = r"C:\Program Files\ELIOT\eliot-host.exe";
    const KERNEL_IMAGE: &str = r"C:\Program Files\ELIOT\eliot-kernel.exe";
    /// The approved Kernel artifact hash the candidate really carries.
    const ARTIFACT: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    /// The immutable configuration hash the candidate really carries.
    const CONFIG: &str = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
    /// The one-use activation nonce the real permit carries; it must never
    /// render, and neither must any digest derived from it.
    const NONCE_CANARY: &str = "9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e";
    /// The digest of the committed prior-Kernel disposition the permit carries.
    const PRIOR_DIGEST: &str = "d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7";
    /// The exact request digest the retained control response is bound to.
    const REPLY_DIGEST: &str = "b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4";
    const HOST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440001";
    const KERNEL_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440002";
    const GENERATION_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440003";
    const WATCHDOG_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440004";
    const HOST_EPOCH_SEQUENCE: u64 = 1;
    const KERNEL_EPOCH_SEQUENCE: u64 = 7;
    /// The retained Kernel peer process identity this contour already holds.
    const EXPECTED_PEER_PID: u32 = 4_242;
    const EXPECTED_PEER_START: u64 = 5_150;

    /// One admitted candidate binding, exactly as the launch contour retains it
    /// before the front door opens: installation, Host and Kernel authority
    /// epochs, activation identity, approved artifact and configuration hashes,
    /// Job, pipe, process and supervision incarnation. The owner's own
    /// `validate` gate runs here, so this is a genuinely consistent candidate
    /// rather than a shape that only satisfies the observation seam.
    fn candidate_binding_for(
        activation: &str,
        kernel_epoch_sequence: u64,
    ) -> Result<HostKernelCandidateBinding, TestError> {
        let kernel_sequence = std::num::NonZeroU64::new(kernel_epoch_sequence)
            .ok_or("the Kernel authority epoch sequence must be non-zero")?;
        let candidate = HostKernelCandidateBinding {
            installation_id: handle(INSTALLATION),
            host_epoch: AuthorityEpoch::new(HOST_EPOCH_SEQUENCE)?,
            kernel_epoch: EpochId::new(EpochLineageId::new(KERNEL_LINEAGE)?, kernel_sequence)?,
            activation_id: handle(activation),
            artifact_hash: handle(ARTIFACT),
            config_hash: handle(CONFIG),
            job_object_id: handle(JOB_NAME),
            pipe_identity: handle(KERNEL_CONTROL_PIPE),
            host_process: HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: HOST_IMAGE.to_owned(),
            },
            job_binding: HostJobBinding {
                job: HostJobIdentity {
                    name: JOB_NAME.to_owned(),
                },
                root: HostJobRoot {
                    process: HostProcessBinding {
                        process_id: EXPECTED_PEER_PID,
                        start_time_100ns: EXPECTED_PEER_START,
                        image_path: KERNEL_IMAGE.to_owned(),
                    },
                    executable: HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            supervision_incarnation: SupervisionLeaseIncarnationBinding {
                supervision_lease_scope_id: "eliot-supervision-scope:v1:front-door".to_owned(),
                supervision_lease_id: String::new(),
                scope_ref_digest: String::new(),
                installation_id: INSTALLATION.to_owned(),
                host_epoch: SupervisionJournalEpoch {
                    lineage_id: HOST_LINEAGE.to_owned(),
                    sequence: HOST_EPOCH_SEQUENCE,
                },
                activation_id: activation.to_owned(),
                activation_generation: SupervisionJournalEpoch {
                    lineage_id: GENERATION_LINEAGE.to_owned(),
                    sequence: 1,
                },
                kernel_generation: SupervisionJournalEpoch {
                    lineage_id: GENERATION_LINEAGE.to_owned(),
                    sequence: 1,
                },
                watchdog_epoch: SupervisionJournalEpoch {
                    lineage_id: WATCHDOG_LINEAGE.to_owned(),
                    sequence: 1,
                },
                observation_scope: canonical_observation_scope(),
                wake_policy: canonical_wake_policy(),
                predecessor: None,
            }
            .with_derived_ids()?,
            restart_budget: RestartBudget::new(1, 1)?,
            agent_bridge_admission: None,
            containment_action: None,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    /// The one-use `Activate` permit this candidate contour would really send,
    /// carrying the canary nonce whose raw material and derived digest must
    /// both stay out of every diagnostic record.
    fn activation_permit(
        candidate: &HostKernelCandidateBinding,
        generation: ResourceGeneration,
    ) -> Result<KernelActivationPermit, TestError> {
        Ok(KernelActivationPermit {
            operation_id: handle(ACTIVATION_OPERATION),
            candidate_binding_digest: candidate.compute_digest()?,
            prior_kernel_disposition_digest: PRIOR_DIGEST.to_owned(),
            journal_transaction_id: handle(NONCE_APPEND),
            journal_sequence: 4,
            generation,
            authority_epoch: candidate.kernel_epoch.clone(),
            activation_nonce: KernelActivationNonce::new(handle(NONCE_CANARY))?,
        })
    }

    /// One authenticated Kernel control response carrying the exact activation
    /// receipt its own permit would have produced.
    fn activation_response(
        message_id: PlatformHandle,
        request_digest: &str,
        activation_receipt: KernelActivationReceipt,
    ) -> KernelControlResponse {
        KernelControlResponse {
            activation_receipt: Some(activation_receipt),
            ..response(message_id, request_digest, None)
        }
    }

    // WORK_UNIT_CASE: 978/9
    #[test]
    fn reconcile_records_separate_before_start_refusal_from_an_unsettled_response() {
        let message = handle("activate-message-978");
        let digest = "a".repeat(64);

        let unusable_response = captured(|| {
            let outcome = activation_response_or_reconcile(
                Err(HostError::RecoveryRequired(TRANSPORT_CANARY.to_owned())),
                &message,
                &digest,
            );
            assert!(matches!(outcome, Ok(None)));
        });
        let mismatched = captured(|| {
            let outcome = activation_response_or_reconcile(
                Ok(response(
                    handle("other-message-978"),
                    &digest,
                    Some(REJECTION_CANARY.to_owned()),
                )),
                &message,
                &digest,
            );
            assert!(matches!(outcome, Ok(None)));
        });
        let refused = captured(|| {
            let outcome = activation_response_or_reconcile(
                Ok(response(
                    message.clone(),
                    &digest,
                    Some(REJECTION_CANARY.to_owned()),
                )),
                &message,
                &digest,
            );
            assert!(outcome.is_err());
        });
        let no_receipt = captured(|| {
            let outcome = activation_response_or_reconcile(
                Ok(response(message.clone(), &digest, None)),
                &message,
                &digest,
            );
            assert!(matches!(outcome, Ok(None)));
        });

        // A refusal that provably happened before any possible start never
        // shares a record kind with the delivered-but-unusable response the
        // only production caller can hand this arm.
        assert!(
            unusable_response.contains("reason=delivered-response-unusable"),
            "got: {unusable_response}"
        );
        assert!(
            mismatched.contains("reason=unknown-binding"),
            "got: {mismatched}"
        );
        assert!(
            refused.contains("reason=before-start-refusal"),
            "got: {refused}"
        );
        assert!(
            no_receipt.contains("reason=no-receipt-carried"),
            "got: {no_receipt}"
        );
        assert!(
            !refused.contains("reason=delivered-response-unusable"),
            "got: {refused}"
        );
        assert!(
            !unusable_response.contains("reason=before-start-refusal"),
            "got: {unusable_response}"
        );
        // No arm may claim a transport failure kind: the erased `HostError`
        // leaves no evidence that a disconnect, timeout or unknown outcome
        // occurred, so neither the retired kind nor any other such claim may be
        // emitted by the arm the transport can actually reach. The retired phase
        // token is named only in the retirement comment on the production
        // branch, never in code, and the fixture pins its retirement under
        // `retired_phase_tokens`.
        assert!(
            !unusable_response.contains("transport-lost"),
            "got: {unusable_response}"
        );
        assert!(
            unusable_response.contains(UNUSABLE_RESPONSE_PHASE),
            "got: {unusable_response}"
        );
        // Every reconcile DECISION is reached by comparing the exact expected
        // activation message identity - including the mismatched record, which
        // exists precisely because that comparison did NOT hold - and no record
        // ever renders that identity. The `operation` slot stays explicitly
        // absent: that key names the canonical KernelRecord operation identity in
        // this file and its activation sibling, so neither the wire message id
        // nor the activation id may fill it.
        // activation id may fill it.
        for records in [&unusable_response, &mismatched, &refused, &no_receipt] {
            assert!(records.contains("operation=missing"), "got: {records}");
            assert!(
                records.contains("phase=host.kernel-front-door reconcile requested"),
                "got: {records}"
            );
            assert!(
                !records.contains("activate-message-978"),
                "the wire message identity must reach no correlation slot: {records}"
            );
        }
    }

    // WORK_UNIT_CASE: 978/12
    #[test]
    fn reconcile_records_carry_no_payload_or_error_text() {
        let message = handle("activate-message-978");
        let digest = "c".repeat(64);
        let refused = captured(|| {
            let outcome = activation_response_or_reconcile(
                Ok(response(
                    message.clone(),
                    &digest,
                    Some(REJECTION_CANARY.to_owned()),
                )),
                &message,
                &digest,
            );
            assert!(outcome.is_err());
        });
        let unusable_response = captured(|| {
            let outcome = activation_response_or_reconcile(
                Err(HostError::RecoveryRequired(TRANSPORT_CANARY.to_owned())),
                &message,
                &digest,
            );
            assert!(matches!(outcome, Ok(None)));
        });
        for (records, canary) in [
            (&refused, REJECTION_CANARY),
            (&unusable_response, TRANSPORT_CANARY),
        ] {
            assert!(
                !records.contains(canary),
                "returned error text must stay out of the record: {records}"
            );
            assert!(
                !records.contains("Kernel rejected Activate"),
                "returned error text must stay out of the record: {records}"
            );
            assert!(!records.contains(digest.as_str()), "got: {records}");
        }
        assert!(
            refused.contains("phase=host.kernel-front-door before-start observed"),
            "got: {refused}"
        );
        assert!(
            unusable_response.contains(UNUSABLE_RESPONSE_PHASE),
            "got: {unusable_response}"
        );
    }

    /// Case `978/7`, extending this file's existing marked case: the live
    /// control request and the live peer gate name the identities the contour
    /// already holds, stay distinct phases, and carry no nonce, pipe, Job, image
    /// or connection string.
    ///
    /// The handshake phases stay unexecuted on purpose.
    /// `connect_authenticated_kernel_front_door` can name its correlation only
    /// after a live Kernel Job observation (`OpenJobObjectW` plus a Job
    /// membership query) and a live named-pipe connect, and this issue admits no
    /// OS call, no live pipe and no new seam. The executed calls do prove the
    /// reachable half and that no handshake or activation phase is fabricated
    /// without one.
    #[test]
    fn control_request_and_peer_gate_name_retained_identities_only() -> TestResult {
        let candidate = candidate_binding_for(ACTIVATION, KERNEL_EPOCH_SEQUENCE)?;
        let generation = ResourceGeneration::new(9)?;
        let permit = activation_permit(&candidate, generation)?;
        let nonce_digest = permit.activation_nonce_digest();
        let control = captured(|| {
            let command = KernelControlCommand::Activate(permit);
            let Ok(request) = kernel_control_request(&candidate, generation, command, 5) else {
                panic!("a retained candidate must build one real control request");
            };
            assert!(request.validate().is_ok(), "an admitted control request");
        });

        assert!(
            control.contains("phase=host.kernel-front-door control requested"),
            "got: {control}"
        );
        // `fence` names the candidate activation identity here, exactly as
        // `kernel_activation_driver.rs` binds it from
        // `record_fence(host, activation_id, activation_generation)`, so the key
        // means one identity across both instrumented files.
        for identity in [
            format!("installation={INSTALLATION}"),
            format!("generation={}", generation.value()),
            format!("artifact={ARTIFACT}"),
            format!("fence={ACTIVATION}"),
        ] {
            assert!(control.contains(&identity), "missing: {control}");
        }
        // `operation` is explicitly absent here, and must be: across the corpus
        // that key names the canonical KernelRecord operation identity, which
        // this closure is never handed. The activation id is already carried by
        // `fence` above, so nothing is lost.
        assert!(
            control.contains("operation=missing"),
            "the absent operation slot must be explicit: {control}"
        );
        assert!(
            !control.contains(&format!("operation={ACTIVATION}")),
            "the activation id must never fill the operation key: {control}"
        );
        // The Kernel authority epoch reaches no slot in THIS record: no key in the
        // frozen correlation vocabulary carries it here, and its lineage id must
        // therefore appear nowhere in the record. This is scoped to this file and
        // its activation sibling - `host_job_launch.rs` does bind an authority-epoch
        // lineage into `fence` at its own launch call sites.
        assert!(
            !control.contains(KERNEL_LINEAGE),
            "the authority epoch must reach no slot: {control}"
        );
        assert!(
            !control.contains(&format!("fence={KERNEL_LINEAGE}")),
            "the authority epoch must not be bound into fence: {control}"
        );
        for withheld in [
            NONCE_CANARY,
            &nonce_digest,
            KERNEL_CONTROL_PIPE,
            JOB_NAME,
            KERNEL_IMAGE,
            "host-control:",
        ] {
            assert!(!control.contains(withheld), "leaked: {control}");
        }

        // The composed peer carries no platform proof, so the gate must refuse
        // on that proof alone and must not reach the image comparison.
        let peer = PeerIdentity::Unavailable {
            reason: PeerIdentityUnavailable::ProviderProofNotComposed,
        };
        let mut gate = None;
        let auth = captured(|| {
            gate = Some(validate_authenticated_kernel_peer(
                &peer,
                EXPECTED_PEER_PID,
                EXPECTED_PEER_START,
                Path::new(KERNEL_IMAGE),
            ));
        });
        let gate = gate.unwrap_or_else(|| panic!("the captured gate must run once"));
        let Err(HostError::ProcessContour(refusal)) = gate else {
            panic!("the peer gate must keep its typed contour refusal");
        };
        assert_eq!(refusal.as_str(), "Kernel peer identity is unavailable");

        let expected_start = format!("pid:{EXPECTED_PEER_PID}:start:{EXPECTED_PEER_START}");
        let start_field = format!("process_start={expected_start}");
        assert!(
            auth.contains("phase=host.kernel-front-door auth requested"),
            "got: {auth}"
        );
        assert!(auth.contains(&start_field), "got: {auth}");
        assert!(!auth.contains(KERNEL_IMAGE), "got: {auth}");
        // No authentication was proven, so no authenticated phase may appear.
        assert!(!auth.contains("authenticated peer observed"), "got: {auth}");
        // Each executed call names only what it holds, never the other phase.
        assert!(!control.contains("auth requested"), "got: {control}");
        assert!(!control.contains(&start_field), "got: {control}");
        assert!(!auth.contains("control requested"), "got: {auth}");
        assert!(!auth.contains(INSTALLATION), "got: {auth}");
        for records in [&control, &auth] {
            for phase in [
                "phase=host.kernel-front-door handshake requested",
                "phase=host.kernel-front-door handshake observed",
                "phase=host.kernel-front-door activation observed",
                "phase=host.kernel-front-door before-start observed",
                "phase=host.kernel-front-door no-receipt reconcile observed",
                "phase=host.kernel-front-door unusable-response observed",
                "phase=host.kernel-front-door unknown observed",
                "phase=host.kernel-front-door reconcile requested",
            ] {
                assert!(!records.contains(phase), "invented: {records}");
            }
        }
        Ok(())
    }

    /// Case `978/7`, second executed contour: two candidate contours that differ
    /// only in identities they already hold must render different records for
    /// the same phase, so a record identifies its own contour instead of its
    /// position in a stage order.
    ///
    /// The distinguishing identity here is the activation identity, which `fence`
    /// names, matching the activation driver; `operation` cannot separate these two
    /// contours because it is the explicit absence marker on both. The Kernel
    /// authority epoch sequence also differs between these two contours but
    /// deliberately reaches no slot: its lineage id is identical for both, so it
    /// could never separate them, and binding it into `fence` is exactly what
    /// made that key mean two identities. The assertions below therefore
    /// re-anchor distinguishability on the activation identity and additionally
    /// pin that the epoch renders nowhere.
    #[test]
    fn concurrent_candidate_contours_render_distinguishable_records() -> TestResult {
        let generation = ResourceGeneration::new(9)?;
        let first = candidate_binding_for(ACTIVATION, KERNEL_EPOCH_SEQUENCE)?;
        let second = candidate_binding_for(OTHER_ACTIVATION, KERNEL_EPOCH_SEQUENCE + 1)?;
        let mut first_request = None;
        let first_out = captured(|| {
            let command = KernelControlCommand::ProbeReady;
            first_request = Some(kernel_control_request(&first, generation, command, 5));
        });
        let mut second_request = None;
        let second_out = captured(|| {
            let command = KernelControlCommand::ProbeReady;
            second_request = Some(kernel_control_request(&second, generation, command, 5));
        });
        let first_request = first_request.unwrap_or_else(|| unreachable!("captured once"));
        let second_request = second_request.unwrap_or_else(|| unreachable!("captured once"));
        assert!(first_request.is_ok(), "a real control request");
        assert!(second_request.is_ok(), "a real control request");

        // `fence` names the activation identity in both files, so two concurrent
        // candidate contours still separate on it. `operation` cannot separate
        // them here - it is the explicit absence marker on both - which is the
        // point: the key carries one meaning corpus-wide rather than becoming a
        // second place the activation id appears.
        let first_fence = format!("fence={ACTIVATION}");
        let second_fence = format!("fence={OTHER_ACTIVATION}");
        assert!(first_out.contains(&first_fence), "{first_out}");
        assert!(second_out.contains(&second_fence), "{second_out}");
        assert!(!second_out.contains(&first_fence), "{second_out}");
        assert!(!first_out.contains(&second_fence), "{first_out}");
        for records in [&first_out, &second_out] {
            assert!(
                records.contains("operation=missing"),
                "operation must stay the explicit absence marker: {records}"
            );
        }
        assert_ne!(first_out, second_out, "one contour per record");
        // The shared Kernel authority epoch lineage reaches no slot on either
        // contour, so the two records differ only by identities they hold.
        for records in [&first_out, &second_out] {
            assert!(
                !records.contains(KERNEL_LINEAGE),
                "the authority epoch must reach no slot: {records}"
            );
        }
        Ok(())
    }

    /// Case `978/9`, extending this file's existing marked case: a settled
    /// activation is distinguishable from every unsettled response and from a
    /// before-start refusal, and the request record that precedes the decision
    /// names no outcome at all.
    ///
    /// No arm here can name a transport failure kind, and that is a property of
    /// the seam rather than of this in-crate fixture. The only production caller
    /// invokes this closure solely when `send_frame` already returned
    /// `Ok(DeliveryOutcome::Delivered)`, so a genuine disconnect or an
    /// `UnknownOutcome` is mapped to `None` before the call and never reaches
    /// it. What does reach the `Err` arm is a delivered response the caller could
    /// not receive or decode into a typed control response, and the caller had
    /// already erased the `TransportError` variant into
    /// `HostError::RecoveryRequired(error.to_string())` on the way. So that arm
    /// records `delivered-response-unusable` and claims no disconnect, timeout
    /// or transport loss; separating those kinds would need the caller's error
    /// taxonomy or a new seam here, both outside this issue.
    #[test]
    // One frozen contour per outcome keeps the case readable; splitting it would
    // only move the same assertions, not add any.
    #[allow(
        clippy::too_many_lines,
        reason = "one frozen activation contour executed against every reachable outcome"
    )]
    fn settled_activation_is_distinct_from_unsettled_and_refused_outcomes() -> TestResult {
        let candidate = candidate_binding_for(ACTIVATION, KERNEL_EPOCH_SEQUENCE)?;
        let generation = ResourceGeneration::new(9)?;
        let permit = activation_permit(&candidate, generation)?;
        let receipt = KernelActivationReceipt::issue(&permit);
        let message = handle(ACTIVATION_MESSAGE);
        let mut settled = Ok(None);
        let settled_records = captured(|| {
            settled = activation_response_or_reconcile(
                Ok(activation_response(
                    message.clone(),
                    REPLY_DIGEST,
                    receipt.clone(),
                )),
                &message,
                REPLY_DIGEST,
            );
        });
        let mut unsettled = Ok(None);
        let unsettled_records = captured(|| {
            unsettled = activation_response_or_reconcile(
                Ok(response(message.clone(), REPLY_DIGEST, None)),
                &message,
                REPLY_DIGEST,
            );
        });
        let mut refused = Ok(None);
        let refused_records = captured(|| {
            refused = activation_response_or_reconcile(
                Ok(response(
                    message.clone(),
                    REPLY_DIGEST,
                    Some(REJECTION_CANARY.to_owned()),
                )),
                &message,
                REPLY_DIGEST,
            );
        });
        let mut unusable = Ok(None);
        let unusable_records = captured(|| {
            unusable = activation_response_or_reconcile(
                Err(HostError::RecoveryRequired(TRANSPORT_CANARY.to_owned())),
                &message,
                REPLY_DIGEST,
            );
        });
        let mut mismatched = Ok(None);
        let mismatched_records = captured(|| {
            mismatched = activation_response_or_reconcile(
                Ok(response(
                    handle(OTHER_ACTIVATION_MESSAGE),
                    REPLY_DIGEST,
                    None,
                )),
                &message,
                REPLY_DIGEST,
            );
        });

        let carried = settled.unwrap_or_else(|error| panic!("settled: {error}"));
        assert_eq!(carried, Some(receipt), "the settled receipt");
        assert!(matches!(unsettled, Ok(None)), "{unsettled:?}");
        assert!(refused.is_err(), "{refused:?}");
        assert!(matches!(unusable, Ok(None)), "{unusable:?}");
        assert!(matches!(mismatched, Ok(None)), "{mismatched:?}");

        // Every outcome carries exactly its own kind, so a settled activation
        // never shares a record with an unsettled response or a refusal.
        let kinds = [
            "delivered-response-unusable",
            "unknown-binding",
            "before-start-refusal",
            "no-receipt-carried",
            "activation-receipt-carried",
        ];
        let arms = [
            (&settled_records, "activation-receipt-carried"),
            (&unsettled_records, "no-receipt-carried"),
            (&refused_records, "before-start-refusal"),
            (&unusable_records, "delivered-response-unusable"),
            (&mismatched_records, "unknown-binding"),
        ];
        for (records, own) in arms {
            for other in kinds {
                if other != own {
                    let field = format!("reason={other}");
                    assert!(!records.contains(&field), "{field} in {records}");
                }
            }
            let own_field = format!("reason={own}");
            assert!(records.contains(&own_field), "{own_field} in {records}");
            // The wire message identity is matched, never recorded.
            // Neither the wire message identity nor the activation id may fill
            // `operation`, which names the canonical KernelRecord operation
            // identity corpus-wide, so that slot stays explicitly absent on
            // every reconcile record.
            assert!(records.contains("operation=missing"), "{records}");
            assert!(
                !records.contains(ACTIVATION_MESSAGE),
                "the wire message identity must reach no correlation slot: {records}"
            );
            assert!(
                !records.contains(OTHER_ACTIVATION_MESSAGE),
                "the wire message identity must reach no correlation slot: {records}"
            );
        }

        // The request record precedes the decision, so it names no outcome kind.
        let every = [
            &settled_records,
            &unsettled_records,
            &refused_records,
            &unusable_records,
            &mismatched_records,
        ];
        for records in every {
            let requested = records
                .lines()
                .find(|line| line.contains(RECONCILE_REQUESTED))
                .unwrap_or_else(|| panic!("no request record: {records}"));
            for kind in kinds {
                assert!(!requested.contains(kind), "{kind} before the decision");
            }
        }
        Ok(())
    }
}
