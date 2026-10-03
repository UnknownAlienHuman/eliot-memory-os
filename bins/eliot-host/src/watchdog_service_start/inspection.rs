//! Read-only installed Watchdog registration selection and runtime inspection.
//!
//! Architecture anchors: `A8` (Watchdog) and `ARCH-WDG-01` (independent
//! supervision). Implementation anchors: `I1.2` (Host SCM lifecycle), `I1.4`
//! (SCM supervision tree), and `I8.2` (independent observation routes).
//!
//! This child owns only approved request selection and read-only registration
//! inspection; it has no authority to register, start, stop, or replace the
//! Watchdog service.

use std::path::Path;

use eliot_platform_windows::ServiceBootstrapArguments;

use super::super::{
    ApprovedGenerationRegistry, CandidateManifest, ELIOT_HOST_SERVICE_NAME,
    ELIOT_WATCHDOG_SERVICE_NAME, HostError, InstallationProfile,
    InstallerServiceRegistrationApproval, InstallerServiceRole, PlatformHandle, ProcessIdentity,
    RuntimeLaunchDescriptor, ServiceAccount, ServiceRegistrationRequest,
    ServiceRegistrationRuntimeInspection, ServiceStartMode, ServiceState, WindowsPlatform,
    phase_b_scm_selector, windows_paths_equal,
};

use super::super::watchdog_publication::HostWatchdogObservation;

// F-LOG-HOST-4 (#979) inspection helpers.
//
// One closed typed observation per boundary. This child fills the shared
// `HostWatchdogObservation` record declared once in `watchdog_publication` and
// emits it through the #889 facade: the record bounds each identity with
// `host_diagnostics::bound_field` and emits through the re-exported `info!` at
// `host_diagnostics::HOST_DIAGNOSTICS_TARGET`, with the sink disposition noted
// through the shared bounded observer (`note_event_log_sink_status`, over
// #984's landed safe port). The phase is a short static token and every
// identity travels in its own slot beside an explicit `*_missing` flag, so a
// record names the exact boundary and the exact identities it already held
// instead of one family-wide sentence that any concurrent start attempt could
// also produce.
//
// Observation-only contract: every helper projects facts the semantic owner has
// already produced and never re-derives one — no protected file is re-read, no
// descriptor is re-hashed, and no extra SCM probe runs to enrich a record. A
// slot carries only nonsecret material this child already owns: the
// installation identity, the approved generation handle or transaction-plan
// generation, the approved image digest, the canonical service registration
// name, the observed SCM state, the SCM wait hint, and the observed process
// PID/start-time pair. The SCM wait hint is a RELATIVE duration in
// milliseconds, so it rides in `scm_wait_hint`; `deadline_basis` carries the
// start path's ABSOLUTE injected-clock deadline and stays explicitly
// unavailable in this child, so one identity never names two incomparable
// deadline values. A registration nonce, credential, signed lease byte,
// raw image or config path, environment value, source/user/model payload and
// arbitrary error text never enter a slot, and a slot this boundary does not
// hold stays explicitly unavailable rather than being filled with a sentence,
// so bounding limits size, not sensitivity: `host_diagnostics::bound_field`
// bounds bytes only, so this caller must pass nonsecret material.
//
// Slot honesty in this child: the approved image digest is held only where the
// approved launch descriptor is in scope, so the registration-inspection
// boundaries below — which hold a canonical service name, the installation id
// and transaction-plan generation of their own bootstrap, and a binary PATH,
// never an image digest — leave `approved_image` explicitly unavailable instead
// of receiving a raw path or a digest invented here. Those boundaries do hold
// the installation identity, and they hold it from that same bootstrap rather
// than from a launch epoch: a bootstrap-less registration leaves the slot
// explicitly unavailable instead of borrowing another boundary's installation.
// The `StateFence` this child reads off the launch descriptor is a
// structural fence with no owner-issued digest and no canonical text form, so
// `state_fence` stays explicitly unavailable rather than gaining a digest
// scheme composed at the record. No publication digest, ORS receipt digest,
// lease identity, lease state, activation identity, supervision disposition,
// publication disposition, start-attempt identity or start-attempt
// disposition is held anywhere in this child, so those slots always render
// `*_missing = true`.
//
// Sink outcome never alters result/order/status/cleanup. There is no mutable
// global dedup cache and no terminal guard here: the single designated
// terminal per failed operation stays with the outer #891/#893 operation that
// owns the failure decision. These records correlate by the identities they
// carry rather than by stage order alone, and they never emit a terminal. A
// bare `?` on an already-observed inner boundary propagates without a second
// record.

/// Emits one inspection boundary record through the #889 facade.
///
/// The sink disposition is observed through the facade's canonical bounded
/// observer and the typed record then emits itself at the shared diagnostics
/// target. Observation only: this record never changes a result, an order, a
/// gate decision, a deadline or a cleanup step, and it is never a terminal
/// emission.
#[cfg(windows)]
fn watchdog_inspection_observe(observation: &HostWatchdogObservation, phase: &'static str) {
    observation.emit(phase);
}

/// Closed projection of one observed SCM state onto its exact static token.
///
/// `ServiceState` carries no owner-issued text form and this child may not
/// invent one, so the reported variant name is the whole token. It names only
/// the state the platform already observed and never implies a heartbeat,
/// authenticated readiness or independent supervision (I01.10, I14.20).
#[cfg(windows)]
const fn inspection_scm_state(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Unknown => "unknown",
        ServiceState::Absent => "absent",
        ServiceState::Stopped => "stopped",
        ServiceState::Starting => "starting",
        ServiceState::Running => "running",
        ServiceState::Stopping => "stopping",
        ServiceState::Failed => "failed",
    }
}

/// Fills the process PID/start-time identity slot from the pair this boundary
/// already holds.
///
/// The owner issues no digest of that pair, so the two validated numbers are
/// projected as they are, in the platform owner's own `windows-pid:…:start:…`
/// spelling so a diagnostic pair stays comparable with the owner's process
/// identity. [`ProcessIdentity::stable_key`] is deliberately not used: it is a
/// raw string that also embeds the image path, and a raw image path never
/// enters a diagnostic slot.
#[cfg(windows)]
fn bind_process_start(observation: &mut HostWatchdogObservation, process: &ProcessIdentity) {
    let ProcessIdentity {
        process_id,
        start_time_100ns,
        ..
    } = *process;
    observation.set_process_start(&format!(
        "windows-pid:{process_id}:start:{start_time_100ns}"
    ));
}

/// Builds the record prefix every registration-inspection boundary holds: the
/// canonical service registration name of the request the caller passed, plus
/// the installation identity and the immutable transaction-plan generation
/// bound to that same registration's bootstrap.
///
/// Both bootstrap identities come from the registration's own immutable
/// bootstrap arguments, one call from `registration.service_name()`, exactly as
/// the start path projects them from the same registration. A bootstrap-less
/// registration holds neither, so both slots stay explicitly unavailable, which
/// is the absent identity rather than a substituted one — in particular the
/// installation slot is never borrowed from a launch epoch this boundary does
/// not hold. Without that installation id a record would be uncorrelatable,
/// because `service_identity` here is the machine-global Watchdog service name.
/// The registration's binary path is never projected into `approved_image`, and
/// no image digest is hashed at the record.
#[cfg(windows)]
fn registration_observation(registration: &ServiceRegistrationRequest) -> HostWatchdogObservation {
    let mut observation = HostWatchdogObservation::default();
    observation.set_service_identity(registration.service_name());
    if let Some(bootstrap) = registration.bootstrap() {
        observation.set_installation(bootstrap.installation_id());
        observation.set_approved_generation(&bootstrap.transaction_plan_generation().to_string());
    }
    observation
}

/// Builds the record prefix the approval boundary holds: the installation
/// identity and the approved image digest of the launch under examination, the
/// generation bound to the approval itself, and the canonical service name once
/// a registration request has been reconstructed from that approval.
///
/// The approved image digest is read off the launch descriptor for the
/// inspected role. Before the request is reconstructed there is no canonical
/// service name to report, so that slot stays explicitly unavailable.
#[cfg(windows)]
fn approval_observation(
    launch: &RuntimeLaunchDescriptor,
    approval: &InstallerServiceRegistrationApproval,
    role: InstallerServiceRole,
    request: Option<&ServiceRegistrationRequest>,
) -> HostWatchdogObservation {
    let mut observation = HostWatchdogObservation::default();
    observation.set_installation(launch.installation_epoch.installation.as_str());
    observation.set_approved_generation(approval.generation().as_str());
    observation.set_approved_image(match role {
        InstallerServiceRole::Host => launch.host_artifact_digest.as_str(),
        InstallerServiceRole::Watchdog => launch.watchdog_artifact_digest.as_str(),
    });
    if let Some(request) = request {
        observation.set_service_identity(request.service_name());
    }
    observation
}

/// Builds the record prefix the Watchdog selection boundary holds: the
/// candidate launch's installation identity and approved Watchdog image digest,
/// plus the canonical Watchdog registration name this child selects.
///
/// The approved candidate generation is set per boundary, because the selection
/// branches report the generation they looked up while the selected branch
/// reports the generation bound to the approval it actually holds.
#[cfg(windows)]
fn watchdog_selection_observation(launch: &RuntimeLaunchDescriptor) -> HostWatchdogObservation {
    let mut observation = HostWatchdogObservation::default();
    observation.set_installation(launch.installation_epoch.installation.as_str());
    observation.set_approved_image(launch.watchdog_artifact_digest.as_str());
    observation.set_service_identity(ELIOT_WATCHDOG_SERVICE_NAME);
    observation
}

#[cfg(windows)]
pub fn approved_service_registration_request(
    launch: &RuntimeLaunchDescriptor,
    approval: &InstallerServiceRegistrationApproval,
    role: InstallerServiceRole,
    expected_image: &PlatformHandle,
) -> Result<ServiceRegistrationRequest, HostError> {
    // Role and generation are two independent binding facts, evaluated in the
    // order the combined condition already used, and each rejection speaks for
    // itself: one shared phase could not separate "wrong role, generation
    // matches" from "wrong role and a stale generation".
    if approval.role() != role {
        let observation = approval_observation(launch, approval, role, None);
        // WORK_UNIT_CASE: 979/4 — approval bound to another role, never used.
        watchdog_inspection_observe(&observation, "approval_role_rejected");
        return Err(HostError::ProcessContour(
            "SCM registration approval does not match the approved runtime launch".to_owned(),
        ));
    }
    if approval.generation() != &launch.generation {
        let mut observation = approval_observation(launch, approval, role, None);
        // The one generation slot carries the generation this boundary
        // REQUESTED, so the record names the generation the launch asked for
        // rather than only the one the approval carried. No role slot exists on
        // the record, so the role/generation split is carried by the phase token
        // and by this branch being reachable only after the role match above.
        observation.set_approved_generation(launch.generation.as_str());
        watchdog_inspection_observe(&observation, "approval_generation_rejected");
        return Err(HostError::ProcessContour(
            "SCM registration approval does not match the approved runtime launch".to_owned(),
        ));
    }
    let request = approval.service_registration_request().map_err(|error| {
        let observation = approval_observation(launch, approval, role, None);
        // WORK_UNIT_CASE: 979/4 — approval not reconstructible, never used.
        watchdog_inspection_observe(&observation, "approval_unreadable");
        HostError::Installation(error)
    })?;
    let expected_name = match role {
        InstallerServiceRole::Host => ELIOT_HOST_SERVICE_NAME,
        InstallerServiceRole::Watchdog => ELIOT_WATCHDOG_SERVICE_NAME,
    };
    if request.service_name() != expected_name
        || request.binary_path() != Path::new(expected_image.as_str())
        || request.start_mode() != ServiceStartMode::Automatic
        || request.account() != ServiceAccount::LocalService
    {
        let observation = approval_observation(launch, approval, role, Some(&request));
        // WORK_UNIT_CASE: 979/4 — non-canonical reconstruction, never used.
        watchdog_inspection_observe(&observation, "approval_non_canonical");
        return Err(HostError::ProcessContour(
            "SCM registration approval reconstructed a non-canonical service request".to_owned(),
        ));
    }
    let bootstrap = request.bootstrap().ok_or_else(|| {
        let observation = approval_observation(launch, approval, role, Some(&request));
        // WORK_UNIT_CASE: 979/4 — bootstrap absent, never used.
        watchdog_inspection_observe(&observation, "approval_bootstrap_absent");
        HostError::ProcessContour(
            "SCM registration approval did not reconstruct a typed bootstrap".to_owned(),
        )
    })?;
    let expected_descriptor_digest = phase_b_scm_selector(&launch.authority_descriptor_digest)
        .map_err(|error| {
            let observation = approval_observation(launch, approval, role, Some(&request));
            // WORK_UNIT_CASE: 979/1 — Phase-B SCM selector boundary.
            watchdog_inspection_observe(&observation, "selector_unavailable");
            HostError::Installation(error)
        })?;
    if bootstrap.config_descriptor_path() != Path::new(launch.authority_descriptor_path.as_str())
        || bootstrap.config_descriptor_digest() != expected_descriptor_digest.as_str()
        || bootstrap.installation_id() != launch.installation_epoch.installation.as_str()
        || bootstrap.host_state_root()
            != Some(Path::new(
                launch.runtime_state_roots.host_state_root.as_str(),
            ))
        || bootstrap.registration_nonce().is_none()
    {
        let observation = approval_observation(launch, approval, role, Some(&request));
        // WORK_UNIT_CASE: 979/4 — inexact bootstrap binding, never used.
        watchdog_inspection_observe(&observation, "approval_bootstrap_inexact");
        return Err(HostError::ProcessContour(
            "SCM registration approval bootstrap is not exact".to_owned(),
        ));
    }
    // `transaction_plan_generation` is the immutable SCM selector minted in
    // Phase A. The live ORS authority generation may advance in Phase B, so
    // callers must bind that value through the Host receipt before admission.
    let observation = approval_observation(launch, approval, role, Some(&request));
    // WORK_UNIT_CASE: 979/4 — approval admitted with exact registration identity.
    watchdog_inspection_observe(&observation, "approval_admitted");
    Ok(request)
}

#[cfg(windows)]
pub fn select_watchdog_approval_for_inspection(
    registry: &ApprovedGenerationRegistry,
    manifest: &CandidateManifest,
) -> Result<Option<InstallerServiceRegistrationApproval>, HostError> {
    if manifest.runtime_launch.profile != InstallationProfile::SystemService {
        let mut observation = watchdog_selection_observation(&manifest.runtime_launch);
        observation.set_approved_generation(manifest.runtime_launch.generation.as_str());
        // WORK_UNIT_CASE: 979/4 — non-service profile needs no Watchdog approval.
        watchdog_inspection_observe(&observation, "non_service_profile");
        return Ok(None);
    }
    let approval = registry
        .service_registration_approval(
            &manifest.runtime_launch.generation,
            InstallerServiceRole::Watchdog,
        )
        .ok_or_else(|| {
            let mut observation = watchdog_selection_observation(&manifest.runtime_launch);
            observation.set_approved_generation(manifest.runtime_launch.generation.as_str());
            // WORK_UNIT_CASE: 979/4 — Watchdog SCM approval absent, never selected.
            watchdog_inspection_observe(&observation, "approval_absent");
            HostError::ProcessContour(
                "approved generation is missing the installer-owned Watchdog SCM approval"
                    .to_owned(),
            )
        })?;
    // `?` propagates the already-observed inner approval boundary; no second record.
    approved_service_registration_request(
        &manifest.runtime_launch,
        approval,
        InstallerServiceRole::Watchdog,
        &manifest.runtime_launch.watchdog_executable_path,
    )?;
    let mut observation = watchdog_selection_observation(&manifest.runtime_launch);
    observation.set_approved_generation(approval.generation().as_str());
    // WORK_UNIT_CASE: 979/4 — Watchdog approval selected with exact identity.
    watchdog_inspection_observe(&observation, "approval_selected");
    Ok(Some(approval.clone()))
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstalledWatchdogRuntimeInspection {
    Matching {
        state: ServiceState,
        wait_hint_ms: u32,
        process: Option<ProcessIdentity>,
    },
    Absent,
    Mismatched,
    Unknown,
}

#[cfg(windows)]
pub trait InstalledWatchdogControl {
    /// Host startup has only this read-only capability.
    fn inspect_registration_runtime(
        &mut self,
        request: &ServiceRegistrationRequest,
    ) -> InstalledWatchdogRuntimeInspection;
}

#[cfg(windows)]
impl InstalledWatchdogControl for WindowsPlatform {
    fn inspect_registration_runtime(
        &mut self,
        request: &ServiceRegistrationRequest,
    ) -> InstalledWatchdogRuntimeInspection {
        match self.inspect_service_registration_runtime(request) {
            ServiceRegistrationRuntimeInspection::Matching { observation } => {
                InstalledWatchdogRuntimeInspection::Matching {
                    state: observation.state(),
                    wait_hint_ms: observation.wait_hint_ms(),
                    process: observation.process().cloned(),
                }
            }
            ServiceRegistrationRuntimeInspection::Absent => {
                InstalledWatchdogRuntimeInspection::Absent
            }
            ServiceRegistrationRuntimeInspection::Mismatched => {
                InstalledWatchdogRuntimeInspection::Mismatched
            }
            ServiceRegistrationRuntimeInspection::Unknown { .. } => {
                InstalledWatchdogRuntimeInspection::Unknown
            }
        }
    }
}

#[cfg(windows)]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "read-only Watchdog inspection remains covered by the production-bound service tests"
    )
)]
pub fn require_running_watchdog<C>(
    control: &mut C,
    registration: &ServiceRegistrationRequest,
) -> Result<(), HostError>
where
    C: InstalledWatchdogControl,
{
    match control.inspect_registration_runtime(registration) {
        InstalledWatchdogRuntimeInspection::Matching {
            state: ServiceState::Running,
            wait_hint_ms,
            process,
        } => {
            let mut observation = registration_observation(registration);
            observation.set_scm_state(inspection_scm_state(ServiceState::Running));
            // The SCM wait hint is a RELATIVE duration in milliseconds, so it
            // rides in its own slot; `deadline_basis` belongs to the start
            // path's ABSOLUTE injected-clock deadline.
            observation.set_scm_wait_hint(&wait_hint_ms.to_string());
            if let Some(process) = process.as_ref() {
                bind_process_start(&mut observation, process);
            }
            // SCM `Running` here is liveness evidence only: no heartbeat is
            // read, no admitted supervision epoch is validated and no
            // readiness is proven by this layer.
            // WORK_UNIT_CASE: 979/5 — SCM Running readback observed, never readiness.
            watchdog_inspection_observe(&observation, "readback_scm_running_liveness_only");
            Ok(())
        }
        InstalledWatchdogRuntimeInspection::Matching {
            state,
            wait_hint_ms,
            process,
        } => {
            let mut observation = registration_observation(registration);
            observation.set_scm_state(inspection_scm_state(state));
            observation.set_scm_wait_hint(&wait_hint_ms.to_string());
            if let Some(process) = process.as_ref() {
                bind_process_start(&mut observation, process);
            }
            // WORK_UNIT_CASE: 979/5 — SCM readback is not Running, never readiness.
            watchdog_inspection_observe(&observation, "readback_scm_not_running");
            Err(HostError::RecoveryRequired(format!(
                "canonical EliotWatchdog service is not Running (observed {state:?})"
            )))
        }
        InstalledWatchdogRuntimeInspection::Absent => {
            // The readback classified the registration as absent without
            // reporting a service state, so the observed-state slot stays
            // explicitly unavailable instead of carrying the verdict itself.
            let observation = registration_observation(registration);
            // WORK_UNIT_CASE: 979/5 — registration absent, never Running.
            watchdog_inspection_observe(&observation, "readback_registration_absent");
            Err(HostError::Platform(
                "canonical EliotWatchdog service is not registered; installer/SCM must register both LocalService siblings before starting Host"
                    .to_owned(),
            ))
        }
        InstalledWatchdogRuntimeInspection::Mismatched => {
            // Same as above: a mismatched registration reports no observed
            // state, so the record carries only what the registration itself
            // binds — canonical service name plus its bootstrap installation id
            // and plan generation — and nothing about the live service.
            let observation = registration_observation(registration);
            // WORK_UNIT_CASE: 979/5 — registration mismatched, never Running.
            watchdog_inspection_observe(&observation, "readback_registration_mismatched");
            Err(HostError::Platform(
                "canonical EliotWatchdog service registration does not match the approved configuration"
                    .to_owned(),
            ))
        }
        InstalledWatchdogRuntimeInspection::Unknown => {
            // An unauthoritative readback observed no state at all; the record
            // says so through the missing flag rather than through prose.
            let observation = registration_observation(registration);
            // WORK_UNIT_CASE: 979/7 — registration unknown, preserved verbatim.
            watchdog_inspection_observe(&observation, "readback_registration_unknown");
            Err(HostError::Platform(
                "canonical EliotWatchdog service registration is not authoritatively observable"
                    .to_owned(),
            ))
        }
    }
}

#[cfg(windows)]
/// SCM-liveness incarnation of the independently SCM-managed Watchdog
/// sibling: the approval path bound the registration to the approved
/// generation/image/bootstrap, and the readback path observed that same
/// registration `Running` with a handle-bound, image-matched process.
///
/// This is SCM liveness only. It is NOT independent-supervision evidence:
/// this layer never reads the Watchdog-owned heartbeat projection
/// (authority state, coverage flag, admitted epoch pair) and never validates
/// any admitted supervision epoch, because no Host-to-Watchdog heartbeat
/// transport exists at SCM-start time and the watchdog may not have admitted
/// any lease yet (pre-activation). Callers must never treat this value as
/// supervised coverage; supervision is proven only by the Kernel `ProbeReady`
/// watchdog-branch gate (exact admitted-epoch equality on the renewed ORS
/// head) plus the exact-lease evidence ref, with governance held degraded
/// until a proven-ready transition. No Host-side heartbeat validator exists:
/// the admitted ORS snapshot carries lease currency (epoch pair, validity
/// window) but no heartbeat recency (no authority state, coverage flag,
/// tick interval, or last-beat timestamp). Heartbeat recency arrives only
/// through the Host-to-Watchdog pipe transport: the Watchdog-owned
/// `WatchdogReadiness` projection plus the Host-recorded receive time,
/// consumed exclusively as the derived `HostObservedWatchdogHeartbeat`
/// (see `watchdog_heartbeat`), with the admission failing closed without
/// a fresh admitted beat. SCM `Running` therefore never implies a fresh
/// heartbeat. `approved_plan_generation` is the
/// approval binding only (the immutable transaction-plan generation that
/// authorized this exact registration), never a supervision epoch. `None`
/// only for bootstrap-less registrations, which the production approval path
/// never produces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedWatchdogScmRunning {
    pub process: ProcessIdentity,
    pub wait_hint_ms: u32,
    pub approved_plan_generation: Option<u64>,
}

#[cfg(windows)]
/// Verifies one already-observed SCM readback as a live, approved Watchdog
/// SCM incarnation, returning the approval binding plus `Running`
/// responsiveness evidence.
///
/// Read-only: performs no SCM inspection itself and owns no start/stop,
/// registration, Job, or kill-handle capability — it only classifies the
/// approval/readback pair the caller already holds. Any unverifiable branch
/// (non-`Running` state, absent process identity, unusable PID/start handle,
/// or substituted image) fails closed with the same typed vocabulary as
/// [`require_running_watchdog`]. A successful return proves SCM liveness of
/// the approved image only; it never proves independent supervision (no
/// heartbeat is read, no admitted epoch is validated).
///
/// Every branch emits exactly one typed observation record naming the
/// installation identity and the canonical service registration identity that
/// the same registration's bootstrap binds — both explicitly unavailable for a
/// bootstrap-less registration — together with the observed SCM state, the
/// transaction-plan generation bound to the registration and the RELATIVE SCM
/// wait hint in its own `scm_wait_hint` slot. The exact process PID/start-time
/// pair joins the record only on the two branches reached after a process
/// identity was bound: `verify_scm_not_running` and
/// `verify_process_identity_absent` return before any pair is held, so on those
/// two branches nothing distinguishes two concurrent incarnations of one
/// registration and they do share one identical record. `approved_image` and
/// `deadline_basis` stay explicitly unavailable here: this boundary holds a
/// registration and a binary path, not an approved image digest, and holds no
/// absolute injected-clock deadline.
pub fn verify_watchdog_scm_running(
    registration: &ServiceRegistrationRequest,
    state: ServiceState,
    wait_hint_ms: u32,
    process: Option<&ProcessIdentity>,
) -> Result<VerifiedWatchdogScmRunning, HostError> {
    let mut observation = registration_observation(registration);
    observation.set_scm_state(inspection_scm_state(state));
    // Relative wait hint, never the absolute deadline: see the slot note on
    // `require_running_watchdog`.
    observation.set_scm_wait_hint(&wait_hint_ms.to_string());
    if state != ServiceState::Running {
        // WORK_UNIT_CASE: 979/5 — SCM readback is not Running, never liveness.
        watchdog_inspection_observe(&observation, "verify_scm_not_running");
        return Err(HostError::RecoveryRequired(format!(
            "canonical EliotWatchdog service is not Running (observed {state:?})"
        )));
    }
    let Some(observed) = process else {
        // No process identity was observed, so the PID/start slot stays
        // explicitly unavailable instead of naming an incarnation this
        // boundary never held.
        // WORK_UNIT_CASE: 979/5 — Running without process identity, never liveness.
        watchdog_inspection_observe(&observation, "verify_process_identity_absent");
        return Err(HostError::RecoveryRequired(
            "Watchdog reached Running without a handle-bound process identity".to_owned(),
        ));
    };
    bind_process_start(&mut observation, observed);
    if observed.process_id == 0
        || observed.start_time_100ns == 0
        || !windows_paths_equal(Path::new(&observed.image_path), registration.binary_path())
    {
        // WORK_UNIT_CASE: 979/4 — unusable or substituted process identity, never liveness.
        watchdog_inspection_observe(&observation, "verify_process_identity_rejected");
        return Err(HostError::RecoveryRequired(
            "Watchdog process identity is unusable or its image is not the approved image"
                .to_owned(),
        ));
    }
    // The validated identities above reach the record instead of a shape
    // label. SCM `Running` plus a usable PID/start pair whose image equals the
    // approved registration path is liveness evidence only: this record claims
    // no heartbeat, no authenticated readiness and no independent supervision
    // (see [`VerifiedWatchdogScmRunning`]).
    // WORK_UNIT_CASE: 979/5 — SCM liveness verified; never supervision evidence.
    watchdog_inspection_observe(&observation, "verify_scm_running_liveness_verified");
    Ok(VerifiedWatchdogScmRunning {
        process: observed.clone(),
        wait_hint_ms,
        approved_plan_generation: registration
            .bootstrap()
            .map(ServiceBootstrapArguments::transaction_plan_generation),
    })
}
