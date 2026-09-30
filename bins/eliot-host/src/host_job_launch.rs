//! Host physical launch cell — approved physical path/digest/environment, suspended launch, Windows Job containment, identity-before-resume, Store-then-Kernel ordering, and liveness cleanup.
//! Architecture `ARCH-MOD-01` Small living Kernel, `ARCH-MOD-02` Depth is additive and micro-modular, `ARCH-PORT-01` Organs and execution contours are replaceable.
//! Implementation `I1.2` Host owns approved artifacts and `HostInstallationEpoch`, `I1.4` physical start-stop of two isolated Job branches (`Host-owned Kernel Job Object` / `Host-owned canonical-store Job Object`, `KILL_ON_JOB_CLOSE`), `I1.11` Store starts before Kernel readiness (`launch_store_then_kernel`), `I10.8.2` suspended launch plus Job assignment plus exact image identity before resume (`SuspendedJobChild::spawn_named` + `validate` + `resume`), `I2.23` this module is a micro-module only (`CrateExtractionDecision`).
//! Forbidden: no semantic, canonical, Kernel, Governor, Surreal SDK, SCM, or Watchdog authority; no default, retry, or adoption.

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::path::{Path, PathBuf};

#[cfg(windows)]
use eliot_contracts::StateFence;
#[cfg(windows)]
use eliot_host_service::{
    AdmittedCollisionOperation, ForeignOccupantRecoveryDirective, ManagedTreeObservation,
    PlannedEndpoint, PlannedEndpointOccupant,
};
#[cfg(windows)]
use eliot_host_state::HostInstallationEpoch;
#[cfg(windows)]
use eliot_installation::{
    InstallationProfile, RuntimeLaunchDescriptor, verify_file_digest_with_lease,
    verify_file_digest_with_user_lease,
};
#[cfg(windows)]
use eliot_kernel_service::semantic_store_config_hash_from_json;
#[cfg(windows)]
use eliot_platform::PlatformHandle;
#[cfg(windows)]
use eliot_platform_windows::{
    JobObjectIdentity, JobObjectLimits, PinnedRuntimeFile, RunningJobChild, SuspendedJobChild,
    SuspendedLaunchSpec, TcpListenerOwnerError, UserOwnedRootLease,
    observe_loopback_tcp_listener_owner,
    profile_supervision::{
        ProfileRootPaths, ProfileRootRequest, ProfileSelection, ProfileSelectionReceipt,
    },
};

#[cfg(windows)]
use super::{
    BranchLiveness, HostError, HostJobBranches, KernelLaunchBinding,
    validate_eliotd_launch_descriptor, validate_store_bootstrap_descriptor,
};
#[cfg(windows)]
use crate::launch_artifact::{
    LaunchLease, approved_locator, open_launch_lease, verify_launch_digest,
};
#[cfg(windows)]
use crate::store_kernel_launch_sequence::{
    StoreKernelLaunchError, StoreLivenessEvidence, launch_store_then_kernel,
};

// F-LOG-HOST-3 (#978) launch observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`,
// `observe_terminal_error`); the Event Log seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never image names,
// paths, digests, argv, env, handles, or arbitrary error text — so bounding
// limits size, not sensitivity (I15.4). Sink outcome never alters
// result/order/count/handle/cleanup/timeout. There is no mutable global dedup
// cache: one terminal emission per failed launch-owned operation is enforced
// by the single outermost guard (`start_approved` owns `host-launch-failed`),
// while inner phases correlate by stage order only. Typed rejections stay
// `HostError::ProcessContour`/`RecoveryRequired` (cases 978/2/978/3);
// admitted launches are distinct from readiness (case 978/4 — admitted here
// is never readiness, which stays with the readiness contour).
#[cfg(windows)]
fn host_launch_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn host_launch_observe(detail: &str) {
    host_launch_note_event_log_unavailable();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

#[cfg(windows)]
fn host_launch_observe_terminal(code: &str) {
    host_launch_note_event_log_unavailable();
    crate::host_diagnostics::observe_terminal_error(code);
}

/// Single-terminal guard for one physical launch operation.
///
/// Armed on entry; the single outermost boundary (`start_approved`) disarms on
/// success. Any `Err` return (explicit or via `?`) drops armed and emits
/// exactly one terminal record with the operation's frozen code. Emitting here
/// never changes the `Result`: the guard only observes the already-produced
/// outcome. No dedup cache, no lock, no second evaluation. This mirrors the
/// `HostTerminalGuard` model in `lib.rs` (F-LOG-HOST-1, #891) without touching
/// it.
#[cfg(windows)]
struct HostLaunchTerminalGuard<'a> {
    code: &'a str,
    armed: bool,
}

#[cfg(windows)]
impl<'a> HostLaunchTerminalGuard<'a> {
    fn armed(code: &'a str) -> Self {
        Self { code, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(windows)]
impl Drop for HostLaunchTerminalGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            host_launch_observe_terminal(self.code);
        }
    }
}

/// Verifies that the executable and config locators resolve to the exact
/// approved canonical paths before any suspended spawn.
///
/// Callers pass locators already resolved through `approved_locator`, so the
/// locator and the approved handle must canonicalize to the same verbatim
/// path; anything else is a substitution, not a spelling variant. Digest and
/// lease verification stay with the caller: this check binds paths, not
/// bytes. The future shared-executor adapter reuses this exact gate before
/// resume; it never replaces it with a caller-supplied hash comparison.
#[cfg(windows)]
fn approved_launch_paths(
    executable: &Path,
    approved_executable_path: &PlatformHandle,
    config_path: &Path,
    approved_config_path: &PlatformHandle,
) -> Result<(), HostError> {
    // WORK_UNIT_CASE: 978/1 — approved paths requested.
    host_launch_observe("host.launch approved paths requested");
    let approved_executable = std::fs::canonicalize(executable).map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        host_launch_observe("host.launch approved paths typed rejection");
        HostError::ProcessContour(error.to_string())
    })?;
    let approved_executable_canonical =
        std::fs::canonicalize(Path::new(approved_executable_path.as_str())).map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch approved paths typed rejection");
            HostError::ProcessContour(error.to_string())
        })?;
    if approved_executable != executable || approved_executable_canonical != approved_executable {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        host_launch_observe("host.launch substitution preserved");
        return Err(HostError::ProcessContour(
            "executable locator is not the approved path".to_owned(),
        ));
    }
    let approved_config = std::fs::canonicalize(config_path).map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        host_launch_observe("host.launch approved paths typed rejection");
        HostError::ProcessContour(error.to_string())
    })?;
    let approved_config_canonical = std::fs::canonicalize(Path::new(approved_config_path.as_str()))
        .map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch approved paths typed rejection");
            HostError::ProcessContour(error.to_string())
        })?;
    if approved_config != config_path || approved_config_canonical != approved_config {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        host_launch_observe("host.launch substitution preserved");
        return Err(HostError::ProcessContour(
            "config locator is not the approved path".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 978/1 — approved paths admitted, distinct from rejection.
    host_launch_observe("host.launch approved paths admitted");
    Ok(())
}

/// Extracts the planned loopback TCP endpoint from the canonical Store
/// arguments (the `--bind` flag). The endpoint must be present exactly once,
/// use the separate flag/value form, be a nonzero port, and be loopback.
///
/// Issue #1775: the planned endpoint is persisted in the approved launch
/// descriptor; this helper reads it back without inventing a default.
#[cfg(windows)]
pub(super) fn planned_store_endpoint(
    canonical_store_arguments: &[PlatformHandle],
) -> Result<std::net::SocketAddr, HostError> {
    let mut bind_value = None;
    for (index, argument) in canonical_store_arguments.iter().enumerate() {
        let argument = argument.as_str();
        if argument.starts_with("--bind=") {
            return Err(HostError::ProcessContour(
                "canonical Store --bind must use one separate flag and value".to_owned(),
            ));
        }
        if argument == "--bind" && bind_value.is_some() {
            return Err(HostError::ProcessContour(
                "canonical Store arguments contain ambiguous --bind flags".to_owned(),
            ));
        }
        if argument == "--bind" {
            bind_value = Some(canonical_store_arguments.get(index + 1).ok_or_else(|| {
                HostError::ProcessContour("canonical Store --bind value is missing".to_owned())
            })?);
        }
    }

    let bind_value = bind_value.ok_or_else(|| {
        HostError::ProcessContour("canonical Store --bind endpoint is missing".to_owned())
    })?;
    let endpoint = bind_value
        .as_str()
        .parse::<std::net::SocketAddr>()
        .map_err(|error| {
            HostError::ProcessContour(format!(
                "canonical Store --bind endpoint is invalid: {error}"
            ))
        })?;
    if endpoint.port() == 0 || !endpoint.ip().is_loopback() {
        return Err(HostError::ProcessContour(
            "canonical Store --bind endpoint must be loopback with a nonzero port".to_owned(),
        ));
    }
    Ok(endpoint)
}

/// One bounded, neutral observation of the planned Store endpoint's listener.
///
/// I3.4 requires that readiness be derived from multiple orthogonal
/// observations and "never one boolean, PID, port or cached declaration". A
/// `Result<Option<u32>, _>` collapses that into two facts, and the caller then
/// reads the empty `None` as a clean absence. This type keeps the three real
/// facts apart:
///
/// * [`StoreEndpointObservation::Absent`] — the read *completed* and reported
///   no listener for this exact endpoint. This is the only clean-absence fact.
/// * [`StoreEndpointObservation::Occupied`] — the read *completed* and reported
///   exactly one listener owner process.
/// * [`StoreEndpointObservation::Unreadable`] — the read did **not** produce a
///   trustworthy answer, so occupancy is unknown rather than absent.
///
/// "The owner could not be read" and "there is no owner" are different facts
/// and no caller may collapse them. `Unreadable` is deliberately not an
/// `Err`: a failed read is an observation outcome to be recorded and refused
/// on, not a thrown defect that reads like a malformed launch contour.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StoreEndpointObservation {
    /// The read completed and no listener owns this exact endpoint.
    Absent,
    /// The read completed and exactly one process owns this exact endpoint.
    Occupied {
        /// Observed owner process ID. Observation data only: it is never an
        /// ownership proof and never authorizes a control effect on its own.
        owner_process_id: u32,
    },
    /// The read did not yield a trustworthy answer. Occupancy is *unknown*,
    /// never absent.
    Unreadable {
        /// Exact platform classification of why the read is untrustworthy.
        /// Retained so the refusal names the real reason instead of prose.
        reason: TcpListenerOwnerError,
    },
}

/// Observes whether one exact loopback TCP endpoint currently has a listener
/// owner, keeping "no listener" and "owner unreadable" as distinct facts.
///
/// Issue #1775: this is a read-only observation. It never kills, adopts, or
/// reuses the occupying process, and it grants no ownership to any listener.
/// Inability to read the owner is not absence of a collision; the caller
/// refuses on `Unreadable` rather than proceeding.
#[cfg(windows)]
pub(super) fn store_endpoint_foreign_occupant(
    endpoint: std::net::SocketAddr,
) -> StoreEndpointObservation {
    match observe_loopback_tcp_listener_owner(endpoint) {
        Ok(observation) => StoreEndpointObservation::Occupied {
            owner_process_id: observation.process_id(),
        },
        // The only genuine absence: the bounded table read completed and held
        // no row for this exact endpoint.
        Err(TcpListenerOwnerError::Missing) => StoreEndpointObservation::Absent,
        // Every other classification — denied, ambiguous, raced, malformed,
        // oversized, unsupported or otherwise unclassifiable — means the read
        // itself was untrustworthy. None of them is evidence of absence.
        Err(reason) => StoreEndpointObservation::Unreadable { reason },
    }
}

/// Identity this installation holds for one planned Store endpoint.
///
/// Threaded into the collision path so a typed directive can be built from
/// facts the site actually holds, rather than from a free-form string. Every
/// field is the *approved* identity: nothing here is inferred from a listener,
/// a name, a path or a port.
#[cfg(windows)]
pub(super) struct StoreEndpointOwnershipBinding<'a> {
    /// Installation identity that planned and owns this endpoint.
    pub(super) installation: &'a PlatformHandle,
    /// Managed generation that planned this endpoint.
    pub(super) generation: &'a PlatformHandle,
    /// Authority fence under which the endpoint was planned and observed.
    pub(super) state_fence: &'a StateFence,
}

/// Observes the planned Store endpoint and refuses launch when it is occupied
/// by anything this installation has not proven it owns.
///
/// This is the fresh-start posture: the caller carries no retained child, so
/// a collision records [`AdmittedCollisionOperation::FreshDependencyStart`].
/// Owned-reconnect callers that proved a retained owned child must use
/// [`ensure_store_endpoint_available_or_owned`] instead, so the directive
/// records [`AdmittedCollisionOperation::OwnedReconnect`].
///
/// The listener owner PID is observation data only; it does not prove that the
/// process is part of this installation. The returned directive preserves that
/// boundary and authorizes no termination, adoption, reuse, or credential
/// attachment.
#[cfg(windows)]
pub(super) fn ensure_store_endpoint_available(
    canonical_store_arguments: &[PlatformHandle],
    binding: &StoreEndpointOwnershipBinding<'_>,
) -> Result<(), HostError> {
    ensure_store_endpoint_available_or_owned(canonical_store_arguments, None, binding)
}

/// Checks a pre-recovery endpoint while the retained, independently verified
/// old Store child may still own its listener. The caller must prove the old
/// child's Job membership and committed predecessor binding before passing
/// its PID; this observation grants no ownership to any other listener. A
/// degenerate retained claim (PID 0) and a corrupt owner observation (PID 0)
/// each fail closed before any admission or directive.
///
/// A preflight port check is not sufficient on its own: the occupant can
/// change between this read and the real connection. This function therefore
/// never treats the endpoint as free-and-therefore-safe on the strength of a
/// single observation. It only classifies what it saw; the launch itself is
/// still admitted solely through the suspended-launch identity proof in
/// [`HostJobBranches::launch`], and a collision refuses the launch outright
/// rather than degrading into a second, trivially-passing check.
#[cfg(windows)]
pub(super) fn ensure_store_endpoint_available_or_owned(
    canonical_store_arguments: &[PlatformHandle],
    retained_old_child_pid: Option<u32>,
    binding: &StoreEndpointOwnershipBinding<'_>,
) -> Result<(), HostError> {
    let endpoint = planned_store_endpoint(canonical_store_arguments).inspect_err(|_error| {
        host_launch_observe("host.launch store endpoint configuration rejected");
    })?;

    // Issue #1775: the directive records the operation this caller actually
    // attempted. A caller that proved a retained owned child is attempting an
    // owned reconnect on that proof; a caller with no retained child is
    // attempting a fresh start. Recording the wrong operation would let a
    // proof obtained for one class be read as permission for another (I3.4),
    // so the posture is bound here from the caller's own proof, never
    // defaulted inside the directive.
    let admitted_operation = if retained_old_child_pid.is_some() {
        AdmittedCollisionOperation::OwnedReconnect
    } else {
        AdmittedCollisionOperation::FreshDependencyStart
    };

    // Issue #1775 (A-stale): a degenerate retained claim fails before any
    // observation is admitted or directed. PID 0 is never a real child
    // process, so a caller projecting its exact-identity proof to PID 0
    // proves no retained child; admitting it on a free endpoint would let an
    // unproven caller proceed toward termination and relaunch. The production
    // reconnect caller refuses a zero PID before calling, so this fires only
    // on caller error, never on a genuine owned reconnect.
    if retained_old_child_pid == Some(0) {
        host_launch_observe("host.launch retained child identity degenerate");
        return Err(HostError::ProcessContour(
            "retained owned child has no observable process identity".to_owned(),
        ));
    }

    match store_endpoint_foreign_occupant(endpoint) {
        // Issue #1775 (A-stale): PID 0 can never own a socket, so an owner
        // observation of PID 0 is corrupt rather than an occupant. It is
        // refused as an untrustworthy read instead of being recorded into a
        // directive or admitted against the retained child; a corrupt read is
        // not absence, so the start/reconnect defers.
        StoreEndpointObservation::Occupied {
            owner_process_id: 0,
        } => {
            host_launch_observe("host.launch store endpoint owner unobservable");
            Err(HostError::StoreEndpointOwnerUnreadable(format!(
                "planned Store endpoint {endpoint} owner observation is not a real process; a corrupt read is not absence, so the start/reconnect defers until exact installation ownership is observable"
            )))
        }
        StoreEndpointObservation::Occupied { owner_process_id }
            if Some(owner_process_id) == retained_old_child_pid =>
        {
            // The caller proved this exact PID is the retained child of *this*
            // Job through committed predecessor binding, so the read agrees
            // with retained identity rather than contradicting it. It still
            // grants no ownership beyond that retained child.
            host_launch_observe("host.launch retained store endpoint owner observed");
            Ok(())
        }
        StoreEndpointObservation::Occupied { owner_process_id } => {
            host_launch_observe("host.launch store endpoint collision observed");
            // #1775: the real detector now produces the typed directive from an
            // actual observation, not a prose string. `origin` is deliberately
            // `Unknown`: a listener PID on the planned endpoint proves
            // neither managed-tree nor shared-substrate membership, and a name,
            // port or endpoint response can never establish control. I3.3
            // admits only inspection/import or a separately admitted alternate
            // endpoint, so the next-action set is read-only by construction.
            // The directive is bound to the operation this caller attempted
            // (`admitted_operation` above), never a defaulted one.
            //
            // The occupant is left RUNNING. Nothing here terminates, kills,
            // authenticates against, adopts, reuses or migrates from it.
            Err(HostError::OriginCollisionUnproven(Box::new(
                store_endpoint_collision_directive(
                    endpoint,
                    Some(owner_process_id),
                    retained_old_child_pid,
                    admitted_operation,
                    binding,
                )?,
            )))
        }
        StoreEndpointObservation::Absent => {
            host_launch_observe("host.launch store endpoint free");
            Ok(())
        }
        StoreEndpointObservation::Unreadable { reason } => {
            // A read that FAILED is not a read that SUCCEEDED WITH AN EMPTY
            // ANSWER. I3.3 requires verifying the owning lineage "before every
            // start/reconnect"; an unreadable owner leaves that unverified, so
            // the launch DEFERS rather than proceeding on a clean-absence
            // reading that was never established.
            host_launch_observe("host.launch store endpoint owner unreadable");
            Err(HostError::StoreEndpointOwnerUnreadable(format!(
                "planned Store endpoint {endpoint} owner could not be read ({reason}); a failed read is not absence, so the start/reconnect defers until exact installation ownership is observable"
            )))
        }
    }
}

/// Builds the typed foreign-occupant recovery directive for one observed
/// foreign occupant of the planned Store endpoint.
///
/// Everything passed here is what this site actually holds: the endpoint read
/// back from the approved launch descriptor, the observed owner process ID
/// (or `None` when the owner could not be read), the retained owned child PID
/// the caller proved through Job membership and committed predecessor binding,
/// the operation that caller attempted on that proof, the managed generation
/// from the approved descriptor, and the installation's own authority state
/// fence.
///
/// The result is a directive, never an effect: it names the blocked control
/// operations, the exact missing ownership evidence and the one safe next
/// action, and it grants nothing. The occupant is left running.
#[cfg(windows)]
fn store_endpoint_collision_directive(
    endpoint: std::net::SocketAddr,
    observed_owner_process_id: Option<u32>,
    retained_owned_process_id: Option<u32>,
    admitted_operation: AdmittedCollisionOperation,
    binding: &StoreEndpointOwnershipBinding<'_>,
) -> Result<ForeignOccupantRecoveryDirective, HostError> {
    let observed_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| {
            HostError::ProcessContour(format!(
                "system clock is before the Unix epoch; collision evidence cannot be timestamped: {error}"
            ))
        })?
        .as_millis();
    let observed_at_unix_ms = u64::try_from(observed_at_unix_ms).map_err(|_error| {
        HostError::ProcessContour(
            "collision observation timestamp exceeds the representable range".to_owned(),
        )
    })?;
    if observed_at_unix_ms == 0 {
        return Err(HostError::ProcessContour(
            "collision observation timestamp is zero".to_owned(),
        ));
    }

    // The authority fence is the one the approved launch descriptor already
    // carries (`RuntimeLaunchDescriptor::authority_state_fence`), not one
    // synthesised here, and the directive validates it. Deriving a fresh fence
    // would let a collision be described against a generation this
    // installation never approved, and the generation handle is an opaque
    // identity rather than a parseable counter, so a derived fence would be a
    // fabrication that also made this typed directive unreachable on a real
    // descriptor. An invalid approved fence fails closed inside the directive.
    let occupant = PlannedEndpointOccupant {
        planned_endpoint: PlannedEndpoint {
            host: endpoint.ip().to_string(),
            port: endpoint.port(),
        },
        installation: binding.installation.clone(),
        generation: binding.generation.clone(),
        state_fence: binding.state_fence.clone(),
        observed_owner_process_id,
        retained_owned_process_id,
        observed_at_unix_ms,
    };

    // #1775: the real detector produces the one typed directive family from an
    // actual observation, not a prose string. The origin is deliberately
    // `UNKNOWN`: a listener PID on the planned endpoint proves neither
    // managed-tree nor shared-substrate membership, and a name, port or endpoint
    // response can never establish control, so shared-runtime membership can
    // never silently become exclusive ownership. I3.3 admits only
    // read-only inspection or a separately admitted alternate endpoint, so the
    // permitted set is read-only by construction and `admit` is the only
    // conversion point from a requested operation to a disposition. The
    // admitted operation is the caller's own attempted operation, passed in
    // rather than defaulted, so the record never re-labels an owned reconnect
    // as a fresh start.
    //
    // The occupant is left RUNNING. Nothing here terminates, kills,
    // authenticates against, adopts, reuses or migrates from it.
    ForeignOccupantRecoveryDirective::for_observed_endpoint_occupant(
        admitted_operation,
        occupant,
        ManagedTreeObservation::Unavailable,
    )
    .map_err(|error| {
        HostError::ProcessContour(format!(
            "planned Store endpoint collision evidence is invalid: {error}"
        ))
    })
}

/// Builds the exact Kernel child argv by injecting the Host-approved
/// digest-bound Doctor executable path into the sealed launch descriptor's
/// stored `kernel_arguments`.
///
/// The stored descriptor carries the 22-value contour (digests only); the
/// Kernel requires the 24-value contour with `--doctor-executable-path`
/// bound immediately after `--doctor-artifact-sha256`. The path comes from
/// the sealed installation manifest (never caller bytes); a relative or
/// empty path fails closed, never defaulted. An already-injected contour
/// or a missing doctor digest also fails closed instead of replacing live
/// authority.
#[cfg(windows)]
pub(super) fn kernel_arguments_with_doctor_anchor(
    kernel_arguments: &[PlatformHandle],
    doctor_executable_path: &PlatformHandle,
) -> Result<Vec<PlatformHandle>, HostError> {
    const DOCTOR_DIGEST_FLAG: &str = "--doctor-artifact-sha256";
    const DOCTOR_PATH_FLAG: &str = "--doctor-executable-path";
    // WORK_UNIT_CASE: 978/1 — doctor anchor requested.
    host_launch_observe("host.launch doctor anchor requested");
    if kernel_arguments
        .iter()
        .any(|argument| argument.as_str() == DOCTOR_PATH_FLAG)
    {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        host_launch_observe("host.launch doctor anchor typed rejection");
        return Err(HostError::ProcessContour(
            "Kernel launch contour already carries a Doctor path anchor".to_owned(),
        ));
    }
    if !Path::new(doctor_executable_path.as_str()).is_absolute() {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        host_launch_observe("host.launch doctor anchor typed rejection");
        return Err(HostError::ProcessContour(
            "Doctor executable path anchor must be absolute".to_owned(),
        ));
    }
    let path_flag = PlatformHandle::new(DOCTOR_PATH_FLAG).map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        host_launch_observe("host.launch doctor anchor typed rejection");
        HostError::ProcessContour(error.to_string())
    })?;
    let mut injected = Vec::with_capacity(kernel_arguments.len().saturating_add(2));
    let mut index = 0;
    let mut anchored = false;
    while index < kernel_arguments.len() {
        let argument = kernel_arguments[index].clone();
        injected.push(argument.clone());
        if argument.as_str() == DOCTOR_DIGEST_FLAG {
            let digest = kernel_arguments.get(index + 1).cloned().ok_or_else(|| {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                host_launch_observe("host.launch doctor anchor typed rejection");
                HostError::ProcessContour(
                    "Kernel launch contour is missing the digested doctor role".to_owned(),
                )
            })?;
            injected.push(digest);
            injected.push(path_flag.clone());
            injected.push(doctor_executable_path.clone());
            index = index.saturating_add(2);
            anchored = true;
            continue;
        }
        index = index.saturating_add(1);
    }
    if !anchored {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        host_launch_observe("host.launch doctor anchor typed rejection");
        return Err(HostError::ProcessContour(
            "Kernel launch contour is missing the digested doctor role".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 978/1 — doctor anchor admitted, exact count preserved.
    host_launch_observe("host.launch doctor anchor admitted");
    Ok(injected)
}

#[cfg(windows)]
impl HostJobBranches {
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the ordered suspended-launch inputs are separate authority bindings and must remain explicit"
    )]
    pub(super) fn launch(
        executable: &Path,
        executable_lease: &LaunchLease,
        identity: &JobObjectIdentity,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        artifact: &PlatformHandle,
        config_path: &Path,
        config_lease: &LaunchLease,
        approved_executable_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        _config_pin: &PinnedRuntimeFile,
        host: &HostInstallationEpoch,
        arguments: &[eliot_platform::PlatformHandle],
        working_directory: &Path,
        kernel_launch_binding: Option<&KernelLaunchBinding>,
        receipt_binding: Option<(&Path, &Path, &Path, &PlatformHandle)>,
        installation_profile: Option<InstallationProfile>,
        profile_root_binding: Option<(&ProfileRootRequest, &ProfileSelectionReceipt)>,
    ) -> Result<RunningJobChild<PlatformHandle>, HostError> {
        // WORK_UNIT_CASE: 978/1 — launch requested, distinct from process/readiness.
        // WORK_UNIT_CASE: 978/4 — request precedes process identity and admitted launch.
        host_launch_observe("host.launch requested");
        if executable_lease.path() != executable || config_lease.path() != config_path {
            // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
            host_launch_observe("host.launch substitution preserved");
            return Err(HostError::ProcessContour(
                "launch locator is not bound to its retained protected file".to_owned(),
            ));
        }
        if let Some((request, expected_selection)) = profile_root_binding {
            let retained =
                eliot_platform_windows::profile_supervision::open_profile_root_leases(request)
                    .map_err(|error| {
                        HostError::ProcessContour(format!("reopen Kernel profile roots: {error}"))
                    })?;
            if retained.selection() != expected_selection {
                return Err(HostError::ProcessContour(
                    "Kernel profile roots changed before child launch".to_owned(),
                ));
            }
            retained.verify_stable_identity().map_err(|error| {
                HostError::ProcessContour(format!(
                    "Kernel profile roots changed before child launch: {error}"
                ))
            })?;
        }
        // WORK_UNIT_CASE: 978/3 — retained lease bound, distinct from image name below.
        host_launch_observe("host.launch retained lease bound");
        approved_launch_paths(
            executable,
            approved_executable_path,
            config_path,
            approved_config_path,
        )?;
        executable_lease.verify().map_err(|error| {
            // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
            host_launch_observe("host.launch substitution preserved");
            HostError::ProcessContour(error)
        })?;
        config_lease.verify().map_err(|error| {
            // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
            host_launch_observe("host.launch substitution preserved");
            HostError::ProcessContour(error)
        })?;
        match executable_lease {
            LaunchLease::Protected(lease) => {
                verify_file_digest_with_lease(lease, artifact, "runtime.artifact")
            }
            LaunchLease::Portable(lease) => {
                verify_file_digest_with_user_lease(lease, artifact, "runtime.artifact")
            }
        }
        .map_err(|error| {
            // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
            host_launch_observe("host.launch substitution preserved");
            HostError::ProcessContour(error.to_string())
        })?;
        match config_lease {
            LaunchLease::Protected(lease) => {
                verify_file_digest_with_lease(lease, config_digest, "runtime.config")
            }
            LaunchLease::Portable(lease) => {
                verify_file_digest_with_user_lease(lease, config_digest, "runtime.config")
            }
        }
        .map_err(|error| {
            // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
            host_launch_observe("host.launch substitution preserved");
            HostError::ProcessContour(error.to_string())
        })?;
        let mut environment = Self::environment(
            host,
            generation,
            config_digest,
            artifact,
            config_path,
            identity,
            kernel_launch_binding,
            receipt_binding,
        );
        if let Some(profile) = installation_profile {
            let profile_name = match profile {
                InstallationProfile::SystemService => "system_service",
                InstallationProfile::UserMode => "user_mode",
                InstallationProfile::PortableDev => "portable_dev",
            };
            environment.push((
                OsString::from("ELIOT_INSTALLATION_PROFILE"),
                OsString::from(profile_name),
            ));
            match (profile, profile_root_binding) {
                (InstallationProfile::SystemService, None) => {}
                (InstallationProfile::SystemService, Some(_)) => {
                    return Err(HostError::ProcessContour(
                        "SystemService launch cannot receive current-user root authority"
                            .to_owned(),
                    ));
                }
                (
                    InstallationProfile::UserMode | InstallationProfile::PortableDev,
                    Some((request, selection)),
                ) => {
                    let expected = match profile {
                        InstallationProfile::UserMode => ProfileSelection::UserMode,
                        InstallationProfile::PortableDev => ProfileSelection::PortableDev,
                        InstallationProfile::SystemService => {
                            return Err(HostError::ProcessContour(
                                "SystemService launch cannot receive current-user root authority"
                                    .to_owned(),
                            ));
                        }
                    };
                    if request.profile != expected || selection.profile != expected {
                        return Err(HostError::ProcessContour(
                            "Kernel launch profile does not match its retained root binding"
                                .to_owned(),
                        ));
                    }
                    let request = serde_json::to_string(request).map_err(|error| {
                        HostError::ProcessContour(format!(
                            "serialize Kernel profile roots: {error}"
                        ))
                    })?;
                    let selection = serde_json::to_string(selection).map_err(|error| {
                        HostError::ProcessContour(format!(
                            "serialize Kernel profile selection: {error}"
                        ))
                    })?;
                    environment.extend([
                        (
                            OsString::from("ELIOT_PROFILE_ROOT_REQUEST"),
                            OsString::from(request),
                        ),
                        (
                            OsString::from("ELIOT_PROFILE_ROOT_SELECTION"),
                            OsString::from(selection),
                        ),
                    ]);
                }
                (InstallationProfile::UserMode | InstallationProfile::PortableDev, None) => {
                    return Err(HostError::ProcessContour(
                        "current-user Kernel launch is missing its retained root binding"
                            .to_owned(),
                    ));
                }
            }
        } else if profile_root_binding.is_some() {
            return Err(HostError::ProcessContour(
                "non-Kernel process cannot receive a Kernel profile root binding".to_owned(),
            ));
        }
        let spec = SuspendedLaunchSpec::new(
            executable.to_path_buf(),
            arguments
                .iter()
                .map(|argument| OsString::from(argument.as_str()))
                .collect(),
            working_directory,
            environment,
        )
        .map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch typed rejection");
            HostError::ProcessContour(error.to_string())
        })?;
        // Issue #1888: this branch starts in its own Host-owned outer Job Object.
        // The platform layer resolves the kill domain owner identity from that
        // one Job Object name, so the record cannot disagree with the name and
        // neither the Kernel nor the Watchdog launcher can present the other's
        // outer Job Object; `CreateJobObjectW` additionally refuses an already
        // open outer name, so two branches cannot share one kill domain. The
        // child is created only after this build's launch probe has observed
        // assignment, permitted nesting, and outer kill-on-close.
        // `JobObjectLimits::default()` installs no CPU, memory, or process
        // ceiling: this branch root carries no admitted manifest limit, and the
        // launch must not invent one.
        if !identity.is_host_outer_kill_domain_name() {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch typed rejection");
            return Err(HostError::ProcessContour(
                "branch Job Object is not a Host-owned outer kill domain".to_owned(),
            ));
        }
        // Issue #1685: the requested approved limits travel through the #1888
        // outer-kill-domain constructor and are bound to the observed enforced
        // limits while still suspended; a divergence rejects the candidate
        // before resume. Core branches carry kill-on-close containment with no
        // job-memory ceiling, so no ceiling is threaded here.
        let resource_limits = JobObjectLimits::default();
        let child = SuspendedJobChild::spawn_named_host_outer_kill_domain(
            spec,
            identity.clone(),
            resource_limits,
        )
        .map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch typed rejection");
            HostError::ProcessContour(error.to_string())
        })?;
        let expected = executable;
        let validated = child
            .validate(|evidence| {
                // Issue #1775: bind the observed containment to the approved
                // branch Job before resume. The platform re-observed this
                // evidence from the retained handles (exact PID/start/image
                // plus Job membership), but only the host knows which branch
                // Job it approved: a suspended child outside that Job is never
                // resumed, never credentialed, and never controlled by
                // name/PID. This establishes the ownership relation before the
                // dependent resume below.
                if evidence.job_identity() != identity {
                    // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                    host_launch_observe("host.launch typed rejection");
                    return Err(
                        "suspended child is not contained in the approved branch Job".to_owned(),
                    );
                }
                // Issue #1685: bind the observed enforced limits to the
                // requested approved limits while still suspended. A divergence
                // rejects the candidate before resume; it never executes.
                if evidence.enforced_limits() != Some(resource_limits) {
                    return Err("approved job limits diverged before resume".to_owned());
                }
                // Issue #1775 (W5-boot): observe the real process identity
                // before resume. The suspended child must report a genuine OS
                // identity — nonzero PID plus nonzero process start time —
                // alongside the approved image below; a degenerate identity
                // refuses before resume rather than admitting an unidentified
                // process into the owned branches. PID alone never authorizes
                // control: the start identity is what distinguishes this child
                // from a PID reuse, and both ride the retained handle into
                // later ownership checks.
                let observed_identity = evidence.process();
                if observed_identity.process_id == 0 || observed_identity.start_time_100ns == 0 {
                    host_launch_observe("host.launch process identity unobservable");
                    return Err(
                        "suspended child has no observable process identity before resume"
                            .to_owned(),
                    );
                }
                let observed = std::fs::canonicalize(&evidence.process().image_path)
                    .map_err(|error| error.to_string())?;
                if observed != expected {
                    // WORK_UNIT_CASE: 978/3 — image identity preserved, distinct from retained path.
                    // WORK_UNIT_CASE: 978/4 — process identity distinct from launch request.
                    host_launch_observe("host.launch image identity preserved");
                    return Err("approved image identity changed before resume".to_owned());
                }
                let observed_executable =
                    std::fs::canonicalize(&observed).map_err(|error| error.to_string())?;
                let approved_executable_canonical =
                    std::fs::canonicalize(Path::new(approved_executable_path.as_str()))
                        .map_err(|error| error.to_string())?;
                if observed_executable != expected
                    || approved_executable_canonical != observed_executable
                {
                    // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
                    host_launch_observe("host.launch substitution preserved");
                    return Err("approved image path changed before resume".to_owned());
                }
                executable_lease.verify()?;
                match executable_lease {
                    LaunchLease::Protected(lease) => {
                        verify_file_digest_with_lease(lease, artifact, "runtime.artifact")
                    }
                    LaunchLease::Portable(lease) => {
                        verify_file_digest_with_user_lease(lease, artifact, "runtime.artifact")
                    }
                }
                .map_err(|error| error.to_string())?;
                let observed_config =
                    std::fs::canonicalize(config_path).map_err(|error| error.to_string())?;
                let approved_config_canonical =
                    std::fs::canonicalize(Path::new(approved_config_path.as_str()))
                        .map_err(|error| error.to_string())?;
                if observed_config != config_path || approved_config_canonical != observed_config {
                    // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
                    host_launch_observe("host.launch substitution preserved");
                    return Err("approved config path changed before resume".to_owned());
                }
                config_lease.verify()?;
                match config_lease {
                    LaunchLease::Protected(lease) => {
                        verify_file_digest_with_lease(lease, config_digest, "runtime.config")
                    }
                    LaunchLease::Portable(lease) => {
                        verify_file_digest_with_user_lease(lease, config_digest, "runtime.config")
                    }
                }
                .map_err(|error| error.to_string())?;
                Ok(generation.clone())
            })
            .map_err(|error| {
                // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
                host_launch_observe("host.launch substitution preserved");
                HostError::ProcessContour(format!("validation failed: {error:?}"))
            })?;
        // WORK_UNIT_CASE: 978/4 — image identity admitted, distinct from request and readiness.
        host_launch_observe("host.launch image identity admitted");
        let running = validated.resume().map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch typed rejection");
            HostError::ProcessContour(error.to_string())
        })?;
        // WORK_UNIT_CASE: 978/1 — launch admitted, distinct from rejection; admitted is never readiness.
        host_launch_observe("host.launch admitted");
        Ok(running)
    }

    /// Resolves the approved Kernel and Store working directories.
    pub(super) fn approved_working_directories(
        launch: &RuntimeLaunchDescriptor,
        portable_root: Option<&UserOwnedRootLease>,
        config_path: &Path,
    ) -> Result<(PathBuf, PathBuf), HostError> {
        // WORK_UNIT_CASE: 978/1 — working directories requested.
        host_launch_observe("host.launch working directories requested");
        if launch.profile != InstallationProfile::PortableDev {
            // WORK_UNIT_CASE: 978/1 — working directories admitted.
            host_launch_observe("host.launch working directories admitted");
            return Ok((
                PathBuf::from(launch.runtime_state_roots.kernel_work_root.as_str()),
                PathBuf::from(launch.runtime_state_roots.store_work_root.as_str()),
            ));
        }
        let root = portable_root
            .ok_or_else(|| {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                host_launch_observe("host.launch working directory typed rejection");
                HostError::ProcessContour("portable root lease is missing".to_owned())
            })?
            .path();
        let root = std::fs::canonicalize(root).map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch working directory typed rejection");
            HostError::ProcessContour(error.to_string())
        })?;
        let config_path = std::fs::canonicalize(config_path).map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch working directory typed rejection");
            HostError::ProcessContour(error.to_string())
        })?;
        if !config_path.starts_with(&root) {
            // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
            host_launch_observe("host.launch substitution preserved");
            return Err(HostError::ProcessContour(
                "portable launch config is outside the retained root".to_owned(),
            ));
        }
        let canonicalize = |path: &PlatformHandle, field: &str| {
            let working_directory =
                std::fs::canonicalize(Path::new(path.as_str())).map_err(|error| {
                    // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                    host_launch_observe("host.launch working directory typed rejection");
                    HostError::ProcessContour(error.to_string())
                })?;
            if !working_directory.starts_with(&root) {
                // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
                host_launch_observe("host.launch substitution preserved");
                return Err(HostError::ProcessContour(format!(
                    "portable {field} is outside the retained root"
                )));
            }
            Ok(working_directory)
        };
        let result = Ok((
            canonicalize(
                &launch.runtime_state_roots.kernel_work_root,
                "Kernel working directory",
            )?,
            canonicalize(
                &launch.runtime_state_roots.store_work_root,
                "Store working directory",
            )?,
        ));
        if result.is_ok() {
            // WORK_UNIT_CASE: 978/1 — working directories admitted.
            host_launch_observe("host.launch working directories admitted");
        }
        result
    }

    /// Resolves the Watchdog failure-domain anchor sink for the Kernel audit
    /// chain.
    ///
    /// I16.10 ("Periodic digest anchor is copied to Watchdog failure domain")
    /// and A13.8 ("External integrity anchors … help detect rollback or
    /// history rewriting") both require the periodic anchor to survive loss or
    /// rollback of the Kernel work root, and I8.1 puts the Watchdog's spool in
    /// its own physically separate root. The sink is therefore the
    /// installer-owned `RuntimeStateRoots::watchdog_state_root` verbatim — not
    /// a Kernel-derived or Host-invented path. It is a proven claim, not a
    /// name: `validate_for_config` has just re-proved the fixed
    /// `<installation_root>/watchdog` topology, whole-component separation from
    /// `kernel_work_root`, and the `roots_digest` that covers this field.
    ///
    /// The Kernel never creates the bound directory (`AuditAnchorBinding::new`
    /// in the Kernel audit chain), so a missing Watchdog root fails the launch
    /// closed here instead of quietly leaving the anchor in the Kernel failure
    /// domain.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ProcessContour`] when the installer-owned
    /// Watchdog state root is not an existing directory.
    pub(super) fn watchdog_anchor_root(
        launch: &RuntimeLaunchDescriptor,
    ) -> Result<&Path, HostError> {
        let root = Path::new(launch.runtime_state_roots.watchdog_state_root.as_str());
        if !root.is_dir() {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch typed rejection");
            return Err(HostError::ProcessContour(
                "installer-owned Watchdog state root is not an existing directory".to_owned(),
            ));
        }
        Ok(root)
    }

    /// Starts the approved Kernel and Store images in separate Job Objects.
    /// Both images are pinned and validated while suspended, then resumed only
    /// after the generation identity has been accepted.
    ///
    /// # Errors
    ///
    /// Returns an error if an approved path, retained file identity, digest,
    /// suspended launch, or rollback cleanup cannot be validated or completed.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "each argument is an independently validated process-contour authority binding"
    )]
    pub fn start_approved(
        &mut self,
        kernel_executable: &Path,
        store_bridge_executable: &Path,
        generation: &PlatformHandle,
        config_digest: &PlatformHandle,
        config_path: &Path,
        approved_kernel_path: &PlatformHandle,
        approved_store_bridge_path: &PlatformHandle,
        approved_config_path: &PlatformHandle,
        kernel_artifact: &PlatformHandle,
        store_artifact: &PlatformHandle,
        host: &HostInstallationEpoch,
        launch: &RuntimeLaunchDescriptor,
    ) -> Result<(), HostError> {
        // WORK_UNIT_CASE: 978/1 — start requested, outermost contour owns the single terminal.
        // WORK_UNIT_CASE: 978/4 — request distinct from process identity and readiness; admitted is never ready.
        host_launch_observe("host.launch start requested");
        let mut launch_terminal = HostLaunchTerminalGuard::armed("host-launch-failed");
        if self.kernel.is_some() || self.store.is_some() {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch typed rejection");
            return Err(HostError::ProcessContour(
                "approved contour is already running".to_owned(),
            ));
        }
        launch.require_phase_b_live().map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch typed rejection");
            HostError::RecoveryRequired(error.to_string())
        })?;
        launch
            .validate_for_config(
                &PlatformHandle::new(config_path.to_string_lossy().into_owned()).map_err(
                    |error| {
                        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                        host_launch_observe("host.launch typed rejection");
                        HostError::ProcessContour(error.to_string())
                    },
                )?,
            )
            .map_err(|error| {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                host_launch_observe("host.launch typed rejection");
                HostError::ProcessContour(error.to_string())
            })?;
        let profile_root_binding = if matches!(
            launch.profile,
            InstallationProfile::UserMode | InstallationProfile::PortableDev
        ) {
            let request = profile_root_request(launch)?;
            let leases =
                eliot_platform_windows::profile_supervision::open_profile_root_leases(&request)
                    .map_err(|error| {
                        host_launch_observe("host.launch profile roots rejected");
                        HostError::ProcessContour(format!(
                            "profile-governed roots could not be retained: {error}"
                        ))
                    })?;
            Some((request, leases))
        } else {
            None
        };
        let portable_root = if launch.profile == InstallationProfile::PortableDev {
            let root = PathBuf::from(
                launch
                    .portable_root
                    .as_ref()
                    .ok_or_else(|| {
                        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                        host_launch_observe("host.launch typed rejection");
                        HostError::ProcessContour("portable root is missing".to_owned())
                    })?
                    .as_str(),
            );
            Some(UserOwnedRootLease::open_existing(&root).map_err(|error| {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                host_launch_observe("host.launch typed rejection");
                HostError::ProcessContour(error.to_string())
            })?)
        } else {
            None
        };
        let kernel_executable =
            approved_locator(kernel_executable, approved_kernel_path, launch.profile)?;
        let kernel_lease =
            open_launch_lease(launch.profile, portable_root.as_ref(), &kernel_executable)?;
        verify_launch_digest(&kernel_lease, kernel_artifact, "runtime.kernel_artifact")?;
        let store_bridge_executable = approved_locator(
            store_bridge_executable,
            approved_store_bridge_path,
            launch.profile,
        )?;
        let store_lease = open_launch_lease(
            launch.profile,
            portable_root.as_ref(),
            &store_bridge_executable,
        )?;
        verify_launch_digest(&store_lease, store_artifact, "runtime.store_artifact")?;
        let config_path = approved_locator(config_path, approved_config_path, launch.profile)?;
        let config_pin = PinnedRuntimeFile::open(&config_path)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let config_lease = open_launch_lease(launch.profile, portable_root.as_ref(), &config_path)?;
        verify_launch_digest(&config_lease, config_digest, "runtime.config")?;
        let semantic_config_hash = semantic_store_config_hash_from_json(
            &config_lease.read_bounded(1024 * 1024).map_err(|error| {
                HostError::ProcessContour(format!("read Store config for semantic digest: {error}"))
            })?,
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let store_bootstrap_path = approved_locator(
            Path::new(launch.store_bootstrap_descriptor_path.as_str()),
            &launch.store_bootstrap_descriptor_path,
            launch.profile,
        )?;
        let store_bootstrap_lease = open_launch_lease(
            launch.profile,
            portable_root.as_ref(),
            &store_bootstrap_path,
        )?;
        let store_bootstrap_requirement = validate_store_bootstrap_descriptor(
            &store_bootstrap_lease,
            &launch.store_bootstrap_descriptor_digest,
            store_artifact,
            &semantic_config_hash,
            host.host_process_nonce().as_handle(),
        )?;
        let eliotd_config_path = approved_locator(
            Path::new(launch.eliotd_config_path.as_str()),
            &launch.eliotd_config_path,
            launch.profile,
        )?;
        let eliotd_config_lease =
            open_launch_lease(launch.profile, portable_root.as_ref(), &eliotd_config_path)?;
        verify_launch_digest(
            &eliotd_config_lease,
            &launch.eliotd_config_digest,
            "runtime.eliotd_config",
        )?;
        let eliotd_descriptor_path = approved_locator(
            Path::new(launch.eliotd_descriptor_path.as_str()),
            &launch.eliotd_descriptor_path,
            launch.profile,
        )?;
        let eliotd_descriptor_lease = open_launch_lease(
            launch.profile,
            portable_root.as_ref(),
            &eliotd_descriptor_path,
        )?;
        verify_launch_digest(
            &eliotd_descriptor_lease,
            &launch.eliotd_descriptor_digest,
            "runtime.eliotd_descriptor",
        )?;
        validate_eliotd_launch_descriptor(
            &eliotd_descriptor_lease,
            &launch.eliotd_descriptor_digest,
            launch,
        )?;
        let store_config_path = approved_locator(
            Path::new(launch.store_config_path.as_str()),
            approved_config_path,
            launch.profile,
        )?;
        if store_config_path != config_path {
            return Err(HostError::ProcessContour(
                "Store config is not the approved generation config".to_owned(),
            ));
        }
        let (kernel_working_directory, store_working_directory) =
            Self::approved_working_directories(launch, portable_root.as_ref(), &config_path)?;
        // I16.10 (issue #1837): bind the periodic digest-anchor sink to the
        // Watchdog failure domain on this launch. Resolved from the validated
        // `RuntimeStateRoots`, so it is derived from the real installer-owned
        // Watchdog root rather than supplied as a plausible-looking path.
        let watchdog_anchor_root = Self::watchdog_anchor_root(launch)?;
        // T6-D2 front-door anchor (issue #461): inject the sealed
        // digest-bound Doctor executable path into the stored 22-value
        // contour so the Kernel receives the exact 24-value launch options.
        // Missing or relative anchors fail closed here, never defaulted.
        let kernel_arguments = kernel_arguments_with_doctor_anchor(
            &launch.kernel_arguments,
            &launch.doctor_executable_path,
        )?;
        // Issue #1775: resolve collision before credential use. Listener PID
        // is observation only; the preflight does not prove socket identity.
        // The typed directive is produced from this real observation, and an
        // unreadable owner defers rather than reporting clean absence.
        ensure_store_endpoint_available(
            &launch.canonical_store_arguments,
            &StoreEndpointOwnershipBinding {
                installation: &host.installation,
                generation: &launch.generation,
                state_fence: &launch.authority_state_fence,
            },
        )?;
        let launch_result = launch_store_then_kernel(
            || {
                Self::launch(
                    &store_bridge_executable,
                    &store_lease,
                    &self.store_identity,
                    generation,
                    config_digest,
                    store_artifact,
                    &config_path,
                    &config_lease,
                    approved_store_bridge_path,
                    approved_config_path,
                    &config_pin,
                    host,
                    &launch.store_bridge_arguments,
                    &store_working_directory,
                    None,
                    None,
                    None,
                    None,
                )
            },
            |store| -> Result<(), StoreLivenessEvidence> {
                let process = store.evidence().process();
                let member = store
                    .job_processes()
                    .map(|members| members.iter().any(|observed| observed == process));
                if !matches!(member, Ok(true)) {
                    return Err(StoreLivenessEvidence::Unknown(
                        "Store process is not an exact member of its approved Job".to_owned(),
                    ));
                }
                match store.observe() {
                    Ok(eliot_platform_windows::RunningJobObservation::Running {
                        active_processes,
                    }) if active_processes > 0 => Ok(()),
                    Ok(eliot_platform_windows::RunningJobObservation::Running { .. }) => {
                        Err(StoreLivenessEvidence::Unknown(
                            "Store reports zero active processes".to_owned(),
                        ))
                    }
                    Ok(
                        eliot_platform_windows::RunningJobObservation::RootExited { .. }
                        | eliot_platform_windows::RunningJobObservation::Exited { .. },
                    ) => Err(StoreLivenessEvidence::Dead),
                    Err(error) => Err(StoreLivenessEvidence::Unknown(error.to_string())),
                }
            },
            || {
                Self::launch(
                    &kernel_executable,
                    &kernel_lease,
                    &self.kernel_identity,
                    generation,
                    config_digest,
                    kernel_artifact,
                    &config_path,
                    &config_lease,
                    approved_kernel_path,
                    approved_config_path,
                    &config_pin,
                    host,
                    &kernel_arguments,
                    &kernel_working_directory,
                    self.kernel_launch_binding.as_ref(),
                    Some((
                        Path::new(launch.runtime_state_roots.host_state_root.as_str()),
                        Path::new(launch.runtime_state_roots.kernel_ors_root.as_str()),
                        watchdog_anchor_root,
                        &launch.runtime_state_roots.roots_digest,
                    )),
                    Some(launch.profile),
                    profile_root_binding
                        .as_ref()
                        .map(|(request, leases)| (request, leases.selection())),
                )
            },
            |mut store| {
                store
                    .terminate_in_place(0xE017_0002)
                    .map(|_| ())
                    .map_err(|error| Box::new((store, error.to_string())))
            },
        );
        match launch_result {
            Ok((store, kernel)) => {
                self.kernel_executable = Some(kernel_executable);
                self.store_bridge_executable = Some(store_bridge_executable);
                self.kernel_lease = Some(kernel_lease);
                self.store_lease = Some(store_lease);
                self.config_path = Some(config_path);
                self.config_lease = Some(config_lease);
                self.store_bootstrap_lease = Some(store_bootstrap_lease);
                self.eliotd_config_lease = Some(eliotd_config_lease);
                self.eliotd_descriptor_lease = Some(eliotd_descriptor_lease);
                self.store_bootstrap_requirement = Some(store_bootstrap_requirement);
                self.config_pin = Some(config_pin);
                self.portable_root = portable_root;
                self.launch = Some(launch.clone());
                self.kernel_artifact_digest = Some(kernel_artifact.clone());
                self.store_artifact_digest = Some(store_artifact.clone());
                self.config_digest = Some(config_digest.clone());
                self.store_config_semantic_hash = Some(semantic_config_hash);
                self.approved_generation = Some(generation.clone());
                self.kernel_candidate = None;
                self.kernel_activation_receipt = None;
                self.kernel_restart_attempts = 0;
                self.store_restart_attempts = 0;
                self.kernel = Some(kernel);
                self.store = Some(store);
                let kernel_live = match Self::branch_state(self.kernel.as_ref()) {
                    Ok(BranchLiveness::Live) => Ok(()),
                    Ok(BranchLiveness::Dead) => {
                        Err("Kernel exited immediately after launch".to_owned())
                    }
                    Err(error) => Err(error),
                };
                match kernel_live {
                    Ok(()) => {
                        // WORK_UNIT_CASE: 978/1 — start admitted, distinct from rejection; admitted is never readiness.
                        host_launch_observe("host.launch start admitted");
                        launch_terminal.disarm();
                        Ok(())
                    }
                    Err(reason) => {
                        let store_cleanup = self.terminate_store();
                        let kernel_cleanup = self.terminate_kernel();
                        if store_cleanup.is_ok() && kernel_cleanup.is_ok() {
                            self.clear_recorded_contour();
                        }
                        Err(if store_cleanup.is_err() || kernel_cleanup.is_err() {
                            HostError::RecoveryRequired(format!(
                                "Kernel launch observation failed ({reason}); Store cleanup={store_cleanup:?}; Kernel cleanup={kernel_cleanup:?}"
                            ))
                        } else {
                            HostError::ProcessContour(format!(
                                "Kernel child is not live after launch ({reason})"
                            ))
                        })
                    }
                }
            }
            Err(
                StoreKernelLaunchError::Launch(error) | StoreKernelLaunchError::Kernel { error },
            ) => {
                self.clear_recorded_contour();
                Err(error)
            }
            Err(StoreKernelLaunchError::StoreNotLive { evidence }) => {
                self.clear_recorded_contour();
                Err(HostError::StoreNotLive { evidence })
            }
            Err(StoreKernelLaunchError::CleanupRequired { store, reason }) => {
                self.kernel_executable = Some(kernel_executable);
                self.store_bridge_executable = Some(store_bridge_executable);
                self.kernel_lease = Some(kernel_lease);
                self.store_lease = Some(store_lease);
                self.config_path = Some(config_path);
                self.config_lease = Some(config_lease);
                self.store_bootstrap_lease = Some(store_bootstrap_lease);
                self.eliotd_config_lease = Some(eliotd_config_lease);
                self.eliotd_descriptor_lease = Some(eliotd_descriptor_lease);
                self.store_bootstrap_requirement = Some(store_bootstrap_requirement);
                self.config_pin = Some(config_pin);
                self.portable_root = portable_root;
                self.launch = Some(launch.clone());
                self.kernel_artifact_digest = Some(kernel_artifact.clone());
                self.store_artifact_digest = Some(store_artifact.clone());
                self.config_digest = Some(config_digest.clone());
                self.approved_generation = Some(generation.clone());
                self.kernel_candidate = None;
                self.kernel_activation_receipt = None;
                self.kernel_restart_attempts = 0;
                self.store_restart_attempts = 0;
                self.store = Some(store);
                Err(HostError::RecoveryRequired(reason))
            }
        }
    }
}

#[cfg(windows)]
pub(super) fn profile_root_request(
    launch: &RuntimeLaunchDescriptor,
) -> Result<ProfileRootRequest, HostError> {
    launch
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let profile = match launch.profile {
        InstallationProfile::UserMode => ProfileSelection::UserMode,
        InstallationProfile::PortableDev => ProfileSelection::PortableDev,
        InstallationProfile::SystemService => {
            return Err(HostError::ProcessContour(
                "current-user root adapter cannot admit SystemService".to_owned(),
            ));
        }
    };
    let governed = &launch.profile_governed_roots;
    if governed.runtime_state_roots != launch.runtime_state_roots {
        return Err(HostError::ProcessContour(
            "runtime roots differ from the digest-bound profile root set".to_owned(),
        ));
    }
    let runtime = &governed.runtime_state_roots;
    let runtime_state_roots = [
        (
            "runtime_state_roots.profile_anchor_root",
            &runtime.profile_anchor_root,
        ),
        (
            "runtime_state_roots.installation_root",
            &runtime.installation_root,
        ),
        (
            "runtime_state_roots.host_state_root",
            &runtime.host_state_root,
        ),
        (
            "runtime_state_roots.kernel_ors_root",
            &runtime.kernel_ors_root,
        ),
        (
            "runtime_state_roots.kernel_work_root",
            &runtime.kernel_work_root,
        ),
        (
            "runtime_state_roots.store_data_root",
            &runtime.store_data_root,
        ),
        (
            "runtime_state_roots.store_work_root",
            &runtime.store_work_root,
        ),
        (
            "runtime_state_roots.store_temp_root",
            &runtime.store_temp_root,
        ),
        (
            "runtime_state_roots.watchdog_state_root",
            &runtime.watchdog_state_root,
        ),
    ]
    .into_iter()
    .map(|(role, path)| (role.to_owned(), PathBuf::from(path.as_str())))
    .collect();
    Ok(ProfileRootRequest {
        profile,
        installation_id: launch.installation_epoch.installation.as_str().to_owned(),
        installation_key: launch
            .profile_installation_key
            .as_ref()
            .map(|key| key.as_str().to_owned()),
        component: launch.profile_component.as_str().to_owned(),
        version: launch.profile_version.as_str().to_owned(),
        generation: launch.generation.as_str().to_owned(),
        authority_descriptor_path: PathBuf::from(launch.authority_descriptor_path.as_str()),
        authority_descriptor_sha256: launch.authority_descriptor_digest.as_str().to_owned(),
        authority_generation: launch.authority_generation.value(),
        roots: ProfileRootPaths {
            immutable_binaries: PathBuf::from(governed.immutable_binaries.as_str()),
            durable_data: PathBuf::from(governed.durable_data.as_str()),
            user_config: PathBuf::from(governed.user_config.as_str()),
            user_cache: PathBuf::from(governed.user_cache.as_str()),
            runtime_state_roots,
        },
        repository_root: launch
            .portable_root
            .as_ref()
            .map(|root| PathBuf::from(root.as_str())),
    })
}

#[cfg(all(test, windows))]
mod approved_path_tests {
    use super::approved_launch_paths;
    use crate::HostError;
    use eliot_platform::PlatformHandle;
    use std::path::PathBuf;

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn create(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("eliot-host-bind-{}-{name}", std::process::id()));
            std::fs::write(&path, b"binding")
                .unwrap_or_else(|error| panic!("test fixture is not writable: {error}"));
            Self { path }
        }

        fn canonical(&self) -> PathBuf {
            std::fs::canonicalize(&self.path)
                .unwrap_or_else(|error| panic!("test fixture cannot be canonicalized: {error}"))
        }

        fn handle(&self) -> PlatformHandle {
            PlatformHandle::new(self.canonical().to_string_lossy().into_owned())
                .unwrap_or_else(|error| panic!("test fixture path is not a handle: {error}"))
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn contour_rejected(result: Result<(), HostError>, expected: &str) {
        let Err(HostError::ProcessContour(reason)) = result else {
            panic!("substituted locator was accepted");
        };
        assert!(
            reason.contains(expected),
            "unexpected rejection reason: {reason}"
        );
    }

    #[test]
    fn approves_exact_canonical_locators() {
        let executable = TempFile::create("bind-ok-exe");
        let config = TempFile::create("bind-ok-cfg");
        if let Err(error) = approved_launch_paths(
            &executable.canonical(),
            &executable.handle(),
            &config.canonical(),
            &config.handle(),
        ) {
            panic!("exact canonical locators were rejected: {error}");
        }
    }

    #[test]
    fn rejects_substituted_executable_locator() {
        let executable = TempFile::create("bind-exe-real");
        let substitute = TempFile::create("bind-exe-fake");
        let config = TempFile::create("bind-exe-cfg");
        contour_rejected(
            approved_launch_paths(
                &executable.canonical(),
                &substitute.handle(),
                &config.canonical(),
                &config.handle(),
            ),
            "executable locator is not the approved path",
        );
    }

    #[test]
    fn rejects_substituted_config_locator() {
        let executable = TempFile::create("bind-cfg-exe");
        let config = TempFile::create("bind-cfg-real");
        let substitute = TempFile::create("bind-cfg-fake");
        contour_rejected(
            approved_launch_paths(
                &executable.canonical(),
                &executable.handle(),
                &config.canonical(),
                &substitute.handle(),
            ),
            "config locator is not the approved path",
        );
    }

    #[test]
    fn rejects_missing_locator_without_spawning() {
        let executable = TempFile::create("bind-missing-exe");
        let config = TempFile::create("bind-missing-cfg");
        let missing =
            std::env::temp_dir().join(format!("eliot-host-bind-{}-absent", std::process::id()));
        let Err(HostError::ProcessContour(_)) = approved_launch_paths(
            &missing,
            &executable.handle(),
            &config.canonical(),
            &config.handle(),
        ) else {
            panic!("missing locator was accepted");
        };
    }

    /// T6-D2 front-door anchor (issue #461): the sealed digest-bound Doctor
    /// path is injected immediately after the doctor digest, a relative
    /// path fails closed, and a contour without the digested doctor role
    /// fails closed naming the doctor role. Fakes only: synthetic handles,
    /// no process is spawned.
    #[test]
    fn injects_the_digest_bound_doctor_path_anchor() {
        use super::kernel_arguments_with_doctor_anchor;

        let handle = |value: &str| {
            PlatformHandle::new(value.to_owned())
                .unwrap_or_else(|error| panic!("test handle is invalid: {error}"))
        };
        let stored = vec![
            handle("--work-root"),
            handle(r"C:\work"),
            handle("--doctor-artifact-sha256"),
            handle(&"a".repeat(64)),
            handle("--testd-artifact-sha256"),
            handle(&"b".repeat(64)),
        ];
        let doctor_path = handle(r"C:\install\eliot-doctor.exe");
        let injected = match kernel_arguments_with_doctor_anchor(&stored, &doctor_path) {
            Ok(injected) => injected,
            Err(error) => panic!("absolute doctor anchor must inject: {error}"),
        };
        assert_eq!(injected.len(), stored.len() + 2);
        assert_eq!(injected[2].as_str(), "--doctor-artifact-sha256");
        assert_eq!(injected[4].as_str(), "--doctor-executable-path");
        assert_eq!(injected[5], doctor_path);
        assert_eq!(injected[6].as_str(), "--testd-artifact-sha256");

        let relative = handle(r"relative\eliot-doctor.exe");
        let Err(HostError::ProcessContour(reason)) =
            kernel_arguments_with_doctor_anchor(&stored, &relative)
        else {
            panic!("relative doctor anchor was accepted");
        };
        assert!(
            reason.to_lowercase().contains("absolute"),
            "unexpected rejection reason: {reason}"
        );

        let without_doctor = vec![handle("--work-root"), handle(r"C:\work")];
        let Err(HostError::ProcessContour(reason)) =
            kernel_arguments_with_doctor_anchor(&without_doctor, &doctor_path)
        else {
            panic!("contour without the digested doctor role was accepted");
        };
        assert!(
            reason.to_lowercase().contains("doctor"),
            "missing-role error must name the doctor role, got: {reason}"
        );
    }
}
