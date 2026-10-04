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
use super::{BranchLiveness, HostError, HostJobBranches, KernelLaunchBinding};
#[cfg(windows)]
use crate::launch_artifact::{
    LaunchLease, approved_locator_with_correlation, open_launch_lease_with_correlation,
    verify_launch_digest_with_correlation,
};
#[cfg(windows)]
use crate::launch_descriptor_validation::{
    validate_eliotd_launch_descriptor_with_correlation,
    validate_store_bootstrap_descriptor_with_correlation,
};
#[cfg(windows)]
use crate::store_kernel_launch_sequence::{
    StoreKernelLaunchError, StoreLivenessEvidence, launch_store_then_kernel_with_correlation,
};

// F-LOG-HOST-3 (#978) launch observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Correlation: [`LaunchPhaseCorrelation`] below carries bounded, secret-free
// identities for one phase record, filled only from handles the call site
// already holds — never re-derived, never probed, and never a raw path, argv,
// environment value, credential, nonce, payload or connection string.
// A slot the call site cannot prove stays absent and renders as explicitly
// missing, because missing evidence cannot be invented by logging. Bounding
// limits size, not sensitivity (I15.4). Sink outcome never alters
// result/order/count/handle/cleanup/timeout. There is no mutable global dedup
// cache; inner phases correlate by their bound identities, never by stage order
// alone.
//
// One designated terminal per underlying operation: the leaf guard below is
// PHASE-ONLY. `HostLaunchTerminalGuard` emits one correlated subordinate phase
// record and no terminal at all. The designated terminal for one failed launch
// is `lib.rs`'s `HostTerminalGuard` on the OUTER contour that wrapped the call:
// the production path arms `BOUNDARY_OPEN_TERMINAL` ("host-open-failed"), while
// `BOUNDARY_START_TERMINAL` ("host-start-failed") is armed only inside
// `start_approved_contour`, which has no in-repo caller. The leaf terminal code
// retired here appears nowhere in this file, so one failed launch cannot produce
// two terminal records. Typed rejections stay
// `HostError::ProcessContour`/`RecoveryRequired` (cases 978/2, 978/3); admitted
// launches are distinct from readiness (case 978/4 — never readiness here).

/// Bounded, secret-free correlation identities for one launch phase record.
///
/// Every slot is filled only from an identity the caller already holds. A slot
/// the call site cannot prove stays absent and renders as explicitly missing;
/// missing evidence is never invented (issue #978 Work: "Missing evidence
/// cannot be invented by logging"). No slot ever carries a raw path, argv,
/// environment value, credential, nonce, payload, connection string, pipe name
/// or arbitrary Debug/Display output (I15.4, I07.20).
#[derive(Clone, Copy)]
pub(crate) struct LaunchPhaseCorrelation<'a> {
    installation: Option<&'a str>,
    generation: Option<u64>,
    operation: Option<&'a str>,
    artifact: Option<&'a str>,
    process_start: Option<&'a str>,
    fence: Option<&'a str>,
    reason: Option<&'a str>,
}

impl<'a> LaunchPhaseCorrelation<'a> {
    /// Every slot explicitly missing: the honest default for a call site that
    /// holds no identity yet.
    pub(crate) const NONE: Self = Self {
        installation: None,
        generation: None,
        operation: None,
        artifact: None,
        process_start: None,
        fence: None,
        reason: None,
    };

    pub(crate) const fn with_installation(mut self, value: &'a str) -> Self {
        self.installation = Some(value);
        self
    }

    pub(crate) const fn with_generation(mut self, value: u64) -> Self {
        self.generation = Some(value);
        self
    }

    pub(crate) const fn with_operation(mut self, value: &'a str) -> Self {
        self.operation = Some(value);
        self
    }

    pub(crate) const fn with_artifact(mut self, value: &'a str) -> Self {
        self.artifact = Some(value);
        self
    }

    pub(crate) const fn with_process_start(mut self, value: &'a str) -> Self {
        self.process_start = Some(value);
        self
    }

    pub(crate) const fn with_fence(mut self, value: &'a str) -> Self {
        self.fence = Some(value);
        self
    }

    pub(crate) const fn with_reason(mut self, value: &'a str) -> Self {
        self.reason = Some(value);
        self
    }

    /// Renders the bounded structured detail for one phase record.
    ///
    /// Fixed order, single-space separated `key=value` pairs: `phase`,
    /// `installation`, `generation`, `operation`, `artifact`, `process_start`,
    /// `fence`, `reason`. Exactly one separating space sits between pairs and
    /// none leads the line. Every retained value goes through the existing
    /// [`crate::host_diagnostics::bound_field`] bound; an absent slot renders
    /// as the frozen `<slot>=missing` marker rather than an empty string, a
    /// zero or a placeholder, so a reader can never mistake a missing identity
    /// for an observed one.
    ///
    /// The WHOLE record is bounded here, to the facade's own
    /// [`crate::host_diagnostics::MAX_DIAGNOSTIC_DETAIL_BYTES`] ceiling, before
    /// it leaves this function. Composing six independently bounded slots plus
    /// keys can exceed that ceiling, and a facade that then truncates the
    /// record cuts the first overflowing value mid-value and can drop the tail
    /// slots whole without a marker — leaving a reader with a truncated
    /// identity, no absence marker, and no way to tell a cut value from a real
    /// one. So a record that does not fit is shortened by shedding WHOLE slots
    /// from the tail backwards (`reason`, then `fence`, `process_start`,
    /// `artifact`, `operation`, `generation`, `installation`), and every shed
    /// slot still renders as the frozen `<slot>=missing` marker. The leading
    /// phase token is never shed, the frozen key order and vocabulary are
    /// unchanged, and the owner-operation identity prefix survives the longest.
    ///
    /// A shed slot reads exactly like an unproven one: it says only that this
    /// record carries no value in that slot, never that the value does not
    /// exist. Shedding is a size decision, not a sensitivity one (I15.4) — no
    /// slot is inspected, re-derived or probed to decide it. Total and
    /// panic-free, with bounded allocation only.
    pub(crate) fn render(&self, phase: &str) -> String {
        let generation = self.generation.map(|value| value.to_string());
        // Frozen key order, one slot per identity this call site already holds.
        // Slot zero is the phase token that leads the record.
        let slots: [(&str, Option<&str>); 8] = [
            ("phase", Some(phase)),
            ("installation", self.installation),
            ("generation", generation.as_deref()),
            ("operation", self.operation),
            ("artifact", self.artifact),
            ("process_start", self.process_start),
            ("fence", self.fence),
            ("reason", self.reason),
        ];
        let mut detail = String::with_capacity(RENDERED_PHASE_DETAIL_BYTES);
        // Shed whole trailing slots until the composed record fits the facade's
        // own detail ceiling, so the facade receives it verbatim. EVERY slot is
        // still rendered: a shed slot renders the frozen `<slot>=missing`
        // marker, never nothing at all, so the emitted vocabulary is always the
        // eight frozen keys in the frozen order and a reader can tell a shed
        // slot from a slot this call site could never have held. Dropping the
        // tail instead would make a real identity indistinguishable from a slot
        // that was never rendered, which is exactly the missing marker this
        // record exists to provide.
        //
        // `shed + 1 < slots.len()` keeps at least the phase token and bounds the
        // loop at `shed == 6`, where `retained == 2`: the last state rendered is
        // the phase token plus `installation` carrying real values and the six
        // remaining slots spelled `missing`. Worst case there is two bounded
        // 256-byte values with their keys plus six short markers, 637 bytes
        // against the 1024-byte ceiling, so a fitting state is always
        // found, the loop is total, and no iteration can fail. Every one of the
        // eight keys is still emitted on every pass, so a shed slot is
        // distinguishable from an absent one by position and by marker alike.
        let mut shed = 0_usize;
        while shed.saturating_add(1) < slots.len() {
            detail.clear();
            let retained = slots.len() - shed;
            for (index, (key, value)) in slots.iter().enumerate() {
                render_phase_slot(
                    &mut detail,
                    key,
                    if index < retained { *value } else { None },
                );
            }
            if detail.len() <= crate::host_diagnostics::MAX_DIAGNOSTIC_DETAIL_BYTES {
                break;
            }
            shed = shed.saturating_add(1);
        }
        detail
    }
}

/// Initial capacity for one rendered phase record. Growth beyond it stays
/// bounded by [`crate::host_diagnostics::bound_field`] per slot, and the
/// composed record stays bounded by
/// [`crate::host_diagnostics::MAX_DIAGNOSTIC_DETAIL_BYTES`]: `render` sheds
/// whole slots as explicit `missing` markers rather than letting the facade
/// truncate a composed record.
const RENDERED_PHASE_DETAIL_BYTES: usize = 512;

/// Spelling of one absent identity slot: the frozen shared `missing` value the
/// issue fixture pins as `correlation_missing_markers`, so absence is explicit
/// and never a placeholder that could read like a real value.
const MISSING_IDENTITY: &str = "missing";

/// Appends one `key=value` pair, bounding the value and spelling an absent slot
/// as the frozen `<slot>=missing` marker. Never inspects content: callers bind
/// only nonsecret identities, so this bounds size, not sensitivity (I15.4).
fn render_phase_slot(detail: &mut String, key: &str, value: Option<&str>) {
    if !detail.is_empty() {
        detail.push(' ');
    }
    detail.push_str(key);
    detail.push('=');
    match value {
        Some(value) => detail.push_str(crate::host_diagnostics::bound_field(value).text()),
        None => detail.push_str(MISSING_IDENTITY),
    }
}

#[cfg(windows)]
fn host_launch_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn host_launch_observe(phase: &str, correlation: &LaunchPhaseCorrelation<'_>) {
    host_launch_note_event_log_unavailable();
    let detail = correlation.render(phase);
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        &detail,
    );
}

/// Path-free process-start identity of one already-held
/// [`eliot_platform_windows::ProcessIdentity`].
///
/// A bare PID is reusable, so the handle-observed creation time rides with it
/// and two incarnations of one PID stay distinguishable. `image_path` is
/// deliberately excluded: a path is never a diagnostic identity (I15.4). Pure
/// projection of fields the caller already holds — no probe, handle open or
/// second process observation runs here.
///
/// SPELLING, stated because it is NOT corpus-uniform: three other Host contours
/// render a `process_start` identity. `scm_launch.rs::scm_process_start_identity`
/// emits this same `windows-pid:{pid}:start:{start}` shape, while
/// `kernel_activation_driver.rs::kernel_process_start_identity` and
/// `kernel_front_door_client.rs::front_door_process_start_identity` both emit
/// `pid:{pid}:start:{start}` for the same fact. So a reader correlates this
/// contour's records with the SCM contour's directly, and must translate for the
/// Kernel activation and front-door records. Unifying the spelling is a
/// cross-file change and is escalated, not done here.
#[cfg(windows)]
fn host_launch_process_start_identity(process: &eliot_platform_windows::ProcessIdentity) -> String {
    format!(
        "windows-pid:{pid}:start:{start}",
        pid = process.process_id,
        start = process.start_time_100ns
    )
}

/// Phase-only guard for one physical launch operation.
///
/// Armed on entry; `start_approved` disarms it once the launch is admitted. Any
/// `Err` return (explicit or via `?`) drops armed and emits exactly one
/// subordinate phase record, correlated with the identities this contour
/// already holds. It emits NO terminal: the designated terminal for one failed
/// launch is `lib.rs`'s `HostTerminalGuard` on the outer contour - the production
/// path arms `BOUNDARY_OPEN_TERMINAL`, while `BOUNDARY_START_TERMINAL` is armed
/// only in the uncalled exported `start_approved_contour` - which this leaf must
/// not duplicate (#978 audit 2). It only observes the outcome; no dedup or lock.
#[cfg(windows)]
struct HostLaunchTerminalGuard<'a> {
    phase: &'a str,
    correlation: LaunchPhaseCorrelation<'a>,
    armed: bool,
}

#[cfg(windows)]
impl<'a> HostLaunchTerminalGuard<'a> {
    fn armed(phase: &'a str, correlation: LaunchPhaseCorrelation<'a>) -> Self {
        Self {
            phase,
            correlation,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(windows)]
impl Drop for HostLaunchTerminalGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            host_launch_observe(self.phase, &self.correlation);
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
///
/// #978: the only values this gate holds itself are locators, and a locator is
/// a raw path that never enters a diagnostic record (I15.4). This cell derives
/// no identity: it forwards the ones the calling contour already holds, while
/// the slots it cannot name (an owner operation id, a process-start identity,
/// and a generation that is not the authority generation) render explicitly
/// missing. Its only callers are this module's `#[cfg(all(test, windows))]`
/// cases now that the production contour calls the `_with_correlation` twin,
/// and that `cfg` is what keeps this identity-free wrapper from reading as
/// dead code without an `allow`.
#[cfg(all(test, windows))]
fn approved_launch_paths(
    executable: &Path,
    approved_executable_path: &PlatformHandle,
    config_path: &Path,
    approved_config_path: &PlatformHandle,
) -> Result<(), HostError> {
    // WORK_UNIT_CASE: 978/1 — approved paths requested.
    approved_launch_paths_with_correlation(
        &LaunchPhaseCorrelation::NONE,
        executable,
        approved_executable_path,
        config_path,
        approved_config_path,
    )
}

/// `approved_launch_paths` with the calling contour's already-held launch
/// correlation forwarded to every record this gate emits.
///
/// Identical logic, phase literals, order, returns and typed rejections; the
/// only difference is the correlation each observation receives. This gate
/// derives no identity and binds no locator or approved handle of its own: the
/// forwarded slots are rendered by `LaunchPhaseCorrelation::render`, so a slot
/// the caller could not hold stays the renderer's explicit absence marker
/// (I15.4).
#[cfg(windows)]
fn approved_launch_paths_with_correlation(
    correlation: &LaunchPhaseCorrelation<'_>,
    executable: &Path,
    approved_executable_path: &PlatformHandle,
    config_path: &Path,
    approved_config_path: &PlatformHandle,
) -> Result<(), HostError> {
    // WORK_UNIT_CASE: 978/1 — approved paths requested.
    host_launch_observe("host.launch approved paths requested", correlation);
    let approved_executable = std::fs::canonicalize(executable).map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        host_launch_observe("host.launch approved paths typed rejection", correlation);
        HostError::ProcessContour(error.to_string())
    })?;
    let approved_executable_canonical =
        std::fs::canonicalize(Path::new(approved_executable_path.as_str())).map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch approved paths typed rejection", correlation);
            HostError::ProcessContour(error.to_string())
        })?;
    if approved_executable != executable || approved_executable_canonical != approved_executable {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        host_launch_observe("host.launch substitution preserved", correlation);
        return Err(HostError::ProcessContour(
            "executable locator is not the approved path".to_owned(),
        ));
    }
    let approved_config = std::fs::canonicalize(config_path).map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        host_launch_observe("host.launch approved paths typed rejection", correlation);
        HostError::ProcessContour(error.to_string())
    })?;
    let approved_config_canonical = std::fs::canonicalize(Path::new(approved_config_path.as_str()))
        .map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch approved paths typed rejection", correlation);
            HostError::ProcessContour(error.to_string())
        })?;
    if approved_config != config_path || approved_config_canonical != approved_config {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        host_launch_observe("host.launch substitution preserved", correlation);
        return Err(HostError::ProcessContour(
            "config locator is not the approved path".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 978/1 — approved paths admitted, distinct from rejection.
    host_launch_observe("host.launch approved paths admitted", correlation);
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
    // #978: the bounded identities this contour already holds are the
    // installation identity and the authority fence epoch lineage from the
    // caller's own ownership binding — the same two the typed directive below
    // carries. The binding's generation is an opaque handle with no numeric
    // spelling here, so that slot stays explicitly missing instead of being
    // re-derived, and no owner operation id is in hand in this file either, so
    // that slot stays missing too. The endpoint itself is read from the approved
    // contour and is never recorded.
    //
    // RESIDUAL KEY COLLISION, recorded here so a reader of THIS file sees it, not
    // only a reader of the fixture: the `fence` slot on this record carries the
    // StateFence's authority-epoch LINEAGE id, while the activation pair
    // (`kernel_activation_driver.rs`, `kernel_front_door_client.rs`) binds the
    // activation id under the same key — and two other sites in THIS file bind a
    // different lineage again, the Host installation epoch's. So `fence` carries
    // three identities across the instrumented corpus. Those types are distinct
    // (`StateFence::authority_epoch` vs `HostInstallationEpoch::epoch`), so under
    // I14.20 line 296 they are not interchangeable. Unifying them is a cross-file
    // contract change and is escalated, not decided here.
    let correlation = LaunchPhaseCorrelation::NONE
        .with_installation(binding.installation.as_str())
        .with_fence(binding.state_fence.authority_epoch.lineage_id.as_str());
    let endpoint = planned_store_endpoint(canonical_store_arguments).inspect_err(|_error| {
        host_launch_observe(
            "host.launch store endpoint configuration rejected",
            &correlation,
        );
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
        host_launch_observe(
            "host.launch retained child identity degenerate",
            &correlation,
        );
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
            host_launch_observe(
                "host.launch store endpoint owner unobservable",
                &correlation,
            );
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
            host_launch_observe(
                "host.launch retained store endpoint owner observed",
                &correlation,
            );
            Ok(())
        }
        StoreEndpointObservation::Occupied { owner_process_id } => {
            host_launch_observe(
                "host.launch store endpoint collision observed",
                &correlation,
            );
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
            host_launch_observe("host.launch store endpoint free", &correlation);
            Ok(())
        }
        StoreEndpointObservation::Unreadable { reason } => {
            // A read that FAILED is not a read that SUCCEEDED WITH AN EMPTY
            // ANSWER. I3.3 requires verifying the owning lineage "before every
            // start/reconnect"; an unreadable owner leaves that unverified, so
            // the launch DEFERS rather than proceeding on a clean-absence
            // reading that was never established.
            host_launch_observe("host.launch store endpoint owner unreadable", &correlation);
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
///
/// #978: the only values this helper holds itself are the stored argument
/// contour and the Doctor executable locator, and both are raw launch values
/// that never enter a diagnostic record. This cell derives no identity: it
/// forwards the ones the calling contour already holds, while the slots it
/// cannot name (an owner operation id, an artifact digest, and a process-start
/// identity) render explicitly missing.
#[cfg(windows)]
pub(super) fn kernel_arguments_with_doctor_anchor(
    kernel_arguments: &[PlatformHandle],
    doctor_executable_path: &PlatformHandle,
) -> Result<Vec<PlatformHandle>, HostError> {
    // WORK_UNIT_CASE: 978/1 — doctor anchor requested.
    kernel_arguments_with_doctor_anchor_with_correlation(
        &LaunchPhaseCorrelation::NONE,
        kernel_arguments,
        doctor_executable_path,
    )
}

/// [`kernel_arguments_with_doctor_anchor`] with the calling contour's
/// already-held launch correlation forwarded to every record this seam emits.
///
/// Identical logic, phase literals, order, injected contour, returns and typed
/// rejections; the only difference is the correlation each observation
/// receives. This seam derives no identity and binds no argument or path value
/// of its own: the forwarded slots are rendered by
/// `LaunchPhaseCorrelation::render`, so a slot the caller could not hold stays
/// the renderer's explicit absence marker (I15.4).
#[cfg(windows)]
pub(super) fn kernel_arguments_with_doctor_anchor_with_correlation(
    correlation: &LaunchPhaseCorrelation<'_>,
    kernel_arguments: &[PlatformHandle],
    doctor_executable_path: &PlatformHandle,
) -> Result<Vec<PlatformHandle>, HostError> {
    const DOCTOR_DIGEST_FLAG: &str = "--doctor-artifact-sha256";
    const DOCTOR_PATH_FLAG: &str = "--doctor-executable-path";
    // WORK_UNIT_CASE: 978/1 — doctor anchor requested; the caller's already-held
    // identities are forwarded and nothing is derived here.
    host_launch_observe("host.launch doctor anchor requested", correlation);
    if kernel_arguments
        .iter()
        .any(|argument| argument.as_str() == DOCTOR_PATH_FLAG)
    {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        host_launch_observe("host.launch doctor anchor typed rejection", correlation);
        return Err(HostError::ProcessContour(
            "Kernel launch contour already carries a Doctor path anchor".to_owned(),
        ));
    }
    if !Path::new(doctor_executable_path.as_str()).is_absolute() {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        host_launch_observe("host.launch doctor anchor typed rejection", correlation);
        return Err(HostError::ProcessContour(
            "Doctor executable path anchor must be absolute".to_owned(),
        ));
    }
    let path_flag = PlatformHandle::new(DOCTOR_PATH_FLAG).map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        host_launch_observe("host.launch doctor anchor typed rejection", correlation);
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
                host_launch_observe("host.launch doctor anchor typed rejection", correlation);
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
        host_launch_observe("host.launch doctor anchor typed rejection", correlation);
        return Err(HostError::ProcessContour(
            "Kernel launch contour is missing the digested doctor role".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 978/1 — doctor anchor admitted, exact count preserved.
    host_launch_observe("host.launch doctor anchor admitted", correlation);
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
        // #978: this contour already holds the Host installation identity, the
        // lineage of the Host installation epoch it runs under, and the approved
        // artifact digest of the exact branch it is launching, so every record
        // below binds all three. The fence slot carries that already-held epoch
        // lineage identity: a `StateFence` itself has no bounded digest spelling,
        // so nothing is re-derived to fill it. `generation` arrives here as an
        // opaque identity handle with no bounded numeric spelling, the branch Job
        // Object name is an object-manager name rather than an approved identity,
        // and the executable/config values in hand are raw paths: those slots stay
        // explicitly missing rather than being re-derived or guessed.
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(host.installation.as_str())
            .with_fence(host.epoch.current.lineage_id.as_str())
            .with_artifact(artifact.as_str());
        // WORK_UNIT_CASE: 978/1 — launch requested, distinct from process/readiness.
        // WORK_UNIT_CASE: 978/4 — request precedes process identity and admitted launch.
        host_launch_observe("host.launch requested", &correlation);
        if executable_lease.path() != executable || config_lease.path() != config_path {
            // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
            host_launch_observe("host.launch substitution preserved", &correlation);
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
        host_launch_observe("host.launch retained lease bound", &correlation);
        approved_launch_paths_with_correlation(
            &correlation,
            executable,
            approved_executable_path,
            config_path,
            approved_config_path,
        )?;
        executable_lease.verify().map_err(|error| {
            // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
            host_launch_observe("host.launch substitution preserved", &correlation);
            HostError::ProcessContour(error)
        })?;
        config_lease.verify().map_err(|error| {
            // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
            host_launch_observe("host.launch substitution preserved", &correlation);
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
            host_launch_observe("host.launch substitution preserved", &correlation);
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
            host_launch_observe("host.launch substitution preserved", &correlation);
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
            host_launch_observe("host.launch typed rejection", &correlation);
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
            host_launch_observe("host.launch typed rejection", &correlation);
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
            host_launch_observe("host.launch typed rejection", &correlation);
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
                    host_launch_observe("host.launch typed rejection", &correlation);
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
                    // #978: the observed process identity is already in hand, so
                    // this record binds the exact incarnation (including its
                    // degenerate reading) instead of a static label alone.
                    let process_start = host_launch_process_start_identity(observed_identity);
                    host_launch_observe(
                        "host.launch process identity unobservable",
                        &correlation.with_process_start(&process_start),
                    );
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
                    let process_start = host_launch_process_start_identity(observed_identity);
                    host_launch_observe(
                        "host.launch image identity preserved",
                        &correlation.with_process_start(&process_start),
                    );
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
                    host_launch_observe("host.launch substitution preserved", &correlation);
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
                    host_launch_observe("host.launch substitution preserved", &correlation);
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
                host_launch_observe("host.launch substitution preserved", &correlation);
                HostError::ProcessContour(format!("validation failed: {error:?}"))
            })?;
        // WORK_UNIT_CASE: 978/4 — image identity admitted, distinct from request and readiness.
        // #978: the retained suspended evidence carries the exact process
        // incarnation that was admitted, so the record binds that identity too.
        let admitted_process_start =
            host_launch_process_start_identity(validated.evidence().process());
        host_launch_observe(
            "host.launch image identity admitted",
            &correlation.with_process_start(&admitted_process_start),
        );
        let running = validated.resume().map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch typed rejection", &correlation);
            HostError::ProcessContour(error.to_string())
        })?;
        // WORK_UNIT_CASE: 978/1 — launch admitted, distinct from rejection; admitted is never readiness.
        let resumed_process_start =
            host_launch_process_start_identity(running.evidence().process());
        host_launch_observe(
            "host.launch admitted",
            &correlation.with_process_start(&resumed_process_start),
        );
        Ok(running)
    }

    /// Resolves the approved Kernel and Store working directories.
    pub(super) fn approved_working_directories(
        launch: &RuntimeLaunchDescriptor,
        portable_root: Option<&UserOwnedRootLease>,
        config_path: &Path,
    ) -> Result<(PathBuf, PathBuf), HostError> {
        // #978: the approved launch descriptor in hand carries this contour's
        // installation identity, its exact authority generation, and the lineage
        // of the authority epoch its approved fence carries (the fence slot holds
        // that already-held epoch lineage because a fence has no bounded digest
        // spelling); the resolved roots themselves are raw paths and stay
        // explicitly missing.
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(launch.installation_epoch.installation.as_str())
            .with_generation(launch.authority_generation.value())
            .with_fence(
                launch
                    .authority_state_fence
                    .authority_epoch
                    .lineage_id
                    .as_str(),
            );
        // WORK_UNIT_CASE: 978/1 — working directories requested.
        host_launch_observe("host.launch working directories requested", &correlation);
        if launch.profile != InstallationProfile::PortableDev {
            // WORK_UNIT_CASE: 978/1 — working directories admitted.
            host_launch_observe("host.launch working directories admitted", &correlation);
            return Ok((
                PathBuf::from(launch.runtime_state_roots.kernel_work_root.as_str()),
                PathBuf::from(launch.runtime_state_roots.store_work_root.as_str()),
            ));
        }
        let root = portable_root
            .ok_or_else(|| {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                host_launch_observe(
                    "host.launch working directory typed rejection",
                    &correlation,
                );
                HostError::ProcessContour("portable root lease is missing".to_owned())
            })?
            .path();
        let root = std::fs::canonicalize(root).map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe(
                "host.launch working directory typed rejection",
                &correlation,
            );
            HostError::ProcessContour(error.to_string())
        })?;
        let config_path = std::fs::canonicalize(config_path).map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe(
                "host.launch working directory typed rejection",
                &correlation,
            );
            HostError::ProcessContour(error.to_string())
        })?;
        if !config_path.starts_with(&root) {
            // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
            host_launch_observe("host.launch substitution preserved", &correlation);
            return Err(HostError::ProcessContour(
                "portable launch config is outside the retained root".to_owned(),
            ));
        }
        let canonicalize = |path: &PlatformHandle, field: &str| {
            let working_directory =
                std::fs::canonicalize(Path::new(path.as_str())).map_err(|error| {
                    // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                    host_launch_observe(
                        "host.launch working directory typed rejection",
                        &correlation,
                    );
                    HostError::ProcessContour(error.to_string())
                })?;
            if !working_directory.starts_with(&root) {
                // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
                host_launch_observe("host.launch substitution preserved", &correlation);
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
            host_launch_observe("host.launch working directories admitted", &correlation);
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
        // #978: the approved launch descriptor in hand carries this contour's
        // installation identity, its exact authority generation and the lineage of
        // the authority epoch its approved fence carries; the Watchdog state root
        // itself is a raw path and stays explicitly missing.
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(launch.installation_epoch.installation.as_str())
            .with_generation(launch.authority_generation.value())
            .with_fence(
                launch
                    .authority_state_fence
                    .authority_epoch
                    .lineage_id
                    .as_str(),
            );
        let root = Path::new(launch.runtime_state_roots.watchdog_state_root.as_str());
        if !root.is_dir() {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch typed rejection", &correlation);
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
        // #978: the identities this contour already holds are the Host
        // installation identity, the Host installation epoch this start runs
        // under, and the approved launch descriptor's exact authority
        // generation. The generation identity handle that also arrives as an
        // argument has no numeric spelling, and no owner operation id is in hand
        // in this file, so those two slots stay explicitly missing rather than
        // carrying some other identity under the wrong name. Both approved
        // artifact digests are in hand here and neither is the single artifact of
        // this contour as a whole, so that slot stays missing too. Locators,
        // retained leases and error text never enter the record (I15.4), and
        // nothing here is re-derived or probed.
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(host.installation.as_str())
            .with_generation(launch.authority_generation.value())
            .with_fence(host.epoch.current.lineage_id.as_str());
        // WORK_UNIT_CASE: 978/1 — start requested; the designated terminal for a
        // failed launch stays `lib.rs`'s `HostTerminalGuard`, and the #978 leaf
        // guard below is phase-only, so one failed launch can never emit two
        // terminals.
        // WORK_UNIT_CASE: 978/4 — request distinct from process identity and readiness; admitted is never ready.
        host_launch_observe("host.launch start requested", &correlation);
        // Phase-only summary of this contour, correlated with those same held
        // identities. It is never a terminal record: the one terminal of a failed
        // physical launch belongs to `lib.rs`.
        let mut launch_terminal =
            HostLaunchTerminalGuard::armed("host.launch start failed observed", correlation);
        if self.kernel.is_some() || self.store.is_some() {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch typed rejection", &correlation);
            return Err(HostError::ProcessContour(
                "approved contour is already running".to_owned(),
            ));
        }
        launch.require_phase_b_live().map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            host_launch_observe("host.launch typed rejection", &correlation);
            HostError::RecoveryRequired(error.to_string())
        })?;
        launch
            .validate_for_config(
                &PlatformHandle::new(config_path.to_string_lossy().into_owned()).map_err(
                    |error| {
                        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                        host_launch_observe("host.launch typed rejection", &correlation);
                        HostError::ProcessContour(error.to_string())
                    },
                )?,
            )
            .map_err(|error| {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                host_launch_observe("host.launch typed rejection", &correlation);
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
                        host_launch_observe("host.launch profile roots rejected", &correlation);
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
                        host_launch_observe("host.launch typed rejection", &correlation);
                        HostError::ProcessContour("portable root is missing".to_owned())
                    })?
                    .as_str(),
            );
            Some(UserOwnedRootLease::open_existing(&root).map_err(|error| {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
                host_launch_observe("host.launch typed rejection", &correlation);
                HostError::ProcessContour(error.to_string())
            })?)
        } else {
            None
        };
        let kernel_executable = approved_locator_with_correlation(
            &correlation,
            kernel_executable,
            approved_kernel_path,
            launch.profile,
        )?;
        let kernel_lease = open_launch_lease_with_correlation(
            &correlation,
            launch.profile,
            portable_root.as_ref(),
            &kernel_executable,
        )?;
        verify_launch_digest_with_correlation(
            &correlation,
            &kernel_lease,
            kernel_artifact,
            "runtime.kernel_artifact",
        )?;
        let store_bridge_executable = approved_locator_with_correlation(
            &correlation,
            store_bridge_executable,
            approved_store_bridge_path,
            launch.profile,
        )?;
        let store_lease = open_launch_lease_with_correlation(
            &correlation,
            launch.profile,
            portable_root.as_ref(),
            &store_bridge_executable,
        )?;
        verify_launch_digest_with_correlation(
            &correlation,
            &store_lease,
            store_artifact,
            "runtime.store_artifact",
        )?;
        let config_path = approved_locator_with_correlation(
            &correlation,
            config_path,
            approved_config_path,
            launch.profile,
        )?;
        let config_pin = PinnedRuntimeFile::open(&config_path)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let config_lease = open_launch_lease_with_correlation(
            &correlation,
            launch.profile,
            portable_root.as_ref(),
            &config_path,
        )?;
        verify_launch_digest_with_correlation(
            &correlation,
            &config_lease,
            config_digest,
            "runtime.config",
        )?;
        let semantic_config_hash = semantic_store_config_hash_from_json(
            &config_lease.read_bounded(1024 * 1024).map_err(|error| {
                HostError::ProcessContour(format!("read Store config for semantic digest: {error}"))
            })?,
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let store_bootstrap_path = approved_locator_with_correlation(
            &correlation,
            Path::new(launch.store_bootstrap_descriptor_path.as_str()),
            &launch.store_bootstrap_descriptor_path,
            launch.profile,
        )?;
        let store_bootstrap_lease = open_launch_lease_with_correlation(
            &correlation,
            launch.profile,
            portable_root.as_ref(),
            &store_bootstrap_path,
        )?;
        let store_bootstrap_requirement = validate_store_bootstrap_descriptor_with_correlation(
            &correlation,
            &store_bootstrap_lease,
            &launch.store_bootstrap_descriptor_digest,
            store_artifact,
            &semantic_config_hash,
            host.host_process_nonce().as_handle(),
        )?;
        let eliotd_config_path = approved_locator_with_correlation(
            &correlation,
            Path::new(launch.eliotd_config_path.as_str()),
            &launch.eliotd_config_path,
            launch.profile,
        )?;
        let eliotd_config_lease = open_launch_lease_with_correlation(
            &correlation,
            launch.profile,
            portable_root.as_ref(),
            &eliotd_config_path,
        )?;
        verify_launch_digest_with_correlation(
            &correlation,
            &eliotd_config_lease,
            &launch.eliotd_config_digest,
            "runtime.eliotd_config",
        )?;
        let eliotd_descriptor_path = approved_locator_with_correlation(
            &correlation,
            Path::new(launch.eliotd_descriptor_path.as_str()),
            &launch.eliotd_descriptor_path,
            launch.profile,
        )?;
        let eliotd_descriptor_lease = open_launch_lease_with_correlation(
            &correlation,
            launch.profile,
            portable_root.as_ref(),
            &eliotd_descriptor_path,
        )?;
        verify_launch_digest_with_correlation(
            &correlation,
            &eliotd_descriptor_lease,
            &launch.eliotd_descriptor_digest,
            "runtime.eliotd_descriptor",
        )?;
        validate_eliotd_launch_descriptor_with_correlation(
            &correlation,
            &eliotd_descriptor_lease,
            &launch.eliotd_descriptor_digest,
            launch,
        )?;
        let store_config_path = approved_locator_with_correlation(
            &correlation,
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
        let kernel_arguments = kernel_arguments_with_doctor_anchor_with_correlation(
            &correlation,
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
        let launch_result = launch_store_then_kernel_with_correlation(
            &correlation,
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
                        host_launch_observe("host.launch start admitted", &correlation);
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

    /// A substituted executable locator is refused with the exact typed reason,
    /// and the approved identity is never replaced by the substitute. This is
    /// the real production `approved_launch_paths` refusal, executed.
    // WORK_UNIT_CASE: 978/3
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

    /// A substituted config locator is refused the same way. The second half of
    /// case 978/3 in this file: the approved config identity is retained across a
    /// substitution failure exactly as the executable identity is.
    // WORK_UNIT_CASE: 978/3
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

/// In-file proof for the #978 structured-correlation contract and the phase-only
/// leaf guard.
///
/// These cases execute the real private seams of this module (the correlation
/// renderer, this file's own observe seam, the production process-start
/// projection, the drop of an armed `HostLaunchTerminalGuard`, and the
/// Store-before-Kernel sequence through the correlation-forwarding entry point
/// this file now calls); no visibility is widened and no production algorithm is
/// restated here. Every value below is a synthetic test identity, never a real
/// path, credential or error text, and where a case has no unit-reachable
/// producer for a slot it says so in its own `HONEST SCOPE` note rather than
/// claiming a proof it does not have.
#[cfg(all(test, windows))]
mod phase_correlation_tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::{HostError, HostLaunchTerminalGuard, LaunchPhaseCorrelation, MISSING_IDENTITY};
    use crate::host_diagnostics::{
        MAX_DIAGNOSTIC_DETAIL_BYTES, MAX_DIAGNOSTIC_FIELD_BYTES, bound_detail,
    };
    use crate::store_kernel_launch_sequence::launch_store_then_kernel_with_correlation;

    /// The eight frozen correlation keys, in the order `LaunchPhaseCorrelation::render`
    /// emits them and the fixture's `correlation_keys` declares them.
    const FROZEN_CORRELATION_KEYS: [&str; 8] = [
        "phase",
        "installation",
        "generation",
        "operation",
        "artifact",
        "process_start",
        "fence",
        "reason",
    ];

    /// In-memory sink that captures facade output without contending for the
    /// process-global subscriber.
    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `emit` under a scoped subscriber and returns the captured text.
    fn capture(emit: impl FnOnce()) -> String {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, emit);
        let bytes = sink
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn count(haystack: &str, needle: &str) -> usize {
        haystack.matches(needle).count()
    }

    /// One already-observed process identity, as a caller that holds one passes
    /// it. No process is spawned, no handle is opened and no probe runs here;
    /// the identity is synthetic and its `image_path` is a canary the record
    /// must never carry.
    fn observed_process_identity(
        process_id: u32,
        start_time_100ns: u64,
    ) -> eliot_platform_windows::ProcessIdentity {
        eliot_platform_windows::ProcessIdentity {
            process_id,
            start_time_100ns,
            image_path: String::from(r"C:\canary\kernel-image.exe"),
        }
    }

    /// The `detail` field of the facade record a production observe call
    /// emitted, read back out of the captured subscriber output. Nothing in this
    /// module composes that text: the bytes are exactly what the real
    /// `host_launch_observe` handed to the #889 facade.
    fn captured_detail(captured: &str) -> String {
        let (_, rest) = captured.split_once("detail=\"").unwrap_or_else(|| {
            panic!("an executed production record must carry a detail: {captured}")
        });
        rest.split_once('"').map_or_else(
            || panic!("the detail field must be terminated: {captured}"),
            |(detail, _)| detail.to_owned(),
        )
    }

    /// One REAL emission of this file's observe seam, returned as the structured
    /// detail the #889 facade recorded for it.
    fn emitted_detail(phase: &str, correlation: &LaunchPhaseCorrelation<'_>) -> String {
        captured_detail(&capture(|| {
            super::host_launch_observe(phase, correlation);
        }))
    }

    /// A captured detail parsed into its ordered `key=value` slots, so a claim
    /// about one slot can never be satisfied by a substring somewhere else in the
    /// record.
    ///
    /// Values are NOT whitespace-free: the `phase` value is a multi-word token by
    /// construction, so the record is never split on spaces. Each value runs from
    /// its own `<key>=` anchor to the next `<key>=` anchor of the frozen
    /// vocabulary, which is the only separator the renderer guarantees.
    fn rendered_slots(detail: &str) -> Vec<(&str, &str)> {
        FROZEN_CORRELATION_KEYS
            .iter()
            .map(|key| {
                let anchor = format!("{key}=");
                let start = detail
                    .find(&anchor)
                    .unwrap_or_else(|| panic!("a captured detail must carry {key}=: {detail}"))
                    + anchor.len();
                let end = FROZEN_CORRELATION_KEYS
                    .iter()
                    .filter(|other| *other != key)
                    .map(|other| format!(" {other}="))
                    .filter_map(|needle| detail[start..].find(&needle).map(|at| start + at))
                    .min()
                    .unwrap_or(detail.len());
                (*key, &detail[start..end])
            })
            .collect()
    }

    /// Value of one slot of an already-parsed captured detail.
    fn slot_value<'a>(parsed: &'a [(&'a str, &'a str)], key: &str) -> &'a str {
        parsed.iter().find(|(name, _)| *name == key).map_or_else(
            || panic!("the emitted record must carry {key}="),
            |(_, value)| *value,
        )
    }

    /// Exact non-secret identity, frozen order, explicit absence for every slot
    /// the call site cannot prove.
    ///
    /// HONEST SCOPE: this case is deliberately NOT attributed to a case number,
    /// because it is a RENDERER case and not a production-path case: it builds a
    /// correlation from its own literals and asserts the rendered string, so it
    /// carries no production execution and no owner-held identity. It is kept
    /// because the frozen order and the absent-slot marker are real contracts,
    /// but attributing it would let a reader conclude that `approved_launch_paths`
    /// or `start_approved` is pinned by it, which it is not. The case-3
    /// attribution in this file sits on the two `rejects_substituted_*_locator`
    /// tests above, which really execute `approved_launch_paths` with a
    /// substituted handle.
    ///
    /// The process-start slot is bound below by the REAL production projection
    /// `host_launch_process_start_identity`. The remaining slots have no
    /// unit-reachable producer in this module - their real producers are
    /// `start_approved`'s already-held `HostInstallationEpoch`, authority
    /// generation and approved digests, reachable only through a full admitted
    /// physical launch.
    #[test]
    fn correlation_binds_exact_nonsecret_identity_and_marks_every_unproven_slot() {
        let process_start =
            super::host_launch_process_start_identity(&observed_process_identity(4321, 99));
        let bound = LaunchPhaseCorrelation::NONE
            .with_installation("installation-7")
            .with_generation(7)
            .with_operation("kernel")
            .with_artifact("a1")
            .with_process_start(&process_start)
            .with_fence("fence-3")
            .with_reason("store_owner_unreadable");
        assert_eq!(
            emitted_detail("host.launch requested", &bound),
            concat!(
                "phase=host.launch requested installation=installation-7 generation=7 ",
                "operation=kernel artifact=a1 process_start=windows-pid:4321:start:99 ",
                "fence=fence-3 reason=store_owner_unreadable",
            ),
            "a real emission must render every bound slot in the frozen order"
        );
        // Every unproven slot renders as explicit absence: never an empty value,
        // a zero or a placeholder that could read like a real identity.
        assert_eq!(
            emitted_detail("host.launch requested", &LaunchPhaseCorrelation::NONE),
            concat!(
                "phase=host.launch requested installation=missing generation=missing ",
                "operation=missing artifact=missing process_start=missing fence=missing ",
                "reason=missing",
            ),
            "a real emission must spell every unproven slot as explicit absence"
        );
    }

    /// A bound process-start identity must differ from an unproven slot.
    ///
    /// HONEST SCOPE: both values are produced by the REAL production projection
    /// `host_launch_process_start_identity`, exactly as the four production call
    /// sites in this file use it, and both records are real emissions. Observing
    /// a `ProcessIdentity` itself needs a suspended launch and a validated child
    /// handle, so this case proves the production projection plus the renderer
    /// and does not claim a live process observation.
    // WORK_UNIT_CASE: 978/4
    #[test]
    fn a_bound_process_identity_is_not_its_own_absence() {
        let phase = "host.launch image identity preserved";
        let first = super::host_launch_process_start_identity(&observed_process_identity(4321, 99));
        let second =
            super::host_launch_process_start_identity(&observed_process_identity(4321, 100));
        assert_eq!(
            first, "windows-pid:4321:start:99",
            "the production projection owns this shared spelling"
        );
        assert_ne!(
            first, second,
            "one reused PID must never yield one process-start identity"
        );
        let bound = LaunchPhaseCorrelation::NONE.with_process_start(&first);
        let unproven = LaunchPhaseCorrelation::NONE;
        let bound_record = emitted_detail(phase, &bound);
        let unproven_record = emitted_detail(phase, &unproven);
        let bound_slots = rendered_slots(&bound_record);
        let unproven_slots = rendered_slots(&unproven_record);
        assert_ne!(
            bound_record, unproven_record,
            "an observed process identity must differ from an unproven slot"
        );
        assert_eq!(
            slot_value(&bound_slots, "process_start"),
            first,
            "the production projection's own value must reach the emitted record: {bound_record}"
        );
        assert_eq!(
            slot_value(&unproven_slots, "process_start"),
            MISSING_IDENTITY,
            "an unproven process slot must read as explicit absence: {unproven_record}"
        );
        assert!(
            !bound_record.contains("canary"),
            "an image path is never a diagnostic identity: {bound_record}"
        );
        // The phase token itself is preserved verbatim, leads the line, and stays
        // distinct from the request and admitted phases of this contour.
        for record in [&bound_record, &unproven_record] {
            assert!(record.starts_with(&format!("phase={phase} ")));
        }
        assert_ne!(phase, "host.launch requested");
        assert_ne!(phase, "host.launch admitted");
    }

    /// Every rendered identity stays inside the field bound, the whole record
    /// stays inside the facade's detail bound, and no value is cut mid-value.
    ///
    /// HONEST SCOPE: the oversized input here is a SYNTHETIC stress value. No
    /// owner holds a 1 KiB identity, and none could be built here without a real
    /// launch, so this case proves the BOUND production `render` and the #889
    /// facade apply, read back out of a real emission. It deliberately claims no
    /// producer for a value no owner holds.
    // WORK_UNIT_CASE: 978/12
    #[test]
    fn every_rendered_identity_stays_bounded_and_path_free() {
        let oversized = "z".repeat(MAX_DIAGNOSTIC_FIELD_BYTES * 4);
        let rendered = emitted_detail(
            "host.launch admitted",
            &LaunchPhaseCorrelation::NONE.with_artifact(&oversized),
        );
        assert!(rendered.contains(&"z".repeat(MAX_DIAGNOSTIC_FIELD_BYTES)));
        assert!(!rendered.contains(&"z".repeat(MAX_DIAGNOSTIC_FIELD_BYTES + 1)));
        // The facade's own detail ceiling still bounds the whole record.
        assert!(
            bound_detail(&rendered).text().len() <= MAX_DIAGNOSTIC_DETAIL_BYTES,
            "rendered detail must respect the facade detail ceiling"
        );
        for separator in ['/', '\\'] {
            assert!(
                !rendered.contains(separator),
                "no rendered identity may carry a path separator: {rendered}"
            );
        }
        assert!(!rendered.contains(".."));
    }

    /// The armed leaf guard emits exactly one correlated subordinate phase
    /// record and no terminal.
    ///
    /// HONEST SCOPE: the guard, its drop, the renderer and the facade are all
    /// production code executed here. The correlation is the owner's SLOT
    /// SELECTION `start_approved` binds - installation, generation and the epoch
    /// lineage fence - with synthetic values, because `start_approved` needs a
    /// full admitted physical launch (approved digests, leases and a validated
    /// descriptor) and cannot be reached from here. So this case proves the
    /// emission count, the correlation SHAPE and the terminal freedom of the real
    /// guard; it does not claim that any owner holds these exact identities.
    // WORK_UNIT_CASE: 978/10
    #[test]
    fn the_armed_leaf_guard_emits_one_phase_record_and_no_terminal() {
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation("installation-7")
            .with_generation(7)
            .with_fence("fence-3");
        let failed = capture(|| {
            drop(HostLaunchTerminalGuard::armed(
                "host.launch start failed observed",
                correlation,
            ));
        });
        assert_eq!(
            count(&failed, "host.entrypoint_stage"),
            1,
            "one failed physical launch emits one subordinate phase record: {failed}"
        );
        assert_eq!(
            count(&failed, "host.terminal_error"),
            0,
            "the leaf guard must emit no terminal; lib.rs owns the one terminal: {failed}"
        );
        let failed_record = captured_detail(&failed);
        assert!(
            failed_record.starts_with("phase=host.launch start failed observed "),
            "the guard's own phase token must lead the record: {failed_record}"
        );
        let parsed = rendered_slots(&failed_record);
        for (key, value) in [
            ("installation", "installation-7"),
            ("generation", "7"),
            ("fence", "fence-3"),
        ] {
            assert_eq!(
                slot_value(&parsed, key),
                value,
                "the owner's bound slot {key} must reach the emitted record: {failed_record}"
            );
        }
        // Every slot this contour does not bind stays explicitly absent rather
        // than being filled with an invented identity.
        for key in ["operation", "artifact", "process_start", "reason"] {
            assert_eq!(
                slot_value(&parsed, key),
                MISSING_IDENTITY,
                "an unbound slot must read as explicit absence: {failed_record}"
            );
        }
        let admitted = capture(|| {
            let mut guard =
                HostLaunchTerminalGuard::armed("host.launch start failed observed", correlation);
            guard.disarm();
        });
        assert_eq!(
            count(&admitted, "host.entrypoint_stage"),
            0,
            "an admitted launch emits no failure record: {admitted}"
        );
    }

    /// A correlation the call site already holds must reach the records the
    /// forwarded helper emits: forwarding it away would render identities the
    /// caller holds as explicit absence.
    ///
    /// HONEST SCOPE: this case is deliberately NOT attributed to a case number.
    /// The correlation is the owner's SLOT SELECTION `start_approved` builds and
    /// now forwards, with the same synthetic values the guard case above holds,
    /// and every record below is a REAL emission of the real
    /// Store-before-Kernel sequence taken through its correlation-forwarding
    /// entry point, read back out of a scoped `tracing` subscriber. Reaching
    /// `start_approved` itself needs a full admitted physical launch (approved
    /// digests, retained leases and a validated descriptor), so this case proves
    /// the FORWARDING seam carries the held identities and not `missing`; it
    /// does not claim that any owner holds these exact identities, and it pins
    /// no phase count, ordering or launch behaviour beyond what the sequence
    /// already emits.
    #[test]
    fn a_forwarded_correlation_reaches_same_operation_phase_records() {
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation("installation-7")
            .with_generation(7)
            .with_fence("fence-3");
        let forwarded = capture(|| {
            let result = launch_store_then_kernel_with_correlation(
                &correlation,
                || Ok::<_, HostError>("store-handle"),
                |store| {
                    assert_eq!(*store, "store-handle");
                    Ok(())
                },
                || Ok::<_, HostError>("kernel-handle"),
                |_store| -> Result<(), Box<(&str, String)>> { Ok(()) },
            );
            assert!(matches!(result, Ok(("store-handle", "kernel-handle"))));
        });
        let records = count(&forwarded, "host.entrypoint_stage");
        assert!(
            records > 1,
            "one sequence must emit more than one same-operation phase record: {forwarded}"
        );
        // Every same-operation phase record the forwarded seam emits carries the
        // identities the caller already held, never their absence marker.
        for record in forwarded.split("host.entrypoint_stage").skip(1) {
            // The split yields the RAW captured text between two event markers, so it
            // still carries the facade's own framing and the subscriber's trailing
            // metadata. `rendered_slots` needs the extracted `detail`, and the
            // difference is load-bearing for `reason`: it is the LAST frozen key, so
            // its span has no following `<key>=` anchor and runs to the end of the
            // haystack - on a raw chunk that end is the closing quote of the quoted
            // detail field plus `detail_bytes=…`, which would read as
            // `missing" detail_bytes=…` instead of the absent marker. Every other
            // key survived only because a later anchor happened to stop it first. The
            // extracted text is bound to a name first because `rendered_slots` returns
            // spans that borrow its argument.
            let detail = captured_detail(record);
            let parsed = rendered_slots(&detail);
            for (key, value) in [
                ("installation", "installation-7"),
                ("generation", "7"),
                ("fence", "fence-3"),
            ] {
                assert_eq!(
                    slot_value(&parsed, key),
                    value,
                    "the forwarded {key} identity must reach the emitted record: {record}"
                );
            }
            // Nothing this contour does not bind is invented by forwarding.
            for key in ["operation", "artifact", "process_start", "reason"] {
                assert_eq!(
                    slot_value(&parsed, key),
                    MISSING_IDENTITY,
                    "an unbound slot must read as explicit absence: {record}"
                );
            }
        }
    }

    /// A record composed from several maximal identities must stay inside the
    /// facade's own detail ceiling, and every slot must read as EITHER a complete
    /// bounded value OR the explicit absent marker - never a value cut in half,
    /// and never a key that vanished because it was shed.
    ///
    /// Marker-free: this is a property of `render` itself, already covered by the
    /// case 978/12 vocabulary; it adds no new case denominator.
    #[test]
    fn an_oversized_record_sheds_whole_slots_and_never_truncates_one() {
        // Each identity at the `bound_field` ceiling, so the full record is far
        // past `MAX_DIAGNOSTIC_DETAIL_BYTES` and shedding is actually reached.
        let maximal = "x".repeat(MAX_DIAGNOSTIC_FIELD_BYTES);
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(&maximal)
            .with_operation(&maximal)
            .with_artifact(&maximal)
            .with_process_start(&maximal)
            .with_fence(&maximal)
            .with_reason(&maximal);
        let rendered = correlation.render("host.launch oversized probe");

        assert!(
            rendered.len() <= MAX_DIAGNOSTIC_DETAIL_BYTES,
            "the composed record must fit the facade ceiling untruncated: {} bytes",
            rendered.len()
        );
        // The facade must never see a truncated record, so its own honesty
        // fields stay false - this is the observable consequence of shedding.
        let bounded = bound_detail(&rendered);
        assert!(
            !bounded.truncated(),
            "the facade truncated what render emitted"
        );
        assert_eq!(bounded.original_bytes(), rendered.len());

        // The phase token always leads and is never shed.
        assert!(
            rendered.starts_with("phase=host.launch oversized probe"),
            "the phase token leads the record: {rendered}"
        );

        // Every slot reads either as a complete value or as the absent marker; a
        // value cut mid-token would leave a fragment with no `=` and no marker.
        //
        // Parsed slot sequence, never byte offsets: shedding must never remove a
        // key, so the record still carries exactly the eight frozen keys in the
        // frozen order, and every value is either the absent marker or a whole
        // bounded value.
        let parsed = rendered_slots(&rendered);
        assert_eq!(
            parsed.len(),
            FROZEN_CORRELATION_KEYS.len(),
            "shedding must render every frozen slot, never drop one: {rendered}"
        );
        for (index, key) in FROZEN_CORRELATION_KEYS.iter().enumerate() {
            let value = parsed[index].1;
            assert_eq!(parsed[index].0, *key, "frozen slot order: {rendered}");
            if index == 0 {
                assert_eq!(
                    value, "host.launch oversized probe",
                    "the phase token is never shed: {rendered}"
                );
                continue;
            }
            assert!(
                value == MISSING_IDENTITY || value == maximal,
                "{key} must be a whole bounded value or the frozen absent marker, got {value:?}"
            );
        }
        // Trailing slots are shed first, so the load-bearing prefix survives and
        // the least load-bearing slot is the one that gives way - as an explicit
        // marker, never as a silently missing key.
        assert!(
            rendered.contains("installation="),
            "the installation identity is load-bearing and must survive: {rendered}"
        );
        assert!(
            !rendered.contains("reason=x"),
            "the reason slot is shed first and must not appear as a cut value: {rendered}"
        );
        assert!(
            rendered.contains("reason=missing"),
            "the shed reason slot must still be present as the frozen marker: {rendered}"
        );
    }

    /// Both private correlation twins in this file render the caller's own
    /// already-held identities into every record their real bodies emit: the
    /// approved-path gate and the Doctor-anchor seam, on their success arms and
    /// on their typed-rejection arms alike, while every slot that neither real
    /// caller binds - and so neither twin derives a source for - stays the
    /// renderer's explicit absence marker. Which slots those are differs per
    /// twin, and the table below follows each twin's own caller.
    ///
    /// HONEST SCOPE: each twin's expected slots are read from the binding
    /// expression its OWN real caller passes, and the two callers bind DIFFERENT
    /// slots, so one shared expectation would be a false claim about one of them.
    /// `HostJobBranches::launch` binds `LaunchPhaseCorrelation::NONE`
    /// `.with_installation(host.installation.as_str())`
    /// `.with_fence(host.epoch.current.lineage_id.as_str())`
    /// `.with_artifact(artifact.as_str())` before it forwards that correlation to
    /// this gate, so the approved-path twin's records really do carry a real
    /// artifact digest, and that same binding names no generation, so that twin's
    /// records really do carry the absence marker there. `start_approved` binds
    /// `.with_installation(host.installation.as_str())`
    /// `.with_generation(launch.authority_generation.value())`
    /// `.with_fence(host.epoch.current.lineage_id.as_str())` before it forwards
    /// that correlation to the anchor seam, naming no artifact, so the anchor
    /// seam's records are exactly the mirror image. Neither caller names an owner
    /// operation, a process-start identity or a reason, so those three read as
    /// explicit absence for both twins.
    ///
    /// The bound VALUES below are still this case's own synthetic, non-secret
    /// literals in the same `installation-7` / generation `7` / `fence-3` style
    /// the cases above already hold, so this case proves the forwarding path and
    /// the rendered slots, not any owner's real installation, generation, artifact
    /// digest or lineage fence. No identity here is read from a path, argv, the
    /// environment, a handle, a descriptor or a probe. All six calls really
    /// execute these twins' own bodies against the same fixtures the
    /// `approved_path_tests` cases construct - written temporary locators for the
    /// approved-path gate, the same stored contour and the same absolute and
    /// relative Doctor anchors for the anchor seam - and every record below is a
    /// REAL emission read back out of a scoped `tracing` subscriber, so no SLOT
    /// assertion below can pass on a string this case composed itself. The
    /// canary, separator and rejection-text assertions below are FORWARD GUARDS
    /// instead: neither twin has a path to those values today, so they pass
    /// trivially, and they stand here so that binding any of them into a
    /// correlation slot, or a future `with_*` bound to a path or an error string,
    /// would fail at these exact lines rather than ship silently.
    ///
    /// SWEEP SCOPE: the loop below reads only the `detail` field of each
    /// captured record. The other facade fields on that same line -
    /// `detail_bytes`, `detail_truncated` and `target` - are outside this sweep
    /// and are not asserted here; this file does not control them.
    ///
    /// Reaching `start_approved` itself needs a full admitted physical launch
    /// (approved digests, retained leases and a validated descriptor), so this
    /// case claims no owner-held identity, and each per-phase occurrence count
    /// below is only the arm these calls reached in these two bodies.
    #[allow(
        clippy::too_many_lines,
        reason = "one case drives both twins' real bodies and reads every captured record, so its per-phase occurrence table stays in one place beside the calls that produced it"
    )]
    #[test]
    fn a_forwarded_correlation_reaches_both_twins_real_phase_records() {
        /// One twin's slot expectation: the slots its real caller binds with the
        /// values it binds there, then the slots that binding leaves unbound.
        type TwinSlots<'s> = (&'s [(&'s str, &'s str)], &'s [&'s str]);
        use super::{
            approved_launch_paths_with_correlation,
            kernel_arguments_with_doctor_anchor_with_correlation,
        };

        // The correlation `HostJobBranches::launch` really forwards into
        // `approved_launch_paths_with_correlation`: the Host installation
        // identity, the installation epoch's lineage identity and the approved
        // artifact digest of the exact branch it launches. That caller binds no
        // generation there, so this twin's records must show the absence marker
        // in that slot. The artifact digest below is a synthetic non-secret
        // literal in the shape the caller binds, and it is deliberately NOT the
        // argv digest canary further down, because this value legitimately
        // reaches this twin's own records.
        let approved_artifact = "c".repeat(64);
        let approved_correlation = LaunchPhaseCorrelation::NONE
            .with_installation("installation-7")
            .with_fence("fence-3")
            .with_artifact(approved_artifact.as_str());
        // The correlation `start_approved` really forwards into
        // `kernel_arguments_with_doctor_anchor_with_correlation`: the Host
        // installation identity, the approved descriptor's authority generation
        // and the installation epoch's lineage identity, naming no artifact. The
        // generation comes from the same descriptor field the caller binds, never
        // from the opaque `generation: &PlatformHandle` argument, which holds no
        // bounded numeric spelling.
        let doctor_correlation = LaunchPhaseCorrelation::NONE
            .with_installation("installation-7")
            .with_generation(7)
            .with_fence("fence-3");
        // The approved-locator fixture shape the `approved_path_tests` cases
        // build: a written temporary file and its canonical path. These names are
        // distinct because this case shares one process with those cases.
        let canonical = |name: &str| -> std::path::PathBuf {
            let path =
                std::env::temp_dir().join(format!("eliot-host-fwd-{}-{name}", std::process::id()));
            std::fs::write(&path, b"binding")
                .unwrap_or_else(|error| panic!("test fixture is not writable: {error}"));
            std::fs::canonicalize(&path)
                .unwrap_or_else(|error| panic!("test fixture cannot be canonicalized: {error}"))
        };
        let locator = |path: &std::path::Path| {
            eliot_platform::PlatformHandle::new(path.to_string_lossy().into_owned())
                .unwrap_or_else(|error| panic!("test fixture path is not a handle: {error}"))
        };
        let executable_path = canonical("bind-ok-exe");
        let executable = locator(&executable_path);
        let config_path = canonical("bind-ok-cfg");
        let config = locator(&config_path);
        let substitute_path = canonical("bind-exe-fake");
        let substitute = locator(&substitute_path);
        let missing =
            std::env::temp_dir().join(format!("eliot-host-fwd-{}-absent", std::process::id()));
        // The stored contour and the absolute and relative Doctor anchors the
        // `approved_path_tests` doctor case constructs.
        let argument = |value: &str| {
            eliot_platform::PlatformHandle::new(value.to_owned())
                .unwrap_or_else(|error| panic!("test handle is invalid: {error}"))
        };
        let stored = vec![
            argument("--work-root"),
            argument(r"C:\work"),
            argument("--doctor-artifact-sha256"),
            argument(&"a".repeat(64)),
            argument("--testd-artifact-sha256"),
            argument(&"b".repeat(64)),
        ];
        let doctor = argument(r"C:\install\eliot-doctor.exe");
        let relative = argument(r"relative\eliot-doctor.exe");
        let without_doctor = vec![argument("--work-root"), argument(r"C:\work")];
        let path_canary = executable_path.to_string_lossy().into_owned();
        let substitute_canary = substitute_path.to_string_lossy().into_owned();
        let missing_canary = missing.to_string_lossy().into_owned();
        let config_canary = config_path.to_string_lossy().into_owned();
        let relative_canary = relative.as_str().to_owned();
        let digest_canary = "a".repeat(64);

        // One scoped subscriber over all six calls, so every record asserted on
        // below is one these real executions emitted.
        let executed = capture(|| {
            // The approved-path gate: the admitted arm, the substitution refusal
            // and the canonicalization refusal.
            if let Err(error) = approved_launch_paths_with_correlation(
                &approved_correlation,
                &executable_path,
                &executable,
                &config_path,
                &config,
            ) {
                panic!("exact canonical locators must stay admitted: {error}");
            }
            let Err(HostError::ProcessContour(reason)) = approved_launch_paths_with_correlation(
                &approved_correlation,
                &executable_path,
                &substitute,
                &config_path,
                &config,
            ) else {
                panic!("a substituted executable locator must stay refused");
            };
            assert!(
                reason.contains("executable locator is not the approved path"),
                "unexpected rejection reason: {reason}"
            );
            let Err(HostError::ProcessContour(_)) = approved_launch_paths_with_correlation(
                &approved_correlation,
                &missing,
                &executable,
                &config_path,
                &config,
            ) else {
                panic!("an absent locator must stay refused");
            };
            // The Doctor-anchor seam: the admitted arm, a relative anchor and a
            // contour without the digested doctor role.
            if let Err(error) = kernel_arguments_with_doctor_anchor_with_correlation(
                &doctor_correlation,
                &stored,
                &doctor,
            ) {
                panic!("the absolute doctor anchor must inject: {error}");
            }
            let Err(HostError::ProcessContour(reason)) =
                kernel_arguments_with_doctor_anchor_with_correlation(
                    &doctor_correlation,
                    &stored,
                    &relative,
                )
            else {
                panic!("a relative doctor anchor must stay refused");
            };
            assert!(
                reason.to_lowercase().contains("absolute"),
                "unexpected rejection reason: {reason}"
            );
            let Err(HostError::ProcessContour(reason)) =
                kernel_arguments_with_doctor_anchor_with_correlation(
                    &doctor_correlation,
                    &without_doctor,
                    &doctor,
                )
            else {
                panic!("a contour without the digested doctor role must stay refused");
            };
            assert!(
                reason.to_lowercase().contains("doctor"),
                "the missing-role reason must name the doctor role: {reason}"
            );
        });
        for path in [&executable_path, &config_path, &substitute_path] {
            let _ = std::fs::remove_file(path);
        }

        // The `detail` field of each captured record, in emission order, never
        // composed by this case. ONLY that field is swept below: the rest of the
        // facade line (`detail_bytes`, `detail_truncated`, `target`) is outside
        // this sweep and is not asserted here.
        let records: Vec<String> = executed
            .split("host.entrypoint_stage")
            .skip(1)
            .map(captured_detail)
            .collect();
        // Each twin's own phases, with how often the calls above reached them, in
        // the same order as the per-twin slot expectations beside it.
        let arms: [(&str, &[(&str, usize)]); 2] = [
            (
                "approved paths",
                &[
                    ("host.launch approved paths requested", 3),
                    ("host.launch approved paths admitted", 1),
                    ("host.launch substitution preserved", 1),
                    ("host.launch approved paths typed rejection", 1),
                ],
            ),
            (
                "doctor anchor",
                &[
                    ("host.launch doctor anchor requested", 3),
                    ("host.launch doctor anchor admitted", 1),
                    ("host.launch doctor anchor typed rejection", 2),
                ],
            ),
        ];
        // Per-twin slot expectations, in that same order: first the slots this
        // twin's REAL caller binds and the value it binds there, then the slots
        // that same binding leaves unbound. The two twins differ because their
        // real callers differ: `HostJobBranches::launch` binds an artifact digest
        // and names no generation, while `start_approved` binds a generation and
        // names no artifact digest.
        let slots: [TwinSlots; 2] = [
            (
                &[
                    ("installation", "installation-7"),
                    ("artifact", approved_artifact.as_str()),
                    ("fence", "fence-3"),
                ],
                &["generation", "operation", "process_start", "reason"],
            ),
            (
                &[
                    ("installation", "installation-7"),
                    ("generation", "7"),
                    ("fence", "fence-3"),
                ],
                &["operation", "artifact", "process_start", "reason"],
            ),
        ];
        let mut reached = 0_usize;
        for ((twin, phases), (bound, unbound)) in arms.into_iter().zip(slots) {
            for (phase, expected) in phases {
                let matching: Vec<&String> = records
                    .iter()
                    .filter(|record| record.starts_with(&format!("phase={phase} ")))
                    .collect();
                assert_eq!(
                    matching.len(),
                    *expected,
                    "the {twin} twin must emit {phase} exactly {expected} time(s) for the calls above: {executed}"
                );
                for record in matching {
                    assert!(
                        record.starts_with(&format!("phase={phase} ")),
                        "the phase token must lead the record: {record}"
                    );
                    let parsed = rendered_slots(record);
                    assert_eq!(
                        slot_value(&parsed, "phase").to_owned(),
                        phase.to_string(),
                        "the record must carry the phase its own twin emitted: {record}"
                    );
                    // Exactly the slots this twin's real caller binds, with the
                    // value that caller binds, reach this twin's record as real
                    // values and never as absence markers. HONEST LIMIT: this case
                    // drives the twin with its OWN call of the real bindings, so it
                    // cannot see whether `launch` or `start_approved` passes that
                    // correlation at all — the production call sites are pinned by
                    // the integration target's source-byte all-sites scan, named here
                    // so a reader knows where that proof lives.
                    for &(key, value) in bound {
                        assert_eq!(
                            slot_value(&parsed, key),
                            value,
                            "the {twin} twin renders the {key}={value} its caller's binding carries: {record}"
                        );
                    }
                    // Exactly the slots that same binding leaves unnamed, and which
                    // this twin therefore derives no source for, read as explicit
                    // absence instead of an invented value.
                    for &key in unbound {
                        assert_eq!(
                            slot_value(&parsed, key),
                            MISSING_IDENTITY,
                            "the {twin} twin's own caller binds no {key}, so forwarding must leave it absent: {record}"
                        );
                    }
                    // FORWARD GUARD, not a proof about today: no phase literal in
                    // either twin and no value either real caller binds contains a
                    // path separator, so these lines pass trivially. They are worth
                    // keeping because a future `with_*` bound to a path would fail
                    // exactly here, where a leaked locator becomes visible.
                    for separator in ['\\', '/'] {
                        assert!(
                            !record.contains(separator),
                            "forward guard: no locator, argv or path value may reach this record: {record}"
                        );
                    }
                    // FORWARD GUARD, one canary per value a twin genuinely receives
                    // as an argument: the approved executable, config and
                    // substituted locators and the absent locator reach the
                    // approved-path twin, the absolute and relative Doctor anchors
                    // reach the anchor seam, and the three contour flags and the
                    // stored doctor digest reach the anchor seam inside its stored
                    // argument list. Nothing in either twin binds any of them, so
                    // these lines pass trivially; they are worth keeping because
                    // binding any one of them into a correlation slot would fail
                    // here, at the slot, rather than reach a record. Nothing here
                    // is a claim that a leak was observed and fixed. The two
                    // values deliberately NOT in this list never reach either twin
                    // at all: `--doctor-executable-path` is only compared and
                    // constructed inside the anchor seam, and `binding` is fixture
                    // file CONTENT that neither twin ever reads - they only
                    // canonicalize and compare paths - so asserting their absence
                    // could not fail.
                    for canary in [
                        path_canary.as_str(),
                        config_canary.as_str(),
                        substitute_canary.as_str(),
                        missing_canary.as_str(),
                        doctor.as_str(),
                        relative_canary.as_str(),
                        "--work-root",
                        "--doctor-artifact-sha256",
                        "--testd-artifact-sha256",
                        digest_canary.as_str(),
                    ] {
                        assert!(
                            !record.contains(canary),
                            "forward guard: no fixture value a twin receives may reach this record: {record}"
                        );
                    }
                    // FORWARD GUARD, same standing as the separators above: no
                    // typed rejection text is rendered into any slot today, so
                    // these lines pass trivially, and a future `with_*` bound to
                    // an error string would fail here.
                    for rejection in [
                        "executable locator is not the approved path",
                        "must be absolute",
                        "digested doctor role",
                    ] {
                        assert!(
                            !record.contains(rejection),
                            "forward guard: typed rejection text may never reach a record: {record}"
                        );
                    }
                }
                reached = reached.saturating_add(*expected);
            }
        }
        assert_eq!(
            records.len(),
            reached,
            "every captured record must be one of these two twins' own arms: {executed}"
        );
    }
}
