//! Kernel-unavailability admission guard and recovery-view boundary.
//!
//! Traceability: Implementation I1.13 (Kernel unavailability); I1.11 startup
//! algorithm (front-door readiness never unlocks Material authority by itself).
//!
//! This is an ordinary view/guard module: it mints no Session, lease,
//! canonical write, or Material authority. It only classifies admission
//! attempts and projects the restricted Recovery View so surviving
//! Host/Watchdog interactions fail closed with the stated data boundary.
//!
//! Forbidden authority: no semantic oracle, no alternate lease authority, no
//! canonical transition, no external-effect claim beyond observed evidence.

#![forbid(unsafe_code)]

use std::fmt;

/// Kernel reachability from the caller's perspective.
///
/// `Unavailable` means the Kernel composition cannot issue new authority.
/// Host and Watchdog remain independently reachable where possible; their
/// surviving interactions are routed to [`RecoveryView`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelAvailability {
    /// Kernel is reachable and normal admission rules apply.
    Available,
    /// Kernel is unreachable: every new authority admission is denied.
    Unavailable,
}

/// User Broker reachability.
///
/// Broker loss is route-specific: it never blocks machine/service-safe work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerAvailability {
    /// User Broker is reachable.
    Available,
    /// User Broker is unreachable: only `interactive_user:<sid>` work defers.
    Unavailable,
}

/// Denial reason for one admission attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDenial {
    /// Kernel is unavailable; no new authority of this kind may be issued.
    KernelUnavailable,
    /// User Broker is unavailable and this route is user-session-bound.
    BrokerDeferred,
}

impl fmt::Display for AdmissionDenial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KernelUnavailable => formatter.write_str("kernel unavailable: admission denied"),
            Self::BrokerDeferred => {
                formatter.write_str("user broker unavailable: interactive work deferred")
            }
        }
    }
}

impl std::error::Error for AdmissionDenial {}

/// Shared Kernel-availability guard.
///
/// Every Session, lease, canonical-write, and external-Material-authority
/// admission path calls this before any other check. When the Kernel is
/// unavailable the attempt is denied; no new authority is issued.
pub fn check_kernel_admission(kernel: KernelAvailability) -> Result<(), AdmissionDenial> {
    match kernel {
        KernelAvailability::Available => Ok(()),
        KernelAvailability::Unavailable => Err(AdmissionDenial::KernelUnavailable),
    }
}

/// Admits a new Session only when the Kernel is available.
pub fn admit_new_session(kernel: KernelAvailability) -> Result<(), AdmissionDenial> {
    check_kernel_admission(kernel)
}

/// Admits a new lease only when the Kernel is available.
pub fn admit_lease(kernel: KernelAvailability) -> Result<(), AdmissionDenial> {
    check_kernel_admission(kernel)
}

/// Admits a canonical write only when the Kernel is available.
pub fn admit_canonical_write(kernel: KernelAvailability) -> Result<(), AdmissionDenial> {
    check_kernel_admission(kernel)
}

/// Admits an external Material authority grant only when the Kernel is
/// available.
pub fn admit_external_material_authority(
    kernel: KernelAvailability,
) -> Result<(), AdmissionDenial> {
    check_kernel_admission(kernel)
}

/// Restricted Recovery View exposed while the Kernel is unavailable.
///
/// The view contains exactly four status categories: build, generation, ORS,
/// and incident state. Semantic task recovery is never projected here; it
/// waits for canonical access (see [`semantic_task_recovery_deferral`]).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RecoveryView {
    /// Build identity (artifact digests, protocol versions).
    pub build: serde_json::Value,
    /// Fencing generation / authority-epoch summary.
    pub generation: serde_json::Value,
    /// ORS (Operational Recovery State) summary.
    pub ors: serde_json::Value,
    /// Incident / supervision-evidence summary.
    pub incident: serde_json::Value,
}

impl RecoveryView {
    /// Builds the restricted view. Callers supply only the four allowed
    /// categories; there is no field for semantic/task state by construction.
    pub fn new(
        build: serde_json::Value,
        generation: serde_json::Value,
        ors: serde_json::Value,
        incident: serde_json::Value,
    ) -> Self {
        Self {
            build,
            generation,
            ors,
            incident,
        }
    }

    /// Projects the view to JSON. The object carries exactly the four allowed
    /// keys; any other category is a construction error, never silently added.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "build": self.build,
            "generation": self.generation,
            "ors": self.ors,
            "incident": self.incident,
        })
    }

    /// Returns the allowed top-level keys in stable order.
    pub fn allowed_keys() -> [&'static str; 4] {
        ["build", "generation", "ors", "incident"]
    }
}

/// Which competent owner produced a recovery observation (I1.9, #1972 AUD2).
///
/// The source is part of the observation itself, never inferred from the
/// caller: Host owns Host observations, Watchdog owns Watchdog observations,
/// and the retained ORS summary is Kernel operational state kept historical
/// with its frontier (I1.9 ownership matrix).
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum RecoveryObservationSource {
    /// Host-issued observation (Host control evidence).
    Host,
    /// Watchdog-issued observation (independent supervision spool).
    Watchdog,
}

/// Host-issued recovery observation retained by the surviving endpoint.
///
/// Carries the owner's source, generation, observation time, and
/// availability/staleness evidence: `reachable` reports availability, and
/// the explicit `observed_at_ms` is the staleness evidence consumers
/// compare against their own clock. Last-known data is never labeled
/// current — the builder below projects it as `historical`. Only
/// build-identity fields travel here; there is no slot for semantic or
/// task state.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ObservedHostRecovery {
    /// Owning source; always [`RecoveryObservationSource::Host`].
    pub source: RecoveryObservationSource,
    /// Host activation/epoch generation the owner reported.
    pub generation: u64,
    /// Observation time on the owner's clock, unix milliseconds.
    pub observed_at_ms: u64,
    /// Availability: the Host was independently reachable when observed.
    pub reachable: bool,
    /// Allowed build-identity fields only (artifact digests, protocol versions).
    pub build: serde_json::Value,
}

/// Watchdog-issued recovery observation retained by the surviving endpoint.
///
/// Same observation contract as [`ObservedHostRecovery`]: source,
/// generation (supervision epoch), observation time, and
/// availability/staleness evidence. Only incident/supervision-evidence
/// fields travel here; there is no slot for semantic or task state.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ObservedWatchdogRecovery {
    /// Owning source; always [`RecoveryObservationSource::Watchdog`].
    pub source: RecoveryObservationSource,
    /// Supervision epoch the owner reported under.
    pub generation: u64,
    /// Observation time on the owner's clock, unix milliseconds.
    pub observed_at_ms: u64,
    /// Availability: the Watchdog was independently reachable when observed.
    pub reachable: bool,
    /// Allowed incident-state fields only (supervision evidence, Problem State).
    pub incident: serde_json::Value,
}

/// Previously retained ORS (Operational Recovery State) summary.
///
/// Always historical with its frontier: the builder below projects it with
/// `"status": "historical"` and the exact frontier it was retained at, so
/// it can never read as current authority. Unavailable current ORS state
/// stays unavailable — callers pass [`None`] and the builder projects
/// `"status": "unavailable"` instead of inventing state. Only operational
/// recovery fields travel here; semantic tasks are never recovered from
/// process metadata, archive copies, or UI cache.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RetainedOrsSummary {
    /// Progress frontier the summary was retained at.
    pub frontier: u64,
    /// Authority-epoch generation the summary belongs to.
    pub generation: u64,
    /// Observation time on the owner's clock, unix milliseconds.
    pub observed_at_ms: u64,
    /// Allowed operational-recovery fields only.
    pub summary: serde_json::Value,
}

/// Builds the narrow typed recovery-view projection for the existing
/// surviving control/status response (I1.13, #1972 AUD2).
///
/// Inputs are competent-owner observations — source, generation,
/// observation time, and availability/staleness on each — never a
/// caller-supplied [`KernelAvailability`] enum. The output reuses the
/// existing [`RecoveryView`] boundary, so exactly the four allowed
/// categories (build, generation, ORS, incident) can appear:
///
/// - `build` carries the Host build identity when the Host was reachable,
///   else `"status": "unavailable"`;
/// - `generation` carries both owner generations with their observation
///   times; an unreachable owner reads `"unavailable"`, never a zero
///   value presented as current;
/// - `ors` carries the retained summary as `"historical"` with its
///   frontier, or `"unavailable"` when there is none — unavailable
///   current ORS state stays unavailable;
/// - `incident` carries the Watchdog incident state when reachable, else
///   `"status": "unavailable"`.
///
/// Nothing here mints Session, lease, canonical-write, or Material
/// authority; no fallback database or second operational owner is created,
/// and Kernel's writable ORS is never opened — the retained summary
/// arrives as a value.
pub fn build_kernel_unavailable_view(
    observed_host: &ObservedHostRecovery,
    observed_watchdog: &ObservedWatchdogRecovery,
    retained_ors_summary: Option<&RetainedOrsSummary>,
) -> RecoveryView {
    let build = if observed_host.reachable {
        serde_json::json!({
            "status": "historical",
            "generation": observed_host.generation,
            "observed_at_ms": observed_host.observed_at_ms,
            "build": observed_host.build,
        })
    } else {
        serde_json::json!({ "status": "unavailable" })
    };
    let host_generation = if observed_host.reachable {
        serde_json::json!({
            "status": "historical",
            "generation": observed_host.generation,
            "observed_at_ms": observed_host.observed_at_ms,
        })
    } else {
        serde_json::json!({ "status": "unavailable" })
    };
    let watchdog_generation = if observed_watchdog.reachable {
        serde_json::json!({
            "status": "historical",
            "generation": observed_watchdog.generation,
            "observed_at_ms": observed_watchdog.observed_at_ms,
        })
    } else {
        serde_json::json!({ "status": "unavailable" })
    };
    let generation = serde_json::json!({
        "host": host_generation,
        "watchdog": watchdog_generation,
    });
    let ors = match retained_ors_summary {
        Some(retained) => serde_json::json!({
            "status": "historical",
            "frontier": retained.frontier,
            "generation": retained.generation,
            "observed_at_ms": retained.observed_at_ms,
            "ors": retained.summary,
        }),
        None => serde_json::json!({ "status": "unavailable" }),
    };
    let incident = if observed_watchdog.reachable {
        serde_json::json!({
            "status": "historical",
            "generation": observed_watchdog.generation,
            "observed_at_ms": observed_watchdog.observed_at_ms,
            "incident": observed_watchdog.incident,
        })
    } else {
        serde_json::json!({ "status": "unavailable" })
    };
    RecoveryView::new(build, generation, ors, incident)
}

/// Semantic task recovery is deferred pending canonical access.
///
/// While the Kernel is unavailable no semantic recovery action is offered;
/// the caller must re-attempt after canonical access is restored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryDeferral {
    /// Machine-readable reason code.
    pub reason: &'static str,
}

impl fmt::Display for RecoveryDeferral {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.reason)
    }
}

/// Defers semantic task recovery pending canonical access.
pub fn semantic_task_recovery_deferral() -> RecoveryDeferral {
    RecoveryDeferral {
        reason: "semantic task recovery deferred pending canonical access",
    }
}

/// Observed state of a previously running external tool.
///
/// A tool is never claimed stopped without observed enforcement evidence.
/// Unknown state stays explicitly unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalToolStatus {
    /// Termination was directly observed (enforcement evidence exists).
    EnforcementObservedStopped,
    /// No termination evidence exists; enforcement is unobserved.
    EnforcementUnobserved,
}

impl fmt::Display for ExternalToolStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnforcementObservedStopped => {
                formatter.write_str("enforcement observed: stopped")
            }
            Self::EnforcementUnobserved => formatter.write_str("enforcement unobserved"),
        }
    }
}

/// Reports the status of a previously running external tool.
///
/// `termination_evidence` must be direct observation of enforcement (receipt,
/// probe, or supervisor confirmation). Anything else — including "Kernel is
/// down so effects must have ceased" — reports [`ExternalToolStatus::EnforcementUnobserved`].
pub fn report_external_tool_status(termination_evidence: bool) -> ExternalToolStatus {
    if termination_evidence {
        ExternalToolStatus::EnforcementObservedStopped
    } else {
        ExternalToolStatus::EnforcementUnobserved
    }
}

/// Lifecycle classification of the Kernel process after a failed access
/// (I1.13, #1972 AUD4).
///
/// The three states stay distinct: a missing response is never confirmed
/// termination, an unobserved tool is never claimed stopped, and only a
/// competent-owner termination receipt confirms the stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelAccessTermination {
    /// A competent-owner termination receipt was observed.
    StoppedConfirmed,
    /// The tool/process may still run; no enforcement evidence exists.
    EnforcementUnobserved,
    /// Missing response, timeout, or cancellation: unknown, never a receipt.
    OutcomeUnknown,
}

impl KernelAccessTermination {
    /// Stable diagnostic code for the classification. Only the variant is
    /// emitted; a failure payload is never logged.
    pub fn observation_code(&self) -> &'static str {
        match self {
            Self::StoppedConfirmed => "stopped_confirmed",
            Self::EnforcementUnobserved => "enforcement_unobserved",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }
}

impl From<ExternalToolStatus> for KernelAccessTermination {
    /// Reuses the existing external-tool projection: observed enforcement
    /// confirms the stop, unobserved enforcement stays unobserved.
    fn from(status: ExternalToolStatus) -> Self {
        match status {
            ExternalToolStatus::EnforcementObservedStopped => Self::StoppedConfirmed,
            ExternalToolStatus::EnforcementUnobserved => Self::EnforcementUnobserved,
        }
    }
}

/// Classifies one failed Kernel access (I1.13, #1972 AUD4).
///
/// No `eliot_ipc::TransportError` variant carries a competent-owner
/// termination receipt, so every failure — a missing response, a timeout,
/// or a cancellation request — classifies
/// [`KernelAccessTermination::OutcomeUnknown`]. A cancellation or timeout
/// is not a termination receipt; only [`confirm_kernel_termination`] with
/// an observed receipt may report `StoppedConfirmed`.
pub fn classify_kernel_access_failure(
    _error: &eliot_ipc::TransportError,
) -> KernelAccessTermination {
    KernelAccessTermination::OutcomeUnknown
}

/// Confirms Kernel termination only from an observed receipt (I1.13, #1972
/// AUD4).
///
/// `termination_receipt_observed` must be a competent-owner termination
/// receipt (supervisor-confirmed exit, observed enforcement). Without one
/// the outcome stays unknown — it never degrades into a stop claim and
/// never borrows the tool-running `EnforcementUnobserved` state.
pub fn confirm_kernel_termination(
    termination_receipt_observed: bool,
) -> KernelAccessTermination {
    if termination_receipt_observed {
        KernelAccessTermination::StoppedConfirmed
    } else {
        KernelAccessTermination::OutcomeUnknown
    }
}

/// Failed Kernel access routed to the recovery projection (I1.13, #1972 AUD4).
///
/// The termination classification and the bounded unavailable view travel
/// together so no consumer can serve the view while implying a stop the
/// failure never confirmed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedAccessRecovery {
    /// Lifecycle classification of the failed access.
    pub termination: KernelAccessTermination,
    /// Bounded unavailable view; see [`build_kernel_unavailable_view`].
    pub view: RecoveryView,
}

/// Routes one failed Kernel access to the recovery-view projection (I1.13,
/// #1972 AUD4).
///
/// The missing response classifies `OutcomeUnknown` (never confirmed
/// termination — see [`classify_kernel_access_failure`]) and the view is
/// built from the competent-owner observations by
/// [`build_kernel_unavailable_view`]. Served by the surviving
/// control/status path; it mints no authority.
pub fn route_failed_kernel_access_to_recovery_view(
    error: &eliot_ipc::TransportError,
    observed_host: &ObservedHostRecovery,
    observed_watchdog: &ObservedWatchdogRecovery,
    retained_ors_summary: Option<&RetainedOrsSummary>,
) -> FailedAccessRecovery {
    FailedAccessRecovery {
        termination: classify_kernel_access_failure(error),
        view: build_kernel_unavailable_view(observed_host, observed_watchdog, retained_ors_summary),
    }
}

/// Prefix binding user-session-bound routes to the User Broker.
pub const INTERACTIVE_USER_ROUTE_PREFIX: &str = "interactive_user:";

/// Returns true when `route` is bound to a user session (`interactive_user:<sid>`).
pub fn is_interactive_user_route(route: &str) -> bool {
    match route.strip_prefix(INTERACTIVE_USER_ROUTE_PREFIX) {
        Some(sid) => !sid.trim().is_empty(),
        None => false,
    }
}

/// Broker-unavailable routing decision for one route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerRouteDecision {
    /// Route remains admissible (machine/service-safe or broker available).
    Admit,
    /// User-session-bound work is deferred until the broker returns.
    Defer,
    /// Re-presented user-session-bound work reconciles against durable state.
    Reconcile,
}

/// Routes one operation under broker availability.
///
/// When only the User Broker is unavailable, machine/service-safe routes and
/// canonical state remain available; only `interactive_user:<sid>` work
/// defers (first attempt) or reconciles (re-attempt).
pub fn decide_broker_route(
    broker: BrokerAvailability,
    route: &str,
    is_reattempt: bool,
) -> BrokerRouteDecision {
    match broker {
        BrokerAvailability::Available => BrokerRouteDecision::Admit,
        BrokerAvailability::Unavailable => {
            if is_interactive_user_route(route) {
                if is_reattempt {
                    BrokerRouteDecision::Reconcile
                } else {
                    BrokerRouteDecision::Defer
                }
            } else {
                BrokerRouteDecision::Admit
            }
        }
    }
}

/// Admits a machine-scoped canonical operation under broker availability.
///
/// Machine-scoped canonical work never depends on the User Broker, so it
/// stays admissible even when the broker is unavailable. Kernel
/// unavailability still denies it via [`admit_canonical_write`]; callers
/// check the Kernel guard first, then this broker route decision.
pub fn admit_machine_canonical_operation(
    kernel: KernelAvailability,
    _broker: BrokerAvailability,
) -> Result<BrokerRouteDecision, AdmissionDenial> {
    check_kernel_admission(kernel)?;
    // Machine-scoped canonical work never depends on the User Broker, so any
    // broker state still admits it. The parameter is kept so callers route
    // broker loss through this single decision point instead of branching.
    Ok(BrokerRouteDecision::Admit)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn shared_guard_denies_all_four_authorities_without_kernel() {
        for attempt in [
            admit_new_session(KernelAvailability::Unavailable),
            admit_lease(KernelAvailability::Unavailable),
            admit_canonical_write(KernelAvailability::Unavailable),
            admit_external_material_authority(KernelAvailability::Unavailable),
        ] {
            assert_eq!(attempt, Err(AdmissionDenial::KernelUnavailable));
        }
    }
}
