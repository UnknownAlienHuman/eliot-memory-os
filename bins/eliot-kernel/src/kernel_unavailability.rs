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
