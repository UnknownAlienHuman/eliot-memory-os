//! Host-owned I1.5 activation, demand-start and lease-gated idle-drain
//! orchestration over the crash-safe `HostStateJournal`.
//!
//! Architecture: A13.2 (the Host Supervisor operates outside the shared
//! Kernel/Watchdog/Doctor failure domain), A2.2 (a role description defines
//! function, not implicit permission), I1.2 (Host owns the activation lineage
//! and the `HostStateJournal`).
//! Implementation: I1.5 (demand-start, observable use, supervision and idle
//! shutdown) and I14.23 (safe shutdown / `DrainCommit` linearization).
//!
//! This module owns the Host half of the I1.5 lifecycle and nothing else:
//!
//! * the observable-use trigger vocabulary and the capabilities each trigger
//!   class may request (I1.5 "Observable use and activation");
//! * coalescing a concurrent trigger behind the current compatible
//!   installation/activation generation instead of starting a second contour;
//! * the generation-bound admission result a caller receives, so admission is
//!   never inferred from process liveness (I1.5: "Starting a process, opening a
//!   pipe or seeing an old heartbeat is not sufficient");
//! * the wake/attach classification against the durable drain linearization
//!   point: pre-commit cancels the drain and returns the *same* generation to
//!   `ACTIVE`, post-commit queues the next activation generation as a durable
//!   `WakeIntent`;
//! * the generation-scoped lease census that gates the ordered idle drain.
//!
//! Durable ownership boundary: every state change here is an append through
//! the existing [`HostComposition::append_record`] reducer, so
//! `eliot-host-state` stays the single writer and owner of the activation state
//! machine. This module never writes a second lifecycle, never invents a
//! receipt, and never treats a live process, an open pipe or a stale heartbeat
//! as a lease.
//!
//! Census honesty: the RuntimeLease row family I1.5 assigns to the Kernel's ORS
//! does not exist in the current source, so the runtime-lease leg of
//! [`HostComposition::idle_lease_census`] reports exactly the durable
//! runtime-lease references the current activation generation holds. An empty
//! reference set means "this generation holds no runtime-lease reference", so
//! the gate is generation-scoped by construction and a future Kernel/ORS lease
//! family must replace that leg rather than sit beside it. The supervision leg
//! re-uses the one published, Kernel-signed supervision-lease mirror Host
//! already commits and verifies for the Watchdog spool
//! (`watchdog_publication::live_supervision_obligation`).

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{ResourceGeneration, StateFence};
use eliot_host_state::{
    ActivationState, DrainRecord, DrainState, EliotActivationRecord, EpochIdentity,
    EpochTransition, HostState, HostStateRecord, ServiceSafetyClass, WakeDisposition, WakeRecord,
    record_checksum,
};
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::{WakeIntent, WakeIntentState};

use super::watchdog_publication::live_supervision_obligation;
use super::{
    HostBranchDisposition, HostComposition, HostError, HostTerminalGuard, drain_rearm_operation,
    fresh_identity, host_lifecycle_observe_drain, host_lifecycle_observe_requested,
    host_lifecycle_observe_scm, operation, record_fence,
};

/// Capability every I1.5 observable-use trigger needs: the Host-owned
/// runtime/supervision contour itself.
pub const CAPABILITY_RUNTIME_SUPERVISION: &str = "runtime-supervision";
/// Capability required by any trigger that reads or writes canonical state.
pub const CAPABILITY_CANONICAL_STORE: &str = "canonical-store";
/// Capability required by any trigger whose obligation needs the independent
/// Watchdog service to keep sensing.
pub const CAPABILITY_INDEPENDENT_SUPERVISION: &str = "independent-supervision";

/// One I1.5 observable-use trigger class.
///
/// The vocabulary is closed and frozen: it is the durable `trigger_class`
/// spelling written into `EliotActivationRecord`, so a new surface joins by
/// reusing an existing class instead of inventing free text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationTriggerClass {
    /// `eliot` CLI request from an authenticated user session.
    CliRequest,
    /// Native UI request over the role-filtered ControlBoard/Operator contract.
    UiRequest,
    /// Agent bridge / MCP attach or tool call.
    AgentBridgeAttach,
    /// ELIOT-launched `AgentAttempt` or external-agent reconciliation.
    AgentAttempt,
    /// Approved maintenance, backup, migration or recovery job.
    ApprovedMaintenanceJob,
    /// Protected external effect that still requires supervision.
    ProtectedExternalEffect,
    /// Watchdog observation of a registered agent/bridge event requiring
    /// reconciliation.
    WatchdogRegisteredActivity,
    /// Task Scheduler wake created by an admitted `WakeIntent`.
    ScheduledWake,
}

impl ActivationTriggerClass {
    /// Frozen durable spelling of the trigger class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CliRequest => "cli-request",
            Self::UiRequest => "ui-request",
            Self::AgentBridgeAttach => "agent-bridge-attach",
            Self::AgentAttempt => "agent-attempt",
            Self::ApprovedMaintenanceJob => "approved-maintenance-job",
            Self::ProtectedExternalEffect => "protected-external-effect",
            Self::WatchdogRegisteredActivity => "watchdog-registered-activity",
            Self::ScheduledWake => "scheduled-wake",
        }
    }

    /// Capabilities this trigger class may request.
    ///
    /// This is the "start only the remaining capabilities required by the
    /// admitted request" boundary: the durable `requested_capabilities` set of
    /// the activation generation is the union of exactly these entries, while
    /// the admitted set is read back from the dependency branches the Host
    /// actually started.
    #[must_use]
    pub const fn requested_capabilities(self) -> &'static [&'static str] {
        match self {
            Self::CliRequest
            | Self::UiRequest
            | Self::AgentBridgeAttach
            | Self::AgentAttempt
            | Self::ProtectedExternalEffect => &[
                CAPABILITY_RUNTIME_SUPERVISION,
                CAPABILITY_CANONICAL_STORE,
                CAPABILITY_INDEPENDENT_SUPERVISION,
            ],
            Self::ApprovedMaintenanceJob => {
                &[CAPABILITY_RUNTIME_SUPERVISION, CAPABILITY_CANONICAL_STORE]
            }
            // A Watchdog observation or a scheduled wake is a reconciliation
            // obligation, not a canonical-data obligation: it never requests
            // the store branch.
            Self::WatchdogRegisteredActivity | Self::ScheduledWake => &[
                CAPABILITY_RUNTIME_SUPERVISION,
                CAPABILITY_INDEPENDENT_SUPERVISION,
            ],
        }
    }
}

/// Classification of one observable-use trigger against the durable drain
/// linearization point (I1.5: "Activation and drain are serialized by one
/// installation-scoped `activation_generation`").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainWakeOutcome {
    /// No drain is open: the trigger coalesces behind the current generation.
    Proceed,
    /// The drain was still pre-linearization and has been cancelled; the same
    /// generation returns to `ACTIVE` after readiness revalidation.
    CancelDrain,
    /// `DrainCommitRecord` already exists: the trigger is queued as the next
    /// activation generation.
    QueueNextGeneration,
    /// The trigger is a replay of observable use the current attempt already
    /// consumed, so it neither opens a new attempt nor cancels this one.
    ReplayAlreadyConsumed,
}

impl DrainWakeOutcome {
    /// Frozen disposition spelling shared with the durable
    /// [`WakeDisposition`] vocabulary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proceed => "proceed",
            Self::CancelDrain => "cancel-drain",
            Self::QueueNextGeneration => "queue-next-generation",
            Self::ReplayAlreadyConsumed => "replay-already-consumed",
        }
    }
}

/// Durable facts one re-armed pre-commit drain attempt binds both of its
/// appended records to.
///
/// They are returned by [`HostComposition::rearm_cancelled_drain`] so the
/// `Draining` record of the same attempt gets byte-identical attempt identity
/// and evidence: the two records of one attempt must agree, and a retry of that
/// attempt must reproduce them exactly.
struct DrainRearmAttempt {
    /// Record checksum of the `Cancelled` predecessor this attempt re-arms.
    /// It is also the value carried in [`DrainRecord::expected_predecessor`].
    predecessor_checksum: String,
    /// `drain_generation` of the predecessor. A re-arm never changes the drain
    /// generation: the reducer rejects a different one, and the successor stays
    /// inside the same installation-scoped `activation_generation`.
    drain_generation: EpochTransition,
    /// Census code read at the re-arm boundary, never the caller's cached one.
    census_code: &'static str,
    /// Attempt evidence, inheriting the predecessor's consumed triggers.
    evidence_refs: Vec<PlatformHandle>,
}

/// Result of the generation-scoped lease census that gates idle drain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdleLeaseCensus {
    /// No runtime-lease reference and no valid supervision lease remains for
    /// the current generation.
    Idle,
    /// The current generation still holds runtime-lease references.
    RuntimeLeased { refs: Vec<PlatformHandle> },
    /// A valid, unexpired, Kernel-signed supervision lease is still published
    /// for the current generation, so Watchdog coverage is still owed.
    Supervised { lease_ref: PlatformHandle },
    /// The census could not be established. Idle drain fails closed.
    Unavailable { reason: &'static str },
}

impl IdleLeaseCensus {
    /// Whether the census admits the ordered idle-drain sequence.
    #[must_use]
    pub const fn admits_drain(&self) -> bool {
        matches!(self, Self::Idle)
    }

    /// Bounded observation code for the Host diagnostics facade (F-LOG-HOST-1,
    /// I15.4: no lease identity, digest or error text in a diagnostic field).
    #[must_use]
    pub const fn observation_code(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::RuntimeLeased { .. } => "runtime-leased",
            Self::Supervised { .. } => "supervised",
            Self::Unavailable { .. } => "unavailable",
        }
    }
}

/// Host-owned admission result bound to the current generations.
///
/// I1.5: "A request is not admitted as an active Session/Attempt until it
/// receives an activation result bound to the current Host/Kernel/Watchdog
/// generations." Every field is a projection of one durable journal snapshot;
/// nothing here is inferred from a live process, a pipe or a heartbeat.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationAdmission {
    /// Durable activation identity of the joined generation.
    pub activation_id: PlatformHandle,
    /// Installation-scoped activation generation the result is bound to.
    pub activation_generation: EpochTransition,
    /// Current activation state.
    pub state: ActivationState,
    /// Host/Kernel/Watchdog/store generations proven for this admission.
    pub host_epoch: EpochIdentity,
    pub kernel_epoch: EpochIdentity,
    pub watchdog_epoch: EpochIdentity,
    pub store_generation: EpochIdentity,
    /// Derived governance profile carried by the durable record.
    pub governance_profile: PlatformHandle,
    /// Fresh readiness evidence flags proven by the readiness owner.
    pub control_ready: bool,
    pub supervision_ready: bool,
    /// Capabilities requested by the observed triggers of this generation.
    pub requested_capabilities: Vec<PlatformHandle>,
    /// Dependency branches the journal proves are running.
    pub admitted_capabilities: Vec<PlatformHandle>,
    /// Runtime-lease references the generation holds.
    pub runtime_lease_refs: Vec<PlatformHandle>,
    /// Supervision-lease references the generation holds.
    pub supervision_lease_refs: Vec<PlatformHandle>,
    /// `WakeIntent` references the generation holds.
    pub wake_intent_refs: Vec<PlatformHandle>,
    /// Durable wake-during-drain disposition, once a drain ran.
    pub drain_disposition: Option<WakeDisposition>,
    /// Whether a concurrent trigger coalesced behind this generation.
    pub coalesced: bool,
    /// Bounded observation code for the Host diagnostics facade.
    pub observation_code: &'static str,
}

impl HostComposition {
    /// Projects the durable activation admission bound to the current
    /// generations.
    ///
    /// Read-only: it never starts, stops or repairs anything, and it never
    /// promotes liveness into readiness.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable Host state cannot be read or the
    /// activation record is absent.
    pub fn activation_admission(&self) -> Result<ActivationAdmission, HostError> {
        // F-LOG-HOST-1: projection only, never a readiness or lease claim.
        host_lifecycle_observe_requested("host.activation-admission requested");
        activation_admission_from(&self.snapshot()?)
    }

    /// Records one authenticated observable-use trigger against the current
    /// activation generation.
    ///
    /// Coalescing: a trigger that arrives while the current generation is
    /// stopped, starting, control-ready or active joins that start. It appends
    /// no activation record, so concurrent triggers never create a second
    /// durable activation record for one compatible generation.
    ///
    /// Pre-linearization drain: the trigger appends the terminal
    /// `Drain(Cancelled)` record and returns [`DrainWakeOutcome::CancelDrain`].
    /// The activation stays `Draining` here on purpose — `ACTIVE` is reached
    /// only through [`HostComposition::resume_cancelled_drain`], which demands a
    /// fresh readiness proof.
    ///
    /// Post-linearization drain: the trigger queues a durable next-generation
    /// `WakeIntent` and returns [`DrainWakeOutcome::QueueNextGeneration`].
    ///
    /// # Errors
    ///
    /// Returns an error when admission is fenced, the generation admits no
    /// observable use, the durable state cannot be read, or the journal
    /// rejects the record.
    pub fn note_observable_use(
        &mut self,
        trigger: ActivationTriggerClass,
        evidence: &PlatformHandle,
    ) -> Result<DrainWakeOutcome, HostError> {
        // F-LOG-HOST-1: one terminal for the whole classification.
        let mut host_terminal = HostTerminalGuard::armed("host-observable-use-failed");
        self.ensure_admission_open()?;
        let state = self.snapshot()?;
        let activation = state.activation.clone().ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        let trigger_class = PlatformHandle::new(trigger.as_str())
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let outcome = if state.drain_commit.is_some() {
            self.queue_next_generation_wake(&activation, trigger, trigger_class, evidence)?;
            DrainWakeOutcome::QueueNextGeneration
        } else if let Some(drain) = state.drain.as_ref().filter(|drain| {
            drain.state == DrainState::Draining
                && matches!(
                    activation.state,
                    ActivationState::Draining | ActivationState::StoppedClean
                )
        }) {
            if drain.evidence_refs.contains(evidence) {
                // The trigger is correlated to the *current attempt*, not to
                // the drain generation: after a re-arm the successor inherits
                // the evidence its predecessor consumed, so a delayed
                // first-attempt trigger is recognised as a replay of an
                // already-admitted request and cannot silently cancel the
                // successor. Generation equality alone cannot express this,
                // because both attempts share one `drain_generation`.
                DrainWakeOutcome::ReplayAlreadyConsumed
            } else {
                let drain_generation = activation
                    .drain_generation
                    .clone()
                    .unwrap_or_else(|| activation.fence.activation_generation.clone());
                self.append_record(HostStateRecord::Drain(DrainRecord {
                    fence: activation.fence.clone(),
                    operation: operation("host-drain-cancel")?,
                    drain_generation,
                    state: DrainState::Cancelled,
                    evidence_refs: vec![evidence.clone(), trigger_class],
                    expected_predecessor: None,
                }))?;
                DrainWakeOutcome::CancelDrain
            }
        } else if matches!(
            activation.state,
            ActivationState::Stopped
                | ActivationState::Starting
                | ActivationState::ControlReady
                | ActivationState::Active
        ) {
            // I1.5: "On wake, every target, capability, policy, budget and
            // State Fence is revalidated. Stale/resolved intents are cancelled
            // rather than executed because they were once queued." A real
            // observable request is exactly that revalidation point, so the
            // generation revalidates its queued WakeIntents here instead of
            // executing anything it once scheduled.
            self.revalidate_pending_wakes(&activation, trigger, evidence)?;
            DrainWakeOutcome::Proceed
        } else {
            return Err(HostError::OwnerLeaseRecovery(format!(
                "Host activation {:?} admits no observable use",
                activation.state
            )));
        };
        let detail = match outcome {
            DrainWakeOutcome::Proceed => "host.observable-use coalesced",
            DrainWakeOutcome::CancelDrain => "host.observable-use drain-cancelled",
            DrainWakeOutcome::QueueNextGeneration => "host.observable-use next-generation-queued",
            DrainWakeOutcome::ReplayAlreadyConsumed => {
                "host.observable-use replay-already-consumed"
            }
        };
        host_lifecycle_observe_scm(detail);
        host_terminal.disarm();
        Ok(outcome)
    }

    /// Returns the current activation generation to `ACTIVE` after a drain
    /// cancellation, and only after a fresh readiness proof.
    ///
    /// The caller supplies the disposition produced by the production
    /// readiness path in the same observation window. Anything other than an
    /// authenticated [`HostBranchDisposition::Healthy`] leaves the activation
    /// `Draining`: a cancelled drain never re-promotes readiness on its own.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable state cannot be read or the journal
    /// rejects the transition.
    pub fn resume_cancelled_drain(
        &mut self,
        disposition: HostBranchDisposition,
    ) -> Result<bool, HostError> {
        // F-LOG-HOST-1: readiness revalidation boundary.
        let mut host_terminal = HostTerminalGuard::armed("host-drain-resume-failed");
        if disposition != HostBranchDisposition::Healthy {
            host_terminal.disarm();
            return Ok(false);
        }
        let state = self.snapshot()?;
        if !state
            .drain
            .as_ref()
            .is_some_and(|drain| drain.state == DrainState::Cancelled)
        {
            host_terminal.disarm();
            return Ok(false);
        }
        let activation = state.activation.clone().ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        if activation.state != ActivationState::Draining {
            host_terminal.disarm();
            return Ok(false);
        }
        self.transition_activation(ActivationState::Active, "host-drain-cancelled")?;
        host_lifecycle_observe_drain("host.drain-resume active-restored");
        host_terminal.disarm();
        Ok(true)
    }

    /// Opens the pre-commit drain window for the current activation
    /// generation.
    ///
    /// This is the ordered I1.5 idle-drain prologue: admissions close
    /// (`Drain(Draining)`) and the activation moves to `Draining` while
    /// `DrainCommitRecord` — the linearization point after which a wake can no
    /// longer cancel — is still absent and therefore still cancellable.
    ///
    /// A cancelled attempt belongs to *this* generation, not to a spent one.
    /// I1.5 requires a pre-linearization trigger to "return the same
    /// generation to `ACTIVE` after readiness revalidation", and the journal
    /// reducer explicitly admits the successor `Requested` inside that same
    /// `drain_generation`. A fresh direct-child generation is therefore not an
    /// alternative rule but a refused one: `activation_transition` admits a new
    /// generation only as a direct child of `StoppedClean | Failed |
    /// DegradedRecovery` into `Starting`, and taking it would clear
    /// `state.drain`, `state.drain_commit`, `state.dependencies` and
    /// `state.wakes`, destroying exactly the cancelled-attempt history and
    /// queued wakes this operation must retain. The re-arm instead appends the
    /// successor `Requested` through this single journal owner and names its
    /// exact predecessor through [`DrainRecord::expected_predecessor`].
    ///
    /// Returns `false` when the current generation cannot open the window
    /// *yet*: it is not `ACTIVE` (its cancelled predecessor is still awaiting
    /// readiness revalidation), or the lease census re-read at this boundary is
    /// not `Idle`. No attempt exists in that case and none is implied.
    ///
    /// # Errors
    ///
    /// Returns an error when admission is fenced, the durable state or census
    /// cannot be read, the journal rejects the record, or this drain attempt
    /// cannot be re-armed at all. A `Failed` attempt, a durable
    /// `DrainCommitRecord` and an unestablished census are reported as
    /// [`HostError::RecoveryRequired`] / [`HostError::OwnerLeaseRecovery`]
    /// rather than as a `false`, so an unreconciled shutdown stays a visible
    /// recovery outcome instead of looking like a spent generation. The rule
    /// stays narrow: it covers those named cases only, not every terminal
    /// drain.
    pub fn begin_idle_drain(&mut self, census_code: &'static str) -> Result<bool, HostError> {
        // F-LOG-HOST-1: Requested vs Draining vs committed stay distinct.
        let mut host_terminal = HostTerminalGuard::armed("host-idle-drain-begin-failed");
        self.ensure_admission_open()?;
        let evidence = fresh_identity("host-idle-drain-evidence")?;
        let census_evidence = PlatformHandle::new(census_code)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let evidence_refs = vec![evidence, census_evidence];
        let state = self.snapshot()?;
        let activation = state.activation.clone().ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        let mut rearm: Option<DrainRearmAttempt> = None;
        if state.drain_commit.is_some() {
            // I14.23: after the durable `DrainCommitRecord` the process and
            // authority fence is linearized, so a wake waits for a fresh
            // activation generation and this prologue can never re-arm the
            // current one. That is an actionable blocked result, not a `false`
            // that reads like a spent generation.
            return Err(HostError::OwnerLeaseRecovery(
                "pre-commit drain is already committed; a fresh activation generation is required"
                    .to_owned(),
            ));
        }
        match state.drain.as_ref().map(|drain| drain.state) {
            Some(DrainState::Draining) => {
                host_terminal.disarm();
                return Ok(true);
            }
            Some(DrainState::Failed) => {
                // I1.5: "A failed or timed-out drain leaves `DEGRADED_RECOVERY`
                // plus a WakeIntent/manual entrypoint rather than reporting
                // `STOPPED_CLEAN`." A `Failed` attempt is not re-armed here:
                // its failure direction is unreconciled, so the result names
                // the recovery obligation instead of resetting a timer.
                host_lifecycle_observe_drain("host.idle-drain drain-failed blocked");
                return Err(HostError::RecoveryRequired(
                    "pre-commit drain is FAILED; drain re-arm requires manual recovery before another attempt"
                        .to_owned(),
                ));
            }
            Some(DrainState::Cancelled) => {
                let predecessor = state.drain.as_ref().ok_or_else(|| {
                    HostError::OwnerLeaseRecovery(
                        "cancelled pre-commit drain record is absent".to_owned(),
                    )
                })?;
                let Some(attempt) = self.rearm_cancelled_drain(&activation, predecessor)? else {
                    host_terminal.disarm();
                    return Ok(false);
                };
                rearm = Some(attempt);
            }
            Some(DrainState::Requested) => {}
            None => {
                if activation.state != ActivationState::Active {
                    host_lifecycle_observe_drain("host.idle-drain not-active");
                    host_terminal.disarm();
                    return Ok(false);
                }
                self.append_record(HostStateRecord::Drain(DrainRecord {
                    fence: activation.fence.clone(),
                    operation: operation("host-idle-drain-request")?,
                    drain_generation: activation.fence.activation_generation.clone(),
                    state: DrainState::Requested,
                    evidence_refs: evidence_refs.clone(),
                    expected_predecessor: None,
                }))?;
            }
        }
        self.append_idle_drain_draining(&activation, rearm.as_ref(), evidence_refs)?;
        self.transition_activation(ActivationState::Draining, "host-idle-drain")?;
        host_lifecycle_observe_drain("host.idle-drain pre-commit open");
        host_terminal.disarm();
        Ok(true)
    }

    /// Appends the `Draining` half of one pre-commit drain attempt.
    ///
    /// A re-armed attempt reuses its own deterministic identity, its
    /// predecessor's `drain_generation` and its inherited evidence, so both
    /// appended records of that attempt agree and an exact retry reproduces
    /// them byte-for-byte. A first attempt keeps the existing label and
    /// generation. The continuation record itself carries no attempt link: only
    /// the `Cancelled -> Requested` edge does.
    ///
    /// # Errors
    ///
    /// Returns an error when the journal rejects the record.
    fn append_idle_drain_draining(
        &mut self,
        activation: &EliotActivationRecord,
        rearm: Option<&DrainRearmAttempt>,
        evidence_refs: Vec<PlatformHandle>,
    ) -> Result<(), HostError> {
        let (operation, drain_generation, evidence_refs) = match rearm {
            Some(attempt) => (
                drain_rearm_operation(
                    &activation.fence,
                    &attempt.drain_generation,
                    &attempt.predecessor_checksum,
                    attempt.census_code,
                    "draining",
                )?,
                attempt.drain_generation.clone(),
                attempt.evidence_refs.clone(),
            ),
            None => (
                operation("host-idle-drain-draining")?,
                activation.fence.activation_generation.clone(),
                evidence_refs,
            ),
        };
        self.append_record(HostStateRecord::Drain(DrainRecord {
            fence: activation.fence.clone(),
            operation,
            drain_generation,
            state: DrainState::Draining,
            evidence_refs,
            expected_predecessor: None,
        }))
        .map(|_| ())
    }

    /// Re-arms a cancelled pre-commit attempt as the successor `Requested` of
    /// the *same* activation generation, or reports that it cannot yet.
    ///
    /// `Ok(None)` is the honest deferral: the activation is not `ACTIVE` again,
    /// or the lease census re-read at this boundary is not `Idle`. `Ok(Some(_))`
    /// means the successor `Requested` is durable; the caller then appends the
    /// matching `Draining` and the activation transition through the same
    /// journal owner.
    ///
    /// Preconditions, all proven here rather than assumed: the activation is
    /// `ACTIVE` again (only `resume_cancelled_drain` produces that, from an
    /// owner-backed readiness revalidation); the prior drain is proven
    /// `Cancelled` by the caller's arm; and no `DrainCommit` exists — the
    /// caller refuses that case, and the reducer refuses it again through its
    /// own `COMMITTED` transition law, so no unresolved irreversible action is
    /// re-armed either.
    ///
    /// The attempt carries its own identity instead of a fresh generation:
    /// [`DrainRecord::expected_predecessor`] names the exact `Cancelled`
    /// predecessor checksum, so the reducer accepts exactly one successor of
    /// that record, a repeated identical request replays, and changed bytes
    /// under the same operation identity conflict.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable state or the census cannot be read or
    /// the journal rejects the successor record.
    fn rearm_cancelled_drain(
        &mut self,
        activation: &EliotActivationRecord,
        predecessor: &DrainRecord,
    ) -> Result<Option<DrainRearmAttempt>, HostError> {
        if activation.state != ActivationState::Active {
            host_lifecycle_observe_drain("host.idle-drain rearm-not-active");
            return Ok(None);
        }
        // A cancellation changes the obligation set, so the caller's cached
        // observation code is not authority for a new attempt: the census is
        // re-read here (I1.5: "Idle drain starts only when no `RuntimeLease`
        // remains and no valid `SupervisionLease` requires live
        // sensing/containment"). This is one read per re-arm attempt, never one
        // per tick.
        let census = self.idle_lease_census()?;
        if !census.admits_drain() {
            host_lifecycle_observe_drain("host.idle-drain rearm-census-not-idle");
            return Ok(None);
        }
        let predecessor_checksum = record_checksum(&HostStateRecord::Drain(predecessor.clone()))?;
        // The successor inherits its predecessor's evidence, which is what
        // keeps a delayed first-attempt trigger recognisable as already
        // consumed by this attempt (see `note_observable_use`) and keeps this
        // re-arm a pure function of durable state.
        let mut evidence_refs = vec![
            PlatformHandle::new(format!("drain-rearm-predecessor:{predecessor_checksum}"))
                .map_err(|error| HostError::Platform(error.to_string()))?,
            PlatformHandle::new(census.observation_code())
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ];
        for bound in &predecessor.evidence_refs {
            if !evidence_refs.contains(bound) {
                evidence_refs.push(bound.clone());
            }
        }
        let attempt = DrainRearmAttempt {
            predecessor_checksum,
            drain_generation: predecessor.drain_generation.clone(),
            census_code: census.observation_code(),
            evidence_refs: evidence_refs.clone(),
        };
        self.append_record(HostStateRecord::Drain(DrainRecord {
            fence: activation.fence.clone(),
            operation: drain_rearm_operation(
                &activation.fence,
                &attempt.drain_generation,
                &attempt.predecessor_checksum,
                attempt.census_code,
                "request",
            )?,
            drain_generation: attempt.drain_generation.clone(),
            state: DrainState::Requested,
            evidence_refs,
            expected_predecessor: Some(attempt.predecessor_checksum.clone()),
        }))?;
        host_lifecycle_observe_drain("host.idle-drain rearm-requested");
        Ok(Some(attempt))
    }

    /// Establishes the generation-scoped lease census that gates idle drain.
    ///
    /// I1.5: "Idle drain starts only when no `RuntimeLease` remains and no valid
    /// `SupervisionLease` requires live sensing/containment." The census has two
    /// independent legs and reports `Unavailable` rather than `Idle` whenever a
    /// leg cannot be established.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable Host state or the Host state root
    /// cannot be read.
    pub fn idle_lease_census(&self) -> Result<IdleLeaseCensus, HostError> {
        // F-LOG-HOST-1: guard probe only; never a terminal and never a claim.
        host_lifecycle_observe_scm("host.lease-census requested");
        let state = self.snapshot()?;
        let activation = state.activation.as_ref().ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        if !activation.runtime_lease_refs.is_empty() {
            return Ok(IdleLeaseCensus::RuntimeLeased {
                refs: activation.runtime_lease_refs.clone(),
            });
        }
        let obligation = self
            .live_supervision_obligation_for(activation)
            .map_err(|error| IdleLeaseCensus::Unavailable {
                reason: lease_census_reason(&error),
            });
        match obligation {
            Ok(Some(lease_ref)) => Ok(IdleLeaseCensus::Supervised { lease_ref }),
            Ok(None) => Ok(IdleLeaseCensus::Idle),
            Err(census) => Ok(census),
        }
    }

    fn live_supervision_obligation_for(
        &self,
        activation: &EliotActivationRecord,
    ) -> Result<Option<PlatformHandle>, HostError> {
        live_supervision_obligation(
            self.launch_options.host_state_root(),
            &self.host.installation,
            &activation.activation_id,
            unix_millis()?,
        )
    }

    /// Returns the durable next-generation `WakeIntent` reference queued after
    /// `DrainCommitRecord`, if the current generation holds a pending one.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable Host state cannot be read.
    pub fn pending_next_generation_wake(&self) -> Result<Option<PlatformHandle>, HostError> {
        let state = self.snapshot()?;
        Ok(state.wakes.iter().find_map(|wake| {
            (wake.intent.state == WakeIntentState::Pending).then(|| wake.wake_id.clone())
        }))
    }

    /// Revalidates every queued `WakeIntent` against the current activation
    /// generation.
    ///
    /// A `WakeIntent` never grants semantic authority, never keeps the stack
    /// alive by itself, and never revives a terminal lease, so revalidation is
    /// the only thing that may move it forward. A `PENDING` intent whose fence,
    /// capability set and maintenance family still bind this generation becomes
    /// `CLAIMED`; anything else is `CANCELLED` rather than executed because it
    /// was once queued.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable state cannot be read or the journal
    /// rejects a transition.
    pub fn revalidate_pending_wakes(
        &mut self,
        activation: &EliotActivationRecord,
        trigger: ActivationTriggerClass,
        evidence: &PlatformHandle,
    ) -> Result<usize, HostError> {
        let state = self.snapshot()?;
        let pending = state
            .wakes
            .iter()
            .filter(|wake| wake.intent.state == WakeIntentState::Pending)
            .cloned()
            .collect::<Vec<_>>();
        if pending.is_empty() {
            return Ok(0);
        }
        let requested = trigger
            .requested_capabilities()
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect::<Vec<_>>();
        let mut claimed = 0_usize;
        for wake in pending {
            let same_generation =
                wake.fence.activation_generation == activation.fence.activation_generation;
            let same_authority = wake
                .intent
                .state_fence
                .authority_epoch
                .is_same_authority(&activation.lineage.kernel_epoch);
            let capabilities_covered = wake
                .required_capabilities
                .iter()
                .all(|capability| requested.iter().any(|value| value == capability.as_str()));
            let mut next = wake.clone();
            next.operation = operation("host-wake-revalidation")?;
            next.reason_evidence_refs.push(evidence.clone());
            next.intent.state = if same_generation && same_authority && capabilities_covered {
                claimed += 1;
                WakeIntentState::Claimed
            } else {
                WakeIntentState::Cancelled
            };
            self.append_record(HostStateRecord::Wake(next))?;
        }
        host_lifecycle_observe_scm("host.wake-revalidation observed");
        Ok(claimed)
    }

    /// Marks every `CLAIMED` `WakeIntent` of the current generation as started
    /// and satisfied.
    ///
    /// The caller is the readiness-proving path: a claimed `WakeIntent` may only
    /// be reported satisfied after a fresh authenticated readiness proof
    /// established that this generation is back in service. A `WakeIntent` is
    /// never satisfied from liveness, an open pipe, or a queued state.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable state cannot be read or the journal
    /// rejects a transition.
    pub fn satisfy_claimed_wakes(&mut self) -> Result<usize, HostError> {
        // F-LOG-HOST-1: single terminal for the whole satisfaction pass.
        let mut host_terminal = HostTerminalGuard::armed("host-wake-satisfy-failed");
        let state = self.snapshot()?;
        let claimed: Vec<WakeRecord> = state
            .wakes
            .iter()
            .filter(|wake| wake.intent.state == WakeIntentState::Claimed)
            .cloned()
            .collect();
        if claimed.is_empty() {
            host_terminal.disarm();
            return Ok(0);
        }
        let mut satisfied = 0_usize;
        for wake in claimed {
            let mut started = wake.clone();
            started.operation = operation("host-wake-start")?;
            started.intent.state = WakeIntentState::Started;
            self.append_record(HostStateRecord::Wake(started))?;
            let mut done = wake.clone();
            done.operation = operation("host-wake-satisfied")?;
            done.intent.state = WakeIntentState::Satisfied;
            self.append_record(HostStateRecord::Wake(done))?;
            satisfied += 1;
        }
        host_lifecycle_observe_scm("host.wake-satisfied observed");
        host_terminal.disarm();
        Ok(satisfied)
    }

    fn queue_next_generation_wake(
        &mut self,
        activation: &EliotActivationRecord,
        trigger: ActivationTriggerClass,
        trigger_class: PlatformHandle,
        evidence: &PlatformHandle,
    ) -> Result<PlatformHandle, HostError> {
        // I1.5: a post-linearization trigger is queued as the next activation
        // generation. The queue entry is a `WakeIntent`: it schedules work but
        // never grants semantic authority, never keeps the stack alive by
        // itself and never revives a terminal lease. Its own state fence is the
        // Kernel epoch of the generation that must be fenced before the next
        // one may start, and on wake every target, capability, policy, budget
        // and State Fence is revalidated by the generation that claims it.
        let wake_id = fresh_identity("wake-next-generation")?;
        let intent = WakeIntent {
            wake_id: wake_id.as_str().to_owned(),
            reason: trigger.as_str().to_owned(),
            state_fence: StateFence::new(
                activation.lineage.kernel_epoch.clone(),
                ResourceGeneration::genesis(),
            ),
            state: WakeIntentState::Pending,
        };
        intent
            .validate()
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let now_ms = unix_millis()?;
        let mut required_capabilities = Vec::with_capacity(trigger.requested_capabilities().len());
        for capability in trigger.requested_capabilities() {
            required_capabilities.push(
                PlatformHandle::new(*capability)
                    .map_err(|error| HostError::Platform(error.to_string()))?,
            );
        }
        let state_fence_revalidation_ref = PlatformHandle::new(format!(
            "wake-revalidation:{}:{}",
            activation.fence.activation_generation.current.lineage_id,
            activation.fence.activation_generation.current.sequence
        ))
        .map_err(|error| HostError::Platform(error.to_string()))?;
        self.append_record(HostStateRecord::Wake(WakeRecord {
            fence: record_fence(
                &self.host,
                &activation.activation_id,
                &activation.fence.activation_generation,
            ),
            operation: operation("host-next-generation-wake")?,
            wake_id: wake_id.clone(),
            intent,
            reason_evidence_refs: vec![evidence.clone(), trigger_class],
            earliest_start: PlatformHandle::new(format!("wake-earliest:{now_ms}"))
                .map_err(|error| HostError::Platform(error.to_string()))?,
            deadline: PlatformHandle::new(format!("wake-deadline:{now_ms}"))
                .map_err(|error| HostError::Platform(error.to_string()))?,
            expiry: PlatformHandle::new(format!("wake-expiry:{now_ms}"))
                .map_err(|error| HostError::Platform(error.to_string()))?,
            required_capabilities,
            maintenance_family: PlatformHandle::new("demand-start-reconciliation")
                .map_err(|error| HostError::Platform(error.to_string()))?,
            safety_class: ServiceSafetyClass::ServiceSafe,
            state_fence_revalidation_ref,
            budget_ref: PlatformHandle::new("wake-budget:drain-next-generation")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        }))?;
        Ok(wake_id)
    }
}

fn activation_admission_from(state: &HostState) -> Result<ActivationAdmission, HostError> {
    let activation = state
        .activation
        .as_ref()
        .ok_or_else(|| HostError::OwnerLeaseRecovery("activation record is absent".to_owned()))?;
    let mut admitted_capabilities = state
        .dependencies
        .iter()
        .filter(|record| record.state == eliot_host_state::DependencyState::Active)
        .map(|record| record.dependency.clone())
        .collect::<Vec<_>>();
    admitted_capabilities.sort();
    admitted_capabilities.dedup();
    Ok(ActivationAdmission {
        activation_id: activation.activation_id.clone(),
        activation_generation: activation.fence.activation_generation.clone(),
        state: activation.state,
        host_epoch: activation.lineage.host_epoch.clone(),
        kernel_epoch: activation.lineage.kernel_epoch.clone(),
        watchdog_epoch: activation.lineage.watchdog_epoch.clone(),
        store_generation: activation.lineage.store_generation.clone(),
        governance_profile: activation.governance_profile.clone(),
        control_ready: activation.readiness.control_ready,
        supervision_ready: activation.readiness.supervision_ready,
        requested_capabilities: activation.requested_capabilities.clone(),
        admitted_capabilities,
        runtime_lease_refs: activation.runtime_lease_refs.clone(),
        supervision_lease_refs: activation.supervision_lease_refs.clone(),
        wake_intent_refs: activation.wake_intent_refs.clone(),
        drain_disposition: activation.wake_during_drain_disposition,
        // More than one durable trigger binding on the same generation is the
        // journal's own proof that concurrent triggers coalesced behind one
        // start instead of creating a second activation record.
        coalesced: activation.trigger_evidence.len() > 1,
        observation_code: activation_state_code(activation.state),
    })
}

/// Bounded observation code for the activation state (F-LOG-HOST-1, I15.4).
#[must_use]
pub const fn activation_state_code(state: ActivationState) -> &'static str {
    match state {
        ActivationState::Stopped => "stopped",
        ActivationState::Starting => "starting",
        ActivationState::ControlReady => "control-ready",
        ActivationState::Active => "active",
        ActivationState::Draining => "draining",
        ActivationState::StoppedClean => "stopped-clean",
        ActivationState::DegradedRecovery => "degraded-recovery",
        ActivationState::Failed => "failed",
    }
}

fn lease_census_reason(error: &HostError) -> &'static str {
    match error {
        HostError::Journal(_)
        | HostError::State(_)
        | HostError::Installation(_)
        | HostError::OwnerLeaseRecovery(_) => "durable-state-unreadable",
        HostError::Platform(_)
        | HostError::ProcessContour(_)
        | HostError::RecoveryRequired(_)
        | HostError::MissingInstallation
        | HostError::StoreNotLive { .. }
        | HostError::OwnerLeaseHeld
        | HostError::Stopped => "supervision-spool-unreadable",
        // A refused independent-Watchdog proof means the supervision
        // obligation cannot be established either, so the census stays
        // `Unavailable` on the supervision leg and never reports `Idle`.
        #[cfg(windows)]
        HostError::WatchdogCoverageUnavailable(_) => "supervision-spool-unreadable",
        #[cfg(windows)]
        HostError::StoreRecoveryRequired(_) => "durable-state-unreadable",
    }
}

fn unix_millis() -> Result<u64, HostError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| HostError::Platform(error.to_string()))
        .and_then(|elapsed| {
            u64::try_from(elapsed.as_millis())
                .map_err(|error| HostError::Platform(error.to_string()))
        })
}
