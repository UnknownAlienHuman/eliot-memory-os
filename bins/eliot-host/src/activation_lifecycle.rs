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
//! Census honesty: the `RuntimeLease` row family I1.5 assigns to the Kernel's ORS
//! now exists as durable state (`ors_runtime_lease_current_v1`, record type
//! `runtime_lease_current`, selected by exact `StateFence` equality through
//! `RedbRecoveryStore::load_runtime_leases_by_state_fence`) with a landed
//! writer: `bins/eliot-kernel/src/control_plane.rs` issues one `Active` row
//! per granted activation into `RedbRecoveryStore::record_runtime_lease_current`
//! (I18.53 ACT-1), and the Kernel census
//! (`bins/eliot-kernel/src/idle_lease_census.rs` `runtime_lease_leg` and
//! `read_runtime_lease_census`) plus the Host retirement barrier
//! (`bins/eliot-host/src/lease_drain.rs`
//! `require_generation_retirement_barrier` over `ReadRuntimeLeaseCensus`)
//! read it back. The Kernel tick beside the issuance site has landed too:
//! `expire_past_due_runtime_leases` and `supersede_stale_runtime_leases` at
//! grant time plus `renew_runtime_leases_for_probe` on the probe path move
//! rows through the owner `RuntimeLease::transition_to` legality — past-due
//! rows reach the `Expired` terminal, stale same-scope identities reach
//! `Superseded`, and live rows held by the probed activation renew from that
//! probe's fresh evidence (renewed supervision head plus live receipt inside
//! `RUNTIME_LEASE_EVIDENCE_FRESHNESS_MS`). The explicit revoke arm has landed
//! beside the same issuance site as well:
//! `KernelControlCommand::RevokeRuntimeLease` moves the named exact-fence row
//! to the `Revoked` terminal through the owner `transition_to` legality and
//! re-records it through the canonical ORS owner — explicit-command-only, so
//! drain and stop never revoke, and the unauthenticated service transition
//! refuses the command with a typed `InvalidField`. The owner-scope identity
//! decision has landed there too:
//! `bins/eliot-kernel/src/control_plane.rs::runtime_lease_id_for_candidate`
//! keys issued rows by the generation-bound identity derived from the
//! validated candidate (`runtime-lease:<activation>:<lineage>:<seq>`), which
//! is the same spelling [`runtime_lease_id_for`] builds from the Host journal
//! record — one identity through the ORS owner, never a sidecar.
//! The Host half below is durable and complete on its own side:
//! the current activation generation holds its generation-bound `RuntimeLease`
//! reference (issued, renewed, and released here from fresh admitting
//! observations). The Host idle-drain mirror reconciles those references to
//! exact-fence owner rows and consumes the same authenticated typed ORS
//! Store-stop census the Kernel consumes. A
//! `StoppedClean` terminal releases
//! the held references (`transition_activation_record` clears them once the
//! `DrainCommitRecord` snapshot carries the obligations, proven by
//! [`prove_terminal_runtime_release`]); recovery terminals
//! keep them because reconciliation is still owed. Supervision stop status is
//! projected from the current ORS owner row; the separately published,
//! Kernel-signed Watchdog mirror remains a coverage input, not an alternate
//! lease terminal authority.

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{ResourceGeneration, StateFence};
use eliot_host_service::runtime_control::HostActivationAdmission;
use eliot_host_state::{
    ActivationState, DrainCommitRecord, DrainRecord, DrainState, EliotActivationRecord,
    EpochIdentity, EpochTransition, HostState, HostStateRecord, KernelReadinessObservationRecord,
    ServiceSafetyClass, WakeDisposition, WakeRecord, record_checksum,
};
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::{WakeIntent, WakeIntentState};
use serde::Serialize;

use super::watchdog_publication::live_supervision_obligation;
use super::{
    BOUNDARY_ACTIVATION_ADMISSION_REQUESTED, BOUNDARY_DRAIN_RESUME_ACTIVE_RESTORED,
    BOUNDARY_DRAIN_RESUME_TERMINAL, BOUNDARY_IDLE_DRAIN_DRAIN_FAILED_BLOCKED,
    BOUNDARY_IDLE_DRAIN_NOT_ACTIVE, BOUNDARY_IDLE_DRAIN_PRE_COMMIT_OPEN,
    BOUNDARY_IDLE_DRAIN_REARM_CENSUS_NOT_IDLE, BOUNDARY_IDLE_DRAIN_REARM_NOT_ACTIVE,
    BOUNDARY_IDLE_DRAIN_REARM_REQUESTED, BOUNDARY_IDLE_DRAIN_TERMINAL,
    BOUNDARY_LEASE_CENSUS_REQUESTED, BOUNDARY_OBSERVABLE_USE_COALESCED,
    BOUNDARY_OBSERVABLE_USE_DRAIN_CANCELLED, BOUNDARY_OBSERVABLE_USE_NEXT_GENERATION_QUEUED,
    BOUNDARY_OBSERVABLE_USE_REPLAY_ALREADY_CONSUMED, BOUNDARY_OBSERVABLE_USE_TERMINAL,
    BOUNDARY_WAKE_REVALIDATION_OBSERVED, BOUNDARY_WAKE_SATISFIED_OBSERVED,
    BOUNDARY_WAKE_SATISFY_TERMINAL, HostBranchDisposition, HostComposition, HostError,
    HostTerminalGuard, drain_rearm_operation, fresh_identity, host_lifecycle_observe_drain,
    host_lifecycle_observe_requested, host_lifecycle_observe_scm, operation, record_fence,
    sha256_json,
};

/// Capability every I1.5 observable-use trigger needs: the Host-owned
/// runtime/supervision contour itself.
pub const CAPABILITY_RUNTIME_SUPERVISION: &str = "runtime-supervision";
/// Capability required by any trigger that reads or writes canonical state.
pub const CAPABILITY_CANONICAL_STORE: &str = "canonical-store";
/// Capability required by any trigger whose obligation needs the independent
/// Watchdog service to keep sensing.
pub const CAPABILITY_INDEPENDENT_SUPERVISION: &str = "independent-supervision";

/// I1.5 post-commit next-generation wake schedule policy.
///
/// A trigger queued after `DrainCommitRecord` is demand for a generation that
/// does not exist yet, so its `WakeIntent` carries a real schedule the
/// stopped-installation demand-start owner fires against (I1.5 "Background
/// wake": a bounded maintenance command only from an admitted
/// `WakeIntent`/policy, with budget, deadline and revalidation):
///
/// * `earliest_start` is the queue instant. The demand already arrived, so the
///   next generation is eligible as soon as the committed generation's
///   authority is fenced and its process descendants are terminated or
///   reconciled — never before.
/// * `deadline` is one I1.5 idle grace later ("DEFAULT idle grace is five
///   minutes", a Config Default). A next generation that has not started by
///   then is late: the installation would otherwise have gone idle again
///   under the same grace.
/// * `expiry` bounds the stale horizon. An intent no generation claimed by
///   then is stale demand and must `EXPIRE` rather than execute (I1.5: stale
///   intents are cancelled rather than executed because they were once
///   queued), surfacing as the deduplicated manual entrypoint I1.5 requires
///   when scheduling is unavailable instead of silently abandoned
///   maintenance.
///
/// [`HostComposition::revalidate_pending_wakes`] consumes this schedule: it
/// moves a past-expiry intent to `Expired` and leaves a not-yet-due intent
/// `Pending`, for owner-spelled markers only. Any other wake family keeps its
/// own policy untouched.
pub const NEXT_GENERATION_WAKE_DEADLINE_MS: u64 = 5 * 60 * 1_000;
/// Stale horizon of a post-commit next-generation `WakeIntent` in
/// milliseconds. See the schedule policy on
/// [`NEXT_GENERATION_WAKE_DEADLINE_MS`].
pub const NEXT_GENERATION_WAKE_EXPIRY_MS: u64 = 60 * 60 * 1_000;

/// Maintenance family spelling of a post-commit next-generation `WakeIntent`.
///
/// This exact spelling is the owner boundary: only wakes queued by the
/// post-commit path carry it, so schedule enforcement and the demand-start
/// handoff never reinterpret another wake family's records.
pub const NEXT_GENERATION_WAKE_MAINTENANCE_FAMILY: &str = "demand-start-reconciliation";

/// Marker prefixes of the post-commit next-generation wake schedule.
///
/// The markers stay opaque [`PlatformHandle`] strings (the journal never
/// parses them), but their millisecond suffix is the policy above, so the
/// demand-start owner and [`HostComposition::revalidate_pending_wakes`] can
/// consume the same durable values the queue path wrote.
const NEXT_GENERATION_WAKE_EARLIEST_PREFIX: &str = "wake-earliest:";
/// See [`NEXT_GENERATION_WAKE_EARLIEST_PREFIX`].
const NEXT_GENERATION_WAKE_DEADLINE_PREFIX: &str = "wake-deadline:";
/// See [`NEXT_GENERATION_WAKE_EARLIEST_PREFIX`].
const NEXT_GENERATION_WAKE_EXPIRY_PREFIX: &str = "wake-expiry:";

/// Schedule verdict of one retained wake against the post-commit
/// next-generation wake policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NextGenerationWakeSchedule {
    /// The wake carries no schedule this owner wrote (another wake family or
    /// an unparseable marker): the existing claim rule applies unchanged.
    NoOwnerPolicy,
    /// The demand already arrived but its earliest start is still in the
    /// future: the intent stays `PENDING` with no row written.
    NotDue,
    /// The intent is due: the existing fence/capability claim rule decides.
    Due,
    /// The stale horizon passed: the intent must `EXPIRE` rather than execute.
    Expired,
}

/// Reads one retained wake's schedule verdict without touching the journal.
///
/// Only wakes in [`NEXT_GENERATION_WAKE_MAINTENANCE_FAMILY`] with fully
/// parseable owner-spelled millisecond markers receive a schedule verdict;
/// every other wake — including the `UserAutomation` horizon family, whose
/// markers name occurrence keys rather than instants — answers
/// [`NextGenerationWakeSchedule::NoOwnerPolicy`] so its own policy stays
/// untouched. A past expiry outranks a future earliest start: stale demand
/// expires even when its window reads inconsistent.
fn next_generation_wake_schedule_state(
    wake: &WakeRecord,
    now_ms: u64,
) -> NextGenerationWakeSchedule {
    if wake.maintenance_family.as_str() != NEXT_GENERATION_WAKE_MAINTENANCE_FAMILY {
        return NextGenerationWakeSchedule::NoOwnerPolicy;
    }
    let Some(expiry_ms) = wake
        .expiry
        .as_str()
        .strip_prefix(NEXT_GENERATION_WAKE_EXPIRY_PREFIX)
        .and_then(|suffix| suffix.parse::<u64>().ok())
    else {
        return NextGenerationWakeSchedule::NoOwnerPolicy;
    };
    if now_ms > expiry_ms {
        return NextGenerationWakeSchedule::Expired;
    }
    let Some(earliest_ms) = wake
        .earliest_start
        .as_str()
        .strip_prefix(NEXT_GENERATION_WAKE_EARLIEST_PREFIX)
        .and_then(|suffix| suffix.parse::<u64>().ok())
    else {
        return NextGenerationWakeSchedule::NoOwnerPolicy;
    };
    if now_ms < earliest_ms {
        return NextGenerationWakeSchedule::NotDue;
    }
    NextGenerationWakeSchedule::Due
}

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
    /// No UI ingress reaches Host in-tree (verified: no UI listener under
    /// `bins/eliot-host`, and `HostRuntimeControlRequest` carries no
    /// caller/principal field that could attribute a carrier to a UI session),
    /// so this class has no producer here. The attested half has landed: the
    /// Operator contract carries the versioned UI-session attestation
    /// (`crates/governor/eliot-governor/src/operator_intent.rs::OperatorIntentUiSessionAttestation`,
    /// stamped only from authenticated UI sessions, fail-closed absence), and
    /// [`ActivationTriggerClass::ui_request_from_attested_ui_session`] derives
    /// this class from that attestation alone. STITCH remainder: the
    /// Host-visible envelope passthrough (wire owner
    /// `crates/kernel/eliot-host-service/src/runtime_control.rs`) and the
    /// one-line classifier hookup
    /// (`bins/eliot-host/src/main.rs::runtime_control_request_trigger_class`).
    /// A `Human`-origin automation carrier must never be minted as this class:
    /// it is CLI-or-UI ambiguous, so that attribution would fabricate the
    /// trigger.
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
    /// No Watchdog observation ingress reaches Host in-tree (verified: no
    /// `WakeIntent` symbol exists anywhere under `bins/eliot-watchdog`, so the
    /// Watchdog owns no signed-intent persistence or Host demand-start
    /// producer; and Watchdog spool intents flow Watchdog-to-Kernel-to-Governor
    /// over `WATCHDOG_SPOOL_BATCH_ROUTE`, never to Host), so this class has no
    /// producer here: a Watchdog SCM demand-start arrives as a bare start with
    /// no journal intent, which this process consumes as nothing rather than
    /// fabricating this class from Watchdog liveness. STITCH caller is the
    /// Watchdog carrier owner, which must attest the watchdog origin on a
    /// Host-visible envelope (`HostRuntimeControlRequest` and the
    /// `UserAutomation` execution carrier both carry no watchdog-origin
    /// discriminator today), or the Governor-owned spool journal path.
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

    /// Derives [`Self::UiRequest`] from an attested UI-session identity.
    ///
    /// `Some` attestation mints `UiRequest`; `None` (the envelope carries no
    /// UI attestation) yields `None`: absence is not a UI request and is
    /// never inferred. The attestation is the only input: a `Human`-origin
    /// automation carrier carries none of these bindings (it is CLI-or-UI
    /// ambiguous), so it must never be converted into
    /// [`AttestedUiSessionIdentity`]; that conversion would fabricate the
    /// trigger.
    #[must_use]
    pub fn ui_request_from_attested_ui_session(
        attestation: Option<&AttestedUiSessionIdentity>,
    ) -> Option<Self> {
        attestation.map(|_| Self::UiRequest)
    }
}

/// Attested UI-session identity a Host-visible envelope carries for one
/// request.
///
/// This is the Host-side reading of the ControlBoard/Operator contract's
/// versioned UI-session attestation
/// (`crates/governor/eliot-governor/src/operator_intent.rs::OperatorIntentUiSessionAttestation`):
/// the authenticated UI principal, session, and authentication receipt the
/// surface owner bound to this exact request. Every member is a validated
/// [`PlatformHandle`], so no blank or control-character value can reach the
/// derivation. It is populated only from authenticated UI sessions — never
/// defaulted, never cloned from a CLI carrier — and its absence means the
/// request is not a UI request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestedUiSessionIdentity {
    /// Authenticated UI principal, bound to the request's receipt.
    pub ui_principal_ref: PlatformHandle,
    /// Authenticated UI session, equal to the candidate's session claim.
    pub ui_session_id: PlatformHandle,
    /// Authentication evidence handle the surface owner bound to this request.
    pub ui_authentication_receipt_ref: PlatformHandle,
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

/// Admitted observable-use trigger: the durable verdict plus the wake-expiry
/// report of the same pass.
///
/// I1.5 background wake: "When scheduling is unavailable, the next observable
/// use surfaces one deduplicated manual action instead of silently abandoning
/// maintenance." [`HostComposition::revalidate_pending_wakes`] moves a
/// past-horizon post-commit next-generation intent to `Expired` on the
/// admitting trigger itself, and that transition happens exactly once per
/// intent (the `Pending` filter never revisits it), so reporting the per-pass
/// count here is already deduplicated. The composition never prints: the
/// `main.rs` caller (`HostIdleDrainSupervisor::note_observable_use`,
/// `admit_console_trigger`) surfaces the count operator-visibly on the same
/// pass, beside the durable `Expired` record that retains the obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservableUseOutcome {
    /// Durable verdict the dispatch loop decides on.
    pub outcome: DrainWakeOutcome,
    /// Post-commit next-generation wake demands this trigger expired with no
    /// demand-start claim. Zero on every arm that does not revalidate.
    pub expired_wake_intents: usize,
}

/// Durable facts one re-armed pre-commit drain attempt binds both of its
/// appended records to.
///
/// They are returned by [`HostComposition::rearm_cancelled_drain`] so the
/// `Draining` record of the same attempt gets byte-identical attempt identity
/// and evidence: the two records of one attempt must agree, and a retry of that
/// attempt must reproduce them exactly. The `Draining` continuation additionally
/// names the exact re-armed `Requested` record checksum, so the reducer admits
/// the continuation only for the attempt it continues.
struct DrainRearmAttempt {
    /// Record checksum of the `Cancelled` predecessor this attempt re-arms.
    /// It is also the value carried in the `Requested` record's
    /// [`DrainRecord::expected_predecessor`].
    predecessor_checksum: String,
    /// `drain_generation` of the predecessor. A re-arm never changes the drain
    /// generation: the reducer rejects a different one, and the successor stays
    /// inside the same installation-scoped `activation_generation`.
    drain_generation: EpochTransition,
    /// Owner census binding read at the re-arm boundary, never the caller's
    /// cached code: `idle:<owner-fence-digest>` over the exact `#1751`
    /// `RuntimeLeaseCensus` fence that admitted this attempt, which the
    /// retirement barrier revalidates before commit.
    census_binding: String,
    /// Record checksum of the re-armed `Requested` record itself. It is the
    /// value carried in the `Draining` continuation's
    /// [`DrainRecord::expected_predecessor`], so a restarted process resumes
    /// the same successor instead of substituting a generic continuation.
    requested_checksum: String,
    /// Attempt evidence, inheriting the predecessor's consumed triggers.
    evidence_refs: Vec<PlatformHandle>,
}

/// Result of the generation-scoped lease census that gates idle drain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdleLeaseCensus {
    /// The owner read proves all Store-dependent obligations terminal for the
    /// exact current generation, and no Host-held lease reference remains.
    Idle {
        /// Typed Kernel/ORS projection also consumed by retirement admission.
        owner_census: eliot_kernel_service::RuntimeLeaseCensus,
    },
    /// A Host-held reference resolves to a non-terminal exact-fence owner row.
    RuntimeLeased {
        refs: Vec<PlatformHandle>,
        /// Same exact-fence owner read used by the Kernel and stop gate.
        owner_census: eliot_kernel_service::RuntimeLeaseCensus,
    },
    /// The exact current ORS supervision lease remains non-terminal.
    Supervised {
        lease_ref: PlatformHandle,
        /// Same exact-fence owner read used by the Kernel and stop gate.
        owner_census: eliot_kernel_service::RuntimeLeaseCensus,
    },
    /// The Host mirror has no matching lease reference, but canonical ORS
    /// still has a non-terminal Store-dependent owner.
    StoreObligationLeased {
        /// Same exact-fence owner read used by the Kernel and stop gate.
        owner_census: eliot_kernel_service::RuntimeLeaseCensus,
    },
    /// The census could not be established. Idle drain fails closed.
    Unavailable { reason: &'static str },
}

impl IdleLeaseCensus {
    /// Whether the census admits the ordered idle-drain sequence.
    #[must_use]
    pub fn admits_drain(&self) -> bool {
        match self {
            Self::Idle { owner_census } => owner_census.is_fully_retired(),
            Self::RuntimeLeased { .. }
            | Self::Supervised { .. }
            | Self::StoreObligationLeased { .. }
            | Self::Unavailable { .. } => false,
        }
    }

    /// Bounded observation code for the Host diagnostics facade (F-LOG-HOST-1,
    /// I15.4: no lease identity, digest or error text in a diagnostic field).
    #[must_use]
    pub const fn observation_code(&self) -> &'static str {
        match self {
            Self::Idle { .. } => "idle",
            Self::RuntimeLeased { .. } => "runtime-leased",
            Self::Supervised { .. } => "supervised",
            Self::StoreObligationLeased { .. } => "store-obligation-leased",
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
///
/// Wire projection: every field already carries the owner's `Serialize`
/// implementation, so this struct derives `Serialize` and travels on the
/// runtime-control wire through the owned member
/// [`eliot_host_service::runtime_control::HostRuntimeControlResponse::AdmissionProjected`]
/// (see [`HostComposition::activation_admission_wire`]).
/// STITCH (dispatch site, second-writer scope — this file must not touch
/// `main.rs`): the manager/integrator attaches the projection in
/// `process_runtime_control_requests` (`bins/eliot-host/src/main.rs`), after
/// `runtime_control_dispatch` produces the operation `response` and before
/// `envelope.respond(response)` (today `main.rs:1619`):
/// `let response = match host.activation_admission_wire() { Ok(admission) =>
/// response.with_activation_admission(admission), Err(_) => response };`
/// so every authenticated answer carries the generation-bound admission when
/// an activation record exists, while the bare operation answer still flows
/// otherwise and the creating trigger is never blocked. Until that lands,
/// the wire member plus the producer below are constructible but unemitted —
/// never faked from liveness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
        host_lifecycle_observe_requested(BOUNDARY_ACTIVATION_ADMISSION_REQUESTED);
        activation_admission_from(&self.snapshot()?)
    }

    /// Projects the durable activation admission onto the runtime-control
    /// wire type owned by `eliot-host-service`.
    ///
    /// Read-only 1:1 projection of [`HostComposition::activation_admission`]:
    /// the same journal snapshot and the same owner types, so the wire
    /// result carries the activation state, activation generation,
    /// governance profile, held lease references and drain disposition the
    /// journal proved. The runtime-control dispatch loop attaches the result
    /// to the real response path (STITCH: `process_runtime_control_requests`
    /// in `bins/eliot-host/src/main.rs`, second-writer scope); the local
    /// stderr line stays diagnostics-only.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable Host state cannot be read or the
    /// activation record is absent.
    pub fn activation_admission_wire(&self) -> Result<HostActivationAdmission, HostError> {
        // F-LOG-HOST-1: projection only, never a readiness or lease claim.
        // Delegation (not a second snapshot/observe): `activation_admission`
        // already records the boundary observation above.
        let admission = self.activation_admission()?;
        Ok(HostActivationAdmission {
            activation_id: admission.activation_id,
            activation_generation: admission.activation_generation,
            state: admission.state,
            host_epoch: admission.host_epoch,
            kernel_epoch: admission.kernel_epoch,
            watchdog_epoch: admission.watchdog_epoch,
            store_generation: admission.store_generation,
            governance_profile: admission.governance_profile,
            control_ready: admission.control_ready,
            supervision_ready: admission.supervision_ready,
            requested_capabilities: admission.requested_capabilities,
            admitted_capabilities: admission.admitted_capabilities,
            runtime_lease_refs: admission.runtime_lease_refs,
            supervision_lease_refs: admission.supervision_lease_refs,
            wake_intent_refs: admission.wake_intent_refs,
            drain_disposition: admission.drain_disposition,
            coalesced: admission.coalesced,
        })
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
    /// The activation stays `Draining` here on purpose — the return to `ACTIVE`
    /// runs through
    /// [`HostComposition::resume_cancelled_drain_on_observable_use`], which
    /// revalidates readiness with a fresh probe before transitioning.
    ///
    /// Post-linearization drain: the trigger queues a durable next-generation
    /// `WakeIntent` and returns [`DrainWakeOutcome::QueueNextGeneration`].
    ///
    /// Returns the durable verdict together with the per-pass wake-expiry
    /// report (see [`ObservableUseOutcome`]): only the `Proceed` arm
    /// revalidates, so only it can report expiries; every other arm reports
    /// zero.
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
    ) -> Result<ObservableUseOutcome, HostError> {
        // F-LOG-HOST-1: one terminal for the whole classification.
        let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_OBSERVABLE_USE_TERMINAL);
        self.ensure_admission_open()?;
        let state = self.snapshot()?;
        let activation = state.activation.clone().ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        let trigger_class = PlatformHandle::new(trigger.as_str())
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let mut expired_wake_intents = 0_usize;
        let outcome = if state.drain_commit.is_some() {
            let queued =
                self.queue_next_generation_wake(&activation, trigger, trigger_class, evidence)?;
            // W5 read side: the queued `WakeIntent` is read back out of the
            // durable journal before the disposition is published. The
            // append above only proves the write was accepted; this read is the
            // single place that observes the *persisted* pending intent, so a
            // journal that dropped or replaced the entry fails the trigger
            // instead of reporting a queued next generation nothing can claim.
            let persisted = self.pending_next_generation_wake()?.ok_or_else(|| {
                HostError::OwnerLeaseRecovery(
                    "queued next-generation WakeIntent is absent from the durable journal"
                        .to_owned(),
                )
            })?;
            if persisted != queued {
                return Err(HostError::OwnerLeaseRecovery(
                    "queued next-generation WakeIntent is not the durable pending intent"
                        .to_owned(),
                ));
            }
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
            let (_, expired) = self.revalidate_pending_wakes(&activation, trigger, evidence)?;
            expired_wake_intents = expired;
            DrainWakeOutcome::Proceed
        } else {
            return Err(HostError::OwnerLeaseRecovery(format!(
                "Host activation {:?} admits no observable use",
                activation.state
            )));
        };
        let detail = match outcome {
            DrainWakeOutcome::Proceed => BOUNDARY_OBSERVABLE_USE_COALESCED,
            DrainWakeOutcome::CancelDrain => BOUNDARY_OBSERVABLE_USE_DRAIN_CANCELLED,
            DrainWakeOutcome::QueueNextGeneration => BOUNDARY_OBSERVABLE_USE_NEXT_GENERATION_QUEUED,
            DrainWakeOutcome::ReplayAlreadyConsumed => {
                BOUNDARY_OBSERVABLE_USE_REPLAY_ALREADY_CONSUMED
            }
        };
        host_lifecycle_observe_scm(detail);
        host_terminal.disarm();
        Ok(ObservableUseOutcome {
            outcome,
            expired_wake_intents,
        })
    }

    /// Returns the current activation generation to `ACTIVE` after a drain
    /// cancellation, and only after a fresh readiness proof.
    ///
    /// The caller supplies the disposition produced by the production
    /// readiness path in the same observation window. Anything other than an
    /// authenticated [`HostBranchDisposition::Healthy`] leaves the activation
    /// `Draining`: a cancelled drain never re-promotes readiness on its own.
    ///
    /// Reachability contract: the sole production caller is
    /// `HostIdleDrainSupervisor::observe_readiness`, which forwards only
    /// [`HostBranchDisposition::Healthy`], and one production producer of
    /// [`HostBranchDisposition::Healthy`] is the readiness gate behind the
    /// exact-current activation check in
    /// `HostComposition::reconcile_branch_readiness_at` — whose fence admits
    /// a pre-commit cancelled drain alongside `Active`. A `Draining`
    /// generation with a `Cancelled` drain therefore observes that proof
    /// through the tick reconcile; its I1.5 return to `ACTIVE` also runs through
    /// [`HostComposition::resume_cancelled_drain_on_observable_use`], which
    /// carries its own fresh probe. This entry stays for reconcile-driven
    /// dispositions and performs the same owner `Active` transition.
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
        let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_DRAIN_RESUME_TERMINAL);
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
        host_lifecycle_observe_drain(BOUNDARY_DRAIN_RESUME_ACTIVE_RESTORED);
        host_terminal.disarm();
        Ok(true)
    }

    /// Returns a `Draining` generation with a cancelled pre-commit drain to
    /// `ACTIVE` on a fresh observable-use trigger, after readiness
    /// revalidation.
    ///
    /// I1.5: "A new observable-use trigger received before the durable drain
    /// linearization point cancels drain and returns the same generation to
    /// `ACTIVE` after readiness revalidation." The cancellation itself is
    /// [`HostComposition::note_observable_use`]; this is the second half, and
    /// the supervisor calls it on the trigger that cancelled the drain (and
    /// retries it on a later trigger the generation could not admit, so a
    /// failed probe never strands the generation).
    ///
    /// The tick reconcile serves this path as well for pre-commit cancelled
    /// drains (its `Healthy` proof admits that state since the fence fix);
    /// the revalidation here is therefore the same fresh proof, not a weaker one, driven by the trigger
    /// instead of the tick: `HostComposition::persist_process_observations`
    /// re-observes Watchdog supervision, probes Kernel readiness live, admits
    /// the observation into the journal and grants the readiness gate —
    /// answered from this call, never from the pre-drain observation retained
    /// since activation. The return to `ACTIVE` then commits through
    /// `HostComposition::transition_activation_with_readiness_evidence`, the
    /// same owner the production start path uses, carrying the just-appended
    /// probe evidence (which also re-binds the generation's runtime and
    /// supervision leases from that fresh evidence). The next tick reconcile
    /// re-proves the restored generation through its own `Active` gate.
    ///
    /// Returns `Ok(false)` when there is no cancelled pre-commit drain to
    /// resume. Anything else that is not proven fails closed with a typed
    /// error instead of stranding the generation silently.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable state cannot be read, the cancelled
    /// record carries no trigger evidence, the recorded serving contour is
    /// gone, no approved active generation exists, the fresh probe is not
    /// provable, or the journal rejects the transition.
    #[cfg(windows)]
    pub fn resume_cancelled_drain_on_observable_use(&mut self) -> Result<bool, HostError> {
        // F-LOG-HOST-1: readiness revalidation boundary.
        let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_DRAIN_RESUME_TERMINAL);
        let state = self.snapshot()?;
        if state.drain_commit.is_some() {
            host_terminal.disarm();
            return Ok(false);
        }
        let Some(drain) = state
            .drain
            .as_ref()
            .filter(|drain| drain.state == DrainState::Cancelled)
        else {
            host_terminal.disarm();
            return Ok(false);
        };
        let activation = state.activation.clone().ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        if activation.state != ActivationState::Draining {
            host_terminal.disarm();
            return Ok(false);
        }
        if drain.evidence_refs.is_empty() {
            return Err(HostError::RecoveryRequired(
                "cancelled pre-commit drain carries no trigger evidence".to_owned(),
            ));
        }
        if !self.has_process_contour() {
            // A pre-commit drain stops nothing, so a generation that reached
            // this state with no recorded serving contour is broken, not
            // idle: returning it to `ACTIVE` would admit an empty contour.
            return Err(HostError::RecoveryRequired(
                "cancelled pre-commit drain has no recorded serving contour".to_owned(),
            ));
        }
        let generation = self
            .registry
            .active()
            .map(|item| item.manifest.generation.clone())
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "cancelled pre-commit drain has no approved active generation".to_owned(),
                )
            })?;
        // The same fresh proof the tick reconcile uses, driven by this
        // trigger. A failing probe leaves `Draining` with a `Cancelled`
        // drain for the next trigger instead of manufacturing readiness.
        self.persist_process_observations(&generation)?;
        self.transition_activation_with_readiness_evidence(
            ActivationState::Active,
            "host-drain-cancelled",
        )?;
        host_lifecycle_observe_drain(BOUNDARY_DRAIN_RESUME_ACTIVE_RESTORED);
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
    /// A durable `Requested` or `Draining` prefix left by a crash between
    /// appends is resumed from the durable record — or refused with a typed
    /// error when it is not bound to this activation — so a restart recovers
    /// the same successor instead of substituting fresh evidence.
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
        let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_IDLE_DRAIN_TERMINAL);
        self.ensure_admission_open()?;
        let evidence = fresh_identity("host-idle-drain-evidence")?;
        let census_evidence = PlatformHandle::new(census_code)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let evidence_refs = vec![evidence, census_evidence];
        let state = self.snapshot()?;
        let activation = state.activation.clone().ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
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
        let opened = match state.drain.as_ref().map(|drain| drain.state) {
            Some(DrainState::Draining) => {
                // Audit 5906086103 D2/D3: a durable `Draining` record alone is
                // not an opened window — the helper verifies the matching
                // `Draining` activation and binding, finishes a missing
                // activation transition through the exact recorded attempt, or
                // fails closed. Only an established window authorizes the
                // caller to publish its timer.
                let drain = state.drain.as_ref().ok_or_else(|| {
                    HostError::OwnerLeaseRecovery(
                        "draining pre-commit drain record is absent".to_owned(),
                    )
                })?;
                self.resume_draining_window(&activation, drain)?
            }
            Some(DrainState::Failed) => {
                // I1.5: "A failed or timed-out drain leaves `DEGRADED_RECOVERY`
                // plus a WakeIntent/manual entrypoint rather than reporting
                // `STOPPED_CLEAN`." A `Failed` attempt is not re-armed here:
                // its failure direction is unreconciled, so the result names
                // the recovery obligation instead of resetting a timer.
                host_lifecycle_observe_drain(BOUNDARY_IDLE_DRAIN_DRAIN_FAILED_BLOCKED);
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
                self.append_idle_drain_draining(&activation, Some(&attempt), Vec::new())?;
                self.transition_activation(ActivationState::Draining, "host-idle-drain")?;
                true
            }
            Some(DrainState::Requested) => {
                // Audit 5906086103 D2: a crash between the re-arm appends
                // leaves `Requested` durable — the helper resumes the
                // successor from the durable record instead of substituting
                // fresh evidence or operations.
                let requested = state.drain.as_ref().ok_or_else(|| {
                    HostError::OwnerLeaseRecovery(
                        "requested pre-commit drain record is absent".to_owned(),
                    )
                })?;
                self.resume_requested_drain(&activation, requested)?
            }
            None => {
                if activation.state != ActivationState::Active {
                    host_lifecycle_observe_drain(BOUNDARY_IDLE_DRAIN_NOT_ACTIVE);
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
                self.append_idle_drain_draining(&activation, None, evidence_refs)?;
                self.transition_activation(ActivationState::Draining, "host-idle-drain")?;
                true
            }
        };
        if opened {
            host_lifecycle_observe_drain(BOUNDARY_IDLE_DRAIN_PRE_COMMIT_OPEN);
        }
        host_terminal.disarm();
        Ok(opened)
    }

    /// Verifies or finishes a durable `Draining` attempt, reporting whether the
    /// pre-commit window is established.
    ///
    /// When the matching `Draining` activation proves the attempt fully
    /// established, the window is durable. When only the activation transition
    /// is missing (crash between the appends), it is finished through the
    /// exact recorded attempt and re-verified. Anything else fails closed: a
    /// partial attempt is never published as a fully opened window while
    /// admissions may still be open.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable state cannot be read, the attempt is
    /// not bound to this activation, or the journal rejects the missing
    /// transition.
    fn resume_draining_window(
        &mut self,
        activation: &EliotActivationRecord,
        drain: &DrainRecord,
    ) -> Result<bool, HostError> {
        if activation.state == ActivationState::Draining {
            verify_drain_activation_binding(activation, drain)?;
            return Ok(true);
        }
        if activation.state != ActivationState::Active {
            return Err(HostError::RecoveryRequired(
                "pre-commit drain is Draining without a matching Active-or-Draining activation; recovery required"
                    .to_owned(),
            ));
        }
        verify_drain_fence_binding(activation, drain)?;
        self.transition_activation(ActivationState::Draining, "host-idle-drain")?;
        let finished = self.snapshot()?;
        let finished_activation = finished.activation.clone().ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        let finished_drain = finished.drain.as_ref().ok_or_else(|| {
            HostError::OwnerLeaseRecovery("draining pre-commit drain record is absent".to_owned())
        })?;
        verify_drain_activation_binding(&finished_activation, finished_drain)?;
        Ok(true)
    }

    /// Resumes a durable `Requested` attempt left by a crash between the
    /// re-arm appends, reporting whether the pre-commit window is established.
    ///
    /// The successor is resumed from the durable record — deterministic
    /// operation, inherited evidence, exact predecessor link — never a fresh
    /// evidence/operation substitution. A first attempt continues link-less on
    /// its durable evidence; a re-armed attempt replays its exact attempt
    /// identity, and a foreign record is refused instead of continued.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable state cannot be read, the attempt is
    /// not bound to this activation, or the journal rejects the continuation.
    fn resume_requested_drain(
        &mut self,
        activation: &EliotActivationRecord,
        requested: &DrainRecord,
    ) -> Result<bool, HostError> {
        if activation.state != ActivationState::Active {
            return Err(HostError::RecoveryRequired(
                "pre-commit drain is Requested without an Active activation to open the window; recovery required"
                    .to_owned(),
            ));
        }
        verify_drain_fence_binding(activation, requested)?;
        if requested.expected_predecessor.is_some() {
            self.append_rearm_draining_continuation(activation, requested)?;
        } else {
            self.append_record(HostStateRecord::Drain(DrainRecord {
                fence: activation.fence.clone(),
                operation: operation("host-idle-drain-draining")?,
                drain_generation: requested.drain_generation.clone(),
                state: DrainState::Draining,
                evidence_refs: requested.evidence_refs.clone(),
                expected_predecessor: None,
            }))?;
        }
        self.transition_activation(ActivationState::Draining, "host-idle-drain")?;
        Ok(true)
    }

    /// Appends the `Draining` half of one pre-commit drain attempt.
    ///
    /// A re-armed attempt reuses its own deterministic identity, its
    /// predecessor's `drain_generation` and its inherited evidence, so both
    /// appended records of that attempt agree and an exact retry reproduces
    /// them byte-for-byte. The continuation additionally names the exact
    /// re-armed `Requested` record checksum, which is what the reducer checks
    /// before admitting it — a restarted process therefore resumes the same
    /// successor instead of substituting a generic continuation. A first
    /// attempt keeps the existing label and generation with no attempt link.
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
        let (operation, drain_generation, evidence_refs, expected_predecessor) = match rearm {
            Some(attempt) => (
                drain_rearm_operation(
                    &activation.fence,
                    &attempt.drain_generation,
                    &attempt.predecessor_checksum,
                    &attempt.census_binding,
                    "draining",
                )?,
                attempt.drain_generation.clone(),
                attempt.evidence_refs.clone(),
                Some(attempt.requested_checksum.clone()),
            ),
            None => (
                operation("host-idle-drain-draining")?,
                activation.fence.activation_generation.clone(),
                evidence_refs,
                None,
            ),
        };
        self.append_record(HostStateRecord::Drain(DrainRecord {
            fence: activation.fence.clone(),
            operation,
            drain_generation,
            state: DrainState::Draining,
            evidence_refs,
            expected_predecessor,
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
    /// `ACTIVE` again (the trigger-driven
    /// [`HostComposition::resume_cancelled_drain_on_observable_use`] produces
    /// that from a fresh probe committed through the start-path owner; the
    /// reconcile-driven [`HostComposition::resume_cancelled_drain`] admits the
    /// same transition for a `Healthy` disposition); the prior drain is proven
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
            host_lifecycle_observe_drain(BOUNDARY_IDLE_DRAIN_REARM_NOT_ACTIVE);
            return Ok(None);
        }
        // A cancellation changes the obligation set, so the caller's cached
        // observation code is not authority for a new attempt: the census is
        // re-read here (I1.5: "Idle drain starts only when no `RuntimeLease`
        // remains and no valid `SupervisionLease` requires live
        // sensing/containment"). This is one read per re-arm attempt, never one
        // per tick.
        let census = self.idle_lease_census()?;
        let IdleLeaseCensus::Idle { owner_census } = &census else {
            host_lifecycle_observe_drain(BOUNDARY_IDLE_DRAIN_REARM_CENSUS_NOT_IDLE);
            return Ok(None);
        };
        if !owner_census.is_fully_retired() {
            host_lifecycle_observe_drain(BOUNDARY_IDLE_DRAIN_REARM_CENSUS_NOT_IDLE);
            return Ok(None);
        }
        // Audit 5906086103 D4: the attempt binds the exact owner-issued census
        // that admitted it — the `#1751` `RuntimeLeaseCensus` fence (same
        // contract the Kernel gate and the retirement barrier consume, see
        // `HostComposition::read_runtime_lease_census_for_activation` and
        // `HostComposition::require_generation_retirement_barrier`), digested
        // into the attempt identity and evidence — never a cached zero, a bare
        // code, or a second Host-local counter. The barrier revalidates the
        // same fence before commit, so new work is either included in that
        // census or prevents the drain.
        let census_binding = format!(
            "idle:{}",
            sha256_json(&(
                &owner_census.state_fence,
                &owner_census.supervision_lease_id
            ))?
        );
        let predecessor_checksum = record_checksum(&HostStateRecord::Drain(predecessor.clone()))?;
        // The successor inherits its predecessor's evidence, which is what
        // keeps a delayed first-attempt trigger recognisable as already
        // consumed by this attempt (see `note_observable_use`) and keeps this
        // re-arm a pure function of durable state.
        let mut evidence_refs = vec![
            PlatformHandle::new(format!("drain-rearm-predecessor:{predecessor_checksum}"))
                .map_err(|error| HostError::Platform(error.to_string()))?,
            PlatformHandle::new(census_binding.clone())
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ];
        for bound in &predecessor.evidence_refs {
            if !evidence_refs.contains(bound) {
                evidence_refs.push(bound.clone());
            }
        }
        let requested = DrainRecord {
            fence: activation.fence.clone(),
            operation: drain_rearm_operation(
                &activation.fence,
                &predecessor.drain_generation,
                &predecessor_checksum,
                &census_binding,
                "request",
            )?,
            drain_generation: predecessor.drain_generation.clone(),
            state: DrainState::Requested,
            evidence_refs: evidence_refs.clone(),
            expected_predecessor: Some(predecessor_checksum.clone()),
        };
        let requested_checksum = record_checksum(&HostStateRecord::Drain(requested.clone()))?;
        let attempt = DrainRearmAttempt {
            predecessor_checksum,
            drain_generation: predecessor.drain_generation.clone(),
            census_binding,
            requested_checksum,
            evidence_refs: evidence_refs.clone(),
        };
        self.append_record(HostStateRecord::Drain(requested))?;
        host_lifecycle_observe_drain(BOUNDARY_IDLE_DRAIN_REARM_REQUESTED);
        Ok(Some(attempt))
    }

    /// Appends the `Draining` continuation of a durable re-armed `Requested`
    /// record after a crash between the re-arm appends.
    ///
    /// Every continuation fact is reconstructed from the durable record: the
    /// cancelled predecessor checksum and census binding it names, its drain
    /// generation, and its inherited evidence. The durable record must itself
    /// reproduce the deterministic re-arm operation of this activation, so a
    /// foreign record is refused instead of continued. The continuation names
    /// the exact durable `Requested` checksum, so the reducer admits it only
    /// for the attempt it continues.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable record is not this activation's
    /// re-arm attempt or the journal rejects the continuation.
    fn append_rearm_draining_continuation(
        &mut self,
        activation: &EliotActivationRecord,
        requested: &DrainRecord,
    ) -> Result<(), HostError> {
        let cancelled_checksum = requested.expected_predecessor.clone().ok_or_else(|| {
            HostError::RecoveryRequired(
                "re-armed Requested record names no cancelled predecessor; recovery required"
                    .to_owned(),
            )
        })?;
        let census_binding = rearm_census_binding_from(requested)?;
        let expected_request = drain_rearm_operation(
            &activation.fence,
            &requested.drain_generation,
            &cancelled_checksum,
            &census_binding,
            "request",
        )?;
        if expected_request != requested.operation {
            return Err(HostError::RecoveryRequired(
                "durable Requested record is not this activation's re-arm attempt; recovery required"
                    .to_owned(),
            ));
        }
        let requested_checksum = record_checksum(&HostStateRecord::Drain(requested.clone()))?;
        self.append_record(HostStateRecord::Drain(DrainRecord {
            fence: activation.fence.clone(),
            operation: drain_rearm_operation(
                &activation.fence,
                &requested.drain_generation,
                &cancelled_checksum,
                &census_binding,
                "draining",
            )?,
            drain_generation: requested.drain_generation.clone(),
            state: DrainState::Draining,
            evidence_refs: requested.evidence_refs.clone(),
            expected_predecessor: Some(requested_checksum),
        }))
        .map(|_| ())
    }

    /// Establishes the generation-scoped lease census that gates idle drain.
    ///
    /// The Host mirror and Kernel stop gate consume the same typed owner
    /// projection. A missing or mismatched authenticated ORS read reports
    /// `Unavailable`; every non-terminal owner remains blocking independent
    /// of its deadline until the owner records a legal transition.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable Host state or the Host state root
    /// cannot be read.
    pub fn idle_lease_census(&self) -> Result<IdleLeaseCensus, HostError> {
        // F-LOG-HOST-1: guard probe only; never a terminal and never a claim.
        host_lifecycle_observe_scm(BOUNDARY_LEASE_CENSUS_REQUESTED);
        let state = self.snapshot()?;
        let activation = state.activation.as_ref().ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        let owner_census = match self.read_runtime_lease_census_for_activation(activation) {
            Ok(census) => census,
            Err(error) => {
                return Ok(IdleLeaseCensus::Unavailable {
                    reason: lease_census_reason(&error),
                });
            }
        };
        let mut active_runtime_lease_refs = Vec::new();
        for lease_ref in &activation.runtime_lease_refs {
            let Some(lease) = owner_census
                .runtime_leases
                .iter()
                .find(|lease| lease.lease_id.as_str() == lease_ref.as_str())
            else {
                // A Host reference is only a mirror. If its exact-fence owner
                // row is missing, the complete census cannot prove whether
                // that referenced lease reached a legal terminal transition.
                return Ok(IdleLeaseCensus::Unavailable {
                    reason: "host-runtime-lease-reference-missing-from-owner-census",
                });
            };
            if !runtime_lease_is_terminal(lease.state) {
                active_runtime_lease_refs.push(lease_ref.clone());
            }
        }
        if !active_runtime_lease_refs.is_empty() {
            return Ok(IdleLeaseCensus::RuntimeLeased {
                refs: active_runtime_lease_refs,
                owner_census,
            });
        }
        let supervision = &owner_census.supervision_lease.record;
        if !runtime_lease_is_terminal(supervision.state) {
            return Ok(IdleLeaseCensus::Supervised {
                lease_ref: match PlatformHandle::new(supervision.lease_id.as_str()) {
                    Ok(lease_ref) => lease_ref,
                    Err(_) => {
                        return Ok(IdleLeaseCensus::Unavailable {
                            reason: "owner-supervision-lease-identity-invalid",
                        });
                    }
                },
                owner_census,
            });
        }
        if owner_census.is_fully_retired() {
            Ok(IdleLeaseCensus::Idle { owner_census })
        } else {
            Ok(IdleLeaseCensus::StoreObligationLeased { owner_census })
        }
    }

    pub(super) fn live_supervision_obligation_for(
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

    /// (Re)binds the pending activation record's held `RuntimeLease` reference
    /// from the admitted observable obligation of this generation.
    ///
    /// I1.5 W4 (`RuntimeLease` issuance/renewal, Host leg): a transition into
    /// a live state holds exactly one runtime lease — the deterministic
    /// [`runtime_lease_id_for`] identity of this activation generation — and
    /// only when the latest durable readiness observation already admitted
    /// this generation on fresh evidence. I1.5: "A `RuntimeLease` is acquired
    /// automatically for an active authenticated ... Session, `AgentAttempt`,
    /// Durable Job, upgrade/repair or unresolved external effect" and "A lease
    /// renewal is a new revision of the same active lease identity and must
    /// carry fresh observed evidence". The generation is the obligation the
    /// Host serves, so issuance binds the identity when the generation first
    /// goes live holding nothing, and renewal re-asserts that same identity on
    /// every later live entry carrying fresh evidence — never a second
    /// identity, never on a stale predecessor. A held reference that is not
    /// this generation's identity fails the transition closed: a stale
    /// predecessor lease is never renewed, and reconciliation stays owed
    /// instead of vanishing into a live state.
    ///
    /// The durable writer is the journal append the caller performs with this
    /// revision; the ORS row for the held identity is committed by the Kernel
    /// writer lane under the same generation-bound identity
    /// (`bins/eliot-kernel/src/control_plane.rs::runtime_lease_id_for_candidate`).
    ///
    /// # Errors
    ///
    /// Returns an error when the durable Host state cannot be read, when no
    /// admitted readiness observation exists, when the admitting observation
    /// is not fresh evidence for this generation, or when the held references
    /// are not this generation's lease.
    pub(super) fn refresh_runtime_lease_binding(
        &self,
        next: &mut EliotActivationRecord,
    ) -> Result<(), HostError> {
        let expected =
            runtime_lease_id_for(&next.activation_id, &next.fence.activation_generation)?;
        let snapshot = self.snapshot()?;
        let observation = snapshot.readiness_observations.last().ok_or_else(|| {
            HostError::RecoveryRequired(
                "runtime-lease binding has no admitted readiness predecessor".to_owned(),
            )
        })?;
        if !is_fresh_admitting_observation(next, observation) {
            return Err(HostError::RecoveryRequired(
                "admitted runtime-lease predecessor is not fresh evidence for this generation"
                    .to_owned(),
            ));
        }
        if next.runtime_lease_refs.is_empty() {
            next.runtime_lease_refs = vec![expected];
            return Ok(());
        }
        if next.runtime_lease_refs.as_slice() == core::slice::from_ref(&expected) {
            return Ok(());
        }
        Err(HostError::RecoveryRequired(
            "held runtime-lease reference is not this generation's lease; stale predecessor leases never renew"
                .to_owned(),
        ))
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

    /// Returns the durable post-commit next-generation wake demand for the
    /// stopped-installation demand-start owner.
    ///
    /// This is the owner handoff the post-commit path was missing: the full
    /// retained [`WakeRecord`] — identity, required capabilities, schedule
    /// window, safety class and fences — read back from the journal, never
    /// reconstructed, so the owner fires only what the journal retains. Only
    /// wakes queued by the post-commit path (see
    /// [`NEXT_GENERATION_WAKE_MAINTENANCE_FAMILY`]) still `Pending` are
    /// eligible; other wake families are never reinterpreted as
    /// next-generation demand. The cross-process arm itself — the
    /// installer-admitted Task Scheduler Host-wake registration firing
    /// `StartService(eliot-host)`, consumed on startup as `ScheduledWake` —
    /// is STITCH work outside this path scope: no Host-wake scheduler
    /// publisher exists in-tree (the in-tree Task Scheduler routes — the
    /// per-user launcher supervision and the signed notify fallback — belong
    /// to other lifecycles and cannot be reused for Host wake), and this
    /// module creates no second scheduler or authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable Host state cannot be read.
    pub fn next_generation_wake_handoff(&self) -> Result<Option<WakeRecord>, HostError> {
        let state = self.snapshot()?;
        Ok(state.wakes.iter().find_map(|wake| {
            (wake.intent.state == WakeIntentState::Pending
                && wake.maintenance_family.as_str() == NEXT_GENERATION_WAKE_MAINTENANCE_FAMILY)
                .then(|| wake.clone())
        }))
    }

    /// Returns the stopped-installation demand this process start serves, if any.
    ///
    /// This is the Host-side consumption point of the post-commit
    /// next-generation demand: the admitted stopped-installation
    /// demand-start owner fires `StartService(eliot-host)` for a `Pending`
    /// intent this journal retains, and the start joins the activation as
    /// [`ActivationTriggerClass::ScheduledWake`] with the intent's durable
    /// `wake_id` as trigger evidence, so the intent is claimed by the
    /// generation it was queued for instead of lingering unowned.
    ///
    /// Only an actionable owner-family intent qualifies: `Pending`, carrying
    /// this owner's maintenance family, with a `Due` or `Expired` schedule. A
    /// not-yet-due intent is not this start's firing and stays `Pending` for
    /// the trigger whose time has come; any other wake family keeps its own
    /// policy untouched. When the journal holds no such intent this start
    /// carries no wake demand and no trigger is recorded.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable Host state or the wall clock cannot
    /// be read.
    pub fn startup_wake_demand(
        &self,
    ) -> Result<Option<(ActivationTriggerClass, PlatformHandle)>, HostError> {
        let state = self.snapshot()?;
        let now_ms = unix_millis()?;
        Ok(state.wakes.iter().find_map(|wake| {
            if wake.intent.state != WakeIntentState::Pending
                || wake.maintenance_family.as_str() != NEXT_GENERATION_WAKE_MAINTENANCE_FAMILY
            {
                return None;
            }
            match next_generation_wake_schedule_state(wake, now_ms) {
                NextGenerationWakeSchedule::Due | NextGenerationWakeSchedule::Expired => {
                    Some((ActivationTriggerClass::ScheduledWake, wake.wake_id.clone()))
                }
                NextGenerationWakeSchedule::NoOwnerPolicy | NextGenerationWakeSchedule::NotDue => {
                    None
                }
            }
        }))
    }

    /// Returns the capability set this activation generation durably requires.
    ///
    /// I1.5 "start only the remaining capabilities required by the admitted
    /// request": the set that may gate a process contour is the one the
    /// activation record itself carries, read back from the journal. It is never
    /// recomputed from the caller's intent, so a contour cannot be started
    /// against a capability no admitted request ever required.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable Host state or the activation record
    /// cannot be read.
    pub fn required_generation_capabilities(&self) -> Result<Vec<PlatformHandle>, HostError> {
        let state = self.snapshot()?;
        let activation = state.activation.as_ref().ok_or_else(|| {
            HostError::OwnerLeaseRecovery("activation record is absent".to_owned())
        })?;
        Ok(activation.requested_capabilities.clone())
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
    /// I1.5 background-wake schedule: a post-commit next-generation intent
    /// additionally carries the queue path's earliest/deadline/expiry markers.
    /// A past-expiry intent becomes `EXPIRED` (a legal journal edge) instead
    /// of claimed or cancelled, and a not-yet-due intent is left `PENDING`
    /// with no row written. Wakes outside this owner's maintenance family
    /// keep their existing claim rule untouched.
    ///
    /// A `Due` owner-family intent presented by a `ScheduledWake` trigger —
    /// the demand-start owner's firing for the generation it was queued for —
    /// is additionally claimed by the direct-child generation once the
    /// parent's `DrainCommitRecord` proves the old authority fenced, with the
    /// generation's own durable requirement as the capability gate. The new
    /// generation can never share the old authority (fencing it is the point
    /// of the commit), so same-authority can never prove this claim; the
    /// commit record naming the wake's generation is the proof instead. An
    /// unserviceable demand is still `CANCELLED` rather than executed because
    /// it was once queued.
    ///
    /// Returns `(claimed, expired)`: claimed intents this pass, and
    /// owner-family intents moved to `Expired` this pass. The caller surfaces
    /// the expired count on the admitting trigger (see
    /// [`ObservableUseOutcome`]); the `Pending` filter never revisits an
    /// expired intent, so that surfacing is deduplicated by construction.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable state cannot be read, the wall clock
    /// cannot be read, or the journal rejects a transition.
    pub fn revalidate_pending_wakes(
        &mut self,
        activation: &EliotActivationRecord,
        trigger: ActivationTriggerClass,
        evidence: &PlatformHandle,
    ) -> Result<(usize, usize), HostError> {
        let state = self.snapshot()?;
        let pending = state
            .wakes
            .iter()
            .filter(|wake| wake.intent.state == WakeIntentState::Pending)
            .cloned()
            .collect::<Vec<_>>();
        if pending.is_empty() {
            return Ok((0, 0));
        }
        let requested = trigger
            .requested_capabilities()
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect::<Vec<_>>();
        // I1.5 background-wake schedule: the durable earliest/deadline/expiry
        // markers the post-commit queue path wrote are consumed here, on the
        // only path that may move a `PENDING` intent forward. The clock is
        // read once for the whole pass; an unreadable clock fails the pass
        // closed rather than claiming under an unproven schedule.
        let now_ms = unix_millis()?;
        let mut claimed = 0_usize;
        let mut expired = 0_usize;
        for wake in pending {
            match next_generation_wake_schedule_state(&wake, now_ms) {
                NextGenerationWakeSchedule::NoOwnerPolicy | NextGenerationWakeSchedule::Due => {}
                NextGenerationWakeSchedule::NotDue => {
                    // Eligible only once the committed generation's authority
                    // is fenced. A `Pending -> Pending` edge does not exist,
                    // so leaving the record untouched is the only honest
                    // wait: no row is written for a demand whose time has not
                    // come.
                    continue;
                }
                NextGenerationWakeSchedule::Expired => {
                    // Stale demand never executes because it was once queued:
                    // `Pending -> Expired` is a legal journal edge, and the
                    // obligation surfaces as the manual entrypoint rather
                    // than a wake nothing may still claim.
                    let mut next = wake.clone();
                    next.operation = operation("host-wake-expiry")?;
                    next.reason_evidence_refs.push(evidence.clone());
                    next.intent.state = WakeIntentState::Expired;
                    self.append_record(HostStateRecord::Wake(next))?;
                    expired += 1;
                    continue;
                }
            }
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
            // AUD6: the demand-start owner's firing serves the demand queued
            // for exactly this generation. The conditions are deliberately
            // narrow: only a `ScheduledWake` trigger may claim across the
            // generation boundary, only for a `Due` intent of this owner's
            // maintenance family, only by the direct-child generation of the
            // wake's own generation, and only when the durable
            // `DrainCommitRecord` names that parent generation — the
            // linearization proof I1.5 requires before the next generation
            // may start. The capability gate reads the generation's own
            // durable requirement, never the trigger's class set, because the
            // firing serves the queued demand rather than stating new demand.
            let next_generation_claim = trigger == ActivationTriggerClass::ScheduledWake
                && wake.maintenance_family.as_str() == NEXT_GENERATION_WAKE_MAINTENANCE_FAMILY
                && matches!(
                    next_generation_wake_schedule_state(&wake, now_ms),
                    NextGenerationWakeSchedule::Due
                )
                && activation
                    .fence
                    .activation_generation
                    .current
                    .is_direct_child_of(&wake.fence.activation_generation.current)
                && state
                    .drain_commit
                    .as_ref()
                    .is_some_and(|commit: &DrainCommitRecord| {
                        commit
                            .drain_generation
                            .current
                            .is_same_authority(&wake.fence.activation_generation.current)
                    })
                && wake.required_capabilities.iter().all(|capability| {
                    activation
                        .requested_capabilities
                        .iter()
                        .any(|required| required.as_str() == capability.as_str())
                });
            let mut next = wake.clone();
            next.operation = operation("host-wake-revalidation")?;
            next.reason_evidence_refs.push(evidence.clone());
            next.intent.state = if (same_generation && same_authority && capabilities_covered)
                || next_generation_claim
            {
                claimed += 1;
                WakeIntentState::Claimed
            } else {
                WakeIntentState::Cancelled
            };
            self.append_record(HostStateRecord::Wake(next))?;
        }
        host_lifecycle_observe_scm(BOUNDARY_WAKE_REVALIDATION_OBSERVED);
        Ok((claimed, expired))
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
        let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_WAKE_SATISFY_TERMINAL);
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
        host_lifecycle_observe_scm(BOUNDARY_WAKE_SATISFIED_OBSERVED);
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
        // I1.5 background-wake schedule: the demand already arrived, so the
        // intent is eligible as soon as the committed generation's authority
        // is fenced (`earliest_start` is now); it is due within one idle
        // grace (`deadline`) and stale past the bounded horizon (`expiry`),
        // after which revalidation expires it instead of executing it.
        // Saturating arithmetic keeps a far-future clock from wrapping the
        // window into the past.
        let deadline_ms = now_ms.saturating_add(NEXT_GENERATION_WAKE_DEADLINE_MS);
        let expiry_ms = now_ms.saturating_add(NEXT_GENERATION_WAKE_EXPIRY_MS);
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
            earliest_start: PlatformHandle::new(format!(
                "{NEXT_GENERATION_WAKE_EARLIEST_PREFIX}{now_ms}"
            ))
            .map_err(|error| HostError::Platform(error.to_string()))?,
            deadline: PlatformHandle::new(format!(
                "{NEXT_GENERATION_WAKE_DEADLINE_PREFIX}{deadline_ms}"
            ))
            .map_err(|error| HostError::Platform(error.to_string()))?,
            expiry: PlatformHandle::new(format!("{NEXT_GENERATION_WAKE_EXPIRY_PREFIX}{expiry_ms}"))
                .map_err(|error| HostError::Platform(error.to_string()))?,
            required_capabilities,
            maintenance_family: PlatformHandle::new(NEXT_GENERATION_WAKE_MAINTENANCE_FAMILY)
                .map_err(|error| HostError::Platform(error.to_string()))?,
            safety_class: ServiceSafetyClass::ServiceSafe,
            state_fence_revalidation_ref,
            budget_ref: PlatformHandle::new("wake-budget:drain-next-generation")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        }))?;
        Ok(wake_id)
    }
}

/// The capability requirement of a fresh control-contour activation.
///
/// I1.5 startup: "Host starts/reconciles Kernel and requests the independent
/// Watchdog service through SCM as sibling activation branches", and the
/// canonical store branch belongs to the same contour because the Host
/// readiness fence refuses `ControlReady` without a proven Store branch. This
/// is the bootstrap requirement of a generation that has no narrower proven
/// ingress; a narrower trigger class contributes its own set through
/// [`ActivationTriggerClass::requested_capabilities`].
#[must_use]
pub const fn control_contour_capabilities() -> &'static [&'static str] {
    &[
        CAPABILITY_RUNTIME_SUPERVISION,
        CAPABILITY_CANONICAL_STORE,
        CAPABILITY_INDEPENDENT_SUPERVISION,
    ]
}

/// Whether a durable activation-generation capability set requires `capability`.
///
/// The set carries handles spelled by the
/// [`ActivationTriggerClass::requested_capabilities`] vocabulary, so the
/// comparison is against that frozen spelling rather than a fresh literal.
#[must_use]
pub fn requires_capability(required: &[PlatformHandle], capability: &str) -> bool {
    required.iter().any(|value| value.as_str() == capability)
}

/// ORS identity prefix for one Host-held generation runtime lease.
///
/// The spelling is the durable key the canonical
/// `ors_runtime_lease_current_v1` table selects by
/// (`RedbRecoveryStore::load_runtime_leases_by_state_fence` requires
/// `key == lease_id`), so the crates-side writer lane adopts this identity
/// without a second scheme.
pub const RUNTIME_LEASE_ID_PREFIX: &str = "runtime-lease";

/// Deterministic `RuntimeLease` identity for one activation generation.
///
/// One lease per live generation: the generation is the obligation the Host
/// serves, and I1.5 renewal is "a new revision of the same active lease
/// identity", so renewal re-asserts this identity on fresh evidence instead of
/// minting a second one. Derived from the durable record content only — never
/// carried, never cached — so a stale predecessor identity can never pass as
/// this generation's lease.
///
/// Row-leg STITCH (I1.5 Work: issuance, renewal, expiry, revocation,
/// reconciliation): this file holds lease *references*, never rows, so row
/// content is never constructed here — rows are committed only by the Kernel
/// writer lane under this identity
/// (`bins/eliot-kernel/src/control_plane.rs::runtime_lease_id_for_candidate`:
/// issuance, the `expire_past_due_runtime_leases`,
/// `supersede_stale_runtime_leases` and `renew_runtime_leases_for_probe` tick,
/// and the explicit-command-only `RevokeRuntimeLease` arm, all through the
/// owner `RuntimeLease::transition_to` legality into
/// `RedbRecoveryStore::record_runtime_lease_current`) and read back by exact
/// `state_fence` equality
/// (`RedbRecoveryStore::load_runtime_leases_by_state_fence` and
/// `load_runtime_lease_census_by_state_fence`, served over the authenticated
/// `ReadRuntimeLeaseCensus` wire by
/// `bins/eliot-kernel/src/idle_lease_census.rs::read_runtime_lease_census`
/// for `bins/eliot-host/src/lease_drain.rs::require_generation_retirement_barrier`).
/// The `Active` to `Reconciling` row producer has no call site yet and belongs
/// beside the existing `Revoked`/`Expired`/`Superseded` arms in that same
/// Kernel writer lane.
///
/// # Errors
///
/// Returns an error when the identity spelling is not a valid handle.
pub fn runtime_lease_id_for(
    activation_id: &PlatformHandle,
    generation: &EpochTransition,
) -> Result<PlatformHandle, HostError> {
    PlatformHandle::new(format!(
        "{RUNTIME_LEASE_ID_PREFIX}:{}:{}:{}",
        activation_id.as_str(),
        generation.current.lineage_id,
        generation.current.sequence
    ))
    .map_err(|error| HostError::Platform(error.to_string()))
}

/// Whether the admitting observation is fresh evidence for this generation.
///
/// Same activation identity and generation, carrying evidence — content
/// compared on the durable records. A stale predecessor observation, or one
/// carrying no evidence, is never freshness: every lease caller fails it
/// closed instead of admitting, issuing, or renewing on observation it did
/// not make. Shared by the supervision binding and
/// [`HostComposition::refresh_runtime_lease_binding`] so both legs enforce
/// one rule (I1.5: "must carry fresh observed evidence").
#[must_use]
pub(super) fn is_fresh_admitting_observation(
    activation: &EliotActivationRecord,
    observation: &KernelReadinessObservationRecord,
) -> bool {
    observation.fence.activation_id == activation.activation_id
        && observation.fence.activation_generation == activation.fence.activation_generation
        && !observation.evidence_refs.is_empty()
}

/// Proves the terminal `RuntimeLease` reference release of a clean stop.
///
/// `transition_activation_record` clears the held runtime-lease references on
/// `StoppedClean` because the obligations were snapshotted into the
/// `DrainCommitRecord` at linearization. This proof runs on that same edge and
/// requires every cleared reference to be this generation's own
/// [`runtime_lease_id_for`] identity: a foreign or stale predecessor reference
/// must never vanish silently — reconciliation is still owed there, so the
/// stop fails closed instead of reporting a clean release it did not prove.
///
/// This proves the reference release only, never a `Released` row transition:
/// row-state expiry, revocation and reconciliation move exclusively through
/// the Kernel writer lane under [`runtime_lease_id_for`] (see its row-leg
/// note), so no lease-row state is fabricated here.
///
/// # Errors
///
/// Returns an error when a held reference is not this generation's lease.
fn runtime_lease_is_terminal(state: eliot_runtime_contracts::LeaseState) -> bool {
    matches!(
        state,
        eliot_runtime_contracts::LeaseState::Released
            | eliot_runtime_contracts::LeaseState::Expired
            | eliot_runtime_contracts::LeaseState::Revoked
            | eliot_runtime_contracts::LeaseState::Superseded
            | eliot_runtime_contracts::LeaseState::Closed
    )
}

pub(super) fn prove_terminal_runtime_release(
    current: &EliotActivationRecord,
) -> Result<(), HostError> {
    let expected =
        runtime_lease_id_for(&current.activation_id, &current.fence.activation_generation)?;
    if current
        .runtime_lease_refs
        .iter()
        .all(|held| *held == expected)
    {
        return Ok(());
    }
    Err(HostError::RecoveryRequired(
        "clean stop would silently release a runtime-lease reference that is not this generation's lease"
            .to_owned(),
    ))
}

/// Requires a pre-commit drain record to be bound to the current activation
/// generation.
///
/// Audit 5906086103 D3: the timer publication gate. The fence identity and
/// generation, the attempt's drain generation, and non-empty admission
/// evidence must all name this generation; a record bound elsewhere is refused
/// instead of published or continued.
fn verify_drain_fence_binding(
    activation: &EliotActivationRecord,
    drain: &DrainRecord,
) -> Result<(), HostError> {
    if drain.fence.activation_id != activation.activation_id
        || drain.fence.activation_generation != activation.fence.activation_generation
        || drain.drain_generation != activation.fence.activation_generation
        || drain.evidence_refs.is_empty()
    {
        return Err(HostError::RecoveryRequired(
            "pre-commit drain attempt is not bound to the current activation generation; recovery required"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Requires a fully established pre-commit window: `Draining` drain plus
/// matching `Draining` activation plus the attempt/admission binding.
///
/// Only an established window authorizes the caller to publish
/// `precommit_opened_at`. A partial prefix is never a window.
fn verify_drain_activation_binding(
    activation: &EliotActivationRecord,
    drain: &DrainRecord,
) -> Result<(), HostError> {
    if activation.state != ActivationState::Draining {
        return Err(HostError::RecoveryRequired(
            "pre-commit window requires a Draining activation; recovery required".to_owned(),
        ));
    }
    verify_drain_fence_binding(activation, drain)
}

/// Reads the owner census binding a durable re-armed `Requested` record was
/// admitted under.
///
/// Evidence layout is the re-arm writer's own contract: the predecessor link,
/// then the census binding (`idle` for attempts admitted before the fence
/// binding landed, `idle:<owner-fence-digest>` after), then the inherited
/// predecessor evidence. Anything else is a foreign record and is refused.
fn rearm_census_binding_from(requested: &DrainRecord) -> Result<String, HostError> {
    let mut refs = requested.evidence_refs.iter();
    let predecessor_ref = refs.next().ok_or_else(|| {
        HostError::RecoveryRequired(
            "re-armed Requested record carries no predecessor evidence; recovery required"
                .to_owned(),
        )
    })?;
    let census_ref = refs.next().ok_or_else(|| {
        HostError::RecoveryRequired(
            "re-armed Requested record carries no owner census binding; recovery required"
                .to_owned(),
        )
    })?;
    if !predecessor_ref
        .as_str()
        .starts_with("drain-rearm-predecessor:")
    {
        return Err(HostError::RecoveryRequired(
            "re-armed Requested record carries no predecessor evidence; recovery required"
                .to_owned(),
        ));
    }
    let binding = census_ref.as_str();
    if binding == "idle" || (binding.starts_with("idle:") && binding.len() > "idle:".len()) {
        Ok(binding.to_owned())
    } else {
        Err(HostError::RecoveryRequired(
            "re-armed Requested record carries no owner census binding; recovery required"
                .to_owned(),
        ))
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
        HostError::StoreCensusKernel(_) => "kernel-store-census-unavailable",
        HostError::StoreCensusTransport(_) => "kernel-store-census-transport-unreadable",
        HostError::StoreCensusIo(_) => "store-census-runtime-unavailable",
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
        // Ownership of the planned Store endpoint is unproven, so the durable
        // supervision state behind it could not be established either; the
        // census must not report `Idle` on an unverified endpoint.
        #[cfg(windows)]
        HostError::OriginCollisionUnproven(_) => "durable-state-unreadable",
        #[cfg(windows)]
        HostError::StoreEndpointOwnerUnreadable(_) => "durable-state-unreadable",
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
