//! `eliotd` daemon entrypoint and runtime loop.
//!
//! Architecture traceability: A13.2 keeps Kernel authority and failure-domain
//! ownership explicit; A13.8 requires integrity evidence and visible
//! degradation. Implementation traceability: I1.8 defines daemon/Kernel
//! ownership and call paths, I2.16 bounds this complete workset, and I2.23
//! admits this cohesive extraction boundary.
//!
//! This module only runs the already-admitted daemon entrypoint and emits
//! readiness/degraded/fatal protocol evidence. It has no Kernel/store semantic
//! authority, lifecycle policy ownership, SCM, Host, Watchdog, or canonical
//! mutation authority.
//!
//! # This driver calls no `commit_canonical_and_refresh` (issue #1929)
//!
//! Recorded because the #1929 work list names this module as the intended
//! production caller of `DaemonComposition::commit_canonical_and_refresh`, and
//! the absence of any such call is the measured reason that entry — and with it
//! the typed task-binding evidence leg — is unreachable. Measured on this tree,
//! not inferred: no production code in this module calls
//! `commit_canonical_and_refresh` or `admit_canonical_write`.
//!
//! It must not be read as "this driver commits no canonical write". It does:
//! the `TestD` owner finish driver runs `commit_testd_terminal_owner_fact`,
//! which exchanges up to three Governor-owned canonical legs over the neutral
//! `KernelTransitionPort`. Those legs therefore pass through
//! `DaemonKernelClient::apply_prepared` and its `check_identity_binding`, so the
//! **live** #1929 admission edge is the transport one
//! (`task_binding_admission::admit_named_mutation_capture`), not the
//! composition-root one. What is unreachable is only the leg that needs a typed
//! `TaskSelectionEvidence`.
//!
//! That leg cannot be given a call here honestly today. Committing through
//! `commit_canonical_and_refresh` requires a caller-presented
//! `MaterialReadinessInputs`, whose `OnboardingReadinessReceipt` is the only
//! carrier of a real `TaskSelectionEvidence`, and this driver has no source for
//! one: the repository's sole production constructor of that receipt,
//! `eliot_workscope::ColdStartController::compile`, is reached only through
//! `eliot_workscope::OnboardingSingleFlight::compile_and_publish` and therefore
//! only through the uncalled
//! `eliot_governor::GovernorComposition::compile_cold_start_at_trigger`.
//! Manufacturing a receipt here — a task revision, an acceptance digest, a
//! governance profile, a lease — would fabricate exactly the authority the
//! admission gate exists to verify, so it was not done. The owner of that
//! receipt is the attach/onboarding ingress, not this driver. See
//! `eliotd::task_binding_admission`'s "Measured reachability" section.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::PathBuf;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    ClockReading, ProductId, RequestId, SessionId, SourceId, StateFence, TaskId,
    canonical_json_bytes, sha256_hex,
};
use eliot_governor::{KernelGenerationSnapshotProvider, KernelTransitionPort};
use eliot_improvement::candidate_bounds::BoundedBacklog;
use eliot_protocol::{
    AgentActivationKernelOwnerReadback, AgentActivationOwnerReadback,
    AgentActivationResolutionDisposition, AgentActivationResolutionResult,
    AgentActivationResolutionTicket, AgentActivationResultAck, AgentActivationResultAckOutcome,
    AgentActivationResultReconcile, HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestEnvelope,
    HostRequestResultBody, HostRequestResultClass, HostRequestResultLineage,
    HostRequestResultSourceRevision, LocalReadAttempt, host_request_operation_id,
};
use eliot_read::{
    CurrentStateView, NamedParameters, ReadApi, ReadOrderingBinding, ReadService, StateRequest,
};
use eliot_runtime_contracts::DaemonProgressChannel;
use eliot_security_contracts::InfluenceState;
use eliot_store_api::{
    EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, ReadConsistency, RevisionKey, ScopeId,
    StoreHealth, StoreHealthStatus,
};
use eliotd::diagnostics::RepeatedFailureGuard;
use eliotd::startup_capability_bindings::{
    DeclaredStartupCapability, RetainedStartupBinding, StartupBindingDisposition,
    StartupCapabilityBindings,
};
use eliotd::startup_readiness::{
    LocalDeltaAdoption, LocalDeltaConflict, LocalReadinessDelta, StartupReadinessProjection,
};
use eliotd::testd_terminal_completion::{
    TestdOwnerDrainOutcome, ack_testd_owner_terminal_completion,
    bind_testd_owner_verifier_dispatch, commit_testd_terminal_owner_fact,
    emit_testd_owner_drain_skip, query_testd_owner_pending_dispatches,
    query_testd_owner_terminal_evidence,
};
use eliotd::{
    ActivationClaim, ActivationSubmitError, AgentActivationResolver, DaemonComposition,
    DaemonConfig, DaemonKernelClient, DaemonStatus, FinishSubmitOutcome, KernelContextReadClient,
    LocalReadSubmitOutcome, MaintenanceObservation, MaintenanceTriggerOrigin, ObserveDeferOutcome,
    PROTOCOL_VERSION, SELF_OBSERVED_FAMILY, SERVICE_NAME, StateSubmitOutcome,
    TaskControllerSubmitOutcome, forward_admitted_local_read, serve_admitted_observe,
    terminal_for_invalid_ticket,
};
use serde::Serialize;
use tokio::time::{Instant, Interval, MissedTickBehavior};

/// Shared daemon composition handle for the run loop. Flight futures own any
/// borrow they need, keeping lock-owning work pollable by the loop. The
/// owner-feed exchange still holds this guard across bounded IO, and the
/// health and maintenance handlers retain their lock waits in polled flights,
/// so neither selected handler blocks the loop behind the owner-feed lock
/// holder. A poisoned `TestD` row never fails the daemon closed; transport
/// failures do, mirroring the local-read poller.
type SharedComposition = Arc<tokio::sync::Mutex<DaemonComposition>>;
/// The run loop and its polled heartbeat share one current-thread readiness
/// projection. Callers borrow it only for synchronous observation/adoption.
type SharedStartupReadiness = Rc<RefCell<StartupReadinessProjection>>;

const ACTIVATION_POLL_INTERVAL: Duration = Duration::from_millis(100);
const HEALTH_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// Bounded drain for an in-flight activation when shutdown arrives. The drain
/// never starts new work and never recomputes under a new id; a timeout
/// surfaces a typed unknown outcome with the original identity.
const SHUTDOWN_ACTIVATION_DRAIN: Duration = Duration::from_secs(2);

/// Bounded observation counter for transient `NotReady` deferrals. Kernel
/// owns retry policy; this counter is diagnostic only and introduces no
/// timer or cache.
static TRANSIENT_DEFERRAL_OBSERVED: AtomicU64 = AtomicU64::new(0);

/// Actual activation activity observed while the one heartbeat flight owns the
/// supervision producer. Fixed counters keep the event cut bounded regardless
/// of heartbeat latency.
#[derive(Default)]
struct DeferredSupervisionActivity {
    claims: u64,
    applied: u64,
}

impl DeferredSupervisionActivity {
    fn note_claim(&mut self) {
        self.claims = self.claims.saturating_add(1);
    }

    fn note_applied(&mut self) {
        self.applied = self.applied.saturating_add(1);
    }

    fn clear(&mut self) {
        self.claims = 0;
        self.applied = 0;
    }
}

struct HealthHeartbeatCompletion {
    result: Result<(), String>,
    supervision_progress: Option<eliotd::SupervisionProgressProducer>,
    failure_guard: RepeatedFailureGuard,
}

struct HealthHeartbeatFlightState {
    future: Pin<Box<dyn std::future::Future<Output = HealthHeartbeatCompletion>>>,
    owns_supervision_producer: bool,
}

/// Sole owner of the one heartbeat tick currently in progress. The future
/// carries the single supervision producer across Kernel awaits and returns it
/// exactly once at settlement.
enum HealthHeartbeatFlight {
    Idle,
    InFlight(HealthHeartbeatFlightState),
}

impl HealthHeartbeatFlight {
    fn owns_supervision_producer(&self) -> bool {
        matches!(
            self,
            Self::InFlight(HealthHeartbeatFlightState {
                owns_supervision_producer: true,
                ..
            })
        )
    }
}

/// Explicit loop exit so a shutdown that races an in-flight submit is never
/// silently dropped. `ShutdownActivationUnknown` carries the original
/// ticket/result identity verbatim; it is a local outcome only, not a
/// protocol change.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RunLoopExit {
    Shutdown,
    ShutdownActivationUnknown {
        ticket_id: String,
        result_sha256: String,
        detail: String,
    },
}

/// Typed dispatch failure so the shutdown drain can distinguish an ambiguous
/// submit (unknown retention, original identity preserved) from a hard
/// fail-closed error. Local only; no protocol change.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ActivationDispatchError {
    Hard(String),
    /// Kernel linearized a result-less deadline expiry. The daemon retires
    /// this ticket without retrying or attempting reconciliation.
    Expired,
    Unknown {
        ticket_id: String,
        result_sha256: String,
        detail: String,
    },
}

/// Retained identity for an in-flight dispatch. Cloned verbatim from the
/// single resolved result; never recomputed and never re-resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RetainedActivationIdentity {
    ticket_id: String,
    result_sha256: String,
}

/// Completion of one in-flight activation step. Claim, resolve-wait and
/// dispatch share one flight branch so health and shutdown stay pollable
/// while any of them is outstanding. The resolve wait lives inside this
/// polled flight (issue #2559): the completion handler only installs the
/// next future and returns to `select!`, never awaiting a lock or another
/// flight there.
enum ActivationCompletion {
    Claim(Result<ActivationClaim, String>),
    Resolve(Result<Option<Box<ActivationResolvedTicket>>, String>),
    Dispatch(Result<(), ActivationDispatchError>),
}

/// One resolved ticket waiting for its submit step. Produced once by the
/// resolve-wait flight; the dispatch step reuses it verbatim and never
/// re-resolves, so a lost acknowledgement reconciles under the same
/// identity instead of invoking the resolver again.
struct ActivationResolvedTicket {
    ticket: AgentActivationResolutionTicket,
    result: AgentActivationResolutionResult,
    /// Issue #1115: the semantic Governor binding combined with the P-07
    /// revision/digest, both captured before this flight was published. The
    /// submit path reuses this pair verbatim and never performs a second
    /// Governor read; a negative disposition carries no pair at all.
    owner_readback: Option<AgentActivationOwnerReadback>,
}

struct ActivationFlightState {
    future: Pin<Box<dyn std::future::Future<Output = ActivationCompletion>>>,
    retained: Option<RetainedActivationIdentity>,
}

/// Sole owner of activation state in `run_loop`. `Idle` means no activation
/// work is outstanding; `InFlight` holds the one pending step. No second
/// owner and no second concurrent activation exist.
enum ActivationFlight {
    Idle,
    InFlight(ActivationFlightState),
}

/// Pure tick gate: the activation timer starts work only when the flight is
/// idle. The in-flight future is polled in its own `select!` branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationTickDecision {
    StartClaim,
    SkipInFlight,
}

fn decide_activation_tick(flight: &ActivationFlight) -> ActivationTickDecision {
    match flight {
        ActivationFlight::Idle => ActivationTickDecision::StartClaim,
        ActivationFlight::InFlight(_) => ActivationTickDecision::SkipInFlight,
    }
}

/// Starts one activation ticket claim step on the shared tick.
///
/// The daemon reads its current named dependency discriminator before the
/// claim request. Kernel uses that authenticated observation to keep a
/// `NotReady` successor in Pending until due time and a changed discriminator
/// are both present; lease expiry alone cannot cross this gate.
fn start_activation_claim(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
) -> Pin<Box<dyn std::future::Future<Output = ActivationCompletion>>> {
    let kernel_clone = Arc::clone(kernel);
    let composition_clone = Arc::clone(composition);
    Box::pin(async move {
        let dependency_revision = {
            let guard = composition_clone.lock().await;
            guard.activation_dependency_revision()
        };
        let outcome: Result<ActivationClaim, String> = kernel_clone
            .claim_agent_activation_ticket(&dependency_revision)
            .await
            .map_err(|error| format!("Kernel activation ticket claim: {error}"));
        ActivationCompletion::Claim(outcome)
    })
}

/// Polls the one in-flight activation step, pending forever while idle so
/// health and shutdown stay pollable with no step outstanding. Claim,
/// resolve-wait and dispatch all ride this one branch.
async fn next_activation_completion(flight: &mut ActivationFlight) -> ActivationCompletion {
    match flight {
        ActivationFlight::Idle => std::future::pending::<ActivationCompletion>().await,
        ActivationFlight::InFlight(state) => (&mut state.future).await,
    }
}

/// Installs the resolve-wait flight for one validated ticket and returns
/// immediately to `select!` (issue #2559). The composition lock wait and the
/// clock read live inside that polled flight, so a suspended local-read,
/// `Skill`, `TestD` or owner-feed step holding the lock keeps being polled
/// while this one queues. No drain-before-lock workaround: the `TestD` drain
/// is its own independently polled flight with short guarded phases.
fn install_activation_resolve(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    flight: &mut ActivationFlight,
    ticket: AgentActivationResolutionTicket,
) {
    *flight = ActivationFlight::InFlight(ActivationFlightState {
        future: start_activation_resolve(Arc::clone(kernel), Arc::clone(composition), ticket),
        retained: None,
    });
}

/// Starts the resolve-wait step for one validated ticket. The returned future
/// captures the P-07 owner projection, acquires the composition guard, reads
/// the clock after that wait and immediately before resolution, then resolves
/// once through the v2 spine.
///
/// Issue #1115: the P-07 readback is taken *before* the guard is acquired, so
/// a rotation after that read is refused by Kernel at Session publication
/// rather than being silently re-read under the semantic lock. A readback
/// failure is carried into the resolve step rather than raised here, so a
/// negative disposition stays independently reportable.
fn start_activation_resolve(
    kernel: Arc<DaemonKernelClient>,
    composition: SharedComposition,
    ticket: AgentActivationResolutionTicket,
) -> Pin<Box<dyn std::future::Future<Output = ActivationCompletion>>> {
    Box::pin(async move {
        let kernel_owner = kernel
            .query_owner_bundle_readback()
            .await
            .map_err(|error| error.to_string());
        let guard = composition.lock().await;
        let now = match unix_ms(SystemTime::now()) {
            Ok(now) => now,
            Err(error) => return ActivationCompletion::Resolve(Err(error)),
        };
        ActivationCompletion::Resolve(resolve_valid_ticket(&guard, kernel_owner, ticket, now))
    })
}

/// Settles one completed resolve-wait step: Kernel-owned expiry idles the
/// flight with no resolve and no submit, otherwise the dispatch step starts
/// carrying the retained result identity for submission/reconciliation.
fn settle_activation_resolve_completion(
    kernel: &Arc<DaemonKernelClient>,
    flight: &mut ActivationFlight,
    outcome: Result<Option<Box<ActivationResolvedTicket>>, String>,
) -> Result<(), String> {
    match outcome {
        Err(error) => Err(error),
        Ok(None) => {
            *flight = ActivationFlight::Idle;
            Ok(())
        }
        Ok(Some(resolved)) => {
            *flight = ActivationFlight::InFlight(start_activation_dispatch(kernel, *resolved));
            Ok(())
        }
    }
}

/// Settles one invalid activation claim (issue #202, owner decision ii).
///
/// Constructs the terminal artifact with no Governor read. The caller idles
/// the flight and continues the loop: no typed-result submit, no reconcile
/// of typed results, no retry of the rejected revision.
fn settle_invalid_claim(ticket_bytes: Vec<u8>, reason: &str) -> Result<(), String> {
    let now = unix_ms(SystemTime::now())?;
    let artifact = terminal_for_invalid_ticket(ticket_bytes, reason, now.max(1))
        .map_err(|error| format!("daemon invalid ticket terminal: {error}"))?;
    debug_assert!(artifact.is_terminal());
    let _ = eliotd::diagnostics::ErrorRecord::of(
        eliotd::diagnostics::OwningComponent::DaemonRuntime,
        "invalid-ticket",
        reason,
    )
    .emit();
    Ok(())
}

/// Settled outcome of one local-read poll step (Implements #18: the eliotd
/// half of the outbound-only `local_read_claim` / `local_read_result`
/// poller). `IdleBackoff` is the null poll (empty queue, or every pair
/// expired); `Accepted` / `Expired` / `StaleAttempt` mirror the typed submit
/// outcome. A stale attempt idles like expiry: the quarantined capability is
/// never retried, and the next tick claims the current generation anew.
enum LocalReadPollOutcome {
    IdleBackoff,
    Accepted,
    Expired,
    StaleAttempt,
}

/// Completion of one in-flight local-read step. Claim, forward, and submit
/// share one flight branch so health and shutdown stay pollable while the
/// step is outstanding; the step handles at most one pair per tick.
enum LocalReadCompletion {
    Settled(Result<LocalReadStep, String>),
}

/// What one settled local-read step produced.
///
/// #2647: the step returns its poll outcome plus at most one bounded readiness
/// delta — only the observation this flight's own attach or re-read actually
/// produced. An empty claim or an ordinary read with no refresh carries no
/// delta, so settling it cannot overwrite newer owner observations the loop
/// recorded while the flight was outstanding. There is no second owner and no
/// shared handle.
struct LocalReadStep {
    /// The poll outcome the loop acts on.
    outcome: LocalReadPollOutcome,
    /// The readiness observation this flight produced, if any.
    delta: Option<LocalReadinessDelta>,
}

struct LocalReadFlightState {
    future: Pin<Box<dyn std::future::Future<Output = LocalReadCompletion>>>,
}

/// Sole owner of local-read poll state in `run_loop`, mirroring
/// [`ActivationFlight`]. `Idle` means no local-read work is outstanding;
/// `InFlight` holds the one pending poll step. No second owner and no second
/// concurrent local-read step exist.
enum LocalReadFlight {
    Idle,
    InFlight(LocalReadFlightState),
}

/// Pure tick gate: the local-read timer starts work only when the flight is
/// idle. The in-flight step is polled in its own `select!` branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalReadTickDecision {
    StartPoll,
    SkipInFlight,
}

fn decide_local_read_tick(flight: &LocalReadFlight) -> LocalReadTickDecision {
    match flight {
        LocalReadFlight::Idle => LocalReadTickDecision::StartPoll,
        LocalReadFlight::InFlight(_) => LocalReadTickDecision::SkipInFlight,
    }
}

/// Settled outcome of one campaign-packet poll step. The packet flight owns
/// a distinct queue/attempt lifecycle and never shares a completion with the
/// query flight.
enum CampaignPacketPollOutcome {
    IdleBackoff,
    Accepted,
    Expired,
    StaleAttempt,
}

enum CampaignPacketCompletion {
    Settled(Result<CampaignPacketPollOutcome, String>),
}

struct CampaignPacketFlightState {
    future: Pin<Box<dyn std::future::Future<Output = CampaignPacketCompletion>>>,
}

enum CampaignPacketFlight {
    Idle,
    InFlight(CampaignPacketFlightState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CampaignPacketTickDecision {
    StartPoll,
    SkipInFlight,
}

fn decide_campaign_packet_tick(flight: &CampaignPacketFlight) -> CampaignPacketTickDecision {
    match flight {
        CampaignPacketFlight::Idle => CampaignPacketTickDecision::StartPoll,
        CampaignPacketFlight::InFlight(_) => CampaignPacketTickDecision::SkipInFlight,
    }
}

/// The published product-proof status for one acceptance item (issue #1903).
///
/// This is the wire view of the ProductProof/FinishService acceptance owner's
/// terminal record and its fail-closed rollup. It is a projection of those two
/// values: the disposition is the rollup's own verdict, and the remaining
/// fields repeat the record's outcome, reason, owner, authority, required
/// missing evidence, and retained build-evidence handle. The build handle is
/// present as non-product proof only, so a successful release build is never
/// read as a live pass.
#[derive(Debug, Serialize)]
pub(super) struct ProductProofStatusWire {
    /// Acceptance item this status describes.
    pub(super) proof_id: String,
    /// Product-proof contract identity the record carries.
    pub(super) contract: String,
    /// Exact I18.24 outcome observed for the required product property.
    pub(super) outcome: eliot_instrument_api::VerificationOutcome,
    /// `pass` or `refused`, taken verbatim from the owner's fail-closed rollup.
    pub(super) disposition: String,
    /// Factual reason for that outcome.
    pub(super) reason: String,
    /// Acceptance owner accountable for the proof.
    pub(super) owner: String,
    /// Authority that imposed the stop condition.
    pub(super) authority_ref: String,
    /// Required evidence that is still absent, in canonical order.
    pub(super) missing_evidence: Vec<String>,
    /// Retained build evidence, explicitly not a product outcome.
    pub(super) build_evidence_id: Option<String>,
    /// Whether the required installed-route execution was observed.
    pub(super) installed_route_observed: bool,
}

impl ProductProofStatusWire {
    /// Projects the owner's record and its own rollup onto the status surface.
    ///
    /// The disposition is read from the rollup the owner produced, not decided
    /// here, so a second verdict cannot exist: this function cannot turn a
    /// refused record into a pass. A refused record still publishes, because
    /// the current product state *is* a refusal — an operator must be able to
    /// read the exact outcome, reason, owner, authority, and required missing
    /// evidence without the record ever becoming a pass.
    fn project(
        status: &eliot_reports::product_proof::ProductProofStatus,
        rollup: &eliot_reports::product_proof::ProductProofRollup,
    ) -> Self {
        Self {
            proof_id: status.proof_id.clone(),
            contract: status.contract.clone(),
            outcome: status.outcome,
            disposition: match rollup {
                eliot_reports::product_proof::ProductProofRollup::Pass { .. } => "pass",
                eliot_reports::product_proof::ProductProofRollup::Refused { .. } => "refused",
            }
            .to_owned(),
            reason: status.reason.clone(),
            owner: status.authority.owner.clone(),
            authority_ref: status.authority.authority_ref.clone(),
            missing_evidence: status.missing_evidence.clone(),
            build_evidence_id: status
                .build_evidence
                .as_ref()
                .map(|build| build.evidence.evidence_id.clone()),
            installed_route_observed: status.retained.installed_route_observed(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum ReadyMessage {
    /// Full daemon readiness was admitted by Kernel after Governor recovery.
    Ready {
        service: &'static str,
        protocol: &'static str,
        generation: u64,
        authority_epoch: u64,
        health: String,
        degraded: bool,
        /// Issue #1903: the terminal product-proof status for the parked
        /// Windows acceptance item, as the ProductProof/FinishService owner
        /// built it from its real stage receipts. It is published on the live
        /// daemon status surface so an operator reads the current product
        /// status here instead of from a type that has no consumer. The
        /// rollup is fail-closed: it reports `Pass` only when the record
        /// validated and its required installed-route execution was actually
        /// observed, and otherwise carries the exact outcome, reason, and
        /// authority. This field is additive; a reader that ignores it keeps
        /// the previous meaning of this message exactly. It is absent only
        /// when the acceptance owner refused to build a record at all, which
        /// is a recorded absence rather than a fabricated verdict.
        #[serde(skip_serializing_if = "Option::is_none")]
        product_proof: Option<ProductProofStatusWire>,
    },
    /// Kernel health degraded while the daemon remains observable.
    Degraded {
        service: &'static str,
        protocol: &'static str,
        reason: String,
    },
    /// Kernel accepted a daemon fatal disposition and fenced the generation.
    Fatal {
        service: &'static str,
        protocol: &'static str,
        reason: String,
    },
    /// Startup or shutdown failed closed.
    Error {
        service: &'static str,
        protocol: &'static str,
        error: String,
    },
}

#[expect(
    clippy::too_many_lines,
    reason = "ordered daemon launch funnel stays in one audit scope: args, protected config, metrics, capabilities, loop (#838)"
)]
pub(super) fn run() -> Result<(), String> {
    let launch = parse_launch_args(std::env::args_os().skip(1))?;
    let config = DaemonConfig::load_protected_bound(
        launch.config_path,
        &launch.config_sha256,
        &launch.launch_nonce,
        &launch.executable_sha256,
    )
    .map_err(|error| error.to_string())?;
    // I16.2/I16.5 (issue #1841): install the bounded-label OpenMetrics stack
    // and publish the local scrape surface. Best-effort by contract (A13.10):
    // a refused configuration is reported and the launch funnel continues, so
    // telemetry can never become a reason the daemon refuses to run. The
    // install is placed after the protected launch descriptor is known,
    // because the installation profile is that admitted contour and not an
    // inference. The Host launch contour carries no scrape address, so none is
    // admitted and the install reports an absent endpoint rather than
    // inventing a port.
    match eliotd::execution_metrics::install_daemon_execution_metrics(&config, None) {
        Ok(observability) => {
            observability.publish_runtime_counters();
            tracing::info!(
                target: "eliotd::diagnostics",
                event = "eliotd.metrics_installed",
                endpoint = observability.describe(),
            );
        }
        Err(error) => {
            tracing::warn!(
                target: "eliotd::diagnostics",
                event = "eliotd.metrics_install_refused",
                reason = error.to_string(),
            );
        }
    }
    // I3.9: the load above already resolved and enforced the effective canonical
    // configuration — a script, an untyped document, or a lower-layer expansion
    // that no higher layer delegated returns `Err` there, so this line is
    // reachable only with a resolved chain. It publishes the inspection answer
    // for the one proven setting chain: the winning value and every contributing
    // layer in canonical precedence order. It gates nothing and grants nothing;
    // the refusal is the config load, not this record.
    let canonical = config.canonical_chain();
    tracing::info!(
        target: "eliotd::diagnostics",
        event = "eliotd.canonical_config_effective",
        key = canonical.key(),
        winning_value = canonical.winning_value(),
        contributing_layers = ?canonical.contributions(),
    );
    // I3.9 (#1966 W4): publish the generated schema for the supported
    // TOML/JSON layer files on the same diagnostics surface. The text is
    // generated at runtime from the single typed shape the decoders enforce,
    // so it cannot rot relative to them. Diagnostics only: it gates nothing
    // and grants nothing.
    tracing::info!(
        target: "eliotd::diagnostics",
        event = "eliotd.canonical_layer_schema_published",
        schema = eliotd::canonical_layer_json_schema_pretty(),
    );
    let kernel = DaemonKernelClient::connect(&config).map_err(|error| error.to_string())?;
    let authority_activation = eliotd::kernel_authority_port(&kernel);
    let mut composition = DaemonComposition::start(
        config,
        Arc::clone(&kernel) as Arc<dyn eliot_governor::KernelGenerationPort>,
        Some(authority_activation),
    )
    .map_err(|error| error.to_string())?;
    // #18 item A: bind the seven declared startup capabilities and record one
    // explicit disposition for each. The returned ledger — not control flow —
    // decides what this generation observed.
    let bindings = bind_declared_startup_capabilities(&kernel, &mut composition);
    // #1773 (I3.4, W2): immediately after the complete paged drain above, apply
    // and COMMIT the dependency change the Host admitted about this daemon's own
    // served bytes. This is the step that makes a restriction durable: an
    // in-process invalidation is erased by a restart, after which the evidence
    // it limited can be re-admitted. It is placed here, before the composition is
    // shared, because the commit is an async Kernel exchange and this is the last
    // point at which the composition can be borrowed exclusively.
    commit_installation_scope_restriction(&mut composition, &launch.executable_sha256);
    // #1145: report the Governor-owned improvement pipeline owner at startup
    // (diagnostics only), keeping the owner identity observable without adding
    // policy semantics to the composition root.
    //
    // Measured at #2703: this is a DIAGNOSTIC REFERENCE ONLY. It is not a
    // dispatch site. No live request reaches `govern_improvement_candidate`,
    // because `ImprovementRouteRequest` is never constructed anywhere in
    // `bins/` or `crates/`, and the candidate → experiment → evaluation →
    // admission path is therefore not yet served by this daemon. The typed
    // result mapping behind it is exhaustive and correct; what is missing is a
    // request source, which is owner scope for #1145, not for this diagnostic.
    // Do not read this line as evidence that the route is wired.
    tracing::info!(
        target: "eliotd::diagnostics",
        event = "eliotd.improvement_pipeline_owner",
        owner = eliotd::governed_improvement_pipeline_owner(),
    );
    // #1693 (I14.22:34): publish the registered maintenance-family catalog once
    // per process, here in the composition startup path. This is the one
    // production reader of `maintenance_family_catalog::entries`, and it is
    // placed on the composition startup contour rather than inside
    // `evaluate_maintenance_trigger` so the emission is once per process and
    // never per trigger. It performs no I/O, opens no store client, reads no
    // clock, consults no composition state, and returns nothing, so it cannot
    // delay or withhold startup or readiness. Do not read this line as the
    // durable record: A13.10 lines 5-9 class it as an operational log that may
    // rotate, and the durable record for a family that cannot start is the
    // canonical notification the blocked family submits through
    // `note_blocked_automation_notification` below.
    eliotd::maintenance_family_catalog::record_registered_catalog();
    // #2560: the retained ledger answers no readiness question. This projection
    // derives the required set from the composition's own live owners and keeps
    // core control readiness separate from optional capability availability, so
    // one failed optional attach degrades exactly the operations that name it
    // instead of withholding readiness for the whole daemon. It performs no IO
    // and starts nothing.
    let startup_readiness = StartupReadinessProjection::new(bindings, &composition);
    // #1688/#1693 (I14.22): retain the two real startup observations for the
    // run-loop maintenance flight. The flight evaluates them after the daemon
    // has published its ready projection, does no startup/readiness gating,
    // and submits any unavailable-family decision through the canonical
    // notification path using only the composition's admitted fence.
    let startup_maintenance_observations = [
        maintenance_observation(
            MaintenanceTriggerOrigin::StartupReconciliation,
            &[startup_readiness.ledger_report()],
            false,
        ),
        maintenance_observation(
            MaintenanceTriggerOrigin::ColdStartCompletion,
            &[
                format!(
                    "startup_bindings_complete={}",
                    startup_readiness.every_declared_capability_bound()
                ),
                startup_readiness.report(),
            ],
            false,
        ),
    ];
    // Issue #88, wave 3: the ready answer carries the once-per-generation
    // supervision bundle. The per-tick producer below cites it verbatim; the
    // Kernel re-verifies every echoed field on each submit.
    //
    // #18 item A: `report_ready` sends the Kernel `daemon_ready` operation, so
    // reaching it on an unadmitted composition would claim a Governor
    // readiness the daemon does not have.
    //
    // #2560: the gate is now the core readiness prerequisites — the composition's
    // own owner set, generation/fence and recovery preconditions plus the
    // mandatory capability set — and not "all seven optional slots bound". A
    // failed notification/Dreamer/Skill attach therefore no longer withholds
    // supervision for the whole daemon; it degrades exactly the operations that
    // name that capability. When a core prerequisite is missing there is no
    // `daemon_ready` answer, so no supervision bundle exists: its lineage and
    // lease head are Kernel-authored and are never invented here. The daemon
    // stays alive, observable, and running, and renews no supervision progress
    // until a later pass satisfies the core prerequisites. The producer is still
    // built once per generation, from the validated ready response and the real
    // owner session only.
    let supervision_progress = if startup_readiness
        .core_readiness_prerequisites_satisfied()
        .is_satisfied()
    {
        let ready_supervision = kernel.report_ready().map_err(|error| error.to_string())?;
        let session_facts = kernel.owner_session_facts().ok_or_else(|| {
            "daemon has no validated Kernel session binding for supervision progress".to_owned()
        })?;
        Some(
            eliotd::SupervisionProgressProducer::new(eliotd::SupervisionProducerDeps {
                daemon_artifact_id: format!("eliotd-exe:{}", launch.executable_sha256),
                daemon_config_digest: launch.config_sha256.clone(),
                launch_nonce: launch.launch_nonce.clone(),
                process_pid: std::process::id(),
                transport_session_evidence: session_facts.session_binding().to_owned(),
                transport_connection_evidence: session_facts.connection_id().to_owned(),
                ready: ready_supervision,
            })
            .map_err(|error| format!("daemon supervision producer: {error}"))?,
        )
    } else {
        None
    };
    // The local-read poller below drives Skill pairs through the composition
    // inside its flight future: share it here so the future owns its handle.
    // All pre-loop exclusive uses are complete; shutdown unwraps below.
    let composition = Arc::new(composition);
    // I1.11 steps 8/9 (issue #1967): publish Governor startup evidence on
    // the authenticated daemon channel for the Kernel consumer. The producer
    // evaluates live retained records only — transport binding, admitted and
    // observed fences, the Config mirror pair, and the retained Governor
    // capability model (holding/restricted/unevaluated partition returned
    // for the readiness record); values whose owners do
    // not exist yet stay missing and yield explicit not-ready evidence
    // instead of a ready claim. Publish failure never fails the daemon: the
    // step-7 live-receipt path above is unchanged and the Kernel keeps steps
    // 8/9 fenced until its consumer lands. No thread, no transport, no
    // start() contour or run-loop change. The returned retained-model
    // evaluation feeds the readiness record below.
    let capability_summary =
        eliotd::startup_evidence_producer::publish_daemon_startup_evidence(&kernel, &composition);
    // #740: readiness record. Handshake (connect) and readiness (recovery +
    // attach gates passed, Kernel accepted ready) stay distinct events.
    let _startup_span = tracing::info_span!("eliotd.daemon_start").entered();
    // I1.11 step 9: restricted skills in the retained capability model become
    // visible degradation on the readiness record (the publish above already
    // warned with the partition).
    //
    // #18 item A: the reported readiness is the composition's computed
    // readiness ANDed with the declared binding ledger, never a literal.
    //
    // #2560: that AND is now split. Core control readiness is the composition's
    // own owner state plus the mandatory capability set; optional capability
    // availability is a separate, visible fact. So a ready generation with one
    // degraded optional capability reports `ready` with `degraded`/`degraded`
    // and the exact per-slot reason, while a missing owner session, a stale view
    // or unresolved recovery still withholds ready and effects regardless of
    // how many optional descriptors are present. `DaemonStatus` keeps its exact
    // wire shape.
    let composition_status = composition.status();
    // #2560: core control readiness is the composition's own owner state plus
    // the mandatory capability set; optional availability is a separate, visible
    // fact. A ready generation with a degraded optional capability reports ready
    // with degraded health and the exact per-slot reason, while a missing owner
    // session, a stale view or unresolved recovery still withholds ready and
    // effects however many optional descriptors are present. `DaemonStatus` keeps
    // its exact wire shape.
    let readiness = eliotd::startup_readiness::evaluate_startup_readiness(
        &startup_readiness,
        &composition_status,
        capability_summary.has_restrictions(),
    );
    // #2560: the same evaluation that produced the ready/degraded record reaches
    // diagnostics, so stdout, diagnostics and dispatch cannot disagree.
    eliotd::startup_readiness::emit_startup_readiness_record(&startup_readiness, &readiness);
    let status = DaemonStatus {
        ready: readiness.ready,
        degraded: readiness.degraded,
        health: readiness.health,
        ..composition_status
    };
    let _ = eliotd::diagnostics::emit_daemon_readiness(status.ready, status.degraded);
    // Issue #1903: the composition's ProductProof/FinishService acceptance
    // owner constructs the terminal product-proof record for the parked
    // Windows acceptance item and this publishes its fail-closed rollup on the
    // live daemon status surface. The record is built by that owner from the
    // launch descriptor this daemon is actually running under and the stage
    // receipts it actually holds, so a refused record publishes its exact
    // outcome, reason, owner, authority, and required missing evidence rather
    // than a pass. Building it never fails the daemon: a record the owner
    // refuses leaves the field absent, which is a recorded absence rather than
    // a fabricated verdict, and readiness, protocol framing, and exit behavior
    // are unchanged.
    let product_proof = match composition.product_proof_status() {
        Ok((record, rollup)) => Some(ProductProofStatusWire::project(&record, &rollup)),
        Err(error) => {
            tracing::warn!(target: "eliotd::diagnostics", "product proof status unavailable: {error}");
            None
        }
    };
    write_json(&ready_message(&status, product_proof))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    // The run loop is the only writer of the composition (TestD owner
    // finish drain); readers lock briefly per step. Wrap here: every
    // pre-loop exclusive use above is complete.
    let composition = SharedComposition::new(tokio::sync::Mutex::new(
        Arc::try_unwrap(composition)
            .map_err(|_| "daemon composition shared before run loop".to_owned())?,
    ));
    let loop_result = runtime.block_on(run_loop(
        Arc::clone(&kernel),
        Arc::clone(&composition),
        supervision_progress,
        startup_readiness,
        startup_maintenance_observations,
    ));
    // The loop dropped its handle on return, so this unwrap is deterministic;
    // the error arm documents the invariant instead of panicking on it.
    let shutdown_result = Arc::try_unwrap(composition)
        .map_err(|_| "daemon composition still shared at shutdown".to_owned())?
        .into_inner()
        .shutdown()
        .map_err(|error| error.to_string());
    // #740: shutdown disposition record. The terminal-failure reports below
    // keep their exact existing behavior; this only names the disposition.
    let final_result = match (loop_result, shutdown_result) {
        (Ok(RunLoopExit::Shutdown), Ok(())) => Ok(()),
        (
            Ok(RunLoopExit::ShutdownActivationUnknown {
                ticket_id,
                result_sha256,
                detail,
            }),
            Ok(()),
        ) => Err(report_terminal_failure(
            &kernel,
            format!(
                "daemon shutdown with activation submit unknown ticket {ticket_id} result {result_sha256}: {detail}"
            ),
        )),
        (Ok(RunLoopExit::Shutdown), Err(error)) | (Err(error), Ok(())) => {
            Err(report_terminal_failure(&kernel, error))
        }
        (
            Ok(RunLoopExit::ShutdownActivationUnknown {
                ticket_id,
                result_sha256,
                detail,
            }),
            Err(shutdown_error),
        ) => Err(report_terminal_failure(
            &kernel,
            format!(
                "daemon shutdown with activation submit unknown ticket {ticket_id} result {result_sha256}: {detail}; shutdown: {shutdown_error}"
            ),
        )),
        (Err(error), Err(shutdown_error)) => Err(report_terminal_failure(
            &kernel,
            format!("{error}; shutdown: {shutdown_error}"),
        )),
    };
    match &final_result {
        Ok(()) => {
            let _ = eliotd::diagnostics::emit_shutdown(
                eliotd::diagnostics::ShutdownOutcome::Clean,
                "daemon shutdown completed",
            );
        }
        Err(error) => {
            let outcome = if error.contains("unknown ticket") {
                eliotd::diagnostics::ShutdownOutcome::WithActivationUnknown
            } else {
                eliotd::diagnostics::ShutdownOutcome::WithError
            };
            let _ = eliotd::diagnostics::emit_shutdown(outcome, error);
        }
    }
    final_result
}

/// Binds the seven declared startup capabilities and records one explicit
/// disposition for each (#18 item A).
///
/// This is the single place holding both the concrete Kernel client and the
/// composition, and it runs the seven startup attach sites in declaration
/// order. Each site yields either the exact admitted identity/descriptor it
/// produced — retained by the returned ledger for the lifetime of the process
/// — or the exact reason it did not bind. No attach propagates with `?`: an
/// unbound capability keeps the daemon alive and observable while withholding
/// readiness, so a degraded optional surface can never remove the process.
fn bind_declared_startup_capabilities(
    kernel: &Arc<DaemonKernelClient>,
    composition: &mut DaemonComposition,
) -> StartupCapabilityBindings {
    // AUD-C02-B: the single place holding both the concrete client and the
    // composition. Push the already-validated Kernel-issued owner session
    // facts (if a handshake validated them) into the composition via the one
    // setter. No new thread, no new handshake, no storing the client; without
    // facts the composition keeps the empty (unadmitted) board behaviour and
    // the capability records why it did not bind.
    let owner_session_binding = match kernel.owner_session_facts() {
        Some(facts) => {
            let retained = RetainedStartupBinding::OwnerSession {
                session_binding: facts.session_binding().to_owned(),
                connection_id: facts.connection_id().to_owned(),
            };
            composition.note_owner_session_binding(facts);
            Ok(retained)
        }
        None => Err("Kernel handshake validated no owner session binding".to_owned()),
    };
    // #1780: attach canonical notification records where the concrete
    // client and the composition meet (same site as the owner-session
    // facts above). A cold/unbound read degrades to the empty inbox with
    // an error record exactly like the skill-tool-source path below: it
    // emits diagnostics and the daemon continues, never failing readiness
    // for an unreadable inbox.
    let notification_snapshot =
        match eliotd::notification_board_attach::attach_notification_snapshot(kernel, composition) {
            eliotd::notification_board_attach::NotificationBoardAttach::Ready(snapshot) => {
                tracing::info!(
                    target: "eliotd::diagnostics",
                    event = "eliotd.notification_snapshot_attached",
                    record_count = snapshot.records.len(),
                );
                Ok(RetainedStartupBinding::NotificationSnapshot {
                    record_count: snapshot.records.len(),
                })
            }
            eliotd::notification_board_attach::NotificationBoardAttach::Unavailable { reason } => {
                Err(reason)
            }
        };
    // T12-06: gated Dreamer intake registration at the same attach site. The
    // readiness-gated accessor plus the fence-bound route-context check prove
    // the intake wiring before readiness is reported; no thread, no transport,
    // no start() contour or run-loop change. The admitted route context is
    // retained by the ledger instead of being dropped here.
    let dreamer_intake = attach_dreamer_intake(composition, kernel);
    // T12-07: gated Dreamer model-call registration at the same attach site. The
    // readiness-gated accessor plus the fence-bound model route-context check prove
    // the model wiring before readiness is reported; no thread, no transport, no
    // provider credentials, no start() contour or run-loop change.
    let dreamer_model = attach_dreamer_model(composition);
    // #872: gated agent-fabric registration at the same attach site. The
    // readiness-gated descriptor proves the admitted ingress reaches the
    // durable swarm-control composition before readiness is reported; no
    // thread, no transport, no start() contour or run-loop change. The
    // admitted descriptor is retained by the ledger.
    let agent_fabric = attach_agent_fabric(composition);
    // #1882: the two declared Skill-path capabilities, in declaration order.
    let (skill_tool_source, skill_tool_basis) = bind_skill_path_capabilities(composition);
    // #1773 (I3.4): rebuild the daemon-held Governor capability admission view
    // from the durable capability-evidence records, at the same attach site that
    // already holds the concrete client and the mutable composition, and before
    // `publish_daemon_startup_evidence` evaluates the retained capability model
    // below. This is the production seam that makes a qualifying record survive
    // a daemon restart: without it the view stays empty and every production
    // route is refused for lack of evidence.
    //
    // The drain is complete and fail-closed, so a partial read is never
    // reported as coverage; a refusal keeps the view as it was, which means
    // any route it cannot evidence stays refused.
    hydrate_capability_evidence_view(composition, kernel);
    // The retained ledger is the only readiness input for the declared
    // capabilities: it cannot be constructed without a disposition for each of
    // the seven, and the whole record (bound identity or unbound reason) is
    // emitted once so the retained evidence is observable, not dropped.
    record_startup_bindings(
        owner_session_binding,
        notification_snapshot,
        dreamer_intake,
        dreamer_model,
        agent_fabric,
        skill_tool_source,
        skill_tool_basis,
    )
}

/// Drains the durable capability-evidence records into the daemon-held Governor
/// admission view at startup (issue #1773, I3.4).
///
/// This is the durable-hydration production seam. The view is otherwise
/// constructed empty, so before this drain every production route is refused
/// for lack of evidence and no record survives a restart. It runs at the
/// existing startup attach site that already holds the concrete Kernel client
/// and the mutable composition — no new thread, no new transport, no new
/// `start()` contour, and no run-loop change; the read travels the one
/// authenticated Kernel named-read route.
///
/// Fail-closed: the drain either covers every page the store serves at this
/// fence or returns an error, and an error is a `warn` diagnostic naming the
/// exact reason. The view then keeps its previous contents, so any production
/// route the view cannot evidence stays refused rather than being treated as
/// "nothing to check".
fn hydrate_capability_evidence_view(
    composition: &mut DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
) {
    let fence = composition.kernel_snapshot().state_fence();
    let scope = match eliot_store_api::ScopeId::new(eliot_governor::GOVERNOR_SCOPE_ID) {
        Ok(scope) => scope,
        Err(error) => {
            tracing::warn!(
                target: "eliotd::capability_evidence",
                event = "eliotd.capability_evidence_hydration_unavailable",
                reason = %error,
                "canonical capability evidence could not be addressed; the admission view keeps its previous contents and any production route it cannot evidence stays refused"
            );
            return;
        }
    };
    let drained = composition
        .capability_admission_mut()
        .map_err(|error| error.to_string())
        .and_then(|view| {
            eliotd::drain_capability_evidence_records(
                view,
                kernel,
                &scope,
                &fence,
                eliot_store_api::MAX_CAPABILITY_EVIDENCE_PAGE_RECORDS,
            )
            .map_err(|error| error.to_string())
        });
    match drained {
        Ok(report) => {
            tracing::info!(
                target: "eliotd::capability_evidence",
                event = "eliotd.capability_evidence_hydrated",
                pages = report.pages,
                observed_records = report.observed_records,
                minted_records = report.minted_records,
                retained_records = report.retained,
                "durable capability evidence rebuilt the Governor admission view through the complete paged read"
            );
        }
        Err(reason) => {
            tracing::warn!(
                target: "eliotd::capability_evidence",
                event = "eliotd.capability_evidence_hydration_unavailable",
                reason = %reason,
                "canonical capability evidence did not refresh the admission view; the view keeps its previous contents and any production route it cannot evidence stays refused"
            );
        }
    }
}

/// The daemon's OWN admitted installation scope, and the only dependency
/// selector built from it (issue #1773, I3.4, W2).
///
/// `executable_sha256` is the digest the Host admitted on the launch contour:
/// the exact 8-value descriptor binding requires the literal
/// `--executable-sha256` flag (`parse_launch_args`), `DaemonConfig::load_protected_bound`
/// validates it, and the same value already names this process's artifact
/// (`eliotd-exe:<digest>`). It is therefore the one fact the daemon can attest
/// to about its own runtime instance and its own integration implementation, and
/// it is bound to both of exactly those two `RouteScopeFingerprint` dimensions.
///
/// Every other dimension stays `None`, i.e. UNKNOWN, never inferred. The
/// requested provider/model/auth/billing route is not observable from this
/// process, and I3.4 is explicit that an unexposed field is `unknown` and must
/// not be back-filled from a UI selection or prompt text. The daemon asserts
/// what it observed about itself and nothing else.
fn observed_installation_scope(executable_sha256: &str) -> eliot_governor::RouteScopeFingerprint {
    let artifact = format!("eliotd-exe:{executable_sha256}");
    eliot_governor::RouteScopeFingerprint {
        runtime_hash: Some(artifact.clone()),
        adapter_hash: Some(artifact),
        ..eliot_governor::RouteScopeFingerprint::default()
    }
}

/// Applies the installation-scope dependency change to the drained admission
/// view and commits every record it limited (issue #1773, I3.4, W2).
///
/// **The selector is narrow by construction, and that is the point.**
/// `ScopeDependencySelector::all()` is exactly the trap this repository already
/// recorded: a record is staled when it DIFFERS from `current` on a selected
/// dimension, so selecting every dimension against a single observed scope
/// invalidates every other route's and account's still-valid evidence, on every
/// call, permanently. Here the selector names only `runtime_hash` and
/// `adapter_hash` — the two dimensions the Host admitted about THIS process.
///
/// **The exact predicate, so the retained case is not over-claimed.** With this
/// selector `ScopeDependencySelector::selects_difference` reduces to
/// `record.runtime_hash != observed.runtime_hash
/// || record.adapter_hash != observed.adapter_hash`. So a record matching the
/// observed installation on BOTH dimensions is never staled, and no other
/// dimension — provider/model, serializer, auth profile, tool-call ordering —
/// can stale anything at all from this call site, which is what preserves
/// `is_fresh_positive_for`'s exact-match retention for every unrelated route. A
/// record that matches one dimension and differs on the other IS staled, and
/// that is correct rather than lossy: `is_fresh_positive_for` already demands
/// exact equality of the whole fingerprint, so such a record could never have
/// admitted the observed route, and this is exactly I3.4's "adapter change makes
/// dependent evidence stale".
///
/// A record that does differ is restricted, and the restriction is then COMMITTED
/// through the Governor's existing `RecordCapabilityEvidenceRecord` leg, so the
/// next restart re-derives it from the served
/// `limitations_and_negative_evidence` rather than from memory.
///
/// The step is a one-shot startup write on a composition that is still
/// exclusively owned here, so a current-thread runtime is built for exactly this
/// step — the same shape `DaemonKernelClient::blocking` already uses for its
/// one-shot exchanges. No thread, no transport, no `start()` contour or
/// run-loop change.
///
/// Fail-closed: a refused commit is a `warn` naming the exact reason and how far
/// it got. The in-process restriction the registry already applied REMAINS, so
/// this process keeps refusing the affected evidence; only its durability across
/// a restart is lost, and the diagnostic says so.
fn commit_installation_scope_restriction(
    composition: &mut DaemonComposition,
    executable_sha256: &str,
) {
    // A drain that failed left the view as it was, so there is nothing for the
    // change to narrow; the step then legitimately restricts nothing and the
    // log line below reports zero rather than claiming coverage.
    let observed = observed_installation_scope(executable_sha256);
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::warn!(
                target: "eliotd::capability_evidence",
                event = "eliotd.capability_evidence_restriction_unavailable",
                reason = %error,
                "the installation-scope restriction could not be committed; it remains in process only, so a restart would forget it while this process keeps refusing the restricted evidence"
            );
            return;
        }
    };
    let committed = runtime.block_on(composition.commit_scope_change_restriction(
        &observed,
        eliot_governor::ScopeDependencySelector {
            runtime_hash: true,
            adapter_hash: true,
            ..eliot_governor::ScopeDependencySelector::none()
        },
    ));
    match committed {
        Ok(report) if report.restricted > 0 => {
            tracing::info!(
                target: "eliotd::capability_evidence",
                event = "eliotd.capability_evidence_restriction_committed",
                restricted_records = report.restricted,
                committed_records = report.committed,
                change_ref = %report.blocking_evidence_ref,
                "a runtime/adapter change staled the dependent evidence and the restriction is now an owner-issued durable fact that survives a restart"
            );
        }
        Ok(_) => {
            tracing::info!(
                target: "eliotd::capability_evidence",
                event = "eliotd.capability_evidence_restriction_not_needed",
                "every retained evidence record already matches this installation's admitted runtime and adapter hashes; nothing was staled and nothing was written"
            );
        }
        Err(error) => {
            tracing::warn!(
                target: "eliotd::capability_evidence",
                event = "eliotd.capability_evidence_restriction_unavailable",
                reason = %error,
                "the installation-scope restriction was not committed; it remains in process only, so a restart would forget it while this process keeps refusing the restricted evidence"
            );
        }
    }
}

/// Binds the two declared Skill-path capabilities (#1882), in declaration
/// order: the canonical tool source, then the installed-Skill tool-basis
/// reconciliation against the live canonical tool view.
///
/// The tool-source proof builds the production canonical registry through the
/// Governor hook and pins the admitted definition version with no skill inputs
/// consumed and nothing delivered (I1.5 starts only admitted capabilities).
/// Reconciliation binds the reconciliation path into the startup sequence and
/// proves the live hook edge executes in the production binary; a fresh startup
/// catalogue is empty, so it marks nothing today, and once installs land it
/// marks entries whose tools left the canonical set so a restart never revives
/// a generally-delivered display for a removed tool. Skill delivery stays
/// optional (A2.3): a failure in either degrades only the skill path. No
/// thread, no transport, no `start()` contour or run-loop change.
fn bind_skill_path_capabilities(
    composition: &DaemonComposition,
) -> (
    Result<RetainedStartupBinding, String>,
    Result<RetainedStartupBinding, String>,
) {
    let skill_tool_source = attach_skill_tool_source().map(|admitted| {
        tracing::info!(
            target: "eliotd::diagnostics",
            event = "eliotd.skill_tool_source_attached",
            admitted_definition_version = %admitted,
        );
        RetainedStartupBinding::SkillToolSource {
            admitted_definition_version: admitted,
        }
    });
    let skill_tool_basis = match composition.skill_reconcile_tool_basis() {
        Ok(marked) => {
            tracing::info!(
                target: "eliotd::diagnostics",
                event = "eliotd.skill_tool_basis_reconciled",
                marked_stale = marked,
            );
            Ok(RetainedStartupBinding::SkillToolBasis {
                marked_stale: marked,
            })
        }
        Err(reason) => Err(reason.to_string()),
    };
    (skill_tool_source, skill_tool_basis)
}

/// Attaches the T12-06 Governor Dreamer intake registration (gated, no lifecycle change).
///
/// Post-`start` attach-style check at the single site holding both the concrete client and the
/// composition: builds the [`GovernorDreamerAdapter`](eliotd::GovernorDreamerAdapter) through
/// the readiness-gated accessor and validates the fence-bound route context. Fails closed
/// before `report_ready` when the Governor is not ready or the admitted fence cannot bind a
/// context. No thread, no transport, no `start()` contour or run-loop change.
///
/// #18 item A: the returned `Err` is the exact reason the capability did not bind; it is
/// recorded in the startup binding ledger and emitted as an `ErrorRecord` instead of
/// propagating, so an unbound intake withholds readiness rather than removing the process.
/// On success the admitted route context itself is the retained evidence.
fn attach_dreamer_intake(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
) -> Result<RetainedStartupBinding, String> {
    let adapter = composition
        .dreamer_admission(kernel)
        .map_err(|error| error.to_string())?;
    let context = adapter
        .dreamer_route_context()
        .map_err(|error| error.to_string())?;
    Ok(RetainedStartupBinding::DreamerIntakeRoute(context))
}

/// Attaches the T12-07 governed Dreamer model-call registration (gated, no lifecycle change).
///
/// Post-`start` attach-style check at the single site holding the composition: builds the
/// [`GovernedDreamerModelAdapter`](eliotd::GovernedDreamerModelAdapter) through the
/// readiness-gated accessor and validates the fence-bound model route context. Fails closed
/// before `report_ready` when the Governor is not ready or the admitted fence cannot bind
/// a context. No thread, no transport, no provider execution or credentials, no `start()`
/// contour or run-loop change.
///
/// #18 item A: the admitted model route context is the retained evidence; a failure records
/// the exact reason instead of propagating.
fn attach_dreamer_model(composition: &DaemonComposition) -> Result<RetainedStartupBinding, String> {
    let adapter = composition
        .dreamer_model()
        .map_err(|error| error.to_string())?;
    let context = adapter
        .model_route_context()
        .map_err(|error| error.to_string())?;
    Ok(RetainedStartupBinding::DreamerModelRoute(context))
}

/// Attaches the #872 durable agent-fabric registration (gated, no lifecycle change).
///
/// Post-`start` attach-style check at the single site holding the composition:
/// builds the [`AgentFabricDescriptor`](eliotd::AgentFabricDescriptor) through
/// the readiness-gated `DaemonComposition::agent_fabric_descriptor` accessor.
/// Fails closed before `report_ready` when the Governor is not ready or the
/// admitted fence cannot bind the descriptor. No coordinator is constructed
/// here, no thread, no transport, no provider execution or credentials, no
/// `start()` contour or run-loop change: the single `AgentCoordinator` is
/// constructed per admitted operation through the fabric composition, and the
/// run loop dispatches only post-activation provider-neutral intents.
///
/// #18 item A: the admitted descriptor is returned as the retained evidence, and a failure
/// records the exact reason instead of propagating.
fn attach_agent_fabric(composition: &DaemonComposition) -> Result<RetainedStartupBinding, String> {
    // #740: #872 attach span over the existing control path. The admitted
    // ingress reaching the durable fabric is recorded with the descriptor
    // identities before readiness is reported.
    let _span = tracing::info_span!("eliotd.fabric_attach").entered();
    let descriptor = composition
        .agent_fabric_descriptor()
        .map_err(|error| error.to_string())?;
    if descriptor.service != SERVICE_NAME {
        return Err("agent fabric descriptor service mismatch".to_owned());
    }
    let _ = eliotd::diagnostics::emit_fabric_attached(
        &descriptor.service,
        descriptor.generation,
        descriptor.authority_epoch,
    );
    Ok(RetainedStartupBinding::AgentFabric(descriptor))
}

/// Records the seven declared startup binding dispositions and emits them once.
///
/// #18 item A: this is the single place the declared denominator becomes durable
/// in-process state. Every capability keeps either its exact admitted
/// identity/descriptor or the exact reason it did not bind; an unbound
/// capability is reported as an `ErrorRecord` at its own owning code and
/// withholds readiness, but never propagates and never removes the process. The
/// whole ledger is emitted so the retained evidence is observable.
fn record_startup_bindings(
    owner_session_binding: Result<RetainedStartupBinding, String>,
    notification_snapshot: Result<RetainedStartupBinding, String>,
    dreamer_intake: Result<RetainedStartupBinding, String>,
    dreamer_model: Result<RetainedStartupBinding, String>,
    agent_fabric: Result<RetainedStartupBinding, String>,
    skill_tool_source: Result<RetainedStartupBinding, String>,
    skill_tool_basis: Result<RetainedStartupBinding, String>,
) -> StartupCapabilityBindings {
    fn disposition(
        capability: DeclaredStartupCapability,
        outcome: Result<RetainedStartupBinding, String>,
    ) -> StartupBindingDisposition {
        match outcome {
            Ok(retained) => StartupBindingDisposition::Bound(Box::new(retained)),
            Err(reason) => {
                let _ = eliotd::diagnostics::ErrorRecord::of(
                    eliotd::diagnostics::OwningComponent::DaemonRuntime,
                    capability.as_str(),
                    &reason,
                )
                .emit();
                StartupBindingDisposition::Unbound(reason)
            }
        }
    }
    let bindings = StartupCapabilityBindings::new(
        disposition(
            DeclaredStartupCapability::OwnerSessionBinding,
            owner_session_binding,
        ),
        disposition(
            DeclaredStartupCapability::NotificationSnapshot,
            notification_snapshot,
        ),
        disposition(DeclaredStartupCapability::DreamerIntake, dreamer_intake),
        disposition(DeclaredStartupCapability::DreamerModel, dreamer_model),
        disposition(DeclaredStartupCapability::AgentFabric, agent_fabric),
        disposition(
            DeclaredStartupCapability::SkillToolSource,
            skill_tool_source,
        ),
        disposition(DeclaredStartupCapability::SkillToolBasis, skill_tool_basis),
    );
    tracing::info!(
        target: "eliotd::diagnostics",
        event = "eliotd.startup_capability_bindings",
        complete = bindings.every_declared_capability_bound(),
        unbound = bindings
            .unbound_reasons()
            .iter()
            .map(|(capability, _)| capability.as_str())
            .collect::<Vec<_>>()
            .join(","),
        bindings = %bindings.report(),
    );
    bindings
}

/// Proves the live canonical tool-source path before readiness (issue #1882,
/// no lifecycle change).
///
/// Post-`start` attach-style check needing no composition handle: builds the
/// production canonical tool source through the Governor hook
/// (`eliot_governor::canonical_skill_tool_source`) and pins the admitted
/// definition version the Skill delivery driver runs under. I1.5 starts only
/// capabilities an admitted request requires, so nothing is installed,
/// issued, or displayed here — this only proves the real tools-owner edge
/// executes in the production binary and records which definition version
/// the skill path is bound to. Skill delivery stays an optional capability
/// (A2.3): a hook failure emits an error record and degrades only the skill
/// path, never daemon readiness. No thread, no transport, no `start()`
/// contour or run-loop change.
fn attach_skill_tool_source() -> Result<String, String> {
    let _span = tracing::info_span!("eliotd.skill_tool_source_attach").entered();
    eliot_governor::canonical_skill_tool_source()
        .map(|(_, admitted)| admitted)
        .map_err(|error| format!("skill tool source unavailable: {error}"))
}

fn report_terminal_failure(kernel: &DaemonKernelClient, reason: String) -> String {
    // #740: owning error record at the terminal-failure boundary. The
    // degraded/fatal/status writes below keep their exact existing behavior.
    let _span = tracing::info_span!("eliotd.terminal_failure").entered();
    let _ = eliotd::diagnostics::ErrorRecord::of(
        eliotd::diagnostics::OwningComponent::DaemonRuntime,
        "terminal-failure",
        &reason,
    )
    .emit();
    let mut terminal = reason.clone();
    if let Err(error) = kernel.report_degraded(reason.clone()) {
        append_failure(&mut terminal, "Kernel degraded report", error);
    }
    if let Err(error) = write_json(&ReadyMessage::Degraded {
        service: SERVICE_NAME,
        protocol: PROTOCOL_VERSION,
        reason: reason.clone(),
    }) {
        append_failure(&mut terminal, "degraded status output", error);
    }
    if let Err(error) = kernel.report_fatal(reason.clone()) {
        append_failure(&mut terminal, "Kernel fatal report", error);
    }
    if let Err(error) = write_json(&ReadyMessage::Fatal {
        service: SERVICE_NAME,
        protocol: PROTOCOL_VERSION,
        reason,
    }) {
        append_failure(&mut terminal, "fatal status output", error);
    }
    terminal
}

fn append_failure(target: &mut String, context: &str, error: impl std::fmt::Display) {
    target.push_str("; ");
    target.push_str(context);
    target.push_str(": ");
    target.push_str(&error.to_string());
}

struct LaunchArgs {
    config_path: PathBuf,
    config_sha256: String,
    launch_nonce: String,
    executable_sha256: String,
}

fn parse_launch_args<I>(args: I) -> Result<LaunchArgs, String>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let args = args.into_iter().collect::<Vec<_>>();
    if args.len() != 8
        || args[0] != "--config-descriptor"
        || args[2] != "--config-descriptor-sha256"
        || args[4] != "--launch-nonce"
        || args[6] != "--executable-sha256"
    {
        return Err("eliotd requires the exact 8-value descriptor binding contour".to_owned());
    }
    let text = |index: usize, label: &str| {
        args[index]
            .to_str()
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
            .ok_or_else(|| format!("{label} must be valid non-empty UTF-8"))
    };
    Ok(LaunchArgs {
        config_path: PathBuf::from(text(1, "config descriptor path")?),
        config_sha256: text(3, "config descriptor digest")?,
        launch_nonce: text(5, "launch nonce")?,
        executable_sha256: text(7, "executable digest")?,
    })
}

struct LoopCadence {
    activation_poll: Interval,
    health_heartbeat: Interval,
}

impl LoopCadence {
    fn production() -> Self {
        Self::with_periods(ACTIVATION_POLL_INTERVAL, HEALTH_HEARTBEAT_INTERVAL)
    }

    fn with_periods(activation_period: Duration, health_period: Duration) -> Self {
        let now = Instant::now();
        let mut activation_poll =
            tokio::time::interval_at(now + activation_period, activation_period);
        let mut health_heartbeat = tokio::time::interval_at(now + health_period, health_period);
        activation_poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
        health_heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
        Self {
            activation_poll,
            health_heartbeat,
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run_loop(
    kernel: Arc<DaemonKernelClient>,
    composition: SharedComposition,
    mut supervision_progress: Option<eliotd::SupervisionProgressProducer>,
    // #2560/#2647: sole owner of the readiness projection. A local-read
    // flight prepares from an immutable snapshot and returns only the bounded
    // delta it actually observed, so there is one authoritative copy and a
    // late completion can never overwrite newer owner observations.
    startup_readiness: StartupReadinessProjection,
    startup_maintenance_observations: [MaintenanceObservation; 2],
) -> Result<RunLoopExit, String> {
    let mut cadence = LoopCadence::production();
    // One projection instance is shared with the heartbeat future. Both
    // heartbeat observation and local-read adoption use short synchronous
    // borrows and release them before any await.
    let startup_readiness = Rc::new(RefCell::new(startup_readiness));
    // Sole owner of activation state. No second owner and no second
    // concurrent activation exist: the timer starts work only when idle and
    // the in-flight step is polled only in its own branch below.
    let mut flight = ActivationFlight::Idle;
    // Sole owner of local-read poll state (Implements #18). The same tick
    // drives it independently of the activation flight: a null claim backs
    // off until the next tick, while a claimed pair forwards through the
    // Kernel `local_read` leg and submits its result body before idling.
    let mut local_read_flight = LocalReadFlight::Idle;
    // Sole owner of observe poll state (issue #2565). The same tick drives
    // it independently of every other flight: a null claim backs off until
    // the next tick, while a claimed observe pair serves through the closed
    // vocabulary and defers through the Kernel defer leg before idling.
    let mut observe_flight = ObserveFlight::Idle;
    // Campaign packets have their own queue, claim, compile, and result
    // flight. They are never consumed by the query poller.
    let mut campaign_packet_flight = CampaignPacketFlight::Idle;
    // State pairs have their own queue, claim, serve, and result flight
    // (#2564 Slice 1). They are never consumed by the query poller and never
    // served through the query-only `GetEvidencePack` twin.
    let mut state_flight = StateFlight::Idle;
    // Task Controller claims ride the same bounded cadence. The owner path is
    // real and independent: one authenticated claim, one Governor transition,
    // and one fenced result submit per tick.
    let mut task_controller_flight = TaskControllerFlight::Idle;
    // Finish candidates ride the same bounded cadence with their own queue and
    // attempt type (issue #1741): one authenticated claim, one Governor finish
    // evaluation, and one fenced result submit per tick.
    let mut finish_flight = FinishFlight::Idle;
    // The solo provider-binding read is one tracked poll at a time. Its Kernel
    // request must remain a select branch so shutdown and other cadence work
    // keep running while the authenticated response is pending.
    let mut solo_poll_flight = SoloPollFlight::Idle;
    let mut solo_poll_last_refusal: Option<String> = None;
    // #2100: O1 owner-feed trigger state. The runtime retains one trigger
    // across passes so an unchanged provider performs no IO, while a
    // revision advance or a recovery re-presentation republishes through the
    // full read->publish->readback exchange. Degradation never fails the
    // loop: pending grants stay pending until a later pass binds them.
    // Issue #2559: the trigger travels with its own polled flight below, so
    // the exchange is polled independently of health and maintenance waits.
    let mut owner_feed = Some(eliotd::OwnerFeedTrigger::new());
    // Sole owner of owner-feed sync state. One bounded read->publish->readback
    // exchange is outstanding at most; the health completion branch starts it
    // when idle and its completion branch settles it back, exactly like the
    // other flights. No second owner and no untracked spawn exist.
    let mut owner_feed_flight = OwnerFeedFlight::Idle;
    // #740 A14: one repeated-failure guard per repeating diagnostic stream.
    // Each guard travels with its own flight future and returns at
    // settlement, so capped output never conflates distinct operations.
    let mut owner_feed_failure_guard = RepeatedFailureGuard::new();
    let mut maintenance_failure_guard = RepeatedFailureGuard::new();
    let mut health_heartbeat_failure_guard = RepeatedFailureGuard::new();
    // Sole owner of TestD owner drain state (issue #325). The same tick
    // drives it independently of the other flights: one bounded drain step
    // binds pending verifier dispatches, publishes terminal verifier facts,
    // submits finish candidates, and acknowledges terminals, all through
    // the Kernel owner routes.
    let mut testd_owner_flight = TestdOwnerFlight::Idle;
    // Issue #1867 W1: sole owner of the improvement-intake dispatch state. The
    // same tick drives it: a real maintenance observation is turned into an
    // owner-actionable improvement artifact and committed durably through the
    // Governor `RecordLearningRecord` seam. Its lock wait stays in this
    // independently polled flight so a cadence handler never suspends polling
    // of the owner-feed lock holder.
    let mut improvement_intake_flight = ImprovementIntakeFlight::Idle;
    // Issue #2559: one cadence observation may wait for the composition lock,
    // but its wait remains in this independently polled flight. A later tick
    // cannot replace the observation already retained here.
    let mut maintenance_flight = MaintenanceFlight::Idle;
    maybe_start_startup_maintenance_triggers(
        &kernel,
        &composition,
        startup_maintenance_observations,
        &mut maintenance_flight,
        &mut maintenance_failure_guard,
    );
    // Health is a one-slot polled flight: a busy tick is coalesced and the
    // sole supervision producer moves into the future until settlement.
    let mut health_heartbeat_flight = HealthHeartbeatFlight::Idle;
    let mut deferred_supervision_activity = DeferredSupervisionActivity::default();
    // Recovery re-presentation at loop start: rebind the Kernel P-07 owner
    // from live Governor state before any activation work is claimed. The
    // exchange starts as the owner-feed flight's first bounded step and is
    // polled by the loop below; it is never awaited here, so the loop stays
    // pollable from its first pass.
    maybe_start_owner_feed_sync(
        &kernel,
        &composition,
        &mut owner_feed,
        &mut owner_feed_flight,
        &mut owner_feed_failure_guard,
    );
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|error| format!("daemon shutdown signal: {error}"))?;
                // #791 (W4/W17): publish the shutdown request to the Kernel
                // client before the drain. Every pending front-door send
                // observes it and settles as `UnknownOutcome` instead of
                // holding this process open until the transport's own
                // per-operation timeout, while the flight drain below keeps
                // its exact existing budget, identity retention and outcomes.
                kernel.request_shutdown();
                // Issue #2559: already-started flights drain together inside
                // one finite budget while every one of them stays polled; no
                // new claim starts here.
                let exit = drain_flights_on_shutdown(
                    &kernel,
                    &composition,
                    &mut flight,
                    &mut local_read_flight,
                    &mut observe_flight,
                    &mut testd_owner_flight,
                    &mut owner_feed_flight,
                    &mut owner_feed,
                    &mut maintenance_flight,
                    &mut improvement_intake_flight,
                    &mut health_heartbeat_flight,
                    &mut supervision_progress,
                    &mut deferred_supervision_activity,
                    &mut solo_poll_flight,
                    &mut solo_poll_last_refusal,
                )
                .await?;
                // #1862: the campaign-packet flight keeps its own queue, claim,
                // compile and result legs, and the Task Controller flight keeps
                // its own queue and attempt type. Both drain on their own
                // bounded budgets after the shared flights settle.
                drain_campaign_packet_on_shutdown(&mut campaign_packet_flight).await?;
                drain_state_on_shutdown(&mut state_flight).await?;
                drain_task_controller_on_shutdown(&mut task_controller_flight).await?;
                drain_finish_on_shutdown(&mut finish_flight).await?;
                return Ok(exit);
            }
            _ = cadence.activation_poll.tick() => {
                // The per-tick poller and drain gates, and the activation
                // claim's own idle gate, all live in `start_tick_work` so the
                // ordering those comments describe is stated once. The claim
                // carries the composition handle it needs to read the named
                // dependency discriminator before the request.
                let readiness_projection = startup_readiness.borrow();
                start_tick_work(
                    &kernel,
                    &composition,
                    &readiness_projection,
                    &mut local_read_flight,
                    &mut observe_flight,
                    &mut testd_owner_flight,
                    &mut flight,
                );
                // Campaign packets ride the same tick under their own gate and
                // are never consumed by the query poller.
                maybe_start_campaign_packet_poll(&kernel, &mut campaign_packet_flight);
                // State pairs ride the same tick under their own gate and are
                // never consumed by the query poller.
                maybe_start_state_poll(&kernel, &composition, &mut state_flight);
                // Task Controller uses a separate queue and attempt type;
                // start it on the same cadence without sharing the local-read
                // completion branch.
                maybe_start_task_controller_poll(
                    &kernel,
                    &composition,
                    &mut task_controller_flight,
                );
                // Finish uses a separate queue and attempt type; start it on the
                // same cadence without sharing the local-read completion branch.
                maybe_start_finish_poll(&kernel, &composition, &mut finish_flight);
                // Issue #1108: start at most one tracked Kernel verification
                // flight. The flight snapshots under a short composition
                // lock and releases it before awaiting owner IO.
                maybe_start_solo_poll(&kernel, &composition, &mut solo_poll_flight);
                // #1688 (I14.22): the idle trigger rides this cadence branch
                // because it is the one place that observes the activation
                // flight, so the `idle` gate the evaluator consumes is a real
                // observation of admitted interactive work rather than a
                // literal. Separate cadence and separate observation from the
                // health-heartbeat admitted-observation trigger below.
                maybe_start_idle_maintenance_trigger(
                    &kernel,
                    &composition,
                    &flight,
                    &mut maintenance_flight,
                    &mut maintenance_failure_guard,
                );
                // Issue #1867 W1: the improvement-intake dispatch rides the same
                // cadence and the same real idle observation, on its own single-
                // owner flight. It never shares the notification completion
                // branch, so a blocked durable commit cannot delay the
                // maintenance notification.
                //
                // #1867 W3: the step also reads the deduplication registry back
                // from the durable candidate records over the retained Kernel
                // transport, which is why the client travels into the future.
                maybe_start_improvement_intake(
                    &kernel,
                    &composition,
                    &flight,
                    &mut improvement_intake_flight,
                );
            }
            completion = next_activation_completion(&mut flight) => {
                settle_activation_completion(
                    &kernel,
                    &composition,
                    &mut supervision_progress,
                    &health_heartbeat_flight,
                    &mut deferred_supervision_activity,
                    &mut flight,
                    completion,
                )?;
            }
            local_read_completion = next_local_read_completion(&mut local_read_flight) => {
                let mut readiness_projection = startup_readiness.borrow_mut();
                settle_local_read_completion_updating_readiness(
                    local_read_completion,
                    &mut local_read_flight,
                    &mut readiness_projection,
                )?;
            }
            observe_completion = next_observe_completion(&mut observe_flight) => {
                settle_observe_completion(observe_completion, &mut observe_flight)?;
            }
            campaign_packet_completion =
                next_campaign_packet_completion(&mut campaign_packet_flight) =>
            {
                settle_campaign_packet_completion(
                    campaign_packet_completion,
                    &mut campaign_packet_flight,
                )?;
            }
            state_completion = next_state_completion(&mut state_flight) => {
                settle_state_completion(state_completion, &mut state_flight)?;
            }
            task_controller_completion =
                next_task_controller_completion(&mut task_controller_flight) => {
                    settle_task_controller_completion(
                        task_controller_completion,
                        &mut task_controller_flight,
                    )?;
                }
            finish_completion = next_finish_completion(&mut finish_flight) => {
                settle_finish_completion(finish_completion, &mut finish_flight)?;
            }
            solo_poll_completion = next_solo_poll_completion(&mut solo_poll_flight) => {
                settle_solo_poll_completion(
                    solo_poll_completion,
                    &mut solo_poll_flight,
                    &mut solo_poll_last_refusal,
                );
            }
            testd_owner_completion = next_testd_owner_completion(&mut testd_owner_flight) => {
                settle_testd_owner_completion(testd_owner_completion, &mut testd_owner_flight)?;
            }
            owner_feed_trigger = next_owner_feed_completion(&mut owner_feed_flight) => {
                settle_owner_feed_completion(
                    owner_feed_trigger,
                    &mut owner_feed,
                    &mut owner_feed_flight,
                    &mut owner_feed_failure_guard,
                );
            }
            maintenance_guard = next_maintenance_completion(&mut maintenance_flight) => {
                settle_maintenance_completion(
                    maintenance_guard,
                    &mut maintenance_flight,
                    &mut maintenance_failure_guard,
                );
            }
            completion = next_improvement_intake_completion(&mut improvement_intake_flight) => {
                settle_improvement_intake_completion(&mut improvement_intake_flight, completion);
            }
            heartbeat_completion = next_health_heartbeat_completion(&mut health_heartbeat_flight) => {
                settle_health_heartbeat_completion(
                    heartbeat_completion,
                    &mut health_heartbeat_flight,
                    &mut supervision_progress,
                    &mut deferred_supervision_activity,
                    true,
                    &mut health_heartbeat_failure_guard,
                )?;
                // Preserve the existing health-before-owner-feed ordering.
                maybe_start_owner_feed_sync(
                    &kernel,
                    &composition,
                    &mut owner_feed,
                    &mut owner_feed_flight,
                    &mut owner_feed_failure_guard,
                );
            }
            _ = cadence.health_heartbeat.tick() => {
                maybe_start_health_heartbeat_tick(
                    &kernel,
                    &composition,
                    &startup_readiness,
                    &mut supervision_progress,
                    matches!(flight, ActivationFlight::InFlight(_)),
                    &mut health_heartbeat_flight,
                    &mut health_heartbeat_failure_guard,
                );
            }
        }
    }
}

/// What one completed activation claim resolves to before the loop acts.
///
/// The ticket is boxed so the idle arm stays a zero-sized value: a claim that
/// resolves to nothing must not carry the ticket's size.
#[derive(Debug)]
enum ActivationClaimStep {
    /// Nothing further runs this pass: the flight idles and the loop resumes.
    Idle,
    /// A valid admitted ticket that may start its dispatch step.
    Valid(Box<AgentActivationResolutionTicket>),
}

/// Resolves one completed activation claim, validate-first (issue #202, owner
/// decision ii).
///
/// An empty claim and an invalid ticket both idle the flight and continue the
/// loop with no Governor read, no typed-result submit, no reconcile of typed
/// results, and no retry of the rejected revision; an invalid ticket
/// constructs its terminal artifact from the claimed bytes alone. A valid
/// ticket notes the Claim channel and is handed to the dispatch step.
fn settle_activation_claim(
    claim: ActivationClaim,
    supervision_progress: &mut Option<eliotd::SupervisionProgressProducer>,
    health_heartbeat_flight: &HealthHeartbeatFlight,
    deferred_activity: &mut DeferredSupervisionActivity,
    buffer_while_heartbeat_in_flight: bool,
) -> Result<ActivationClaimStep, String> {
    match claim {
        ActivationClaim::Empty => Ok(ActivationClaimStep::Idle),
        ActivationClaim::Invalid {
            ticket_bytes,
            reason,
        } => {
            settle_invalid_claim(ticket_bytes, &reason)?;
            Ok(ActivationClaimStep::Idle)
        }
        ActivationClaim::Valid(ticket) => {
            note_supervision_claim(
                supervision_progress.as_mut(),
                health_heartbeat_flight,
                deferred_activity,
                buffer_while_heartbeat_in_flight,
            );
            Ok(ActivationClaimStep::Valid(Box::new(*ticket)))
        }
    }
}

/// Settles one completed activation step for the live loop.
///
/// A completed claim installs the resolve-wait flight, a completed
/// resolve-wait installs the dispatch flight or idles on Kernel-owned
/// expiry, and a completed dispatch idles after noting supervision work.
/// Every arm installs synchronously and returns to `select!` (issue #2559):
/// no lock wait and no other flight is awaited here, so this completion branch
/// returns control to `select!` immediately.
fn settle_activation_completion(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    supervision_progress: &mut Option<eliotd::SupervisionProgressProducer>,
    health_heartbeat_flight: &HealthHeartbeatFlight,
    deferred_activity: &mut DeferredSupervisionActivity,
    flight: &mut ActivationFlight,
    completion: ActivationCompletion,
) -> Result<(), String> {
    match completion {
        ActivationCompletion::Claim(claim_outcome) => {
            let claim = claim_outcome?;
            // Issue #202 (owner decision ii), validate-first.
            match settle_activation_claim(
                claim,
                supervision_progress,
                health_heartbeat_flight,
                deferred_activity,
                true,
            )? {
                ActivationClaimStep::Idle => {
                    *flight = ActivationFlight::Idle;
                }
                ActivationClaimStep::Valid(ticket) => {
                    // Issue #2559: the validated ticket is retained by the
                    // new resolve-wait flight; the lock wait inside that
                    // flight stays polled alongside every other flight
                    // instead of stalling the loop here.
                    install_activation_resolve(kernel, composition, flight, *ticket);
                }
            }
            Ok(())
        }
        ActivationCompletion::Resolve(resolve_outcome) => {
            settle_activation_resolve_completion(kernel, flight, resolve_outcome)
        }
        ActivationCompletion::Dispatch(dispatch_outcome) => match dispatch_outcome {
            Ok(()) => {
                note_supervision_applied(
                    supervision_progress.as_mut(),
                    health_heartbeat_flight,
                    deferred_activity,
                    true,
                );
                *flight = ActivationFlight::Idle;
                Ok(())
            }
            // #1115: Kernel-owned deadline expiry retires this ticket without
            // retry, but no result was accepted and no Apply progress exists.
            Err(ActivationDispatchError::Expired) => {
                *flight = ActivationFlight::Idle;
                Ok(())
            }
            Err(ActivationDispatchError::Hard(error)) => Err(error),
            Err(ActivationDispatchError::Unknown { detail, .. }) => Err(detail),
        },
    }
}

/// Starts the tick-driven work for one shared-cadence tick.
///
/// The local-read poller and the `TestD` owner drain each ride the same tick
/// under their own gate: both must start even while an activation is in
/// flight, so their gates are checked before the activation early-continue.
/// The activation claim itself still starts only when its flight is idle.
fn start_tick_work(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    startup_readiness: &StartupReadinessProjection,
    local_read_flight: &mut LocalReadFlight,
    observe_flight: &mut ObserveFlight,
    testd_owner_flight: &mut TestdOwnerFlight,
    flight: &mut ActivationFlight,
) {
    maybe_start_local_read_poll(kernel, composition, startup_readiness, local_read_flight);
    maybe_start_observe_poll(kernel, observe_flight);
    maybe_start_testd_owner_drain(kernel, composition, testd_owner_flight);
    if decide_activation_tick(flight) == ActivationTickDecision::StartClaim {
        *flight = ActivationFlight::InFlight(ActivationFlightState {
            // #1115: the claim reads the daemon's current named dependency
            // discriminator from the composition before requesting, so the
            // Kernel-side `NotReady` supersede gate sees an authenticated
            // observation instead of an implicit one.
            future: start_activation_claim(kernel, composition),
            retained: None,
        });
    }
}

/// Notes one claimed activation on the supervision Claim channel when a
/// supervision lineage exists.
///
/// #18 item A: a generation whose declared capabilities did not all bind was
/// never reported ready, so the Kernel issued no `daemon_ready` bundle and
/// there is no lineage or lease head to advance. Absence of the producer is an
/// explicit not-ready state, not a silent drop: the readiness record already
/// reported the withholding.
fn note_supervision_claim(
    producer: Option<&mut eliotd::SupervisionProgressProducer>,
    health_heartbeat_flight: &HealthHeartbeatFlight,
    deferred_activity: &mut DeferredSupervisionActivity,
    buffer_while_heartbeat_in_flight: bool,
) {
    if let Some(producer) = producer {
        producer.note_claim();
    } else if buffer_while_heartbeat_in_flight
        && health_heartbeat_flight.owns_supervision_producer()
    {
        deferred_activity.note_claim();
    }
}

/// Notes one Kernel-accepted dispatch on the supervision Dispatch/Apply
/// channels when a supervision lineage exists. Mirrors
/// [`note_supervision_claim`].
fn note_supervision_applied(
    producer: Option<&mut eliotd::SupervisionProgressProducer>,
    health_heartbeat_flight: &HealthHeartbeatFlight,
    deferred_activity: &mut DeferredSupervisionActivity,
    buffer_while_heartbeat_in_flight: bool,
) {
    if let Some(producer) = producer {
        producer.note_kernel_applied();
    } else if buffer_while_heartbeat_in_flight
        && health_heartbeat_flight.owns_supervision_producer()
    {
        deferred_activity.note_applied();
    }
}

/// Builds the sanitized maintenance observation for one wired trigger site.
///
/// Shared by every trigger arm so each one names the same self-observed family
/// and passes its evidence identities through the shared diagnostics sanitizer:
/// a trigger can never carry control characters, secrets, or unbounded detail
/// into the evaluator's own field validation. The family is the one
/// self-observed family this daemon can honestly name today; the registered
/// per-observation family catalog is #1693's to supply.
fn maintenance_observation(
    origin: MaintenanceTriggerOrigin,
    evidence_refs: &[String],
    activation_in_flight: bool,
) -> MaintenanceObservation {
    let evidence_refs = evidence_refs
        .iter()
        .map(|reference| eliotd::diagnostics::sanitize_identity(reference))
        .collect();
    MaintenanceObservation {
        origin,
        family: SELF_OBSERVED_FAMILY,
        evidence_refs,
        activation_in_flight,
    }
}

/// Evaluates one real maintenance observation and captures the exact admitted
/// fence the durable notification will use. A successful Governor decision is
/// always handed to the notification owner: it decides whether the Governor
/// admitted a job and the family catalog admits its execution route.
fn maintenance_notification_candidate(
    composition: &DaemonComposition,
    observation: MaintenanceObservation,
    failure_guard: &mut RepeatedFailureGuard,
) -> Option<(
    eliot_contracts::StateFence,
    eliot_maintenance::AutomationTriggerDecision,
    eliotd::notification_state_emit::MaintenanceNotificationEvidence,
)> {
    let (decision, evidence) =
        match composition.evaluate_maintenance_trigger_with_evidence(observation) {
            Ok(evaluated) => evaluated,
            Err(error) => {
                // #740 A14: the cadence re-evaluates every tick, so a standing
                // refusal gates its record on this stream's guard instead of
                // emitting unbounded repeats.
                if failure_guard.should_emit() {
                    let _ = eliotd::diagnostics::ErrorRecord::of_daemon_error(&error).emit();
                }
                return None;
            }
        };
    match composition.notification_state_admission_fence() {
        Ok(fence) => Some((fence, decision, evidence)),
        Err(error) => {
            // No exchange is attempted until the composition exposes an
            // admitted Kernel fence. This remains a diagnostic gap, never a
            // startup or readiness gate.
            if failure_guard.should_emit() {
                let _ = eliotd::diagnostics::ErrorRecord::of_daemon_error(&error).emit();
            }
            None
        }
    }
}

/// Evaluates one observation under the composition lock, then drops the guard
/// before the canonical notification exchange. The exchange is a retained
/// run-loop flight rather than detached work.
async fn evaluate_and_emit_maintenance_notification(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    observation: MaintenanceObservation,
    failure_guard: &mut RepeatedFailureGuard,
) {
    let candidate = {
        let guard = composition.lock().await;
        maintenance_notification_candidate(&guard, observation, failure_guard)
    };
    if let Some((fence, decision, evidence)) = candidate {
        note_blocked_automation_notification(kernel, fence, &decision, &evidence, failure_guard)
            .await;
    }
}

/// Starts the two startup observations in the one retained maintenance
/// flight. The run loop continues polling all other work while any bounded
/// notification exchange is in progress.
fn maybe_start_startup_maintenance_triggers(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    observations: [MaintenanceObservation; 2],
    flight: &mut MaintenanceFlight,
    failure_guard: &mut RepeatedFailureGuard,
) {
    if !matches!(flight, MaintenanceFlight::Idle) {
        return;
    }
    let kernel = Arc::clone(kernel);
    let composition = Arc::clone(composition);
    let mut failure_guard = std::mem::replace(failure_guard, RepeatedFailureGuard::new());
    *flight = MaintenanceFlight::InFlight(MaintenanceFlightState {
        future: Box::pin(async move {
            for observation in observations {
                evaluate_and_emit_maintenance_notification(
                    &kernel,
                    &composition,
                    observation,
                    &mut failure_guard,
                )
                .await;
            }
            failure_guard
        }),
    });
}

/// Captures the idle trigger from the activation-poll cadence observation.
///
/// The evidence is the flight state the tick just decided from, so the
/// decision and its evidence are the same observation. This is a periodic
/// idle *observation*, not a busy-to-idle edge detector: the loop retains no
/// previous-idle flag, and inventing one to manufacture a transition edge
/// would be a fabricated event source.
fn idle_maintenance_observation(flight: &ActivationFlight) -> MaintenanceObservation {
    let activation_in_flight = matches!(flight, ActivationFlight::InFlight(_));
    maintenance_observation(
        MaintenanceTriggerOrigin::IdleTransition,
        &[format!("activation_in_flight={activation_in_flight}")],
        activation_in_flight,
    )
}

/// Starts one retained cadence maintenance evaluation when its flight is
/// idle. Capturing the observation before creating the future preserves the
/// actual activation state that triggered it; a busy flight is left untouched.
fn maybe_start_idle_maintenance_trigger(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    activation_flight: &ActivationFlight,
    flight: &mut MaintenanceFlight,
    failure_guard: &mut RepeatedFailureGuard,
) {
    if !matches!(flight, MaintenanceFlight::Idle) {
        return;
    }
    let observation = idle_maintenance_observation(activation_flight);
    let kernel = Arc::clone(kernel);
    let composition = Arc::clone(composition);
    // #740 A14: the stream's repeated-failure guard travels with the future
    // exactly like the heartbeat and owner-feed guards, so a standing
    // per-cadence refusal cannot emit unbounded records.
    let mut failure_guard = std::mem::replace(failure_guard, RepeatedFailureGuard::new());
    *flight = MaintenanceFlight::InFlight(MaintenanceFlightState {
        future: Box::pin(async move {
            evaluate_and_emit_maintenance_notification(
                &kernel,
                &composition,
                observation,
                &mut failure_guard,
            )
            .await;
            failure_guard
        }),
    });
}

/// Polls one retained maintenance evaluation, pending forever while idle.
async fn next_maintenance_completion(flight: &mut MaintenanceFlight) -> RepeatedFailureGuard {
    match flight {
        MaintenanceFlight::Idle => std::future::pending::<RepeatedFailureGuard>().await,
        MaintenanceFlight::InFlight(state) => (&mut state.future).await,
    }
}

/// Releases a completed maintenance flight so a later cadence observation can
/// start. Settlement itself is synchronous and cannot block the run loop.
fn settle_maintenance_completion(
    completion: RepeatedFailureGuard,
    flight: &mut MaintenanceFlight,
    failure_guard: &mut RepeatedFailureGuard,
) {
    *failure_guard = completion;
    *flight = MaintenanceFlight::Idle;
}

/// Submits one owner-side canonical notification when the evaluated family
/// cannot start (issues #1780/#1693, I11.5/I14.22).
///
/// I11.5 makes the persistent record the durable obligation and delivery only
/// the presentation, so a refused emission is an explicit typed gap recorded
/// through the existing minimal operational diagnostics — never a silent drop
/// and never a daemon-killing error. The Kernel health poll has already
/// completed by this point, so a refused emission never rolls the daemon back
/// to a failed poll; it is awaited before the supervision submit below, so it
/// does delay that one submit for the length of one bounded exchange. A
/// notification exchange is bounded by the transport's own operation deadline
/// and normally never runs at all, because a recorded decision is skipped
/// without any write. That is the A13.8 visible-degradation contract: the
/// daemon stays alive and observable while the operator can see the refusal.
async fn note_blocked_automation_notification(
    kernel: &Arc<DaemonKernelClient>,
    fence: eliot_contracts::StateFence,
    decision: &eliot_maintenance::AutomationTriggerDecision,
    evidence: &eliotd::notification_state_emit::MaintenanceNotificationEvidence,
    failure_guard: &mut RepeatedFailureGuard,
) {
    match eliotd::notification_state_emit::emit_blocked_automation_notification(
        kernel, fence, decision, evidence,
    )
    .await
    {
        Ok(Some(eliotd::notification_state_emit::NotificationStateEmit::Committed {
            dedup_key,
            notification_id,
            operation_id,
        })) => {
            tracing::info!(
                target: "eliotd::diagnostics",
                event = "eliotd.notification_state_emitted",
                dedup_key = %dedup_key,
                notification_id = %notification_id,
                operation_id = %operation_id,
            );
        }
        Ok(None) => {}
        Err(error) => {
            // #740 A14: both callers re-notify every tick while blocked, so
            // the record gates on the caller's stream guard instead of
            // emitting unbounded repeats.
            if failure_guard.should_emit() {
                let _ = eliotd::diagnostics::ErrorRecord::of(
                    eliotd::diagnostics::OwningComponent::DaemonRuntime,
                    "notification-state",
                    &error.to_string(),
                )
                .emit();
            }
        }
    }
}

/// Starts one health tick when its slot is idle. The activation state is
/// captured with the timer event, and the sole supervision producer travels
/// with the future until its ordered acknowledgement sequence completes. The
/// stream's repeated-failure guard travels the same way (#740 A14), so a
/// standing per-tick refusal cannot emit unbounded records.
fn maybe_start_health_heartbeat_tick(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    startup_readiness: &SharedStartupReadiness,
    supervision_progress: &mut Option<eliotd::SupervisionProgressProducer>,
    activation_in_flight: bool,
    flight: &mut HealthHeartbeatFlight,
    failure_guard: &mut RepeatedFailureGuard,
) {
    if !matches!(flight, HealthHeartbeatFlight::Idle) {
        return;
    }
    let kernel = Arc::clone(kernel);
    let composition = Arc::clone(composition);
    let startup_readiness = Rc::clone(startup_readiness);
    let mut producer = supervision_progress.take();
    let owns_supervision_producer = producer.is_some();
    let mut failure_guard = std::mem::replace(failure_guard, RepeatedFailureGuard::new());
    *flight = HealthHeartbeatFlight::InFlight(HealthHeartbeatFlightState {
        future: Box::pin(async move {
            let result = run_health_heartbeat_tick(
                &kernel,
                &composition,
                producer.as_mut(),
                activation_in_flight,
                &startup_readiness,
                &mut failure_guard,
            )
            .await;
            HealthHeartbeatCompletion {
                result,
                supervision_progress: producer,
                failure_guard,
            }
        }),
        owns_supervision_producer,
    });
}

/// Polls the one health tick, pending forever while its slot is idle.
async fn next_health_heartbeat_completion(
    flight: &mut HealthHeartbeatFlight,
) -> HealthHeartbeatCompletion {
    match flight {
        HealthHeartbeatFlight::Idle => std::future::pending::<HealthHeartbeatCompletion>().await,
        HealthHeartbeatFlight::InFlight(state) => (&mut state.future).await,
    }
}

/// Returns the producer after the heartbeat future completes, then places
/// activity observed during its event cut after the completed tick's ordered
/// Claim/Dispatch/Apply acknowledgements. Failed ticks do not apply deferred
/// activity because there will be no next heartbeat in this loop.
fn settle_health_heartbeat_completion(
    completion: HealthHeartbeatCompletion,
    flight: &mut HealthHeartbeatFlight,
    supervision_progress: &mut Option<eliotd::SupervisionProgressProducer>,
    deferred_activity: &mut DeferredSupervisionActivity,
    apply_deferred_activity: bool,
    failure_guard: &mut RepeatedFailureGuard,
) -> Result<(), String> {
    *flight = HealthHeartbeatFlight::Idle;
    *failure_guard = completion.failure_guard;
    *supervision_progress = completion.supervision_progress;
    if apply_deferred_activity
        && completion.result.is_ok()
        && let Some(producer) = supervision_progress.as_mut()
    {
        producer.note_deferred_activity(deferred_activity.claims, deferred_activity.applied);
    }
    deferred_activity.clear();
    completion.result
}

/// Emits one #740 cache-health record from an owner `StoreHealth` poll
/// (#740 A8). Ready and Degraded project to their distinct cache states
/// under the manifest digest the poll actually returned; Unavailable emits
/// nothing because `CacheState` cannot represent it and merging it into
/// Degraded would conflate two distinct owner states.
fn emit_cache_health_from_store_poll(health: &StoreHealth) {
    let state = match health.status {
        StoreHealthStatus::Ready => Some(eliotd::diagnostics::CacheState::Healthy),
        StoreHealthStatus::Degraded => Some(eliotd::diagnostics::CacheState::Degraded),
        StoreHealthStatus::Unavailable => None,
    };
    if let Some(state) = state {
        let _ = eliotd::diagnostics::emit_cache_health(state, health.manifest_digest.as_str());
    }
}

/// Runs one health-heartbeat tick (Implements #88, wave 3): the Kernel
/// health poll stays evidence-only, then the same tick submits supervision
/// progress built from observed work. The poll's Store dimension is reused as
/// the observation's `store_dependency` evidence, never as renewal authority.
///
/// Issue #2559: the tick runs in its own polled flight, and the run loop
/// starts the owner-feed exchange after it settles. A stalled owner-feed
/// step cannot stall health or supervision polling.
///
/// #18 item A: the health poll runs unconditionally, so liveness stays observed
/// even for a generation that never reported ready; only the progress renewal
/// is absent, because the Kernel authored no supervision lineage for it.
async fn run_health_heartbeat_tick(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    supervision_progress: Option<&mut eliotd::SupervisionProgressProducer>,
    activation_in_flight: bool,
    startup_readiness: &SharedStartupReadiness,
    failure_guard: &mut RepeatedFailureGuard,
) -> Result<(), String> {
    let health: StoreHealth = KernelTransitionPort::health(kernel.as_ref())
        .await
        .map_err(|error| format!("Kernel health heartbeat: {error}"))?;
    emit_cache_health_from_store_poll(&health);
    // #1688 (I14.22): the Kernel health poll is this daemon's one admitted
    // self-observation per heartbeat, so it is the admitted-observation
    // trigger. The evidence identities are the observed health status and the
    // store manifest digest the poll actually returned - never a synthetic
    // signal. `activation_in_flight` is the activation state captured when
    // this timer event started the flight, so maintenance and supervision use
    // one immutable observation even as the loop continues polling work.
    // Issue #1780/#1693 (I11.5/I14.22): hand every successful decision plus its
    // admitted fence to the notification owner. It checks both Governor job
    // admission and the registered family's execution route, so a Governor-
    // admitted decision whose family route cannot start is still persisted.
    // The canonical write itself happens after this lock is released, so no
    // Kernel exchange ever crosses the composition mutex (issue #18 N3).
    let (readiness_verdict, readiness_report, blocked_automation) = {
        let guard = composition.lock().await;
        let mut readiness_projection = startup_readiness.borrow_mut();
        // #2560: re-read the composition's own owner facts once per heartbeat.
        // This performs no capability IO and re-files no slot, so a slow
        // optional attach never blocks here and an unchanged owner does no work.
        // Generation-scoped retained proofs are re-checked against the observed
        // generation/epoch, so a proof admitted at an earlier generation reads
        // as unavailable instead of staying usable because it was retained.
        // #2647: an identical observation retires no in-flight delta basis;
        // only a real owner-context change does.
        readiness_projection
            .observe_owner(&guard)
            .map_err(|error| format!("startup readiness owner observation: {error}"))?;
        let readiness_verdict = eliotd::startup_readiness::evaluate_startup_readiness(
            &readiness_projection,
            &guard.status(),
            false,
        );
        let readiness_report = readiness_projection.report();
        // Same tolerance as `DaemonComposition::note_maintenance_trigger`: a
        // rejected evaluation is an explicit typed gap, never a daemon-killing
        // error, and the trigger stays durable for the next eligible pass.
        let blocked_automation = match guard.evaluate_maintenance_trigger_with_evidence(
            maintenance_observation(
                MaintenanceTriggerOrigin::AdmittedObservation,
                &[
                    format!("store_health={:?}", health.status),
                    health.manifest_digest.as_str().to_owned(),
                ],
                activation_in_flight,
            ),
        ) {
            Ok((decision, evidence)) => match guard.notification_state_admission_fence() {
                Ok(fence) => Some((fence, decision, evidence)),
                // A not-ready composition is a typed refusal, not a reason to
                // pretend there is no blocked automation: it is recorded with
                // the same minimal diagnostics the evaluation refusal uses.
                // #740 A14: both refusal records below gate on this tick
                // stream's guard, so a standing per-tick refusal cannot emit
                // unbounded repeats.
                Err(error) => {
                    if failure_guard.should_emit() {
                        let _ = eliotd::diagnostics::ErrorRecord::of_daemon_error(&error).emit();
                    }
                    None
                }
            },
            Err(error) => {
                if failure_guard.should_emit() {
                    let _ = eliotd::diagnostics::ErrorRecord::of_daemon_error(&error).emit();
                }
                None
            }
        };
        (readiness_verdict, readiness_report, blocked_automation)
    };
    if let Some((fence, decision, evidence)) = blocked_automation {
        note_blocked_automation_notification(kernel, fence, &decision, &evidence, failure_guard)
            .await;
    }
    // #2560: the same readiness evaluation that produced the startup record
    // reaches diagnostics here, so an operator sees exactly when a core
    // prerequisite is missing or an optional capability is degraded. A fully
    // healthy generation stays quiet rather than re-recording itself every
    // heartbeat: this is a change report, not a poll of every optional provider.
    if !readiness_verdict.core_satisfied() || readiness_verdict.capability_degraded {
        tracing::info!(
            target: "eliotd::diagnostics",
            event = "eliotd.startup_readiness_heartbeat",
            core_satisfied = readiness_verdict.core_satisfied(),
            readiness = %readiness_report,
        );
    }
    if let Some(producer) = supervision_progress {
        submit_supervision_heartbeat(kernel, producer, &health, activation_in_flight).await?;
    }
    Ok(())
}

/// Submits per-tick supervision progress from observed work (Implements #88,
/// wave 3).
///
/// One observation per due channel goes out in fixed channel order, adopting
/// the Kernel answer after each submit so later channels cite the fresh head.
/// A transport failure retries once with the byte-identical request (exact
/// replay is idempotent, never a second renewal); typed refusals converge
/// locally without retry. A refused or failed tick fails the daemon closed
/// exactly like the health poll it rides with.
async fn submit_supervision_heartbeat(
    kernel: &Arc<DaemonKernelClient>,
    producer: &mut eliotd::SupervisionProgressProducer,
    health: &StoreHealth,
    activation_in_flight: bool,
) -> Result<(), String> {
    // #740: heartbeat span. Outcomes and refusal codes are named; lease
    // material, cursors, and digests never enter the sink.
    let _span = tracing::info_span!("eliotd.supervision_heartbeat").entered();
    let inputs = eliotd::SupervisionTickInputs {
        store_ready: health.status == StoreHealthStatus::Ready,
        activation_in_flight,
    };
    let store_dimension = eliotd::store_dependency_dimension(health.status);
    for channel in [
        DaemonProgressChannel::Claim,
        DaemonProgressChannel::Dispatch,
        DaemonProgressChannel::Apply,
    ] {
        if !producer.submit_due(channel) {
            continue;
        }
        let request = producer.build_observation(channel, &inputs, store_dimension)?;
        let answer = match kernel.submit_supervision_progress(&request).await {
            Ok(answer) => answer,
            Err(first_error) => {
                kernel
                    .submit_supervision_progress(&request)
                    .await
                    .map_err(|error| {
                        format!("Kernel supervision progress submit: {first_error}; retry: {error}")
                    })?
            }
        };
        producer.adopt_answer(&answer)?;
        if let Some(outcome) = answer.outcome {
            tracing::info!(
                target: "eliotd::diagnostics",
                event = "eliotd.supervision_heartbeat_decided",
                outcome = outcome.as_str(),
            );
        } else if let Some(code) = answer.refusal_code.as_deref() {
            tracing::info!(
                target: "eliotd::diagnostics",
                event = "eliotd.supervision_heartbeat_refused",
                code = code,
            );
        }
    }
    Ok(())
}

/// Resolves one validated ticket under the already-held composition guard.
///
/// Returns `None` when the ticket expired at or after the Kernel deadline:
/// the resolver is never called and nothing is submitted or reconciled for
/// an expired ticket. Issue #2559: the caller reads the clock after its lock
/// wait and immediately before calling here, so expiry while waiting
/// prevents semantic resolution, including at the exact deadline boundary.
/// Otherwise resolves once through the v2 spine for the dispatch step to
/// submit verbatim.
///
/// Issue #1115: `kernel_owner` is the P-07 projection the caller captured
/// *before* this lock was taken, so a rotation after that read is refused by
/// Kernel at Session publication instead of being re-read under the semantic
/// lock. A readback failure is deferred for negative dispositions, which do
/// not create a Session and must remain independently reportable, so it is
/// surfaced only once a `Resolved` result actually needs the pair.
fn resolve_valid_ticket(
    composition: &DaemonComposition,
    kernel_owner: Result<Option<AgentActivationKernelOwnerReadback>, String>,
    ticket: AgentActivationResolutionTicket,
    now: u64,
) -> Result<Option<Box<ActivationResolvedTicket>>, String> {
    if activation_deadline_expired(now, ticket.kernel_deadline_unix_ms) {
        // Kernel owns the typed expiry outcome.  Do not call the resolver
        // at or after its exact deadline, and do not submit or reconcile an
        // expired ticket.
        return Ok(None);
    }
    // Single v2 result resolution per newly admitted ticket. The v2 resolver
    // maps all seven Governor outcomes to typed results; the Resolved arm
    // then obtains one independent current-owner readback below. Any Err is a
    // real validation/readiness failure and must fail closed rather than
    // silently discarding a disposition.
    //
    // #839 (W2/W15/A7): the loop dispatches through the
    // [`AgentActivationResolver`] boundary, not the inherent
    // `DaemonComposition` method. The inherent method and the trait method
    // share one name, so this fully qualified call is the trait-dispatch
    // production caller: the trait implementation on `DaemonComposition`
    // delegates to the same projection, and nothing about the resolved
    // result changes.
    let result = AgentActivationResolver::resolve_agent_activation_v2(composition, &ticket, now)
        .map_err(|error| {
            format!(
                "daemon activation resolve ticket {}: {error}",
                ticket.ticket_id
            )
        })?;
    let semantic_owner = if matches!(
        &result.disposition,
        AgentActivationResolutionDisposition::Resolved { .. }
    ) {
        Some(
            composition
                .current_activation_owner_readback(now)
                .map_err(|error| {
                    format!(
                        "daemon activation owner readback ticket {}: {error}",
                        ticket.ticket_id
                    )
                })?,
        )
    } else {
        None
    };
    // A Resolved result is submitted only with two current owner projections:
    // the semantic Governor binding and the exact P-07 revision/digest. The
    // P-07 pair was captured before this lock was taken and is checked under
    // the Kernel owner lock at submit time.
    let owner_readback = if matches!(
        &result.disposition,
        AgentActivationResolutionDisposition::Resolved { .. }
    ) {
        let semantic = semantic_owner.ok_or_else(|| {
            "Resolved activation result is missing its semantic owner readback".to_owned()
        })?;
        let kernel_owner = kernel_owner
            .map_err(|error| {
                format!(
                    "daemon activation Kernel owner readback ticket {}: {error}",
                    ticket.ticket_id
                )
            })?
            .ok_or_else(|| {
                format!(
                    "daemon activation Kernel owner is unbound for ticket {}",
                    ticket.ticket_id
                )
            })?;
        Some(
            semantic
                .with_kernel_owner_readback(kernel_owner)
                .map_err(|error| {
                    format!(
                        "daemon activation owner projection ticket {}: {error}",
                        ticket.ticket_id
                    )
                })?,
        )
    } else {
        None
    };
    Ok(Some(Box::new(ActivationResolvedTicket {
        ticket,
        result,
        owner_readback,
    })))
}

/// Starts the dispatch step for one resolved ticket, carrying the retained
/// result identity for submission and lost-acknowledgement reconciliation.
/// The retained bytes/digest are reused verbatim and never recomputed, and
/// the resolver is never invoked again under a new identity. Issue #1115: the
/// owner pair captured by the resolve step travels with the ticket, so this
/// flight performs no second Governor read.
fn start_activation_dispatch(
    kernel: &Arc<DaemonKernelClient>,
    resolved: ActivationResolvedTicket,
) -> ActivationFlightState {
    let retained = RetainedActivationIdentity {
        ticket_id: resolved.ticket.ticket_id.clone(),
        result_sha256: resolved.result.result_sha256.clone(),
    };
    let kernel_clone = Arc::clone(kernel);
    let future: Pin<Box<dyn std::future::Future<Output = ActivationCompletion>>> =
        Box::pin(async move {
            let outcome = dispatch_agent_activation_result(
                &kernel_clone,
                &resolved.ticket,
                resolved.result,
                resolved.owner_readback,
            )
            .await;
            ActivationCompletion::Dispatch(outcome)
        });
    ActivationFlightState {
        future,
        retained: Some(retained),
    }
}

/// Stage-aware shutdown drain for every already-started flight (issue
/// #2559). No new claim or heartbeat starts here; already-started claim,
/// resolve-wait, dispatch, local-read, observe, `TestD` owner, owner-feed,
/// heartbeat and retained cadence-maintenance steps keep being polled
/// together inside one declared finite budget. `request_shutdown` has already
/// been published, so an in-flight heartbeat may settle with a Kernel error;
/// the drain deliberately ignores that result and drops its producer without
/// applying deferred activity because no later heartbeat will be sent.
///
/// A claimed/waiting ticket carries no result digest yet, so exhausting the
/// budget while waiting or resolving settles as a clean shutdown: nothing
/// was submitted and the Kernel-owned ticket simply expires. A resolved and
/// submitting result keeps its retained identity instead: an unknown
/// acknowledgement or a budget exhausted mid-submit settles as a typed
/// unknown carrying the original ticket/result verbatim, never a fabricated
/// hash. Local-read, observe, `TestD` owner, owner-feed and maintenance steps
/// always settle as plain shutdown: an un-submitted pair's attempt capability is
/// revoked on disconnect, an already-persisted `TestD` decision
/// exact-replays, and a pending owner-feed publication leaves dependent
/// grants pending. Only non-heartbeat step failures fail closed. Dropping every
/// flight here also releases all owned composition references before the
/// existing final shutdown, without leaking detached work.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the shutdown drain polls every flight's borrowed state in one select and retains its bounded deadline"
)]
async fn drain_flights_on_shutdown(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    flight: &mut ActivationFlight,
    local_read_flight: &mut LocalReadFlight,
    observe_flight: &mut ObserveFlight,
    testd_owner_flight: &mut TestdOwnerFlight,
    owner_feed_flight: &mut OwnerFeedFlight,
    owner_feed: &mut Option<eliotd::OwnerFeedTrigger>,
    maintenance_flight: &mut MaintenanceFlight,
    improvement_intake_flight: &mut ImprovementIntakeFlight,
    health_heartbeat_flight: &mut HealthHeartbeatFlight,
    supervision_progress: &mut Option<eliotd::SupervisionProgressProducer>,
    deferred_activity: &mut DeferredSupervisionActivity,
    solo_poll_flight: &mut SoloPollFlight,
    solo_poll_last_refusal: &mut Option<String>,
) -> Result<RunLoopExit, String> {
    // #740: drain span. Idle drains and unknown-retention drains emit
    // distinct dispositions with the original identity verbatim.
    let _span = tracing::info_span!("eliotd.activation_drain").entered();
    let deadline = Instant::now() + SHUTDOWN_ACTIVATION_DRAIN;
    let mut no_supervision: Option<eliotd::SupervisionProgressProducer> = None;
    // #740 A14: the drain settles in-flight guards into this throwaway slot
    // because no new tick starts here; counts are meaningless at shutdown.
    let mut shutdown_failure_guard = RepeatedFailureGuard::new();
    let mut activation_exit = RunLoopExit::Shutdown;
    loop {
        if matches!(flight, ActivationFlight::Idle)
            && matches!(local_read_flight, LocalReadFlight::Idle)
            && matches!(observe_flight, ObserveFlight::Idle)
            && matches!(testd_owner_flight, TestdOwnerFlight::Idle)
            && matches!(owner_feed_flight, OwnerFeedFlight::Idle)
            && matches!(maintenance_flight, MaintenanceFlight::Idle)
            && matches!(improvement_intake_flight, ImprovementIntakeFlight::Idle)
            && matches!(health_heartbeat_flight, HealthHeartbeatFlight::Idle)
            && matches!(solo_poll_flight, SoloPollFlight::Idle)
        {
            return Ok(activation_exit);
        }
        tokio::select! {
            completion = next_activation_completion(flight) => {
                match completion {
                    ActivationCompletion::Claim(claim_outcome) => {
                        let claim = match claim_outcome {
                            Err(error) => return Err(error),
                            Ok(claim) => claim,
                        };
                        match settle_activation_claim(
                            claim,
                            &mut no_supervision,
                            health_heartbeat_flight,
                            deferred_activity,
                            false,
                        )? {
                            ActivationClaimStep::Idle => {
                                *flight = ActivationFlight::Idle;
                            }
                            ActivationClaimStep::Valid(ticket) => {
                                install_activation_resolve(kernel, composition, flight, *ticket);
                            }
                        }
                    }
                    ActivationCompletion::Resolve(resolve_outcome) => {
                        settle_activation_resolve_completion(kernel, flight, resolve_outcome)?;
                    }
                    ActivationCompletion::Dispatch(dispatch_outcome) => {
                        *flight = ActivationFlight::Idle;
                        match dispatch_outcome {
                            // #1115: a Kernel-owned deadline expiry carries no
                            // uncertain retention — the Kernel linearized the
                            // result-less expiry — so a drain that observes it
                            // settles as a clean shutdown exactly like an
                            // accepted dispatch, never as an unknown identity.
                            Ok(()) | Err(ActivationDispatchError::Expired) => {}
                            Err(ActivationDispatchError::Hard(error)) => return Err(error),
                            Err(ActivationDispatchError::Unknown {
                                ticket_id,
                                result_sha256,
                                detail,
                            }) => {
                                let _ = eliotd::diagnostics::emit_drain(
                                    eliotd::diagnostics::DrainOutcome::ActivationUnknown,
                                    &ticket_id,
                                    &result_sha256,
                                );
                                activation_exit = RunLoopExit::ShutdownActivationUnknown {
                                    ticket_id,
                                    result_sha256,
                                    detail,
                                };
                            }
                        }
                    }
                }
            }
            local_read_completion = next_local_read_completion(local_read_flight) => {
                // #2560: the bounded shutdown drain owns no readiness state, so
                // a capability-refused pair still settles here exactly like any
                // other. The loop's projection is untouched by this path.
                settle_local_read_completion(local_read_completion, local_read_flight)?;
            }
            observe_completion = next_observe_completion(observe_flight) => {
                // The observe drain owns no readiness state either: a
                // deferred, settled, expired, or stale pair settles here
                // exactly like any other. An un-submitted pair's attempt
                // capability is revoked on disconnect, mirroring the
                // local-read drain.
                settle_observe_completion(observe_completion, observe_flight)?;
            }
            testd_owner_completion = next_testd_owner_completion(testd_owner_flight) => {
                settle_testd_owner_completion(testd_owner_completion, testd_owner_flight)?;
            }
            owner_feed_trigger = next_owner_feed_completion(owner_feed_flight) => {
                settle_owner_feed_completion(
                    owner_feed_trigger,
                    owner_feed,
                    owner_feed_flight,
                    &mut shutdown_failure_guard,
                );
            }
            maintenance_guard = next_maintenance_completion(maintenance_flight) => {
                settle_maintenance_completion(
                    maintenance_guard,
                    maintenance_flight,
                    &mut shutdown_failure_guard,
                );
            }
            completion = next_improvement_intake_completion(improvement_intake_flight) => {
                settle_improvement_intake_completion(improvement_intake_flight, completion);
            }
            heartbeat_completion = next_health_heartbeat_completion(health_heartbeat_flight) => {
                discard_shutdown_heartbeat_completion(
                    heartbeat_completion,
                    health_heartbeat_flight,
                    supervision_progress,
                    deferred_activity,
                    &mut shutdown_failure_guard,
                );
            }
            solo_poll_completion = next_solo_poll_completion(solo_poll_flight) => {
                settle_solo_poll_completion(
                    solo_poll_completion,
                    solo_poll_flight,
                    solo_poll_last_refusal,
                );
            }
            () = tokio::time::sleep_until(deadline) => {
                // Budget exhausted with work still outstanding: drop every
                // flight without starting anything new. Classify activation
                // separately because only that stage can retain a result id.
                let exit = activation_exit_after_drain_timeout(flight, activation_exit);
                *local_read_flight = LocalReadFlight::Idle;
                *observe_flight = ObserveFlight::Idle;
                *testd_owner_flight = TestdOwnerFlight::Idle;
                *owner_feed_flight = OwnerFeedFlight::Idle;
                *maintenance_flight = MaintenanceFlight::Idle;
                *improvement_intake_flight = ImprovementIntakeFlight::Idle;
                *health_heartbeat_flight = HealthHeartbeatFlight::Idle;
                *solo_poll_flight = SoloPollFlight::Idle;
                *supervision_progress = None;
                deferred_activity.clear();
                return Ok(exit);
            }
        }
    }
}

/// Shutdown was requested before the drain. A heartbeat may return a Kernel
/// shutdown error, so only its producer is recovered; deferred observations
/// are discarded because this process will send no later supervision tick.
fn discard_shutdown_heartbeat_completion(
    completion: HealthHeartbeatCompletion,
    flight: &mut HealthHeartbeatFlight,
    supervision_progress: &mut Option<eliotd::SupervisionProgressProducer>,
    deferred_activity: &mut DeferredSupervisionActivity,
    failure_guard: &mut RepeatedFailureGuard,
) {
    let _ = settle_health_heartbeat_completion(
        completion,
        flight,
        supervision_progress,
        deferred_activity,
        false,
        failure_guard,
    );
}

/// Resolves the activation disposition when the shared shutdown budget ends.
/// Only a dispatch flight owns a result identity; claim and resolve flights
/// remain result-less and preserve the prior shutdown disposition.
fn activation_exit_after_drain_timeout(
    flight: &mut ActivationFlight,
    activation_exit: RunLoopExit,
) -> RunLoopExit {
    match std::mem::replace(flight, ActivationFlight::Idle) {
        ActivationFlight::Idle => activation_exit,
        ActivationFlight::InFlight(state) => match state.retained {
            Some(identity) => {
                let _ = eliotd::diagnostics::emit_drain(
                    eliotd::diagnostics::DrainOutcome::ActivationUnknown,
                    &identity.ticket_id,
                    &identity.result_sha256,
                );
                RunLoopExit::ShutdownActivationUnknown {
                    ticket_id: identity.ticket_id,
                    result_sha256: identity.result_sha256,
                    detail: "daemon shutdown drain timed out with activation submit outstanding; original ticket/result identity retained, no recompute"
                        .to_owned(),
                }
            }
            None => activation_exit,
        },
    }
}

/// The trigger travels with its in-flight sync step and returns on
/// completion, so exactly one trigger exists across passes: no clone of
/// mutable state and no renewal race.
struct OwnerFeedFlightState {
    future: Pin<
        Box<dyn std::future::Future<Output = (eliotd::OwnerFeedTrigger, RepeatedFailureGuard)>>,
    >,
}

/// Sole owner of owner-feed sync state in `run_loop`, mirroring
/// [`LocalReadFlight`]. `Idle` means no sync work is outstanding; `InFlight`
/// holds the one pending bounded exchange. No second owner and no second
/// concurrent exchange exist.
enum OwnerFeedFlight {
    Idle,
    InFlight(OwnerFeedFlightState),
}

/// Retains one idle-maintenance observation until its guarded evaluation
/// completes. The observation is captured from the activation state at start
/// time; no later tick replaces or mutates it while waiting for composition.
struct MaintenanceFlightState {
    future: Pin<Box<dyn std::future::Future<Output = RepeatedFailureGuard>>>,
}

/// Sole owner of the cadence maintenance observation currently being
/// evaluated. Keeping its lock wait in a polled flight prevents a selected
/// cadence handler from suspending polling of the owner-feed lock holder.
enum MaintenanceFlight {
    Idle,
    InFlight(MaintenanceFlightState),
}

/// Starts one O1 owner-feed synchronization pass (issue #2100) on its own
/// polled flight. The pass keeps its composition borrow inside the flight
/// future (issue #2559): when the owner borrow must span the Kernel
/// read->publish->readback exchange, that bounded future is retained as a
/// polled flight rather than awaited inside the health tick. The stream's
/// repeated-failure guard travels with the future exactly like the trigger
/// (#740 A14), so a standing feed failure cannot emit unbounded records.
fn maybe_start_owner_feed_sync(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    owner_feed: &mut Option<eliotd::OwnerFeedTrigger>,
    flight: &mut OwnerFeedFlight,
    failure_guard: &mut RepeatedFailureGuard,
) {
    if !matches!(flight, OwnerFeedFlight::Idle) {
        return;
    }
    let Some(trigger) = owner_feed.take() else {
        return;
    };
    let kernel_clone = Arc::clone(kernel);
    let composition_clone = Arc::clone(composition);
    let mut failure_guard = std::mem::replace(failure_guard, RepeatedFailureGuard::new());
    *flight = OwnerFeedFlight::InFlight(OwnerFeedFlightState {
        future: Box::pin(async move {
            let trigger = run_owner_feed_sync(
                &kernel_clone,
                composition_clone,
                trigger,
                &mut failure_guard,
            )
            .await;
            (trigger, failure_guard)
        }),
    });
}

/// Polls the one in-flight owner-feed step, pending forever while idle so
/// health and shutdown stay pollable with no step outstanding.
async fn next_owner_feed_completion(
    flight: &mut OwnerFeedFlight,
) -> (eliotd::OwnerFeedTrigger, RepeatedFailureGuard) {
    match flight {
        OwnerFeedFlight::Idle => {
            std::future::pending::<(eliotd::OwnerFeedTrigger, RepeatedFailureGuard)>().await
        }
        OwnerFeedFlight::InFlight(state) => (&mut state.future).await,
    }
}

/// Settles one completed owner-feed sync step back to idle, returning its
/// trigger for the next pass. Every outcome idles until the next trigger:
/// a proven publish was already recorded, and a degraded pass leaves grants
/// pending for a later pass. The feed never gates readiness and never fails
/// the daemon.
fn settle_owner_feed_completion(
    completion: (eliotd::OwnerFeedTrigger, RepeatedFailureGuard),
    owner_feed: &mut Option<eliotd::OwnerFeedTrigger>,
    flight: &mut OwnerFeedFlight,
    failure_guard: &mut RepeatedFailureGuard,
) {
    *owner_feed = Some(completion.0);
    *failure_guard = completion.1;
    *flight = OwnerFeedFlight::Idle;
}

/// Runs one O1 owner-feed synchronization pass (issue #2100) and records
/// its outcome.
///
/// A proven publish emits the bound revision for diagnostics; an unchanged
/// provider stays silent; a degraded pass emits an error record and the loop
/// continues, retrying on a later tick. The feed never gates readiness and
/// never fails the daemon: an unbound Kernel owner only leaves grants
/// pending, exactly like an absent P-07 port. Only the synchronous snapshot
/// capture holds the composition guard; Kernel reads and publication use the
/// owned plan after that guard is released so activation can claim and resolve
/// while the feed's sequential transport exchanges are pending.
async fn run_owner_feed_sync(
    kernel: &Arc<DaemonKernelClient>,
    composition: SharedComposition,
    mut trigger: eliotd::OwnerFeedTrigger,
    failure_guard: &mut RepeatedFailureGuard,
) -> eliotd::OwnerFeedTrigger {
    let plan = {
        let guard = composition.lock().await;
        eliotd::capture_owner_feed_plan(&guard)
    };
    let result = match plan {
        Ok(plan) => eliotd::maintain_owner_feed(plan, kernel, &mut trigger).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(Some(revision)) => {
            tracing::info!(
                target: "eliotd::diagnostics",
                event = "eliotd.owner_feed_published",
                revision = revision,
            );
        }
        Ok(None) => {}
        Err(error) => {
            // #740 A14: the feed retries on a later tick, so a standing
            // failure gates its record on this stream's guard instead of
            // emitting unbounded repeats.
            if failure_guard.should_emit() {
                let _ = eliotd::diagnostics::ErrorRecord::of(
                    eliotd::diagnostics::OwningComponent::DaemonRuntime,
                    "owner-feed",
                    &error.to_string(),
                )
                .emit();
            }
        }
    }
    trigger
}

/// Starts one local-read poll step for the outbound-only poller (Implements
/// #18): claim one queued admitted `eliot.query` pair, forward it through
/// the Kernel `local_read` leg, and submit its result body. At most one pair
/// per tick; a null claim backs off until the next tick.
fn start_local_read_poll(
    kernel: &Arc<DaemonKernelClient>,
    composition: SharedComposition,
    startup_readiness: StartupReadinessProjection,
) -> Pin<Box<dyn std::future::Future<Output = LocalReadCompletion>>> {
    let kernel_clone = Arc::clone(kernel);
    Box::pin(async move {
        LocalReadCompletion::Settled(
            run_local_read_poll(&kernel_clone, composition, startup_readiness).await,
        )
    })
}

/// Starts the local-read poll step when its flight is idle. Checked before
/// the activation gate on every tick so the poller stays live while an
/// activation is in flight.
fn maybe_start_local_read_poll(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    startup_readiness: &StartupReadinessProjection,
    flight: &mut LocalReadFlight,
) {
    if decide_local_read_tick(flight) == LocalReadTickDecision::StartPoll {
        *flight = LocalReadFlight::InFlight(LocalReadFlightState {
            // #2560/#2647: a bounded immutable snapshot travels with the step
            // as its decision basis; only an actually observed delta comes
            // back with it. The run loop keeps the only authoritative copy.
            future: start_local_read_poll(
                kernel,
                Arc::clone(composition),
                startup_readiness.clone(),
            ),
        });
    }
}

/// Polls the one in-flight local-read step, pending forever while idle so
/// health and shutdown stay pollable with no step outstanding.
async fn next_local_read_completion(flight: &mut LocalReadFlight) -> LocalReadCompletion {
    match flight {
        LocalReadFlight::Idle => std::future::pending::<LocalReadCompletion>().await,
        LocalReadFlight::InFlight(state) => (&mut state.future).await,
    }
}

/// Settles one completed local-read poll step back to idle. Every outcome —
/// null-poll backoff, accepted persist, the expected expiry race, or a stale
/// attempt quarantine (the next claim mints or returns the current
/// generation) — simply idles until the next tick; only a step failure fails
/// the daemon closed.
fn settle_local_read_completion(
    completion: LocalReadCompletion,
    flight: &mut LocalReadFlight,
) -> Result<(), String> {
    match completion {
        LocalReadCompletion::Settled(Ok(step)) => {
            // The poll outcome itself stays what it always was — a settle
            // signal, not a decision — but it is named rather than dropped, so
            // a capability refusal is distinguishable from an ordinary accept
            // in the loop's own record.
            tracing::info!(
                target: "eliotd::diagnostics",
                event = "eliotd.local_read_settled",
                outcome = local_read_outcome_name(&step.outcome),
                delta = local_read_delta_name(step.delta.as_ref()),
            );
            *flight = LocalReadFlight::Idle;
            Ok(())
        }
        LocalReadCompletion::Settled(Err(error)) => Err(error),
    }
}

/// Settles one completed local-read poll step and adopts the bounded delta the
/// step observed into the run loop's single authoritative projection (#2647).
///
/// Same settle contract as [`settle_local_read_completion`]; the only
/// difference is that a demand-driven capability observation the step produced
/// is filed through checked adoption — current basis only, one slot, loop
/// requirements and unrelated slots preserved — instead of replacing the whole
/// projection. A stale delta is refused without touching readiness, and the
/// step's own read/submit outcome still settles exactly once either way.
fn settle_local_read_completion_updating_readiness(
    completion: LocalReadCompletion,
    flight: &mut LocalReadFlight,
    startup_readiness: &mut StartupReadinessProjection,
) -> Result<(), String> {
    let LocalReadCompletion::Settled(Ok(step)) = &completion else {
        return settle_local_read_completion(completion, flight);
    };
    // Adopt the flight's own observation, if it made one, before the outcome
    // settles. Adoption is synchronous and touches at most one slot; a refused
    // delta leaves the loop's projection exactly as the heartbeat and earlier
    // adoptions left it.
    if let Some(delta) = &step.delta {
        let adoption = startup_readiness
            .adopt_local_delta(delta)
            .map_err(|error| format!("daemon local-read delta adoption: {error}"))?;
        tracing::info!(
            target: "eliotd::diagnostics",
            event = "eliotd.local_read_delta_adoption",
            outcome = local_read_outcome_name(&step.outcome),
            adoption = local_delta_adoption_name(&adoption),
            readiness = %startup_readiness.report(),
        );
    }
    settle_local_read_completion(completion, flight)
}

/// Names one settled local-read poll outcome for the loop's own record.
fn local_read_outcome_name(outcome: &LocalReadPollOutcome) -> &'static str {
    match outcome {
        LocalReadPollOutcome::IdleBackoff => "idle_backoff",
        LocalReadPollOutcome::Accepted => "accepted",
        LocalReadPollOutcome::Expired => "expired",
        LocalReadPollOutcome::StaleAttempt => "stale_attempt",
    }
}

/// Names the readiness delta one settled local-read step carried, if any.
fn local_read_delta_name(delta: Option<&LocalReadinessDelta>) -> &'static str {
    match delta {
        Some(delta) => delta.capability().as_str(),
        None => "none",
    }
}

/// Names one local-read delta adoption disposition for the loop's own record.
fn local_delta_adoption_name(adoption: &LocalDeltaAdoption) -> &'static str {
    match adoption {
        LocalDeltaAdoption::Adopted { .. } => "adopted",
        LocalDeltaAdoption::Duplicate => "duplicate",
        LocalDeltaAdoption::Stale { conflict } => match conflict {
            LocalDeltaConflict::OwnerContextChanged => "stale_owner_context",
            LocalDeltaConflict::SlotChanged => "stale_slot",
        },
    }
}

/// Derives the task-bound scope the reconstruction composition borrow pins
/// for one admitted pair (#2564 I6/A1).
///
/// The envelope work scope, else its session — never an MCP argument — exactly
/// as the reconstruction route's own trusted-scope derivation reads the same
/// admitted envelope. A pair with no usable scope fails the poll step before
/// any borrow, so an unscoped claim can never reach the reconstruction owner.
fn reconstruction_borrow_scope(
    envelope: &eliot_protocol::HostRequestEnvelope,
) -> Result<eliot_store_api::ScopeId, String> {
    let scope_text = envelope
        .identity
        .work_scope_id
        .as_deref()
        .filter(|scope| !scope.trim().is_empty())
        .or_else(|| {
            envelope
                .identity
                .session_id
                .as_deref()
                .filter(|scope| !scope.trim().is_empty())
        })
        .ok_or_else(|| "daemon reconstruction borrow binds no scope".to_owned())?;
    eliot_store_api::ScopeId::new(scope_text.to_owned())
        .map_err(|error| format!("daemon reconstruction borrow scope: {error}"))
}

/// Runs one local-read poll step: `local_read_claim` (pair plus fenced
/// attempt capability, or null meaning backoff), then
/// [`forward_admitted_local_read`] for the admitted pair under that attempt,
/// then `local_read_result` with the returned [`HostRequestResultBody`]
/// (accepted, the expected expiry race, or the stale-attempt quarantine).
/// Exact replays stay idempotent by Kernel contract. Any step failure fails
/// the daemon closed — a claimed pair that cannot forward or submit is never
/// silently discarded. A stale capability is never retried: the step settles
/// and the next tick claims the current generation anew.
#[expect(
    clippy::too_many_lines,
    reason = "ordered claim-forward-submit poll step stays whole: any step failure fails closed, never discards (#838)"
)]
async fn run_local_read_poll(
    kernel: &Arc<DaemonKernelClient>,
    composition: SharedComposition,
    startup_readiness: StartupReadinessProjection,
) -> Result<LocalReadStep, String> {
    // #740: receipt span over the claim/forward/submit poll step. Pair
    // presence and submit outcome are named; payload bytes never are.
    let _span = tracing::info_span!("eliotd.local_read_poll").entered();
    let pair = kernel
        .claim_local_read_pair_async()
        .await
        .map_err(|error| format!("Kernel local-read pair claim: {error}"))?;
    let Some((envelope, tool, attempt)) = pair else {
        // #2647: an empty claim observed nothing, so it carries no delta.
        return Ok(LocalReadStep {
            outcome: LocalReadPollOutcome::IdleBackoff,
            delta: None,
        });
    };
    let step = |outcome: LocalReadPollOutcome, delta: Option<LocalReadinessDelta>| LocalReadStep {
        outcome,
        delta,
    };
    // The Skill plan captures the admitted fence under a short guard, performs
    // canonical acceptance I/O with no composition lock, then commits against
    // a fresh guard only after rechecking that exact fence. Ordinary forwarded
    // reads use no composition state and keep the existing path.
    //
    // #1862: an admitted `eliot.packet` is deliberately NOT served here. It is
    // claimed, compiled and settled by the dedicated campaign-packet flight, so
    // this query-only Gateway leg can never reinterpret packet material as
    // `GetEvidencePack` selectors.
    // #1882: Skill pairs serve locally through the composition Skill driver
    // instead of forwarding on the Kernel `local_read` leg (which serves
    // store reads only). Recognition is the shared Skill tool predicate over
    // the pair's tool name; anything else keeps the existing forward path
    // byte-identical. The served result body submits through the same
    // idempotent leg below, so claimed skill pairs settle exactly like
    // forwarded ones.
    //
    // #2560: a request that names an unavailable startup capability is refused
    // specifically, and only that request is. The check runs before the
    // composition guard is taken (it needs no owner state) and before any
    // dispatch, so a refusal never blocks on the Skill driver and never stops
    // an unrelated admitted read. The claimed pair still settles through the
    // same idempotent submit leg, so a capability refusal is never a dropped
    // pair.
    if eliotd::skill_dispatch::is_skill_tool(&tool) {
        // #2647: one demand-driven attempt per flight. The attach runs at most
        // once here; its observation travels with the step whether this demand
        // is refused or served, and the loop adopts it only while the
        // snapshot's basis is still current.
        let (refused, delta) = skill_capability_refusal(&startup_readiness)?;
        if let Some(refusal) = refused {
            let body = eliotd::skill_dispatch::skill_result_body(
                &envelope,
                &attempt,
                &eliot_agent_bridge_core::SkillResultEnvelope::refused(
                    &eliot_skill::SkillError::Surface(refusal.clone()),
                ),
            )
            .map_err(|error| format!("daemon skill capability refusal body: {error}"))?;
            let outcome = match submit_local_read_result_idempotent(kernel, &body).await? {
                LocalReadSubmitOutcome::Accepted => LocalReadPollOutcome::Accepted,
                LocalReadSubmitOutcome::Expired => LocalReadPollOutcome::Expired,
                LocalReadSubmitOutcome::StaleAttempt => LocalReadPollOutcome::StaleAttempt,
            };
            return Ok(step(outcome, delta));
        }
        // #2664: the execute leg also reads the owner-retained execution
        // position, and that read is a plain in-process owner lookup. It runs
        // under the SAME short composition borrow that snapshots the fence and
        // the borrow is dropped before the plan runs, so no composition guard
        // is ever held across the plan's canonical reads or its awaits.
        let (admitted_fence, execution_owner_read) = {
            let guard = composition.lock().await;
            (
                guard.kernel_snapshot().state_fence().clone(),
                eliotd::skill_dispatch::execution_owner_read(&guard, &tool),
            )
        };
        let plan = Box::pin(eliotd::skill_dispatch::plan_skill_pair(
            kernel,
            admitted_fence,
            execution_owner_read,
            &envelope,
            &tool,
            &attempt,
        ))
        .await;
        let body = {
            // #1957: the commit step also hydrates the daemon-held Governor
            // capability admission view from the canonical evidence read this
            // intake already performed, so the guard is taken mutably here.
            let mut guard = composition.lock().await;
            eliotd::skill_dispatch::commit_skill_pair(&mut guard, &envelope, &attempt, plan)
        };
        let outcome = match submit_local_read_result_idempotent(kernel, &body).await? {
            LocalReadSubmitOutcome::Accepted => LocalReadPollOutcome::Accepted,
            LocalReadSubmitOutcome::Expired => LocalReadPollOutcome::Expired,
            LocalReadSubmitOutcome::StaleAttempt => LocalReadPollOutcome::StaleAttempt,
        };
        return Ok(step(outcome, delta));
    }
    // #1187 W1/A1: a claimed pair naming the broker-owned operator read
    // capability is served here, not forwarded on the Kernel `local_read` leg,
    // because that leg serves store reads only. The branch builds one board
    // over one immutable Governor snapshot and performs exactly one
    // authenticated role-filtered read on it, so the canonical role-filtered
    // view — or the board's exact typed refusal, including a `PlanGap` naming
    // the missing owner — is served from the live daemon path instead of being
    // composed into a board nobody reads. Every claimed pair, refusal included,
    // settles through the same idempotent submit leg below, so a ControlBoard
    // read can never poison the poller or drop a pair. The composition guard is
    // held only around the read; it never crosses the submit leg.
    //
    // NOT REACHABLE AT RUNTIME for `operator.command` (#1187 piece C,
    // re-verified against the current source of both crates). No production
    // `operator.command` pair can reach the predicate below. The shared local-read carrier
    // now admits `eliot.query` and the four `skill.*` lifecycle tools; closing
    // the Operator gap still takes FOUR independent gates, not one. Each is
    // cited by symbol rather than by line, because a line number in a comment
    // is wrong the next time the file moves:
    //
    // 1. Queue. `host_request_route::KernelComposition::invoke_read_host_request`
    //    is the only production entry that queues a pair for this poller, and it
    //    queues only what `host_request_route::check_local_read_admission`
    //    resolves. That routes through
    //    `host_request_route::local_read_admission_from_tool`, whose closed
    //    `match` admits `eliot.packet`, `eliot.query`, and the exact-capability
    //    Skill tools `skill.inject`, `skill.display`, `skill.activate`, and
    //    `skill.execute`; every other name, including `operator.command`, is
    //    refused. The fallback
    //    `host_request_route::daemon_claim_queue::check_task_controller_admission`
    //    does not route `operator.command` to this poller either.
    // 2. Claim. `host_request_route::KernelComposition::claim_local_read_pair`
    //    rechecks the retained pair and only claims `Query` or `Skill`
    //    admissions. `operator.command` matches neither admission.
    // 3. Claim receipt. `daemon_kernel_client::DaemonKernelClient::claim_local_read_pair_async`
    //    independently allows `eliot.query` or one of the four names returned
    //    by `skill_tool_kind`, and requires an exact envelope-capability/tool
    //    name match. It refuses `operator.command`. That gate is production
    //    code inside `bins/eliotd` — not a test — and it sits on the same
    //    `local_read_claim` wire operation as gate 2.
    // 4. Submit. `host_request_route::KernelComposition::submit_local_read_result`
    //    delegates to `submit_claimed_result`, whose local-read queue accepts
    //    only `eliot.query` or `is_skill_lifecycle_tool(capability)`. A claimed
    //    `operator.command` pair could not settle its own result body either.
    //
    // A fifth gap sits upstream of all four and is not a gate at all: nothing in
    // this repository presents a host request naming this capability. The only
    // production envelope builder is `kernel_host_request_client::finish_envelope`
    // in `eliot-agent-bridge`; its tool surface is the closed `ADMITTED_TOOL_NAMES`
    // set in `eliot_mcp::contract` (eight `eliot.*` names, and this is not one of
    // them); and the Operator's own closed set in
    // `apps/Eliot.Operator/Protocol/OperatorIntent.cs::LegacyOperatorAdapter::AdmittedTools`
    // does not carry it either.
    //
    // Gates 1, 2 and 4 are one Kernel act in `host_request_route.rs`, and doing
    // only that is worse than doing nothing: it would hand this poller a pair
    // that gate 3 refuses, and a refused claim is a step failure, which
    // `settle_local_read_completion` escalates into a failed daemon. Gate 3 and
    // the absent producer are separate owner acts in files this lane does not
    // own, so this branch stays source-reachable only.
    //
    // #1882: the four `skill.*` lifecycle capabilities now pass their own
    // closed admission, claim, daemon validation and submit gates; this
    // ControlBoard analysis does not apply to the Skill branch above. For
    // `operator.command`, adding a branch would NOT create a production caller,
    // and claiming one would be false: none of the four gates admits that
    // capability, and no producer presents it either.
    if eliotd::is_controlboard_read_tool(&tool) {
        let body = match eliotd::notification_board_attach::fetch_notification_snapshot(kernel)
            .await
        {
            Ok(snapshot) => {
                let mut guard = composition.lock().await;
                let kernel_fence = kernel.snapshot().state_fence();
                let composition_fence = guard.kernel_snapshot().state_fence();
                if snapshot.state_fence != kernel_fence || snapshot.state_fence != composition_fence
                {
                    eliotd::controlboard_notification_refresh_refusal_body(
                        &envelope,
                        &attempt,
                        "Kernel or composition state fence changed before notification attach",
                    )
                } else {
                    guard.note_notification_snapshot(snapshot.records);
                    eliotd::serve_controlboard_view(&guard, &envelope, &attempt)
                }
            }
            Err(reason) => {
                eliotd::controlboard_notification_refresh_refusal_body(&envelope, &attempt, &reason)
            }
        };
        let outcome = match submit_local_read_result_idempotent(kernel, &body).await? {
            LocalReadSubmitOutcome::Accepted => LocalReadPollOutcome::Accepted,
            LocalReadSubmitOutcome::Expired => LocalReadPollOutcome::Expired,
            LocalReadSubmitOutcome::StaleAttempt => LocalReadPollOutcome::StaleAttempt,
        };
        // #2647: this leg builds a board over the composition and reads it; it
        // attaches no startup capability and re-evaluates no readiness, so the
        // flight observed nothing and carries no delta. Settling it therefore
        // cannot overwrite owner observations the loop recorded meanwhile, the
        // same contract the ordinary forwarded read below settles under.
        return Ok(step(outcome, None));
    }
    // #2857: an admitted `eliot.query` whose explicit intent mode is
    // `context_reconstruction` is the one request that owns Context
    // reconstruction, so it is served HERE by the selector-complete
    // reconstruction route instead of being forwarded on the Kernel
    // `local_read` leg. That leg answers a single `GetEvidencePack` read and
    // cannot express the six-read closure; the reconstruction route derives
    // every identity from this admitted pair plus the retained authenticated
    // Kernel session, resolves the closed selector set from the authenticated
    // Task Controller owner, and calls
    // `KernelContextReadClient::reconstruct_context_inputs` — the existing
    // Governor composition edge over `GovernorContextInputs`. The closure is
    // input reconstruction, never an admitted view. A prerequisite refusal
    // (missing owner identity, unbound attempt, moved fence) is a typed daemon
    // step failure, exactly like a forward or submit failure, so the claimed
    // pair is never silently dropped. Every other query shape keeps the
    // forwarded path byte-identical.
    if eliotd::is_context_reconstruction_query(&envelope, &tool) {
        // #2564 (I6/A1): this branch is the live production invocation of the
        // reconstruction owner behind `serve_context_reconstruction`
        // (`daemon_runtime.rs::run_local_read_poll` — not the activation
        // `submit_agent_activation_result` leg, which serves no state/packet
        // pair). The serve is reached through the daemon composition's
        // `DaemonComposition::reconstruction_composition` borrow: readiness is
        // checked there, and the exact admitted fence plus the task-bound
        // scope are pinned at borrow time. The guard is dropped before any
        // owner read, so no composition lock crosses the reconstruction
        // awaits. A refused borrow, or a fence pin that no longer matches the
        // admitted pair, is a typed step failure like any other prerequisite
        // refusal, so the claimed pair is never silently discarded.
        let reads = KernelContextReadClient::new(Arc::clone(kernel));
        let scope = reconstruction_borrow_scope(&envelope)?;
        {
            let guard = composition.lock().await;
            let borrowed = guard
                .reconstruction_composition(kernel, &reads, scope)
                .map_err(|error| format!("daemon reconstruction composition: {error}"))?;
            if *borrowed.admitted_fence() != envelope.state_fence {
                return Err("daemon reconstruction fence moved before serve".to_owned());
            }
        }
        let body = Box::pin(eliotd::serve_context_reconstruction(
            kernel, &envelope, &tool, &attempt,
        ))
        .await
        .map_err(|error| format!("daemon context reconstruction: {error}"))?;
        let outcome = match submit_local_read_result_idempotent(kernel, &body).await? {
            LocalReadSubmitOutcome::Accepted => LocalReadPollOutcome::Accepted,
            LocalReadSubmitOutcome::Expired => LocalReadPollOutcome::Expired,
            LocalReadSubmitOutcome::StaleAttempt => LocalReadPollOutcome::StaleAttempt,
        };
        return Ok(step(outcome, None));
    }
    let body = forward_admitted_local_read(kernel, envelope, tool, attempt)
        .await
        .map_err(|error| format!("daemon local-read forward: {error}"))?;
    let outcome = match submit_local_read_result_idempotent(kernel, &body).await? {
        LocalReadSubmitOutcome::Accepted => LocalReadPollOutcome::Accepted,
        LocalReadSubmitOutcome::Expired => LocalReadPollOutcome::Expired,
        LocalReadSubmitOutcome::StaleAttempt => LocalReadPollOutcome::StaleAttempt,
    };
    // #2647: an ordinary forwarded read produces no readiness observation.
    Ok(step(outcome, None))
}

/// Re-evaluates the Skill startup capabilities this demand names, and returns
/// the exact refusal when one of them is still unavailable afterwards (#2560).
///
/// The demand-driven refresh runs against a working copy of the flight's
/// immutable snapshot, so the refusal decision observes the real attach
/// outcome without mutating any shared state (#2647). The observation the
/// attach actually produced — if it ran at all — travels back as the step's
/// bounded delta, bound to this snapshot's basis; the loop adopts it only
/// while that basis is still current.
///
/// Thin seam over [`eliotd::startup_readiness::reevaluate_demanded_capability`]:
/// the real owner attach is supplied here because this is the module that owns
/// it, and the readiness module stays IO-free.
fn skill_capability_refusal(
    snapshot: &StartupReadinessProjection,
) -> Result<(Option<String>, Option<LocalReadinessDelta>), String> {
    let mut working = snapshot.clone();
    let mut observed: Option<Result<RetainedStartupBinding, String>> = None;
    eliotd::startup_readiness::reevaluate_demanded_capability(
        &mut working,
        DeclaredStartupCapability::SkillToolSource,
        || {
            let outcome = attach_skill_tool_source().map(|admitted_definition_version| {
                RetainedStartupBinding::SkillToolSource {
                    admitted_definition_version,
                }
            });
            observed = Some(outcome.clone());
            outcome
        },
    )
    .map_err(|error| format!("daemon skill capability refresh: {error}"))?;
    let refusal = eliotd::startup_readiness::refuse_unavailable_capabilities(
        &working,
        &[
            DeclaredStartupCapability::SkillToolSource,
            DeclaredStartupCapability::SkillToolBasis,
        ],
    );
    let delta = observed.map(|observed| {
        snapshot.prepare_local_delta(eliotd::startup_readiness::CapabilityRefresh {
            capability: DeclaredStartupCapability::SkillToolSource,
            reason: eliotd::startup_readiness::StartupRefreshReason::CapabilityDemanded,
            observed,
        })
    });
    Ok((refusal, delta))
}

/// Submits one forwarded local-read result body, retrying once with the
/// byte-identical body when the first submit fails.
///
/// This is the local-read twin of the activation lost-acknowledgement
/// reconcile: the retained body is reused verbatim, never recomputed, and no
/// local replay cache or timer is introduced. The retry is safe because the
/// Kernel submit leg is exact-replay idempotent — an identical body under the
/// same identity persists once and replays, never duplicates. Only transport
/// failures retry: `Expired` and `StaleAttempt` are settled outcomes, so a
/// quarantined capability is never resubmitted.
async fn submit_local_read_result_idempotent(
    kernel: &DaemonKernelClient,
    body: &eliot_protocol::HostRequestResultBody,
) -> Result<LocalReadSubmitOutcome, String> {
    match kernel.submit_local_read_result_async(body).await {
        Ok(outcome) => Ok(outcome),
        Err(first_error) => kernel
            .submit_local_read_result_async(body)
            .await
            .map_err(|error| {
                format!("Kernel local-read result submit: {first_error}; retry: {error}")
            }),
    }
}

/// What one settled observe poll step produced (issue #2565).
///
/// `Deferred` is the honest steady state while the Governor observation
/// owner has no connected admission: the pair retired, the durable record
/// `Routed`, no effect produced. `Settled` means the record already closed.
/// `Expired` is the expected claim/defer race; `StaleAttempt` quarantines a
/// superseded capability (the next claim mints the current generation anew).
/// Every outcome idles until the next tick; only a step failure fails the
/// daemon closed.
enum ObservePollOutcome {
    IdleBackoff,
    Deferred,
    Settled,
    Expired,
    StaleAttempt,
}

/// Completion of one in-flight observe step. Claim, serve, and defer share
/// one flight branch so health and shutdown stay pollable while the step is
/// outstanding; the step handles at most one pair per tick.
enum ObserveCompletion {
    Settled(Result<ObserveStep, String>),
}

/// What one settled observe step produced: its poll outcome plus the exact
/// owner identity the serve named, so the loop's own record distinguishes
/// which admission is still missing without reading payload bytes.
struct ObserveStep {
    /// The poll outcome the loop acts on.
    outcome: ObservePollOutcome,
    /// Served suboperation discriminator (`None` on an empty claim).
    suboperation: Option<&'static str>,
    /// Missing owner admission the serve named (`None` on an empty claim).
    owner_capability: Option<&'static str>,
    /// Residual program that owns the missing semantics (`None` on an empty claim).
    residual_owner: Option<&'static str>,
    /// Exact condition that resumes the deferred pair (`None` on an empty claim).
    resume: Option<&'static str>,
}

struct ObserveFlightState {
    future: Pin<Box<dyn std::future::Future<Output = ObserveCompletion>>>,
}

/// Sole owner of observe poll state in `run_loop`, mirroring
/// [`LocalReadFlight`]. `Idle` means no observe work is outstanding;
/// `InFlight` holds the one pending poll step. No second owner and no second
/// concurrent observe step exist.
enum ObserveFlight {
    Idle,
    InFlight(ObserveFlightState),
}

/// Pure tick gate: the observe timer starts work only when the flight is
/// idle. The in-flight step is polled in its own `select!` branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObserveTickDecision {
    StartPoll,
    SkipInFlight,
}

fn decide_observe_tick(flight: &ObserveFlight) -> ObserveTickDecision {
    match flight {
        ObserveFlight::Idle => ObserveTickDecision::StartPoll,
        ObserveFlight::InFlight(_) => ObserveTickDecision::SkipInFlight,
    }
}

fn start_observe_poll(
    kernel: &Arc<DaemonKernelClient>,
) -> Pin<Box<dyn std::future::Future<Output = ObserveCompletion>>> {
    let kernel_clone = Arc::clone(kernel);
    Box::pin(async move { ObserveCompletion::Settled(run_observe_poll(&kernel_clone).await) })
}

/// Starts the observe poll step when its flight is idle. Checked on the same
/// tick as the other pollers so the observe queue stays live while an
/// activation or a local read is in flight.
fn maybe_start_observe_poll(kernel: &Arc<DaemonKernelClient>, flight: &mut ObserveFlight) {
    if decide_observe_tick(flight) == ObserveTickDecision::StartPoll {
        *flight = ObserveFlight::InFlight(ObserveFlightState {
            future: start_observe_poll(kernel),
        });
    }
}

/// Polls the one in-flight observe step, pending forever while idle so
/// health and shutdown stay pollable with no step outstanding.
async fn next_observe_completion(flight: &mut ObserveFlight) -> ObserveCompletion {
    match flight {
        ObserveFlight::Idle => std::future::pending::<ObserveCompletion>().await,
        ObserveFlight::InFlight(state) => (&mut state.future).await,
    }
}

/// Settles one completed observe step back to idle. Every outcome — null-poll
/// backoff, honest deferral, settled record, the expected expiry race, or a
/// stale attempt quarantine (the next claim mints or returns the current
/// generation) — simply idles until the next tick; only a step failure fails
/// the daemon closed.
fn settle_observe_completion(
    completion: ObserveCompletion,
    flight: &mut ObserveFlight,
) -> Result<(), String> {
    match completion {
        ObserveCompletion::Settled(Ok(step)) => {
            tracing::info!(
                target: "eliotd::diagnostics",
                event = "eliotd.observe_settled",
                outcome = observe_outcome_name(&step.outcome),
                suboperation = step.suboperation.unwrap_or("none"),
                owner_capability = step.owner_capability.unwrap_or("none"),
                residual_owner = step.residual_owner.unwrap_or("none"),
                resume = step.resume.unwrap_or("none"),
            );
            *flight = ObserveFlight::Idle;
            Ok(())
        }
        ObserveCompletion::Settled(Err(error)) => Err(error),
    }
}

/// Names one settled observe poll outcome for the loop's own record.
fn observe_outcome_name(outcome: &ObservePollOutcome) -> &'static str {
    match outcome {
        ObservePollOutcome::IdleBackoff => "idle_backoff",
        ObservePollOutcome::Deferred => "deferred",
        ObservePollOutcome::Settled => "settled",
        ObservePollOutcome::Expired => "expired",
        ObservePollOutcome::StaleAttempt => "stale_attempt",
    }
}

/// Runs one observe poll step: `semantic_observe_claim` (pair plus fenced
/// attempt capability, or null meaning backoff), then
/// [`serve_admitted_observe`] for the admitted pair under that attempt, then
/// `semantic_observe_deferred` with the served deferral (deferred, settled,
/// the expected expiry race, or the stale-attempt quarantine). Exact
/// replays stay idempotent by Kernel contract. Any step failure fails the
/// daemon closed — a claimed pair that cannot serve or defer is never
/// silently discarded. A stale capability is never retried: the step settles
/// and the next tick claims the current generation anew.
async fn run_observe_poll(kernel: &DaemonKernelClient) -> Result<ObserveStep, String> {
    // #740: receipt span over the claim/serve/defer poll step. Pair
    // presence and defer outcome are named; payload bytes never are.
    let _span = tracing::info_span!("eliotd.observe_poll").entered();
    let pair = kernel
        .claim_observe_pair_async()
        .await
        .map_err(|error| format!("Kernel observe pair claim: {error}"))?;
    let Some((envelope, tool, attempt)) = pair else {
        return Ok(ObserveStep {
            outcome: ObservePollOutcome::IdleBackoff,
            suboperation: None,
            owner_capability: None,
            residual_owner: None,
            resume: None,
        });
    };
    let operation_id = host_request_operation_id(&envelope);
    let request_digest = envelope.envelope_sha256.clone();
    let deferral = serve_admitted_observe(&envelope, &tool, &attempt)
        .map_err(|error| format!("daemon observe serve: {error}"))?;
    let step = |outcome: ObservePollOutcome| ObserveStep {
        outcome,
        suboperation: Some(deferral.suboperation.as_str()),
        owner_capability: Some(deferral.owner_capability),
        residual_owner: Some(deferral.residual_owner),
        resume: Some(deferral.resume),
    };
    let outcome =
        match defer_observe_pair_idempotent(kernel, &operation_id, &request_digest, &attempt)
            .await?
        {
            ObserveDeferOutcome::Deferred => ObservePollOutcome::Deferred,
            ObserveDeferOutcome::Settled => ObservePollOutcome::Settled,
            ObserveDeferOutcome::Expired => ObservePollOutcome::Expired,
            ObserveDeferOutcome::StaleAttempt => ObservePollOutcome::StaleAttempt,
        };
    Ok(step(outcome))
}

/// Defers one served observe pair, retrying once with byte-identical
/// arguments when the first defer fails.
///
/// The retry is safe because the Kernel defer leg is idempotent — an
/// identical defer under the same live attempt retires once and replays
/// (`Routed` stays `Routed`), never duplicates. Only transport failures
/// retry: `Expired`, `Settled`, and `StaleAttempt` are settled outcomes, so
/// a quarantined capability is never resubmitted.
async fn defer_observe_pair_idempotent(
    kernel: &DaemonKernelClient,
    operation_id: &str,
    request_digest: &str,
    attempt: &eliot_protocol::LocalReadAttempt,
) -> Result<ObserveDeferOutcome, String> {
    match kernel
        .defer_observe_claim_async(operation_id, request_digest, attempt)
        .await
    {
        Ok(outcome) => Ok(outcome),
        Err(first_error) => kernel
            .defer_observe_claim_async(operation_id, request_digest, attempt)
            .await
            .map_err(|error| format!("Kernel observe defer: {first_error}; retry: {error}")),
    }
}

/// Starts one campaign-packet claim/compile/result step. The packet route is
/// independent from both the query Gateway and Task Controller transitions.
fn start_campaign_packet_poll(
    kernel: &Arc<DaemonKernelClient>,
) -> Pin<Box<dyn std::future::Future<Output = CampaignPacketCompletion>>> {
    let kernel_clone = Arc::clone(kernel);
    Box::pin(async move {
        CampaignPacketCompletion::Settled(run_campaign_packet_poll(&kernel_clone).await)
    })
}

fn maybe_start_campaign_packet_poll(
    kernel: &Arc<DaemonKernelClient>,
    flight: &mut CampaignPacketFlight,
) {
    if decide_campaign_packet_tick(flight) == CampaignPacketTickDecision::StartPoll {
        *flight = CampaignPacketFlight::InFlight(CampaignPacketFlightState {
            future: start_campaign_packet_poll(kernel),
        });
    }
}

async fn next_campaign_packet_completion(
    flight: &mut CampaignPacketFlight,
) -> CampaignPacketCompletion {
    match flight {
        CampaignPacketFlight::Idle => std::future::pending::<CampaignPacketCompletion>().await,
        CampaignPacketFlight::InFlight(state) => (&mut state.future).await,
    }
}

fn settle_campaign_packet_completion(
    completion: CampaignPacketCompletion,
    flight: &mut CampaignPacketFlight,
) -> Result<(), String> {
    match completion {
        CampaignPacketCompletion::Settled(Ok(_)) => {
            *flight = CampaignPacketFlight::Idle;
            Ok(())
        }
        CampaignPacketCompletion::Settled(Err(error)) => Err(error),
    }
}

/// Claims one packet from the packet queue, compiles it from authenticated
/// owner reads, and submits only through the packet result route. No branch in
/// this function projects packet material as `GetEvidencePack` selectors.
async fn run_campaign_packet_poll(
    kernel: &DaemonKernelClient,
) -> Result<CampaignPacketPollOutcome, String> {
    let _span = tracing::info_span!("eliotd.campaign_packet_poll").entered();
    let pair = kernel
        .claim_campaign_packet_pair_async()
        .await
        .map_err(|error| format!("Kernel campaign-packet pair claim: {error}"))?;
    let Some((envelope, tool, attempt)) = pair else {
        return Ok(CampaignPacketPollOutcome::IdleBackoff);
    };
    let body =
        eliotd::campaign_packet::serve_campaign_packet_pair(kernel, &envelope, &tool, &attempt)
            .await
            .map_err(|error| format!("daemon campaign packet compilation: {error}"))?;
    match submit_campaign_packet_result_idempotent(kernel, &body).await? {
        LocalReadSubmitOutcome::Accepted => Ok(CampaignPacketPollOutcome::Accepted),
        LocalReadSubmitOutcome::Expired => Ok(CampaignPacketPollOutcome::Expired),
        LocalReadSubmitOutcome::StaleAttempt => Ok(CampaignPacketPollOutcome::StaleAttempt),
    }
}

async fn submit_campaign_packet_result_idempotent(
    kernel: &DaemonKernelClient,
    body: &eliot_protocol::HostRequestResultBody,
) -> Result<LocalReadSubmitOutcome, String> {
    match kernel.submit_campaign_packet_result_async(body).await {
        Ok(outcome) => Ok(outcome),
        Err(first_error) => kernel
            .submit_campaign_packet_result_async(body)
            .await
            .map_err(|error| {
                format!("Kernel campaign-packet result submit: {first_error}; retry: {error}")
            }),
    }
}

async fn drain_campaign_packet_on_shutdown(
    flight: &mut CampaignPacketFlight,
) -> Result<RunLoopExit, String> {
    let previous = std::mem::replace(flight, CampaignPacketFlight::Idle);
    let CampaignPacketFlight::InFlight(state) = previous else {
        return Ok(RunLoopExit::Shutdown);
    };
    match tokio::time::timeout(SHUTDOWN_ACTIVATION_DRAIN, state.future).await {
        Ok(CampaignPacketCompletion::Settled(Err(error))) => Err(error),
        _ => Ok(RunLoopExit::Shutdown),
    }
}

/// Settled outcome of one state poll step (#2564 Slice 1). The state flight
/// owns a distinct queue/attempt/result lifecycle (`state_claim` /
/// `state_result`) and never shares a completion with the query flight: a
/// query, Skill or packet result can never complete a State claim.
enum StatePollOutcome {
    IdleBackoff,
    Accepted,
    Expired,
    StaleAttempt,
}

enum StateCompletion {
    Settled(Result<StatePollOutcome, String>),
}

struct StateFlightState {
    future: Pin<Box<dyn std::future::Future<Output = StateCompletion>>>,
}

enum StateFlight {
    Idle,
    InFlight(StateFlightState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateTickDecision {
    StartPoll,
    SkipInFlight,
}

fn decide_state_tick(flight: &StateFlight) -> StateTickDecision {
    match flight {
        StateFlight::Idle => StateTickDecision::StartPoll,
        StateFlight::InFlight(_) => StateTickDecision::SkipInFlight,
    }
}

fn start_state_poll(
    kernel: &Arc<DaemonKernelClient>,
    composition: SharedComposition,
) -> Pin<Box<dyn std::future::Future<Output = StateCompletion>>> {
    let kernel_clone = Arc::clone(kernel);
    Box::pin(async move {
        StateCompletion::Settled(run_state_poll(&kernel_clone, composition).await)
    })
}

fn maybe_start_state_poll(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    flight: &mut StateFlight,
) {
    if decide_state_tick(flight) == StateTickDecision::StartPoll {
        *flight = StateFlight::InFlight(StateFlightState {
            future: start_state_poll(kernel, Arc::clone(composition)),
        });
    }
}

async fn next_state_completion(flight: &mut StateFlight) -> StateCompletion {
    match flight {
        StateFlight::Idle => std::future::pending::<StateCompletion>().await,
        StateFlight::InFlight(state) => (&mut state.future).await,
    }
}

fn settle_state_completion(
    completion: StateCompletion,
    flight: &mut StateFlight,
) -> Result<(), String> {
    match completion {
        StateCompletion::Settled(Ok(_)) => {
            *flight = StateFlight::Idle;
            Ok(())
        }
        StateCompletion::Settled(Err(error)) => Err(error),
    }
}

/// Runs one state poll step: `state_claim` (pair plus fenced attempt
/// capability, or null meaning backoff), then [`serve_state_pair`] for the
/// admitted pair under that attempt, then `state_result` with the returned
/// [`HostRequestResultBody`] (accepted, the expected expiry race, or the
/// stale-attempt quarantine). Exact replays stay idempotent by Kernel
/// contract. Any step failure fails the daemon closed — a claimed pair that
/// cannot serve or submit is never silently discarded. A stale capability is
/// never retried: the step settles and the next tick claims the current
/// generation anew.
async fn run_state_poll(
    kernel: &Arc<DaemonKernelClient>,
    composition: SharedComposition,
) -> Result<StatePollOutcome, String> {
    // #740: receipt span over the claim/serve/submit poll step. Pair
    // presence and submit outcome are named; payload bytes never are.
    let _span = tracing::info_span!("eliotd.state_poll").entered();
    let pair = kernel
        .claim_state_pair_async()
        .await
        .map_err(|error| format!("Kernel state pair claim: {error}"))?;
    let Some((envelope, tool, attempt)) = pair else {
        return Ok(StatePollOutcome::IdleBackoff);
    };
    let body = serve_state_pair(kernel, &composition, &envelope, &tool, &attempt)
        .await
        .map_err(|error| format!("daemon state serve: {error}"))?;
    match submit_state_result_idempotent(kernel, &body).await? {
        StateSubmitOutcome::Accepted => Ok(StatePollOutcome::Accepted),
        StateSubmitOutcome::Expired => Ok(StatePollOutcome::Expired),
        StateSubmitOutcome::StaleAttempt => Ok(StatePollOutcome::StaleAttempt),
    }
}

/// Returns whether one claimed pair is the admitted `eliot.state` shape the
/// state lane owns: the envelope capability and the tool name agree on
/// `eliot.state`. A query, Skill or packet pair is never reinterpreted as
/// state.
fn is_state_pair(envelope: &HostRequestEnvelope, tool: &serde_json::Value) -> bool {
    envelope.identity.capability == "eliot.state"
        && tool
            .as_object()
            .and_then(|object| object.get("name"))
            .and_then(serde_json::Value::as_str)
            == Some("eliot.state")
}

/// Derives the trusted scope of one admitted state pair: the envelope work
/// scope, else its session — never an MCP argument, exactly as the Kernel's
/// `local_state_selectors_from_tool` derives it.
fn trusted_state_scope(envelope: &HostRequestEnvelope) -> Result<ScopeId, String> {
    let scope_text = envelope
        .identity
        .work_scope_id
        .as_deref()
        .filter(|scope| !scope.trim().is_empty())
        .or_else(|| {
            envelope
                .identity
                .session_id
                .as_deref()
                .filter(|scope| !scope.trim().is_empty())
        })
        .ok_or_else(|| "admitted state request binds no usable scope".to_owned())?;
    ScopeId::new(scope_text.to_owned())
        .map_err(|error| format!("admitted state scope: {error}"))
}

/// Parses the admitted `include` projection-field list with the Kernel's
/// closed discipline (`local_state_selectors_from_tool`): absent or null is
/// the default full projection; entries are unique non-blank control-free
/// field names. Anything else fails the step before any read.
fn state_include_fields(tool: &serde_json::Value) -> Result<Vec<String>, String> {
    let arguments = tool
        .as_object()
        .and_then(|object| object.get("arguments"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "admitted state arguments must be an object".to_owned())?;
    match arguments.get("include") {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Array(items)) => {
            let mut seen = BTreeSet::new();
            let mut include = Vec::with_capacity(items.len());
            for item in items {
                let field = item
                    .as_str()
                    .filter(|field| {
                        !field.trim().is_empty() && !field.chars().any(char::is_control)
                    })
                    .ok_or_else(|| {
                        "admitted state include must list unique non-blank fields".to_owned()
                    })?;
                if !seen.insert(field) {
                    return Err(
                        "admitted state include must list unique non-blank fields".to_owned(),
                    );
                }
                include.push(field.to_owned());
            }
            Ok(include)
        }
        Some(_) => Err("admitted state include must list unique non-blank fields".to_owned()),
    }
}

/// Builds the read metadata bound to the admitted state envelope and the
/// retained authenticated owner session.
///
/// The task binding stays optional: authenticated discovery with no selected
/// task is served as the bounded selection/intake state, never refused for
/// want of a task and never given an invented `TaskContract`. A present but
/// blank or control-bearing task is read the same way the state serve on the
/// sibling slice reads it — as absent — because the admitted envelope, not
/// this poller, owns task admission.
fn state_read_context(
    envelope: &HostRequestEnvelope,
    task_id: Option<&str>,
    fence: &StateFence,
) -> Result<eliot_contracts::RequestMetadata, String> {
    let operation = host_request_operation_id(envelope);
    let request_id = RequestId::new(format!("eliotd:state-preview:{operation}"))
        .map_err(|error| format!("state request id: {error}"))?;
    let session_id = envelope
        .identity
        .session_id
        .as_deref()
        .map(SessionId::new)
        .transpose()
        .map_err(|error| format!("admitted session identity: {error}"))?;
    let task_id = task_id
        .map(TaskId::new)
        .transpose()
        .map_err(|error| format!("admitted task identity: {error}"))?;
    let context = eliot_contracts::RequestMetadata {
        request_id,
        session_id,
        task_id,
        product_id: ProductId::new(SERVICE_NAME).map_err(|error| error.to_string())?,
        source_id: SourceId::new(SERVICE_NAME).map_err(|error| error.to_string())?,
        state_fence: fence.clone(),
        clock: ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    context
        .validate()
        .map_err(|error| format!("state request metadata: {error}"))?;
    Ok(context)
}

/// Serves one admitted `eliot.state` pair through the Governor state/query
/// facade subset (#2564 Slice 1, A1 adjudication).
///
/// This lane invokes `ReadApi::state` over a fresh `KernelContextReadClient`
/// — the existing Governor composition edge for bounded current-state reads
/// — never the full seven-role `reconstruct_context_inputs` (whose closed
/// request requires a non-blank evidence subject, task, projection and
/// affordance selectors this lane must not invent) and never the query-only
/// `GetEvidencePack` twin (state is never routed as query). The
/// `DaemonComposition::reconstruction_composition` borrow pins readiness plus
/// the exact admitted fence and scope; the guard drops before any owner read,
/// so no composition lock crosses the reconstruction awaits. The reads are
/// the owner-resolved selectors of the admitted operation: `GetRevisionHeads`
/// with empty parameters, then the scope-bound `GetScopeRevisionView` and —
/// only when the envelope binds a task — the task-bound `GetTaskState` under
/// `ExactFence` over the observed dependency revisions. A task-bound preview
/// without its task fact is a step failure, never a healthy empty preview;
/// an empty list is never claimed `KnownEmpty` here — the owner reads speak
/// for themselves through their bound views.
async fn serve_state_pair(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
    attempt: &LocalReadAttempt,
) -> Result<HostRequestResultBody, String> {
    if !is_state_pair(envelope, tool) {
        return Err("request is not the admitted eliot.state shape".to_owned());
    }
    attempt
        .validate()
        .map_err(|error| format!("state attempt is not bound shape: {error}"))?;
    let scope = trusted_state_scope(envelope)?;
    if attempt.operation_id != host_request_operation_id(envelope)
        || attempt.scope_id != scope.as_str()
        || attempt.authority_epoch != envelope.state_fence.authority_epoch
        || attempt.expires_at_unix_ms != envelope.identity.deadline_unix_ms
        || attempt.facet_method != envelope.identity.capability
    {
        return Err("state attempt does not bind the admitted request".to_owned());
    }
    let retained_fence = kernel.kernel_fence();
    if envelope.state_fence != retained_fence {
        return Err("admitted State Fence differs from the retained Kernel fence".to_owned());
    }
    // The retained owner session must belong to this live client generation:
    // a missing Kernel-authenticated session is a step failure, never a
    // substituted principal. (The blank-principal sub-check stays with the
    // lib serve edges that own `OwnerSessionFacts` field access.)
    if kernel.owner_session_facts().is_none() {
        return Err("no authenticated owner session is retained for this state preview".to_owned());
    }
    let include = state_include_fields(tool)?;
    let reads = KernelContextReadClient::new(Arc::clone(kernel));
    {
        let guard = composition.lock().await;
        let borrowed = guard
            .reconstruction_composition(kernel, &reads, scope.clone())
            .map_err(|error| format!("daemon state composition: {error}"))?;
        if *borrowed.admitted_fence() != envelope.state_fence {
            return Err("daemon state fence moved before serve".to_owned());
        }
    }
    serve_state_views(kernel, envelope, attempt, &scope, include, &retained_fence).await
}

/// Reads the owner-backed state views for one pinned admitted pair and binds
/// them into the digest-committed result body.
///
/// The `GetRevisionHeads` observation carries empty parameters; the
/// scope/task reads carry exactly the admitted scope, the admitted task (when
/// bound) and the catalogue's own bound. Every view must echo its operation
/// and the admitted fence or the step fails closed: a previous generation is
/// never served as current.
async fn serve_state_views(
    kernel: &Arc<DaemonKernelClient>,
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    scope: &ScopeId,
    include: Vec<String>,
    fence: &StateFence,
) -> Result<HostRequestResultBody, String> {
    let task_id = envelope
        .identity
        .task_id
        .as_deref()
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control));
    let ctx = state_read_context(envelope, task_id, fence)?;
    let service = ReadService::new(KernelContextReadClient::new(Arc::clone(kernel)));
    let heads = service
        .state(
            &ctx,
            StateRequest {
                operation: NamedReadOperation::GetRevisionHeads,
                scope_id: None,
                consistency: ReadConsistency::Eventual,
                dependency_revisions: BTreeMap::new(),
                ordering: ReadOrderingBinding::without_order_dependency(),
                parameters: NamedParameters::new(),
                provenance_handles: Vec::new(),
            },
        )
        .await
        .map_err(|error| format!("daemon state revision heads: {error}"))?;
    if heads.operation != NamedReadOperation::GetRevisionHeads || heads.state_fence != *fence {
        return Err("daemon state revision heads do not match the admitted fence".to_owned());
    }
    // Declared dependency minimums are exactly what the owner observed under
    // the admitted fence: non-zero revisions carrying that fence. Anything
    // older, zero or foreign never becomes a minimum.
    let mut dependencies: BTreeMap<RevisionKey, u64> = BTreeMap::new();
    for head in &heads.revision_heads {
        if head.state_fence == *fence && head.revision != 0 {
            dependencies.insert(head.key.clone(), head.revision);
        }
    }
    let scope_view = service
        .state(
            &ctx,
            StateRequest {
                operation: NamedReadOperation::GetScopeRevisionView,
                scope_id: Some(scope.clone()),
                consistency: ReadConsistency::ExactFence,
                dependency_revisions: dependencies.clone(),
                ordering: ReadOrderingBinding::without_order_dependency(),
                parameters: NamedParameters::new(),
                provenance_handles: Vec::new(),
            },
        )
        .await
        .map_err(|error| format!("daemon state scope view: {error}"))?;
    if scope_view.operation != NamedReadOperation::GetScopeRevisionView
        || scope_view.state_fence != *fence
    {
        return Err("daemon state scope view does not match the admitted fence".to_owned());
    }
    // No selected task is authenticated discovery: the bounded scope views
    // above are the preview. A bound task joins its exact task fact; without
    // that fact the task-bound preview is refused, never served empty.
    let task_view = match task_id {
        None => None,
        Some(task) => Some(
            read_task_state_view(&service, &ctx, scope, task, &dependencies, fence).await?,
        ),
    };
    let response = serde_json::json!({
        "operation": "eliot.state",
        "scope_id": scope.as_str(),
        "task_id": task_id,
        "include": include,
        "revision_heads": heads.revision_heads.clone(),
        "scope": scope_view,
        "task_state": task_view,
    });
    state_result_body(envelope, attempt, &response, &heads, fence)
}

/// Reads the exact task fact for one task-bound admitted pair.
///
/// The selectors are the admitted scope, the admitted task and the
/// catalogue's own bound — never a defaulted or substituted identity. The
/// view must echo its operation and the admitted fence: a task-bound preview
/// without its task fact is refused by the caller, never served empty.
async fn read_task_state_view(
    service: &ReadService<KernelContextReadClient>,
    ctx: &eliot_contracts::RequestMetadata,
    scope: &ScopeId,
    task: &str,
    dependencies: &BTreeMap<RevisionKey, u64>,
    fence: &StateFence,
) -> Result<CurrentStateView, String> {
    let mut parameters = NamedParameters::new();
    parameters
        .insert(
            "task_id".to_owned(),
            serde_json::Value::String(task.to_owned()),
        )
        .map_err(|error| format!("daemon state task selector: {error}"))?;
    parameters
        .insert(
            "max_records".to_owned(),
            serde_json::Value::String(EVIDENCE_PACK_MAX_RECORDS.to_string()),
        )
        .map_err(|error| format!("daemon state task bound: {error}"))?;
    let view = service
        .state(
            ctx,
            StateRequest {
                operation: NamedReadOperation::GetTaskState,
                scope_id: Some(scope.clone()),
                consistency: ReadConsistency::ExactFence,
                dependency_revisions: dependencies.clone(),
                ordering: ReadOrderingBinding::without_order_dependency(),
                parameters,
                provenance_handles: Vec::new(),
            },
        )
        .await
        .map_err(|error| format!("daemon state task view: {error}"))?;
    if view.operation != NamedReadOperation::GetTaskState || view.state_fence != *fence {
        return Err("daemon state task view does not match the admitted fence".to_owned());
    }
    Ok(view)
}

/// Projects the owner-backed state views into the host-request result body.
///
/// The response carries the exact bound views plus the identity they were
/// read under. The lineage declares the read class with the observed source
/// revisions and fence: a read of already-retained evidence with its actual
/// revision and provenance, creating no new semantic record. `request_sha256`
/// binds the actual expected admitted envelope, and the result digest covers
/// the exact bounded response bytes.
fn state_result_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    response: &serde_json::Value,
    heads: &CurrentStateView,
    fence: &StateFence,
) -> Result<HostRequestResultBody, String> {
    let bytes = canonical_json_bytes(response)
        .map_err(|error| format!("state response bytes: {error}"))?;
    let result_digest = sha256_hex(&bytes);
    let source_revisions = heads
        .revision_heads
        .iter()
        .map(|head| HostRequestResultSourceRevision {
            key: head.key.as_str().to_owned(),
            revision: head.revision,
            state_fence: head.state_fence.clone(),
        })
        .collect::<Vec<_>>();
    let body = HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: result_digest.clone(),
        response: response.clone(),
        attempt: Some(attempt.clone()),
        lineage: Some(HostRequestResultLineage {
            output_artifact_ref: None,
            output_digest: result_digest,
            producer_ref: None,
            source_revisions: Some(source_revisions),
            source_state_fence: Some(fence.clone()),
            input_refs: None,
            transformation_lineage: None,
            closure_refs: None,
            policy_fence: None,
            origin_evidence_refs: None,
            semantic_receipt_ref: None,
            result_class: HostRequestResultClass::ExistingEvidenceRead,
            proof_ceiling: None,
            influence_state: InfluenceState::Unknown,
            instruction_taint: None,
        }),
        evidence: None,
    };
    body.validate()
        .map_err(|error| format!("state result body is not valid: {error}"))?;
    Ok(body)
}

/// Submits one served state result body, retrying once with the byte-identical
/// body when the first submit fails.
///
/// This is the state twin of the local-read lost-acknowledgement reconcile:
/// the retained body is reused verbatim, never recomputed, and no local
/// replay cache or timer is introduced. The retry is safe because the Kernel
/// submit leg is exact-replay idempotent — an identical body under the same
/// identity persists once and replays, never duplicates. Only transport
/// failures retry: `Expired` and `StaleAttempt` are settled outcomes, so a
/// quarantined capability is never resubmitted.
async fn submit_state_result_idempotent(
    kernel: &DaemonKernelClient,
    body: &HostRequestResultBody,
) -> Result<StateSubmitOutcome, String> {
    match kernel.submit_state_result_async(body).await {
        Ok(outcome) => Ok(outcome),
        Err(first_error) => kernel
            .submit_state_result_async(body)
            .await
            .map_err(|error| {
                format!("Kernel state result submit: {first_error}; retry: {error}")
            }),
    }
}

async fn drain_state_on_shutdown(flight: &mut StateFlight) -> Result<RunLoopExit, String> {
    let previous = std::mem::replace(flight, StateFlight::Idle);
    let StateFlight::InFlight(state) = previous else {
        return Ok(RunLoopExit::Shutdown);
    };
    match tokio::time::timeout(SHUTDOWN_ACTIVATION_DRAIN, state.future).await {
        Ok(StateCompletion::Settled(Err(error))) => Err(error),
        _ => Ok(RunLoopExit::Shutdown),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskControllerPollOutcome {
    /// No queued invocation; back off until the next tick.
    IdleBackoff,
    /// The result body was committed or exact-replayed.
    Accepted,
    /// The fenced attempt expired before its result committed.
    Expired,
    /// The attempt was replaced/revoked and was quarantined.
    StaleAttempt,
}

/// Completion of one in-flight Task Controller step.
enum TaskControllerCompletion {
    Settled(Result<TaskControllerPollOutcome, String>),
}

struct TaskControllerFlightState {
    future: Pin<Box<dyn std::future::Future<Output = TaskControllerCompletion>>>,
}

/// Sole owner of Task Controller poll state in the runtime loop.
enum TaskControllerFlight {
    Idle,
    InFlight(TaskControllerFlightState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskControllerTickDecision {
    StartPoll,
    SkipInFlight,
}

fn decide_task_controller_tick(flight: &TaskControllerFlight) -> TaskControllerTickDecision {
    match flight {
        TaskControllerFlight::Idle => TaskControllerTickDecision::StartPoll,
        TaskControllerFlight::InFlight(_) => TaskControllerTickDecision::SkipInFlight,
    }
}

fn start_task_controller_poll(
    kernel: &Arc<DaemonKernelClient>,
    composition: SharedComposition,
) -> Pin<Box<dyn std::future::Future<Output = TaskControllerCompletion>>> {
    let kernel_clone = Arc::clone(kernel);
    Box::pin(async move {
        TaskControllerCompletion::Settled(
            Box::pin(run_task_controller_poll(&kernel_clone, composition)).await,
        )
    })
}

fn maybe_start_task_controller_poll(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    flight: &mut TaskControllerFlight,
) {
    if decide_task_controller_tick(flight) == TaskControllerTickDecision::StartPoll {
        *flight = TaskControllerFlight::InFlight(TaskControllerFlightState {
            future: start_task_controller_poll(kernel, Arc::clone(composition)),
        });
    }
}

async fn next_task_controller_completion(
    flight: &mut TaskControllerFlight,
) -> TaskControllerCompletion {
    match flight {
        TaskControllerFlight::Idle => std::future::pending::<TaskControllerCompletion>().await,
        TaskControllerFlight::InFlight(state) => (&mut state.future).await,
    }
}

fn settle_task_controller_completion(
    completion: TaskControllerCompletion,
    flight: &mut TaskControllerFlight,
) -> Result<(), String> {
    match completion {
        TaskControllerCompletion::Settled(Ok(_)) => {
            *flight = TaskControllerFlight::Idle;
            Ok(())
        }
        TaskControllerCompletion::Settled(Err(error)) => Err(error),
    }
}

/// What one completed finish poll resolves to before the loop acts (issue
/// #1741). A null claim backs off until the next tick; a claimed pair serves
/// through the Governor finish owner and submits one fenced result body.
enum FinishPollOutcome {
    IdleBackoff,
    Accepted,
    Expired,
    StaleAttempt,
}

/// Completion of one in-flight finish poll step.
enum FinishCompletion {
    Settled(Result<FinishPollOutcome, String>),
}

struct FinishFlightState {
    future: Pin<Box<dyn std::future::Future<Output = FinishCompletion>>>,
}

/// Sole owner of finish poll state in `run_loop`, mirroring
/// [`TaskControllerFlight`]. `Idle` means no finish work is outstanding;
/// `InFlight` holds the one pending poll step.
enum FinishFlight {
    Idle,
    InFlight(FinishFlightState),
}

/// Completion of one authenticated provider-binding poll. This owner read is
/// side-effect free; refusal leaves the intake queued for a later cadence.
enum SoloPollCompletion {
    Settled(Result<eliotd::solo_agent_driver::SoloPollOutcome, String>),
}

struct SoloPollFlightState {
    future: Pin<Box<dyn std::future::Future<Output = SoloPollCompletion>>>,
}

/// Sole owner of the asynchronous solo provider-binding poll in `run_loop`.
/// The future remains a select branch while Kernel IO is pending.
enum SoloPollFlight {
    Idle,
    InFlight(SoloPollFlightState),
}

fn start_solo_poll(
    kernel: &Arc<DaemonKernelClient>,
    composition: SharedComposition,
) -> Pin<Box<dyn std::future::Future<Output = SoloPollCompletion>>> {
    let kernel = Arc::clone(kernel);
    Box::pin(async move {
        let result = eliotd::solo_poll_queue_async(&composition, &kernel)
            .await
            .map_err(|error| error.to_string());
        SoloPollCompletion::Settled(result)
    })
}

fn maybe_start_solo_poll(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    flight: &mut SoloPollFlight,
) {
    if matches!(flight, SoloPollFlight::Idle) {
        *flight = SoloPollFlight::InFlight(SoloPollFlightState {
            future: start_solo_poll(kernel, Arc::clone(composition)),
        });
    }
}

async fn next_solo_poll_completion(flight: &mut SoloPollFlight) -> SoloPollCompletion {
    match flight {
        SoloPollFlight::Idle => std::future::pending::<SoloPollCompletion>().await,
        SoloPollFlight::InFlight(state) => (&mut state.future).await,
    }
}

fn settle_solo_poll_completion(
    completion: SoloPollCompletion,
    flight: &mut SoloPollFlight,
    last_refusal: &mut Option<String>,
) {
    *flight = SoloPollFlight::Idle;
    let result = match completion {
        SoloPollCompletion::Settled(result) => result,
    };
    match result {
        Ok(eliotd::solo_agent_driver::SoloPollOutcome::Drove {
            operation_id,
            dispatch_id,
        }) => {
            tracing::info!(
                target: "eliotd::diagnostics",
                event = "eliotd.solo_drive_retained",
                operation_id = %eliotd::diagnostics::sanitize_identity(&operation_id),
                dispatch_id = %eliotd::diagnostics::sanitize_identity(&dispatch_id),
            );
            *last_refusal = None;
        }
        Ok(_) => *last_refusal = None,
        Err(error) => {
            if last_refusal.as_deref() != Some(error.as_str()) {
                tracing::warn!(
                    target: "eliotd::diagnostics",
                    event = "eliotd.solo_poll_refused",
                    detail = %error,
                );
                *last_refusal = Some(error);
            }
        }
    }
}

/// Pure tick gate: the finish timer starts work only when the flight is idle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinishTickDecision {
    StartPoll,
    SkipInFlight,
}

fn decide_finish_tick(flight: &FinishFlight) -> FinishTickDecision {
    match flight {
        FinishFlight::Idle => FinishTickDecision::StartPoll,
        FinishFlight::InFlight(_) => FinishTickDecision::SkipInFlight,
    }
}

fn start_finish_poll(
    kernel: &Arc<DaemonKernelClient>,
    composition: SharedComposition,
) -> Pin<Box<dyn std::future::Future<Output = FinishCompletion>>> {
    let kernel_clone = Arc::clone(kernel);
    Box::pin(async move {
        FinishCompletion::Settled(Box::pin(run_finish_poll(&kernel_clone, composition)).await)
    })
}

fn maybe_start_finish_poll(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    flight: &mut FinishFlight,
) {
    if decide_finish_tick(flight) == FinishTickDecision::StartPoll {
        *flight = FinishFlight::InFlight(FinishFlightState {
            future: start_finish_poll(kernel, Arc::clone(composition)),
        });
    }
}

async fn next_finish_completion(flight: &mut FinishFlight) -> FinishCompletion {
    match flight {
        FinishFlight::Idle => std::future::pending::<FinishCompletion>().await,
        FinishFlight::InFlight(state) => (&mut state.future).await,
    }
}

fn settle_finish_completion(
    completion: FinishCompletion,
    flight: &mut FinishFlight,
) -> Result<(), String> {
    match completion {
        FinishCompletion::Settled(Ok(_)) => {
            *flight = FinishFlight::Idle;
            Ok(())
        }
        FinishCompletion::Settled(Err(error)) => Err(error),
    }
}

async fn run_finish_poll(
    kernel: &DaemonKernelClient,
    composition: SharedComposition,
) -> Result<FinishPollOutcome, String> {
    let _span = tracing::info_span!("eliotd.finish_poll").entered();
    let claimed = kernel
        .claim_finish_pair_async()
        .await
        .map_err(|error| format!("Kernel finish pair claim: {error}"))?;
    let Some(claimed) = claimed else {
        return Ok(FinishPollOutcome::IdleBackoff);
    };
    let body = Box::pin(eliotd::serve_finish_claim(kernel, &composition, claimed))
        .await
        .map_err(|error| format!("daemon finish dispatch: {error}"))?;
    match kernel.submit_finish_result_async(&body).await {
        Ok(FinishSubmitOutcome::Accepted) => Ok(FinishPollOutcome::Accepted),
        Ok(FinishSubmitOutcome::Expired) => Ok(FinishPollOutcome::Expired),
        Ok(FinishSubmitOutcome::StaleAttempt) => Ok(FinishPollOutcome::StaleAttempt),
        Err(first_error) => match kernel.submit_finish_result_async(&body).await {
            Ok(FinishSubmitOutcome::Accepted) => Ok(FinishPollOutcome::Accepted),
            Ok(FinishSubmitOutcome::Expired) => Ok(FinishPollOutcome::Expired),
            Ok(FinishSubmitOutcome::StaleAttempt) => Ok(FinishPollOutcome::StaleAttempt),
            Err(second_error) => Err(format!(
                "Kernel finish result submit: {first_error}; retry: {second_error}"
            )),
        },
    }
}

async fn drain_finish_on_shutdown(flight: &mut FinishFlight) -> Result<RunLoopExit, String> {
    let previous = std::mem::replace(flight, FinishFlight::Idle);
    let FinishFlight::InFlight(state) = previous else {
        return Ok(RunLoopExit::Shutdown);
    };
    match tokio::time::timeout(SHUTDOWN_ACTIVATION_DRAIN, state.future).await {
        Ok(FinishCompletion::Settled(Err(error))) => Err(error),
        _ => Ok(RunLoopExit::Shutdown),
    }
}

async fn run_task_controller_poll(
    kernel: &Arc<DaemonKernelClient>,
    composition: SharedComposition,
) -> Result<TaskControllerPollOutcome, String> {
    let _span = tracing::info_span!("eliotd.task_controller_poll").entered();
    let claimed = kernel
        .claim_task_controller_pair_async()
        .await
        .map_err(|error| format!("Kernel Task Controller pair claim: {error}"))?;
    let Some(claimed) = claimed else {
        return Ok(TaskControllerPollOutcome::IdleBackoff);
    };
    let reads = KernelContextReadClient::new(Arc::clone(kernel));
    let prepared = eliotd::campaign_task_controller::prepare_task_controller_claim(
        &reads,
        kernel.as_ref(),
        claimed,
    )
    .await
    .map_err(|error| format!("daemon Task Controller preparation: {error}"))?;
    let body = match prepared {
        eliotd::campaign_task_controller::TaskControllerClaimPreparation::Rejected(body) => *body,
        eliotd::campaign_task_controller::TaskControllerClaimPreparation::Ready(prepared) => {
            let transition = {
                let guard = composition.lock().await;
                eliotd::campaign_task_controller::prepare_task_controller_transition(
                    &guard, *prepared,
                )
            };
            match transition {
                eliotd::campaign_task_controller::TaskControllerTransitionPreparation::Rejected(
                    body,
                ) => *body,
                eliotd::campaign_task_controller::TaskControllerTransitionPreparation::Failed(
                    error,
                ) => return Err(format!("daemon Task Controller dispatch: {error}")),
                eliotd::campaign_task_controller::TaskControllerTransitionPreparation::Ready(
                    execution,
                ) => eliotd::campaign_task_controller::exchange_task_controller_transition(
                    kernel.as_ref(),
                    *execution,
                )
                .await
                .map_err(|error| format!("daemon Task Controller dispatch: {error}"))?,
            }
        }
    };
    match kernel.submit_task_controller_result_async(&body).await {
        Ok(TaskControllerSubmitOutcome::Accepted) => Ok(TaskControllerPollOutcome::Accepted),
        Ok(TaskControllerSubmitOutcome::Expired) => Ok(TaskControllerPollOutcome::Expired),
        Ok(TaskControllerSubmitOutcome::StaleAttempt) => {
            Ok(TaskControllerPollOutcome::StaleAttempt)
        }
        Err(first_error) => match kernel.submit_task_controller_result_async(&body).await {
            Ok(TaskControllerSubmitOutcome::Accepted) => Ok(TaskControllerPollOutcome::Accepted),
            Ok(TaskControllerSubmitOutcome::Expired) => Ok(TaskControllerPollOutcome::Expired),
            Ok(TaskControllerSubmitOutcome::StaleAttempt) => {
                Ok(TaskControllerPollOutcome::StaleAttempt)
            }
            Err(second_error) => Err(format!(
                "Kernel Task Controller result submit: {first_error}; retry: {second_error}"
            )),
        },
    }
}

async fn drain_task_controller_on_shutdown(
    flight: &mut TaskControllerFlight,
) -> Result<RunLoopExit, String> {
    let previous = std::mem::replace(flight, TaskControllerFlight::Idle);
    let TaskControllerFlight::InFlight(state) = previous else {
        return Ok(RunLoopExit::Shutdown);
    };
    match tokio::time::timeout(SHUTDOWN_ACTIVATION_DRAIN, state.future).await {
        Ok(TaskControllerCompletion::Settled(Err(error))) => Err(error),
        _ => Ok(RunLoopExit::Shutdown),
    }
}

/// Completion of one in-flight `TestD` owner drain step. Bind, terminal
/// publish, finish submit, and ack share one flight branch so health and
/// shutdown stay pollable while the bounded step is outstanding; the step
/// handles at most one bounded poll per queue per tick.
enum TestdOwnerCompletion {
    Settled(Result<TestdOwnerDrainOutcome, String>),
}

struct TestdOwnerFlightState {
    future: Pin<Box<dyn std::future::Future<Output = TestdOwnerCompletion>>>,
}

/// Sole owner of `TestD` owner drain state in `run_loop`, mirroring
/// [`LocalReadFlight`]. `Idle` means no drain work is outstanding;
/// `InFlight` holds the one pending drain step. No second owner and no
/// second concurrent drain step exist.
enum TestdOwnerFlight {
    Idle,
    InFlight(TestdOwnerFlightState),
}

/// Completion of one in-flight improvement-intake step.
enum ImprovementIntakeCompletion {
    Settled(Result<(), String>),
}

struct ImprovementIntakeFlightState {
    future: Pin<Box<dyn std::future::Future<Output = ImprovementIntakeCompletion>>>,
}

/// Sole owner of the improvement-intake dispatch state in `run_loop`
/// (issue #1867 W1, I12.24).
///
/// This is the twelfth single-owner polled flight and the production reach
/// point for `eliot-improvement`: before it, the improvement intake bridge
/// had no call site in the daemon and the candidate/brief path was
/// unreachable. `Idle` means no dispatch is outstanding; `InFlight` holds
/// the one pending bounded step. No second owner and no second concurrent
/// dispatch exist.
enum ImprovementIntakeFlight {
    Idle,
    InFlight(ImprovementIntakeFlightState),
}

/// Evaluates one real maintenance observation and assembles the
/// owner-actionable improvement artifact over it, under the composition guard.
///
/// Four reads and one pure assembly, all under the lock:
///
/// - the maintenance trigger decision, from the live observation;
/// - the admitted Kernel fence for this pass, which is also the fence the
///   deduplication registry is read back at;
/// - the maintenance (`G-19`) improvement admission policy record, read from
///   the live `GovernorOwners::maintenance` owner — this is where the
///   per-surface bound numbers and the owning authority come from
///   (`eliotd::improvement_intake_dispatch::maintenance_bound`), so the
///   daemon spells none of them;
/// - the Governor learning-closure image, read through
///   `DaemonComposition::learning_closure().store()` so the brief's safe
///   boundary is the newest boundary an owner actually closed
///   (`SafeBoundary::from_observed_closure`). This is a read of already
///   committed in-process state — the store's own mutex, no transport — and it
///   is done HERE, inside the composition guard, because it must not race the
///   guard release that precedes the authenticated dedup read below. An empty
///   image is a typed refusal, so the pass commits nothing until a
///   consequential closure has been observed.
///
/// The admission is deliberately NOT performed here. It needs the restored
/// deduplication registry first, and that registry is read over the
/// authenticated Kernel named-read route, which is an exchange and must not
/// run while the composition guard is held. The admission is therefore the
/// second guarded phase, [`admit_over_restored_registry`], after the guard has
/// been released for the read — the same contour the Skill and ControlBoard
/// reads already use.
///
/// The guarded phase performs no exchange: evaluating, assembling and reading
/// the policy are all pure with respect to the Kernel.
fn improvement_intake_artifact(
    composition: &DaemonComposition,
    observation: MaintenanceObservation,
) -> Result<
    (
        eliotd::improvement_intake_dispatch::ImprovementArtifact,
        eliot_maintenance::ImprovementAdmissionPolicy,
        eliot_contracts::StateFence,
    ),
    String,
> {
    let decision = composition
        .evaluate_maintenance_trigger(observation)
        .map_err(|error| error.to_string())?;
    let fence = composition
        .notification_state_admission_fence()
        .map_err(|error| error.to_string())?;
    // The brief's safe boundary is observed here, under the composition guard
    // the caller already holds: `learning_closure()` is the daemon's single
    // Governor-owned closure image, and `store()` hands back the canonical
    // learning-delta store whose newest committed record IS an
    // owner-observed consequential boundary.
    let artifact = eliotd::improvement_intake_dispatch::assemble_improvement_artifact(
        &decision,
        &fence,
        composition.learning_closure().store(),
    )
    .map_err(|error| error.to_string())?;
    // The G-19 decision record, read through the EXISTING maintenance owner.
    // The operation and idempotency key bind this exact observation, so the
    // policy a candidate is admitted under names the observation it belongs to.
    let policy = composition
        .maintenance_improvement_admission_policy(
            &eliotd::improvement_intake_dispatch::improvement_bound_operation(&decision),
            &eliotd::improvement_intake_dispatch::improvement_bound_idempotency_key(&decision),
        )
        .map_err(|error| error.to_string())?;
    Ok((artifact, policy, fence))
}

/// Admits the assembled artifact into the deduplication registry restored from
/// the durable candidate records, through the GOVERNED path.
///
/// The registry is REBUILT from the records this daemon previously committed,
/// read back through the existing authenticated `GetLearningRecordRange`
/// route (`eliotd::improvement_dedup_read::read_candidate_scope`). It is not
/// constructed empty: a backlog built empty at every pass can never take its
/// evidence-lineage merge branch, which is the whole of I12.24:297's
/// "Duplicates merge by evidence lineage" on this path.
///
/// The fence is re-read under this fresh borrow and compared with the fence
/// the registry was read at. The read and the admission are separated by an
/// await with no lock held, so the fence can move in between; admitting
/// against a registry read at a superseded fence would bound the admission
/// with a set that is no longer the current one, so a moved fence refuses the
/// pass instead. This is the same re-check `run_local_read_poll` already
/// applies to its ControlBoard snapshot.
///
/// `rows` must be the EXHAUSTIVE candidate scope. A refused or unexhausted
/// read never reaches here: it is a typed error the caller turns into a
/// diagnostic, and the admission is not attempted against a partial set.
fn admit_over_restored_registry(
    composition: &DaemonComposition,
    policy: &eliot_maintenance::ImprovementAdmissionPolicy,
    rows: &[serde_json::Value],
    artifact: &eliotd::improvement_intake_dispatch::ImprovementArtifact,
    fence: &eliot_contracts::StateFence,
) -> Result<eliotd::improvement_intake_dispatch::GovernedImprovementAdmission, String> {
    let current = composition
        .notification_state_admission_fence()
        .map_err(|error| error.to_string())?;
    if current != *fence {
        return Err(
            "the admitted state fence moved between the dedup registry read and the admission"
                .to_owned(),
        );
    }
    // The bound still comes from the G-19 owner record, never from a literal
    // and never from the restored records.
    let bound = eliotd::improvement_intake_dispatch::maintenance_bound(policy)
        .map_err(|error| error.to_string())?;
    let mut backlog: BoundedBacklog =
        eliotd::improvement_dedup_read::restored_registry(rows, bound)
            .map_err(|error| error.to_string())?;
    eliotd::improvement_intake_dispatch::admit_improvement_artifact(
        composition.improvement_governor(),
        policy,
        &mut backlog,
        artifact,
        fence,
    )
    .map_err(|error| error.to_string())
}

/// Runs one improvement-intake step: evaluate and assemble the artifact over a
/// real observation, read the deduplication registry back from the durable
/// candidate records, admit into it through the governed path, and commit the
/// artifact — and every archive receipt the admission produced — durably
/// through the Governor `RecordLearningRecord` seam.
///
/// Four phases, and the lock is held for three of them:
///
/// 1. guarded: evaluate the observation, capture the admitted fence, assemble
///    the artifact, read the `G-19` admission policy;
/// 2. UNGUARDED: read the whole candidate scope back through the existing
///    authenticated `GetLearningRecordRange` route at the fence captured in
///    phase 1. No mutex is held across this await, exactly as the Skill
///    acceptance and evidence reads are run;
/// 3. guarded: re-check the fence, rebuild the bounded backlog from those
///    records, and run the governed admission against it;
/// 4. guarded: commit.
///
/// A refused or unexhausted phase-2 read is a typed error and the pass STOPS.
/// It is never treated as an empty registry: admitting against "nothing was
/// there" is precisely the failure this read exists to prevent, because it
/// makes a repeat of the same evidence lineage look like a first observation.
///
/// The durable write is owned entirely by
/// [`eliotd::DaemonComposition::commit_learning_record`], the one
/// Governor-owned caller of the closed `RecordLearningRecord` mutation. The
/// commit is a retained run-loop flight rather than detached work, the
/// composition lock is never held across a durable exchange, and a refusal is
/// a typed diagnostic rather than a loop failure — exactly the discipline
/// [`evaluate_and_emit_maintenance_notification`] already uses for the
/// notification leg.
async fn run_improvement_intake(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    observation: MaintenanceObservation,
) -> Result<(), String> {
    let prepared = {
        let guard = composition.lock().await;
        improvement_intake_artifact(&guard, observation)
    };
    let (artifact, policy, fence) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = eliotd::diagnostics::ErrorRecord::of(
                eliotd::diagnostics::OwningComponent::DaemonRuntime,
                "improvement-intake",
                &error,
            )
            .emit();
            return Ok(());
        }
    };
    // The deduplication registry, read back from the records this daemon
    // committed, at the fence this pass admitted under. Unguarded: the read is
    // an authenticated Kernel exchange and the composition guard is not held
    // across it.
    let rows = eliotd::improvement_dedup_read::read_candidate_scope(kernel, &fence)
        .await
        .map_err(|error| error.to_string())?;
    let restored = rows.len();
    let admitted = {
        let guard = composition.lock().await;
        admit_over_restored_registry(&guard, &policy, &rows, &artifact, &fence)
    };
    let admitted = match admitted {
        Ok(admitted) => admitted,
        Err(error) => {
            let _ = eliotd::diagnostics::ErrorRecord::of(
                eliotd::diagnostics::OwningComponent::DaemonRuntime,
                "improvement-admission",
                &error,
            )
            .emit();
            return Ok(());
        }
    };
    let committed = {
        let mut guard = composition.lock().await;
        eliotd::improvement_intake_dispatch::commit_improvement_artifact(
            &mut guard, &artifact, &admitted, &fence,
        )
        .await
    };
    match committed {
        Ok((receipt, effective)) => {
            tracing::info!(
                target: "eliotd::diagnostics",
                event = "eliotd.improvement_candidate_committed",
                candidate_id = %artifact.candidate.candidate_id,
                brief_id = %artifact.brief.brief_id,
                operation_id = %receipt.operation_id,
                effective,
                // The owner-decided bound and the owner-issued admission that
                // enforced it, so the diagnostic names the bound rather than
                // implying one.
                bound_max_active = admitted.bound.max_active,
                bound_min_value = admitted.bound.min_value,
                governor_authority_ref = %admitted.bound.governor_authority_ref,
                governed_admission_digest = %admitted.admission_digest,
                // How many durable candidate records the deduplication
                // registry was rebuilt from, and what the admission decided
                // against it. A merge here is a real lineage merge into an
                // entry this daemon committed on an earlier pass, not into a
                // registry that was empty again.
                restored_candidate_records = restored,
                admission = ?admitted.report.outcome,
            );
            for archived in &admitted.report.archived {
                // Every archive receipt is a recorded disposition, and the
                // commit above has already made it durable. This line makes
                // the disposition observable in the daemon's own operational
                // surface so an archival is never process-local (W3).
                tracing::info!(
                    target: "eliotd::diagnostics",
                    event = "eliotd.improvement_candidate_archived",
                    candidate_id = %archived.candidate_id,
                    target_surface = ?archived.target_surface,
                    cause = ?archived.cause,
                    archived_lifecycle = ?archived.archived_lifecycle,
                    archived_revision = archived.archived_revision,
                );
            }
        }
        Err(error) => {
            let _ = eliotd::diagnostics::ErrorRecord::of(
                eliotd::diagnostics::OwningComponent::DaemonRuntime,
                "improvement-commit",
                &error.to_string(),
            )
            .emit();
        }
    }
    Ok(())
}

/// Starts one improvement-intake step when its flight is idle. The
/// observation is captured from the activation state before the future is
/// created, so the decision and its evidence are the same observation; a busy
/// flight is left untouched.
///
/// The retained Kernel client is cloned into the future because the step now
/// performs an authenticated named read — the deduplication-registry read-back
/// — as well as the durable write. It is the same retained transport every
/// other read in this loop uses, not a second client.
fn maybe_start_improvement_intake(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    activation_flight: &ActivationFlight,
    flight: &mut ImprovementIntakeFlight,
) {
    if !matches!(flight, ImprovementIntakeFlight::Idle) {
        return;
    }
    let observation = idle_maintenance_observation(activation_flight);
    let kernel = Arc::clone(kernel);
    let composition = Arc::clone(composition);
    *flight = ImprovementIntakeFlight::InFlight(ImprovementIntakeFlightState {
        future: Box::pin(async move {
            let result = run_improvement_intake(&kernel, &composition, observation).await;
            ImprovementIntakeCompletion::Settled(result)
        }),
    });
}

/// Polls one retained improvement-intake step, pending forever while idle so
/// health and shutdown stay pollable with no step outstanding.
async fn next_improvement_intake_completion(
    flight: &mut ImprovementIntakeFlight,
) -> ImprovementIntakeCompletion {
    match flight {
        ImprovementIntakeFlight::Idle => std::future::pending().await,
        ImprovementIntakeFlight::InFlight(state) => (&mut state.future).await,
    }
}

/// Releases a completed improvement-intake flight so a later cadence
/// observation can start. Settlement itself is synchronous and cannot block
/// the run loop; the step never fails the loop, so every outcome idles. The
/// settled result is consumed here so a step that did not complete is still
/// recorded as a diagnostic rather than dropped.
fn settle_improvement_intake_completion(
    flight: &mut ImprovementIntakeFlight,
    completion: ImprovementIntakeCompletion,
) {
    if let ImprovementIntakeCompletion::Settled(Err(error)) = completion {
        let _ = eliotd::diagnostics::ErrorRecord::of(
            eliotd::diagnostics::OwningComponent::DaemonRuntime,
            "improvement-intake-settle",
            &error,
        )
        .emit();
    }
    *flight = ImprovementIntakeFlight::Idle;
}

/// Pure tick gate: the `TestD` owner timer starts work only when the flight
/// is idle. The in-flight step is polled in its own `select!` branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestdOwnerTickDecision {
    StartDrain,
    SkipInFlight,
}

fn decide_testd_owner_tick(flight: &TestdOwnerFlight) -> TestdOwnerTickDecision {
    match flight {
        TestdOwnerFlight::Idle => TestdOwnerTickDecision::StartDrain,
        TestdOwnerFlight::InFlight(_) => TestdOwnerTickDecision::SkipInFlight,
    }
}

/// Starts one `TestD` owner drain step for the finish cadence (issue #325):
/// bind pending verifier dispatches, publish terminal verifier facts,
/// submit finish candidates, and acknowledge terminals, all through the
/// Kernel owner routes. At most one bounded step per tick; an empty poll
/// backs off until the next tick.
fn start_testd_owner_drain(
    kernel: &Arc<DaemonKernelClient>,
    composition: SharedComposition,
) -> Pin<Box<dyn std::future::Future<Output = TestdOwnerCompletion>>> {
    let kernel_clone = Arc::clone(kernel);
    Box::pin(async move {
        // Boxed: the phase-split drain future exceeds the inline bound, and
        // keeping it on the stack would push this flight future past the
        // large-future threshold. Same future, same step.
        TestdOwnerCompletion::Settled(
            Box::pin(run_testd_owner_drain(&kernel_clone, composition)).await,
        )
    })
}

/// Starts the `TestD` owner drain step when its flight is idle. Checked on
/// every tick alongside the other pollers so terminal evidence publishes
/// while activations are in flight.
fn maybe_start_testd_owner_drain(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    flight: &mut TestdOwnerFlight,
) {
    if decide_testd_owner_tick(flight) == TestdOwnerTickDecision::StartDrain {
        *flight = TestdOwnerFlight::InFlight(TestdOwnerFlightState {
            future: start_testd_owner_drain(kernel, Arc::clone(composition)),
        });
    }
}

/// Polls the one in-flight `TestD` owner drain step, pending forever while
/// idle so health and shutdown stay pollable with no step outstanding.
async fn next_testd_owner_completion(flight: &mut TestdOwnerFlight) -> TestdOwnerCompletion {
    match flight {
        TestdOwnerFlight::Idle => std::future::pending::<TestdOwnerCompletion>().await,
        TestdOwnerFlight::InFlight(state) => (&mut state.future).await,
    }
}

/// Settles one completed `TestD` owner drain step back to idle. A drained
/// step idles until the next tick; only a step failure fails the daemon
/// closed — a poisoned row that cannot drain is recorded as a diagnostic
/// and skipped inside the step, never silently discarded and never fatal.
fn settle_testd_owner_completion(
    completion: TestdOwnerCompletion,
    flight: &mut TestdOwnerFlight,
) -> Result<(), String> {
    match completion {
        TestdOwnerCompletion::Settled(Ok(_)) => {
            *flight = TestdOwnerFlight::Idle;
            Ok(())
        }
        TestdOwnerCompletion::Settled(Err(error)) => Err(error),
    }
}

/// Runs one `TestD` owner drain step through the production finish caller.
///
/// #18 item B: the bounded step is split into phases so the composition guard
/// is never held across a Kernel exchange at all:
///
/// ```text
/// (a) guard held   — read the composition readiness gate (no exchange);
/// (b) no guard     — both bounded owner polls;
/// (c) guard held   — plan the exact owner bind payload for one pending
///                    dispatch (a pure read of the retained owners);
/// (d) no guard     — the owner bind leg;
/// (e) no guard     — the two Governor-owned canonical legs for one terminal
///                    row, phase-split inside
///                    `commit_testd_terminal_owner_fact` (plan under the guard,
///                    exchange without it, revalidate under it again);
/// (f) no guard     — the owner terminal ack leg.
/// ```
///
/// Before this change the guard was held across the whole step: both polls plus
/// three Kernel exchanges per row, so one bounded step stalled every other task
/// waiting on the same lock. The remaining guard-held phases are pure reads of
/// the retained owners and synchronous owner refreshes, so none of them awaits.
/// Semantics are unchanged: one bounded step per
/// tick, at most one outstanding drain, exact replay rather than duplication,
/// a poisoned row recorded as a diagnostic and skipped, and only a transport
/// failure of a poll failing the daemon closed.
async fn run_testd_owner_drain(
    kernel: &DaemonKernelClient,
    composition: SharedComposition,
) -> Result<TestdOwnerDrainOutcome, String> {
    // #740-style receipt span over the bind/publish/submit/ack drain step.
    // Row counts are named; digests and payload bytes never are.
    let _span = tracing::info_span!("eliotd.testd_owner_drain").entered();
    if !testd_owner_drain_admitted(&composition).await {
        return Err(
            "TestD owner drain: TestD owner drain needs a Ready Governor composition".to_owned(),
        );
    }
    let mut outcome = TestdOwnerDrainOutcome::default();
    // (b) no guard: the first bounded owner poll.
    let pending = query_testd_owner_pending_dispatches(kernel)
        .await
        .map_err(|error| format!("TestD owner drain: {error}"))?;
    for entry in &pending {
        // (c) guard held: plan the exact bind payload, then release it.
        let planned = {
            let guard = composition.lock().await;
            guard.plan_testd_verifier_dispatch_binding(entry)
        };
        let bound = match planned {
            Ok(binding) => {
                // (d) no guard: the owner bind leg.
                bind_testd_owner_verifier_dispatch(kernel, &entry.job.job_id, binding).await
            }
            Err(error) => Err(error),
        };
        match bound {
            Ok(()) => outcome.dispatch_bindings_persisted += 1,
            Err(error) => {
                outcome.rows_skipped += 1;
                emit_testd_owner_drain_skip(&entry.job.job_id, &error);
            }
        }
    }
    // (b) no guard: the second bounded owner poll.
    let terminals = query_testd_owner_terminal_evidence(kernel)
        .await
        .map_err(|error| format!("TestD owner drain: {error}"))?;
    for evidence in &terminals {
        // (e) no guard: the two Governor-owned canonical legs, phase-split
        // inside so the guard covers only their pure reads.
        let committed = commit_testd_terminal_owner_fact(kernel, &composition, evidence).await;
        match committed {
            Ok(receipt) => {
                // (f) no guard: the owner terminal ack leg.
                match ack_testd_owner_terminal_completion(kernel, &evidence.job.job_id, receipt)
                    .await
                {
                    Ok(()) => {
                        outcome.terminals_drained += 1;
                        outcome.finish_decisions_persisted += 1;
                        outcome.terminals_acked += 1;
                    }
                    Err(error) => {
                        outcome.rows_skipped += 1;
                        emit_testd_owner_drain_skip(&evidence.job.job_id, &error);
                    }
                }
            }
            Err(error) => {
                outcome.rows_skipped += 1;
                emit_testd_owner_drain_skip(&evidence.job.job_id, &error);
            }
        }
    }
    Ok(outcome)
}

/// Reads the composition readiness gate the drain requires, holding the guard
/// only for that synchronous read.
async fn testd_owner_drain_admitted(composition: &SharedComposition) -> bool {
    let guard = composition.lock().await;
    guard.readiness() == eliot_governor::CompositionReadiness::Ready
}

/// Submits one already-resolved v2 result through the existing authenticated
/// transport. Every valid disposition is submitted; no disposition is coerced
/// to success and none is silently discarded.
///
/// On a possible submission ambiguity (unknown outcome / reconnect) the exact
/// retained ticket/result identity is reconciled before any second Governor
/// read: the retained result is reused verbatim, never recomputed, and no
/// local replay cache or timer is introduced. The typed acknowledgement
/// creates no Session, authority, or Finish; only bounded ticket identity is
/// carried in diagnostics.
async fn dispatch_agent_activation_result(
    kernel: &DaemonKernelClient,
    ticket: &AgentActivationResolutionTicket,
    result: AgentActivationResolutionResult,
    owner_readback: Option<eliot_protocol::AgentActivationOwnerReadback>,
) -> Result<(), ActivationDispatchError> {
    // #740: dispatch span over the submit-then-reconcile path. The retained
    // result is reused verbatim; only bounded ticket identity is carried.
    let _span = tracing::info_span!(
        "eliotd.activation_dispatch",
        ticket = %eliotd::diagnostics::sanitize_identity(&ticket.ticket_id)
    )
    .entered();
    observe_transient_deferral(&result);
    // The semantic and P-07 owner readbacks were captured before this
    // asynchronous flight was published. The submit path reuses both values
    // verbatim; it never performs a second Governor read.
    match kernel
        .submit_agent_activation_result(&result, owner_readback)
        .await
    {
        Ok(ack) => classify_submit_ack(ticket, &result, &ack),
        // #839 (W14/A3): the submit failure's own provenance now decides the
        // path. A failure that provably never reached the transport, and a
        // definitive non-acceptance, hold nothing for Kernel to reconcile and
        // are reported as-is; only a possibly-submitted failure retains the
        // exact ticket/result identity and reconciles it from Kernel retention
        // before any second Governor read. The retained result is never
        // recomputed on any path.
        Err(ActivationSubmitError::Expired) => Err(ActivationDispatchError::Expired),
        Err(
            ActivationSubmitError::NotAttempted { detail }
            | ActivationSubmitError::Rejected { detail },
        ) => Err(ActivationDispatchError::Hard(format!(
            "daemon activation result submit ticket {}: {detail}",
            ticket.ticket_id
        ))),
        Err(submit_error @ ActivationSubmitError::PossiblySubmitted { .. }) => {
            // The submit may have committed before the acknowledgement was
            // lost. Retain the exact ticket/result identity and reconcile
            // from Kernel retention before any second Governor read. Do not
            // recompute a different result here.
            let submit_detail = submit_error.detail().to_owned();
            let query = retained_reconcile_query(ticket, &result)?;
            let ack = kernel
                .reconcile_agent_activation_result(&query)
                .await
                .map_err(|error| {
                    ActivationDispatchError::Hard(format!(
                        "Kernel activation result reconcile ticket {}: {error}; submit: {submit_detail}",
                        ticket.ticket_id
                    ))
                })?;
            classify_reconcile_ack(ticket, &result, &ack, &submit_detail)
        }
    }
}

/// Builds the lost-acknowledgement reconcile query from the single retained
/// result. The ticket id and result digest are cloned verbatim; no second
/// Governor read and no recompute occur here.
fn retained_reconcile_query(
    ticket: &AgentActivationResolutionTicket,
    result: &AgentActivationResolutionResult,
) -> Result<AgentActivationResultReconcile, ActivationDispatchError> {
    AgentActivationResultReconcile::new(ticket.ticket_id.clone(), result.result_sha256.clone())
        .map_err(|error| {
            ActivationDispatchError::Hard(format!(
                "daemon activation reconcile ticket {} query: {error}",
                ticket.ticket_id
            ))
        })
}

/// Classifies a submit acknowledgement against the retained identity. Unknown
/// preserves the original ticket/result identity verbatim in a typed outcome
/// instead of silently dropping it.
fn classify_submit_ack(
    ticket: &AgentActivationResolutionTicket,
    result: &AgentActivationResolutionResult,
    ack: &AgentActivationResultAck,
) -> Result<(), ActivationDispatchError> {
    if ack.ticket_id != ticket.ticket_id
        || ack.ticket_id != result.ticket_id
        || ack.result_sha256 != result.result_sha256
    {
        return Err(ActivationDispatchError::Hard(format!(
            "Kernel activation result ack ticket {} binding mismatch",
            ticket.ticket_id
        )));
    }
    // #1115: the full accepted-payload validation belongs to the `Accepted`
    // arm only, exactly as in reconcile classification. Running the
    // accepted-result validator before this match rejected every closed
    // `Unknown` acknowledgement as a payload mismatch and made the typed
    // `Unknown` outcome below unreachable.
    match ack.outcome {
        AgentActivationResultAckOutcome::Accepted => {
            ack.validate_against_result(result).map_err(|error| {
                ActivationDispatchError::Hard(format!(
                    "Kernel activation result ack payload mismatch: {error}"
                ))
            })?;
            // #740: ack record. Stable retained-result correlation is not
            // completed work; no completion is claimed here.
            let _ = eliotd::diagnostics::emit_activation_ack(
                &ticket.ticket_id,
                &result.result_sha256,
                &ack.outcome,
            );
            Ok(())
        }
        AgentActivationResultAckOutcome::Unknown => Err(ActivationDispatchError::Unknown {
            ticket_id: ticket.ticket_id.clone(),
            result_sha256: result.result_sha256.clone(),
            detail: format!(
                "Kernel activation result ack ticket {} unknown without retention",
                ticket.ticket_id
            ),
        }),
    }
}

/// Classifies a reconcile acknowledgement after a submit failure. The
/// retained result is reused verbatim; Unknown preserves the original
/// ticket/result identity verbatim and never triggers a recompute.
fn classify_reconcile_ack(
    ticket: &AgentActivationResolutionTicket,
    result: &AgentActivationResolutionResult,
    ack: &AgentActivationResultAck,
    submit_detail: &str,
) -> Result<(), ActivationDispatchError> {
    match ack.outcome {
        AgentActivationResultAckOutcome::Accepted => {
            ack.validate_against_result(result).map_err(|error| {
                ActivationDispatchError::Hard(format!(
                    "Kernel activation reconcile ack payload mismatch: {error}"
                ))
            })?;
            // #740: reconcile-ack record. Reconciled retention is not
            // completed work; no completion is claimed here.
            let _ = eliotd::diagnostics::emit_activation_ack(
                &ticket.ticket_id,
                &result.result_sha256,
                &ack.outcome,
            );
            if ack.ticket_id != ticket.ticket_id || ack.result_sha256 != result.result_sha256 {
                return Err(ActivationDispatchError::Hard(format!(
                    "Kernel activation result reconcile ticket {} binding mismatch",
                    ticket.ticket_id
                )));
            }
            Ok(())
        }
        AgentActivationResultAckOutcome::Unknown => Err(ActivationDispatchError::Unknown {
            ticket_id: ticket.ticket_id.clone(),
            result_sha256: result.result_sha256.clone(),
            detail: format!(
                "Kernel activation result submit ticket {} failed without retention: {submit_detail}",
                ticket.ticket_id
            ),
        }),
    }
}

/// Observes the transient `NotReady` deferral without adding retry policy.
/// The predecessor result remains immutable. Reconsideration is possible only
/// through a fresh Kernel-issued successor ticket after the declared due time
/// (`not_before`) and only when the named dependency revision has materially
/// changed; Kernel owns that gate. Claim-lease expiry never triggers reuse, and
/// any changed result under the predecessor ticket is an identity conflict.
#[expect(
    clippy::print_stderr,
    reason = "operator stderr line kept byte-exact per #740 alongside its structured tracing twin (#838)"
)]
fn observe_transient_deferral(result: &AgentActivationResolutionResult) {
    if result.is_transient_retry()
        && let Some(not_before) = transient_not_before(result)
    {
        TRANSIENT_DEFERRAL_OBSERVED.fetch_add(1, Ordering::Relaxed);
        // #740: structured twin of the operator stderr line below. The
        // existing line keeps its exact bytes; this only adds the typed
        // record to the diagnostics sink.
        tracing::info!(
            target: "eliotd::diagnostics",
            event = "eliotd.transient_deferral",
            ticket = %eliotd::diagnostics::sanitize_identity(&result.ticket_id),
            not_before = not_before,
        );
        eprintln!(
            "eliotd transient activation deferral ticket {} not_before {not_before}",
            result.ticket_id
        );
    }
}

fn transient_not_before(result: &AgentActivationResolutionResult) -> Option<u64> {
    match &result.disposition {
        AgentActivationResolutionDisposition::NotReady { retry, .. } => {
            Some(retry.not_before_unix_ms)
        }
        _ => None,
    }
}

fn unix_ms(now: SystemTime) -> Result<u64, String> {
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("daemon activation clock precedes Unix epoch: {error}"))?;
    elapsed
        .as_millis()
        .try_into()
        .map_err(|_| "daemon activation clock exceeds u64 milliseconds".to_owned())
}

fn activation_deadline_expired(now: u64, deadline: u64) -> bool {
    now >= deadline
}

fn ready_message(
    status: &DaemonStatus,
    product_proof: Option<ProductProofStatusWire>,
) -> ReadyMessage {
    ReadyMessage::Ready {
        service: SERVICE_NAME,
        protocol: PROTOCOL_VERSION,
        generation: status.generation,
        authority_epoch: status.authority_epoch,
        health: status.health.clone(),
        degraded: status.degraded,
        product_proof,
    }
}

pub(super) fn write_json(message: &ReadyMessage) -> Result<(), String> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_json_to(&mut output, message)
}

fn write_json_to(output: &mut impl Write, message: &ReadyMessage) -> Result<(), String> {
    serde_json::to_writer(&mut *output, message)
        .map_err(|error| format!("daemon status encode/write: {error}"))?;
    output
        .write_all(b"\n")
        .map_err(|error| format!("daemon status delimiter write: {error}"))?;
    output
        .flush()
        .map_err(|error| format!("daemon status flush: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_tick_survives_faster_activation_poll() {
        let mut cadence =
            LoopCadence::with_periods(Duration::from_millis(5), Duration::from_millis(20));
        let deadline = Instant::now() + Duration::from_millis(200);
        let mut activation_ticks = 0_u32;
        let mut health_ticks = 0_u32;

        while health_ticks < 2 {
            tokio::select! {
                _ = cadence.activation_poll.tick() => {
                    activation_ticks += 1;
                }
                _ = cadence.health_heartbeat.tick() => {
                    health_ticks += 1;
                }
                () = tokio::time::sleep_until(deadline) => {
                    panic!("health cadence was starved by the faster activation poll");
                }
            }
        }

        assert!(activation_ticks >= 2);
        assert_eq!(health_ticks, 2);
    }

    #[test]
    fn activation_clock_preserves_exact_unix_milliseconds() {
        let observed = UNIX_EPOCH + Duration::from_millis(42);
        assert_eq!(unix_ms(observed), Ok(42));
    }

    #[test]
    fn activation_clock_rejects_time_before_unix_epoch() {
        let observed = UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("one second before Unix epoch must be representable");
        let error = unix_ms(observed).expect_err("pre-epoch clock must fail closed");
        assert!(error.contains("precedes Unix epoch"));
    }

    #[test]
    fn skill_tool_source_attach_proves_the_live_registry_edge() {
        // Real tools owner through the Governor hook, executed in the
        // production binary target: the attach pins a non-blank admitted
        // definition version with no skill inputs consumed and nothing
        // delivered.
        let admitted = attach_skill_tool_source().expect("live canonical tool source must attach");
        assert!(!admitted.trim().is_empty());
    }

    #[test]
    fn status_writer_emits_one_newline_delimited_json_record() {
        let mut output = Vec::new();
        write_json_to(
            &mut output,
            &ReadyMessage::Degraded {
                service: SERVICE_NAME,
                protocol: PROTOCOL_VERSION,
                reason: "injected degradation".to_owned(),
            },
        )
        .expect("status record must be written");

        assert_eq!(output.last(), Some(&b'\n'));
        let value: serde_json::Value =
            serde_json::from_slice(&output[..output.len() - 1]).expect("valid JSON record");
        assert_eq!(value["status"], "degraded");
        assert_eq!(value["reason"], "injected degradation");
    }

    struct RejectingWriter;

    impl Write for RejectingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected status output failure",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn status_writer_surfaces_write_failure() {
        let error = write_json_to(
            &mut RejectingWriter,
            &ReadyMessage::Error {
                service: SERVICE_NAME,
                protocol: PROTOCOL_VERSION,
                error: "primary failure".to_owned(),
            },
        )
        .expect_err("writer failure must not be ignored");

        assert!(error.contains("daemon status encode/write"));
        assert!(error.contains("injected status output failure"));
    }

    #[tokio::test]
    async fn activation_flight_gates_second_start_and_keeps_health_and_shutdown_pollable() {
        assert_eq!(
            decide_activation_tick(&ActivationFlight::Idle),
            ActivationTickDecision::StartClaim
        );
        let mut flight = ActivationFlight::InFlight(ActivationFlightState {
            future: Box::pin(std::future::pending::<ActivationCompletion>()),
            retained: None,
        });
        assert_eq!(
            decide_activation_tick(&flight),
            ActivationTickDecision::SkipInFlight
        );

        let mut cadence =
            LoopCadence::with_periods(Duration::from_millis(5), Duration::from_millis(10));
        let deadline = Instant::now() + Duration::from_millis(300);
        let mut health_served = false;
        let mut shutdown_served = false;
        let mut activation_ticks = 0_u32;
        let shutdown = tokio::time::sleep(Duration::from_millis(60));
        tokio::pin!(shutdown);
        while !health_served || !shutdown_served {
            tokio::select! {
                _ = cadence.activation_poll.tick() => {
                    assert_eq!(
                        decide_activation_tick(&flight),
                        ActivationTickDecision::SkipInFlight
                    );
                    activation_ticks += 1;
                }
                completion = async {
                    match &mut flight {
                        ActivationFlight::Idle => {
                            std::future::pending::<ActivationCompletion>().await
                        }
                        ActivationFlight::InFlight(state) => (&mut state.future).await,
                    }
                } => {
                    let _ = completion;
                    panic!("never-completing activation future must stay pending");
                }
                _ = cadence.health_heartbeat.tick() => {
                    health_served = true;
                }
                () = &mut shutdown => {
                    shutdown_served = true;
                }
                () = tokio::time::sleep_until(deadline) => {
                    panic!("health/shutdown starved by never-completing activation");
                }
            }
        }
        assert!(health_served && shutdown_served);
        assert!(activation_ticks >= 1);
    }

    #[test]
    fn submit_failure_reconcile_unknown_reuses_original_identity() {
        use std::cell::Cell;
        use std::num::NonZeroU64;

        use eliot_contracts::{EpochId, EpochLineageId, RequestId, ResourceGeneration, StateFence};
        use eliot_protocol::{AgentActivationResultAck, AgentActivationRetryDirective};

        const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
        let epoch = EpochId::new(
            EpochLineageId::new(LINEAGE).expect("valid lineage"),
            NonZeroU64::new(1).expect("nonzero sequence"),
        )
        .expect("valid epoch");
        let fence = StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"));
        let ticket = AgentActivationResolutionTicket {
            wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
            ticket_id: "ticket-1".to_owned(),
            activation_request_id: RequestId::new("activation-request-1").expect("request id"),
            demand_id: "demand-1".to_owned(),
            activation_request_sha256: "a".repeat(64),
            peer_admission_receipt_sha256: "b".repeat(64),
            connection_id: "connection-1".to_owned(),
            workspace_selector: None,
            cancellation_id: "cancellation-1".to_owned(),
            state_fence: fence,
            kernel_deadline_unix_ms: 100,
            successor_of: None,
            ticket_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("valid ticket");

        let resolver_calls = Cell::new(0_u32);
        let resolve_once = || {
            resolver_calls.set(resolver_calls.get() + 1);
            AgentActivationResolutionResult::new(
                &ticket,
                50,
                AgentActivationResolutionDisposition::NotReady {
                    recovery_handle: "recovery-1".to_owned(),
                    retry: AgentActivationRetryDirective {
                        dependency_ref: "dep-1".to_owned(),
                        observed_dependency_revision: "rev-1".to_owned(),
                        not_before_unix_ms: 75,
                    },
                },
            )
            .expect("valid test result")
        };
        let result = resolve_once();
        let original_ticket = ticket.ticket_id.clone();
        let original_sha = result.result_sha256.clone();

        let query = retained_reconcile_query(&ticket, &result).expect("reconcile query");
        assert_eq!(query.ticket_id, original_ticket);
        assert_eq!(query.result_sha256, original_sha);

        let ack = AgentActivationResultAck::unknown(&query).expect("unknown ack");
        match classify_reconcile_ack(&ticket, &result, &ack, "injected submit transport failure") {
            Err(ActivationDispatchError::Unknown {
                ticket_id,
                result_sha256,
                detail,
            }) => {
                assert_eq!(ticket_id, original_ticket);
                assert_eq!(result_sha256, original_sha);
                assert!(detail.contains(&original_ticket));
            }
            other => panic!("expected typed Unknown, got {other:?}"),
        }
        assert_eq!(resolver_calls.get(), 1);
    }

    // WORK_UNIT_CASE: 839/23
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "839 dispatch batch test: deterministic fixture construction only, no production path"
    )]
    fn transport_failure_is_distinct_from_semantic_result() {
        use std::num::NonZeroU64;

        use eliot_contracts::{EpochId, EpochLineageId, RequestId, ResourceGeneration, StateFence};

        const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
        let epoch = EpochId::new(
            EpochLineageId::new(LINEAGE).expect("valid lineage"),
            NonZeroU64::new(1).expect("nonzero sequence"),
        )
        .expect("valid epoch");
        let fence = StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"));
        let ticket = AgentActivationResolutionTicket {
            wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
            ticket_id: "ticket-23".to_owned(),
            activation_request_id: RequestId::new("activation-request-23").expect("request id"),
            demand_id: "demand-23".to_owned(),
            activation_request_sha256: "a".repeat(64),
            peer_admission_receipt_sha256: "b".repeat(64),
            connection_id: "connection-23".to_owned(),
            workspace_selector: None,
            cancellation_id: "cancellation-23".to_owned(),
            state_fence: fence,
            kernel_deadline_unix_ms: 100,
            successor_of: None,
            ticket_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("valid ticket");
        let result = AgentActivationResolutionResult::new(
            &ticket,
            50,
            AgentActivationResolutionDisposition::FailedInternal {
                failure_handle: "daemon.test:recovery".to_owned(),
            },
        )
        .expect("valid test result");
        let original_ticket = ticket.ticket_id.clone();
        let original_sha = result.result_sha256.clone();

        // A lost acknowledgement reconciles from retention: the query carries
        // only the retained ticket identity plus digest, never new semantics.
        let query = retained_reconcile_query(&ticket, &result).expect("reconcile query");
        assert_eq!(query.ticket_id, original_ticket);
        assert_eq!(query.result_sha256, original_sha);

        // Transport failure without retention is a typed Unknown carrying the
        // original identity and the submit detail: never Ok, never a semantic
        // disposition, never a recomputed result.
        let ack = AgentActivationResultAck::unknown(&query).expect("unknown ack");
        match classify_reconcile_ack(&ticket, &result, &ack, "injected submit transport failure") {
            Err(ActivationDispatchError::Unknown {
                ticket_id,
                result_sha256,
                detail,
            }) => {
                assert_eq!(ticket_id, original_ticket);
                assert_eq!(result_sha256, original_sha);
                assert!(detail.contains(&original_ticket));
                assert!(detail.contains("injected submit transport failure"));
            }
            other => panic!("expected typed Unknown, got {other:?}"),
        }
        // The retained result is untouched: same digest, still bound to the
        // exact ticket, still no binding.
        assert_eq!(result.result_sha256, original_sha);
        assert!(result.resolved_binding().is_none());
        result.validate_against(&ticket).expect("valid binding");

        // A mismatched acknowledgement fails closed as Hard, never coerces.
        let accepted = AgentActivationResultAck::accepted(&result).expect("accept ack");
        let mut other_ticket = ticket.clone();
        other_ticket.ticket_id = "ticket-other".to_owned();
        other_ticket.ticket_sha256 = other_ticket.compute_digest().expect("digest");
        match classify_submit_ack(&other_ticket, &result, &accepted) {
            Err(ActivationDispatchError::Hard(_)) => {}
            other => panic!("expected Hard binding mismatch, got {other:?}"),
        }
    }

    // WORK_UNIT_CASE: 839/24
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "839 dispatch batch test: deterministic fixture construction only, no production path"
    )]
    fn unknown_reconnect_and_retained_replay_avoid_second_governor_read() {
        use std::cell::Cell;
        use std::num::NonZeroU64;

        use eliot_contracts::{EpochId, EpochLineageId, RequestId, ResourceGeneration, StateFence};

        const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
        let epoch = EpochId::new(
            EpochLineageId::new(LINEAGE).expect("valid lineage"),
            NonZeroU64::new(1).expect("nonzero sequence"),
        )
        .expect("valid epoch");
        let fence = StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"));
        let ticket = AgentActivationResolutionTicket {
            wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
            ticket_id: "ticket-24".to_owned(),
            activation_request_id: RequestId::new("activation-request-24").expect("request id"),
            demand_id: "demand-24".to_owned(),
            activation_request_sha256: "a".repeat(64),
            peer_admission_receipt_sha256: "b".repeat(64),
            connection_id: "connection-24".to_owned(),
            workspace_selector: None,
            cancellation_id: "cancellation-24".to_owned(),
            state_fence: fence,
            kernel_deadline_unix_ms: 100,
            successor_of: None,
            ticket_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("valid ticket");

        // One Governor-backed resolution only. The reconnect leg below must
        // reuse this retained result verbatim, never resolve again.
        let resolver_calls = Cell::new(0_u32);
        let resolve_once = || {
            resolver_calls.set(resolver_calls.get() + 1);
            AgentActivationResolutionResult::new(
                &ticket,
                50,
                AgentActivationResolutionDisposition::FailedInternal {
                    failure_handle: "daemon.test:recovery".to_owned(),
                },
            )
            .expect("valid test result")
        };
        let result = resolve_once();
        let original_ticket = ticket.ticket_id.clone();
        let original_sha = result.result_sha256.clone();

        // The reconcile query clones the retained identity verbatim: no
        // second Governor read and no recompute occur here.
        let query = retained_reconcile_query(&ticket, &result).expect("reconcile query");
        assert_eq!(query.ticket_id, original_ticket);
        assert_eq!(query.result_sha256, original_sha);

        // An unknown retention answer preserves the original identity
        // verbatim instead of triggering a recompute under a new digest.
        let ack = AgentActivationResultAck::unknown(&query).expect("unknown ack");
        match classify_reconcile_ack(&ticket, &result, &ack, "injected reconnect failure") {
            Err(ActivationDispatchError::Unknown {
                ticket_id,
                result_sha256,
                detail,
            }) => {
                assert_eq!(ticket_id, original_ticket);
                assert_eq!(result_sha256, original_sha);
                assert!(detail.contains(&original_ticket));
            }
            other => panic!("expected typed Unknown, got {other:?}"),
        }

        // A durable retained record surviving the reconnect answers with the
        // same stable positive acknowledgement. The daemon settles the
        // original result identity verbatim and never asks Governor to resolve
        // the ticket a second time.
        let reconciled = AgentActivationResultAck::accepted(&result).expect("reconciled ack");
        classify_reconcile_ack(
            &ticket,
            &result,
            &reconciled,
            "injected acknowledgement loss",
        )
        .expect("retained replay settles");
        assert_eq!(reconciled.ticket_id, original_ticket);
        assert_eq!(reconciled.result_sha256, original_sha);
        assert_eq!(reconciled.result.as_ref(), Some(&result));
        assert_eq!(
            resolver_calls.get(),
            1,
            "reconnect must not repeat the Governor read"
        );
        assert_eq!(result.result_sha256, original_sha);
        result.validate_against(&ticket).expect("valid binding");
    }

    // WORK_UNIT_CASE: 839/25
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "839 dispatch batch test: deterministic fixture construction only, no production path"
    )]
    fn acknowledgement_creates_no_session_authority_or_finish() {
        use std::num::NonZeroU64;

        use eliot_contracts::{EpochId, EpochLineageId, RequestId, ResourceGeneration, StateFence};

        const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
        let epoch = EpochId::new(
            EpochLineageId::new(LINEAGE).expect("valid lineage"),
            NonZeroU64::new(1).expect("nonzero sequence"),
        )
        .expect("valid epoch");
        let fence = StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"));
        let ticket = AgentActivationResolutionTicket {
            wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
            ticket_id: "ticket-25".to_owned(),
            activation_request_id: RequestId::new("activation-request-25").expect("request id"),
            demand_id: "demand-25".to_owned(),
            activation_request_sha256: "a".repeat(64),
            peer_admission_receipt_sha256: "b".repeat(64),
            connection_id: "connection-25".to_owned(),
            workspace_selector: None,
            cancellation_id: "cancellation-25".to_owned(),
            state_fence: fence,
            kernel_deadline_unix_ms: 100,
            successor_of: None,
            ticket_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("valid ticket");
        let result = AgentActivationResolutionResult::new(
            &ticket,
            50,
            AgentActivationResolutionDisposition::FailedInternal {
                failure_handle: "daemon.test:recovery".to_owned(),
            },
        )
        .expect("valid test result");
        let original_sha = result.result_sha256.clone();

        // The single positive acknowledgement shape settles with unit and
        // echoes the retained result verbatim. Fresh commit, exact replay,
        // and reconcile all use these identical bytes. The classifier takes
        // only the ticket, retained result, and ack: no composition or Session
        // handle enters, so no Session, authority, or Finish can be minted.
        let ack = AgentActivationResultAck::accepted(&result).expect("accept ack");
        let replay_ack = AgentActivationResultAck::accepted(&result).expect("replay ack");
        let reconcile_ack = AgentActivationResultAck::accepted(&result).expect("reconcile ack");
        assert_eq!(ack, replay_ack);
        assert_eq!(ack, reconcile_ack);
        classify_submit_ack(&ticket, &result, &ack).expect("positive ack settles");
        assert_eq!(ack.ticket_id, ticket.ticket_id);
        assert_eq!(ack.result_sha256, result.result_sha256);
        assert_eq!(ack.result.as_ref(), Some(&result));

        // Unknown is not a settlement: it preserves the original identity
        // in a typed outcome instead of minting anything.
        let query = retained_reconcile_query(&ticket, &result).expect("reconcile query");
        let unknown = AgentActivationResultAck::unknown(&query).expect("unknown ack");
        match classify_submit_ack(&ticket, &result, &unknown) {
            Err(ActivationDispatchError::Unknown {
                ticket_id,
                result_sha256,
                ..
            }) => {
                assert_eq!(ticket_id, ticket.ticket_id);
                assert_eq!(result_sha256, result.result_sha256);
            }
            other => panic!("expected typed Unknown, got {other:?}"),
        }

        // Nothing was minted: same digest, no binding, still bound to the
        // exact ticket.
        assert_eq!(result.result_sha256, original_sha);
        assert!(result.resolved_binding().is_none());
        result.validate_against(&ticket).expect("valid binding");
    }
}
