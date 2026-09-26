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

use std::io::{self, Write};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_governor::KernelTransitionPort;
use eliot_protocol::{
    AgentActivationKernelOwnerReadback, AgentActivationOwnerReadback,
    AgentActivationResolutionDisposition, AgentActivationResolutionResult,
    AgentActivationResolutionTicket, AgentActivationResultAck, AgentActivationResultAckOutcome,
    AgentActivationResultReconcile,
};
use eliot_runtime_contracts::DaemonProgressChannel;
use eliot_store_api::{StoreHealth, StoreHealthStatus};
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
    ActivationClaim, DaemonComposition, DaemonConfig, DaemonError, DaemonKernelClient,
    DaemonStatus, LocalReadSubmitOutcome, MaintenanceObservation, MaintenanceTriggerOrigin,
    PROTOCOL_VERSION, SELF_OBSERVED_FAMILY, SERVICE_NAME, forward_admitted_local_read,
    terminal_for_invalid_ticket,
};
use serde::Serialize;
use tokio::time::{Instant, Interval, MissedTickBehavior};

/// Shared daemon composition handle for the run loop. The loop holds no
/// long-lived borrow: every flight future locks briefly (readers) or for
/// one bounded drain (the TestD owner finish driver, the only writer), so
/// health, shutdown, and concurrent readers stay pollable. A poisoned row
/// never fails the daemon closed; transport failures do, mirroring the
/// local-read poller.
type SharedComposition = Arc<tokio::sync::Mutex<DaemonComposition>>;

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

pub(super) fn run() -> Result<(), String> {
    let launch = parse_launch_args(std::env::args_os().skip(1))?;
    let config = DaemonConfig::load_protected_bound(
        launch.config_path,
        &launch.config_sha256,
        &launch.launch_nonce,
        &launch.executable_sha256,
    )
    .map_err(|error| error.to_string())?;
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
    // #1145: root the Governor-owned improvement candidate route in the
    // production daemon: report the pipeline owner at startup (diagnostics
    // only). The candidate → experiment → evaluation → admission path itself
    // runs through `eliotd::govern_improvement_candidate` on live requests;
    // this reference keeps the owner identity observable without adding
    // policy semantics to the composition root.
    tracing::info!(
        target: "eliotd::diagnostics",
        event = "eliotd.improvement_pipeline_owner",
        owner = eliotd::governed_improvement_pipeline_owner(),
    );
    // #2560: the retained ledger answers no readiness question. This projection
    // derives the required set from the composition's own live owners and keeps
    // core control readiness separate from optional capability availability, so
    // one failed optional attach degrades exactly the operations that name it
    // instead of withholding readiness for the whole daemon. It performs no IO
    // and starts nothing.
    let startup_readiness = StartupReadinessProjection::new(bindings, &composition);
    // #1688 (I14.22): the Governor-owned maintenance trigger evaluator runs
    // here, at the one startup-reconciliation site that holds both the concrete
    // `Arc<DaemonKernelClient>` and the composition, and again once the declared
    // startup binding ledger has completed. The first pass observes that owner
    // recovery just rebuilt every owner at the current fence; the second
    // observes that the daemon is now whole, so first-run obligations became
    // visible. Both are pure reads of the composed Governor owner: no queue,
    // no scheduler, no background maintenance loop, and no new thread. Neither
    // is a startup gate - a trigger that cannot be evaluated is recorded as a
    // typed gap and the daemon continues, exactly like the attach paths above.
    note_maintenance_trigger_at(
        &composition,
        MaintenanceTriggerOrigin::StartupReconciliation,
        vec![startup_readiness.ledger_report()],
        false,
    );
    note_maintenance_trigger_at(
        &composition,
        MaintenanceTriggerOrigin::ColdStartCompletion,
        vec![
            format!(
                "startup_bindings_complete={}",
                startup_readiness.every_declared_capability_bound()
            ),
            startup_readiness.report(),
        ],
        false,
    );
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
    write_json(&ready_message(&status))?;

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
        (Ok(RunLoopExit::Shutdown), Err(error)) => Err(report_terminal_failure(&kernel, error)),
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
        (Err(error), Ok(())) => Err(report_terminal_failure(&kernel, error)),
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
            eliotd::notification_board_attach::NotificationBoardAttach::Ready(records) => {
                tracing::info!(
                    target: "eliotd::diagnostics",
                    event = "eliotd.notification_snapshot_attached",
                    record_count = records.len(),
                );
                Ok(RetainedStartupBinding::NotificationSnapshot {
                    record_count: records.len(),
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

async fn run_loop(
    kernel: Arc<DaemonKernelClient>,
    composition: SharedComposition,
    mut supervision_progress: Option<eliotd::SupervisionProgressProducer>,
    // #2560/#2647: sole owner of the readiness projection. A local-read
    // flight prepares from an immutable snapshot and returns only the bounded
    // delta it actually observed, so there is one authoritative copy and a
    // late completion can never overwrite newer owner observations.
    mut startup_readiness: StartupReadinessProjection,
) -> Result<RunLoopExit, String> {
    let mut cadence = LoopCadence::production();
    // Sole owner of activation state. No second owner and no second
    // concurrent activation exist: the timer starts work only when idle and
    // the in-flight step is polled only in its own branch below.
    let mut flight = ActivationFlight::Idle;
    // Sole owner of local-read poll state (Implements #18). The same tick
    // drives it independently of the activation flight: a null claim backs
    // off until the next tick, while a claimed pair forwards through the
    // Kernel `local_read` leg and submits its result body before idling.
    let mut local_read_flight = LocalReadFlight::Idle;
    // #2100: O1 owner-feed trigger state. The runtime retains one trigger
    // across passes so an unchanged provider performs no IO, while a
    // revision advance or a recovery re-presentation republishes through the
    // full read->publish->readback exchange. Degradation never fails the
    // loop: pending grants stay pending until a later pass binds them.
    // Issue #2559: the trigger travels with its own polled flight below, so
    // a stalled exchange never stalls health or shutdown polling.
    let mut owner_feed = Some(eliotd::OwnerFeedTrigger::new());
    // Sole owner of owner-feed sync state. One bounded read->publish->readback
    // exchange is outstanding at most; the health tick starts it when idle
    // and its completion branch settles it back, exactly like the other
    // flights. No second owner and no untracked spawn exist.
    let mut owner_feed_flight = OwnerFeedFlight::Idle;
    // Sole owner of TestD owner drain state (issue #325). The same tick
    // drives it independently of the other flights: one bounded drain step
    // binds pending verifier dispatches, publishes terminal verifier facts,
    // submits finish candidates, and acknowledges terminals, all through
    // the Kernel owner routes.
    let mut testd_owner_flight = TestdOwnerFlight::Idle;
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
    );
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|error| format!("daemon shutdown signal: {error}"))?;
                // Issue #2559: already-started flights drain together inside
                // one finite budget while every one of them stays polled; no
                // new claim starts here.
                let exit = drain_flights_on_shutdown(
                    &kernel,
                    &composition,
                    &mut flight,
                    &mut local_read_flight,
                    &mut testd_owner_flight,
                    &mut owner_feed_flight,
                    &mut owner_feed,
                )
                .await?;
                return Ok(exit);
            }
            _ = cadence.activation_poll.tick() => {
                // The per-tick poller and drain gates, and the activation
                // claim's own idle gate, all live in `start_tick_work` so the
                // ordering those comments describe is stated once. The claim
                // carries the composition handle it needs to read the named
                // dependency discriminator before the request.
                start_tick_work(
                    &kernel,
                    &composition,
                    &startup_readiness,
                    &mut local_read_flight,
                    &mut testd_owner_flight,
                    &mut flight,
                );
                // #1688 (I14.22): the idle trigger rides this cadence branch
                // because it is the one place that observes the activation
                // flight, so the `idle` gate the evaluator consumes is a real
                // observation of admitted interactive work rather than a
                // literal. Separate cadence and separate observation from the
                // health-heartbeat admitted-observation trigger below.
                note_idle_maintenance_trigger(&composition, &flight).await;
            }
            completion = next_activation_completion(&mut flight) => {
                settle_activation_completion(
                    &kernel,
                    &composition,
                    &mut supervision_progress,
                    &mut flight,
                    completion,
                )?;
            }
            local_read_completion = next_local_read_completion(&mut local_read_flight) => {
                settle_local_read_completion_updating_readiness(
                    local_read_completion,
                    &mut local_read_flight,
                    &mut startup_readiness,
                )?;
            }
            testd_owner_completion = next_testd_owner_completion(&mut testd_owner_flight) => {
                settle_testd_owner_completion(testd_owner_completion, &mut testd_owner_flight)?;
            }
            owner_feed_trigger = next_owner_feed_completion(&mut owner_feed_flight) => {
                settle_owner_feed_completion(
                    owner_feed_trigger,
                    &mut owner_feed,
                    &mut owner_feed_flight,
                );
            }
            _ = cadence.health_heartbeat.tick() => {
                run_health_heartbeat_tick(
                    &kernel,
                    &composition,
                    &mut owner_feed,
                    &mut owner_feed_flight,
                    &mut supervision_progress,
                    &flight,
                    &mut startup_readiness,
                )
                .await?;
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
            note_supervision_claim(supervision_progress.as_mut());
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
/// no lock wait and no other flight is awaited here, so activation,
/// local-read, `TestD`, health and shutdown stay pollable throughout.
fn settle_activation_completion(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    supervision_progress: &mut Option<eliotd::SupervisionProgressProducer>,
    flight: &mut ActivationFlight,
    completion: ActivationCompletion,
) -> Result<(), String> {
    match completion {
        ActivationCompletion::Claim(claim_outcome) => {
            let claim = claim_outcome?;
            // Issue #202 (owner decision ii), validate-first.
            match settle_activation_claim(claim, supervision_progress)? {
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
            // #1115: a Kernel-owned deadline expiry is a completed step, not a
            // dispatch this daemon applied. It retires the ticket exactly like
            // an accepted dispatch — idle, no retry, no reconcile — so both
            // settle through the same supervision note.
            Ok(()) | Err(ActivationDispatchError::Expired) => {
                note_supervision_applied(supervision_progress.as_mut());
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
/// The local-read poller and the TestD owner drain each ride the same tick
/// under their own gate: both must start even while an activation is in
/// flight, so their gates are checked before the activation early-continue.
/// The activation claim itself still starts only when its flight is idle.
fn start_tick_work(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    startup_readiness: &StartupReadinessProjection,
    local_read_flight: &mut LocalReadFlight,
    testd_owner_flight: &mut TestdOwnerFlight,
    flight: &mut ActivationFlight,
) {
    maybe_start_local_read_poll(kernel, composition, startup_readiness, local_read_flight);
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
fn note_supervision_claim(producer: Option<&mut eliotd::SupervisionProgressProducer>) {
    if let Some(producer) = producer {
        producer.note_claim();
    }
}

/// Notes one Kernel-accepted dispatch on the supervision Dispatch/Apply
/// channels when a supervision lineage exists. Mirrors
/// [`note_supervision_claim`].
fn note_supervision_applied(producer: Option<&mut eliotd::SupervisionProgressProducer>) {
    if let Some(producer) = producer {
        producer.note_kernel_applied();
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
    evidence_refs: Vec<String>,
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

/// Runs one Governor maintenance trigger evaluation from a real durable
/// trigger site (I14.22, issue #1688).
///
/// This is the single runtime entry for every wired trigger. It is
/// deliberately tolerant: [`DaemonComposition::note_maintenance_trigger`]
/// records an explicit typed gap through the existing minimal operational
/// diagnostics and returns, so a maintenance observation can never become a
/// startup gate, a readiness gate, or a daemon-killing error. I14.22 keeps an
/// unevaluable trigger durable and surfaces it on the next eligible startup
/// rather than dropping it.
fn note_maintenance_trigger_at(
    composition: &DaemonComposition,
    origin: MaintenanceTriggerOrigin,
    evidence_refs: Vec<String>,
    activation_in_flight: bool,
) {
    composition.note_maintenance_trigger(maintenance_observation(
        origin,
        evidence_refs,
        activation_in_flight,
    ));
}

/// Evaluates the idle trigger from the activation-poll cadence branch.
///
/// The evidence is the flight state the tick just decided from, so the
/// decision and its evidence are the same observation. This is a periodic
/// idle *observation*, not a busy-to-idle edge detector: the loop retains no
/// previous-idle flag, and inventing one to manufacture a transition edge
/// would be a fabricated event source.
async fn note_idle_maintenance_trigger(composition: &SharedComposition, flight: &ActivationFlight) {
    let activation_in_flight = matches!(flight, ActivationFlight::InFlight(_));
    let guard = composition.lock().await;
    note_maintenance_trigger_at(
        &guard,
        MaintenanceTriggerOrigin::IdleTransition,
        vec![format!("activation_in_flight={activation_in_flight}")],
        activation_in_flight,
    );
}

/// Submits one owner-side canonical notification for a blocked automation
/// decision (issue #1780, I11.5).
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
) {
    match eliotd::notification_state_emit::emit_blocked_automation_notification(
        kernel, fence, decision,
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
            let _ = eliotd::diagnostics::ErrorRecord::of(
                eliotd::diagnostics::OwningComponent::DaemonRuntime,
                "notification-state",
                &error.to_string(),
            )
            .emit();
        }
    }
}

/// Runs one health-heartbeat tick (Implements #88, wave 3): the Kernel
/// health poll stays evidence-only, then the same tick submits supervision
/// progress built from observed work. The poll's Store dimension is reused as
/// the observation's `store_dependency` evidence, never as renewal authority.
///
/// Issue #2559: the tick never waits for the owner-feed exchange. The
/// exchange rides its own polled flight started below when idle, so a
/// stalled owner-feed step cannot stall health or supervision polling.
///
/// #18 item A: the health poll runs unconditionally, so liveness stays observed
/// even for a generation that never reported ready; only the progress renewal
/// is absent, because the Kernel authored no supervision lineage for it.
async fn run_health_heartbeat_tick(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    owner_feed: &mut Option<eliotd::OwnerFeedTrigger>,
    owner_feed_flight: &mut OwnerFeedFlight,
    supervision_progress: &mut Option<eliotd::SupervisionProgressProducer>,
    flight: &ActivationFlight,
    startup_readiness: &mut StartupReadinessProjection,
) -> Result<(), String> {
    let health: StoreHealth = KernelTransitionPort::health(kernel.as_ref())
        .await
        .map_err(|error| format!("Kernel health heartbeat: {error}"))?;
    // #1688 (I14.22): the Kernel health poll is this daemon's one admitted
    // self-observation per heartbeat, so it is the admitted-observation
    // trigger. The evidence identities are the observed health status and the
    // store manifest digest the poll actually returned - never a synthetic
    // signal. `activation_in_flight` is the same live observation the
    // supervision submit below uses, so the `idle` gate stays consistent with
    // what this tick actually did.
    let activation_in_flight = matches!(flight, ActivationFlight::InFlight(_));
    let readiness_verdict;
    // Issue #1780 (I11.5): an admitted automation decision that admits no job
    // is an automation failure, and I11.5 requires it to become one persistent
    // canonical notification instead of a log line. The decision and the
    // admission fence are both taken from the composition under this one lock;
    // the canonical write itself happens after the lock is released, so no
    // Kernel exchange ever crosses the composition mutex (issue #18 N3).
    let blocked_automation = {
        let guard = composition.lock().await;
        // #2560: re-read the composition's own owner facts once per heartbeat.
        // This performs no capability IO and re-files no slot, so a slow
        // optional attach never blocks here and an unchanged owner does no work.
        // Generation-scoped retained proofs are re-checked against the observed
        // generation/epoch, so a proof admitted at an earlier generation reads
        // as unavailable instead of staying usable because it was retained.
        // #2647: an identical observation retires no in-flight delta basis;
        // only a real owner-context change does.
        startup_readiness
            .observe_owner(&guard)
            .map_err(|error| format!("startup readiness owner observation: {error}"))?;
        readiness_verdict = eliotd::startup_readiness::evaluate_startup_readiness(
            startup_readiness,
            &guard.status(),
            false,
        );
        // Same tolerance as `DaemonComposition::note_maintenance_trigger`: a
        // rejected evaluation is an explicit typed gap, never a daemon-killing
        // error, and the trigger stays durable for the next eligible pass.
        match guard.evaluate_maintenance_trigger(maintenance_observation(
            MaintenanceTriggerOrigin::AdmittedObservation,
            vec![
                format!("store_health={:?}", health.status),
                health.manifest_digest.as_str().to_owned(),
            ],
            activation_in_flight,
        )) {
            Ok(decision) if decision.admits_job => None,
            Ok(decision) => match guard.notification_state_admission_fence() {
                Ok(fence) => Some((fence, decision)),
                // A not-ready composition is a typed refusal, not a reason to
                // pretend there is no blocked automation: it is recorded with
                // the same minimal diagnostics the evaluation refusal uses.
                Err(error) => {
                    let _ = eliotd::diagnostics::ErrorRecord::of_daemon_error(&error).emit();
                    None
                }
            },
            Err(error) => {
                let _ = eliotd::diagnostics::ErrorRecord::of_daemon_error(&error).emit();
                None
            }
        }
    };
    if let Some((fence, decision)) = blocked_automation {
        note_blocked_automation_notification(kernel, fence, &decision).await;
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
            readiness = %startup_readiness.report(),
        );
    }
    if let Some(producer) = supervision_progress.as_mut() {
        submit_supervision_heartbeat(kernel, producer, &health, activation_in_flight).await?;
    }
    // #2100: revision-advance trigger for the Kernel P-07 owner feed.
    // Unchanged providers perform no IO here; an advanced provider
    // republishes with readback proof. The exchange starts on its own
    // polled flight when idle and is never awaited here: its pending
    // publication may gate dependent grants but never health polling.
    maybe_start_owner_feed_sync(kernel, composition, owner_feed, owner_feed_flight);
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
    let result = composition
        .resolve_agent_activation_v2(&ticket, now)
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
/// #2559). No new claim starts here; already-started claim, resolve-wait,
/// dispatch, local-read, `TestD` owner and owner-feed steps keep being polled
/// together inside one declared finite budget.
///
/// A claimed/waiting ticket carries no result digest yet, so exhausting the
/// budget while waiting or resolving settles as a clean shutdown: nothing
/// was submitted and the Kernel-owned ticket simply expires. A resolved and
/// submitting result keeps its retained identity instead: an unknown
/// acknowledgement or a budget exhausted mid-submit settles as a typed
/// unknown carrying the original ticket/result verbatim, never a fabricated
/// hash. Local-read, `TestD` owner and owner-feed steps always settle as plain
/// shutdown: an un-submitted pair's attempt capability is revoked on
/// disconnect, an already-persisted `TestD` decision exact-replays, and a
/// pending owner-feed publication leaves dependent grants pending. Only a
/// step failure fails closed. Dropping every flight here also releases all
/// owned composition references before the existing final shutdown, without
/// leaking detached work.
async fn drain_flights_on_shutdown(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    flight: &mut ActivationFlight,
    local_read_flight: &mut LocalReadFlight,
    testd_owner_flight: &mut TestdOwnerFlight,
    owner_feed_flight: &mut OwnerFeedFlight,
    owner_feed: &mut Option<eliotd::OwnerFeedTrigger>,
) -> Result<RunLoopExit, String> {
    // #740: drain span. Idle drains and unknown-retention drains emit
    // distinct dispositions with the original identity verbatim.
    let _span = tracing::info_span!("eliotd.activation_drain").entered();
    let deadline = Instant::now() + SHUTDOWN_ACTIVATION_DRAIN;
    let mut no_supervision: Option<eliotd::SupervisionProgressProducer> = None;
    let mut activation_exit = RunLoopExit::Shutdown;
    loop {
        if matches!(flight, ActivationFlight::Idle)
            && matches!(local_read_flight, LocalReadFlight::Idle)
            && matches!(testd_owner_flight, TestdOwnerFlight::Idle)
            && matches!(owner_feed_flight, OwnerFeedFlight::Idle)
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
                        match settle_activation_claim(claim, &mut no_supervision)? {
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
            }            testd_owner_completion = next_testd_owner_completion(testd_owner_flight) => {
                settle_testd_owner_completion(testd_owner_completion, testd_owner_flight)?;
            }
            owner_feed_trigger = next_owner_feed_completion(owner_feed_flight) => {
                settle_owner_feed_completion(owner_feed_trigger, owner_feed, owner_feed_flight);
            }
            () = tokio::time::sleep_until(deadline) => {
                // Budget exhausted with work still outstanding: drop every
                // flight without starting anything new. The activation phase
                // decides the exit: a retained result means an uncertain
                // submission, while a claim or resolve-wait in flight means
                // no digest exists yet and shutdown stays clean.
                let exit = match std::mem::replace(flight, ActivationFlight::Idle) {
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
                };
                *local_read_flight = LocalReadFlight::Idle;
                *testd_owner_flight = TestdOwnerFlight::Idle;
                *owner_feed_flight = OwnerFeedFlight::Idle;
                return Ok(exit);
            }
        }
    }
}

/// The trigger travels with its in-flight sync step and returns on
/// completion, so exactly one trigger exists across passes: no clone of
/// mutable state and no renewal race.
struct OwnerFeedFlightState {
    future: Pin<Box<dyn std::future::Future<Output = eliotd::OwnerFeedTrigger>>>,
}

/// Sole owner of owner-feed sync state in `run_loop`, mirroring
/// [`LocalReadFlight`]. `Idle` means no sync work is outstanding; `InFlight`
/// holds the one pending bounded exchange. No second owner and no second
/// concurrent exchange exist.
enum OwnerFeedFlight {
    Idle,
    InFlight(OwnerFeedFlightState),
}

/// Starts one O1 owner-feed synchronization pass (issue #2100) on its own
/// polled flight. The pass keeps its composition borrow inside the flight
/// future (issue #2559): when the owner borrow must span the Kernel
/// read->publish->readback exchange, that bounded future is retained as a
/// polled flight rather than awaited inside the health tick.
fn maybe_start_owner_feed_sync(
    kernel: &Arc<DaemonKernelClient>,
    composition: &SharedComposition,
    owner_feed: &mut Option<eliotd::OwnerFeedTrigger>,
    flight: &mut OwnerFeedFlight,
) {
    if !matches!(flight, OwnerFeedFlight::Idle) {
        return;
    }
    let Some(trigger) = owner_feed.take() else {
        return;
    };
    let kernel_clone = Arc::clone(kernel);
    let composition_clone = Arc::clone(composition);
    *flight = OwnerFeedFlight::InFlight(OwnerFeedFlightState {
        future: Box::pin(async move {
            run_owner_feed_sync(&kernel_clone, composition_clone, trigger).await
        }),
    });
}

/// Polls the one in-flight owner-feed step, pending forever while idle so
/// health and shutdown stay pollable with no step outstanding.
async fn next_owner_feed_completion(flight: &mut OwnerFeedFlight) -> eliotd::OwnerFeedTrigger {
    match flight {
        OwnerFeedFlight::Idle => std::future::pending::<eliotd::OwnerFeedTrigger>().await,
        OwnerFeedFlight::InFlight(state) => (&mut state.future).await,
    }
}

/// Settles one completed owner-feed sync step back to idle, returning its
/// trigger for the next pass. Every outcome idles until the next trigger:
/// a proven publish was already recorded, and a degraded pass leaves grants
/// pending for a later pass. The feed never gates readiness and never fails
/// the daemon.
fn settle_owner_feed_completion(
    trigger: eliotd::OwnerFeedTrigger,
    owner_feed: &mut Option<eliotd::OwnerFeedTrigger>,
    flight: &mut OwnerFeedFlight,
) {
    *owner_feed = Some(trigger);
    *flight = OwnerFeedFlight::Idle;
}

/// Runs one O1 owner-feed synchronization pass (issue #2100) and records
/// its outcome.
///
/// A proven publish emits the bound revision for diagnostics; an unchanged
/// provider stays silent; a degraded pass emits an error record and the loop
/// continues, retrying on a later tick. The feed never gates readiness and
/// never fails the daemon: an unbound Kernel owner only leaves grants
/// pending, exactly like an absent P-07 port.
async fn run_owner_feed_sync(
    kernel: &Arc<DaemonKernelClient>,
    composition: SharedComposition,
    mut trigger: eliotd::OwnerFeedTrigger,
) -> eliotd::OwnerFeedTrigger {
    let guard = composition.lock().await;
    match eliotd::maintain_owner_feed(&guard, kernel, &mut trigger).await {
        Ok(Some(revision)) => {
            tracing::info!(
                target: "eliotd::diagnostics",
                event = "eliotd.owner_feed_published",
                revision = revision,
            );
        }
        Ok(None) => {}
        Err(error) => {
            let _ = eliotd::diagnostics::ErrorRecord::of(
                eliotd::diagnostics::OwningComponent::DaemonRuntime,
                "owner-feed",
                &error.to_string(),
            )
            .emit();
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

/// Runs one local-read poll step: `local_read_claim` (pair plus fenced
/// attempt capability, or null meaning backoff), then
/// [`forward_admitted_local_read`] for the admitted pair under that attempt,
/// then `local_read_result` with the returned [`HostRequestResultBody`]
/// (accepted, the expected expiry race, or the stale-attempt quarantine).
/// Exact replays stay idempotent by Kernel contract. Any step failure fails
/// the daemon closed — a claimed pair that cannot forward or submit is never
/// silently discarded. A stale capability is never retried: the step settles
/// and the next tick claims the current generation anew.
async fn run_local_read_poll(
    kernel: &DaemonKernelClient,
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
    // Issue #2559: the composition guard is held only around the Skill
    // drive, which borrows the Governor owner. Ordinary forwarded reads use
    // no composition state, so no guard crosses the Kernel forward leg or
    // either submit leg. The Skill borrow spans its IO inside this already
    // polled flight; the loop keeps polling every other flight while it is
    // outstanding instead of queueing behind it in a branch body.
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
        let body = {
            let guard = composition.lock().await;
            eliotd::skill_dispatch::serve_skill_pair(&guard, kernel, &envelope, &tool, &attempt)
                .await
        };
        let outcome = match submit_local_read_result_idempotent(kernel, &body).await? {
            LocalReadSubmitOutcome::Accepted => LocalReadPollOutcome::Accepted,
            LocalReadSubmitOutcome::Expired => LocalReadPollOutcome::Expired,
            LocalReadSubmitOutcome::StaleAttempt => LocalReadPollOutcome::StaleAttempt,
        };
        return Ok(step(outcome, delta));
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

/// Completion of one in-flight TestD owner drain step. Bind, terminal
/// publish, finish submit, and ack share one flight branch so health and
/// shutdown stay pollable while the bounded step is outstanding; the step
/// handles at most one bounded poll per queue per tick.
enum TestdOwnerCompletion {
    Settled(Result<TestdOwnerDrainOutcome, String>),
}

struct TestdOwnerFlightState {
    future: Pin<Box<dyn std::future::Future<Output = TestdOwnerCompletion>>>,
}

/// Sole owner of TestD owner drain state in `run_loop`, mirroring
/// [`LocalReadFlight`]. `Idle` means no drain work is outstanding;
/// `InFlight` holds the one pending drain step. No second owner and no
/// second concurrent drain step exist.
enum TestdOwnerFlight {
    Idle,
    InFlight(TestdOwnerFlightState),
}

/// Pure tick gate: the TestD owner timer starts work only when the flight
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

/// Starts one TestD owner drain step for the finish cadence (issue #325):
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

/// Starts the TestD owner drain step when its flight is idle. Checked on
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

/// Polls the one in-flight TestD owner drain step, pending forever while
/// idle so health and shutdown stay pollable with no step outstanding.
async fn next_testd_owner_completion(flight: &mut TestdOwnerFlight) -> TestdOwnerCompletion {
    match flight {
        TestdOwnerFlight::Idle => std::future::pending::<TestdOwnerCompletion>().await,
        TestdOwnerFlight::InFlight(state) => (&mut state.future).await,
    }
}

/// Settles one completed TestD owner drain step back to idle. A drained
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

/// Runs one TestD owner drain step through the production finish caller.
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
        Err(DaemonError::ActivationExpired) => Err(ActivationDispatchError::Expired),
        Err(submit_error) => {
            // The submit may have committed before the acknowledgement was
            // lost. Retain the exact ticket/result identity and reconcile
            // from Kernel retention before any second Governor read. Do not
            // recompute a different result here.
            let submit_detail = submit_error.to_string();
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
    ack.validate_against_result(result).map_err(|error| {
        ActivationDispatchError::Hard(format!(
            "Kernel activation result ack payload mismatch: {error}"
        ))
    })?;
    match ack.outcome {
        AgentActivationResultAckOutcome::Accepted => {
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
fn observe_transient_deferral(result: &AgentActivationResolutionResult) {
    if result.is_transient_retry() {
        if let Some(not_before) = transient_not_before(result) {
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

/// Plans one closed T11.1 `GetEvidencePack` read for the daemon query path.
///
/// This is the registration half of the `eliot.query` plumbing: the caller
/// holds the already-connected [`DaemonKernelClient`] and the
/// [`DaemonComposition`] (see `context_read_client`), and calls this pure
/// planner with the exact admitted fence plus explicit `scope_id`/`subject`/
/// `max_records` selectors. The returned [`NamedReadRequest`] travels the
/// single `store_named` transport via [`KernelContextReadClient`]; free text
/// never becomes a selector and no second consistency algorithm lives here.
///
/// For T11.1 the consistency is `Eventual` with no dependency revisions, so
/// this is exactly the `ReadService` fast path (no stable re-read, no churn
/// check); when the `eliot-read` dependency is available the caller should
/// delegate to `ReadService::query` with a `Verification` intent instead of
/// calling `execute_named` directly. The store catalogue remains the
/// authority: this planner validates shape only, and the closed
/// `subject`/`max_records` membership plus the `EVIDENCE_PACK_MAX_RECORDS`
/// cap are enforced by the adapters.
#[allow(
    dead_code,
    reason = "T11.1 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn plan_daemon_evidence_read(
    fence: &eliot_contracts::StateFence,
    scope_id: &str,
    subject: &str,
    max_records: &str,
) -> Result<eliot_store_api::NamedReadRequest, String> {
    if subject.trim().is_empty() || subject.chars().any(char::is_control) {
        return Err(
            "daemon evidence read subject must be non-blank with no control characters".to_owned(),
        );
    }
    if max_records.trim().is_empty() || max_records.chars().any(char::is_control) {
        return Err(
            "daemon evidence read max_records must be a non-blank decimal bound".to_owned(),
        );
    }
    let bound: u32 = max_records.trim().parse().map_err(|_| {
        "daemon evidence read max_records must be a positive decimal bound".to_owned()
    })?;
    if bound == 0 {
        return Err("daemon evidence read max_records must be a positive decimal bound".to_owned());
    }
    let scope = eliot_store_api::ScopeId::new(scope_id)
        .map_err(|error| format!("daemon evidence read scope: {error}"))?;
    let mut parameters = std::collections::BTreeMap::new();
    parameters.insert(
        "subject".to_owned(),
        serde_json::Value::String(subject.trim().to_owned()),
    );
    parameters.insert(
        "max_records".to_owned(),
        serde_json::Value::String(max_records.trim().to_owned()),
    );
    let request = eliot_store_api::NamedReadRequest {
        operation: eliot_store_api::NamedReadOperation::GetEvidencePack,
        scope_id: Some(scope),
        consistency: eliot_store_api::ReadConsistency::Eventual,
        state_fence: fence.clone(),
        parameters,
    };
    request
        .validate()
        .map_err(|error| format!("daemon evidence read request: {error}"))?;
    Ok(request)
}

/// Projects a successful evidence-pack response into the daemon query content.
///
/// Returns the exact record/provenance shape the `eliot.query` caller
/// receives: the store payload crosses unchanged under `evidence_pack` with
/// its subject/scope identity. Fails closed when the operation is not
/// `GetEvidencePack`, the fence does not match the admitted fence, or the
/// payload lacks the versioned `records`/`provenance` shape.
#[allow(
    dead_code,
    reason = "T11.1 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn project_daemon_evidence_response(
    response: &eliot_store_api::NamedReadResponse,
    admitted_fence: &eliot_contracts::StateFence,
    expected_subject: &str,
) -> Result<serde_json::Value, String> {
    if response.operation != eliot_store_api::NamedReadOperation::GetEvidencePack {
        return Err("daemon evidence response operation must be GetEvidencePack".to_owned());
    }
    if response.state_fence != *admitted_fence {
        return Err("daemon evidence response fence does not match the admitted fence".to_owned());
    }
    response
        .validate()
        .map_err(|error| format!("daemon evidence response: {error}"))?;
    let subject = response
        .payload
        .get("subject")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "daemon evidence payload misses its subject".to_owned())?;
    if subject != expected_subject {
        return Err(
            "daemon evidence payload subject does not match the requested subject".to_owned(),
        );
    }
    if response
        .payload
        .get("records")
        .and_then(serde_json::Value::as_array)
        .is_none()
    {
        return Err("daemon evidence payload misses its records array".to_owned());
    }
    if response
        .payload
        .get("provenance")
        .and_then(serde_json::Value::as_object)
        .is_none()
    {
        return Err("daemon evidence payload misses its provenance".to_owned());
    }
    Ok(serde_json::json!({
        "operation": "GetEvidencePack",
        "subject": subject,
        "evidence_pack": response.payload,
    }))
}

/// Plans one closed T11.2 `GetCurrentEpistemicPosition` read for the daemon
/// query path.
///
/// This is the registration half of the `eliot.query` CEP plumbing: the caller
/// holds the already-connected [`DaemonKernelClient`] and the
/// [`DaemonComposition`] (see `context_read_client`), and calls this pure
/// planner with the exact admitted fence plus explicit `scope_id`/`position`
/// selectors. The returned [`NamedReadRequest`] travels the single
/// `store_named` transport via [`KernelContextReadClient`] with
/// `ExactFence`; free text never becomes a selector and no second position
/// resolver lives here. The store catalogue remains the authority: this
/// planner validates shape only, and the closed `position` membership is
/// enforced by the adapters.
#[allow(
    dead_code,
    reason = "T11.2 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn plan_daemon_position_read(
    fence: &eliot_contracts::StateFence,
    scope_id: &str,
    position: &str,
) -> Result<eliot_store_api::NamedReadRequest, String> {
    if position.trim().is_empty() || position.chars().any(char::is_control) {
        return Err(
            "daemon position read position must be non-blank with no control characters".to_owned(),
        );
    }
    let scope = eliot_store_api::ScopeId::new(scope_id)
        .map_err(|error| format!("daemon position read scope: {error}"))?;
    let mut parameters = std::collections::BTreeMap::new();
    parameters.insert(
        "position".to_owned(),
        serde_json::Value::String(position.trim().to_owned()),
    );
    let request = eliot_store_api::NamedReadRequest {
        operation: eliot_store_api::NamedReadOperation::GetCurrentEpistemicPosition,
        scope_id: Some(scope),
        consistency: eliot_store_api::ReadConsistency::ExactFence,
        state_fence: fence.clone(),
        parameters,
    };
    request
        .validate()
        .map_err(|error| format!("daemon position read request: {error}"))?;
    Ok(request)
}

/// Projects a successful current-epistemic-position response into the daemon
/// query content.
///
/// Returns the exact admitted wire CEP shape the `eliot.query` caller
/// receives: the store payload crosses unchanged under
/// `current_epistemic_position` with its position identity. Fails closed when
/// the operation is not `GetCurrentEpistemicPosition`, the fence does not
/// match the admitted fence, or the payload lacks the versioned admitted
/// position shape.
#[allow(
    dead_code,
    reason = "T11.2 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn project_daemon_position_response(
    response: &eliot_store_api::NamedReadResponse,
    admitted_fence: &eliot_contracts::StateFence,
    expected_position: &str,
) -> Result<serde_json::Value, String> {
    if response.operation != eliot_store_api::NamedReadOperation::GetCurrentEpistemicPosition {
        return Err(
            "daemon position response operation must be GetCurrentEpistemicPosition".to_owned(),
        );
    }
    if response.state_fence != *admitted_fence {
        return Err("daemon position response fence does not match the admitted fence".to_owned());
    }
    response
        .validate()
        .map_err(|error| format!("daemon position response: {error}"))?;
    Ok(serde_json::json!({
        "operation": "GetCurrentEpistemicPosition",
        "position": expected_position,
        "current_epistemic_position": response.payload,
    }))
}

/// Closed T11.3 role denominator for one task-bound `ContextReconstruction`.
///
/// The seven provider-role keys follow the T11 acquisition table: task frame,
/// critical attention, current epistemic position, cue activation,
/// negative memory, evidence/source assurance, and affordances. The
/// understanding-projection read carries one exact closed `selector`; the
/// cue-activation and negative-memory roles share a single physical read only
/// when they deliberately address the same source snapshot, and otherwise each
/// plans its own read, so this denominator stays seven roles over six or seven
/// physical reads. The current-epistemic-position role payload doubles as the
/// activation evidence bound to the admitted fence. An eighth role key, a
/// missing role, or a duplicate role is a denominator mismatch and fails
/// closed — never silent absorption.
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) const CONTEXT_RECONSTRUCTION_ROLES: [&str; 7] = [
    "task_frame",
    "critical_attention",
    "current_epistemic_position",
    "cue_activation",
    "negative_memory",
    "evidence",
    "affordances",
];

/// Typed per-role readout assembled by the reconstruction dispatch.
///
/// `Present` carries the exact owner payload crossed unchanged;
/// `KnownEmpty` carries an authoritative completed empty lookup (never a
/// transport failure or a partial scan); `Stale` reports a fence/generation
/// mismatch for that role (a previous generation is never served as
/// current); `Unsupported` reports a missing provider or an unadmitted
/// catalogue operation, distinctly from `KnownEmpty`.
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RoleReadout {
    Present(serde_json::Value),
    KnownEmpty(serde_json::Value),
    Stale { detail: String },
    Unsupported { detail: String },
}

impl RoleReadout {
    const fn disposition(&self) -> &'static str {
        match self {
            Self::Present(_) => "present",
            Self::KnownEmpty(_) => "known_empty",
            Self::Stale { .. } => "stale",
            Self::Unsupported { .. } => "unsupported",
        }
    }
}

/// The catalogue-declared explicit bound key every owner handler parses.
///
/// `eliot_store_api::operation_parameters` declares `max_records` as
/// `Subject`-shaped text, so the bound travels as its **decimal string**; this
/// is the only place the daemon renders one.
const DAEMON_MAX_RECORDS_KEY: &str = "max_records";

/// Fills the store catalogue's declared selector map for one T11.3
/// reconstruction role read from the caller-resolved exact values.
///
/// The key set, the required/optional shape and the declared text shape all
/// come from [`eliot_store_api::declared_read_parameters`] — the single
/// catalogue that the Governor producer builds its own `NamedParameters` from
/// and that the Kernel capability gate validates with
/// [`eliot_store_api::validate_typed_read_parameters`]. This seam therefore
/// keeps no second parameter list and cannot drift from the owner: it fills
/// exactly the declared keys, refuses a resolved value the operation does not
/// declare, and refuses a missing required declaration.
///
/// The declared bound key takes the caller's explicit bound as its decimal
/// string (the exact form every owner handler parses). Every other declared
/// key takes the caller's exact resolved text; a blank, control-bearing or
/// numeric value is refused here, and an OPTIONAL declared key with no
/// resolved value is OMITTED entirely rather than sent as null — the declared
/// "no specific problem is requested" contract option, which the
/// `GetAttentionAndProblems` handler answers with its own exact null.
///
/// A bound outside `1..=EVIDENCE_PACK_MAX_RECORDS` fails closed: that numeric
/// range is the one restriction the declaration does not carry, and the store
/// owner enforces it on every handler.
fn daemon_reconstruction_parameters(
    operation: eliot_store_api::NamedReadOperation,
    role: &'static str,
    resolved: &[(&str, &str)],
    max_records: u32,
) -> Result<std::collections::BTreeMap<String, serde_json::Value>, String> {
    if max_records == 0 || max_records > eliot_store_api::EVIDENCE_PACK_MAX_RECORDS {
        return Err(format!(
            "daemon reconstruction {role} read max_records must be within 1..=EVIDENCE_PACK_MAX_RECORDS"
        ));
    }
    let mut parameters = std::collections::BTreeMap::new();
    for declaration in eliot_store_api::declared_read_parameters(operation) {
        let value = if declaration.name == DAEMON_MAX_RECORDS_KEY {
            Some(max_records.to_string())
        } else {
            resolved
                .iter()
                .find(|(name, _)| *name == declaration.name)
                .map(|(_, value)| (*value).to_owned())
        };
        match value {
            Some(text) if text.trim().is_empty() || text.chars().any(char::is_control) => {
                return Err(format!(
                    "daemon reconstruction {role} read {} must be non-blank text with no control characters",
                    declaration.name
                ));
            }
            Some(text) => {
                parameters.insert(declaration.name.to_owned(), serde_json::Value::String(text));
            }
            None if declaration.required => {
                return Err(format!(
                    "daemon reconstruction {role} read requires its declared {} selector",
                    declaration.name
                ));
            }
            None => {}
        }
    }
    for (name, _) in resolved {
        if !parameters.contains_key(*name) {
            return Err(format!(
                "daemon reconstruction {role} read selector {name} is not declared for this operation"
            ));
        }
    }
    eliot_store_api::validate_typed_read_parameters(operation, &parameters)
        .map_err(|error| format!("daemon reconstruction {role} read selectors: {error}"))?;
    Ok(parameters)
}

/// Plans one closed T11.3 reconstruction role read with the catalogue's exact
/// selectors.
///
/// Shared shape check for the four task-bound reads (`GetTaskState`,
/// `GetAttentionAndProblems`, `GetUnderstandingProjectionInputs`,
/// `GetCapabilityEvidenceState`): scope-bound, `ExactFence` against the exact
/// admitted fence, and carrying the closed selector map the store catalogue
/// declares for `operation` — no fabricated `all` selector, no empty default,
/// and no second parameter list. A fence change surfaces as a mismatch, never
/// as a previous generation served as current.
fn plan_daemon_reconstruction_role_read(
    fence: &eliot_contracts::StateFence,
    scope_id: &str,
    operation: eliot_store_api::NamedReadOperation,
    role: &'static str,
    resolved: &[(&str, &str)],
    max_records: u32,
) -> Result<eliot_store_api::NamedReadRequest, String> {
    if scope_id.trim().is_empty() || scope_id.chars().any(char::is_control) {
        return Err(format!(
            "daemon reconstruction {role} read scope must be non-blank with no control characters"
        ));
    }
    let scope = eliot_store_api::ScopeId::new(scope_id)
        .map_err(|error| format!("daemon reconstruction {role} read scope: {error}"))?;
    let parameters = daemon_reconstruction_parameters(operation, role, resolved, max_records)?;
    let request = eliot_store_api::NamedReadRequest {
        operation,
        scope_id: Some(scope),
        consistency: eliot_store_api::ReadConsistency::ExactFence,
        state_fence: fence.clone(),
        parameters,
    };
    request
        .validate()
        .map_err(|error| format!("daemon reconstruction {role} read request: {error}"))?;
    Ok(request)
}

/// Projects one successful T11.3 role response into daemon content.
///
/// Binds the answer to the exact read it was asked for before it becomes daemon
/// content: the planned operation, the admitted fence, the requested scope,
/// the requested selector the owner handler echoes (`selector_key` must equal
/// `expected_selector`, or be the handler's exact null when no specific
/// identity was requested), the source-envelope version, a `records` array,
/// and the authoritative `matched_total`/`returned`/`truncated` provenance.
/// A response answering a different task, problem, source selector or skill is
/// refused even when its operation and fence match, and a payload whose
/// provenance does not describe its own records is never projected as
/// present.
///
/// The exact counts cross unchanged beside the payload so the owning Governor
/// reconstruction composition can derive the role disposition from them; this
/// seam does not decide admission, capability qualification or packet
/// readiness from a successful retrieval.
fn project_daemon_role_response(
    response: &eliot_store_api::NamedReadResponse,
    admitted_fence: &eliot_contracts::StateFence,
    scope_id: &str,
    operation: eliot_store_api::NamedReadOperation,
    operation_name: &'static str,
    role: &'static str,
    selector_key: &'static str,
    expected_selector: Option<&str>,
) -> Result<serde_json::Value, String> {
    if scope_id.trim().is_empty() || scope_id.chars().any(char::is_control) {
        return Err(
            "daemon reconstruction role scope must be non-blank with no control characters"
                .to_owned(),
        );
    }
    if response.operation != operation {
        return Err(format!(
            "daemon reconstruction {role} response operation must be {operation_name}"
        ));
    }
    if response.state_fence != *admitted_fence {
        return Err(format!(
            "daemon reconstruction {role} response fence does not match the admitted fence"
        ));
    }
    response
        .validate()
        .map_err(|error| format!("daemon reconstruction {role} response: {error}"))?;
    let payload = &response.payload;
    if payload.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(format!(
            "daemon reconstruction {role} response payload version is unsupported"
        ));
    }
    if payload.get("scope_id").and_then(serde_json::Value::as_str) != Some(scope_id) {
        return Err(format!(
            "daemon reconstruction {role} response scope does not match the requested scope"
        ));
    }
    match (payload.get(selector_key), expected_selector) {
        (Some(serde_json::Value::String(echoed)), Some(expected)) if echoed == expected => {}
        (Some(serde_json::Value::Null), None) => {}
        _ => {
            return Err(format!(
                "daemon reconstruction {role} response {selector_key} does not match the requested selector"
            ));
        }
    }
    let Some(records) = payload.get("records").and_then(serde_json::Value::as_array) else {
        return Err(format!(
            "daemon reconstruction {role} response payload misses its records array"
        ));
    };
    let provenance = payload
        .get("provenance")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            format!("daemon reconstruction {role} response payload misses its provenance")
        })?;
    let matched_total = provenance
        .get("matched_total")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            format!("daemon reconstruction {role} response provenance misses matched_total")
        })?;
    let returned = provenance
        .get("returned")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            format!("daemon reconstruction {role} response provenance misses returned")
        })?;
    let truncated = provenance
        .get("truncated")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            format!("daemon reconstruction {role} response provenance misses truncated")
        })?;
    if truncated != (matched_total > returned) {
        return Err(format!(
            "daemon reconstruction {role} response provenance truncation flag contradicts its counts"
        ));
    }
    if returned != records.len() as u64 {
        return Err(format!(
            "daemon reconstruction {role} response provenance returned count contradicts its records"
        ));
    }
    // Dynamic role key: `serde_json::json!` would freeze an identifier key as
    // a literal, so the object is built imperatively to carry the payload
    // under its exact role key alongside the operation/role identity and the
    // observed counts.
    let mut object = serde_json::Map::with_capacity(6);
    object.insert(
        "operation".to_owned(),
        serde_json::Value::String(operation_name.to_owned()),
    );
    object.insert(
        "role".to_owned(),
        serde_json::Value::String(role.to_owned()),
    );
    object.insert(role.to_owned(), response.payload.clone());
    object.insert("matched_total".to_owned(), matched_total.into());
    object.insert("returned".to_owned(), returned.into());
    object.insert("truncated".to_owned(), truncated.into());
    Ok(serde_json::Value::Object(object))
}

/// Plans one closed T11.3 `GetTaskState` read for the daemon reconstruction
/// path, carrying the catalogue's exact `task_id` + `max_records` selectors.
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn plan_daemon_task_state_read(
    fence: &eliot_contracts::StateFence,
    scope_id: &str,
    task_id: &str,
    max_records: u32,
) -> Result<eliot_store_api::NamedReadRequest, String> {
    plan_daemon_reconstruction_role_read(
        fence,
        scope_id,
        eliot_store_api::NamedReadOperation::GetTaskState,
        "task frame",
        &[("task_id", task_id)],
        max_records,
    )
}

/// Plans one closed T11.3 `GetAttentionAndProblems` read for the daemon
/// reconstruction path, carrying the catalogue's `max_records` bound plus the
/// exact `problem_id` when one is requested. `None` is the declared "no
/// specific problem is requested" contract option: the `problem_id` key is
/// then omitted rather than sent as a substituted identity, and the handler
/// answers with its own exact null.
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn plan_daemon_attention_read(
    fence: &eliot_contracts::StateFence,
    scope_id: &str,
    problem_id: Option<&str>,
    max_records: u32,
) -> Result<eliot_store_api::NamedReadRequest, String> {
    let resolved: &[(&str, &str)] = match problem_id {
        Some(problem_id) => &[("problem_id", problem_id)],
        None => &[],
    };
    plan_daemon_reconstruction_role_read(
        fence,
        scope_id,
        eliot_store_api::NamedReadOperation::GetAttentionAndProblems,
        "critical attention",
        resolved,
        max_records,
    )
}

/// Plans one closed T11.3 `GetUnderstandingProjectionInputs` read for the
/// daemon reconstruction path, carrying the catalogue's exact `selector` +
/// `max_records` for one resolved source set. The cue-activation and
/// negative-memory roles plan their OWN selector, so one unrelated source
/// snapshot is never relabelled into both roles.
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn plan_daemon_understanding_inputs_read(
    fence: &eliot_contracts::StateFence,
    scope_id: &str,
    selector: &str,
    max_records: u32,
) -> Result<eliot_store_api::NamedReadRequest, String> {
    plan_daemon_reconstruction_role_read(
        fence,
        scope_id,
        eliot_store_api::NamedReadOperation::GetUnderstandingProjectionInputs,
        "understanding inputs",
        &[("selector", selector)],
        max_records,
    )
}

/// Plans one closed T11.3 `GetCapabilityEvidenceState` read for the daemon
/// reconstruction path (affordances role), carrying the catalogue's exact
/// `skill_id` + `max_records` selectors instead of an empty map.
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn plan_daemon_capability_evidence_read(
    fence: &eliot_contracts::StateFence,
    scope_id: &str,
    skill_id: &str,
    max_records: u32,
) -> Result<eliot_store_api::NamedReadRequest, String> {
    plan_daemon_reconstruction_role_read(
        fence,
        scope_id,
        eliot_store_api::NamedReadOperation::GetCapabilityEvidenceState,
        "affordances",
        &[("skill_id", skill_id)],
        max_records,
    )
}

/// Projects a successful task-state response into the daemon query content,
/// bound to the exact `task_id` this read was asked for.
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn project_daemon_task_state_response(
    response: &eliot_store_api::NamedReadResponse,
    admitted_fence: &eliot_contracts::StateFence,
    scope_id: &str,
    expected_task_id: &str,
) -> Result<serde_json::Value, String> {
    project_daemon_role_response(
        response,
        admitted_fence,
        scope_id,
        eliot_store_api::NamedReadOperation::GetTaskState,
        "GetTaskState",
        "task_frame",
        "task_id",
        Some(expected_task_id),
    )
}

/// Projects a successful attention-and-problems response into the daemon
/// query content, bound to the requested scope and to the exact `problem_id`
/// (or to the handler's exact null when no specific problem was requested).
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn project_daemon_attention_response(
    response: &eliot_store_api::NamedReadResponse,
    admitted_fence: &eliot_contracts::StateFence,
    scope_id: &str,
    expected_problem_id: Option<&str>,
) -> Result<serde_json::Value, String> {
    project_daemon_role_response(
        response,
        admitted_fence,
        scope_id,
        eliot_store_api::NamedReadOperation::GetAttentionAndProblems,
        "GetAttentionAndProblems",
        "critical_attention",
        "problem_id",
        expected_problem_id,
    )
}

/// Projects a successful understanding-projection-inputs response into the
/// daemon query content, bound to the exact `selector` that read requested.
/// The cue-activation and negative-memory roles project from their OWN
/// selector, so an answer to a different source set is never relabelled into
/// both roles.
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn project_daemon_understanding_inputs_response(
    response: &eliot_store_api::NamedReadResponse,
    admitted_fence: &eliot_contracts::StateFence,
    scope_id: &str,
    expected_selector: &str,
) -> Result<serde_json::Value, String> {
    project_daemon_role_response(
        response,
        admitted_fence,
        scope_id,
        eliot_store_api::NamedReadOperation::GetUnderstandingProjectionInputs,
        "GetUnderstandingProjectionInputs",
        "understanding_inputs",
        "selector",
        Some(expected_selector),
    )
}

/// Projects a successful capability-evidence response into the daemon query
/// content (affordances role), bound to the exact `skill_id` this read was
/// asked for.
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn project_daemon_capability_evidence_response(
    response: &eliot_store_api::NamedReadResponse,
    admitted_fence: &eliot_contracts::StateFence,
    scope_id: &str,
    expected_skill_id: &str,
) -> Result<serde_json::Value, String> {
    project_daemon_role_response(
        response,
        admitted_fence,
        scope_id,
        eliot_store_api::NamedReadOperation::GetCapabilityEvidenceState,
        "GetCapabilityEvidenceState",
        "affordances",
        "skill_id",
        Some(expected_skill_id),
    )
}

/// Exact owner-resolved selectors for one daemon-side T11.3 reconstruction
/// closure.
///
/// One closed carrier instead of a positional argument list: every member is an
/// exact value the store catalogue declares for one reconstruction read, and
/// the closure cannot be planned without all of them. There is no fabricated
/// `all` selector and no empty default anywhere in this shape — the daemon must
/// say which task, problem, source sets and skill it means before any read is
/// planned, exactly as the Governor producer's own request does.
///
/// `problem_id` is the only optional member: `None` is the declared "no
/// specific problem is requested" contract option, and the `problem_id` key is
/// then omitted rather than sent as a substituted identity. `max_records` is
/// the shared explicit bound for the four task-bound reads and travels as its
/// decimal string; the T11.1 evidence bound and the T11.2 position selector
/// stay separate closure members, so no role silently reuses another's bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch carries it once the daemon dispatches the query route"
)]
pub(super) struct DaemonReconstructionSelectors<'a> {
    /// Exact `task_id` for the task-frame read.
    pub(super) task_id: &'a str,
    /// Exact `problem_id` for the attention read, or `None` when no specific
    /// problem is requested.
    pub(super) problem_id: Option<&'a str>,
    /// Exact `selector` for the cue-activation projection read.
    pub(super) cue_selector: &'a str,
    /// Exact `selector` for the negative-memory projection read.
    pub(super) negative_memory_selector: &'a str,
    /// Exact `skill_id` for the affordances read.
    pub(super) skill_id: &'a str,
    /// Explicit shared bound for the four task-bound reads.
    pub(super) max_records: u32,
}

/// Plans the closed `ContextReconstruction` closure for the daemon.
///
/// Canonical role order: the four T11.3 role reads (each carrying the closed
/// selectors the store catalogue declares for it, so the plans this produces
/// are exactly the requests the Kernel capability gate admits and the store
/// handlers serve), then the T11.1 evidence-pack read (explicit
/// `subject`/`max_records` selectors) and the T11.2 position read (explicit
/// `position` selector, doubling as the activation evidence). This mirrors the
/// Governor read facade's `ContextReconstruction` intent gate without
/// depending on it: `bins/eliotd` owns no `eliot-read` dependency, so the
/// operations are listed explicitly here and must stay in parity with that
/// gate. Free text never becomes a selector and no second consistency
/// algorithm lives here.
///
/// The closure is six physical reads when the cue-activation and
/// negative-memory slots deliberately address the SAME exact source snapshot
/// (identical `selector`), and seven when they address different source sets:
/// a differing selector gets its own read, so one unrelated result is never
/// relabelled into both roles. The store catalogue remains the authority: use
/// [`context_reconstruction_role_admission`] to check manifest admission
/// before dispatch.
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn plan_daemon_context_reconstruction(
    fence: &eliot_contracts::StateFence,
    scope_id: &str,
    selectors: DaemonReconstructionSelectors<'_>,
    subject: &str,
    max_records: &str,
    position: &str,
) -> Result<Vec<eliot_store_api::NamedReadRequest>, String> {
    let mut planned = vec![
        plan_daemon_task_state_read(fence, scope_id, selectors.task_id, selectors.max_records)?,
        plan_daemon_attention_read(fence, scope_id, selectors.problem_id, selectors.max_records)?,
        plan_daemon_understanding_inputs_read(
            fence,
            scope_id,
            selectors.cue_selector,
            selectors.max_records,
        )?,
    ];
    if selectors.negative_memory_selector != selectors.cue_selector {
        planned.push(plan_daemon_understanding_inputs_read(
            fence,
            scope_id,
            selectors.negative_memory_selector,
            selectors.max_records,
        )?);
    }
    planned.push(plan_daemon_capability_evidence_read(
        fence,
        scope_id,
        selectors.skill_id,
        selectors.max_records,
    )?);
    planned.push(plan_daemon_evidence_read(
        fence,
        scope_id,
        subject,
        max_records,
    )?);
    planned.push(plan_daemon_position_read(fence, scope_id, position)?);
    Ok(planned)
}

/// Reports per-operation catalogue admission for the reconstruction closure.
///
/// This checks every planned reconstruction request against the real
/// generated operation manifests: the catalogue — not this planner — decides
/// which reads may execute. Until the Store owner activates a read, its entry
/// reports `false` and production dispatch must not call it; an unadmitted
/// role is reported `Unsupported` by the assembly, distinctly from an
/// authoritative `KnownEmpty`.
///
/// The four T11.3 role plans are now selector-complete, so their admission
/// result reflects the real catalogue decision for the exact requested
/// selectors instead of a parameter-free request the catalogue can only
/// refuse.
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn context_reconstruction_role_admission(
    fence: &eliot_contracts::StateFence,
    scope_id: &str,
    selectors: DaemonReconstructionSelectors<'_>,
    subject: &str,
    max_records: &str,
    position: &str,
) -> Result<Vec<(&'static str, bool)>, String> {
    let planned = plan_daemon_context_reconstruction(
        fence,
        scope_id,
        selectors,
        subject,
        max_records,
        position,
    )?;
    let entries = eliot_store_api::generated_operation_manifests()
        .map_err(|error| format!("daemon reconstruction admission manifests: {error}"))?;
    let mut admission = Vec::with_capacity(planned.len());
    for request in &planned {
        let name: &'static str = match request.operation {
            eliot_store_api::NamedReadOperation::GetTaskState => "GetTaskState",
            eliot_store_api::NamedReadOperation::GetAttentionAndProblems => {
                "GetAttentionAndProblems"
            }
            eliot_store_api::NamedReadOperation::GetUnderstandingProjectionInputs => {
                "GetUnderstandingProjectionInputs"
            }
            eliot_store_api::NamedReadOperation::GetCapabilityEvidenceState => {
                "GetCapabilityEvidenceState"
            }
            eliot_store_api::NamedReadOperation::GetEvidencePack => "GetEvidencePack",
            eliot_store_api::NamedReadOperation::GetCurrentEpistemicPosition => {
                "GetCurrentEpistemicPosition"
            }
            _ => {
                return Err(
                    "daemon reconstruction closure planned an out-of-closure operation".to_owned(),
                );
            }
        };
        let admitted = request.validate_against_catalogue(&entries).is_ok();
        admission.push((name, admitted));
    }
    Ok(admission)
}

/// Assembles the seven role dispositions plus fence identity into the daemon
/// reconstruction content.
///
/// `roles` must carry exactly the [`CONTEXT_RECONSTRUCTION_ROLES`]
/// denominator once each, in any order: a missing, duplicate, or eighth role
/// fails closed. Each readout keeps its disposition (`present`,
/// `known_empty`, `stale`, `unsupported`) with its exact payload or typed
/// detail; stale and unsupported roles are reported, never replaced with a
/// previous generation or an invented empty. The
/// `current_epistemic_position` role payload is the activation evidence bound
/// to the admitted fence.
#[allow(
    dead_code,
    reason = "T11.3 registration API; production bridge dispatch calls it once the manifest admits the query route"
)]
pub(super) fn project_daemon_context_reconstruction(
    admitted_fence: &eliot_contracts::StateFence,
    scope_id: &str,
    roles: &[(&str, RoleReadout)],
) -> Result<serde_json::Value, String> {
    if scope_id.trim().is_empty() || scope_id.chars().any(char::is_control) {
        return Err(
            "daemon reconstruction scope must be non-blank with no control characters".to_owned(),
        );
    }
    if roles.len() != CONTEXT_RECONSTRUCTION_ROLES.len() {
        return Err(format!(
            "daemon reconstruction requires exactly {} roles, observed {}",
            CONTEXT_RECONSTRUCTION_ROLES.len(),
            roles.len()
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (role, _) in roles {
        if !CONTEXT_RECONSTRUCTION_ROLES.contains(role) {
            return Err(format!(
                "daemon reconstruction role {role:?} is outside the closed denominator"
            ));
        }
        if !seen.insert(*role) {
            return Err(format!(
                "daemon reconstruction role {role:?} is reported twice"
            ));
        }
    }
    let projected: Vec<serde_json::Value> = roles
        .iter()
        .map(|(role, readout)| match readout {
            RoleReadout::Present(payload) | RoleReadout::KnownEmpty(payload) => serde_json::json!({
                "role": role,
                "disposition": readout.disposition(),
                "payload": payload,
            }),
            RoleReadout::Stale { detail } | RoleReadout::Unsupported { detail } => {
                serde_json::json!({
                    "role": role,
                    "disposition": readout.disposition(),
                    "detail": detail,
                })
            }
        })
        .collect();
    Ok(serde_json::json!({
        "operation": "ContextReconstruction",
        "scope_id": scope_id,
        "state_fence": admitted_fence,
        "roles": projected,
    }))
}

fn ready_message(status: &DaemonStatus) -> ReadyMessage {
    ReadyMessage::Ready {
        service: SERVICE_NAME,
        protocol: PROTOCOL_VERSION,
        generation: status.generation,
        authority_epoch: status.authority_epoch,
        health: status.health.clone(),
        degraded: status.degraded,
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

    #[test]
    #[allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::too_many_lines,
        reason = "T11.1 registration test: every asserted subject, bound, scope, fence, and projection value is derived from the test inputs; nothing is canned"
    )]
    fn daemon_evidence_read_plans_closed_request_and_projects_exact_response() {
        use std::num::NonZeroU64;

        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};

        const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
        let epoch = EpochId::new(
            EpochLineageId::new(LINEAGE).expect("valid lineage"),
            NonZeroU64::new(1).expect("nonzero sequence"),
        )
        .expect("valid epoch");
        let fence = StateFence::new(epoch, ResourceGeneration::genesis());

        // Closed planning: exact subject + explicit bound + scope + fence.
        let request = plan_daemon_evidence_read(&fence, "scope-evidence", "evidence-alpha", "10")
            .expect("closed evidence read plans");
        assert_eq!(
            request.operation,
            eliot_store_api::NamedReadOperation::GetEvidencePack
        );
        assert_eq!(request.state_fence, fence);
        // The planned request passes the real catalogue gate: only
        // `subject`/`max_records` cross, so generation never reports an
        // unknown parameter.
        let entries =
            eliot_store_api::generated_operation_manifests().expect("catalogue generates");
        request
            .validate_against_catalogue(&entries)
            .expect("planned request is catalogue-closed");

        // Free text, blank scope, and bad bounds fail closed before transport.
        assert!(plan_daemon_evidence_read(&fence, "scope-evidence", "  ", "10").is_err());
        assert!(plan_daemon_evidence_read(&fence, "  ", "evidence-alpha", "10").is_err());
        for bound in ["0", "ten", "  "] {
            assert!(
                plan_daemon_evidence_read(&fence, "scope-evidence", "evidence-alpha", bound)
                    .is_err(),
                "bound {bound:?} must fail closed"
            );
        }

        // Projection: exact record/provenance crosses unchanged; wrong
        // subject, wrong fence, or malformed payload fails closed.
        let response = eliot_store_api::NamedReadResponse {
            operation: eliot_store_api::NamedReadOperation::GetEvidencePack,
            state_fence: fence.clone(),
            revision_heads: Vec::new(),
            payload: serde_json::json!({
                "version": 1,
                "subject": "evidence-alpha",
                "records": [{"capture_index": 0}],
                "provenance": {"matched_total": 1},
            }),
        };
        let projected = project_daemon_evidence_response(&response, &fence, "evidence-alpha")
            .expect("exact response projects");
        assert_eq!(projected["subject"], "evidence-alpha");
        assert_eq!(projected["evidence_pack"], response.payload);
        assert!(
            project_daemon_evidence_response(&response, &fence, "evidence-beta").is_err(),
            "wrong subject must fail closed"
        );
        let changed = StateFence::new(
            EpochId::new(
                EpochLineageId::new(LINEAGE).expect("valid lineage"),
                NonZeroU64::new(2).expect("nonzero sequence"),
            )
            .expect("valid epoch"),
            ResourceGeneration::genesis(),
        );
        assert!(
            project_daemon_evidence_response(&response, &changed, "evidence-alpha").is_err(),
            "changed fence must fail closed"
        );
    }
}
