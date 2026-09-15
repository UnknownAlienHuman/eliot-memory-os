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
    AgentActivationResolutionDisposition, AgentActivationResolutionResult,
    AgentActivationResolutionTicket, AgentActivationResultAck, AgentActivationResultAckOutcome,
    AgentActivationResultReconcile,
};
use eliotd::{
    DaemonComposition, DaemonConfig, DaemonKernelClient, DaemonStatus, PROTOCOL_VERSION,
    SERVICE_NAME,
};
use serde::Serialize;
use tokio::time::{Instant, Interval, MissedTickBehavior};

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

/// Completion of one in-flight activation step. Claim and dispatch share one
/// flight branch so health and shutdown stay pollable while either is
/// outstanding.
enum ActivationCompletion {
    Claim(Result<Option<AgentActivationResolutionTicket>, String>),
    Dispatch(Result<(), ActivationDispatchError>),
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
    // AUD-C02-B: the single place holding both the concrete client and the
    // composition. Push the already-validated Kernel-issued owner session
    // facts (if a handshake validated them) into the composition via the one
    // setter. No new thread, no new handshake, no storing the client; without
    // facts the composition keeps the empty (unadmitted) board behaviour.
    if let Some(facts) = kernel.owner_session_facts() {
        composition.note_owner_session_binding(facts);
    }
    kernel.report_ready().map_err(|error| error.to_string())?;
    let status = composition.status();
    write_json(&ready_message(&status))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let loop_result = runtime.block_on(run_loop(Arc::clone(&kernel), &composition));
    let shutdown_result = composition.shutdown().map_err(|error| error.to_string());
    match (loop_result, shutdown_result) {
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
    }
}

fn report_terminal_failure(kernel: &DaemonKernelClient, reason: String) -> String {
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
    composition: &DaemonComposition,
) -> Result<RunLoopExit, String> {
    let mut cadence = LoopCadence::production();
    // Sole owner of activation state. No second owner and no second
    // concurrent activation exist: the timer starts work only when idle and
    // the in-flight step is polled only in its own branch below.
    let mut flight = ActivationFlight::Idle;
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|error| format!("daemon shutdown signal: {error}"))?;
                return drain_activation_on_shutdown(&mut flight).await;
            }
            _ = cadence.activation_poll.tick() => {
                if decide_activation_tick(&flight) != ActivationTickDecision::StartClaim {
                    continue;
                }
                let kernel_clone = Arc::clone(&kernel);
                let future: Pin<Box<dyn std::future::Future<Output = ActivationCompletion>>> =
                    Box::pin(async move {
                        let outcome: Result<
                            Option<AgentActivationResolutionTicket>,
                            String,
                        > = kernel_clone
                            .claim_agent_activation_ticket()
                            .await
                            .map_err(|error| {
                                format!("Kernel activation ticket claim: {error}")
                            });
                        ActivationCompletion::Claim(outcome)
                    });
                flight = ActivationFlight::InFlight(ActivationFlightState {
                    future,
                    retained: None,
                });
            }
            completion = async {
                match &mut flight {
                    ActivationFlight::Idle => {
                        std::future::pending::<ActivationCompletion>().await
                    }
                    ActivationFlight::InFlight(state) => (&mut state.future).await,
                }
            } => {
                match completion {
                    ActivationCompletion::Claim(claim_outcome) => {
                        let ticket = match claim_outcome {
                            Err(error) => return Err(error),
                            Ok(None) => {
                                flight = ActivationFlight::Idle;
                                continue;
                            }
                            Ok(Some(ticket)) => ticket,
                        };
                        let now = unix_ms(SystemTime::now())?;
                        if activation_deadline_expired(now, ticket.kernel_deadline_unix_ms) {
                            // Kernel owns the typed expiry outcome.  Do not call
                            // the resolver at or after its exact deadline, and do
                            // not submit or reconcile an expired ticket.
                            flight = ActivationFlight::Idle;
                            continue;
                        }
                        // Single v2 resolution per newly admitted ticket.  The v2
                        // resolver maps all seven Governor outcomes to typed
                        // results; any Err is a real validation/readiness failure
                        // and must fail closed rather than silently discarding a
                        // disposition.
                        let result = composition
                            .resolve_agent_activation_v2(&ticket, now)
                            .map_err(|error| {
                                format!(
                                    "daemon activation resolve ticket {}: {error}",
                                    ticket.ticket_id
                                )
                            })?;
                        let retained = RetainedActivationIdentity {
                            ticket_id: ticket.ticket_id.clone(),
                            result_sha256: result.result_sha256.clone(),
                        };
                        let kernel_clone = Arc::clone(&kernel);
                        let future: Pin<
                            Box<dyn std::future::Future<Output = ActivationCompletion>>,
                        > = Box::pin(async move {
                            let outcome = dispatch_agent_activation_result(
                                &kernel_clone,
                                &ticket,
                                result,
                            )
                            .await;
                            ActivationCompletion::Dispatch(outcome)
                        });
                        flight = ActivationFlight::InFlight(ActivationFlightState {
                            future,
                            retained: Some(retained),
                        });
                    }
                    ActivationCompletion::Dispatch(dispatch_outcome) => match dispatch_outcome {
                        Ok(()) => {
                            flight = ActivationFlight::Idle;
                        }
                        Err(ActivationDispatchError::Hard(error)) => return Err(error),
                        Err(ActivationDispatchError::Unknown { detail, .. }) => {
                            return Err(detail);
                        }
                    },
                }
            }
            _ = cadence.health_heartbeat.tick() => {
                KernelTransitionPort::health(&*kernel)
                    .await
                    .map_err(|error| format!("Kernel health heartbeat: {error}"))?;
            }
        }
    }
}

/// Bounded shutdown drain for one in-flight activation. Never starts new
/// work, never recomputes under a new id, and never silently drops an
/// ambiguous submit: the original ticket/result identity is retained and a
/// timeout or unknown retention surfaces a typed unknown outcome.
async fn drain_activation_on_shutdown(
    flight: &mut ActivationFlight,
) -> Result<RunLoopExit, String> {
    let previous = std::mem::replace(flight, ActivationFlight::Idle);
    let ActivationFlight::InFlight(state) = previous else {
        return Ok(RunLoopExit::Shutdown);
    };
    let retained = state.retained;
    match tokio::time::timeout(SHUTDOWN_ACTIVATION_DRAIN, state.future).await {
        Ok(ActivationCompletion::Claim(claim_outcome)) => match claim_outcome {
            Ok(None) => Ok(RunLoopExit::Shutdown),
            Ok(Some(_)) => Ok(RunLoopExit::Shutdown),
            Err(error) => Err(error),
        },
        Ok(ActivationCompletion::Dispatch(dispatch_outcome)) => match dispatch_outcome {
            Ok(()) => Ok(RunLoopExit::Shutdown),
            Err(ActivationDispatchError::Hard(error)) => Err(error),
            Err(ActivationDispatchError::Unknown {
                ticket_id,
                result_sha256,
                detail,
            }) => Ok(RunLoopExit::ShutdownActivationUnknown {
                ticket_id,
                result_sha256,
                detail,
            }),
        },
        Err(_) => {
            if let Some(identity) = retained {
                Ok(RunLoopExit::ShutdownActivationUnknown {
                    ticket_id: identity.ticket_id,
                    result_sha256: identity.result_sha256,
                    detail: "daemon shutdown drain timed out with activation submit outstanding; original ticket/result identity retained, no recompute"
                        .to_owned(),
                })
            } else {
                Ok(RunLoopExit::Shutdown)
            }
        }
    }
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
) -> Result<(), ActivationDispatchError> {
    observe_transient_deferral(&result);
    match kernel.submit_agent_activation_result(&result).await {
        Ok(ack) => classify_submit_ack(ticket, &result, &ack),
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
    match ack.outcome {
        AgentActivationResultAckOutcome::Accepted
        | AgentActivationResultAckOutcome::ExactReplay
        | AgentActivationResultAckOutcome::Reconciled => Ok(()),
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
        AgentActivationResultAckOutcome::Accepted
        | AgentActivationResultAckOutcome::ExactReplay
        | AgentActivationResultAckOutcome::Reconciled => {
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

/// Observes the transient `NotReady` deferral coupling without adding retry
/// policy. Reconsideration requires the declared due time (`not_before`) plus
/// fresh Governor evidence (changed named dependency revision); Kernel owns
/// that gate (`bins/eliot-kernel/src/agent_bridge.rs::not_ready_supersede_allowed`,
/// `bins/eliot-kernel/src/lib.rs::AgentActivationResultPhase::DeferredNotReady`).
/// Claim-lease expiry alone never triggers a daemon retry, and this loop keeps
/// no cache or timer for it: the next Kernel-issued claim drives any gated
/// supersede, and a changed same-ticket result that misses the gate conflicts
/// on the submit path.
fn observe_transient_deferral(result: &AgentActivationResolutionResult) {
    if result.is_transient_retry() {
        if let Some(not_before) = transient_not_before(result) {
            TRANSIENT_DEFERRAL_OBSERVED.fetch_add(1, Ordering::Relaxed);
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
        return Err("daemon evidence read subject must be non-blank with no control characters"
            .to_owned());
    }
    if max_records.trim().is_empty() || max_records.chars().any(char::is_control) {
        return Err("daemon evidence read max_records must be a non-blank decimal bound".to_owned());
    }
    let bound: u32 = max_records
        .trim()
        .parse()
        .map_err(|_| "daemon evidence read max_records must be a positive decimal bound".to_owned())?;
    if bound == 0 {
        return Err(
            "daemon evidence read max_records must be a positive decimal bound".to_owned(),
        );
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
        return Err("daemon evidence payload subject does not match the requested subject"
            .to_owned());
    }
    if response.payload.get("records").and_then(serde_json::Value::as_array).is_none() {
        return Err("daemon evidence payload misses its records array".to_owned());
    }
    if response.payload.get("provenance").and_then(serde_json::Value::as_object).is_none() {
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
        return Err("daemon position read position must be non-blank with no control characters"
            .to_owned());
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
        return Err("daemon position response operation must be GetCurrentEpistemicPosition".to_owned());
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
            activation_request_sha256: "a".repeat(64),
            peer_admission_receipt_sha256: "b".repeat(64),
            connection_id: "connection-1".to_owned(),
            state_fence: fence,
            kernel_deadline_unix_ms: 100,
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
        let request =
            plan_daemon_evidence_read(&fence, "scope-evidence", "evidence-alpha", "10")
                .expect("closed evidence read plans");
        assert_eq!(
            request.operation,
            eliot_store_api::NamedReadOperation::GetEvidencePack
        );
        assert_eq!(request.state_fence, fence);
        // The planned request passes the real catalogue gate: only
        // `subject`/`max_records` cross, so generation never reports an
        // unknown parameter.
        let entries = eliot_store_api::generated_operation_manifests()
            .expect("catalogue generates");
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
        let projected =
            project_daemon_evidence_response(&response, &fence, "evidence-alpha")
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
