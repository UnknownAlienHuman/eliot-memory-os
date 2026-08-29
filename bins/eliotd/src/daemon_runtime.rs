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
use std::sync::Arc;
use std::time::Duration;

use eliot_governor::KernelTransitionPort;
use eliotd::{
    DaemonComposition, DaemonConfig, DaemonKernelClient, DaemonStatus, PROTOCOL_VERSION,
    SERVICE_NAME,
};
use serde::Serialize;
use tokio::time::{Instant, Interval, MissedTickBehavior};

const ACTIVATION_POLL_INTERVAL: Duration = Duration::from_millis(100);
const HEALTH_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

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
    let composition = DaemonComposition::start(
        config,
        Arc::clone(&kernel) as Arc<dyn eliot_governor::KernelGenerationPort>,
    )
    .map_err(|error| error.to_string())?;
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
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(report_terminal_failure(&kernel, error)),
        (Ok(()), Err(error)) => Err(report_terminal_failure(&kernel, error)),
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
) -> Result<(), String> {
    let mut cadence = LoopCadence::production();
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|error| format!("daemon shutdown signal: {error}"))?;
                return Ok(());
            }
            _ = cadence.activation_poll.tick() => {
                if let Some(ticket) = kernel
                    .claim_agent_activation_ticket()
                    .await
                    .map_err(|error| format!("Kernel activation ticket claim: {error}"))?
                {
                    let now = unix_ms();
                    if activation_deadline_expired(now, ticket.kernel_deadline_unix_ms) {
                        // Kernel owns the typed expiry outcome.  Do not call
                        // the resolver at or after its exact deadline.
                        continue;
                    }
                    if let Ok(decision) = composition.resolve_agent_activation(&ticket, now)
                        && let Err(error) = kernel.submit_agent_activation_decision(&decision).await
                    {
                        // Kernel projects the expected deadline race as an
                        // explicit known outcome. Any remaining transport
                        // error is a real daemon-loop failure.
                        return Err(format!("Kernel activation decision submit: {error}"));
                    }
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

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn activation_deadline_expired(now: u64, deadline: u64) -> bool {
    now >= deadline
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
}
