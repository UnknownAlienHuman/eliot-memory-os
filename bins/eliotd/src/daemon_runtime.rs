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

use eliot_governor::KernelTransitionPort;
use eliotd::{
    DaemonComposition, DaemonConfig, DaemonKernelClient, DaemonStatus, PROTOCOL_VERSION,
    SERVICE_NAME,
};
use serde::Serialize;

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
    write_json(&ready_message(&status));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let loop_result = runtime.block_on(run_loop(Arc::clone(&kernel), &composition));
    let shutdown_result = composition.shutdown().map_err(|error| error.to_string());
    match (loop_result, shutdown_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => {
            let _ = kernel.report_degraded(error.clone());
            write_json(&ReadyMessage::Degraded {
                service: SERVICE_NAME,
                protocol: PROTOCOL_VERSION,
                reason: error.clone(),
            });
            let _ = kernel.report_fatal(error.clone());
            write_json(&ReadyMessage::Fatal {
                service: SERVICE_NAME,
                protocol: PROTOCOL_VERSION,
                reason: error.clone(),
            });
            Err(error)
        }
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(shutdown_error)) => {
            let combined = format!("{error}; shutdown: {shutdown_error}");
            let _ = kernel.report_degraded(combined.clone());
            write_json(&ReadyMessage::Degraded {
                service: SERVICE_NAME,
                protocol: PROTOCOL_VERSION,
                reason: combined.clone(),
            });
            let _ = kernel.report_fatal(combined.clone());
            write_json(&ReadyMessage::Fatal {
                service: SERVICE_NAME,
                protocol: PROTOCOL_VERSION,
                reason: combined.clone(),
            });
            Err(combined)
        }
    }
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

async fn run_loop(
    kernel: Arc<DaemonKernelClient>,
    composition: &DaemonComposition,
) -> Result<(), String> {
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|error| format!("daemon shutdown signal: {error}"))?;
                return Ok(());
            }
            () = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
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
            () = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
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

pub(super) fn write_json(message: &ReadyMessage) {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let _ = serde_json::to_writer(&mut output, message);
    let _ = output.write_all(b"\n");
    let _ = output.flush();
}
