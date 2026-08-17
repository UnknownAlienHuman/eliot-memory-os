//! `eliotd` service entrypoint.
//!
//! Host/N1 owns the authenticated Kernel-generation transport. This binary
//! composes Governor only from that transport and never creates a local Store,
//! ProcessExecutor, or authority source.

use std::io::{self, Write};
use std::sync::Arc;

use eliot_governor::KernelTransitionPort;
use eliotd::{
    DaemonComposition, DaemonConfig, DaemonKernelClient, DaemonStatus, PROTOCOL_VERSION,
    SERVICE_NAME,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ReadyMessage {
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

fn main() {
    if let Err(error) = run() {
        write_json(&ReadyMessage::Error {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            error,
        });
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = DaemonConfig::load_protected().map_err(|error| error.to_string())?;
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
    let loop_result = runtime.block_on(run_loop(Arc::clone(&kernel)));
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

async fn run_loop(kernel: Arc<DaemonKernelClient>) -> Result<(), String> {
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|error| format!("daemon shutdown signal: {error}"))?;
                return Ok(());
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                KernelTransitionPort::health(&*kernel)
                    .await
                    .map_err(|error| format!("Kernel health heartbeat: {error}"))?;
            }
        }
    }
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

fn write_json(message: &ReadyMessage) {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let _ = serde_json::to_writer(&mut output, message);
    let _ = output.write_all(b"\n");
    let _ = output.flush();
}
