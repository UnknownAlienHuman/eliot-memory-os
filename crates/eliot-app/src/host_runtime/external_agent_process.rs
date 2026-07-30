use anyhow::{Context, Result, bail};
use eliot_types::MAX_SECRET_BOUNDARY_BYTES;
use std::io::Read as _;
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub(super) struct ManagedExternalAgentOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub process_tree_terminated: bool,
    pub root_pid: u32,
    pub observed_processes: Vec<String>,
    pub duration_ms: u64,
}

pub(super) async fn run_external_agent_process<F>(
    command: Command,
    absolute_timeout: Duration,
    cleanup_grace: Duration,
    on_spawned: F,
) -> Result<ManagedExternalAgentOutput>
where
    F: FnOnce(u32) -> Result<()>,
{
    let (spawned_tx, spawned_rx) = tokio::sync::oneshot::channel::<Result<u32, String>>();
    let (dispatch_tx, dispatch_rx) = mpsc::sync_channel::<bool>(1);
    let worker = tokio::task::spawn_blocking(move || {
        run_blocking_provider(
            &command,
            absolute_timeout,
            cleanup_grace,
            spawned_tx,
            &dispatch_rx,
        )
    });
    let root_pid = match spawned_rx.await {
        Ok(Ok(pid)) => pid,
        Ok(Err(error)) => {
            let _ = dispatch_tx.send(false);
            let _ = worker.await;
            bail!("{error}");
        }
        Err(_) => {
            let _ = dispatch_tx.send(false);
            let _ = worker.await;
            bail!("managed provider spawn worker ended before reporting a process");
        }
    };
    let callback = on_spawned(root_pid);
    let _ = dispatch_tx.send(callback.is_ok());
    let output = worker
        .await
        .context("managed provider process worker panicked")??;
    callback?;
    Ok(output)
}

fn run_blocking_provider(
    command: &Command,
    absolute_timeout: Duration,
    cleanup_grace: Duration,
    spawned_tx: tokio::sync::oneshot::Sender<Result<u32, String>>,
    dispatch_rx: &mpsc::Receiver<bool>,
) -> Result<ManagedExternalAgentOutput> {
    let started = Instant::now();
    let mut child = match eliot_windows_ipc::SuspendedJobChild::spawn(command) {
        Ok(child) => child,
        Err(error) => {
            let _ = spawned_tx.send(Err(format!(
                "spawn provider in suspended kill-on-close Job Object: {error}"
            )));
            return Err(error.into());
        }
    };
    let root_pid = child.id();
    let stdout = child
        .take_stdout()
        .context("managed provider stdout pipe is missing")?;
    let stderr = child
        .take_stderr()
        .context("managed provider stderr pipe is missing")?;
    let stdout_thread = std::thread::spawn(move || read_bounded(stdout));
    let stderr_thread = std::thread::spawn(move || read_bounded(stderr));
    let mut observed_processes = child
        .job_processes()
        .unwrap_or_default()
        .into_iter()
        .map(|process| format!("{}:{}", process.pid, process.image.display()))
        .collect::<Vec<_>>();
    let _ = spawned_tx.send(Ok(root_pid));
    let dispatch_admitted = dispatch_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or(false);
    if !dispatch_admitted {
        child
            .terminate(145)
            .context("terminate provider after dispatch journal failure")?;
    }

    let exit = if dispatch_admitted {
        child.wait_timeout(absolute_timeout)?
    } else {
        child.wait_timeout(cleanup_grace)?
    };
    let (exit_code, timed_out) = if let Some(code) = exit {
        (Some(code), false)
    } else {
        child
            .terminate(146)
            .context("terminate timed-out provider Job Object")?;
        let code = child
            .wait_timeout(cleanup_grace)?
            .context("provider Job Object cleanup exceeded its bounded deadline")?;
        (Some(code), dispatch_admitted)
    };
    observed_processes.extend(
        child
            .observed_processes()
            .into_iter()
            .map(|process| format!("{}:{}", process.pid, process.image.display())),
    );
    observed_processes.sort();
    observed_processes.dedup();
    let stdout = stdout_thread
        .join()
        .map_err(|_| anyhow::anyhow!("provider stdout reader panicked"))??;
    let stderr = stderr_thread
        .join()
        .map_err(|_| anyhow::anyhow!("provider stderr reader panicked"))??;
    drop(child);
    Ok(ManagedExternalAgentOutput {
        exit_code,
        stdout,
        stderr,
        timed_out,
        process_tree_terminated: true,
        root_pid,
        observed_processes,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

fn read_bounded(mut reader: std::fs::File) -> std::io::Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        let remaining = MAX_SECRET_BOUNDARY_BYTES
            .saturating_add(1)
            .saturating_sub(retained.len());
        retained.extend_from_slice(&chunk[..count.min(remaining)]);
    }
    Ok(retained)
}
