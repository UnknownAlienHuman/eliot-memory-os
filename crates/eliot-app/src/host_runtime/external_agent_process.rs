use super::supervised_process::{
    ChildCriticality, ProcessRestartPolicy, RestartStrategy, SupervisedChildKind,
    SupervisedProcessSpec, run_supervised_process_with_spawn_hook,
};
use anyhow::{Context, Result, bail};
use eliot_engine::{
    OperationRuntimeHandle,
    runtime_supervision::{AdapterExecutionContext, CancellationToken},
};
use eliot_types::{MAX_SECRET_BOUNDARY_BYTES, ProcessReapReceipt, ProviderTimeoutProfile};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::Command;
use std::time::Duration;
use tokio::time::Instant;

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
    pub reap_receipt: ProcessReapReceipt,
}

pub(super) async fn run_external_agent_process<F>(
    command: Command,
    operation_id: String,
    absolute_timeout: Duration,
    cleanup_grace: Duration,
    context: Option<AdapterExecutionContext>,
    on_spawned: F,
) -> Result<ManagedExternalAgentOutput>
where
    F: FnOnce(u32) -> Result<()>,
{
    let executable = command.get_program().into();
    let args = command.get_args().map(OsString::from).collect();
    let cwd = command
        .get_current_dir()
        .map(ToOwned::to_owned)
        .map_or_else(std::env::current_dir, Ok)
        .context("resolve supervised provider cwd")?;
    let environment = command
        .get_envs()
        .filter_map(|(name, value)| value.map(|value| (name.into(), value.into())))
        .collect::<BTreeMap<OsString, OsString>>();
    let absolute_runtime_deadline_ms =
        u64::try_from(absolute_timeout.as_millis()).unwrap_or(u64::MAX);
    let cleanup_grace_ms = u64::try_from(cleanup_grace.as_millis()).unwrap_or(u64::MAX);
    let context = context.unwrap_or_else(|| AdapterExecutionContext {
        operation_id: operation_id.clone(),
        generation: 1,
        cancellation: CancellationToken::new(),
        deadline: Instant::now() + absolute_timeout,
        runtime_store: OperationRuntimeHandle::disabled(),
        role_lease_id: None,
        role_lease_epoch: None,
        runtime_contract_sha256: None,
    });
    let spec = SupervisedProcessSpec {
        operation_id,
        invocation_id: None,
        generation: context.generation,
        child_kind: SupervisedChildKind::Provider,
        criticality: ChildCriticality::InvocationDependency,
        restart_policy: ProcessRestartPolicy {
            strategy: RestartStrategy::RestForOne,
            max_restarts: 1,
            restart_window_seconds: 60,
            base_backoff_ms: 250,
            pre_dispatch_only: true,
        },
        executable,
        args,
        cwd,
        environment,
        stdin_payload: None,
        stdout_limit_bytes: u64::try_from(MAX_SECRET_BOUNDARY_BYTES).unwrap_or(u64::MAX),
        stderr_limit_bytes: u64::try_from(MAX_SECRET_BOUNDARY_BYTES).unwrap_or(u64::MAX),
        timeout_profile: ProviderTimeoutProfile {
            profile_id: "managed-provider-default-v1".to_owned(),
            provider: "managed-external-agent".to_owned(),
            route_or_operation_class: "provider".to_owned(),
            spawn_deadline_ms: Some(5_000),
            dispatch_ack_deadline_ms: Some(5_000),
            first_output_deadline_ms: None,
            idle_output_deadline_ms: None,
            absolute_runtime_deadline_ms,
            cancellation_grace_ms: 100,
            cleanup_grace_ms,
            reconciliation_window_ms: cleanup_grace_ms,
            output_heartbeat_supported: false,
            status_lookup_supported: false,
            evidence_basis: vec!["governed launch contract wall-clock budget".to_owned()],
            assumptions: Vec::new(),
            hard_upper_bounds: vec!["absolute runtime and cleanup grace".to_owned()],
            policy_version: "runtime-supervision-v1".to_owned(),
        },
        runtime_contract_sha256: context.runtime_contract_sha256.clone(),
        role_lease_id: context.role_lease_id.clone(),
        role_lease_epoch: context.role_lease_epoch,
    };
    let output = run_supervised_process_with_spawn_hook(spec, context, on_spawned).await?;
    if output.stdout_total_bytes < u64::try_from(output.stdout.len()).unwrap_or(u64::MAX)
        || output.stderr_total_bytes < u64::try_from(output.stderr.len()).unwrap_or(u64::MAX)
    {
        bail!("supervised provider byte accounting is inconsistent");
    }
    if output.cancelled && !output.timed_out && output.exit_code == Some(0) {
        bail!("supervised provider reported cancellation with a successful exit");
    }
    if let Some(error) = &output.worker_error {
        bail!("supervised provider cleanup failed: {error}");
    }
    let root_pid = output
        .reap_receipt
        .root_pid
        .context("supervised provider did not report a root PID")?;
    let observed_processes = vec![
        format!("job:{}", output.reap_receipt.job_object_name),
        format!("pid:{root_pid}"),
    ];
    Ok(ManagedExternalAgentOutput {
        exit_code: output.exit_code,
        stdout: output.stdout,
        stderr: output.stderr,
        timed_out: output.timed_out,
        process_tree_terminated: output.reap_receipt.proves_complete_reap(),
        root_pid,
        observed_processes,
        duration_ms: output.reap_receipt.elapsed_ms,
        reap_receipt: output.reap_receipt,
    })
}
