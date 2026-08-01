use crate::runtime_instance::{
    RuntimeInstance, RuntimePublicationState, atomic_write_json, sha256_file,
};
use anyhow::{Context, Result, bail, ensure};
use eliot_engine::{HostBrokerService, OperationRuntimeHandle};
use eliot_types::{
    AdapterCircuitState, AgentHostId, AgentSessionState, AuthorityLeaseLifetime,
    AuthorityLeaseState, ExternalAgentPurpose, OPERATION_AUTHORITY_SCHEMA_VERSION,
    OperationAuthorityCloseRequest, OperationAuthorityTerminalOutcome, OperationCancellationState,
    OperationJobState, OperationReconciliationState, RUNTIME_INTEGRITY_REPORT_SCHEMA_VERSION,
    RuntimeAdapterHealth, RuntimeAuthorityIntegrity, RuntimeCoreHealth, RuntimeIntegrityHealth,
    RuntimeOperationDetail, RuntimeOperationHealth, RuntimeOverallStatus, RuntimeReconcileDecision,
    RuntimeReconcileDryRun, RuntimeSupervisionReport, SealStagingState,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

const EXTERNAL_ADAPTER_IDS: [&str; 3] = [
    "external-agent:claude",
    "external-agent:antigravity",
    "external-agent:opencode",
];

#[derive(Default)]
struct SealInventory {
    partial_ids: BTreeSet<String>,
    published_without_authority: u32,
    authority_without_published: u32,
    quarantine_records: u32,
    errors: Vec<String>,
}

fn authority_owner_issue(
    broker: &eliot_types::DelegationState,
    lease: &eliot_types::TaskRoleLease,
) -> Option<&'static str> {
    match lease.lifetime {
        AuthorityLeaseLifetime::Legacy => Some("legacy_authority_requires_typed_recovery"),
        AuthorityLeaseLifetime::Persistent => (lease.owner_operation_id.is_some()
            || lease.seal_attempt_id.is_some())
        .then_some("persistent_authority_has_temporary_owner"),
        AuthorityLeaseLifetime::OperationBound => {
            let Some(owner) = lease.owner_operation_id.as_deref() else {
                return Some("operation_bound_authority_has_no_live_exact_owner");
            };
            let healthy = lease.seal_attempt_id.is_none()
                && broker.operation_jobs.iter().any(|job| {
                    job.job_id == owner
                        && job.invocation_id == owner
                        && job.generation == lease.generation
                        && job.role_lease_id.as_deref() == Some(lease.role_lease_id.as_str())
                        && job.role_lease_epoch == Some(lease.epoch)
                        && matches!(
                            job.state,
                            OperationJobState::Queued | OperationJobState::Running
                        )
                });
            (!healthy).then_some("operation_bound_authority_has_no_live_exact_owner")
        }
        AuthorityLeaseLifetime::SealBound => lease
            .seal_attempt_id
            .as_deref()
            .is_none_or(str::is_empty)
            .then_some("seal_bound_authority_has_no_seal_owner"),
    }
}

fn terminal_authority_outcome(
    state: OperationJobState,
) -> Option<OperationAuthorityTerminalOutcome> {
    match state {
        OperationJobState::Completed => Some(OperationAuthorityTerminalOutcome::Completed),
        OperationJobState::Failed | OperationJobState::Abandoned => {
            Some(OperationAuthorityTerminalOutcome::FailedAfterDispatch)
        }
        OperationJobState::TimedOut => Some(OperationAuthorityTerminalOutcome::TimedOut),
        OperationJobState::Cancelled => Some(OperationAuthorityTerminalOutcome::Cancelled),
        OperationJobState::UnknownOutcome | OperationJobState::Reconciled => {
            Some(OperationAuthorityTerminalOutcome::ReconciledUnknown)
        }
        OperationJobState::Queued | OperationJobState::Running => None,
    }
}

fn partial_operation_close_requests(
    root: &Path,
    broker: &eliot_types::DelegationState,
) -> Result<Vec<OperationAuthorityCloseRequest>> {
    let mut requests = Vec::new();
    for lease in broker.task_role_leases.iter().filter(|lease| {
        lease.lifetime == AuthorityLeaseLifetime::OperationBound
            && lease.state == AuthorityLeaseState::Revoked
    }) {
        let Some(operation_id) = lease.owner_operation_id.as_deref() else {
            continue;
        };
        let Some(job) = broker.operation_jobs.iter().find(|job| {
            job.job_id == operation_id
                && job.invocation_id == operation_id
                && job.generation == lease.generation
                && job.role_lease_id.as_deref() == Some(lease.role_lease_id.as_str())
                && job.role_lease_epoch == Some(lease.epoch)
        }) else {
            continue;
        };
        let Some(terminal_outcome) = terminal_authority_outcome(job.state) else {
            continue;
        };
        let Some(binding) = broker.agent_host_sessions.iter().find(|binding| {
            binding.agent_session_id == lease.agent_session_id
                && binding.generation == lease.generation
                && binding.state == AgentSessionState::Retired
                && binding.bound_task_id == Some(lease.task_id)
        }) else {
            continue;
        };
        let authority_path = root
            .join("reports")
            .join("role-lease-authority")
            .join(format!(
                "{}.json",
                blake3::hash(lease.role_lease_id.as_bytes()).to_hex()
            ));
        let authority: Value =
            serde_json::from_slice(&std::fs::read(&authority_path).with_context(|| {
                format!(
                    "read operation close authority projection {}",
                    authority_path.display()
                )
            })?)?;
        let close_complete = [
            "canonical_revoked_role_receipt",
            "canonical_retired_binding_receipt",
            "canonical_terminal_job_receipt",
        ]
        .iter()
        .all(|field| authority.get(*field).is_some_and(|value| !value.is_null()));
        if close_complete {
            continue;
        }
        let purpose: ExternalAgentPurpose = serde_json::from_value(
            authority
                .get("purpose")
                .cloned()
                .context("partial operation close has no typed purpose")?,
        )?;
        let project_id = binding
            .bound_project_id
            .context("partial operation close binding has no project")?;
        let close_idempotency_key = authority
            .get("close_idempotency_key")
            .and_then(Value::as_str)
            .map_or_else(|| format!("{}:close", job.idempotency_key), str::to_owned);
        requests.push(OperationAuthorityCloseRequest {
            schema_version: OPERATION_AUTHORITY_SCHEMA_VERSION.to_owned(),
            operation_id: operation_id.to_owned(),
            purpose,
            generation: lease.generation,
            project_id,
            task_id: lease.task_id,
            agent_session_id: lease.agent_session_id,
            role_lease_id: lease.role_lease_id.clone(),
            expected_epoch: lease.epoch,
            terminal_outcome,
            result_or_failure_ref: job.result_ref.clone(),
            reason: "typed_partial_operation_close_reconciliation".to_owned(),
            idempotency_key: close_idempotency_key,
        });
    }
    requests.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    Ok(requests)
}

#[allow(
    clippy::too_many_lines,
    reason = "one read-only integrity snapshot keeps cross-section counts and decisions consistent"
)]
pub(crate) async fn inspect(
    config_path: &Path,
    runtime_store: &OperationRuntimeHandle,
    core_prerequisites_ready: bool,
    instance: Option<&str>,
) -> Result<RuntimeSupervisionReport> {
    let now = OffsetDateTime::now_utc();
    let root = crate::delegation_runtime::root_from_config(config_path);
    let broker = crate::delegation_runtime::load_state(&root)?;
    let partial_operation_closes = partial_operation_close_requests(&root, &broker)?;
    let checkpoints = runtime_store.list_nonterminal_checkpoints().await?;
    let staging = runtime_store.load_incomplete_seal_staging().await?;
    let recovery_cursor = runtime_store.recovery_cursor().await?;
    let instance = RuntimeInstance::select(config_path, instance)?;
    let publication = instance
        .read_publication_any_state(crate::named_pipe_ipc::IPC_PROTOCOL_VERSION)
        .ok();
    let expected_sha256 = publication.as_ref().and_then(|publication| {
        (!publication.executable_sha256.is_empty()).then(|| publication.executable_sha256.clone())
    });
    let observed_sha256 = publication
        .as_ref()
        .and_then(|publication| sha256_file(&publication.executable).ok());
    let executable = publication
        .as_ref()
        .map(|publication| publication.executable.display().to_string());
    let hash_matches = expected_sha256
        .as_ref()
        .zip(observed_sha256.as_ref())
        .is_none_or(|(expected, observed)| expected == observed);
    let publication_ready = publication
        .as_ref()
        .is_some_and(|publication| publication.state == RuntimePublicationState::Ready);
    let ipc_ready = runtime_store.is_enabled();
    let core_ready = core_prerequisites_ready && ipc_ready && hash_matches;
    let core = RuntimeCoreHealth {
        ready: core_ready,
        ipc_ready,
        db_ready: core_prerequisites_ready,
        writer_ready: core_prerequisites_ready,
        read_service_ready: core_prerequisites_ready,
        service_generation: publication
            .as_ref()
            .map(|publication| publication.runtime_id.clone()),
        executable_sha256: observed_sha256.clone(),
    };

    let mut details = checkpoints
        .iter()
        .map(|checkpoint| RuntimeOperationDetail {
            operation_id: checkpoint.operation_id.clone(),
            generation: checkpoint.generation,
            phase: checkpoint.phase,
            last_progress_at: checkpoint.last_progress_at.to_string(),
            phase_deadline_at: checkpoint.phase_deadline_at.to_string(),
            root_pid: checkpoint.root_pid,
            active_process_count: checkpoint.active_process_count,
            stdin_state: byte_stream_state(checkpoint.stdin_bytes, checkpoint.is_terminal()),
            stdout_state: byte_stream_state(checkpoint.stdout_bytes, checkpoint.is_terminal()),
            stderr_state: byte_stream_state(checkpoint.stderr_bytes, checkpoint.is_terminal()),
            cancellation_state: checkpoint.cancellation_state,
            reconciliation_state: checkpoint.reconciliation_state,
            role_lease_id: checkpoint.role_lease_id.clone(),
            role_lease_epoch: checkpoint.role_lease_epoch,
        })
        .collect::<Vec<_>>();
    details.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    let stuck = checkpoints
        .iter()
        .filter(|checkpoint| {
            now > checkpoint.phase_deadline_at || now > checkpoint.absolute_deadline_at
        })
        .count();
    let cleanup_pending = checkpoints
        .iter()
        .filter(|checkpoint| {
            checkpoint.active_process_count > 0
                && checkpoint.cancellation_state != OperationCancellationState::NotRequested
        })
        .count()
        + partial_operation_closes.len();
    let orphan_processes = checkpoints
        .iter()
        .filter(|checkpoint| {
            checkpoint.active_process_count > 0
                && (now > checkpoint.phase_deadline_at
                    || now > checkpoint.absolute_deadline_at
                    || checkpoint.cancellation_state != OperationCancellationState::NotRequested)
        })
        .map(|checkpoint| checkpoint.active_process_count)
        .sum();
    let operations = RuntimeOperationHealth {
        active: usize_to_u32(checkpoints.len()),
        stuck: usize_to_u32(stuck),
        awaiting_reconciliation: usize_to_u32(
            checkpoints
                .iter()
                .filter(|checkpoint| {
                    checkpoint.reconciliation_state == OperationReconciliationState::Pending
                })
                .count()
                + partial_operation_closes.len(),
        ),
        cleanup_pending: usize_to_u32(cleanup_pending),
        orphan_processes,
        oldest_last_progress_at: checkpoints
            .iter()
            .map(|checkpoint| checkpoint.last_progress_at)
            .min()
            .map(|value| value.to_string()),
        details,
    };

    let session_by_id = broker
        .agent_host_sessions
        .iter()
        .map(|session| (session.agent_session_id, session))
        .collect::<BTreeMap<_, _>>();
    let orphaned_role_leases = broker
        .task_role_leases
        .iter()
        .filter(|lease| {
            matches!(
                lease.state,
                AuthorityLeaseState::Active | AuthorityLeaseState::Pending
            ) && (session_by_id
                .get(&lease.agent_session_id)
                .is_none_or(|session| {
                    session.state != AgentSessionState::Active
                        || session.generation != lease.generation
                })
                || authority_owner_issue(&broker, lease).is_some())
        })
        .count();
    let stale_epoch_results = broker
        .agent_results
        .iter()
        .filter(|result| {
            let invocation = broker
                .agent_invocations
                .iter()
                .find(|invocation| invocation.invocation_id == result.invocation_id);
            let lease = invocation.and_then(|invocation| {
                broker
                    .task_role_leases
                    .iter()
                    .find(|lease| lease.role_lease_id == invocation.role_lease_id)
            });
            invocation.zip(lease).is_none_or(|(invocation, lease)| {
                lease.state != AuthorityLeaseState::Active
                    || invocation.role_lease_epoch != result.role_lease_epoch
                    || invocation.operation_generation != result.operation_generation
                    || lease.epoch != result.role_lease_epoch
                    || lease.generation != result.operation_generation
            })
        })
        .count();
    let mut seal_inventory = scan_seal_inventory(config_path, &broker)?;
    seal_inventory.partial_ids.extend(
        staging
            .iter()
            .map(|checkpoint| checkpoint.seal_attempt_id.clone()),
    );
    let authority_integrity = RuntimeAuthorityIntegrity {
        active_sessions: usize_to_u32(
            broker
                .agent_host_sessions
                .iter()
                .filter(|session| session.state == AgentSessionState::Active)
                .count(),
        ),
        active_role_leases: usize_to_u32(
            broker
                .task_role_leases
                .iter()
                .filter(|lease| lease.state == AuthorityLeaseState::Active)
                .count(),
        ),
        pending_role_leases: usize_to_u32(
            broker
                .task_role_leases
                .iter()
                .filter(|lease| lease.state == AuthorityLeaseState::Pending)
                .count(),
        ),
        orphaned_role_leases: usize_to_u32(orphaned_role_leases),
        revoked_role_leases: usize_to_u32(
            broker
                .task_role_leases
                .iter()
                .filter(|lease| {
                    matches!(
                        lease.state,
                        AuthorityLeaseState::Revoked | AuthorityLeaseState::Expired
                    )
                })
                .count(),
        ),
        stale_epoch_results: usize_to_u32(stale_epoch_results),
        partial_seals: usize_to_u32(seal_inventory.partial_ids.len()),
        published_plans_without_authority: seal_inventory.published_without_authority,
        authority_without_published_plan: seal_inventory.authority_without_published,
    };

    let mut integrity_errors = seal_inventory.errors;
    if !hash_matches {
        integrity_errors.push("governor_executable_hash_mismatch".to_owned());
    }
    if orphaned_role_leases > 0 {
        integrity_errors.push("orphaned_role_leases".to_owned());
    }
    if authority_integrity.partial_seals > 0 {
        integrity_errors.push("partial_seals".to_owned());
    }
    if authority_integrity.published_plans_without_authority > 0 {
        integrity_errors.push("published_plans_without_authority".to_owned());
    }
    if authority_integrity.authority_without_published_plan > 0 {
        integrity_errors.push("authority_without_published_plan".to_owned());
    }
    if operations.orphan_processes > 0 || operations.cleanup_pending > 0 {
        integrity_errors.push("orphan_or_cleanup_processes".to_owned());
    }
    if !partial_operation_closes.is_empty() {
        integrity_errors.push("partial_operation_close_canonical_proof".to_owned());
    }
    if operations.awaiting_reconciliation > 0 {
        integrity_errors.push("operations_awaiting_reconciliation".to_owned());
    }
    if operations.stuck > 0 {
        integrity_errors.push("stuck_operations".to_owned());
    }
    integrity_errors.sort();
    integrity_errors.dedup();

    let runtime_integrity = RuntimeIntegrityHealth {
        clean: integrity_errors.is_empty(),
        expected_governor_sha256: expected_sha256,
        observed_governor_sha256: observed_sha256,
        locked_active_binary: executable,
        process_orphans: operations.orphan_processes,
        incomplete_staging_roots: usize_to_u32(staging.len()),
        quarantine_records: seal_inventory.quarantine_records,
        last_startup_recovery_ref: recovery_cursor,
        last_watchdog_action_ref: checkpoints
            .iter()
            .find_map(|checkpoint| checkpoint.last_evidence_refs.last())
            .cloned(),
    };
    let adapters = adapter_health(runtime_store, &checkpoints, &broker).await?;
    let provider_dispatch_safe = core.ready
        && runtime_integrity.clean
        && authority_integrity.orphaned_role_leases == 0
        && authority_integrity.partial_seals == 0
        && authority_integrity.published_plans_without_authority == 0
        && authority_integrity.authority_without_published_plan == 0;
    let (overall, reason) = if !core.ready {
        (RuntimeOverallStatus::NotReady, "core_not_ready".to_owned())
    } else if !provider_dispatch_safe {
        (
            RuntimeOverallStatus::IntegrityFailed,
            integrity_errors
                .first()
                .cloned()
                .unwrap_or_else(|| "runtime_integrity_failed".to_owned()),
        )
    } else if adapters.iter().any(|adapter| !adapter.ready) {
        (
            RuntimeOverallStatus::Degraded,
            "optional_adapter_degraded".to_owned(),
        )
    } else {
        (
            RuntimeOverallStatus::Ready,
            "runtime_integrity_clean".to_owned(),
        )
    };
    let _ = publication_ready;
    Ok(RuntimeSupervisionReport {
        schema_version: RUNTIME_INTEGRITY_REPORT_SCHEMA_VERSION.to_owned(),
        generated_at: now.to_string(),
        core,
        adapters,
        operations,
        authority_integrity,
        runtime_integrity,
        overall,
        reason,
        provider_dispatch_safe,
        integrity_errors,
    })
}

async fn open_external_adapter_circuits(
    runtime_store: &OperationRuntimeHandle,
) -> Result<Vec<&'static str>> {
    let mut adapter_ids = Vec::new();
    for adapter_id in EXTERNAL_ADAPTER_IDS {
        if runtime_store
            .load_restart_window(adapter_id)
            .await?
            .is_some_and(|window| window.circuit_state == AdapterCircuitState::Open)
        {
            adapter_ids.push(adapter_id);
        }
    }
    Ok(adapter_ids)
}

async fn open_external_adapter_circuit_decisions(
    runtime_store: &OperationRuntimeHandle,
) -> Result<Vec<RuntimeReconcileDecision>> {
    Ok(open_external_adapter_circuits(runtime_store)
        .await?
        .into_iter()
        .map(|adapter_id| RuntimeReconcileDecision {
            operation_id: adapter_id.to_owned(),
            generation: 0,
            decision: "half_open_static_adapter_probe".to_owned(),
            mutates: false,
            reason: "durable_adapter_circuit_open".to_owned(),
        })
        .collect())
}

fn sort_reconcile_decisions(decisions: &mut [RuntimeReconcileDecision]) {
    decisions.sort_by(|left, right| {
        left.operation_id
            .cmp(&right.operation_id)
            .then(left.generation.cmp(&right.generation))
    });
}

pub(crate) async fn reconcile_dry_run(
    config_path: &Path,
    runtime_store: &OperationRuntimeHandle,
) -> Result<RuntimeReconcileDryRun> {
    let now = OffsetDateTime::now_utc();
    let root = crate::delegation_runtime::root_from_config(config_path);
    let broker = crate::delegation_runtime::load_state(&root)?;
    let checkpoints = runtime_store.list_nonterminal_checkpoints().await?;
    let staging = runtime_store.load_incomplete_seal_staging().await?;
    let mut decisions = Vec::new();
    for checkpoint in checkpoints {
        let expired = now > checkpoint.phase_deadline_at || now > checkpoint.absolute_deadline_at;
        if expired || checkpoint.cancellation_state != OperationCancellationState::NotRequested {
            let post_dispatch =
                checkpoint.dispatch_state != eliot_types::ProviderDispatchState::NotStarted;
            decisions.push(RuntimeReconcileDecision {
                operation_id: checkpoint.operation_id,
                generation: checkpoint.generation,
                decision: if post_dispatch {
                    "fence_reap_reconcile_no_retry"
                } else {
                    "fence_reap_pre_dispatch"
                }
                .to_owned(),
                mutates: false,
                reason: if expired {
                    "deadline_exceeded"
                } else {
                    "cancellation_requested"
                }
                .to_owned(),
            });
        }
    }
    for checkpoint in staging {
        decisions.push(RuntimeReconcileDecision {
            operation_id: checkpoint.seal_attempt_id,
            generation: checkpoint.generation,
            decision: match checkpoint.state {
                SealStagingState::Staged => "remove_unowned_staging",
                SealStagingState::Activated => "finish_or_abandon_activated_seal",
                SealStagingState::Published | SealStagingState::Abandoned => {
                    "remove_completed_staging_checkpoint"
                }
            }
            .to_owned(),
            mutates: false,
            reason: "incomplete_seal_staging_checkpoint".to_owned(),
        });
    }
    for lease in &broker.task_role_leases {
        if matches!(
            lease.state,
            AuthorityLeaseState::Active | AuthorityLeaseState::Pending
        ) && (broker
            .agent_host_sessions
            .iter()
            .find(|session| session.agent_session_id == lease.agent_session_id)
            .is_none_or(|session| session.state != AgentSessionState::Active)
            || authority_owner_issue(&broker, lease).is_some())
        {
            let reason = authority_owner_issue(&broker, lease)
                .unwrap_or("no_active_owner_session")
                .to_owned();
            decisions.push(RuntimeReconcileDecision {
                operation_id: lease.role_lease_id.clone(),
                generation: lease.generation,
                decision: match lease.lifetime {
                    AuthorityLeaseLifetime::OperationBound => "close_operation_bound_authority",
                    AuthorityLeaseLifetime::Legacy => "typed_legacy_authority_recovery",
                    AuthorityLeaseLifetime::Persistent | AuthorityLeaseLifetime::SealBound => {
                        "block_invalid_declared_authority"
                    }
                }
                .to_owned(),
                mutates: false,
                reason,
            });
        }
    }
    for close in partial_operation_close_requests(&root, &broker)? {
        decisions.push(RuntimeReconcileDecision {
            operation_id: close.operation_id,
            generation: close.generation,
            decision: "retry_operation_close_canonical_proof".to_owned(),
            mutates: false,
            reason: "local_fence_present_canonical_close_incomplete".to_owned(),
        });
    }
    decisions.extend(open_external_adapter_circuit_decisions(runtime_store).await?);
    sort_reconcile_decisions(&mut decisions);
    Ok(RuntimeReconcileDryRun {
        schema_version: "eliot-runtime-reconcile-dry-run-v1".to_owned(),
        generated_at: now.to_string(),
        dry_run: true,
        decisions,
        provider_calls: 0,
        writes: 0,
    })
}

pub(crate) async fn reconcile_apply(
    config_path: &Path,
    runtime_store: &OperationRuntimeHandle,
    instance: Option<&str>,
) -> Result<Value> {
    let root = crate::delegation_runtime::root_from_config(config_path);
    let broker = crate::delegation_runtime::load_state(&root)?;
    let requests = partial_operation_close_requests(&root, &broker)?;
    let governor_instance = crate::host_runtime::host_governor_instance(config_path)?;
    let mut close_receipts = Vec::new();
    for close in requests {
        let response = crate::named_pipe_ipc::host_governor_request(
            &governor_instance,
            "host/operation-scope-close",
            serde_json::to_value(close)?,
        )
        .await
        .context("reconcile partial operation close through daemon-owned WriterActor")?;
        close_receipts.push(response);
    }
    let mut adapter_circuit_probes = Vec::new();
    for adapter_id in open_external_adapter_circuits(runtime_store).await? {
        adapter_circuit_probes.push(
            crate::host_runtime::half_open_external_agent_circuit(config_path, adapter_id).await?,
        );
    }
    let status = inspect(config_path, runtime_store, true, instance).await?;
    persist_report(config_path, &status)?;
    Ok(json!({
        "schema_version": "eliot-runtime-reconcile-apply-v1",
        "generated_at": OffsetDateTime::now_utc(),
        "dry_run": false,
        "provider_calls": 0,
        "raw_state_edits": 0,
        "canonical_close_receipts": close_receipts,
        "adapter_circuit_probes": adapter_circuit_probes,
        "provider_dispatch_safe": status.provider_dispatch_safe,
        "runtime_integrity_clean": status.runtime_integrity.clean,
    }))
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn legacy_authority_recovery(
    config_path: &Path,
    runtime_store: &OperationRuntimeHandle,
    dry_run: bool,
) -> Result<Value> {
    let root = crate::delegation_runtime::root_from_config(config_path);
    let broker = crate::delegation_runtime::load_state(&root)?;
    let checkpoints = runtime_store.list_nonterminal_checkpoints().await?;
    let mut dispositions = Vec::new();
    let mut recoverable = Vec::new();
    for lease in broker
        .task_role_leases
        .iter()
        .filter(|lease| lease.lifetime == AuthorityLeaseLifetime::Legacy)
    {
        let binding = broker
            .agent_host_sessions
            .iter()
            .find(|binding| binding.agent_session_id == lease.agent_session_id);
        let invocation = broker.agent_invocations.iter().find(|request| {
            request.role_lease_id == lease.role_lease_id
                && request.task_id == lease.task_id
                && request.role_lease_epoch == lease.epoch
                && request.operation_generation == lease.generation
        });
        let job = invocation.and_then(|request| {
            broker
                .operation_jobs
                .iter()
                .find(|job| job.invocation_id == request.invocation_id)
        });
        let result = invocation.and_then(|request| {
            broker.agent_results.iter().find(|result| {
                result.invocation_id == request.invocation_id
                    && result.role_lease_epoch == lease.epoch
                    && result.operation_generation == lease.generation
            })
        });
        let live_checkpoint = invocation.is_some_and(|request| {
            checkpoints.iter().any(|checkpoint| {
                checkpoint.operation_id == request.invocation_id
                    || checkpoint.role_lease_id.as_deref() == Some(lease.role_lease_id.as_str())
            })
        });
        let exact_legacy_smoke = lease.state == AuthorityLeaseState::Active
            && lease.seal_attempt_id.as_deref() == Some("legacy-live-grant")
            && lease.owner_operation_id.is_none()
            && lease.epoch > 0
            && lease.generation > 0
            && binding.is_some_and(|binding| {
                binding.state == AgentSessionState::Active
                    && binding.generation == lease.generation
                    && binding.bound_task_id == Some(lease.task_id)
                    && binding
                        .task_role_lease_refs
                        .iter()
                        .any(|role_lease_id| role_lease_id == &lease.role_lease_id)
            })
            && invocation
                .is_some_and(|request| request.invocation_id.starts_with("external-agent-smoke-"))
            && job.is_some_and(|job| {
                !matches!(
                    job.state,
                    OperationJobState::Queued | OperationJobState::Running
                ) && job.result_ref.is_some()
                    && job.generation == lease.generation
                    && job.role_lease_id.as_deref() == Some(lease.role_lease_id.as_str())
                    && job.role_lease_epoch == Some(lease.epoch)
            })
            && result.is_some_and(|result| result.canonical_receipt.is_some())
            && !live_checkpoint;
        let disposition = if exact_legacy_smoke {
            "recover_exact_terminal_legacy_smoke"
        } else if lease.state != AuthorityLeaseState::Active {
            "already_terminal"
        } else if lease.seal_attempt_id.as_deref() != Some("legacy-live-grant") {
            "ambiguous_legacy_owner"
        } else if live_checkpoint {
            "live_or_unreconciled_operation"
        } else {
            "insufficient_exact_terminal_evidence"
        };
        dispositions.push(json!({
            "role_lease_id": lease.role_lease_id,
            "epoch": lease.epoch,
            "generation": lease.generation,
            "state": lease.state,
            "disposition": disposition,
            "recoverable": exact_legacy_smoke,
        }));
        if exact_legacy_smoke {
            let request = invocation.context("recoverable legacy lease has no invocation")?;
            let job = job.context("recoverable legacy lease has no operation job")?;
            recoverable.push(OperationAuthorityCloseRequest {
                schema_version: OPERATION_AUTHORITY_SCHEMA_VERSION.to_owned(),
                operation_id: request.invocation_id.clone(),
                purpose: ExternalAgentPurpose::ProviderSmoke,
                generation: lease.generation,
                project_id: request.project_id,
                task_id: lease.task_id,
                agent_session_id: lease.agent_session_id,
                role_lease_id: lease.role_lease_id.clone(),
                expected_epoch: lease.epoch,
                terminal_outcome: match job.state {
                    OperationJobState::Completed => OperationAuthorityTerminalOutcome::Completed,
                    OperationJobState::TimedOut => OperationAuthorityTerminalOutcome::TimedOut,
                    OperationJobState::Cancelled => OperationAuthorityTerminalOutcome::Cancelled,
                    OperationJobState::UnknownOutcome | OperationJobState::Reconciled => {
                        OperationAuthorityTerminalOutcome::ReconciledUnknown
                    }
                    OperationJobState::Failed | OperationJobState::Abandoned => {
                        OperationAuthorityTerminalOutcome::FailedAfterDispatch
                    }
                    OperationJobState::Queued | OperationJobState::Running => {
                        unreachable!("recoverable legacy job was proven terminal")
                    }
                },
                result_or_failure_ref: job.result_ref.clone(),
                reason: "typed_exact_terminal_legacy_smoke_recovery".to_owned(),
                idempotency_key: format!(
                    "legacy-authority-recovery:{}:{}",
                    lease.role_lease_id, lease.epoch
                ),
            });
        }
    }
    dispositions.sort_by(|left, right| {
        left.get("role_lease_id")
            .and_then(Value::as_str)
            .cmp(&right.get("role_lease_id").and_then(Value::as_str))
    });
    let mut close_receipts = Vec::new();
    if !dry_run {
        ensure!(
            dispositions.iter().all(|item| {
                item.get("recoverable").and_then(Value::as_bool) == Some(true)
                    || item.get("disposition").and_then(Value::as_str) == Some("already_terminal")
            }),
            "legacy authority recovery refuses apply while ambiguous active Legacy leases remain"
        );
        let instance = crate::host_runtime::host_governor_instance(config_path)?;
        for close in recoverable {
            let response = crate::named_pipe_ipc::host_governor_request(
                &instance,
                "host/operation-scope-close",
                serde_json::to_value(close)?,
            )
            .await
            .context("route typed legacy recovery through operation close")?;
            close_receipts.push(response);
        }
    }
    Ok(json!({
        "schema_version": "eliot-legacy-authority-recovery-v1",
        "generated_at": OffsetDateTime::now_utc(),
        "dry_run": dry_run,
        "provider_calls": 0,
        "raw_state_edits": 0,
        "dispositions": dispositions,
        "close_receipts": close_receipts,
    }))
}

pub(crate) async fn startup_recover_and_report(
    config_path: &Path,
    runtime_store: &OperationRuntimeHandle,
    instance: Option<&str>,
) -> Result<RuntimeSupervisionReport> {
    let now = OffsetDateTime::now_utc();
    let checkpoints_before = runtime_store.list_nonterminal_checkpoints().await?;
    recover_authority(config_path, &checkpoints_before)?;
    crate::host_runtime::supervised_process::recover_stale_job_objects(runtime_store, now, true)
        .await?;
    recover_unowned_staging(config_path, runtime_store).await?;
    let report = inspect(config_path, runtime_store, true, instance).await?;
    persist_report(config_path, &report)?;
    let canonical_close_recovery_only = report.core.ready
        && report.operations.active == 0
        && report.operations.stuck == 0
        && report.operations.orphan_processes == 0
        && report
            .integrity_errors
            .iter()
            .any(|error| error == "partial_operation_close_canonical_proof")
        && report.integrity_errors.iter().all(|error| {
            matches!(
                error.as_str(),
                "partial_operation_close_canonical_proof"
                    | "operations_awaiting_reconciliation"
                    | "orphan_or_cleanup_processes"
            )
        });
    if !report.provider_dispatch_safe && !canonical_close_recovery_only {
        bail!(
            "runtime integrity blocks provider dispatch: {}",
            report.integrity_errors.join(", ")
        );
    }
    Ok(report)
}

pub(crate) fn persist_report(config_path: &Path, report: &RuntimeSupervisionReport) -> Result<()> {
    let root = crate::delegation_runtime::root_from_config(config_path);
    let report_root = root.join("reports/runtime-supervision");
    std::fs::create_dir_all(&report_root)?;
    atomic_write_json(&report_root.join("latest.json"), report)?;
    let markdown = format!(
        "# Runtime supervision\n\n- overall: `{:?}`\n- reason: `{}`\n- provider dispatch safe: `{}`\n- active operations: `{}`\n- orphan processes: `{}`\n- orphaned role leases: `{}`\n- partial seals: `{}`\n",
        report.overall,
        report.reason,
        report.provider_dispatch_safe,
        report.operations.active,
        report.operations.orphan_processes,
        report.authority_integrity.orphaned_role_leases,
        report.authority_integrity.partial_seals,
    );
    crate::runtime_instance::atomic_write_bytes(&report_root.join("latest.md"), markdown.as_bytes())
}

async fn recover_unowned_staging(
    config_path: &Path,
    runtime_store: &OperationRuntimeHandle,
) -> Result<()> {
    let root = crate::delegation_runtime::root_from_config(config_path);
    let broker = crate::delegation_runtime::load_state(&root)?;
    let allowed_root = cognitive_root(config_path);
    for checkpoint in runtime_store.load_incomplete_seal_staging().await? {
        let has_authority = broker.task_role_leases.iter().any(|lease| {
            lease.seal_attempt_id.as_deref() == Some(&checkpoint.seal_attempt_id)
                && matches!(
                    lease.state,
                    AuthorityLeaseState::Active | AuthorityLeaseState::Pending
                )
        });
        if checkpoint.state == SealStagingState::Staged && !has_authority {
            let staging_root = PathBuf::from(&checkpoint.staging_root);
            if staging_root.exists() {
                let allowed = allowed_root
                    .as_ref()
                    .is_some_and(|allowed| staging_root.starts_with(allowed));
                if !allowed {
                    bail!(
                        "refuse to remove staging root outside cognitive root: {}",
                        staging_root.display()
                    );
                }
                std::fs::remove_dir_all(&staging_root).with_context(|| {
                    format!("remove unowned staging root {}", staging_root.display())
                })?;
            }
            runtime_store
                .remove_seal_staging(checkpoint.seal_attempt_id)
                .await?;
        } else if crate::cognitive_field_runner::recover_incomplete_seal_checkpoint(
            config_path,
            &checkpoint,
        )? {
            runtime_store
                .remove_seal_staging(checkpoint.seal_attempt_id)
                .await?;
        }
    }
    Ok(())
}

fn recover_authority(
    config_path: &Path,
    recovered_checkpoints: &[eliot_types::OperationRuntimeCheckpoint],
) -> Result<()> {
    let root = crate::delegation_runtime::root_from_config(config_path);
    let mut broker = crate::delegation_runtime::load_state(&root)?;
    let before = serde_json::to_vec(&broker)?;
    HostBrokerService.expire_authority(&mut broker, OffsetDateTime::now_utc());
    let session_state = broker
        .agent_host_sessions
        .iter()
        .map(|session| {
            (
                session.agent_session_id,
                (session.state, session.generation),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut revoke = broker
        .task_role_leases
        .iter()
        .filter(|lease| {
            matches!(
                lease.state,
                AuthorityLeaseState::Active | AuthorityLeaseState::Pending
            ) && session_state
                .get(&lease.agent_session_id)
                .is_none_or(|(state, generation)| {
                    *state != AgentSessionState::Active || *generation != lease.generation
                })
        })
        .map(|lease| {
            (
                lease.role_lease_id.clone(),
                lease.epoch,
                "startup_orphaned_owner".to_owned(),
            )
        })
        .collect::<Vec<_>>();
    let operation_bound_leaks = broker
        .task_role_leases
        .iter()
        .filter(|lease| {
            matches!(
                lease.state,
                AuthorityLeaseState::Active | AuthorityLeaseState::Pending
            ) && lease.lifetime == AuthorityLeaseLifetime::OperationBound
                && authority_owner_issue(&broker, lease).is_some()
        })
        .map(|lease| {
            (
                lease.role_lease_id.clone(),
                lease.epoch,
                lease.agent_session_id,
            )
        })
        .collect::<Vec<_>>();
    for (role_lease_id, epoch, session_id) in operation_bound_leaks {
        revoke.push((
            role_lease_id,
            epoch,
            "startup_operation_bound_owner_not_live".to_owned(),
        ));
        let _ = HostBrokerService.retire_session(
            &mut broker,
            session_id,
            "startup_operation_bound_owner_not_live",
        );
    }
    for checkpoint in recovered_checkpoints {
        if let (Some(role_lease_id), Some(role_lease_epoch)) =
            (&checkpoint.role_lease_id, checkpoint.role_lease_epoch)
        {
            revoke.push((
                role_lease_id.clone(),
                role_lease_epoch,
                "startup_recovered_operation".to_owned(),
            ));
        }
    }
    revoke.sort();
    revoke.dedup();
    for (role_lease_id, epoch, reason) in revoke {
        let _ = HostBrokerService.revoke_role(&mut broker, &role_lease_id, epoch, &reason, None);
    }
    if serde_json::to_vec(&broker)? != before {
        crate::delegation_runtime::save_host_broker_state(&root, &broker)?;
    }
    Ok(())
}

async fn adapter_health(
    runtime_store: &OperationRuntimeHandle,
    checkpoints: &[eliot_types::OperationRuntimeCheckpoint],
    broker: &eliot_types::DelegationState,
) -> Result<Vec<RuntimeAdapterHealth>> {
    let mut reports = Vec::new();
    for adapter_id in EXTERNAL_ADAPTER_IDS {
        let host_id = match adapter_id {
            "external-agent:claude" => AgentHostId::Claude,
            "external-agent:antigravity" => AgentHostId::Antigravity,
            "external-agent:opencode" => AgentHostId::OpenCode,
            _ => unreachable!("bounded external adapter inventory"),
        };
        let window = runtime_store.load_restart_window(adapter_id).await?;
        let active_operations = checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.adapter_id.as_deref() == Some(adapter_id))
            .count();
        let installed = broker
            .agent_host_sessions
            .iter()
            .any(|session| session.host_identity.host_id == host_id);
        let authenticated = broker.agent_host_sessions.iter().any(|session| {
            session.host_identity.host_id == host_id && session.state == AgentSessionState::Active
        });
        let circuit_ready = window
            .as_ref()
            .is_none_or(|window| window.circuit_state != AdapterCircuitState::Open);
        reports.push(RuntimeAdapterHealth {
            adapter_id: adapter_id.to_owned(),
            installed,
            authenticated,
            ready: installed && authenticated && circuit_ready,
            circuit_state: window
                .as_ref()
                .map_or(AdapterCircuitState::Closed, |window| window.circuit_state),
            active_operations: usize_to_u32(active_operations),
            queued_operations: 0,
            restart_count_window: window
                .as_ref()
                .map_or(0, |window| usize_to_u32(window.restart_timestamps.len())),
            last_success_at: window
                .as_ref()
                .and_then(|window| window.last_success_at.clone()),
            last_failure_at: window
                .as_ref()
                .and_then(|window| window.last_failure_at.clone()),
            last_failure_class: window
                .as_ref()
                .and_then(|window| window.last_failure_class.clone()),
            last_terminal_operation_ref: window
                .and_then(|window| window.last_terminal_operation_ref),
        });
    }
    Ok(reports)
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded read-only seal inventory scan keeps one fail-closed classification pass"
)]
fn scan_seal_inventory(
    config_path: &Path,
    broker: &eliot_types::DelegationState,
) -> Result<SealInventory> {
    let Some(root) = cognitive_root(config_path) else {
        return Ok(SealInventory::default());
    };
    if !root.is_dir() {
        return Ok(SealInventory::default());
    }
    let mut inventory = SealInventory::default();
    let files = bounded_seal_files(&root, 20_000, 100_000, 20_000)?;
    let mut published_ids = BTreeSet::new();
    for path in files {
        let parent_name = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str());
        let is_json = path
            .extension()
            .is_some_and(|extension| extension == "json");
        if parent_name == Some("abandoned-seals") && is_json {
            inventory.quarantine_records = inventory.quarantine_records.saturating_add(1);
            continue;
        }
        if parent_name != Some("seal-records") {
            continue;
        }
        if !is_json {
            continue;
        }
        let value = match std::fs::read(&path)
            .with_context(|| format!("read seal record {}", path.display()))
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).map_err(Into::into))
        {
            Ok(value) => value,
            Err(error) => {
                inventory
                    .errors
                    .push(format!("seal_record_unreadable:{error}"));
                continue;
            }
        };
        let seal_attempt_id = value
            .get("seal_attempt_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let generation = value
            .get("generation")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let state = value
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if matches!(state, "validating" | "staged" | "activated") {
            inventory.partial_ids.insert(seal_attempt_id.clone());
        }
        if state == "published" {
            published_ids.insert(seal_attempt_id.clone());
            let published_root = value
                .get("published_root")
                .and_then(Value::as_str)
                .map(PathBuf::from);
            let provider_plan_sha256 = value
                .get("provider_plan_sha256")
                .and_then(Value::as_str)
                .filter(|sha256| !sha256.is_empty());
            let plan_current = published_root
                .as_ref()
                .zip(provider_plan_sha256)
                .is_some_and(|(root, expected_sha256)| {
                    sha256_file(&root.join("candidate-provider-plan.json"))
                        .is_ok_and(|actual_sha256| actual_sha256 == expected_sha256)
                });
            let lease_ids = value
                .get("role_lease_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            let authority_current = !lease_ids.is_empty()
                && lease_ids.iter().all(|lease_id| {
                    broker.task_role_leases.iter().any(|lease| {
                        lease.role_lease_id == *lease_id
                            && lease.state == AuthorityLeaseState::Active
                            && lease.generation == generation
                    })
                });
            if !plan_current || !authority_current {
                inventory.published_without_authority =
                    inventory.published_without_authority.saturating_add(1);
            }
        }
    }
    inventory.authority_without_published = usize_to_u32(
        broker
            .task_role_leases
            .iter()
            .filter(|lease| {
                matches!(
                    lease.state,
                    AuthorityLeaseState::Active | AuthorityLeaseState::Pending
                ) && lease
                    .seal_attempt_id
                    .as_ref()
                    .is_some_and(|seal_attempt_id| !published_ids.contains(seal_attempt_id))
            })
            .count(),
    );
    Ok(inventory)
}

fn bounded_seal_files(
    root: &Path,
    directory_limit: usize,
    entry_limit: usize,
    relevant_file_limit: usize,
) -> Result<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut directories = 0_usize;
    let mut entries_seen = 0_usize;
    while let Some(directory) = pending.pop() {
        directories = directories.saturating_add(1);
        if directories > directory_limit {
            bail!(
                "runtime integrity scan exceeded bounded directory limit {directory_limit} under {}",
                root.display()
            );
        }
        let mut entries = std::fs::read_dir(&directory)
            .with_context(|| format!("scan runtime integrity directory {}", directory.display()))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        entries_seen = entries_seen.saturating_add(entries.len());
        if entries_seen > entry_limit {
            bail!(
                "runtime integrity scan exceeded bounded entry limit {entry_limit} under {}",
                root.display()
            );
        }
        entries.sort();
        let relevant_directory = directory
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| matches!(name, "seal-records" | "abandoned-seals"));
        for path in entries {
            if path.is_dir() {
                pending.push(path);
            } else if relevant_directory
                && path
                    .extension()
                    .is_some_and(|extension| extension == "json")
            {
                files.push(path);
                if files.len() > relevant_file_limit {
                    bail!(
                        "runtime integrity scan exceeded bounded relevant-file limit {relevant_file_limit} under {}",
                        root.display()
                    );
                }
            }
        }
    }
    Ok(files)
}

fn cognitive_root(config_path: &Path) -> Option<PathBuf> {
    let runtime_root = crate::delegation_runtime::root_from_config(config_path);
    let colocated = runtime_root.join("cognitive-field");
    if colocated.is_dir() {
        return Some(colocated);
    }
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|root| root.join("Eliot/cognitive-field"))
}

fn byte_stream_state(bytes: u64, terminal: bool) -> String {
    if terminal {
        "terminal".to_owned()
    } else if bytes > 0 {
        "progressing".to_owned()
    } else {
        "open".to_owned()
    }
}

fn usize_to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        authority_owner_issue, bounded_seal_files, inspect, reconcile_dry_run, scan_seal_inventory,
        sha256_file,
    };
    use eliot_engine::{WriterActor, WriterConfig};
    use eliot_store::{CanonicalStore, ControlWal};
    use eliot_types::{
        AdapterCircuitState, AgentHostId, AgentRole, AgentSessionId, AuthorityLeaseLifetime,
        AuthorityLeaseState, ControlWalConfig, DelegationState, GovernorConfig, OperationJob,
        OperationJobState, OperationPhase, OperationRestartWindow, RuntimeOverallStatus, TaskId,
        TaskRoleLease,
    };
    use std::fs;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[test]
    fn operation_bound_runtime_integrity_requires_one_live_exact_owner() {
        let mut broker = DelegationState::default();
        let now = OffsetDateTime::now_utc();
        let task_id = TaskId::new_v7();
        let session_id = AgentSessionId::new_v7();
        let lease = TaskRoleLease {
            role_lease_id: "operation-role-lease:integrity".to_owned(),
            task_id,
            agent_session_id: session_id,
            role: AgentRole::Auditor,
            capability_scope: vec!["emit_candidate_observation".to_owned()],
            expires_at: now + time::Duration::minutes(5),
            epoch: 3,
            state: AuthorityLeaseState::Active,
            lifetime: AuthorityLeaseLifetime::OperationBound,
            owner_operation_id: Some("operation:integrity".to_owned()),
            seal_attempt_id: None,
            generation: 4,
            issued_at: Some(now),
            activated_at: Some(now),
            consumed_at: None,
            revoked_at: None,
            revoke_reason: None,
            superseded_by_epoch: None,
        };
        broker.task_role_leases.push(lease.clone());
        broker.operation_jobs.push(OperationJob {
            job_id: "operation:integrity".to_owned(),
            invocation_id: "operation:integrity".to_owned(),
            host_id: AgentHostId::Claude,
            state: OperationJobState::Running,
            attempt: 1,
            resume_session_id: None,
            result_ref: None,
            idempotency_key: "operation:integrity".to_owned(),
            created_at: now,
            updated_at: now,
            generation: 4,
            phase: OperationPhase::Running,
            phase_started_at: Some(now),
            last_progress_at: Some(now),
            phase_deadline_at: Some(lease.expires_at),
            absolute_deadline_at: Some(lease.expires_at),
            restart_count: 0,
            runtime_contract_sha256: Some("c".repeat(64)),
            role_lease_id: Some(lease.role_lease_id.clone()),
            role_lease_epoch: Some(lease.epoch),
        });
        assert_eq!(authority_owner_issue(&broker, &lease), None);
        broker.operation_jobs[0].state = OperationJobState::Completed;
        assert_eq!(
            authority_owner_issue(&broker, &lease),
            Some("operation_bound_authority_has_no_live_exact_owner")
        );
    }

    #[test]
    fn seal_scan_bounds_relevant_records_without_counting_historical_artifacts()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("eliot-seal-scan-{}", Uuid::new_v4()));
        let history = root.join("run/history");
        let seals = root.join("run/seal-records");
        fs::create_dir_all(&history)?;
        fs::create_dir_all(&seals)?;
        for index in 0..4 {
            fs::write(history.join(format!("artifact-{index}.json")), b"{}")?;
        }
        let seal = seals.join("seal.json");
        fs::write(&seal, b"{}")?;

        let files = bounded_seal_files(&root, 8, 16, 1)?;
        assert_eq!(files, [seal]);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn seal_inventory_binds_published_candidate_plan_and_exact_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("eliot-seal-integrity-{}", Uuid::new_v4()));
        let config_path = root.join("config/governor.toml");
        let seal_records = root.join("cognitive-field/run/seal-records");
        let published_root = root.join("cognitive-field/run/sealed/3");
        fs::create_dir_all(&seal_records)?;
        fs::create_dir_all(&published_root)?;
        let candidate_plan = published_root.join("candidate-provider-plan.json");
        fs::write(&candidate_plan, b"{\"plan_hash\":\"test-plan\"}\n")?;

        let now = OffsetDateTime::now_utc();
        let lease = TaskRoleLease {
            role_lease_id: "role-lease:published-plan".to_owned(),
            task_id: TaskId::new_v7(),
            agent_session_id: AgentSessionId::new_v7(),
            role: AgentRole::Implementer,
            capability_scope: vec!["candidate_only".to_owned()],
            expires_at: now + time::Duration::minutes(5),
            epoch: 1,
            state: AuthorityLeaseState::Active,
            lifetime: AuthorityLeaseLifetime::SealBound,
            owner_operation_id: None,
            seal_attempt_id: Some("provider-plan-seal:test-g3".to_owned()),
            generation: 3,
            issued_at: Some(now),
            activated_at: Some(now),
            consumed_at: None,
            revoked_at: None,
            revoke_reason: None,
            superseded_by_epoch: None,
        };
        let broker = DelegationState {
            task_role_leases: vec![lease],
            ..DelegationState::default()
        };
        let seal = serde_json::json!({
            "seal_attempt_id": "provider-plan-seal:test-g3",
            "generation": 3,
            "state": "published",
            "published_root": published_root,
            "provider_plan_sha256": sha256_file(&candidate_plan)?,
            "role_lease_ids": ["role-lease:published-plan"],
        });
        fs::write(
            seal_records.join("provider-plan-seal_test-g3.json"),
            serde_json::to_vec_pretty(&seal)?,
        )?;

        let inventory = scan_seal_inventory(&config_path, &broker)?;
        assert_eq!(inventory.published_without_authority, 0);
        assert_eq!(inventory.authority_without_published, 0);

        fs::write(&candidate_plan, b"{\"plan_hash\":\"tampered\"}\n")?;
        let tampered = scan_seal_inventory(&config_path, &broker)?;
        assert_eq!(tampered.published_without_authority, 1);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn runtime_integrity_reports_core_ready_orphan_authority_as_integrity_failed()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("eliot-runtime-integrity-{}", Uuid::new_v4()));
        let config_path = root.join("config/governor.toml");
        fs::create_dir_all(
            config_path
                .parent()
                .ok_or_else(|| std::io::Error::other("config path has no parent"))?,
        )?;
        fs::create_dir_all(root.join("cognitive-field"))?;
        let mut broker = DelegationState::default();
        let now = OffsetDateTime::now_utc();
        broker.task_role_leases.push(TaskRoleLease {
            role_lease_id: "orphan-role-lease".to_owned(),
            task_id: TaskId::new_v7(),
            agent_session_id: AgentSessionId::new_v7(),
            role: AgentRole::Implementer,
            capability_scope: vec!["candidate_only".to_owned()],
            expires_at: now + time::Duration::minutes(5),
            epoch: 1,
            state: AuthorityLeaseState::Active,
            lifetime: eliot_types::AuthorityLeaseLifetime::OperationBound,
            owner_operation_id: Some("missing-owner".to_owned()),
            seal_attempt_id: None,
            generation: 1,
            issued_at: Some(now),
            activated_at: Some(now),
            consumed_at: None,
            revoked_at: None,
            revoke_reason: None,
            superseded_by_epoch: None,
        });
        crate::delegation_runtime::save_host_broker_state(&root, &broker)?;
        let wal = ControlWal::open(&ControlWalConfig {
            path: root.join("control.redb").display().to_string(),
        })?;
        let store = CanonicalStore::new(GovernorConfig::default().db.surreal);
        let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
        let runtime = writer.operation_runtime();
        let actor_task = tokio::spawn(actor.run());

        let report = inspect(&config_path, &runtime, true, None).await?;
        assert_eq!(report.overall, RuntimeOverallStatus::IntegrityFailed);
        assert!(!report.provider_dispatch_safe);
        assert_eq!(report.authority_integrity.orphaned_role_leases, 1);

        drop(runtime);
        drop(writer);
        actor_task.await?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn reconcile_dry_run_reports_open_external_adapter_circuit_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("eliot-runtime-reconcile-{}", Uuid::new_v4()));
        let config_path = root.join("config/governor.toml");
        fs::create_dir_all(
            config_path
                .parent()
                .ok_or_else(|| std::io::Error::other("config path has no parent"))?,
        )?;
        crate::delegation_runtime::save_host_broker_state(&root, &DelegationState::default())?;
        let wal = ControlWal::open(&ControlWalConfig {
            path: root.join("control.redb").display().to_string(),
        })?;
        let store = CanonicalStore::new(GovernorConfig::default().db.surreal);
        let (writer, actor) = WriterActor::channel(wal, store, &WriterConfig::default());
        let runtime = writer.operation_runtime();
        let actor_task = tokio::spawn(actor.run());
        let now = OffsetDateTime::now_utc();
        runtime
            .put_restart_window(OperationRestartWindow {
                schema_version: "eliot-operation-restart-window-v1".to_owned(),
                key: "external-agent:claude".to_owned(),
                restart_timestamps: vec![now.to_string()],
                circuit_state: AdapterCircuitState::Open,
                consecutive_failures: 2,
                last_success_at: None,
                last_failure_at: Some(now.to_string()),
                last_failure_class: Some("pre_dispatch".to_owned()),
                last_terminal_operation_ref: Some("operation:fixture".to_owned()),
                updated_at: now.to_string(),
            })
            .await?;

        let dry_run = reconcile_dry_run(&config_path, &runtime).await?;
        assert_eq!(dry_run.provider_calls, 0);
        assert_eq!(dry_run.writes, 0);
        assert!(dry_run.decisions.iter().any(|decision| {
            decision.operation_id == "external-agent:claude"
                && decision.decision == "half_open_static_adapter_probe"
                && !decision.mutates
        }));
        assert_eq!(
            runtime
                .load_restart_window("external-agent:claude")
                .await?
                .map(|window| window.circuit_state),
            Some(AdapterCircuitState::Open)
        );

        drop(runtime);
        drop(writer);
        actor_task.await?;
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
