use crate::runtime_instance::{
    RuntimeInstance, RuntimePublicationState, atomic_write_json, sha256_file,
};
use anyhow::{Context, Result, bail};
use eliot_engine::{HostBrokerService, OperationRuntimeHandle};
use eliot_types::{
    AdapterCircuitState, AgentHostId, AgentSessionState, AuthorityLeaseState,
    OperationCancellationState, OperationReconciliationState,
    RUNTIME_INTEGRITY_REPORT_SCHEMA_VERSION, RuntimeAdapterHealth, RuntimeAuthorityIntegrity,
    RuntimeCoreHealth, RuntimeIntegrityHealth, RuntimeOperationDetail, RuntimeOperationHealth,
    RuntimeOverallStatus, RuntimeReconcileDecision, RuntimeReconcileDryRun,
    RuntimeSupervisionReport, SealStagingState,
};
use serde_json::Value;
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
        .count();
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
                .count(),
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
            ) && session_by_id
                .get(&lease.agent_session_id)
                .is_none_or(|session| {
                    session.state != AgentSessionState::Active
                        || session.generation != lease.generation
                })
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
        ) && broker
            .agent_host_sessions
            .iter()
            .find(|session| session.agent_session_id == lease.agent_session_id)
            .is_none_or(|session| session.state != AgentSessionState::Active)
        {
            decisions.push(RuntimeReconcileDecision {
                operation_id: lease.role_lease_id.clone(),
                generation: lease.generation,
                decision: "revoke_orphaned_role_lease".to_owned(),
                mutates: false,
                reason: "no_active_owner_session".to_owned(),
            });
        }
    }
    decisions.sort_by(|left, right| {
        left.operation_id
            .cmp(&right.operation_id)
            .then(left.generation.cmp(&right.generation))
    });
    Ok(RuntimeReconcileDryRun {
        schema_version: "eliot-runtime-reconcile-dry-run-v1".to_owned(),
        generated_at: now.to_string(),
        dry_run: true,
        decisions,
        provider_calls: 0,
        writes: 0,
    })
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
    if !report.provider_dispatch_safe {
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
            last_success_at: None,
            last_failure_at: window.as_ref().map(|window| window.updated_at.clone()),
            last_failure_class: window.and_then(|window| window.last_failure_class),
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
    let files = bounded_files(&root, 20_000)?;
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
            let plan_present = published_root
                .as_ref()
                .is_some_and(|root| root.join("provider-plan.json").is_file());
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
            if !plan_present || !authority_current {
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

fn bounded_files(root: &Path, limit: usize) -> Result<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut entries = std::fs::read_dir(&directory)
            .with_context(|| format!("scan runtime integrity directory {}", directory.display()))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort();
        for path in entries {
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
                if files.len() > limit {
                    bail!(
                        "runtime integrity scan exceeded bounded file limit {limit} under {}",
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
    use super::inspect;
    use eliot_engine::{WriterActor, WriterConfig};
    use eliot_store::{CanonicalStore, ControlWal};
    use eliot_types::{
        AgentRole, AgentSessionId, AuthorityLeaseState, ControlWalConfig, DelegationState,
        GovernorConfig, RuntimeOverallStatus, TaskId, TaskRoleLease,
    };
    use std::fs;
    use time::OffsetDateTime;
    use uuid::Uuid;

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
}
