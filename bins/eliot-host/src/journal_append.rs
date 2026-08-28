mod readiness_append;
#[cfg(windows)]
pub(super) use readiness_append::append_authenticated_kernel_readiness;

use super::{HostError, fresh_identity, operation, record_fence, sha256_json};
use eliot_host_state::{
    ActivationState, AppendReceipt, CleanMarker, EliotActivationRecord, EpochIdentity,
    EpochTransition, HostInstallationEpoch, HostKernelStoreLineage, HostState,
    HostStateJournalService, HostStateRecord, JOURNAL_VERSION, JournalBackend, JournalError,
    JournalManifest, KernelJobBinding, KernelRecord, LifecycleTimestamps, PriorKernelDisposition,
    PriorKernelSource, ReadinessEvidence, ReconcileOutcome,
};
#[cfg(windows)]
use eliot_host_state::{StoreRebindRecord, StoreRebindState};
#[cfg(windows)]
use eliot_kernel_service::StoreRebindReceipt;
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::{
    HealthDimension, HealthVector, ServiceProcessRecord, ServiceProcessState,
};

/// Checks every identity that the authoritative Job termination observation
/// can be compared against in the durable Kernel binding.
///
/// The Job API gives us the terminated root process identity, image and Job
/// name.  The durable process record supplies the authority binding that
/// admitted that root: owner, exact PID/start handle and a non-zero authority
/// epoch.  A match on only a non-zero PID (or only the image) would permit a
/// substituted child to be recorded as the previous Kernel.
pub(super) fn exact_termination_binding_matches(
    job: &KernelJobBinding,
    expected_process: &ServiceProcessRecord,
    observed_process_id: u32,
    observed_start_time_100ns: u64,
    observed_image_path: &str,
    observed_job_name: &str,
) -> bool {
    observed_process_id == job.root_pid
        && observed_start_time_100ns == job.root_start_time_100ns
        && observed_image_path == job.root_image_path.as_str()
        && observed_job_name == job.job_name.as_str()
        && expected_process.owner == job.owner.as_str()
        && expected_process.process_id
            == format!("pid:{}:start:{}", job.root_pid, job.root_start_time_100ns)
        && expected_process.authority_epoch.value() != 0
}

pub(super) fn terminated_prior_kernel(
    prior: &KernelRecord,
    terminated: &eliot_platform_windows::TerminatedJobChild,
) -> Result<PriorKernelDisposition, HostError> {
    let job = prior.candidate_job_binding.clone().ok_or_else(|| {
        HostError::OwnerLeaseRecovery("prior Kernel Job binding is absent".to_owned())
    })?;
    let expected_process = prior.process.clone().ok_or_else(|| {
        HostError::OwnerLeaseRecovery("prior Kernel process binding is absent".to_owned())
    })?;
    if !exact_termination_binding_matches(
        &job,
        &expected_process,
        terminated.process().process_id,
        terminated.process().start_time_100ns,
        &terminated.process().image_path,
        terminated.job_identity().name(),
    ) || !terminated.history().complete()
        || !terminated.job_empty()
        || !terminated.root_reaped()
    {
        return Err(HostError::RecoveryRequired(
            "Terminated Kernel evidence does not match exact durable prior binding".to_owned(),
        ));
    }
    let mut process = expected_process;
    process.state = ServiceProcessState::Stopped;
    process.health = HealthVector {
        liveness: HealthDimension::Unknown,
        readiness: HealthDimension::Unknown,
        freshness: HealthDimension::Unknown,
        compatibility: HealthDimension::Unknown,
        integrity: HealthDimension::Unknown,
        capacity: HealthDimension::Unknown,
    };
    Ok(PriorKernelDisposition::Terminated(PriorKernelSource {
        host: prior.fence.host.clone(),
        activation_identity: prior.activation_identity.clone(),
        generation: prior.kernel_generation.clone(),
        job,
        process,
        history_complete: terminated.history().complete(),
        job_empty: terminated.job_empty(),
        root_reaped: terminated.root_reaped(),
    }))
}

pub(super) fn initial_activation_record(
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
    state: ActivationState,
    label: &str,
) -> Result<EliotActivationRecord, HostError> {
    let ready = matches!(
        state,
        ActivationState::ControlReady | ActivationState::Active
    );
    let drain_generation = matches!(
        state,
        ActivationState::Draining | ActivationState::StoppedClean
    )
    .then(|| activation_generation.clone());
    Ok(EliotActivationRecord {
        fence: record_fence(host, activation_id, activation_generation),
        operation: operation(label)?,
        activation_id: activation_id.clone(),
        trigger_class: PlatformHandle::new("host-runtime-lifecycle")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        trigger_evidence: vec![
            PlatformHandle::new("host-owner-lease-held")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
        requester_principal_session_or_scheduler: PlatformHandle::new("host-composition")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        requested_capabilities: vec![
            PlatformHandle::new("runtime-supervision")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
        candidate_scope: host.installation.clone(),
        state,
        drain_generation,
        lineage: HostKernelStoreLineage {
            host_epoch: host.epoch.current.clone(),
            kernel_epoch: EpochIdentity {
                lineage: fresh_identity("kernel-lineage")?,
                sequence: 1,
            },
            watchdog_epoch: EpochIdentity {
                lineage: fresh_identity("watchdog-lineage")?,
                sequence: 1,
            },
            store_generation: EpochIdentity {
                lineage: fresh_identity("store-lineage")?,
                sequence: 1,
            },
        },
        readiness: ReadinessEvidence {
            supervision_ready: ready,
            control_ready: ready,
            evidence_refs: vec![
                PlatformHandle::new(if ready {
                    "kernel-ready-receipt-validated"
                } else {
                    "host-lifecycle-not-ready"
                })
                .map_err(|error| HostError::Platform(error.to_string()))?,
            ],
        },
        governance_profile: PlatformHandle::new("runtime-live-v3")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        runtime_lease_refs: Vec::new(),
        supervision_lease_refs: Vec::new(),
        wake_intent_refs: Vec::new(),
        drain_commit_ref: None,
        wake_during_drain_disposition: None,
        boot_session_evidence: vec![
            PlatformHandle::new("host-process-epoch")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
        power_transition_evidence: Vec::new(),
        timestamps: LifecycleTimestamps {
            started_at: (state != ActivationState::Stopped)
                .then(|| fresh_identity("host-started-at"))
                .transpose()?,
            ready_at: ready.then(|| fresh_identity("host-ready-at")).transpose()?,
            draining_at: (state == ActivationState::Draining)
                .then(|| fresh_identity("host-draining-at"))
                .transpose()?,
            stopped_at: (state == ActivationState::StoppedClean)
                .then(|| fresh_identity("host-stopped-at"))
                .transpose()?,
        },
        failure_and_recovery_directive: None,
    })
}

pub(super) fn transition_activation_record(
    current: &EliotActivationRecord,
    state: ActivationState,
    label: &str,
) -> Result<EliotActivationRecord, HostError> {
    let mut next = current.clone();
    next.operation = operation(label)?;
    next.state = state;
    let ready = matches!(
        state,
        ActivationState::ControlReady | ActivationState::Active
    );
    next.readiness.control_ready = ready;
    next.readiness.supervision_ready = ready;
    if ready {
        next.readiness.evidence_refs = vec![
            PlatformHandle::new("kernel-ready-receipt-validated")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ];
        next.timestamps.ready_at = Some(fresh_identity("host-ready-at")?);
    }
    if state == ActivationState::Draining {
        next.drain_generation = Some(next.fence.activation_generation.clone());
        next.timestamps.draining_at = Some(fresh_identity("host-draining-at")?);
    }
    if state == ActivationState::StoppedClean {
        next.timestamps.stopped_at = Some(fresh_identity("host-stopped-at")?);
    }
    Ok(next)
}

pub(super) fn append_reconciled<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    record: HostStateRecord,
) -> Result<AppendReceipt, HostError> {
    match journal.append(record.clone()) {
        Ok(receipt) => Ok(receipt),
        Err(JournalError::OutcomeUnknown { transaction_id }) => {
            match journal.reconcile(&transaction_id)? {
                ReconcileOutcome::Committed => journal.append(record).map_err(HostError::Journal),
                ReconcileOutcome::NotCommitted | ReconcileOutcome::StillUnknown => {
                    Err(HostError::Journal(JournalError::OutcomeUnknown {
                        transaction_id,
                    }))
                }
            }
        }
        Err(error) => Err(HostError::Journal(error)),
    }
}

#[cfg(windows)]
pub(super) fn append_store_rebind_terminal<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    mut record: StoreRebindRecord,
    state: StoreRebindState,
    receipt: Option<&StoreRebindReceipt>,
) -> Result<(), HostError> {
    if record.state == state && state == StoreRebindState::Unknown {
        return Ok(());
    }
    match state {
        StoreRebindState::Committed => {
            let receipt = receipt.ok_or_else(|| {
                HostError::RecoveryRequired(
                    "committed Store rebind disposition has no receipt".to_owned(),
                )
            })?;
            if receipt.operation_id != record.operation_id
                || receipt.request_digest != record.request_digest.as_str()
                || receipt.requirement_digest != record.requirement.as_str()
                || receipt.candidate_binding_digest != record.candidate_binding_digest.as_str()
                || receipt.store_fence != record.store_fence.as_str()
                || receipt.process_binding.process.process_id != record.process_id
                || receipt.process_binding.process.start_time_100ns
                    != record.process_start_time_100ns
                || receipt.process_binding.process.image_path != record.process_image_path.as_str()
                || receipt.process_binding.job != record.job_name
                || receipt.generation.value() != record.generation
                || receipt.authority_epoch.value() != record.authority_epoch
            {
                return Err(HostError::RecoveryRequired(
                    "Store rebind startup receipt did not match exact journal identity".to_owned(),
                ));
            }
            receipt
                .validate()
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
            record.receipt_request_digest = Some(
                PlatformHandle::new(receipt.request_digest.clone())
                    .map_err(|error| HostError::Platform(error.to_string()))?,
            );
            record.receipt_store_fence = Some(
                PlatformHandle::new(receipt.store_fence.clone())
                    .map_err(|error| HostError::Platform(error.to_string()))?,
            );
        }
        StoreRebindState::Aborted | StoreRebindState::Unknown => {
            record.receipt_request_digest = None;
            record.receipt_store_fence = None;
        }
        StoreRebindState::Pending => {
            return Err(HostError::RecoveryRequired(
                "Store rebind terminal helper received Pending".to_owned(),
            ));
        }
    }
    record.state = state;
    record.operation = operation(&format!(
        "store-rebind:{}:{}",
        record.operation_id.as_str(),
        match state {
            StoreRebindState::Committed => "committed",
            StoreRebindState::Aborted => "aborted",
            StoreRebindState::Unknown => "unknown",
            StoreRebindState::Pending => unreachable!(),
        }
    ))?;
    append_reconciled(journal, HostStateRecord::StoreRebind(record))?;
    Ok(())
}

#[cfg(windows)]
pub(super) fn persist_store_rebind_disposition<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    operation_id: &PlatformHandle,
    request_digest: &str,
    disposition: StoreRebindState,
) -> Result<(), HostError> {
    if !matches!(
        disposition,
        StoreRebindState::Aborted | StoreRebindState::Unknown
    ) {
        return Err(HostError::RecoveryRequired(
            "invalid Store rebind terminal disposition".to_owned(),
        ));
    }
    let record = journal
        .snapshot()?
        .store_rebinds
        .into_iter()
        .find(|record| {
            record.operation_id == *operation_id
                && record.request_digest.as_str() == request_digest
                && matches!(
                    record.state,
                    StoreRebindState::Pending | StoreRebindState::Unknown
                )
        })
        .ok_or_else(|| {
            HostError::RecoveryRequired(
                "Store rebind terminal disposition has no exact pending journal record".to_owned(),
            )
        })?;
    if record.state == StoreRebindState::Unknown && disposition == StoreRebindState::Unknown {
        return Ok(());
    }
    let mut terminal = record;
    terminal.state = disposition;
    terminal.operation = operation(&format!(
        "store-rebind:{}:{}",
        terminal.operation_id.as_str(),
        match disposition {
            StoreRebindState::Aborted => "aborted",
            StoreRebindState::Unknown => "unknown",
            StoreRebindState::Pending | StoreRebindState::Committed => unreachable!(),
        }
    ))?;
    terminal.receipt_request_digest = None;
    terminal.receipt_store_fence = None;
    append_reconciled(journal, HostStateRecord::StoreRebind(terminal))?;
    Ok(())
}

pub(super) fn clean_marker_record(
    snapshot: &HostState,
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> Result<HostStateRecord, HostError> {
    Ok(HostStateRecord::CleanMarker(CleanMarker {
        fence: record_fence(host, activation_id, activation_generation),
        operation: operation("host-clean-marker")?,
        manifest: JournalManifest {
            schema_version: JOURNAL_VERSION,
            last_sequence: snapshot.sequence,
            last_checksum: PlatformHandle::new(
                snapshot.last_checksum.as_deref().unwrap_or("GENESIS"),
            )
            .map_err(|error| HostError::Platform(error.to_string()))?,
        },
        shutdown_evidence_refs: vec![
            PlatformHandle::new("host-owner-release-fenced")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
    }))
}

#[cfg(test)]
pub(super) fn append_clean_marker<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> Result<(), HostError> {
    let snapshot = journal.snapshot()?;
    append_reconciled(
        journal,
        clean_marker_record(&snapshot, host, activation_id, activation_generation)?,
    )?;
    Ok(())
}

/// Digest of the immutable installer identity that a fresh Host journal
/// activation must carry before it can be reconciled.  The journal does not
/// become an authority source: this binding is written into the new
/// Starting/ControlReady contour after a crash and never turns historical
/// Active evidence into live process proof.
pub(super) fn pending_activation_binding(
    pending: &eliot_installation::PendingActivation,
) -> Result<PlatformHandle, HostError> {
    let digest = sha256_json(&(
        "pending-activation-binding-v2",
        &pending.transaction_id,
        &pending.plan_digest,
        &pending.manifest.generation,
        &pending.config_digest,
        &pending.kernel_artifact_digest,
        &pending.store_bridge_artifact_digest,
        &pending.canonical_store_artifact_digest,
        &pending.host_executable_path,
        &pending.host_artifact_digest,
        &pending.runtime_state_roots_digest,
        &pending.manifest_digest,
        pending
            .phase_b_prepared
            .as_ref()
            .map(|prepared| &prepared.prepared_digest),
    ))?;
    PlatformHandle::new(format!("pending-activation-binding:{digest}"))
        .map_err(|error| HostError::Platform(error.to_string()))
}
