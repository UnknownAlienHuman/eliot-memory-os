mod readiness_append;
#[cfg(windows)]
pub(super) use readiness_append::{
    append_authenticated_kernel_readiness, append_authenticated_kernel_readiness_with_heartbeat,
};

use super::{HostError, fresh_identity, fresh_lineage_id, operation, record_fence, sha256_json};
use eliot_host_state::{
    ActivationState, AppendReceipt, CleanMarker, DrainCommitRecord, DrainRecord, DrainState,
    EliotActivationRecord, EpochTransition, FailureRecoveryDirective, HostInstallationEpoch,
    HostKernelStoreLineage, HostState, HostStateJournalService, HostStateRecord, JOURNAL_VERSION,
    JournalBackend, JournalError, JournalManifest, KernelJobBinding,
    KernelReadinessObservationRecord, KernelRecord, LifecycleTimestamps, PriorKernelDisposition,
    PriorKernelSource, ReadinessEvidence, ReconcileOutcome, WakeDisposition, record_checksum,
};
#[cfg(windows)]
use eliot_host_state::{StoreRebindRecord, StoreRebindState};
#[cfg(windows)]
use eliot_kernel_service::StoreRebindReceipt;
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::{
    HealthDimension, HealthVector, ServiceProcessRecord, ServiceProcessState,
};

// F-LOG-HOST-6 (#981) journal-append observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never records,
// receipts, digests, or arbitrary error text — so bounding limits size, not
// sensitivity (I15.4). Requested append, durable observed append, and
// unknown outcome stay distinct (I14.21): possible loss is never promoted
// into a receipt. These primitives own no terminal: a single terminal per
// failed journal operation is enforced by the outermost owner boundary in
// `lib.rs` (#891) or Host composition (#893), while these phases correlate
// by stage order only. Sink outcome never alters result/order/cleanup.
fn host_journal_observe(detail: &str) {
    let _ = crate::windows_event_log::event_log_sink_status();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

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

/// I1.9 A1 gate: permits a Host-managed Kernel restart only when the valid
/// journal `Kernel` record carries this relaunch's approved artifact and
/// full process lineage for that approval, the journal itself binds the
/// approved config to that exact record, the relaunch config is the approved
/// config, and the record is owned by the current activation fence.
///
/// The record is the original journal recording: it is revalidated with the
/// existing [`KernelRecord::validate`], never replaced by a freshly
/// recomputed checksum over a held copy. The approved artifact bound here is
/// the exact digest the relaunch is about to start; the required lineage is
/// the record's own generation/Job/process binding (`kernel_generation`,
/// `candidate_job_binding`, `process`), which must be present in that same
/// record.
///
/// The approved CONFIG is bound through the journal's own record-bound
/// approval, not through two live values. I1.9 requires the journal to hold
/// "approved artifact/config hashes"; the record that carries the approved
/// config for one exact Kernel record is
/// [`KernelReadinessObservationRecord`], whose `config_digest` is admitted
/// only together with the `active_kernel_record_checksum` of the record that
/// was active when the observation was appended. This gate therefore joins
/// the retained observations to the retained record with the same
/// record-checksum-to-config join the Watchdog lease load already performs:
/// the authorizing record's journal checksum is recomputed from the journal's
/// own record, and the ORIGINAL recorded observation — never a copy of it — is
/// admitted through [`KernelReadinessObservationRecord::validate_against`],
/// which runs that record's own `validate()` and refuses an observation that
/// is not bound to this exact record, fence, Job root and authority epoch.
/// An observation bound to a superseded record, a missing observation, an
/// observation naming a different approved config, or a valid but unrelated
/// current manifest therefore refuses the restart instead of authorizing it.
///
/// The remaining config leg joins the relaunch descriptor to the approved
/// Phase-B config: `materialized_config_digest` (the Phase-B config the
/// relaunch will actually start) must equal `approved_config` (the Phase-B
/// digest the committed activation fence binds to the active manifest),
/// mirroring the Store leg's `approved_config_hash` requirement digest bind.
/// Both config legs therefore read the Phase-B live domain — never the
/// manifest's Phase-A staged-file digest — so the gate stays satisfiable on
/// a normally materialised contour and still refuses live drift. The fence
/// bind requires the record's
/// `RecordFence` to equal the fence recomputed from the current Host
/// installation epoch, activation id and activation generation, so a
/// stale-activation record cannot authorize a restart. Absence, invalidity, an
/// artifact or config mismatch, missing lineage, or a foreign fence refuses
/// the restart as manual recovery instead of reconstructing or approximating
/// state from a live PID or a directory listing.
#[allow(
    clippy::too_many_arguments,
    reason = "the restart join keeps retained approval, record-bound config approval, relaunch descriptor and owner fence explicit so no binding is inferred"
)]
pub(super) fn require_journal_kernel_restart_record(
    current: &KernelRecord,
    readiness_observations: &[KernelReadinessObservationRecord],
    kernel_artifact: &PlatformHandle,
    approved_config: &PlatformHandle,
    materialized_config_digest: &PlatformHandle,
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> Result<(), HostError> {
    current.validate().map_err(|error| {
        HostError::RecoveryRequired(format!(
            "Kernel restart refused: durable Kernel record is invalid ({error}); manual recovery required"
        ))
    })?;
    if current.approved_artifact_hash != *kernel_artifact {
        return Err(HostError::RecoveryRequired(
            "Kernel restart refused: durable Kernel record does not bind the approved relaunch artifact; manual recovery required"
                .to_owned(),
        ));
    }
    if current.candidate_job_binding.is_none() || current.process.is_none() {
        return Err(HostError::RecoveryRequired(
            "Kernel restart refused: durable Kernel record carries no PID/Job lineage for the approved artifact; manual recovery required"
                .to_owned(),
        ));
    }
    if !journal_record_binds_approved_config(current, readiness_observations, approved_config) {
        return Err(HostError::RecoveryRequired(
            "Kernel restart refused: no valid HostStateJournal record binds the approved config to the authorizing Kernel record; manual recovery required"
                .to_owned(),
        ));
    }
    if *approved_config != *materialized_config_digest {
        return Err(HostError::RecoveryRequired(
            "Kernel restart refused: relaunch config is not the approved config; manual recovery required"
                .to_owned(),
        ));
    }
    if current.fence != record_fence(host, activation_id, activation_generation) {
        return Err(HostError::RecoveryRequired(
            "Kernel restart refused: durable Kernel record is not owned by the current activation fence; manual recovery required"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Reports whether the retained journal state binds `approved_config` to
/// `current` as one record-bound approval pair.
///
/// `approved_config` is stated in the Phase-B live domain: the retained
/// observation carries the Phase-B digest admitted at readiness, so the
/// caller resolves the manifest's approval into that domain before calling.
///
/// The binding is proved by the journal's own owner: the authorizing record's
/// journal checksum is recomputed from the record the journal itself retained,
/// and every retained observation is admitted through the existing
/// [`KernelReadinessObservationRecord::validate_against`], which revalidates
/// the ORIGINAL recorded observation and refuses any observation whose
/// recorded `active_kernel_record_checksum`, fence, Job root, process or
/// authority epoch is not this exact record's. A record without such an
/// observation, and an observation that approves a different config, are both
/// unbound — no checksum is recomputed over a held copy of the observation and
/// no approval is inferred from a manifest, a live process or a directory.
fn journal_record_binds_approved_config(
    current: &KernelRecord,
    readiness_observations: &[KernelReadinessObservationRecord],
    approved_config: &PlatformHandle,
) -> bool {
    let Ok(authorizing_checksum) = record_checksum(&HostStateRecord::Kernel(current.clone()))
    else {
        return false;
    };
    readiness_observations.iter().any(|observation| {
        observation
            .validate_against(current, &authorizing_checksum)
            .is_ok()
            && observation.config_digest == *approved_config
    })
}

/// The proven ingress one fresh activation generation is created for.
///
/// I1.5 requires the durable `EliotActivationRecord` to carry the real
/// `trigger_class`, `requester` and `requested_capabilities` of the request
/// that started the contour. The creation append is the only place those fields
/// may be established: `activation_transition` admits no same-state update, so
/// every later value is inherited from the generation's creation record. Writing
/// a fixed spelling here instead would make every generation claim the same
/// ingress regardless of what actually started it.
pub(super) struct ActivationIngress {
    /// Durable I1.5 `trigger_class` spelling of the starting request.
    pub(super) trigger_class: &'static str,
    /// Durable I1.5 `requester_principal_session_or_scheduler` of that request.
    pub(super) requester: String,
    /// Capability requirement the starting request admitted, spelled by the
    /// `ActivationTriggerClass` vocabulary.
    pub(super) capabilities: &'static [&'static str],
}

pub(super) fn initial_activation_record(
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
    state: ActivationState,
    label: &str,
    ingress: &ActivationIngress,
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
    if ingress.capabilities.is_empty() {
        return Err(HostError::OwnerLeaseRecovery(format!(
            "activation generation {label} has no proven ingress capability requirement"
        )));
    }
    let mut requested_capabilities = Vec::with_capacity(ingress.capabilities.len());
    for capability in ingress.capabilities {
        let handle = PlatformHandle::new(*capability)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        if !requested_capabilities.contains(&handle) {
            requested_capabilities.push(handle);
        }
    }
    Ok(EliotActivationRecord {
        fence: record_fence(host, activation_id, activation_generation),
        operation: operation(label)?,
        activation_id: activation_id.clone(),
        trigger_class: PlatformHandle::new(ingress.trigger_class)
            .map_err(|error| HostError::Platform(error.to_string()))?,
        trigger_evidence: vec![
            PlatformHandle::new("host-owner-lease-held")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
        requester_principal_session_or_scheduler: PlatformHandle::new(&ingress.requester)
            .map_err(|error| HostError::Platform(error.to_string()))?,
        requested_capabilities,
        candidate_scope: host.installation.clone(),
        state,
        drain_generation,
        lineage: HostKernelStoreLineage {
            host_epoch: host.epoch.current.clone(),
            kernel_epoch: EpochTransition::genesis(fresh_lineage_id()?).current,
            watchdog_epoch: EpochTransition::genesis(fresh_lineage_id()?).current,
            store_generation: EpochTransition::genesis(fresh_lineage_id()?).current,
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
        governance_profile: PlatformHandle::new(if ready {
            "runtime-live-v3"
        } else {
            // I1.5 (#1750): a fresh activation has no verified Watchdog
            // branch yet, so it persists the degraded profile instead of
            // claiming independently supervised live governance. The profile
            // turns live only on a proven-ready transition below.
            "runtime-degraded-v3"
        })
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
    if state == ActivationState::Starting {
        // A new explicit activation attempt does not inherit readiness or a
        // recovery directive from the stopped/degraded generation. The new
        // attempt must publish fresh evidence before any live transition.
        // Keep one explicit non-live marker because the durable readiness
        // projection requires a non-empty evidence set even while Starting.
        next.readiness.evidence_refs = vec![
            PlatformHandle::new("host-starting-fresh-readiness-required")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ];
        next.timestamps.ready_at = None;
        next.failure_and_recovery_directive = None;
        next.governance_profile = PlatformHandle::new("runtime-degraded-v3")
            .map_err(|error| HostError::Platform(error.to_string()))?;
    }
    // I1.5 (#1750): governance turns live only on a proven-ready transition.
    // On Windows that transition runs after the Watchdog SCM verification and
    // the ProbeReady watchdog-branch gate; other platforms have no
    // independently-supervised readiness (ProbeReady fails closed, I1.7), so
    // the live profile must never be read as an independent-supervision claim
    // there. Any other transition preserves the current profile instead of
    // rewriting history.
    if ready {
        next.governance_profile = PlatformHandle::new("runtime-live-v3")
            .map_err(|error| HostError::Platform(error.to_string()))?;
    }
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
        // I1.5 W4 release: a clean stop ends the generation's fenced
        // authority, so the generation releases the runtime-lease references
        // it held. The obligations were snapshotted into the
        // `DrainCommitRecord` at linearization
        // (`drain_commit_record_for_stop`); recovery terminals (`Failed`,
        // `DegradedRecovery`) keep their refs because reconciliation is still
        // owed there.
        next.runtime_lease_refs = Vec::new();
    }
    Ok(next)
}

/// Carries the exact fresh readiness evidence into the activation record.
/// The generic transition helper intentionally remains small for historical
/// callers, while a live supervised transition must not erase the heartbeat
/// receipt that authorized it.
pub(super) fn transition_activation_record_with_evidence(
    current: &EliotActivationRecord,
    state: ActivationState,
    label: &str,
    evidence_refs: &[PlatformHandle],
) -> Result<EliotActivationRecord, HostError> {
    let mut next = transition_activation_record(current, state, label)?;
    if matches!(
        state,
        ActivationState::ControlReady | ActivationState::Active
    ) && !evidence_refs.is_empty()
    {
        next.readiness.evidence_refs = evidence_refs.to_vec();
    }
    Ok(next)
}

/// Projects a live contour loss as an explicit recovery state. The caller
/// supplies the bounded failure reference and recovery directive; this helper
/// only records that fact and never invents a Watchdog-specific cause.
pub(super) fn degraded_activation(
    current: &EliotActivationRecord,
    label: &str,
    failure_ref: &PlatformHandle,
    directive: &str,
) -> Result<EliotActivationRecord, HostError> {
    let mut next = transition_activation_record(current, ActivationState::DegradedRecovery, label)?;
    next.governance_profile = PlatformHandle::new("runtime-degraded-v3")
        .map_err(|error| HostError::Platform(error.to_string()))?;
    next.readiness.evidence_refs = vec![failure_ref.clone()];
    next.timestamps.ready_at = None;
    next.failure_and_recovery_directive = Some(FailureRecoveryDirective {
        failure_ref: failure_ref.clone(),
        recovery_owner: PlatformHandle::new("host-composition")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        directive: PlatformHandle::new(directive)
            .map_err(|error| HostError::Platform(error.to_string()))?,
    });
    Ok(next)
}

/// Single reconcile-decision choke for every `ProductionHostStateJournal` write.
///
/// Both generic `HostStateRecord` appends and readiness-observation appends
/// funnel their `OutcomeUnknown` reconciliation through this helper so the
/// retry/fail-closed policy has exactly one owner. The underlying journal
/// admission stays distinct (`append` rejects readiness observations by
/// design; `append_readiness_observation` enforces the approved contour), but
/// the durable-outcome handling does not fork. Each caller performs its own
/// retry append so its by-value record stays consumed (moved) into the retry
/// instead of only cloned inside a closure.
fn reconcile_unknown_outcome<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    transaction_id: &PlatformHandle,
) -> Result<bool, HostError> {
    match journal.reconcile(transaction_id)? {
        ReconcileOutcome::Committed => {
            host_journal_observe("host.journal reconcile committed observed");
            Ok(true)
        }
        ReconcileOutcome::NotCommitted | ReconcileOutcome::StillUnknown => {
            host_journal_observe("host.journal reconcile unknown observed");
            Err(HostError::Journal(JournalError::OutcomeUnknown {
                transaction_id: transaction_id.clone(),
            }))
        }
    }
}

pub(super) fn append_reconciled<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    record: HostStateRecord,
) -> Result<AppendReceipt, HostError> {
    host_journal_observe("host.journal append requested");
    match journal.append(record.clone()) {
        Ok(receipt) => {
            host_journal_observe("host.journal append durable observed");
            Ok(receipt)
        }
        Err(JournalError::OutcomeUnknown { transaction_id }) => {
            host_journal_observe("host.journal append outcome unknown observed");
            if reconcile_unknown_outcome(journal, &transaction_id)? {
                journal.append(record).map_err(HostError::Journal)
            } else {
                // Unreachable today: the choke fails closed instead of returning
                // `Ok(false)`. Retained fail-closed so semantics stay identical
                // if the policy ever evolves.
                Err(HostError::Journal(JournalError::OutcomeUnknown {
                    transaction_id,
                }))
            }
        }
        Err(error) => {
            host_journal_observe("host.journal append rejected observed");
            Err(HostError::Journal(error))
        }
    }
}

#[cfg(windows)]
pub(super) fn append_store_rebind_terminal<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    mut record: StoreRebindRecord,
    state: StoreRebindState,
    receipt: Option<&StoreRebindReceipt>,
) -> Result<(), HostError> {
    host_journal_observe("host.journal rebind terminal requested");
    if record.state == state && state == StoreRebindState::Unknown {
        host_journal_observe("host.journal rebind unknown noop observed");
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
                || receipt.authority_epoch.sequence.get() != record.authority_epoch
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
    host_journal_observe("host.journal rebind terminal appended");
    Ok(())
}

#[cfg(windows)]
pub(super) fn persist_store_rebind_disposition<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    operation_id: &PlatformHandle,
    request_digest: &str,
    disposition: StoreRebindState,
) -> Result<(), HostError> {
    host_journal_observe("host.journal rebind disposition requested");
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
        host_journal_observe("host.journal rebind unknown noop observed");
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
    host_journal_observe("host.journal rebind disposition appended");
    Ok(())
}

/// Builds the I1.5 `DrainCommit` linearization record for Host stop,
/// carrying the Kernel lease/receipt snapshot observed in the journal into
/// `lease_and_pending_operation_snapshot`.
///
/// The snapshot is the exact live authority Host must fence before stopping:
/// the activation's runtime and supervision lease refs, the latest readiness
/// observation's predecessor lease identity and ORS receipt, and every
/// non-terminal store-rebind operation. An empty snapshot is honest only
/// when the journal proves no lease or pending operation remains; callers
/// must not substitute a placeholder. The `drain_generation` correlation
/// binds this commit to the `Requested`/`Draining` records that precede it.
///
/// The commit is bound to the durable drain admission, not to a live
/// observation: the journal must already carry the `DrainRecord` for this
/// exact fence and `drain_generation`, with trigger evidence naming what
/// opened it (idle-lease census evidence for an idle drain,
/// `scm-stop-request` for a requested shutdown). A commit for an unadmitted
/// generation is refused instead of persisted. `Pending`/`Unknown`
/// store-rebind operations are retained in the snapshot by operation id;
/// retention is the fence, never a terminal disposition.
pub(super) fn drain_commit_record_for_stop(
    snapshot: &HostState,
    activation: &EliotActivationRecord,
    drain_generation: &EpochTransition,
) -> Result<DrainCommitRecord, HostError> {
    let drain = snapshot.drain.as_ref().ok_or_else(|| {
        HostError::RecoveryRequired(
            "Host DrainCommit has no durable drain admission for this generation; append the Requested/Draining drain records before the DrainCommit linearization"
                .to_owned(),
        )
    })?;
    if drain.fence != activation.fence || drain.drain_generation != *drain_generation {
        return Err(HostError::RecoveryRequired(
            "Host DrainCommit names a generation without a matching durable drain admission; re-drive the drain for this exact activation fence and generation before committing"
                .to_owned(),
        ));
    }
    if drain.evidence_refs.is_empty() {
        return Err(HostError::RecoveryRequired(
            "Host drain admission carries no trigger evidence; an idle drain and a requested shutdown stay distinguishable only through the bound admission evidence"
                .to_owned(),
        ));
    }
    let mut lease_and_pending: Vec<PlatformHandle> = Vec::new();
    lease_and_pending.extend(activation.runtime_lease_refs.iter().cloned());
    lease_and_pending.extend(activation.supervision_lease_refs.iter().cloned());
    if let Some(readiness) = snapshot.readiness_observations.last()
        && let Some(predecessor) = readiness.active_supervision_lease.as_ref()
    {
        lease_and_pending.push(
            PlatformHandle::new(predecessor.supervision_lease_id.clone())
                .map_err(|error| HostError::Platform(error.to_string()))?,
        );
        lease_and_pending.push(
            PlatformHandle::new(predecessor.ors_receipt_sha256.clone())
                .map_err(|error| HostError::Platform(error.to_string()))?,
        );
    }
    for rebind in snapshot.store_rebinds.iter().filter(|record| {
        matches!(
            record.state,
            eliot_host_state::StoreRebindState::Pending
                | eliot_host_state::StoreRebindState::Unknown
        )
    }) {
        lease_and_pending.push(rebind.operation_id.clone());
    }
    Ok(DrainCommitRecord {
        fence: activation.fence.clone(),
        operation: operation("host-drain-commit")?,
        drain_generation: drain_generation.clone(),
        last_admission_closed_at: fresh_identity("host-admission-closed-at")?,
        lease_and_pending_operation_snapshot: lease_and_pending,
        authority_epochs_fenced: vec![activation.lineage.kernel_epoch.clone()],
        // I14.23 store-first order: the canonical-store branch stops before
        // the kernel branch, and only after the marker gate below has proven
        // no canonical-data/maintenance lease or pending Store operation
        // remains outside the commit snapshot.
        processes_modules_and_store_branches_to_stop: vec![
            PlatformHandle::new("canonical-store-branch")
                .map_err(|error| HostError::Platform(error.to_string()))?,
            PlatformHandle::new("kernel-branch")
                .map_err(|error| HostError::Platform(error.to_string()))?,
        ],
        wake_during_drain_disposition: WakeDisposition::QueueNextGeneration,
        irreversible_stage: PlatformHandle::new("authority-fenced")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        recovery_owner: PlatformHandle::new("host-composition")
            .map_err(|error| HostError::Platform(error.to_string()))?,
        committed_at: fresh_identity("host-drain-committed-at")?,
    })
}

/// Names at most eight residual identities in a refusal; a longer set reports
/// its exact remaining length instead of growing the error without bound.
fn bounded_residual_list(handles: &[PlatformHandle]) -> String {
    use std::fmt::Write as _;
    const MAX_LISTED: usize = 8;
    let mut text = handles
        .iter()
        .take(MAX_LISTED)
        .map(eliot_platform::PlatformHandle::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if handles.len() > MAX_LISTED {
        let _ = write!(text, ", and {} more", handles.len() - MAX_LISTED);
    }
    text
}

/// Refuses a drain-shutdown clean marker unless the journal proves the exact
/// combination #1686 requires before `StoppedClean`: the drain is still
/// `Draining` (never cancelled, failed or stuck pre-commit), the
/// `DrainCommit` linearization is present and bound to this activation fence
/// and drain generation, the covered Kernel record (when present) belongs to
/// this exact activation, no Store rebind operation is left
/// `Pending`/`Unknown`, and every lease ref the activation still names is
/// fenced inside the commit snapshot.
///
/// I14.23 orders "flush audit/outbox/ORS" and "stop store only when no
/// canonical data lease remains" before "publish intentional shutdown state
/// to Watchdog/Host", and I1.5 leaves a "failed or timed-out drain" as
/// "`DEGRADED_RECOVERY` plus a WakeIntent/manual entrypoint rather than
/// reporting `STOPPED_CLEAN`". The gate projects only facts the Host journal
/// itself owns: the Kernel coordinator's own prepared/intentional publication
/// lives kernel-side, live descendant termination (empty Job, reaped root) is
/// enforced by the caller's store-first termination step and re-projected by
/// `terminated_prior_kernel` on the next observe, and the sibling Watchdog
/// stop with the Governor-owned checkpoint/flush acknowledgements are those
/// owners' evidence. A missing piece therefore refuses the marker as explicit
/// incomplete recovery with the exact residual and safe next action instead
/// of completing a clean shutdown; per I14.13 no refusal claims rollback of
/// an already executed external effect.
fn refuse_clean_marker_without_drain_termination_evidence(
    snapshot: &HostState,
    activation: &EliotActivationRecord,
    drain: &DrainRecord,
) -> Result<(), HostError> {
    if drain.state != DrainState::Draining {
        return Err(HostError::RecoveryRequired(format!(
            "Host drain ended as {:?}, not Draining; a cancelled, failed or unlinearized drain is never a clean stop; re-drive the drain to its commit or recover the degraded contour",
            drain.state
        )));
    }
    let commit = snapshot.drain_commit.as_ref().ok_or_else(|| {
        HostError::RecoveryRequired(
            "Host drain has no DrainCommit linearization for this generation; append the DrainCommit before the clean marker; a pre-commit wake cancels the drain instead of completing it"
                .to_owned(),
        )
    })?;
    if commit.fence != activation.fence || commit.drain_generation != drain.drain_generation {
        return Err(HostError::RecoveryRequired(
            "Host DrainCommit is not bound to this activation fence and drain generation; append the DrainCommit linearization for this exact generation before the clean marker"
                .to_owned(),
        ));
    }
    if let Some(kernel) = snapshot.kernel.as_ref()
        && (kernel.fence.activation_id != activation.activation_id
            || kernel.fence.activation_generation != activation.fence.activation_generation
            || kernel.activation_identity != activation.activation_id)
    {
        return Err(HostError::RecoveryRequired(
            "Host clean marker covers a foreign Kernel contour; reconcile the current generation's Kernel record before claiming this generation clean"
                .to_owned(),
        ));
    }
    let open_rebinds: Vec<PlatformHandle> = snapshot
        .store_rebinds
        .iter()
        .filter(|record| {
            matches!(
                record.state,
                eliot_host_state::StoreRebindState::Pending
                    | eliot_host_state::StoreRebindState::Unknown
            )
        })
        .map(|record| record.operation_id.clone())
        .collect();
    if !open_rebinds.is_empty() {
        return Err(HostError::RecoveryRequired(format!(
            "Store obligations remain without a terminal disposition: {}; reconcile each exact operation through the Store rebind owner before the clean marker",
            bounded_residual_list(&open_rebinds)
        )));
    }
    let unfenced: Vec<PlatformHandle> = activation
        .runtime_lease_refs
        .iter()
        .chain(activation.supervision_lease_refs.iter())
        .filter(|lease| !commit.lease_and_pending_operation_snapshot.contains(*lease))
        .cloned()
        .collect();
    if !unfenced.is_empty() {
        return Err(HostError::RecoveryRequired(format!(
            "Authority remains outside the drain commit snapshot: {}; fence every live lease in the DrainCommit linearization before the clean marker",
            bounded_residual_list(&unfenced)
        )));
    }
    Ok(())
}

pub(super) fn clean_marker_record(
    snapshot: &HostState,
    host: &HostInstallationEpoch,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> Result<HostStateRecord, HostError> {
    let activation = snapshot.activation.as_ref().ok_or_else(|| {
        HostError::RecoveryRequired(
            "Host clean marker has no durable activation for this generation; start or recover the activation contour before claiming a clean stop"
                .to_owned(),
        )
    })?;
    if activation.activation_id != *activation_id
        || activation.fence.activation_generation != *activation_generation
    {
        return Err(HostError::RecoveryRequired(
            "Host clean marker names a superseded activation generation; reconcile the current activation contour before claiming a clean stop"
                .to_owned(),
        ));
    }
    if let Some(drain) = snapshot.drain.as_ref() {
        refuse_clean_marker_without_drain_termination_evidence(snapshot, activation, drain)?;
    }
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
    host_journal_observe("host.journal clean marker requested");
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

#[cfg(test)]
pub(super) fn test_activation_ingress() -> ActivationIngress {
    ActivationIngress {
        trigger_class: crate::activation_lifecycle::ActivationTriggerClass::AgentBridgeAttach
            .as_str(),
        requester: "test-requester".to_owned(),
        capabilities: crate::activation_lifecycle::control_contour_capabilities(),
    }
}

#[cfg(test)]
mod governance_profile_tests {
    use super::super::{fresh_host_epoch, root_epoch};
    use super::*;

    #[test]
    fn fresh_activation_stays_degraded_until_ready_is_proven() -> Result<(), HostError> {
        let installation = PlatformHandle::new("installation:test")
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let host = fresh_host_epoch(installation, None)?;
        let activation_id = fresh_identity("governance-activation")?;
        let activation_generation = root_epoch(fresh_lineage_id()?);
        let starting = initial_activation_record(
            &host,
            &activation_id,
            &activation_generation,
            ActivationState::Starting,
            "host-open",
            &test_activation_ingress(),
        )?;
        assert_eq!(starting.governance_profile.as_str(), "runtime-degraded-v3");
        let active =
            transition_activation_record(&starting, ActivationState::Active, "host-active")?;
        assert_eq!(active.governance_profile.as_str(), "runtime-live-v3");
        Ok(())
    }
}
