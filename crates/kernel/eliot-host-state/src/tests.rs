use std::sync::Arc;

use eliot_platform::{PlatformHandle, PortOutcome, UnknownReason};
use eliot_runtime_contracts::{
    HealthDimension, KernelActivationState, ServiceProcessRecord, WakeIntent,
};
use serde_json::json;

use crate::*;

fn h(value: &str) -> PlatformHandle {
    PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
}

fn epoch(lineage: &str, sequence: u64) -> EpochIdentity {
    EpochIdentity {
        lineage: h(lineage),
        sequence,
    }
}

fn step(lineage: &str, sequence: u64) -> EpochTransition {
    EpochTransition {
        current: epoch(lineage, sequence),
        parent: (sequence > 1).then(|| epoch(lineage, sequence - 1)),
    }
}

fn host(sequence: u64) -> HostInstallationEpoch {
    HostInstallationEpoch {
        installation: h("eliot-installation"),
        epoch: step("host-lineage", sequence),
        nonce: h(&format!("nonce-{sequence}")),
        recovery: None,
    }
}

fn recovery_host(reason: RecoveryLineageReason, lineage: &str) -> HostInstallationEpoch {
    HostInstallationEpoch {
        installation: h("eliot-installation"),
        epoch: step(lineage, 1),
        nonce: h(&format!("recovery-nonce-{lineage}")),
        recovery: Some(RecoveryLineageEvidence {
            reason,
            source_evidence_refs: vec![h("recovery-source-evidence")],
        }),
    }
}

fn operation(id: &str) -> IdempotencyIdentity {
    IdempotencyIdentity {
        operation_id: h(id),
        idempotency_key: h(&format!("key-{id}")),
    }
}

fn fence(host: &HostInstallationEpoch, activation: &EpochTransition) -> RecordFence {
    RecordFence {
        host: host.clone(),
        activation_id: h("activation-one"),
        activation_generation: activation.clone(),
    }
}

fn process_manifest() -> ImmutableProcessManifest {
    ImmutableProcessManifest {
        manifest_identity: h("dependency-process-manifest"),
        executable_identity: h("surrealdb-executable"),
        invocation_hash: h("sha256-invocation"),
        job_object_policy_ref: h("dependency-job-policy"),
        readiness_contract_ref: h("dependency-readiness-contract"),
    }
}

fn lifecycle_budget() -> DependencyLifecycleBudget {
    DependencyLifecycleBudget {
        budget_identity: h("dependency-lifecycle-budget"),
        start_attempts_remaining: 2,
        stop_attempts_remaining: 2,
        restart_attempts_remaining: 3,
    }
}

fn resource_budget() -> DependencyResourceBudget {
    DependencyResourceBudget {
        budget_identity: h("dependency-resource-budget"),
        max_cpu_time_ms: 5_000,
        max_memory_bytes: 1_048_576,
        max_process_handles: 32,
        max_io_bytes: 16_777_216,
        max_child_processes: 4,
    }
}

fn ready_kernel_process() -> ServiceProcessRecord {
    serde_json::from_value(json!({
        "process_id": "kernel-process-lineage",
        "owner": "Host",
        "state": "READY",
        "health": {
            "liveness": "HEALTHY",
            "readiness": "HEALTHY",
            "freshness": "HEALTHY",
            "compatibility": "HEALTHY",
            "integrity": "HEALTHY",
            "capacity": "HEALTHY"
        },
        "authority_epoch": 1
    }))
    .unwrap_or_else(|_| unreachable!())
}

fn stopped_kernel_process() -> ServiceProcessRecord {
    let mut process = ready_kernel_process();
    process.state = eliot_runtime_contracts::ServiceProcessState::Stopped;
    process.health.liveness = HealthDimension::Unknown;
    process
}

fn terminated_prior(
    history_complete: bool,
    members: Vec<PlatformHandle>,
) -> PriorKernelDisposition {
    PriorKernelDisposition::Terminated(PriorKernelSource {
        generation: step("prior-kernel-lineage", 1),
        job: KernelJobBinding {
            job_identity: h("prior-kernel-job"),
            root_process_identity: h("prior-kernel-root"),
            member_processes: members,
            root_reaped: true,
        },
        process: stopped_kernel_process(),
        history_complete,
    })
}

fn kernel_record(
    host: &HostInstallationEpoch,
    generation: &EpochTransition,
    op: &str,
    state: KernelActivationState,
) -> KernelRecord {
    let handoff = matches!(
        state,
        KernelActivationState::ShadowNoAuthority
            | KernelActivationState::HandoffPrepared
            | KernelActivationState::OldTerminated
            | KernelActivationState::NonceIssued
            | KernelActivationState::Activating
    );
    let live_job = KernelJobBinding {
        job_identity: h("kernel-job"),
        root_process_identity: h("kernel-root"),
        member_processes: vec![h("kernel-root")],
        root_reaped: false,
    };
    KernelRecord {
        fence: fence(host, generation),
        operation: operation(op),
        activation_identity: h("activation-one"),
        approved_artifact_hash: h("sha256-kernel-artifact"),
        active_pipe_identity: h("kernel-stable-pipe"),
        candidate_pipe_identity: handoff.then(|| h("kernel-candidate-pipe")),
        candidate_job_binding: matches!(
            state,
            KernelActivationState::Activating | KernelActivationState::Active
        )
        .then_some(live_job),
        prior_kernel_disposition: PriorKernelDisposition::NoPriorKernel,
        kernel_generation: step("kernel-lineage", 1),
        one_time_nonce: OneTimeNonceState {
            nonce_ref: matches!(
                state,
                KernelActivationState::NonceIssued
                    | KernelActivationState::Activating
                    | KernelActivationState::Active
                    | KernelActivationState::Failed
                    | KernelActivationState::ManualRecovery
            )
            .then(|| h("kernel-nonce")),
            state: match state {
                KernelActivationState::NonceIssued | KernelActivationState::Activating => {
                    NonceState::Issued
                }
                KernelActivationState::Active => NonceState::Consumed,
                KernelActivationState::Failed | KernelActivationState::ManualRecovery => {
                    NonceState::Revoked
                }
                _ => NonceState::Unissued,
            },
        },
        state,
        process: (state == KernelActivationState::Active).then(ready_kernel_process),
        readiness_evidence: (state == KernelActivationState::Active)
            .then(|| h("kernel-ready"))
            .into_iter()
            .collect(),
        disposition_evidence: vec![h("kernel-disposition")],
    }
}

fn dependency_record(
    host: &HostInstallationEpoch,
    activation: &EpochTransition,
    op: &str,
    state: DependencyState,
) -> DependencyRecord {
    DependencyRecord {
        fence: fence(host, activation),
        operation: operation(op),
        dependency: h("surrealdb"),
        process_manifest: process_manifest(),
        requester_identity: h("host-requester"),
        process_generation: step("dependency-lineage", 1),
        state,
        outcome: if state == DependencyState::Active {
            PortOutcome::Known(ready_kernel_process())
        } else {
            PortOutcome::Unknown(UnknownReason::NotObserved)
        },
        pid_job_lineage_refs: Vec::new(),
        lifecycle_budget: lifecycle_budget(),
        resource_budget: resource_budget(),
        approved_artifact_hash: h("sha256-artifact"),
        approved_config_hash: h("sha256-config"),
        disposition_evidence: vec![h("dependency-evidence")],
    }
}

fn activation(
    host: &HostInstallationEpoch,
    generation: &EpochTransition,
    op: &str,
    state: ActivationState,
) -> HostStateRecord {
    let ready = matches!(
        state,
        ActivationState::ControlReady | ActivationState::Active
    );
    HostStateRecord::Activation(EliotActivationRecord {
        fence: fence(host, generation),
        operation: operation(op),
        activation_id: h("activation-one"),
        trigger_class: h("observable-use"),
        trigger_evidence: vec![h("trigger-evidence")],
        requester_principal_session_or_scheduler: h("principal-session"),
        requested_capabilities: vec![h("kernel-control")],
        candidate_scope: h("installation-scope"),
        state,
        drain_generation: matches!(
            state,
            ActivationState::Draining | ActivationState::StoppedClean
        )
        .then(|| {
            step(
                generation.current.lineage.as_str(),
                generation.current.sequence,
            )
        }),
        lineage: HostKernelStoreLineage {
            host_epoch: host.epoch.current.clone(),
            kernel_epoch: epoch("kernel-lineage", 1),
            watchdog_epoch: epoch("watchdog-lineage", 1),
            store_generation: epoch("store-lineage", 1),
        },
        readiness: ReadinessEvidence {
            supervision_ready: ready,
            control_ready: ready,
            evidence_refs: vec![h("readiness-evidence")],
        },
        governance_profile: h("governed-profile"),
        runtime_lease_refs: vec![],
        supervision_lease_refs: vec![],
        wake_intent_refs: vec![],
        drain_commit_ref: None,
        wake_during_drain_disposition: None,
        boot_session_evidence: vec![h("boot-session-evidence")],
        power_transition_evidence: vec![],
        timestamps: LifecycleTimestamps {
            started_at: Some(h("t-started")),
            ready_at: ready.then(|| h("t-ready")),
            draining_at: (state == ActivationState::Draining).then(|| h("t-draining")),
            stopped_at: (state == ActivationState::StoppedClean).then(|| h("t-stopped")),
        },
        failure_and_recovery_directive: None,
    })
}

pub(crate) fn redb_test_activation(
    host: &HostInstallationEpoch,
    generation: &EpochTransition,
    op: &str,
) -> HostStateRecord {
    activation(host, generation, op, ActivationState::Starting)
}

fn advance_activation(
    journal: &HostStateJournal<MemoryBackend>,
    host: &HostInstallationEpoch,
    generation: &EpochTransition,
    state: ActivationState,
    op: &str,
) {
    journal
        .append(activation(host, generation, op, state))
        .unwrap_or_else(|error| panic!("activation transition failed: {error}"));
}

fn active_journal() -> (
    HostStateJournal<MemoryBackend>,
    HostInstallationEpoch,
    EpochTransition,
) {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal = HostStateJournal::open(MemoryBackend::default(), host.clone())
        .unwrap_or_else(|_| unreachable!());
    advance_activation(
        &journal,
        &host,
        &generation,
        ActivationState::Starting,
        "a-start",
    );
    advance_activation(
        &journal,
        &host,
        &generation,
        ActivationState::ControlReady,
        "a-control-ready",
    );
    advance_activation(
        &journal,
        &host,
        &generation,
        ActivationState::Active,
        "a-active",
    );
    (journal, host, generation)
}

fn wake(
    host: &HostInstallationEpoch,
    generation: &EpochTransition,
    op: &str,
    wake_id: &str,
    state: &str,
) -> HostStateRecord {
    let intent: WakeIntent = serde_json::from_value(json!({
        "wake_id": wake_id,
        "reason": "observable use",
        "state_fence": {"authority_epoch": 1, "resource_generation": 1},
        "state": state
    }))
    .unwrap_or_else(|_| unreachable!());
    HostStateRecord::Wake(WakeRecord {
        fence: fence(host, generation),
        operation: operation(op),
        wake_id: h(wake_id),
        intent,
        reason_evidence_refs: vec![h("wake-reason-evidence")],
        earliest_start: h("t-earliest"),
        deadline: h("t-deadline"),
        expiry: h("t-expiry"),
        required_capabilities: vec![h("kernel-control")],
        maintenance_family: h("interactive"),
        safety_class: ServiceSafetyClass::ServiceSafe,
        state_fence_revalidation_ref: h("fence-revalidation"),
        budget_ref: h("budget-one"),
    })
}

#[test]
fn lifecycle_matrix_rejects_skips_and_allows_declared_path() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal = HostStateJournal::open(MemoryBackend::default(), host.clone()).unwrap();
    journal
        .append(activation(
            &host,
            &generation,
            "start",
            ActivationState::Starting,
        ))
        .unwrap();
    assert!(matches!(
        journal.append(activation(
            &host,
            &generation,
            "skip",
            ActivationState::Active
        )),
        Err(JournalError::IllegalTransition {
            machine: "activation",
            ..
        })
    ));
    advance_activation(
        &journal,
        &host,
        &generation,
        ActivationState::ControlReady,
        "control",
    );
    advance_activation(
        &journal,
        &host,
        &generation,
        ActivationState::Active,
        "active",
    );
}

#[test]
fn same_generation_activation_cannot_change_activation_identity() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal = HostStateJournal::open(MemoryBackend::default(), host.clone()).unwrap();
    journal
        .append(activation(
            &host,
            &generation,
            "activation-start",
            ActivationState::Starting,
        ))
        .unwrap();
    let mut next = activation(
        &host,
        &generation,
        "activation-ready",
        ActivationState::ControlReady,
    );
    let HostStateRecord::Activation(changed) = &mut next else {
        unreachable!();
    };
    changed.activation_id = h("different-activation");
    assert_eq!(journal.append(next), Err(JournalError::StaleFence));
    assert_eq!(journal.snapshot().unwrap().sequence, 1);
}

#[test]
fn exact_replay_is_idempotent_and_changed_payload_conflicts() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal = HostStateJournal::open(MemoryBackend::default(), host.clone()).unwrap();
    let record = activation(&host, &generation, "same", ActivationState::Starting);
    let first = journal.append(record.clone()).unwrap();
    let replay = journal.append(record.clone()).unwrap();
    assert_eq!(first.sequence(), replay.sequence());
    assert_eq!(replay.disposition(), AppendDisposition::Replayed);
    let mut conflict = record;
    let HostStateRecord::Activation(value) = &mut conflict else {
        unreachable!();
    };
    value.trigger_class = h("different-trigger");
    assert_eq!(
        journal.append(conflict),
        Err(JournalError::IdempotencyConflict)
    );
    assert_eq!(journal.snapshot().unwrap().sequence, 1);
}

#[test]
fn wake_lifecycle_is_fenced_and_terminal_states_do_not_revive() {
    let (journal, host, generation) = active_journal();
    journal
        .append(wake(&host, &generation, "w1", "wake-one", "PENDING"))
        .unwrap();
    journal
        .append(wake(&host, &generation, "w2", "wake-one", "CLAIMED"))
        .unwrap();
    journal
        .append(wake(&host, &generation, "w3", "wake-one", "STARTED"))
        .unwrap();
    journal
        .append(wake(&host, &generation, "w4", "wake-one", "SATISFIED"))
        .unwrap();
    assert!(matches!(
        journal.append(wake(&host, &generation, "w5", "wake-one", "PENDING")),
        Err(JournalError::IllegalTransition {
            machine: "wake",
            ..
        })
    ));
}

#[test]
fn dependency_lifecycle_rejects_illegal_first_active_record() {
    let (journal, host, generation) = active_journal();
    let record = HostStateRecord::Dependency(DependencyRecord {
        fence: fence(&host, &generation),
        operation: operation("dependency-active"),
        dependency: h("surrealdb"),
        process_manifest: process_manifest(),
        requester_identity: h("host-requester"),
        process_generation: step("dependency-lineage", 1),
        state: DependencyState::Active,
        outcome: PortOutcome::Unknown(UnknownReason::NotObserved),
        pid_job_lineage_refs: vec![],
        lifecycle_budget: lifecycle_budget(),
        resource_budget: resource_budget(),
        approved_artifact_hash: h("sha256-artifact"),
        approved_config_hash: h("sha256-config"),
        disposition_evidence: vec![h("dependency-evidence")],
    });
    assert!(matches!(
        journal.append(record),
        Err(JournalError::Invalid(_))
    ));
}

#[test]
fn dependency_requires_manifest_requester_and_complete_lifecycle_budget() {
    let (journal, host, generation) = active_journal();
    let record = HostStateRecord::Dependency(dependency_record(
        &host,
        &generation,
        "dependency-required-fields",
        DependencyState::Starting,
    ));
    let encoded = serde_json::to_value(&record).unwrap();

    for missing in ["process_manifest", "requester_identity", "lifecycle_budget"] {
        let mut value = encoded.clone();
        value["dependency"]
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .remove(missing);
        assert!(serde_json::from_value::<HostStateRecord>(value).is_err());
    }
    for missing in [
        "start_attempts_remaining",
        "stop_attempts_remaining",
        "restart_attempts_remaining",
    ] {
        let mut value = encoded.clone();
        value["dependency"]["lifecycle_budget"]
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .remove(missing);
        assert!(serde_json::from_value::<HostStateRecord>(value).is_err());
    }

    let mut blank_manifest = encoded;
    blank_manifest["dependency"]["process_manifest"]["invocation_hash"] = json!(" ");
    let malformed: HostStateRecord = serde_json::from_value(blank_manifest).unwrap();
    assert!(matches!(
        journal.append(malformed),
        Err(JournalError::Invalid(_))
    ));
}

#[test]
fn dependency_manifest_and_requester_are_immutable_within_process_generation() {
    let (journal, host, generation) = active_journal();
    journal
        .append(HostStateRecord::Dependency(dependency_record(
            &host,
            &generation,
            "dependency-start-immutable",
            DependencyState::Starting,
        )))
        .unwrap();
    let mut next = dependency_record(
        &host,
        &generation,
        "dependency-active-immutable",
        DependencyState::Active,
    );
    next.process_manifest.invocation_hash = h("different-invocation");
    assert_eq!(
        journal.append(HostStateRecord::Dependency(next)),
        Err(JournalError::StaleFence)
    );
}

#[test]
fn dependency_wake_and_drain_replay_or_conflict_by_exact_identity() {
    let (journal, host, generation) = active_journal();
    let dependency = HostStateRecord::Dependency(DependencyRecord {
        fence: fence(&host, &generation),
        operation: operation("dependency-start"),
        dependency: h("surrealdb"),
        process_manifest: process_manifest(),
        requester_identity: h("host-requester"),
        process_generation: step("dependency-lineage", 1),
        state: DependencyState::Starting,
        outcome: PortOutcome::Unknown(UnknownReason::NotObserved),
        pid_job_lineage_refs: vec![],
        lifecycle_budget: lifecycle_budget(),
        resource_budget: resource_budget(),
        approved_artifact_hash: h("sha256-artifact"),
        approved_config_hash: h("sha256-config"),
        disposition_evidence: vec![h("dependency-evidence")],
    });
    let wake = wake(&host, &generation, "wake-start", "wake-replay", "PENDING");
    let drain = HostStateRecord::Drain(DrainRecord {
        fence: fence(&host, &generation),
        operation: operation("drain-replay"),
        drain_generation: step("activation-lineage", 1),
        state: DrainState::Requested,
        evidence_refs: vec![h("drain-evidence")],
    });

    for record in [&dependency, &wake, &drain] {
        journal.append(record.clone()).unwrap();
        assert_eq!(
            journal.append(record.clone()).unwrap().disposition(),
            AppendDisposition::Replayed
        );
    }

    let mut dependency_conflict = dependency;
    let HostStateRecord::Dependency(value) = &mut dependency_conflict else {
        unreachable!();
    };
    value.approved_config_hash = h("sha256-config-other");
    assert_eq!(
        journal.append(dependency_conflict),
        Err(JournalError::IdempotencyConflict)
    );

    let mut wake_conflict = wake;
    let HostStateRecord::Wake(value) = &mut wake_conflict else {
        unreachable!();
    };
    value.reason_evidence_refs = vec![h("other-wake-evidence")];
    assert_eq!(
        journal.append(wake_conflict),
        Err(JournalError::IdempotencyConflict)
    );

    let mut drain_conflict = drain;
    let HostStateRecord::Drain(value) = &mut drain_conflict else {
        unreachable!();
    };
    value.evidence_refs = vec![h("other-drain-evidence")];
    assert_eq!(
        journal.append(drain_conflict),
        Err(JournalError::IdempotencyConflict)
    );
}

#[test]
fn partial_transaction_never_commits_ram_and_remains_reconcilable() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal = HostStateJournal::open(
        MemoryBackend::with_fault(FaultPoint::FlushUnknown),
        host.clone(),
    )
    .unwrap();
    let error = journal
        .append(activation(
            &host,
            &generation,
            "partial",
            ActivationState::Starting,
        ))
        .unwrap_err();
    let JournalError::OutcomeUnknown { transaction_id } = error else {
        panic!("expected a typed unknown outcome");
    };
    assert_eq!(journal.snapshot().unwrap().sequence, 0);
    assert_eq!(
        journal.reconcile(&transaction_id).unwrap(),
        ReconcileOutcome::StillUnknown
    );
    let backend = journal.into_backend().unwrap();
    let reopened = HostStateJournal::open(backend, host).unwrap();
    assert_eq!(
        reopened.reconcile(&transaction_id).unwrap(),
        ReconcileOutcome::StillUnknown
    );
    assert_eq!(reopened.snapshot().unwrap().sequence, 0);
}

#[test]
fn unknown_prepare_is_exposed_with_stable_transaction_identity() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal = HostStateJournal::open(
        MemoryBackend::with_fault(FaultPoint::PrepareUnknown),
        host.clone(),
    )
    .unwrap();
    let error = journal
        .append(activation(
            &host,
            &generation,
            "prepare-unknown",
            ActivationState::Starting,
        ))
        .unwrap_err();
    assert!(matches!(error, JournalError::OutcomeUnknown { .. }));
    assert_eq!(journal.snapshot().unwrap().sequence, 0);
}

#[test]
fn prepared_transaction_enumerates_and_survives_reopen_without_retry() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal = HostStateJournal::open(
        MemoryBackend::with_fault(FaultPoint::AppendFailed),
        host.clone(),
    )
    .unwrap_or_else(|_| unreachable!());
    let result = journal.append(activation(
        &host,
        &generation,
        "prepared-enumeration",
        ActivationState::Starting,
    ));
    assert!(matches!(
        result,
        Err(JournalError::Backend(BackendError::Failed(_)))
    ));
    let pending = journal
        .pending_transactions()
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(pending.len(), 1);
    let transaction_id = pending[0].transaction_id.clone();
    let backend = journal.into_backend().unwrap_or_else(|_| unreachable!());
    let reopened = HostStateJournal::open(backend, host).unwrap_or_else(|_| unreachable!());
    assert_eq!(
        reopened
            .pending_transactions()
            .unwrap_or_else(|_| unreachable!()),
        pending
    );
    assert_eq!(
        reopened
            .reconcile(&transaction_id)
            .unwrap_or_else(|_| unreachable!()),
        ReconcileOutcome::StillUnknown
    );
}

#[test]
fn backend_failures_are_not_misreported_as_unknown_outcomes() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal = HostStateJournal::open(
        MemoryBackend::with_fault(FaultPoint::AppendFailed),
        host.clone(),
    )
    .unwrap();
    assert!(matches!(
        journal.append(activation(
            &host,
            &generation,
            "append-failure",
            ActivationState::Starting,
        )),
        Err(JournalError::Backend(BackendError::Failed(_)))
    ));
    assert_eq!(journal.snapshot().unwrap().sequence, 0);
}

#[test]
fn missing_platform_provider_is_an_honest_plan_gap() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal =
        HostStateJournal::open(MemoryBackend::with_fault(FaultPoint::PlanGap), host.clone())
            .unwrap();
    assert_eq!(
        journal.append(activation(
            &host,
            &generation,
            "missing-platform",
            ActivationState::Starting,
        )),
        Err(JournalError::PlanGap {
            dependency: "P-01 eliot-platform",
        })
    );
    assert_eq!(journal.snapshot().unwrap().sequence, 0);
}

#[test]
fn postcommit_unknown_reconciles_without_blind_retry() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal = HostStateJournal::open(
        MemoryBackend::with_fault(FaultPoint::CommitAfterUnknown),
        host.clone(),
    )
    .unwrap();
    let record = activation(&host, &generation, "postcommit", ActivationState::Starting);
    let error = journal.append(record.clone()).unwrap_err();
    let JournalError::OutcomeUnknown { transaction_id } = error else {
        panic!("expected a typed unknown outcome");
    };
    assert_eq!(journal.snapshot().unwrap().sequence, 0);
    assert_eq!(
        journal.reconcile(&transaction_id).unwrap(),
        ReconcileOutcome::Committed
    );
    assert_eq!(journal.snapshot().unwrap().sequence, 1);
    assert_eq!(
        journal.append(record).unwrap().disposition(),
        AppendDisposition::Replayed
    );
}

#[test]
fn committed_transaction_from_foreign_host_epoch_cannot_reconcile_as_committed() {
    let old_host = host(1);
    let generation = step("activation-lineage", 1);
    let old = HostStateJournal::open(
        MemoryBackend::with_fault(FaultPoint::CommitAfterUnknown),
        old_host.clone(),
    )
    .unwrap();
    let error = old
        .append(activation(
            &old_host,
            &generation,
            "foreign-host-commit",
            ActivationState::Starting,
        ))
        .unwrap_err();
    let JournalError::OutcomeUnknown { transaction_id } = error else {
        unreachable!();
    };
    let backend = old.into_backend().unwrap();
    let foreign = HostStateJournal::open(backend, host(2)).unwrap();
    assert_eq!(
        foreign.reconcile(&transaction_id),
        Err(JournalError::StaleFence)
    );
    assert_eq!(foreign.snapshot().unwrap().sequence, 0);
}

#[test]
fn committed_backend_receipt_must_match_durable_operation_checksum() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal = HostStateJournal::open(
        MemoryBackend::with_fault(FaultPoint::CommitAfterUnknown),
        host.clone(),
    )
    .unwrap();
    let error = journal
        .append(activation(
            &host,
            &generation,
            "tampered-commit",
            ActivationState::Starting,
        ))
        .unwrap_err();
    let JournalError::OutcomeUnknown { transaction_id } = error else {
        unreachable!();
    };
    let mut backend = journal.into_backend().unwrap();
    backend.rewrite_committed_checksum_for_test(&transaction_id, "fnv1a64-deadbeefdeadbeef");
    assert!(matches!(
        HostStateJournal::open(backend, host),
        Err(JournalError::IdempotencyConflict)
    ));
}

#[test]
fn crash_reopen_replays_committed_state() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal = HostStateJournal::open(MemoryBackend::default(), host.clone()).unwrap();
    journal
        .append(activation(
            &host,
            &generation,
            "durable",
            ActivationState::Starting,
        ))
        .unwrap();
    let backend = journal.into_backend().unwrap();
    let reopened = HostStateJournal::open(backend, host).unwrap();
    let state = reopened.snapshot().unwrap();
    assert_eq!(state.sequence, 1);
    assert_eq!(state.activation.unwrap().state, ActivationState::Starting);
}

#[test]
fn replay_rejects_torn_checksum_version_and_sequence_frames() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal = HostStateJournal::open(MemoryBackend::default(), host.clone()).unwrap();
    journal
        .append(activation(
            &host,
            &generation,
            "corruption",
            ActivationState::Starting,
        ))
        .unwrap();
    let image = journal.into_backend().unwrap().durable_image().clone();
    let bytes = &image.epochs[0].bytes;

    let mut torn = bytes.clone();
    torn.pop();
    assert!(matches!(
        HostStateJournal::<MemoryBackend>::replay_bytes(&torn, host.clone()),
        Err(JournalError::Torn { .. })
    ));

    let mut checksum = bytes.clone();
    let payload_start = checksum
        .windows(2)
        .position(|window| window == b"\n{")
        .map_or_else(|| unreachable!(), |offset| offset + 1);
    checksum[payload_start] = b'[';
    assert!(matches!(
        HostStateJournal::<MemoryBackend>::replay_bytes(&checksum, host.clone()),
        Err(JournalError::Checksum { .. } | JournalError::Invalid(_))
    ));

    let mut version = bytes.clone();
    let version_field = version
        .windows(11)
        .position(|window| window == br#""version":1"#)
        .map_or_else(|| unreachable!(), |offset| offset + 10);
    version[version_field] = b'2';
    assert!(matches!(
        HostStateJournal::<MemoryBackend>::replay_bytes(&version, host.clone()),
        Err(JournalError::UnknownVersion { .. } | JournalError::Invalid(_))
    ));

    let mut sequence = bytes.clone();
    let sequence_field = sequence
        .windows(12)
        .position(|window| window == br#""sequence":1"#)
        .map_or_else(|| unreachable!(), |offset| offset + 11);
    sequence[sequence_field] = b'2';
    assert!(matches!(
        HostStateJournal::<MemoryBackend>::replay_bytes(&sequence, host),
        Err(JournalError::Sequence | JournalError::Checksum { .. })
    ));
}

#[test]
fn new_epoch_retains_prior_evidence_until_explicit_retirement() {
    let old_host = host(1);
    let old_activation = step("activation-lineage", 1);
    let old = HostStateJournal::open(MemoryBackend::default(), old_host.clone()).unwrap();
    old.append(activation(
        &old_host,
        &old_activation,
        "old-start",
        ActivationState::Starting,
    ))
    .unwrap();
    let backend = old.into_backend().unwrap();
    let new_host = host(2);
    let new_activation = step("new-activation-lineage", 1);
    let new = HostStateJournal::open(backend, new_host.clone()).unwrap();
    assert_eq!(new.snapshot().unwrap().retained_epochs.len(), 1);
    new.append(activation(
        &new_host,
        &new_activation,
        "new-start",
        ActivationState::Starting,
    ))
    .unwrap();
    new.append(HostStateRecord::EpochRetirement(EpochRetirementRecord {
        fence: fence(&new_host, &new_activation),
        operation: operation("retire-old"),
        retired_host: old_host.clone(),
        retirement_evidence_refs: vec![h("retirement-proof")],
        retired_at: h("t-retired"),
    }))
    .unwrap();
    assert!(
        new.snapshot()
            .unwrap()
            .retained_epochs
            .iter()
            .any(|item| item.host == old_host && item.retired)
    );
    let backend = new.into_backend().unwrap();
    let reopened = HostStateJournal::open(backend, new_host).unwrap();
    assert!(reopened.snapshot().unwrap().retained_epochs[0].retired);
}

#[test]
fn distinct_root_lineage_requires_explicit_recovery_evidence() {
    let old_host = host(1);
    let old = HostStateJournal::open(MemoryBackend::default(), old_host.clone()).unwrap();
    old.append(activation(
        &old_host,
        &step("activation-lineage", 1),
        "old-root-start",
        ActivationState::Starting,
    ))
    .unwrap();
    let backend = old.into_backend().unwrap();
    let unrelated_root = HostInstallationEpoch {
        installation: old_host.installation,
        epoch: step("unadmitted-root-lineage", 1),
        nonce: h("unadmitted-root-nonce"),
        recovery: None,
    };
    assert!(matches!(
        HostStateJournal::open(backend.clone(), unrelated_root),
        Err(JournalError::RecoveryRequiresNewEpoch)
    ));

    let mut unproven_recovery =
        recovery_host(RecoveryLineageReason::Restore, "unproven-recovery-lineage");
    unproven_recovery
        .recovery
        .as_mut()
        .unwrap_or_else(|| unreachable!())
        .source_evidence_refs
        .clear();
    assert!(matches!(
        HostStateJournal::open(backend, unproven_recovery),
        Err(JournalError::Invalid(_))
    ));
}

#[test]
fn restore_and_break_glass_create_new_root_lineages_without_retiring_old_evidence() {
    let old_host = host(1);
    let old = HostStateJournal::open(MemoryBackend::default(), old_host.clone()).unwrap();
    old.append(activation(
        &old_host,
        &step("activation-lineage", 1),
        "old-recovery-source",
        ActivationState::Starting,
    ))
    .unwrap();
    let backend = old.into_backend().unwrap();

    for (reason, lineage) in [
        (RecoveryLineageReason::Restore, "restored-host-lineage"),
        (
            RecoveryLineageReason::BreakGlass,
            "break-glass-host-lineage",
        ),
    ] {
        let recovered =
            HostStateJournal::open(backend.clone(), recovery_host(reason, lineage)).unwrap();
        let retained = recovered.snapshot().unwrap().retained_epochs;
        assert_eq!(retained.len(), 1);
        assert!(retained[0].replay_verified);
        assert!(!retained[0].retired);
    }
}

#[test]
fn corruption_recovery_preserves_raw_epoch_evidence_until_explicit_retirement() {
    let old_host = host(1);
    let old = HostStateJournal::open(MemoryBackend::default(), old_host.clone()).unwrap();
    old.append(activation(
        &old_host,
        &step("activation-lineage", 1),
        "old-corrupt-source",
        ActivationState::Starting,
    ))
    .unwrap();
    let mut backend = old.into_backend().unwrap();
    backend.corrupt_epoch_for_test(0);
    let corrupt_bytes = backend.durable_image().epochs[0].bytes.clone();

    let recovered_host = recovery_host(
        RecoveryLineageReason::Corruption,
        "corruption-recovery-lineage",
    );
    let recovered_activation = step("recovered-activation-lineage", 1);
    let recovered = HostStateJournal::open(backend, recovered_host.clone()).unwrap();
    let retained = recovered.snapshot().unwrap().retained_epochs;
    assert_eq!(retained.len(), 1);
    assert!(!retained[0].replay_verified);
    assert!(!retained[0].forensic_digest.is_empty());
    assert!(!retained[0].retired);

    recovered
        .append(activation(
            &recovered_host,
            &recovered_activation,
            "recovered-start",
            ActivationState::Starting,
        ))
        .unwrap();
    recovered
        .append(HostStateRecord::EpochRetirement(EpochRetirementRecord {
            fence: fence(&recovered_host, &recovered_activation),
            operation: operation("retire-corrupt-epoch"),
            retired_host: old_host,
            retirement_evidence_refs: vec![h("manual-retirement-evidence")],
            retired_at: h("t-corrupt-retired"),
        }))
        .unwrap();
    let backend = recovered.into_backend().unwrap();
    assert_eq!(backend.durable_image().epochs[0].bytes, corrupt_bytes);
    assert_eq!(backend.durable_image().epochs.len(), 2);
    let reopened = HostStateJournal::open(backend, recovered_host).unwrap();
    assert!(reopened.snapshot().unwrap().retained_epochs[0].retired);
}

#[test]
fn cross_lineage_epoch_is_not_ordered_or_adopted() {
    let old_host = host(1);
    let generation = step("activation-lineage", 1);
    let old = HostStateJournal::open(MemoryBackend::default(), old_host.clone()).unwrap();
    old.append(activation(
        &old_host,
        &generation,
        "old",
        ActivationState::Starting,
    ))
    .unwrap();
    let backend = old.into_backend().unwrap();
    let unrelated = HostInstallationEpoch {
        installation: old_host.installation.clone(),
        epoch: EpochTransition {
            current: epoch("other-lineage", 2),
            parent: Some(old_host.epoch.current.clone()),
        },
        nonce: h("unrelated-nonce"),
        recovery: None,
    };
    assert!(matches!(
        HostStateJournal::open(backend, unrelated),
        Err(JournalError::EpochLineageConflict | JournalError::RecoveryRequiresNewEpoch)
    ));
}

#[test]
fn committed_drain_cannot_be_cancelled_into_same_generation() {
    let (journal, host, generation) = active_journal();
    let drain_generation = step("activation-lineage", 1);
    journal
        .append(HostStateRecord::Drain(DrainRecord {
            fence: fence(&host, &generation),
            operation: operation("drain-request"),
            drain_generation: drain_generation.clone(),
            state: DrainState::Requested,
            evidence_refs: vec![h("drain-request-evidence")],
        }))
        .unwrap();
    journal
        .append(HostStateRecord::Drain(DrainRecord {
            fence: fence(&host, &generation),
            operation: operation("drain-start"),
            drain_generation: drain_generation.clone(),
            state: DrainState::Draining,
            evidence_refs: vec![h("drain-start-evidence")],
        }))
        .unwrap();
    advance_activation(
        &journal,
        &host,
        &generation,
        ActivationState::Draining,
        "activation-draining",
    );
    journal
        .append(HostStateRecord::DrainCommit(DrainCommitRecord {
            fence: fence(&host, &generation),
            operation: operation("drain-commit"),
            drain_generation,
            last_admission_closed_at: h("t-admission-closed"),
            lease_and_pending_operation_snapshot: vec![h("lease-snapshot")],
            authority_epochs_fenced: vec![epoch("authority-lineage", 1)],
            processes_modules_and_store_branches_to_stop: vec![h("kernel-process")],
            wake_during_drain_disposition: WakeDisposition::QueueNextGeneration,
            irreversible_stage: h("authority-fenced"),
            recovery_owner: h("host-recovery"),
            committed_at: h("t-committed"),
        }))
        .unwrap();
    assert!(matches!(
        journal.append(activation(
            &host,
            &generation,
            "cancel-too-late",
            ActivationState::Active
        )),
        Err(JournalError::IllegalTransition {
            machine: "activation",
            ..
        })
    ));
}

#[test]
fn observation_variant_cannot_bypass_host_fence_and_unknown_fields_fail() {
    let bare_observation = json!({
        "observation": {
            "record_id": "obs-1",
            "kind": "AUDIT",
            "event": null,
            "coverage_gap": null,
            "journal_control_event": false,
            "parent_record_id": null
        }
    });
    assert!(serde_json::from_value::<HostStateRecord>(bare_observation).is_err());

    let host = host(1);
    let generation = step("activation-lineage", 1);
    let record = activation(&host, &generation, "serde", ActivationState::Starting);
    let mut value = serde_json::to_value(record).unwrap();
    value["activation"]["unexpected"] = json!(true);
    assert!(serde_json::from_value::<HostStateRecord>(value).is_err());
}

#[test]
fn semantic_validation_rejects_transparently_deserialized_blank_nested_handle() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let record = activation(&host, &generation, "blank", ActivationState::Starting);
    let mut value = serde_json::to_value(record).unwrap();
    value["activation"]["requested_capabilities"][0] = json!(" ");
    let malformed: HostStateRecord = serde_json::from_value(value).unwrap();
    let journal = HostStateJournal::open(MemoryBackend::default(), host).unwrap();
    assert!(matches!(
        journal.append(malformed),
        Err(JournalError::Invalid(_))
    ));
}

#[test]
fn checked_sequence_overflow_fails_without_backend_mutation() {
    let host = host(1);
    let generation = step("activation-lineage", 1);
    let journal = HostStateJournal::open(MemoryBackend::default(), host.clone()).unwrap();
    journal.set_sequence_for_test(u64::MAX);
    assert_eq!(
        journal.append(activation(
            &host,
            &generation,
            "overflow",
            ActivationState::Starting
        )),
        Err(JournalError::Sequence)
    );
}

#[test]
fn concurrent_unique_wakes_are_serialized_and_poison_is_typed() {
    let (journal, host, generation) = active_journal();
    let journal = Arc::new(journal);
    let mut workers = Vec::new();
    for index in 0..8_u8 {
        let journal = Arc::clone(&journal);
        let host = host.clone();
        let generation = generation.clone();
        workers.push(std::thread::spawn(move || {
            journal.append(wake(
                &host,
                &generation,
                &format!("wake-op-{index}"),
                &format!("wake-{index}"),
                "PENDING",
            ))
        }));
    }
    for worker in workers {
        assert!(worker.join().unwrap().is_ok());
    }
    assert_eq!(journal.snapshot().unwrap().wakes.len(), 8);
    journal.poison_state_for_test();
    assert_eq!(journal.snapshot(), Err(JournalError::Synchronization));
}

#[test]
fn kernel_record_requires_approved_artifact_explicit_pipes_and_active_evidence() {
    let (journal, host, generation) = active_journal();
    let idle = HostStateRecord::Kernel(kernel_record(
        &host,
        &generation,
        "kernel-required-fields",
        KernelActivationState::Idle,
    ));
    let encoded = serde_json::to_value(idle).unwrap();
    for missing in [
        "approved_artifact_hash",
        "active_pipe_identity",
        "candidate_job_binding",
        "prior_kernel_disposition",
    ] {
        let mut value = encoded.clone();
        value["kernel"]
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .remove(missing);
        assert!(serde_json::from_value::<HostStateRecord>(value).is_err());
    }

    let mut same_pipe = kernel_record(
        &host,
        &generation,
        "kernel-same-pipe",
        KernelActivationState::ShadowNoAuthority,
    );
    same_pipe.candidate_pipe_identity = Some(same_pipe.active_pipe_identity.clone());
    assert!(matches!(
        journal.append(HostStateRecord::Kernel(same_pipe)),
        Err(JournalError::Invalid(_))
    ));

    let mut missing_process = kernel_record(
        &host,
        &generation,
        "kernel-missing-process",
        KernelActivationState::Active,
    );
    missing_process.process = None;
    assert!(matches!(
        journal.append(HostStateRecord::Kernel(missing_process)),
        Err(JournalError::Invalid(_))
    ));

    let mut missing_readiness = kernel_record(
        &host,
        &generation,
        "kernel-missing-readiness",
        KernelActivationState::Active,
    );
    missing_readiness.readiness_evidence.clear();
    assert!(matches!(
        journal.append(HostStateRecord::Kernel(missing_readiness)),
        Err(JournalError::Invalid(_))
    ));
}

#[test]
fn kernel_old_terminated_rejects_opaque_or_incomplete_disposition() {
    let (journal, host, generation) = active_journal();
    let mut cases = vec![
        PriorKernelDisposition::Running(PriorKernelSource {
            generation: step("prior-kernel-lineage", 1),
            job: KernelJobBinding {
                job_identity: h("prior-kernel-job"),
                root_process_identity: h("prior-kernel-root"),
                member_processes: vec![h("prior-kernel-root")],
                root_reaped: false,
            },
            process: ready_kernel_process(),
            history_complete: true,
        }),
        PriorKernelDisposition::Unknown(PriorKernelSource {
            generation: step("prior-kernel-lineage", 1),
            job: KernelJobBinding {
                job_identity: h("prior-kernel-job"),
                root_process_identity: h("prior-kernel-root"),
                member_processes: vec![],
                root_reaped: true,
            },
            process: stopped_kernel_process(),
            history_complete: false,
        }),
        terminated_prior(false, vec![]),
        terminated_prior(true, vec![h("prior-kernel-root")]),
    ];
    for (index, disposition) in cases.drain(..).enumerate() {
        let mut record = kernel_record(
            &host,
            &generation,
            &format!("kernel-invalid-disposition-{index}"),
            KernelActivationState::OldTerminated,
        );
        record.prior_kernel_disposition = disposition;
        assert!(matches!(
            journal.append(HostStateRecord::Kernel(record)),
            Err(JournalError::Invalid(_))
        ));
    }

    let mut opaque_only = kernel_record(
        &host,
        &generation,
        "kernel-opaque-only",
        KernelActivationState::OldTerminated,
    );
    opaque_only.prior_kernel_disposition = PriorKernelDisposition::Unknown(PriorKernelSource {
        generation: step("prior-kernel-lineage", 1),
        job: KernelJobBinding {
            job_identity: h("prior-kernel-job"),
            root_process_identity: h("prior-kernel-root"),
            member_processes: vec![],
            root_reaped: true,
        },
        process: stopped_kernel_process(),
        history_complete: true,
    });
    opaque_only.disposition_evidence = vec![h("looks-like-proof")];
    assert!(
        journal
            .append(HostStateRecord::Kernel(opaque_only))
            .is_err()
    );
}

#[test]
fn kernel_nonce_is_absent_until_old_terminated_and_retained_through_active() {
    let (journal, host, generation) = active_journal();
    for (state, op) in [
        (KernelActivationState::Idle, "nonce-idle"),
        (KernelActivationState::ShadowNoAuthority, "nonce-shadow"),
        (KernelActivationState::HandoffPrepared, "nonce-prepared"),
        (KernelActivationState::OldTerminated, "nonce-terminated"),
    ] {
        journal
            .append(HostStateRecord::Kernel(kernel_record(
                &host,
                &generation,
                op,
                state,
            )))
            .unwrap_or_else(|error| panic!("kernel transition failed: {error}"));
    }
    let nonce_issued = kernel_record(
        &host,
        &generation,
        "nonce-issued",
        KernelActivationState::NonceIssued,
    );
    let nonce = nonce_issued
        .one_time_nonce
        .nonce_ref
        .clone()
        .unwrap_or_else(|| unreachable!());
    journal
        .append(HostStateRecord::Kernel(nonce_issued))
        .unwrap_or_else(|error| panic!("nonce issuance failed: {error}"));
    let activating = kernel_record(
        &host,
        &generation,
        "nonce-activating",
        KernelActivationState::Activating,
    );
    assert_eq!(activating.one_time_nonce.nonce_ref, Some(nonce.clone()));
    journal
        .append(HostStateRecord::Kernel(activating))
        .unwrap_or_else(|error| panic!("activation failed: {error}"));
    let active = kernel_record(
        &host,
        &generation,
        "nonce-active",
        KernelActivationState::Active,
    );
    assert_eq!(active.one_time_nonce.nonce_ref, Some(nonce));
    journal
        .append(HostStateRecord::Kernel(active))
        .unwrap_or_else(|error| panic!("active transition failed: {error}"));
    assert_eq!(
        journal
            .snapshot()
            .unwrap()
            .kernel
            .unwrap()
            .one_time_nonce
            .state,
        NonceState::Consumed
    );
}

#[test]
fn kernel_append_must_bind_current_eliot_activation_identity() {
    let (journal, host, generation) = active_journal();
    let mut kernel = kernel_record(
        &host,
        &generation,
        "kernel-wrong-activation",
        KernelActivationState::Idle,
    );
    kernel.activation_identity = h("foreign-activation");
    assert_eq!(
        journal.append(HostStateRecord::Kernel(kernel)),
        Err(JournalError::StaleFence)
    );
    assert!(journal.snapshot().unwrap().kernel.is_none());
}

#[test]
fn kernel_transition_matrix_rejects_activation_without_handoff() {
    let (journal, host, generation) = active_journal();
    let record = HostStateRecord::Kernel(KernelRecord {
        fence: fence(&host, &generation),
        operation: operation("kernel-illegal"),
        activation_identity: h("activation-one"),
        approved_artifact_hash: h("sha256-kernel-artifact"),
        active_pipe_identity: h("kernel-stable-pipe"),
        candidate_pipe_identity: Some(h("kernel-candidate-pipe")),
        candidate_job_binding: Some(KernelJobBinding {
            job_identity: h("kernel-job"),
            root_process_identity: h("kernel-root"),
            member_processes: vec![h("kernel-root")],
            root_reaped: false,
        }),
        prior_kernel_disposition: PriorKernelDisposition::NoPriorKernel,
        kernel_generation: step("kernel-lineage", 1),
        one_time_nonce: OneTimeNonceState {
            nonce_ref: Some(h("kernel-nonce")),
            state: NonceState::Consumed,
        },
        state: KernelActivationState::Active,
        process: Some(ready_kernel_process()),
        readiness_evidence: vec![h("kernel-ready")],
        disposition_evidence: vec![h("kernel-disposition")],
    });
    assert!(matches!(
        journal.append(record),
        Err(JournalError::IllegalTransition {
            machine: "kernel",
            ..
        })
    ));
}
