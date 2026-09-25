use std::error::Error;
use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, EpochTransition, OperationId, ProductId, RequestId,
    RequestMetadata, ResourceGeneration, SessionId, SourceId, StateFence,
};
use eliot_host_service::HostWakeIntentAdapter;
use eliot_host_state::{
    ActivationState, EliotActivationRecord, HostInstallationEpoch, HostKernelStoreLineage,
    HostStateJournalService, HostStateRecord, IdempotencyIdentity, LifecycleTimestamps,
    MemoryBackend, ReadinessEvidence, RecordFence, ServiceSafetyClass, WakeRecord,
};
use eliot_kernel_service::{
    UserAutomationRuntimeError, UserAutomationWakeCancellation,
    UserAutomationWakeCancellationTarget, UserAutomationWakePort,
};
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::{WakeIntent, WakeIntentState};
use eliot_store_api::OperationIdentity;

type TestResult = Result<(), Box<dyn Error>>;

fn handle(value: &str) -> PlatformHandle {
    PlatformHandle::new(value.to_owned()).unwrap_or_else(|_| unreachable!())
}

fn epoch(lineage: &str) -> EpochId {
    EpochId::new(
        EpochLineageId::new(lineage).unwrap_or_else(|_| unreachable!()),
        NonZeroU64::new(1).unwrap_or_else(|| unreachable!()),
    )
    .unwrap_or_else(|_| unreachable!())
}

fn transition(lineage: &str) -> EpochTransition {
    EpochTransition {
        current: epoch(lineage),
        parent: None,
    }
}

fn host() -> HostInstallationEpoch {
    HostInstallationEpoch {
        installation: handle("eliot-test-installation"),
        epoch: transition("550e8400-e29b-41d4-a716-446655440000"),
        nonce: handle("eliot-test-host-nonce"),
        recovery: None,
    }
}

fn activation_generation() -> EpochTransition {
    transition("550e8400-e29b-41d4-a716-446655440001")
}

fn record_fence(host: &HostInstallationEpoch) -> RecordFence {
    RecordFence {
        host: host.clone(),
        activation_id: handle("eliot-test-activation"),
        activation_generation: activation_generation(),
    }
}

fn operation(name: &str) -> IdempotencyIdentity {
    IdempotencyIdentity {
        operation_id: handle(name),
        idempotency_key: handle(&format!("key-{name}")),
    }
}

fn activation_record(
    host: &HostInstallationEpoch,
    state: ActivationState,
    name: &str,
) -> HostStateRecord {
    let ready = matches!(
        state,
        ActivationState::ControlReady | ActivationState::Active
    );
    HostStateRecord::Activation(EliotActivationRecord {
        fence: record_fence(host),
        operation: operation(name),
        activation_id: handle("eliot-test-activation"),
        trigger_class: handle("test-trigger"),
        trigger_evidence: vec![handle("test-trigger-evidence")],
        requester_principal_session_or_scheduler: handle("test-principal"),
        requested_capabilities: vec![handle("host-state")],
        candidate_scope: handle("test-scope"),
        state,
        drain_generation: None,
        lineage: HostKernelStoreLineage {
            host_epoch: host.epoch.current.clone(),
            kernel_epoch: epoch("550e8400-e29b-41d4-a716-446655440002"),
            watchdog_epoch: epoch("550e8400-e29b-41d4-a716-446655440003"),
            store_generation: epoch("550e8400-e29b-41d4-a716-446655440004"),
        },
        readiness: ReadinessEvidence {
            supervision_ready: ready,
            control_ready: ready,
            evidence_refs: vec![handle("test-readiness")],
        },
        governance_profile: handle("test-governed"),
        runtime_lease_refs: Vec::new(),
        supervision_lease_refs: Vec::new(),
        wake_intent_refs: Vec::new(),
        drain_commit_ref: None,
        wake_during_drain_disposition: None,
        boot_session_evidence: vec![handle("test-boot")],
        power_transition_evidence: Vec::new(),
        timestamps: LifecycleTimestamps {
            started_at: Some(handle("test-started")),
            ready_at: ready.then(|| handle("test-ready")),
            draining_at: None,
            stopped_at: None,
        },
        failure_and_recovery_directive: None,
    })
}

fn wake_record(host: &HostInstallationEpoch, state_fence: StateFence) -> HostStateRecord {
    let wake_id = "wake-automation-1";
    HostStateRecord::Wake(WakeRecord {
        fence: record_fence(host),
        operation: operation("wake-create"),
        wake_id: handle(wake_id),
        intent: WakeIntent {
            wake_id: wake_id.to_owned(),
            reason: "user automation schedule".to_owned(),
            state_fence,
            state: WakeIntentState::Pending,
        },
        reason_evidence_refs: vec![handle("wake-reason-evidence")],
        earliest_start: handle("t-earliest"),
        deadline: handle("t-deadline"),
        expiry: handle("t-expiry"),
        required_capabilities: vec![handle("kernel-control")],
        maintenance_family: handle("interactive"),
        safety_class: ServiceSafetyClass::ServiceSafe,
        state_fence_revalidation_ref: handle("fence-revalidation"),
        budget_ref: handle("budget-one"),
    })
}

fn request_metadata(state_fence: StateFence) -> RequestMetadata {
    RequestMetadata {
        request_id: RequestId::new("automation-remove-request").unwrap_or_else(|_| unreachable!()),
        session_id: Some(SessionId::new("session-1").unwrap_or_else(|_| unreachable!())),
        task_id: None,
        product_id: ProductId::new("eliot-test").unwrap_or_else(|_| unreachable!()),
        source_id: SourceId::new("eliot-user-automation").unwrap_or_else(|_| unreachable!()),
        state_fence,
        clock: ClockReading {
            valid_time_ms: Some(1),
            known_time_ms: Some(1),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        },
    }
}

fn cancellation(
    context: RequestMetadata,
    target: UserAutomationWakeCancellationTarget,
) -> UserAutomationWakeCancellation {
    UserAutomationWakeCancellation {
        state_fence: context.state_fence.clone(),
        context,
        authenticated_principal: "human-1".to_owned(),
        identity: OperationIdentity {
            operation_id: OperationId::new("automation-remove").unwrap_or_else(|_| unreachable!()),
            idempotency_key: "automation-remove-key".to_owned(),
            canonical_request_hash: "b".repeat(64),
        },
        automation_id: "automation-1".to_owned(),
        automation_revision: "revision-7".to_owned(),
        only_unadmitted: true,
        targets: vec![target],
    }
}

#[tokio::test]
async fn host_wake_adapter_cancels_real_pending_record_and_refuses_wrong_target() -> TestResult {
    let host = host();
    let journal = HostStateJournalService::from_backend(MemoryBackend::default(), host.clone())?;
    for (state, operation_name) in [
        (ActivationState::Starting, "activation-start"),
        (ActivationState::ControlReady, "activation-ready"),
        (ActivationState::Active, "activation-active"),
    ] {
        journal.append(activation_record(&host, state, operation_name))?;
    }

    let state_fence = StateFence::new(host.epoch.current.clone(), ResourceGeneration::genesis());
    let wake = wake_record(&host, state_fence.clone());
    let HostStateRecord::Wake(wake_before) = wake.clone() else {
        unreachable!();
    };
    let wake_checksum = eliot_host_state::record_checksum(&wake)?;
    journal.append(wake)?;

    let target = UserAutomationWakeCancellationTarget {
        automation_id: "automation-1".to_owned(),
        automation_revision: "revision-7".to_owned(),
        wake_id: wake_before.wake_id.as_str().to_owned(),
        operation_id: wake_before.operation.operation_id.as_str().to_owned(),
        idempotency_key: wake_before.operation.idempotency_key.as_str().to_owned(),
        record_checksum: wake_checksum,
        state_fence: state_fence.clone(),
    };
    let adapter = HostWakeIntentAdapter::new(&journal);

    let mut foreign_target = target.clone();
    foreign_target.wake_id = "foreign-wake".to_owned();
    let foreign_error = adapter
        .cancel_pending_wakes(cancellation(
            request_metadata(state_fence.clone()),
            foreign_target,
        ))
        .await
        .expect_err("foreign wake identity must be refused");
    assert!(matches!(
        foreign_error,
        UserAutomationRuntimeError::Rejected(_)
    ));

    let cancelled = adapter
        .cancel_pending_wakes(cancellation(
            request_metadata(state_fence.clone()),
            target.clone(),
        ))
        .await?;
    assert_eq!(cancelled, ["wake-automation-1"]);

    let snapshot = journal.snapshot()?;
    let wake_after = snapshot
        .wakes
        .iter()
        .find(|wake| wake.wake_id == wake_before.wake_id)
        .ok_or("cancelled wake missing from canonical journal")?;
    assert_eq!(wake_after.intent.state, WakeIntentState::Cancelled);
    assert_eq!(wake_after.fence, wake_before.fence);
    assert_eq!(wake_after.wake_id, wake_before.wake_id);
    assert_eq!(wake_after.intent.wake_id, wake_before.intent.wake_id);
    assert_eq!(wake_after.intent.reason, wake_before.intent.reason);
    assert_eq!(
        wake_after.intent.state_fence,
        wake_before.intent.state_fence
    );
    assert_eq!(
        wake_after.reason_evidence_refs,
        wake_before.reason_evidence_refs
    );
    assert_eq!(wake_after.earliest_start, wake_before.earliest_start);
    assert_eq!(wake_after.deadline, wake_before.deadline);
    assert_eq!(wake_after.expiry, wake_before.expiry);
    assert_eq!(
        wake_after.required_capabilities,
        wake_before.required_capabilities
    );
    assert_eq!(
        wake_after.maintenance_family,
        wake_before.maintenance_family
    );
    assert_eq!(wake_after.safety_class, wake_before.safety_class);
    assert_eq!(
        wake_after.state_fence_revalidation_ref,
        wake_before.state_fence_revalidation_ref
    );
    assert_eq!(wake_after.budget_ref, wake_before.budget_ref);

    let stale_error = adapter
        .cancel_pending_wakes(cancellation(request_metadata(state_fence), target))
        .await
        .expect_err("a target bound to the pre-cancellation record is stale");
    assert_eq!(stale_error, UserAutomationRuntimeError::IdentityConflict);

    Ok(())
}
