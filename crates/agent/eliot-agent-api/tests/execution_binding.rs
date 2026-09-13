//! S1 provider-execution binding tests for issue #361 (freeze
//! `A01_PROVIDER_EXECUTION_BINDING_V1`).
//!
//! Unit-level only: no live runtime, no network, no SurrealDB, no daemon.
//! Deferred to later slices (see PR body "Deferred cases"): wrong generation,
//! route drift, multi-rebind, resume/fork lineage, session-spoof.

use eliot_agent_api::{
    AgentAttempt, AgentWorkUnitBrief, AttemptId, AttemptState, AuthorityEnvelope, AuthorityEpoch,
    BudgetEnvelope, CancellationState, ContinuityKind, ContractError, EffectCeiling, EffectKind,
    EventCursor, ExecutionUnit, ExecutionUnitObservation, LaunchRequestId, NativeSession,
    NativeSessionLocator, ProviderExecutionBinding, ProviderObservationLineage, RequestId,
    ResourceGeneration, RouteFingerprint, SessionId, SessionObservation, StateFence, TaskId,
    WorkLeaseId, WorkUnitId, validate_execution_binding,
};
use eliot_contracts::{TaskRevision, sha256_hex};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn route() -> RouteFingerprint {
    RouteFingerprint {
        host_family: "test-host".into(),
        adapter: "test-adapter".into(),
        protocol_transport: "loopback".into(),
        runtime_hash: "sha256:runtime".into(),
        adapter_hash: "sha256:adapter".into(),
        provider: "provider".into(),
        model: "model".into(),
        auth_billing: "subscription".into(),
        serializer_hash: "sha256:serializer".into(),
        tool_semantics_hash: "sha256:tools".into(),
        reasoning_mode: "visible".into(),
        continuation_behavior: "native_resume".into(),
        feature_flags_hash: "sha256:features".into(),
    }
}

fn budget() -> BudgetEnvelope {
    BudgetEnvelope {
        context_tokens: 10_000,
        wall_time_ms: 60_000,
        output_bytes: 1_000_000,
        cost_microunits: 1_000,
        max_depth: 2,
        max_descendants: 4,
    }
}

fn ceiling() -> EffectCeiling {
    EffectCeiling {
        scope_ref: "scope:test".into(),
        allowed: [EffectKind::Observe].into_iter().collect(),
        max_external_effects: 0,
    }
}

fn lease(value: &str) -> Result<WorkLeaseId, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(serde_json::json!({
        "namespace": "eliot.governor.work-lease",
        "revision": "v1",
        "value": value,
    }))?)
}

fn fence() -> Result<StateFence, Box<dyn std::error::Error>> {
    Ok(StateFence::new(
        AuthorityEpoch::new(1)?,
        ResourceGeneration::new(1)?,
    ))
}

fn admitted_attempt() -> Result<AgentAttempt, Box<dyn std::error::Error>> {
    let work_budget = budget();
    Ok(AgentAttempt {
        id: AttemptId::new("attempt-binding-1")?,
        launch_request_id: LaunchRequestId::new("launch-binding-1")?,
        task_id: TaskId::new("task-binding-1")?,
        parent_attempt: None,
        work_unit: AgentWorkUnitBrief {
            id: WorkUnitId::new("unit-binding-1")?,
            objective: "observe".into(),
            causal_property: "provider binding".into(),
            scope_ref: "scope:test".into(),
            expected_outputs: vec!["evidence".into()],
            source_refs: vec!["source".into()],
            verifier_ref: "verifier".into(),
            integration_owner: "owner".into(),
            contract_revision: "v1".into(),
            budget: work_budget.clone(),
            effect_ceiling: ceiling(),
            stop_condition: "verified".into(),
        },
        session: Some(SessionId::new("session-binding-1")?),
        lease: lease("lease-binding-1")?,
        state: AttemptState::Admitted,
        continuity: ContinuityKind::Fresh,
        route: route(),
        budget: work_budget,
        authority: AuthorityEnvelope {
            epoch: AuthorityEpoch::new(1)?,
            scope_ref: "scope:test".into(),
            effect_ceiling: ceiling(),
            lease: lease("lease-binding-1")?,
            state_fence: fence()?,
            valid_until: "2026-09-13T00:00:00Z".into(),
        },
        cancellation: CancellationState::NotRequested,
        event_cursor: None,
        continuation: None,
        provider_binding: None,
    })
}

fn bound_binding(
    admitted: &AgentAttempt,
) -> Result<ProviderExecutionBinding, Box<dyn std::error::Error>> {
    Ok(ProviderExecutionBinding {
        attempt_id: admitted.id.clone(),
        lease_id: admitted.lease.clone(),
        state_fence: fence()?,
        runtime_generation: ResourceGeneration::new(1)?,
        route: admitted.route.clone(),
        session_id: admitted.session.clone(),
        provider_scope_ref: "scope:test".into(),
        native_session: NativeSession::Native(NativeSessionLocator::new("thread-turn-1")?),
        execution_unit: ExecutionUnit::new("codex", "turn-1")?,
        start_request_id: RequestId::new("req-binding-1")?,
        start_request_sha256: sha256_hex(b"req-binding-1"),
    })
}

#[test]
fn exact_binding_tuple_is_accepted() -> TestResult {
    let admitted = admitted_attempt()?;
    let binding = bound_binding(&admitted)?;
    validate_execution_binding(&binding, &admitted, &fence()?, ResourceGeneration::new(1)?)?;
    let mut stored = admitted.clone();
    stored.provider_binding = Some(binding.clone());
    stored.validate()?;
    assert_eq!(stored.attributable_binding()?, &binding);
    Ok(())
}

#[test]
fn changed_turn_is_rejected() -> TestResult {
    let mut admitted = admitted_attempt()?;
    let original = bound_binding(&admitted)?;
    admitted.provider_binding = Some(original.clone());
    // A same-turn steer keeps the same binding and stays attributable.
    validate_execution_binding(&original, &admitted, &fence()?, ResourceGeneration::new(1)?)?;
    // A changed turn against the stored binding is a rebind and fails closed:
    // a new turn is a new attempt, never a silent rebind.
    let mut changed = original;
    changed.execution_unit = ExecutionUnit::new("codex", "turn-2")?;
    assert_eq!(
        validate_execution_binding(&changed, &admitted, &fence()?, ResourceGeneration::new(1)?),
        Err(ContractError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn changed_lease_is_rejected() -> TestResult {
    let admitted = admitted_attempt()?;
    let mut binding = bound_binding(&admitted)?;
    binding.lease_id = lease("lease-other")?;
    assert_eq!(
        validate_execution_binding(&binding, &admitted, &fence()?, ResourceGeneration::new(1)?),
        Err(ContractError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn compatible_but_unequal_fence_is_rejected() -> TestResult {
    let admitted = admitted_attempt()?;
    let binding = bound_binding(&admitted)?;
    let current = StateFence {
        authority_epoch: AuthorityEpoch::new(1)?,
        resource_generation: ResourceGeneration::new(1)?,
        task_revision: Some(TaskRevision::new(1)?),
        policy_revision: None,
        integration_revision: None,
    };
    current
        .validate()
        .map_err(|_| ContractError::InvalidStateFence)?;
    // Premise: compatible under `is_compatible_with`, yet not equal.
    assert!(binding.state_fence.is_compatible_with(&current));
    assert_ne!(binding.state_fence, current);
    assert_eq!(
        validate_execution_binding(&binding, &admitted, &current, ResourceGeneration::new(1)?),
        Err(ContractError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn session_only_observation_carries_no_attempt_authority() -> TestResult {
    let session_only = ProviderObservationLineage::SessionObservation(SessionObservation {
        session_id: Some(SessionId::new("session-binding-1")?),
        native: NativeSession::Native(NativeSessionLocator::new("thread-turn-1")?),
    });
    assert_eq!(
        session_only.attributable_binding().err(),
        Some(ContractError::BindingMismatch)
    );
    let admitted = admitted_attempt()?;
    let binding = bound_binding(&admitted)?;
    let unit_observation =
        ProviderObservationLineage::ExecutionUnitObservation(ExecutionUnitObservation {
            binding: binding.clone(),
            cursor: EventCursor::new("cursor-1")?,
            sequence: 1,
        });
    assert_eq!(unit_observation.attributable_binding()?, &binding);
    Ok(())
}

#[test]
fn missing_binding_yields_no_attributable_output() -> TestResult {
    let admitted = admitted_attempt()?;
    assert!(admitted.provider_binding.is_none());
    // An unresolved launch is representable: the attempt itself validates.
    admitted.validate()?;
    // But no output is attributable without a binding: fail closed.
    assert_eq!(
        admitted.attributable_binding().err(),
        Some(ContractError::BindingMismatch)
    );
    Ok(())
}
