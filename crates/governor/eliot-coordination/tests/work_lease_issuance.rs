use eliot_contracts::{
    AuthorityEpoch, ClockReading, ResourceGeneration, StateFence, canonical_json_bytes,
};
use eliot_coordination::{
    AgentHeartbeat, AgentSession, CoordinationError, CoordinationOwner, RegisterSession,
    SessionState, WorkItem, WorkLeaseIssuanceDisposition, WorkLeaseIssuanceError,
    WorkLeaseIssuanceFailure, WorkLeaseRequest, WorkState,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn clock() -> ClockReading {
    ClockReading {
        valid_time_ms: None,
        known_time_ms: None,
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

fn ready_owner() -> TestResult<(CoordinationOwner, StateFence)> {
    let mut owner = CoordinationOwner::new();
    let state_fence = fence();
    owner.register_session(RegisterSession {
        request_id: "register-session".to_owned(),
        session_id: "session-1".to_owned(),
        principal_id: "principal-1".to_owned(),
        route_ref: "route-1".to_owned(),
        authority_epoch: AuthorityEpoch::genesis(),
        state_fence: state_fence.clone(),
        now: 10,
        heartbeat_deadline: 100,
    })?;
    register_work(&mut owner, &state_fence, "work-1", "task-1", "register-work")?;
    Ok((owner, state_fence))
}

fn register_work(
    owner: &mut CoordinationOwner,
    state_fence: &StateFence,
    work_item_id: &str,
    task_id: &str,
    request_id: &str,
) -> TestResult {
    owner.register_work(
        WorkItem {
            work_item_id: work_item_id.to_owned(),
            task_id: task_id.to_owned(),
            state: WorkState::Ready,
            state_fence: state_fence.clone(),
            owner_session_id: None,
            lease_id: None,
            attempt: 0,
            checkpoint_ref: None,
            result_ref: None,
        },
        request_id,
        "principal-1",
        clock(),
    )?;
    Ok(())
}

fn lease_request(state_fence: &StateFence) -> WorkLeaseRequest {
    WorkLeaseRequest {
        request_id: "claim-work".to_owned(),
        lease_id: "legacy-lease-1".to_owned(),
        work_item_id: "work-1".to_owned(),
        session_id: "session-1".to_owned(),
        authority_epoch: AuthorityEpoch::genesis(),
        state_fence: state_fence.clone(),
        now: 20,
        lease_duration: 40,
    }
}

fn issuance_error(
    result: Result<eliot_coordination::WorkLeaseIssuanceResult, WorkLeaseIssuanceFailure>,
) -> TestResult<WorkLeaseIssuanceFailure> {
    match result {
        Ok(_) => Err("operation unexpectedly produced canonical WorkLease issuance".into()),
        Err(error) => Ok(error),
    }
}

#[test]
fn current_owner_emits_canonical_work_lease_identity_from_same_call_evidence() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let request = lease_request(&state_fence);
    let result = owner.acquire_work_with_issuance(request.clone())?;

    assert_eq!(
        result.disposition(),
        WorkLeaseIssuanceDisposition::OwnerIssued
    );
    assert_eq!(result.decision().lease.lease_id, request.lease_id);
    assert_eq!(result.provenance().source_request(), &request);
    assert_eq!(result.provenance().source_decision(), result.decision());
    assert_eq!(result.provenance().evidence_commitment_sha256().len(), 64);

    let encoded = canonical_json_bytes(result.provenance().canonical_work_lease_id())?;
    let encoded = String::from_utf8(encoded)?;
    assert!(encoded.contains("\"namespace\":\"eliot.governor.work-lease\""));
    assert!(encoded.contains("\"revision\":\"v1\""));
    assert!(encoded.contains(result.provenance().evidence_commitment_sha256()));
    assert!(!encoded.contains("legacy-lease-1"));
    Ok(())
}

#[test]
fn exact_retry_returns_identical_issuance_without_second_event() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let request = lease_request(&state_fence);
    let first = owner.acquire_work_with_issuance(request.clone())?;
    let second = owner.acquire_work_with_issuance(request)?;

    assert_eq!(first.decision(), second.decision());
    assert_eq!(
        first.provenance().canonical_work_lease_id(),
        second.provenance().canonical_work_lease_id()
    );
    assert_eq!(
        first.provenance().evidence_commitment_sha256(),
        second.provenance().evidence_commitment_sha256()
    );
    assert_eq!(owner.events().len(), 3);
    Ok(())
}

#[test]
fn changed_retry_under_issued_request_identity_fails_before_mutation() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let request = lease_request(&state_fence);
    owner.acquire_work_with_issuance(request.clone())?;

    let mut changed = request.clone();
    changed.lease_duration = 41;
    let error = issuance_error(owner.acquire_work_with_issuance(changed))?;
    assert_eq!(
        error,
        WorkLeaseIssuanceFailure::Coordination(CoordinationError::IdempotencyConflict(
            "claim-work".to_owned()
        ))
    );

    let mut changed_identity = request;
    changed_identity.lease_id = "legacy-lease-2".to_owned();
    let error = issuance_error(owner.acquire_work_with_issuance(changed_identity))?;
    assert_eq!(
        error,
        WorkLeaseIssuanceFailure::Coordination(CoordinationError::IdempotencyConflict(
            "claim-work".to_owned()
        ))
    );
    assert_eq!(owner.events().len(), 3);
    Ok(())
}

#[test]
fn compatibility_acquisition_cannot_be_upgraded_to_canonical_issuance() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let request = lease_request(&state_fence);
    owner.acquire_work(request.clone())?;

    let error = issuance_error(owner.acquire_work_with_issuance(request.clone()))?;
    assert_eq!(
        error,
        WorkLeaseIssuanceFailure::Evidence(WorkLeaseIssuanceError::PostHocIssuanceRejected)
    );
    assert_eq!(owner.events().len(), 3);

    let repeated = issuance_error(owner.acquire_work_with_issuance(request))?;
    assert_eq!(repeated, error);
    assert_eq!(owner.events().len(), 3);
    Ok(())
}

#[test]
fn changed_legacy_replay_is_an_idempotency_conflict_not_new_provenance() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let request = lease_request(&state_fence);
    owner.acquire_work(request.clone())?;

    let mut changed = request;
    changed.lease_duration = 41;
    let error = issuance_error(owner.acquire_work_with_issuance(changed))?;
    assert_eq!(
        error,
        WorkLeaseIssuanceFailure::Coordination(CoordinationError::IdempotencyConflict(
            "claim-work".to_owned()
        ))
    );
    assert_eq!(owner.events().len(), 3);
    Ok(())
}

#[test]
fn rejected_acquisition_emits_no_identity_and_keeps_request_reusable() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let request = lease_request(&state_fence);
    let mut invalid = request.clone();
    invalid.lease_duration = 0;

    let error = issuance_error(owner.acquire_work_with_issuance(invalid))?;
    assert_eq!(
        error,
        WorkLeaseIssuanceFailure::Coordination(CoordinationError::InvalidField("lease_duration"))
    );
    assert_eq!(owner.events().len(), 2);

    let accepted = owner.acquire_work_with_issuance(request)?;
    assert_eq!(
        accepted.disposition(),
        WorkLeaseIssuanceDisposition::OwnerIssued
    );
    assert_eq!(owner.events().len(), 3);
    Ok(())
}

#[test]
fn exact_retry_after_recovery_and_heartbeat_returns_original_issuance() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let request = lease_request(&state_fence);
    let original = owner.acquire_work_with_issuance(request.clone())?;
    let original_id = original.provenance().canonical_work_lease_id().clone();
    let original_commitment = original
        .provenance()
        .evidence_commitment_sha256()
        .to_owned();
    let original_decision = original.provenance().source_decision().clone();

    let heartbeat = owner.heartbeat(AgentHeartbeat {
        request_id: "heartbeat-1".to_owned(),
        session_id: "session-1".to_owned(),
        lease_id: "legacy-lease-1".to_owned(),
        authority_epoch: AuthorityEpoch::genesis(),
        state_fence,
        now: 30,
        extend_to: 90,
    })?;
    assert_eq!(heartbeat.lease.expires_at, 90);

    let mut recovered = CoordinationOwner::from_snapshot(owner.clone())?;
    let replay = recovered.acquire_work_with_issuance(request)?;
    assert_eq!(replay.decision(), &original_decision);
    assert_eq!(replay.decision().lease.expires_at, 60);
    assert_eq!(replay.provenance().canonical_work_lease_id(), &original_id);
    assert_eq!(
        replay.provenance().evidence_commitment_sha256(),
        original_commitment
    );
    assert_eq!(recovered.events().len(), 4);
    Ok(())
}

#[test]
fn stale_fence_is_rejected_before_issuance() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let mut request = lease_request(&state_fence);
    request.state_fence = StateFence::new(
        AuthorityEpoch::genesis(),
        ResourceGeneration::new(2)?,
    );

    let error = issuance_error(owner.acquire_work_with_issuance(request))?;
    assert_eq!(
        error,
        WorkLeaseIssuanceFailure::Coordination(CoordinationError::FenceMismatch)
    );
    assert_eq!(owner.events().len(), 2);
    Ok(())
}

#[test]
fn stale_epoch_is_rejected_before_issuance() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let stale_epoch = AuthorityEpoch::new(2)?;
    let mut request = lease_request(&state_fence);
    request.authority_epoch = stale_epoch;
    request.state_fence = StateFence::new(stale_epoch, ResourceGeneration::genesis());

    let error = issuance_error(owner.acquire_work_with_issuance(request))?;
    assert_eq!(
        error,
        WorkLeaseIssuanceFailure::Coordination(CoordinationError::FenceMismatch)
    );
    assert_eq!(owner.events().len(), 2);
    Ok(())
}

#[test]
fn reused_scalar_lease_identity_cannot_overwrite_an_existing_lease() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let first_request = lease_request(&state_fence);
    owner.acquire_work_with_issuance(first_request)?;
    register_work(
        &mut owner,
        &state_fence,
        "work-2",
        "task-2",
        "register-work-2",
    )?;

    let second_request = WorkLeaseRequest {
        request_id: "claim-work-2".to_owned(),
        lease_id: "legacy-lease-1".to_owned(),
        work_item_id: "work-2".to_owned(),
        session_id: "session-1".to_owned(),
        authority_epoch: AuthorityEpoch::genesis(),
        state_fence,
        now: 30,
        lease_duration: 40,
    };
    let error = issuance_error(owner.acquire_work_with_issuance(second_request))?;
    assert_eq!(
        error,
        WorkLeaseIssuanceFailure::Coordination(CoordinationError::Duplicate(
            "legacy-lease-1".to_owned()
        ))
    );
    assert_eq!(owner.events().len(), 4);
    Ok(())
}

#[test]
fn source_session_remains_the_current_coordination_owner_record() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let result = owner.acquire_work_with_issuance(lease_request(&state_fence))?;
    let session: AgentSession = owner.read_active_session(
        "session-1",
        30,
        AuthorityEpoch::genesis(),
        &state_fence,
    )?;
    assert_eq!(session.state, SessionState::Active);
    assert_eq!(
        result.provenance().source_decision().lease.holder_session_id,
        session.session_id
    );
    Ok(())
}
