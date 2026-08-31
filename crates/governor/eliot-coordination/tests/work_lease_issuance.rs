use eliot_contracts::{
    AuthorityEpoch, ClockReading, ResourceGeneration, StateFence, canonical_json_bytes,
};
use eliot_coordination::{
    AgentHeartbeat, AgentSession, CoordinationError, CoordinationOwner, RegisterSession,
    SessionState, WorkItem, WorkLeaseIssuanceDisposition, WorkLeaseIssuanceFailure,
    WorkLeaseRequest, WorkState,
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
    owner.register_work(
        WorkItem {
            work_item_id: "work-1".to_owned(),
            task_id: "task-1".to_owned(),
            state: WorkState::Ready,
            state_fence: state_fence.clone(),
            owner_session_id: None,
            lease_id: None,
            attempt: 0,
            checkpoint_ref: None,
            result_ref: None,
        },
        "register-work",
        "principal-1",
        clock(),
    )?;
    Ok((owner, state_fence))
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
    assert_eq!(
        result.provenance().evidence_commitment_sha256().len(),
        64
    );

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
fn changed_request_under_same_identity_is_an_idempotency_conflict() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let request = lease_request(&state_fence);
    owner.acquire_work_with_issuance(request.clone())?;

    let mut changed = request.clone();
    changed.lease_duration = 41;
    let error = match owner.acquire_work_with_issuance(changed) {
        Ok(_) => return Err("changed retry unexpectedly produced an issuance".into()),
        Err(error) => error,
    };
    assert_eq!(
        error,
        WorkLeaseIssuanceFailure::Coordination(CoordinationError::IdempotencyConflict(
            "claim-work".to_owned()
        ))
    );

    let mut changed_identity = request;
    changed_identity.lease_id = "legacy-lease-2".to_owned();
    let error = match owner.acquire_work_with_issuance(changed_identity) {
        Ok(_) => return Err("changed lease identity unexpectedly produced an issuance".into()),
        Err(error) => error,
    };
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
fn rejected_acquisition_emits_no_canonical_identity() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let mut request = lease_request(&state_fence);
    request.lease_duration = 0;
    let error = match owner.acquire_work_with_issuance(request) {
        Ok(_) => return Err("invalid acquisition unexpectedly produced an issuance".into()),
        Err(error) => error,
    };
    assert_eq!(
        error,
        WorkLeaseIssuanceFailure::Coordination(CoordinationError::InvalidField("lease_duration"))
    );
    assert_eq!(owner.events().len(), 2);
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
    let stale_generation = ResourceGeneration::new(2)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    request.state_fence = StateFence::new(AuthorityEpoch::genesis(), stale_generation);
    let error = match owner.acquire_work_with_issuance(request) {
        Ok(_) => return Err("stale fence unexpectedly produced an issuance".into()),
        Err(error) => error,
    };
    assert_eq!(
        error,
        WorkLeaseIssuanceFailure::Coordination(CoordinationError::FenceMismatch)
    );
    assert_eq!(owner.events().len(), 2);
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
