use std::error::Error;

use eliot_contracts::{AuthorityEpoch, ClockReading, ResourceGeneration, StateFence};
use eliot_coordination::{
    CoordinationError, CoordinationEventKind, CoordinationOwner, RegisterSession, WorkItem,
    WorkLeaseIssuanceProvenance, WorkLeaseIssuanceResult, WorkLeaseRequest, WorkState,
};

type TestResult = Result<(), Box<dyn Error>>;

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

fn ready_owner() -> Result<(CoordinationOwner, StateFence), CoordinationError> {
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

fn request(state_fence: &StateFence) -> WorkLeaseRequest {
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

fn assert_public_type<T>() {}

#[test]
fn coordination_package_owns_public_issuance_result_and_provenance() {
    assert_public_type::<WorkLeaseIssuanceResult>();
    assert_public_type::<WorkLeaseIssuanceProvenance>();
}

#[test]
fn exact_accepted_retry_returns_the_same_owner_issued_identity_and_provenance() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let claim = request(&state_fence);

    let first = owner.acquire_work_with_issuance(claim.clone())?;
    let replay = owner.acquire_work_with_issuance(claim)?;

    assert_eq!(first, replay);
    assert_eq!(first.decision().event.kind, CoordinationEventKind::WorkClaimed);
    assert_eq!(first.decision().lease.lease_id, "legacy-lease-1");
    assert_eq!(first.work_lease_id(), replay.work_lease_id());
    assert_eq!(
        first.evidence_commitment_sha256(),
        replay.evidence_commitment_sha256()
    );
    let commitment = first.evidence_commitment_sha256();
    assert_eq!(commitment.len(), 64);
    assert!(commitment
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_eq!(owner.current_sequence(), 3);
    Ok(())
}

#[test]
fn changed_bytes_under_the_same_request_identity_create_no_second_lease() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let claim = request(&state_fence);
    let issued = owner.acquire_work_with_issuance(claim.clone())?;
    let sequence = owner.current_sequence();

    let mut conflict = claim;
    conflict.lease_id = "different-legacy-lease".to_owned();
    assert_eq!(
        owner.acquire_work_with_issuance(conflict),
        Err(CoordinationError::IdempotencyConflict(
            "claim-work".to_owned()
        ))
    );
    assert_eq!(owner.current_sequence(), sequence);
    let projection = owner.read_active_work_lease(
        "work-1",
        "session-1",
        30,
        AuthorityEpoch::genesis(),
        &state_fence,
    )?;
    assert_eq!(projection.lease.lease_id, "legacy-lease-1");
    assert_eq!(issued.decision().lease, projection.lease);
    Ok(())
}

#[test]
fn rejected_fence_emits_no_owner_issued_identity_or_coordination_event() -> TestResult {
    let (mut owner, state_fence) = ready_owner()?;
    let sequence = owner.current_sequence();
    let stale_fence = StateFence::new(
        AuthorityEpoch::genesis(),
        ResourceGeneration::new(2)?,
    );
    let mut stale = request(&state_fence);
    stale.state_fence = stale_fence;

    assert_eq!(
        owner.acquire_work_with_issuance(stale),
        Err(CoordinationError::FenceMismatch)
    );
    assert_eq!(owner.current_sequence(), sequence);
    assert_eq!(
        owner.read_unique_active_work_lease(
            30,
            AuthorityEpoch::genesis(),
            &state_fence,
        ),
        Err(CoordinationError::NoActiveBinding)
    );
    Ok(())
}
