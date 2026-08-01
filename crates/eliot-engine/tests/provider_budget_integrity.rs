use eliot_engine::{
    EngineError, ProviderCallCampaignRequest, ProviderCallReservationDecision,
    ProviderCallReservationOwner, ProviderCallReservationRequest,
};
use eliot_types::{ProjectId, ProviderCallReservationState, TaskId};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use std::thread::JoinHandle;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> TestResult<Self> {
        let path =
            std::env::temp_dir().join(format!("eliot-l1b-r-{label}-{}", ProjectId::new_v7()));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn request(campaign: &str, key: &str) -> ProviderCallReservationRequest {
    ProviderCallReservationRequest {
        campaign_id: campaign.to_owned(),
        task_id: TaskId::new_v7(),
        provider: "antigravity".to_owned(),
        idempotency_key: key.to_owned(),
        gate_decision_ref: "delegation-decision:test".to_owned(),
    }
}

fn open_campaign(
    owner: &ProviderCallReservationOwner,
    campaign_id: &str,
    max_calls: u32,
) -> TestResult {
    owner.open_campaign(ProviderCallCampaignRequest {
        campaign_id: campaign_id.to_owned(),
        max_calls,
        closed: false,
    })?;
    Ok(())
}

fn reserved(decision: ProviderCallReservationDecision) -> TestResult<String> {
    match decision {
        ProviderCallReservationDecision::Reserved(value) => Ok(value.reservation_id),
        other => Err(format!("expected reservation, found {other:?}").into()),
    }
}

fn join_decisions(
    handles: Vec<JoinHandle<Result<ProviderCallReservationDecision, EngineError>>>,
) -> TestResult<Vec<ProviderCallReservationDecision>> {
    let mut decisions = Vec::with_capacity(handles.len());
    for handle in handles {
        let decision = handle
            .join()
            .map_err(|_| std::io::Error::other("reservation thread panicked"))??;
        decisions.push(decision);
    }
    Ok(decisions)
}

#[test]
fn reservation_cannot_create_or_size_its_campaign() -> TestResult {
    let root = TempRoot::new("controller-owned")?;
    let owner = ProviderCallReservationOwner::new(root.path());
    assert!(
        owner
            .reserve(request("campaign:controller-owned", "first"))
            .is_err()
    );
    open_campaign(&owner, "campaign:controller-owned", 1)?;
    assert!(matches!(
        owner.reserve(request("campaign:controller-owned", "first"))?,
        ProviderCallReservationDecision::Reserved(_)
    ));
    Ok(())
}

#[test]
fn concurrent_distinct_requests_cannot_exceed_campaign_limit() -> TestResult {
    let root = TempRoot::new("concurrent-distinct")?;
    let owner = Arc::new(ProviderCallReservationOwner::new(root.path()));
    open_campaign(&owner, "campaign:concurrent", 1)?;
    let barrier = Arc::new(Barrier::new(16));
    let handles = (0..16)
        .map(|index| {
            let owner = Arc::clone(&owner);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                owner.reserve(request("campaign:concurrent", &format!("key-{index}")))
            })
        })
        .collect::<Vec<_>>();
    let decisions = join_decisions(handles)?;
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, ProviderCallReservationDecision::Reserved(_)))
            .count(),
        1
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, ProviderCallReservationDecision::BudgetExceeded))
            .count(),
        15
    );
    let ledger = owner.snapshot()?;
    assert_eq!(ledger.reservations.len(), 1);
    assert_eq!(ledger.budgets[0].remaining_calls, 0);
    Ok(())
}

#[test]
fn concurrent_same_key_is_one_reservation_and_idempotent_replay() -> TestResult {
    let root = TempRoot::new("concurrent-idempotent")?;
    let owner = Arc::new(ProviderCallReservationOwner::new(root.path()));
    open_campaign(&owner, "campaign:idempotent", 1)?;
    let barrier = Arc::new(Barrier::new(12));
    let handles = (0..12)
        .map(|_| {
            let owner = Arc::clone(&owner);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                owner.reserve(request("campaign:idempotent", "stable-key"))
            })
        })
        .collect::<Vec<_>>();
    let decisions = join_decisions(handles)?;
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, ProviderCallReservationDecision::Reserved(_)))
            .count(),
        1
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(
                decision,
                ProviderCallReservationDecision::IdempotentReplay(_)
            ))
            .count(),
        11
    );
    assert_eq!(owner.snapshot()?.reservations.len(), 1);
    Ok(())
}

#[test]
fn unknown_dispatch_outcome_consumes_slot_and_forbids_blind_retry() -> TestResult {
    let root = TempRoot::new("unknown-outcome")?;
    let owner = ProviderCallReservationOwner::new(root.path());
    open_campaign(&owner, "campaign:unknown", 1)?;
    let reservation_id = reserved(owner.reserve(request("campaign:unknown", "first"))?)?;
    owner.mark_dispatching(&reservation_id)?;
    owner.mark_dispatched(&reservation_id, "external-invocation:test")?;
    let unknown = owner.mark_unknown_outcome(&reservation_id, "transport ended after dispatch")?;
    assert_eq!(unknown.state, ProviderCallReservationState::UnknownOutcome);
    assert!(unknown.consumes_budget);
    assert!(matches!(
        owner.reserve(request("campaign:unknown", "retry"))?,
        ProviderCallReservationDecision::BudgetExceeded
    ));
    assert!(
        owner
            .release_pre_dispatch(&reservation_id, "cannot prove no dispatch")
            .is_err()
    );
    Ok(())
}

#[test]
fn proven_pre_dispatch_failure_releases_slot() -> TestResult {
    let root = TempRoot::new("release")?;
    let owner = ProviderCallReservationOwner::new(root.path());
    open_campaign(&owner, "campaign:release", 1)?;
    let reservation_id = reserved(owner.reserve(request("campaign:release", "first"))?)?;
    owner.mark_dispatching(&reservation_id)?;
    let released = owner.release_pre_dispatch(&reservation_id, "provider process not started")?;
    assert_eq!(
        released.state,
        ProviderCallReservationState::ReleasedPreDispatch
    );
    assert!(!released.consumes_budget);
    assert!(matches!(
        owner.reserve(request("campaign:release", "second"))?,
        ProviderCallReservationDecision::Reserved(_)
    ));
    Ok(())
}

#[test]
fn campaign_close_blocks_reserved_slot_from_entering_dispatch() -> TestResult {
    let root = TempRoot::new("close-race")?;
    let owner = ProviderCallReservationOwner::new(root.path());
    open_campaign(&owner, "campaign:closed", 1)?;
    let reservation_id = reserved(owner.reserve(request("campaign:closed", "first"))?)?;
    owner.close_campaign("campaign:closed")?;
    assert!(owner.mark_dispatching(&reservation_id).is_err());
    assert!(matches!(
        owner.reserve(request("campaign:closed", "second"))?,
        ProviderCallReservationDecision::CampaignClosed
    ));
    owner.release_pre_dispatch(&reservation_id, "campaign closed before dispatch")?;
    Ok(())
}

#[test]
fn completed_reservation_survives_restart_and_replays_review() -> TestResult {
    let root = TempRoot::new("completed-restart")?;
    let reservation_id = {
        let owner = ProviderCallReservationOwner::new(root.path());
        open_campaign(&owner, "campaign:complete", 1)?;
        let reservation_id = reserved(owner.reserve(request("campaign:complete", "stable"))?)?;
        owner.mark_dispatching(&reservation_id)?;
        owner.mark_dispatched(&reservation_id, "external-invocation:complete")?;
        owner.complete(&reservation_id, "executed-review:complete")?;
        reservation_id
    };
    let restarted = ProviderCallReservationOwner::new(root.path());
    let replay = restarted.reserve(request("campaign:complete", "stable"))?;
    match replay {
        ProviderCallReservationDecision::IdempotentReplay(value) => {
            assert_eq!(value.reservation_id, reservation_id);
            assert_eq!(
                value.review_ref.as_deref(),
                Some("executed-review:complete")
            );
            assert_eq!(value.state, ProviderCallReservationState::Completed);
        }
        other => return Err(format!("expected completed replay, found {other:?}").into()),
    }
    Ok(())
}

#[test]
fn dispatching_reservation_survives_restart_without_refund() -> TestResult {
    let root = TempRoot::new("dispatching-restart")?;
    let reservation_id = {
        let owner = ProviderCallReservationOwner::new(root.path());
        open_campaign(&owner, "campaign:restart", 1)?;
        let reservation_id = reserved(owner.reserve(request("campaign:restart", "first"))?)?;
        owner.mark_dispatching(&reservation_id)?;
        reservation_id
    };
    let restarted = ProviderCallReservationOwner::new(root.path());
    let unknown = restarted.mark_unknown_outcome(&reservation_id, "controller restarted")?;
    assert_eq!(unknown.state, ProviderCallReservationState::UnknownOutcome);
    assert!(matches!(
        restarted.reserve(request("campaign:restart", "retry"))?,
        ProviderCallReservationDecision::BudgetExceeded
    ));
    Ok(())
}

#[test]
fn immutable_campaign_max_rejects_late_budget_expansion() -> TestResult {
    let root = TempRoot::new("immutable-max")?;
    let owner = ProviderCallReservationOwner::new(root.path());
    open_campaign(&owner, "campaign:immutable", 1)?;
    let _ = owner.reserve(request("campaign:immutable", "first"))?;
    assert!(
        owner
            .open_campaign(ProviderCallCampaignRequest {
                campaign_id: "campaign:immutable".to_owned(),
                max_calls: 2,
                closed: false,
            })
            .is_err()
    );
    assert_eq!(owner.snapshot()?.budgets[0].max_calls, 1);
    Ok(())
}
