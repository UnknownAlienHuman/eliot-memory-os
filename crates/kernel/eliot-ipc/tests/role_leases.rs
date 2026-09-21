//! Minimal acceptance proof for issue #1943 (I7.21 role leases).
//!
//! Scope is the `eliot-ipc` role-lease boundary only:
//! `crates/kernel/eliot-ipc/src/role_lease.rs`. Every test calls the real
//! public API: a Task Controller context that transitions to Worker cannot
//! overwrite the active plan or finish the task (including via the revoked
//! prior context), and a verifier context creates scoped evaluation
//! candidates but rejects implementation mutation unless a separately
//! issued, explicitly downgraded role context is active.

use eliot_contracts::{EpochId, EpochLineageId};
use eliot_ipc::{
    AgentRole, CapabilityContext, DelegatedAuthority, IndependenceDowngrade, ScopeBinding,
    WorkScopePolicy, op,
};
use std::num::NonZeroU64;

const NOW: u64 = 1_800_000_000_000;
const ISSUED: u64 = 1_799_999_000_000;
const EXPIRES: u64 = 1_800_000_100_000;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn some<T>(option: Option<T>) -> T {
    match option {
        Some(value) => value,
        None => panic!("unexpected none"),
    }
}

fn epoch(sequence: u64) -> EpochId {
    let lineage = ok(EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000"));
    ok(EpochId::new(lineage, some(NonZeroU64::new(sequence))))
}

fn binding(work_item: Option<&str>, lease_epoch: u64) -> ScopeBinding {
    ScopeBinding {
        scope: "task-envelope-7".to_owned(),
        task_id: "task-7".to_owned(),
        work_item_id: work_item.map(str::to_owned),
        route: "agent-swarm".to_owned(),
        governance_revision: "gov-r11".to_owned(),
        authority_epoch: epoch(3),
        lease_epoch,
        issued_at_unix_ms: ISSUED,
        expires_at_unix_ms: EXPIRES,
    }
}

fn open() -> WorkScopePolicy {
    WorkScopePolicy { allow_subset: None }
}

fn no_delegation() -> DelegatedAuthority {
    DelegatedAuthority { allow_subset: None }
}

#[test]
fn controller_to_worker_revokes_prior_authority() {
    let mut context = ok(CapabilityContext::admit(
        "ctx-controller-1",
        AgentRole::TaskController,
        binding(None, 1),
        &open(),
        &no_delegation(),
    ));
    ok(context.active().authorize(op::PLAN_REVISE, NOW));

    let record = ok(context.transition(
        "ctx-worker-2",
        AgentRole::Worker,
        &binding(Some("work-item-9"), 2),
        &open(),
        &no_delegation(),
        None,
        NOW,
    ));
    assert_eq!(record.prev_role, AgentRole::TaskController);
    assert_eq!(record.new_role, AgentRole::Worker);
    assert!(!record.independence_downgraded);

    // Worker context cannot overwrite the active plan or finish the task.
    assert!(context.active().authorize(op::PLAN_OVERWRITE, NOW).is_err());
    assert!(context.active().authorize(op::TASK_FINISH, NOW).is_err());
    assert!(context.active().authorize(op::PLAN_REVISE, NOW).is_err());
    // Worker keeps its own lease-covered authority.
    ok(context.active().authorize(op::WORK_ITEM_ACT, NOW));

    // The preceding controller context is closed: residual authority is gone.
    let prior = some(
        context
            .revoked()
            .iter()
            .find(|token| token.context_id() == record.prev_context_id),
    );
    assert!(prior.revoked());
    assert!(prior.authorize(op::PLAN_REVISE, NOW).is_err());
    assert_eq!(
        context.independence().roles_held,
        vec![AgentRole::TaskController, AgentRole::Worker]
    );
}

#[test]
fn verifier_rejects_implementation_mutation_without_downgrade() {
    let mut context = ok(CapabilityContext::admit(
        "ctx-verifier-1",
        AgentRole::Verifier,
        binding(Some("eval-item-3"), 1),
        &open(),
        &no_delegation(),
    ));
    ok(context
        .active()
        .authorize(op::EVALUATION_CANDIDATE_CREATE, NOW));
    ok(context.active().authorize(op::VERIFICATION_RUN, NOW));
    assert!(
        context
            .active()
            .authorize(op::IMPLEMENTATION_MUTATE, NOW)
            .is_err()
    );

    // Silent relabeling to worker is rejected: no downgrade record, no move.
    let rejected = context.transition(
        "ctx-worker-2",
        AgentRole::Worker,
        &binding(Some("eval-item-3"), 2),
        &open(),
        &no_delegation(),
        None,
        NOW,
    );
    assert!(rejected.is_err());
    assert_eq!(context.active().role(), AgentRole::Verifier);

    // An explicitly downgraded, separately issued worker context mutates
    // under worker authority while the profile records the downgrade.
    let downgrade = IndependenceDowngrade {
        from_role: AgentRole::Verifier,
        to_role: AgentRole::Worker,
        reason: "separate implementation pass after evaluation; independence downgraded".to_owned(),
        recorded_at_unix_ms: NOW,
    };
    let record = ok(context.transition(
        "ctx-worker-2",
        AgentRole::Worker,
        &binding(Some("eval-item-3"), 2),
        &open(),
        &no_delegation(),
        Some(downgrade),
        NOW,
    ));
    assert!(record.independence_downgraded);
    ok(context.active().authorize(op::WORK_ITEM_ACT, NOW));
    assert!(context.independence().downgraded);
    assert_eq!(context.independence().downgrade_records.len(), 1);
    // The verifier context itself never authorizes the mutation.
    let verifier = some(
        context
            .revoked()
            .iter()
            .find(|token| token.context_id() == record.prev_context_id),
    );
    assert!(verifier.authorize(op::IMPLEMENTATION_MUTATE, NOW).is_err());
}

#[test]
fn lease_window_opening_is_enforced_fail_closed() {
    let context = ok(CapabilityContext::admit(
        "ctx-worker-window-1",
        AgentRole::Worker,
        binding(Some("work-item-9"), 1),
        &open(),
        &no_delegation(),
    ));
    // Before owner-observed issuance the token authorizes nothing.
    assert!(
        context
            .active()
            .authorize(op::WORK_ITEM_ACT, ISSUED - 1)
            .is_err()
    );
    ok(context.active().authorize(op::WORK_ITEM_ACT, NOW));
    assert!(
        context
            .active()
            .authorize(op::WORK_ITEM_ACT, EXPIRES)
            .is_err()
    );
}
