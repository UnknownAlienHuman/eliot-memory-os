use crate::{EngineError, work_lease_is_active};
use eliot_types::{
    DelegationBudget, DelegationDecision, DelegationDecisionKind, DelegationJob,
    DelegationJobState, DelegationOrigin, DelegationOutcome, DelegationOutcomeStatus,
    DelegationPublicStatus, DelegationReason, DelegationRequest, DelegationReviewResponse,
    DelegationState, ProviderCallBudgetState, ProviderCallLedger, ProviderCallReservation,
    ProviderCallReservationState, TaskId, WorkLease, WorktreeLease,
};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};

const PROVIDER_ID: &str = "antigravity";
const CONSTRAINTS: [&str; 3] = ["candidate_only", "tainted", "disposable_worktree"];

#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct DelegationPolicyContext {
    pub incident_lockdown: bool,
    pub forbidden_data_exposure: bool,
    pub g3b_done_verified: bool,
    pub provider_available: bool,
    pub provider_healthy: bool,
    pub provider_version_supported: bool,
    pub plugin_and_mcp_verified: bool,
    pub active_work_lease: bool,
    pub budget_available: bool,
    pub cooldown_active: bool,
    pub duplicate_fresh_review: bool,
}

impl Default for DelegationPolicyContext {
    fn default() -> Self {
        Self {
            incident_lockdown: false,
            forbidden_data_exposure: false,
            g3b_done_verified: true,
            provider_available: true,
            provider_healthy: true,
            provider_version_supported: true,
            plugin_and_mcp_verified: true,
            active_work_lease: true,
            budget_available: true,
            cooldown_active: false,
            duplicate_fresh_review: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DelegationPolicyService;

impl DelegationPolicyService {
    #[must_use]
    pub fn decide(
        &self,
        request: &DelegationRequest,
        context: &DelegationPolicyContext,
    ) -> DelegationDecision {
        if let Some(reason) = hard_denial(request, context) {
            return decision(request, DelegationDecisionKind::Deny, vec![reason]);
        }
        let triggers = strong_triggers(&request.question);
        match request.origin {
            DelegationOrigin::UserDirected => decision(
                request,
                DelegationDecisionKind::Execute,
                vec![DelegationReason::ExplicitUserRequest],
            ),
            DelegationOrigin::CodexRequested if !triggers.is_empty() => {
                decision(request, DelegationDecisionKind::Execute, triggers)
            }
            DelegationOrigin::CodexRequested => decision(
                request,
                DelegationDecisionKind::NoExternalReview,
                vec![DelegationReason::TrivialDeterministicTask],
            ),
            DelegationOrigin::PolicyShadow if triggers.is_empty() => decision(
                request,
                DelegationDecisionKind::NoExternalReview,
                vec![DelegationReason::TrivialDeterministicTask],
            ),
            DelegationOrigin::PolicyShadow => {
                decision(request, DelegationDecisionKind::ShadowRecommend, triggers)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegationBudgetReservation {
    Reserved,
    BudgetExceeded,
    CooldownActive,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DelegationBudgetService;

impl DelegationBudgetService {
    #[must_use]
    pub fn for_task(&self, task_id: eliot_types::TaskId) -> DelegationBudget {
        DelegationBudget {
            budget_id: new_id("delegation-budget"),
            task_id,
            provider_id: PROVIDER_ID.to_owned(),
            user_directed_limit: 2,
            codex_requested_limit: 1,
            user_directed_used: 0,
            codex_requested_used: 0,
            transient_retry_limit: 1,
            transient_retries_used: 0,
            cooldown_seconds: 300,
            last_execution_at: None,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn reserve(
        &self,
        budget: &mut DelegationBudget,
        origin: DelegationOrigin,
        now: OffsetDateTime,
    ) -> DelegationBudgetReservation {
        let limit_exceeded = match origin {
            DelegationOrigin::UserDirected => {
                budget.user_directed_used >= budget.user_directed_limit
            }
            DelegationOrigin::CodexRequested => {
                budget.codex_requested_used >= budget.codex_requested_limit
            }
            DelegationOrigin::PolicyShadow => return DelegationBudgetReservation::Reserved,
        };
        if limit_exceeded {
            return DelegationBudgetReservation::BudgetExceeded;
        }
        if budget.last_execution_at.is_some_and(|last| {
            now < last
                + Duration::seconds(i64::try_from(budget.cooldown_seconds).unwrap_or(i64::MAX))
        }) {
            return DelegationBudgetReservation::CooldownActive;
        }
        match origin {
            DelegationOrigin::UserDirected => budget.user_directed_used += 1,
            DelegationOrigin::CodexRequested => budget.codex_requested_used += 1,
            DelegationOrigin::PolicyShadow => {}
        }
        budget.last_execution_at = Some(now);
        DelegationBudgetReservation::Reserved
    }

    pub fn release(&self, budget: &mut DelegationBudget, origin: DelegationOrigin) {
        match origin {
            DelegationOrigin::UserDirected => {
                budget.user_directed_used = budget.user_directed_used.saturating_sub(1);
            }
            DelegationOrigin::CodexRequested => {
                budget.codex_requested_used = budget.codex_requested_used.saturating_sub(1);
            }
            DelegationOrigin::PolicyShadow => {}
        }
        budget.last_execution_at = None;
    }

    pub fn reserve_transient_retry(&self, budget: &mut DelegationBudget) -> bool {
        if budget.transient_retries_used >= budget.transient_retry_limit {
            return false;
        }
        budget.transient_retries_used += 1;
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCallReservationRequest {
    pub campaign_id: String,
    pub task_id: TaskId,
    pub provider: String,
    pub idempotency_key: String,
    pub gate_decision_ref: String,
    pub max_calls: u32,
    pub campaign_closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderCallReservationDecision {
    Reserved(ProviderCallReservation),
    IdempotentReplay(ProviderCallReservation),
    BudgetExceeded,
    CampaignClosed,
}

#[derive(Clone, Debug)]
pub struct ProviderCallReservationOwner {
    root: PathBuf,
}

impl ProviderCallReservationOwner {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn reserve(
        &self,
        request: ProviderCallReservationRequest,
    ) -> Result<ProviderCallReservationDecision, EngineError> {
        self.mutate(|ledger| {
            if let Some(existing) = ledger.reservations.iter().find(|reservation| {
                reservation.campaign_id == request.campaign_id
                    && reservation.idempotency_key == request.idempotency_key
            }) {
                return Ok(ProviderCallReservationDecision::IdempotentReplay(
                    existing.clone(),
                ));
            }
            let budget_index = ensure_provider_call_budget(ledger, &request)?;
            if request.campaign_closed || ledger.budgets[budget_index].closed {
                return Ok(ProviderCallReservationDecision::CampaignClosed);
            }
            refresh_provider_call_budget(ledger, budget_index);
            if ledger.budgets[budget_index].remaining_calls == 0 {
                return Ok(ProviderCallReservationDecision::BudgetExceeded);
            }
            let now = OffsetDateTime::now_utc();
            let slot_index = ledger.budgets[budget_index].next_slot_index;
            ledger.budgets[budget_index].next_slot_index = slot_index.saturating_add(1);
            ledger.budgets[budget_index].revision =
                ledger.budgets[budget_index].revision.saturating_add(1);
            let reservation = ProviderCallReservation {
                reservation_id: new_id("provider-call-reservation"),
                campaign_id: request.campaign_id,
                task_id: request.task_id,
                provider: request.provider,
                idempotency_key: request.idempotency_key,
                slot_index,
                budget_revision: ledger.budgets[budget_index].revision,
                gate_decision_ref: request.gate_decision_ref,
                state: ProviderCallReservationState::Reserved,
                reserved_at: now,
                dispatch_started_at: None,
                external_invocation_ref: None,
                review_ref: None,
                terminal_at: None,
                consumes_budget: true,
                release_or_failure_reason: None,
            };
            ledger.reservations.push(reservation.clone());
            refresh_provider_call_budget(ledger, budget_index);
            Ok(ProviderCallReservationDecision::Reserved(reservation))
        })
    }

    pub fn mark_dispatching(
        &self,
        reservation_id: &str,
    ) -> Result<ProviderCallReservation, EngineError> {
        self.transition(reservation_id, false, |reservation, now| {
            require_reservation_state(reservation, &[ProviderCallReservationState::Reserved])?;
            reservation.state = ProviderCallReservationState::Dispatching;
            reservation.release_or_failure_reason = None;
            reservation.terminal_at = None;
            let _ = now;
            Ok(())
        })
    }

    pub fn mark_dispatched(
        &self,
        reservation_id: &str,
        external_invocation_ref: &str,
    ) -> Result<ProviderCallReservation, EngineError> {
        self.transition(reservation_id, false, |reservation, now| {
            require_reservation_state(reservation, &[ProviderCallReservationState::Dispatching])?;
            reservation.state = ProviderCallReservationState::Dispatched;
            reservation.dispatch_started_at = Some(now);
            reservation.external_invocation_ref = Some(external_invocation_ref.to_owned());
            Ok(())
        })
    }

    pub fn complete(
        &self,
        reservation_id: &str,
        review_ref: &str,
    ) -> Result<ProviderCallReservation, EngineError> {
        self.transition(reservation_id, true, |reservation, now| {
            require_reservation_state(reservation, &[ProviderCallReservationState::Dispatched])?;
            reservation.state = ProviderCallReservationState::Completed;
            reservation.review_ref = Some(review_ref.to_owned());
            reservation.terminal_at = Some(now);
            Ok(())
        })
    }

    pub fn fail_after_dispatch(
        &self,
        reservation_id: &str,
        reason: &str,
    ) -> Result<ProviderCallReservation, EngineError> {
        self.transition(reservation_id, true, |reservation, now| {
            require_reservation_state(reservation, &[ProviderCallReservationState::Dispatched])?;
            reservation.state = ProviderCallReservationState::Failed;
            reservation.terminal_at = Some(now);
            reservation.release_or_failure_reason = Some(reason.to_owned());
            Ok(())
        })
    }

    pub fn mark_unknown_outcome(
        &self,
        reservation_id: &str,
        reason: &str,
    ) -> Result<ProviderCallReservation, EngineError> {
        self.transition(reservation_id, true, |reservation, now| {
            require_reservation_state(
                reservation,
                &[
                    ProviderCallReservationState::Dispatching,
                    ProviderCallReservationState::Dispatched,
                ],
            )?;
            reservation.state = ProviderCallReservationState::UnknownOutcome;
            reservation.terminal_at = Some(now);
            reservation.release_or_failure_reason = Some(reason.to_owned());
            reservation.consumes_budget = true;
            Ok(())
        })
    }

    pub fn release_pre_dispatch(
        &self,
        reservation_id: &str,
        proof: &str,
    ) -> Result<ProviderCallReservation, EngineError> {
        self.transition(reservation_id, true, |reservation, now| {
            require_reservation_state(
                reservation,
                &[
                    ProviderCallReservationState::Reserved,
                    ProviderCallReservationState::Dispatching,
                ],
            )?;
            if reservation.dispatch_started_at.is_some()
                || reservation.external_invocation_ref.is_some()
            {
                return Err(rejected(
                    "provider call reservation cannot be released after dispatch evidence",
                ));
            }
            reservation.state = ProviderCallReservationState::ReleasedPreDispatch;
            reservation.terminal_at = Some(now);
            reservation.consumes_budget = false;
            reservation.release_or_failure_reason = Some(proof.to_owned());
            Ok(())
        })
    }

    pub fn close_campaign(&self, campaign_id: &str) -> Result<ProviderCallLedger, EngineError> {
        self.mutate(|ledger| {
            let budget = ledger
                .budgets
                .iter_mut()
                .find(|budget| budget.campaign_id == campaign_id)
                .ok_or_else(|| rejected("provider call budget not found"))?;
            budget.closed = true;
            budget.revision = budget.revision.saturating_add(1);
            budget.updated_at = OffsetDateTime::now_utc();
            Ok(ledger.clone())
        })
    }

    pub fn snapshot(&self) -> Result<ProviderCallLedger, EngineError> {
        self.with_lock(load_provider_call_ledger)
    }

    fn transition<F>(
        &self,
        reservation_id: &str,
        allow_after_campaign_close: bool,
        transition: F,
    ) -> Result<ProviderCallReservation, EngineError>
    where
        F: FnOnce(&mut ProviderCallReservation, OffsetDateTime) -> Result<(), EngineError>,
    {
        self.mutate(|ledger| {
            let reservation_index = ledger
                .reservations
                .iter()
                .position(|reservation| reservation.reservation_id == reservation_id)
                .ok_or_else(|| rejected("provider call reservation not found"))?;
            let campaign_id = ledger.reservations[reservation_index].campaign_id.clone();
            let budget_index = ledger
                .budgets
                .iter()
                .position(|budget| budget.campaign_id == campaign_id)
                .ok_or_else(|| rejected("provider call budget not found"))?;
            if ledger.budgets[budget_index].closed && !allow_after_campaign_close {
                return Err(rejected(
                    "provider call reservation cannot enter dispatch after campaign close",
                ));
            }
            transition(
                &mut ledger.reservations[reservation_index],
                OffsetDateTime::now_utc(),
            )?;
            ledger.budgets[budget_index].revision =
                ledger.budgets[budget_index].revision.saturating_add(1);
            refresh_provider_call_budget(ledger, budget_index);
            ledger.reservations[reservation_index].budget_revision =
                ledger.budgets[budget_index].revision;
            Ok(ledger.reservations[reservation_index].clone())
        })
    }

    fn mutate<T, F>(&self, mutation: F) -> Result<T, EngineError>
    where
        F: FnOnce(&mut ProviderCallLedger) -> Result<T, EngineError>,
    {
        self.with_lock(|path| {
            let mut ledger = load_provider_call_ledger(path)?;
            let output = mutation(&mut ledger)?;
            validate_provider_call_ledger(&ledger)?;
            write_provider_call_ledger(path, &ledger)?;
            Ok(output)
        })
    }

    fn with_lock<T, F>(&self, operation: F) -> Result<T, EngineError>
    where
        F: FnOnce(&Path) -> Result<T, EngineError>,
    {
        let runtime = self.root.join("runtime");
        fs::create_dir_all(&runtime)?;
        let lock_path = runtime.join("provider-call-ledger.lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(lock_path)?;
        lock.lock()?;
        let result = operation(&runtime.join("provider-call-ledger.json"));
        drop(lock);
        result
    }
}

fn ensure_provider_call_budget(
    ledger: &mut ProviderCallLedger,
    request: &ProviderCallReservationRequest,
) -> Result<usize, EngineError> {
    if request.max_calls == 0 {
        return Err(rejected(
            "provider call budget must allow at least one call",
        ));
    }
    if let Some(index) = ledger
        .budgets
        .iter()
        .position(|budget| budget.campaign_id == request.campaign_id)
    {
        if ledger.budgets[index].max_calls != request.max_calls {
            return Err(rejected("provider call budget maximum is immutable"));
        }
        return Ok(index);
    }
    ledger.budgets.push(ProviderCallBudgetState {
        campaign_id: request.campaign_id.clone(),
        schema_version: "l1b-r-1".to_owned(),
        max_calls: request.max_calls,
        next_slot_index: 1,
        reserved_slots: 0,
        dispatched_slots: 0,
        terminal_slots: 0,
        remaining_calls: request.max_calls,
        revision: 0,
        closed: request.campaign_closed,
        updated_at: OffsetDateTime::now_utc(),
    });
    Ok(ledger.budgets.len() - 1)
}

fn refresh_provider_call_budget(ledger: &mut ProviderCallLedger, budget_index: usize) {
    let campaign_id = ledger.budgets[budget_index].campaign_id.clone();
    let scoped = ledger
        .reservations
        .iter()
        .filter(|reservation| reservation.campaign_id == campaign_id)
        .collect::<Vec<_>>();
    let active = scoped
        .iter()
        .filter(|reservation| reservation.consumes_budget)
        .count();
    ledger.budgets[budget_index].reserved_slots = bounded_u32(
        scoped
            .iter()
            .filter(|reservation| {
                matches!(
                    reservation.state,
                    ProviderCallReservationState::Reserved
                        | ProviderCallReservationState::Dispatching
                )
            })
            .count(),
    );
    ledger.budgets[budget_index].dispatched_slots = bounded_u32(
        scoped
            .iter()
            .filter(|reservation| reservation.dispatch_started_at.is_some())
            .count(),
    );
    ledger.budgets[budget_index].terminal_slots = bounded_u32(
        scoped
            .iter()
            .filter(|reservation| reservation.terminal_at.is_some())
            .count(),
    );
    ledger.budgets[budget_index].remaining_calls = ledger.budgets[budget_index]
        .max_calls
        .saturating_sub(bounded_u32(active));
    ledger.budgets[budget_index].updated_at = OffsetDateTime::now_utc();
}

fn validate_provider_call_ledger(ledger: &ProviderCallLedger) -> Result<(), EngineError> {
    for budget in &ledger.budgets {
        if budget.dispatched_slots > budget.max_calls
            || budget.remaining_calls > budget.max_calls
            || budget
                .reserved_slots
                .saturating_add(budget.dispatched_slots)
                > budget.max_calls
        {
            return Err(rejected("provider call budget invariant violated"));
        }
        let mut slots = ledger
            .reservations
            .iter()
            .filter(|reservation| reservation.campaign_id == budget.campaign_id)
            .map(|reservation| reservation.slot_index)
            .collect::<Vec<_>>();
        slots.sort_unstable();
        slots.dedup();
        if slots.len()
            != ledger
                .reservations
                .iter()
                .filter(|reservation| reservation.campaign_id == budget.campaign_id)
                .count()
        {
            return Err(rejected("provider call reservation slot is not unique"));
        }
    }
    Ok(())
}

fn require_reservation_state(
    reservation: &ProviderCallReservation,
    allowed: &[ProviderCallReservationState],
) -> Result<(), EngineError> {
    if allowed.contains(&reservation.state) {
        Ok(())
    } else {
        Err(rejected("forbidden provider call reservation transition"))
    }
}

fn rejected(message: &str) -> EngineError {
    EngineError::WriteRejected(message.to_owned())
}

fn load_provider_call_ledger(path: &Path) -> Result<ProviderCallLedger, EngineError> {
    for candidate in [
        path.to_path_buf(),
        path.with_extension("json.next"),
        path.with_extension("json.bak"),
    ] {
        if candidate.is_file()
            && let Ok(ledger) =
                serde_json::from_reader::<_, ProviderCallLedger>(File::open(candidate)?)
        {
            validate_provider_call_ledger(&ledger)?;
            return Ok(ledger);
        }
    }
    Ok(ProviderCallLedger::default())
}

fn write_provider_call_ledger(path: &Path, ledger: &ProviderCallLedger) -> Result<(), EngineError> {
    let next = path.with_extension("json.next");
    let backup = path.with_extension("json.bak");
    let bytes = serde_json::to_vec_pretty(ledger)?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&next)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    if backup.exists() {
        fs::remove_file(&backup)?;
    }
    if path.exists() {
        fs::rename(path, &backup)?;
    }
    if let Err(error) = fs::rename(&next, path) {
        if backup.exists() {
            let _ = fs::rename(&backup, path);
        }
        return Err(error.into());
    }
    if backup.exists() {
        fs::remove_file(backup)?;
    }
    Ok(())
}

fn bounded_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DelegationHealth {
    pub g3b_done_verified: bool,
    pub provider_available: bool,
    pub provider_healthy: bool,
    pub provider_version_supported: bool,
    pub plugin_and_mcp_verified: bool,
    pub incident_lockdown: bool,
    pub evidence_refs: Vec<String>,
    pub checked_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DelegationHealthService;

impl DelegationHealthService {
    #[must_use]
    #[allow(clippy::fn_params_excessive_bools)]
    pub fn policy_context(
        &self,
        health: &DelegationHealth,
        active_work_lease: bool,
        budget_available: bool,
        cooldown_active: bool,
        duplicate_fresh_review: bool,
    ) -> DelegationPolicyContext {
        DelegationPolicyContext {
            incident_lockdown: health.incident_lockdown,
            g3b_done_verified: health.g3b_done_verified,
            provider_available: health.provider_available,
            provider_healthy: health.provider_healthy,
            provider_version_supported: health.provider_version_supported,
            plugin_and_mcp_verified: health.plugin_and_mcp_verified,
            active_work_lease,
            budget_available,
            cooldown_active,
            duplicate_fresh_review,
            ..DelegationPolicyContext::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DelegationExecutionService;

impl DelegationExecutionService {
    pub fn require_active_work_lease<'a>(
        &self,
        request: &DelegationRequest,
        leases: &'a [WorkLease],
    ) -> Option<&'a WorkLease> {
        leases.iter().find(|lease| {
            lease.work_lease_id == request.work_lease_id
                && lease.project_id == request.project_id
                && lease.task_id == request.task_id
                && work_lease_is_active(lease)
        })
    }

    #[must_use]
    pub fn create_job(
        &self,
        request: &DelegationRequest,
        decision: &DelegationDecision,
        worktree: &WorktreeLease,
        external_review_job_ref: String,
    ) -> DelegationJob {
        DelegationJob {
            job_id: new_id("delegation-job"),
            delegation_id: request.delegation_id.clone(),
            decision_id: decision.decision_id.clone(),
            provider_id: PROVIDER_ID.to_owned(),
            worktree_lease_id: worktree.worktree_lease_id,
            external_review_job_ref,
            state: DelegationJobState::Queued,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn transition(&self, job: &mut DelegationJob, state: DelegationJobState) {
        job.state = state;
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DelegationOutcomeService;

impl DelegationOutcomeService {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn record(
        &self,
        delegation_id: &str,
        result_ref: Option<String>,
        proposed_unique: u32,
        proposed_accepted: u32,
        rejected: u32,
        duplicates: u32,
        verifier_refs: Vec<String>,
        changed_controller_decision: bool,
        actual_runtime_ms: u64,
        provider_call_count: u32,
        provider_failed: bool,
    ) -> DelegationOutcome {
        let acceptance_proven = changed_controller_decision || !verifier_refs.is_empty();
        let accepted = if acceptance_proven {
            proposed_accepted
        } else {
            0
        };
        let status = if provider_failed {
            DelegationOutcomeStatus::ProviderFailed
        } else if accepted > 0 {
            DelegationOutcomeStatus::Useful
        } else if proposed_unique > 0 {
            DelegationOutcomeStatus::PartiallyUseful
        } else if duplicates > 0 {
            DelegationOutcomeStatus::Redundant
        } else {
            DelegationOutcomeStatus::NoUsefulResult
        };
        DelegationOutcome {
            outcome_id: new_id("delegation-outcome"),
            delegation_id: delegation_id.to_owned(),
            result_ref,
            status,
            unique_findings: proposed_unique,
            accepted_findings: accepted,
            rejected_findings: rejected,
            duplicate_findings: duplicates,
            verifier_refs,
            changed_controller_decision,
            actual_runtime_ms,
            provider_call_count,
            monetary_cost_known: false,
            integrity_evidence_present: false,
            authority_violations: 0,
            live_tree_violations: 0,
            notes: vec![
                "external output remains candidate-only until controller reconciliation".to_owned(),
            ],
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DelegationReportService;

impl DelegationReportService {
    #[must_use]
    pub fn response(
        &self,
        request: &DelegationRequest,
        decision: &DelegationDecision,
        job: Option<&DelegationJob>,
    ) -> DelegationReviewResponse {
        let status = match decision.kind {
            DelegationDecisionKind::Execute => match job.map(|job| job.state) {
                Some(DelegationJobState::Running) => DelegationPublicStatus::Running,
                Some(DelegationJobState::Completed) => DelegationPublicStatus::Completed,
                Some(
                    DelegationJobState::Failed
                    | DelegationJobState::TimedOut
                    | DelegationJobState::Cancelled,
                ) => DelegationPublicStatus::Denied,
                _ => DelegationPublicStatus::Queued,
            },
            DelegationDecisionKind::Deny => DelegationPublicStatus::Denied,
            DelegationDecisionKind::ShadowRecommend => DelegationPublicStatus::Shadow,
            DelegationDecisionKind::NoExternalReview => DelegationPublicStatus::NoExternalReview,
        };
        DelegationReviewResponse {
            delegation_id: request.delegation_id.clone(),
            decision: decision.kind,
            provider: decision.provider_id.clone(),
            reasons: decision.reasons.clone(),
            job_id: job.map(|job| job.job_id.clone()),
            constraints: decision.constraints.clone(),
            status,
        }
    }

    #[must_use]
    pub fn summary(&self, state: &DelegationState) -> serde_json::Value {
        let live_tree_violations = state
            .outcomes
            .iter()
            .map(|outcome| u64::from(outcome.live_tree_violations))
            .sum::<u64>();
        let authority_violations = state
            .outcomes
            .iter()
            .map(|outcome| u64::from(outcome.authority_violations))
            .sum::<u64>();
        let recursive_executions = state
            .decisions
            .iter()
            .filter(|decision| {
                decision
                    .reasons
                    .contains(&DelegationReason::RecursiveProviderCall)
            })
            .count();
        serde_json::json!({
            "component": "delegation_report",
            "requests": state.requests.len(),
            "decisions": state.decisions,
            "budgets": state.budgets,
            "jobs": state.jobs,
            "outcomes": state.outcomes,
            "live_tree_violation_total": live_tree_violations,
            "authority_violation_total": authority_violations,
            "recursive_execution_total": recursive_executions,
            "integrity_evidence_complete": state.outcomes.iter().filter(|outcome| outcome.provider_call_count > 0).all(|outcome| outcome.integrity_evidence_present),
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DelegationDoctorIntegration;

impl DelegationDoctorIntegration {
    #[must_use]
    pub fn report(&self, health: &DelegationHealth, state: &DelegationState) -> serde_json::Value {
        let live_tree_violations = state
            .outcomes
            .iter()
            .map(|outcome| u64::from(outcome.live_tree_violations))
            .sum::<u64>();
        let authority_violations = state
            .outcomes
            .iter()
            .map(|outcome| u64::from(outcome.authority_violations))
            .sum::<u64>();
        serde_json::json!({
            "component": "delegation_doctor",
            "g3b_baseline_health": health,
            "last_routed_call": state.requests.last(),
            "task_budget_state": state.budgets.last(),
            "recursion_denials": state.decisions.iter().filter(|decision| decision.reasons.contains(&DelegationReason::RecursiveProviderCall)).count(),
            "provider_failures": state.outcomes.iter().filter(|outcome| outcome.status == DelegationOutcomeStatus::ProviderFailed).count(),
            "live_tree_violation_count": live_tree_violations,
            "authority_violation_count": authority_violations,
            "integrity_evidence_complete": state.outcomes.iter().filter(|outcome| outcome.provider_call_count > 0).all(|outcome| outcome.integrity_evidence_present),
        })
    }
}

fn hard_denial(
    request: &DelegationRequest,
    context: &DelegationPolicyContext,
) -> Option<DelegationReason> {
    if request.origin_chain.delegation_depth > 1
        || request
            .origin_chain
            .provider_chain
            .iter()
            .any(|provider| provider.eq_ignore_ascii_case(PROVIDER_ID))
        || request.origin_chain.root_origin == eliot_types::DelegationRootOrigin::ExternalProvider
    {
        return Some(DelegationReason::RecursiveProviderCall);
    }
    [
        (
            context.incident_lockdown,
            DelegationReason::IncidentLockdown,
        ),
        (
            context.forbidden_data_exposure,
            DelegationReason::ForbiddenDataExposure,
        ),
        (
            !context.g3b_done_verified,
            DelegationReason::G3BNotDoneVerified,
        ),
        (
            !context.provider_available,
            DelegationReason::ProviderUnavailable,
        ),
        (
            !context.provider_healthy,
            DelegationReason::ProviderUnhealthy,
        ),
        (
            !context.provider_version_supported,
            DelegationReason::ProviderVersionBelow1_1_1,
        ),
        (
            !context.plugin_and_mcp_verified,
            DelegationReason::PluginOrMcpIntegrationNotVerified,
        ),
        (
            !context.active_work_lease,
            DelegationReason::MissingWorkLease,
        ),
        (!context.budget_available, DelegationReason::BudgetExceeded),
        (context.cooldown_active, DelegationReason::CooldownActive),
        (
            context.duplicate_fresh_review,
            DelegationReason::FreshEquivalentReview,
        ),
    ]
    .into_iter()
    .find_map(|(blocked, reason)| blocked.then_some(reason))
}

fn strong_triggers(question: &str) -> Vec<DelegationReason> {
    let lower = question.to_ascii_lowercase();
    let mut reasons = Vec::new();
    for (matches, reason) in [
        (
            contains_any(
                &lower,
                &["security", "authority", "credential", "recursive"],
            ),
            DelegationReason::SecurityBoundary,
        ),
        (
            contains_any(
                &lower,
                &[
                    "integration",
                    "mcp",
                    "plugin",
                    "provider",
                    "executable",
                    "antigravity",
                ],
            ),
            DelegationReason::ExternalIntegration,
        ),
        (
            contains_any(
                &lower,
                &["multiple modules", "multi-module", "architecture"],
            ),
            DelegationReason::MultiModuleImpact,
        ),
        (
            contains_any(
                &lower,
                &["failed twice", "two failures", "repeated failure"],
            ),
            DelegationReason::RepeatedFailure,
        ),
        (
            contains_any(&lower, &["verifiers disagree", "verifier disagreement"]),
            DelegationReason::VerifierDisagreement,
        ),
        (
            contains_any(&lower, &["evidence gap", "missing evidence"]),
            DelegationReason::EvidenceGap,
        ),
        (
            contains_any(&lower, &["high ambiguity", "ambiguous"]),
            DelegationReason::HighAmbiguity,
        ),
        (
            contains_any(&lower, &["broad diff", "high-impact diff"]),
            DelegationReason::BroadDiff,
        ),
        (
            contains_any(&lower, &["completion audit", "independent audit"]),
            DelegationReason::IndependentCompletionAudit,
        ),
    ] {
        if matches {
            reasons.push(reason);
        }
    }
    reasons
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn decision(
    request: &DelegationRequest,
    kind: DelegationDecisionKind,
    reasons: Vec<DelegationReason>,
) -> DelegationDecision {
    let executes = kind == DelegationDecisionKind::Execute;
    DelegationDecision {
        decision_id: new_id("delegation-decision"),
        delegation_id: request.delegation_id.clone(),
        kind,
        provider_id: executes.then(|| PROVIDER_ID.to_owned()),
        reasons,
        constraints: if executes {
            CONSTRAINTS.map(str::to_owned).to_vec()
        } else {
            Vec::new()
        },
        budget_id: None,
        provider_health_ref: None,
        external_review_request_ref: None,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}:{}", eliot_types::WorkLeaseId::new_v7())
}
