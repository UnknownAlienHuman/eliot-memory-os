use crate::{EngineError, work_lease_is_active};
use eliot_types::delegation::{
    PROVIDER_CALL_CAMPAIGN_SCHEMA_VERSION, protected_delegation_identity_is_valid,
};
use eliot_types::{
    DelegationBudget, DelegationDecision, DelegationDecisionKind, DelegationJob,
    DelegationJobState, DelegationOrigin, DelegationOutcome, DelegationOutcomeStatus,
    DelegationPublicStatus, DelegationReason, DelegationRequest, DelegationReviewResponse,
    DelegationState, ProviderCallBudgetState, ProviderCallLedger, ProviderCallReservation,
    ProviderCallReservationState, TaskId, WorkLease, WorktreeLease,
};
use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};

const PROVIDER_ID: &str = "antigravity";
const CONSTRAINTS: [&str; 3] = ["candidate_only", "tainted", "disposable_worktree"];
/// Where an explicit reconciliation preserves the original bytes of a refused
/// provider-call ledger candidate. It is never one of the candidate names, so a
/// preserved copy can never be read back as current or staged ledger state.
const PROVIDER_CALL_LEDGER_QUARANTINE_DIR: &str = "provider-call-ledger-quarantine";

#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct DelegationPolicyContext {
    pub incident_lockdown: bool,
    pub forbidden_data_exposure: bool,
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
pub struct ProviderCallCampaignRequest {
    pub campaign_id: String,
    pub max_calls: u32,
    pub closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCallReservationRequest {
    pub campaign_id: String,
    pub task_id: TaskId,
    pub provider: String,
    pub idempotency_key: String,
    pub gate_decision_ref: String,
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

    pub fn open_campaign(
        &self,
        request: ProviderCallCampaignRequest,
    ) -> Result<ProviderCallBudgetState, EngineError> {
        if !protected_delegation_identity_is_valid(&request.campaign_id) {
            return Err(rejected(
                "provider campaign ID must be a nonempty identity within the bound",
            ));
        }
        if request.max_calls == 0 {
            return Err(rejected(
                "provider call budget must allow at least one call",
            ));
        }
        self.mutate(|ledger| {
            if let Some(budget) = ledger
                .budgets
                .iter_mut()
                .find(|budget| budget.campaign_id == request.campaign_id)
            {
                if budget.max_calls != request.max_calls {
                    return Err(rejected("provider call budget maximum is immutable"));
                }
                if request.closed && !budget.closed {
                    budget.closed = true;
                    budget.revision = budget.revision.saturating_add(1);
                    budget.updated_at = OffsetDateTime::now_utc();
                }
                return Ok(budget.clone());
            }
            let budget = ProviderCallBudgetState {
                campaign_id: request.campaign_id,
                schema_version: PROVIDER_CALL_CAMPAIGN_SCHEMA_VERSION.to_owned(),
                max_calls: request.max_calls,
                next_slot_index: 1,
                reserved_slots: 0,
                dispatched_slots: 0,
                terminal_slots: 0,
                remaining_calls: request.max_calls,
                revision: 0,
                closed: request.closed,
                updated_at: OffsetDateTime::now_utc(),
            };
            ledger.budgets.push(budget.clone());
            Ok(budget)
        })
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
            let Some(budget_index) = ledger
                .budgets
                .iter()
                .position(|budget| budget.campaign_id == request.campaign_id)
            else {
                return Ok(ProviderCallReservationDecision::CampaignClosed);
            };
            if ledger.budgets[budget_index].closed {
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
        self.with_lock(|path| load_provider_call_ledger(path).map_err(EngineError::from))
    }

    /// Read the ledger without creating or rewriting anything.
    ///
    /// Absence still yields the empty ledger without touching the lock file; an
    /// existing-but-undecodable ledger refuses here too, so a reader cannot
    /// observe a known-empty budget that the mutating path would refuse.
    pub fn snapshot_read_only(&self) -> Result<ProviderCallLedger, EngineError> {
        let runtime = self.root.join("runtime");
        let ledger_path = runtime.join("provider-call-ledger.json");
        if ![
            ledger_path.clone(),
            ledger_path.with_extension("json.next"),
            ledger_path.with_extension("json.bak"),
        ]
        .iter()
        .any(|path| path.is_file())
        {
            return Ok(ProviderCallLedger::default());
        }
        let lock_path = runtime.join("provider-call-ledger.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| {
                EngineError::WriteRejected(format!(
                    "provider ledger exists without an openable read-only lock {}: {error}",
                    lock_path.display()
                ))
            })?;
        lock.lock()?;
        let result = load_provider_call_ledger(&ledger_path).map_err(EngineError::from);
        drop(lock);
        result
    }

    /// The explicit, operator-authorized reconciliation of a preserved corrupt
    /// provider-call ledger.
    ///
    /// This is the only path that ends the [`ProviderCallLedgerUnknown`] block,
    /// and it can only end it through an explicit disposition of every
    /// preserved candidate:
    ///
    /// * the ledger must currently be unknown, so a healthy ledger can never be
    ///   downgraded to an older record here;
    /// * `operator_ref` must be a bounded identity, because an authority field
    ///   is never silently defaulted;
    /// * every candidate the refusal enumerated must carry exactly one
    ///   disposition. There is no default and no implied "the backup is the
    ///   good one";
    /// * [`ProviderCallLedgerCandidateAction::PreserveAsQuarantine`] copies a
    ///   candidate's original bytes into the quarantine area and leaves the
    ///   candidate refused in place. It admits nothing, so the outcome carries
    ///   no ledger and the state stays unknown;
    /// * [`ProviderCallLedgerCandidateAction::SupersedeWithRecoveredRecord`] is
    ///   the only disposition that unblocks. It is permitted at most once, it
    ///   must name the current candidate, and it requires
    ///   `recovered_record_from`: the operator's own copy of the ORIGINAL
    ///   recorded bytes. A refused candidate can never be admitted on its own
    ///   bytes, because a candidate whose bytes decode and validate is by
    ///   definition not in the unknown state this reconciles.
    ///
    /// The admitted bytes are re-validated by the same
    /// [`decode_provider_call_ledger`] and the same
    /// [`validate_provider_call_ledger`] every candidate is held to, and they
    /// are then installed verbatim: no digest is recomputed, no weaker second
    /// validator runs, and no normalized re-serialization replaces them.
    ///
    /// The corrupt evidence is never deleted, truncated or overwritten in place.
    /// The superseded candidate is renamed into the quarantine area and every
    /// preserved candidate is copied byte-for-byte, and the copy is compared
    /// with the original before it is reported.
    ///
    /// Nothing here produces `ProviderCallLedger::default()`: when no candidate
    /// is admitted the state stays unknown and new provider calls stay blocked.
    pub fn reconcile_provider_call_ledger(
        &self,
        reconciliation: &ProviderCallLedgerReconciliation,
    ) -> Result<ProviderCallLedgerReconciliationOutcome, EngineError> {
        if !protected_delegation_identity_is_valid(&reconciliation.operator_ref) {
            return Err(rejected(
                "provider call ledger reconciliation requires an explicit bounded operator identity",
            ));
        }
        self.with_lock(|path| apply_provider_call_ledger_reconciliation(path, reconciliation))
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
            // A corrupt or unknown ledger never reaches the mutation: the
            // unknown disposition is preserved and no write is attempted, so
            // `open_campaign` and `reserve` cannot mint a fresh budget and
            // reservation as though the prior calls never existed.
            let mut ledger = load_provider_call_ledger(path).map_err(EngineError::from)?;
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

/// The one durable provider-call ledger candidate roles are tried in, with the
/// authority each one carries. The role is a fixed code, never a path, so a
/// refusal can name which authoritative file was refused without echoing the
/// filesystem or the ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCallLedgerCandidate {
    Current,
    Staged,
    Backup,
}

impl ProviderCallLedgerCandidate {
    fn code(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Staged => "staged",
            Self::Backup => "backup",
        }
    }

    /// The one file this candidate role names. The role-to-name mapping is
    /// defined once so the loader, the read-only snapshot and the
    /// reconciliation owner can never disagree about which file is which.
    fn path(self, ledger_path: &Path) -> PathBuf {
        match self {
            Self::Current => ledger_path.to_path_buf(),
            Self::Staged => ledger_path.with_extension("json.next"),
            Self::Backup => ledger_path.with_extension("json.bak"),
        }
    }
}

/// Why one existing candidate could not be admitted as current ledger state.
///
/// `Unreadable` is an existing file that cannot be opened, `Malformed` is bytes
/// the strict decoder rejects, and `Invalid` is a decodable ledger whose
/// relations the validator rejects. The distinction is bounded to these three
/// codes: no decode error, field value, count or byte from the candidate is
/// carried onward.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderCallLedgerFault {
    Unreadable,
    Malformed,
    Invalid,
}

impl ProviderCallLedgerFault {
    fn code(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::Malformed => "malformed",
            Self::Invalid => "invalid",
        }
    }
}

/// Bounded per-candidate diagnostics for one refused ledger file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProviderCallLedgerCandidateFault {
    candidate: ProviderCallLedgerCandidate,
    fault: ProviderCallLedgerFault,
}

/// The typed corruption/unknown disposition of the persisted provider-call
/// ledger.
///
/// Absence and corruption are distinct and this type carries only corruption:
/// it exists exactly when at least one candidate file exists and none of them
/// decoded and validated. It is never converted into an empty ledger, because
/// an empty ledger is the forbidden promotion of unknown historical coverage to
/// a current "no reservations, no consumed budget". The caller-visible
/// refusal blocks new provider calls until explicit reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCallLedgerUnknown {
    faults: Vec<ProviderCallLedgerCandidateFault>,
}

impl fmt::Display for ProviderCallLedgerUnknown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "provider call ledger is unknown; new provider calls are blocked \
             pending reconciliation: ",
        )?;
        for (index, entry) in self.faults.iter().enumerate() {
            if index > 0 {
                formatter.write_str(", ")?;
            }
            write!(
                formatter,
                "{}={}",
                entry.candidate.code(),
                entry.fault.code()
            )?;
        }
        Ok(())
    }
}

impl From<ProviderCallLedgerUnknown> for EngineError {
    fn from(unknown: ProviderCallLedgerUnknown) -> Self {
        EngineError::ProviderCallLedgerUnknown(unknown.to_string())
    }
}

/// What an operator explicitly decided to do with one preserved corrupt
/// provider-call ledger candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCallLedgerCandidateAction {
    /// Keep this candidate's original bytes refused in place and take a
    /// verified byte-identical copy into the quarantine area.
    ///
    /// It never moves the candidate, because moving the last refused candidate
    /// would leave no candidate at all and the next load would silently produce
    /// an empty ledger.
    PreserveAsQuarantine,
    /// Supersede this candidate: the record the operator authorizes through
    /// [`ProviderCallLedgerReconciliation::recovered_record_from`] becomes the
    /// current ledger, and this candidate's original bytes are preserved by
    /// renaming them into the quarantine area.
    SupersedeWithRecoveredRecord,
}

/// One explicitly named candidate and the explicitly chosen action for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCallLedgerCandidateDisposition {
    pub candidate: ProviderCallLedgerCandidate,
    pub action: ProviderCallLedgerCandidateAction,
}

/// The operator intent that a reconciliation requires. Every field is filled by
/// the caller: nothing here has a default, and an absent field refuses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCallLedgerReconciliation {
    /// One disposition per candidate the refusal enumerated, each exactly once.
    /// There is no default disposition and no implied choice of candidate.
    pub dispositions: Vec<ProviderCallLedgerCandidateDisposition>,
    /// The operator's own copy of the ORIGINAL recorded ledger bytes. It is
    /// required exactly when some candidate is superseded, and refused when
    /// nothing is, because a recovered record nobody admitted changes nothing.
    pub recovered_record_from: Option<PathBuf>,
    /// The bounded identity of the operator authorizing this reconciliation.
    pub operator_ref: String,
}

/// Where one preserved corrupt candidate's original bytes now live.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCallLedgerQuarantineEntry {
    pub candidate: ProviderCallLedgerCandidate,
    pub path: PathBuf,
}

/// The proven result of one reconciliation.
///
/// `admitted` is `None` whenever nothing was explicitly admitted, and then
/// `still_unknown` is true and new provider calls stay blocked. An admitted
/// ledger is never a default ledger: it is the operator's recovered record
/// after the same decode and validation every candidate is held to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCallLedgerReconciliationOutcome {
    pub admitted: Option<ProviderCallLedger>,
    pub quarantined: Vec<ProviderCallLedgerQuarantineEntry>,
    pub still_unknown: bool,
}

/// The complete relation every persisted provider-call ledger must prove.
///
/// `validate_provider_call_ledger` recomputes each budget counter from the
/// reservations that carry it instead of range-checking the stored number, so a
/// ledger whose stored counters were edited downward cannot be admitted as
/// current state.
fn validate_provider_call_ledger(ledger: &ProviderCallLedger) -> Result<(), EngineError> {
    let mut campaigns = HashSet::new();
    for budget in &ledger.budgets {
        if !protected_delegation_identity_is_valid(&budget.campaign_id) {
            return Err(rejected(
                "provider call campaign identity is empty or unbounded",
            ));
        }
        if !campaigns.insert(budget.campaign_id.as_str()) {
            return Err(rejected("provider call campaign identity is not unique"));
        }
        if budget.schema_version != PROVIDER_CALL_CAMPAIGN_SCHEMA_VERSION {
            return Err(rejected(
                "provider call budget schema version is not the owned version",
            ));
        }
        if budget.max_calls == 0 {
            return Err(rejected("provider call budget allows no call"));
        }
    }

    let mut reservations = HashSet::new();
    let mut idempotency_keys = HashSet::new();
    let mut slots = HashSet::new();
    for reservation in &ledger.reservations {
        for value in [
            reservation.reservation_id.as_str(),
            reservation.campaign_id.as_str(),
            reservation.provider.as_str(),
            reservation.idempotency_key.as_str(),
            reservation.gate_decision_ref.as_str(),
        ] {
            if !protected_delegation_identity_is_valid(value) {
                return Err(rejected(
                    "provider call reservation identity or ref is empty or unbounded",
                ));
            }
        }
        if !reservations.insert(reservation.reservation_id.as_str()) {
            return Err(rejected("provider call reservation identity is not unique"));
        }
        let Some(budget) = ledger
            .budgets
            .iter()
            .find(|budget| budget.campaign_id == reservation.campaign_id)
        else {
            return Err(rejected(
                "provider call reservation references no existing campaign",
            ));
        };
        if !idempotency_keys.insert((
            reservation.campaign_id.as_str(),
            reservation.idempotency_key.as_str(),
        )) {
            return Err(rejected(
                "provider call reservation idempotency key is not unique within its campaign",
            ));
        }
        if reservation.slot_index == 0 {
            return Err(rejected("provider call reservation slot index is zero"));
        }
        if !slots.insert((reservation.campaign_id.as_str(), reservation.slot_index)) {
            return Err(rejected("provider call reservation slot is not unique"));
        }
        if reservation.budget_revision > budget.revision {
            return Err(rejected(
                "provider call reservation names a budget revision that does not exist",
            ));
        }
        validate_provider_call_reservation_evidence(reservation)?;
    }

    for budget in &ledger.budgets {
        let scoped = ledger
            .reservations
            .iter()
            .filter(|reservation| reservation.campaign_id == budget.campaign_id);
        let mut reserved_slots = 0;
        let mut dispatched_slots = 0;
        let mut terminal_slots = 0;
        let mut consumed_slots = 0;
        let mut next_slot_index = 1;
        for reservation in scoped {
            if matches!(
                reservation.state,
                ProviderCallReservationState::Reserved | ProviderCallReservationState::Dispatching
            ) {
                reserved_slots += 1;
            }
            if reservation.dispatch_started_at.is_some() {
                dispatched_slots += 1;
            }
            if reservation.terminal_at.is_some() {
                terminal_slots += 1;
            }
            if reservation.consumes_budget {
                consumed_slots += 1;
            }
            next_slot_index = next_slot_index.max(reservation.slot_index.saturating_add(1));
        }
        let consumed = bounded_u32(consumed_slots);
        if budget.reserved_slots != bounded_u32(reserved_slots)
            || budget.dispatched_slots != bounded_u32(dispatched_slots)
            || budget.terminal_slots != bounded_u32(terminal_slots)
            || budget.remaining_calls != budget.max_calls.saturating_sub(consumed)
            || budget.next_slot_index != next_slot_index
        {
            return Err(rejected(
                "provider call budget counters are not recomputed from their reservations",
            ));
        }
        if consumed > budget.max_calls {
            return Err(rejected(
                "provider call budget is exceeded by its own reservations",
            ));
        }
    }
    Ok(())
}

/// State-specific evidence for one reservation.
///
/// Every field the reservation carries as evidence for the state it claims is
/// compared with that state: a terminal state without its terminal time, a
/// dispatched state without the invocation it dispatched, a pre-dispatch state
/// carrying dispatch evidence, or a release that still claims the budget. The
/// messages are fixed and name no field value.
fn validate_provider_call_reservation_evidence(
    reservation: &ProviderCallReservation,
) -> Result<(), EngineError> {
    let dispatch_started = reservation.dispatch_started_at.is_some();
    let invocation_ref = reservation.external_invocation_ref.is_some();
    if dispatch_started != invocation_ref {
        return Err(rejected(
            "provider call reservation dispatch evidence is not bound to its state",
        ));
    }
    for ref_value in [
        reservation.external_invocation_ref.as_deref(),
        reservation.review_ref.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !protected_delegation_identity_is_valid(ref_value) {
            return Err(rejected(
                "provider call reservation dispatch or review ref is empty or unbounded",
            ));
        }
    }
    let terminal_proven = |expected_reason: bool| {
        reservation.terminal_at.is_some()
            && reservation.release_or_failure_reason.is_some() == expected_reason
    };
    match reservation.state {
        ProviderCallReservationState::Reserved | ProviderCallReservationState::Dispatching => {
            if dispatch_started
                || reservation.review_ref.is_some()
                || reservation.terminal_at.is_some()
                || !reservation.consumes_budget
                || reservation.release_or_failure_reason.is_some()
            {
                return Err(rejected(
                    "provider call reservation state contradicts its evidence",
                ));
            }
        }
        ProviderCallReservationState::Dispatched => {
            if !dispatch_started
                || reservation.review_ref.is_some()
                || reservation.terminal_at.is_some()
                || !reservation.consumes_budget
                || reservation.release_or_failure_reason.is_some()
            {
                return Err(rejected(
                    "provider call reservation state contradicts its evidence",
                ));
            }
        }
        ProviderCallReservationState::Completed => {
            if !dispatch_started
                || reservation.review_ref.is_none()
                || !terminal_proven(false)
                || !reservation.consumes_budget
            {
                return Err(rejected(
                    "provider call reservation state contradicts its evidence",
                ));
            }
        }
        ProviderCallReservationState::Failed | ProviderCallReservationState::UnknownOutcome => {
            if reservation.review_ref.is_some()
                || !terminal_proven(true)
                || !reservation.consumes_budget
            {
                return Err(rejected(
                    "provider call reservation state contradicts its evidence",
                ));
            }
        }
        ProviderCallReservationState::ReleasedPreDispatch => {
            if dispatch_started
                || reservation.review_ref.is_some()
                || !terminal_proven(true)
                || reservation.consumes_budget
            {
                return Err(rejected(
                    "provider call reservation state contradicts its evidence",
                ));
            }
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

/// Load the persisted provider-call ledger, keeping absence and corruption
/// distinct.
///
/// Absence means no candidate file exists, and only that case yields the empty
/// ledger. Corruption means at least one candidate exists and none of them
/// decoded and validated; that case returns the typed
/// [`ProviderCallLedgerUnknown`] refusal instead of an empty ledger, so unknown
/// historical coverage is never promoted to a current "no reservations, no
/// consumed budget" and every caller that would mint a new reservation or a new
/// budget refuses.
///
/// Each candidate keeps one bounded diagnostic naming only the fixed candidate
/// role and the fixed fault code; the decode error, the field that failed and
/// the bytes themselves are never echoed.
fn load_provider_call_ledger(path: &Path) -> Result<ProviderCallLedger, ProviderCallLedgerUnknown> {
    let mut existed = false;
    let mut faults = Vec::new();
    for candidate in [
        ProviderCallLedgerCandidate::Current,
        ProviderCallLedgerCandidate::Staged,
        ProviderCallLedgerCandidate::Backup,
    ] {
        let candidate_path = candidate.path(path);
        if !candidate_path.is_file() {
            continue;
        }
        existed = true;
        match decode_provider_call_ledger(&candidate_path) {
            Ok(ledger) => return Ok(ledger),
            Err(fault) => faults.push(ProviderCallLedgerCandidateFault {
                candidate,
                fault,
            }),
        }
    }
    if !existed {
        return Ok(ProviderCallLedger::default());
    }
    Err(ProviderCallLedgerUnknown { faults })
}

/// Decode and validate exactly one candidate file.
///
/// The three faults are bounded classifications of a refusal: `Unreadable` is
/// an open failure, `Malformed` is a strict-decode failure including an unknown
/// or duplicate member, and `Invalid` is a decodable ledger whose relations the
/// validator rejects.
fn decode_provider_call_ledger(
    candidate: &Path,
) -> Result<ProviderCallLedger, ProviderCallLedgerFault> {
    let file = File::open(candidate).map_err(|_| ProviderCallLedgerFault::Unreadable)?;
    let ledger = serde_json::from_reader::<_, ProviderCallLedger>(file)
        .map_err(|_| ProviderCallLedgerFault::Malformed)?;
    validate_provider_call_ledger(&ledger).map_err(|_| ProviderCallLedgerFault::Invalid)?;
    Ok(ledger)
}

/// Apply one explicit operator disposition of the preserved corrupt candidates.
///
/// The caller holds the ledger lock, so a reconciliation cannot race a
/// concurrent campaign: the unknown state is re-read here and the whole
/// disposition set is checked against it before a single byte moves.
fn apply_provider_call_ledger_reconciliation(
    path: &Path,
    reconciliation: &ProviderCallLedgerReconciliation,
) -> Result<ProviderCallLedgerReconciliationOutcome, EngineError> {
    let unknown = load_provider_call_ledger(path).map_err(|_| {
        rejected(
            "provider call ledger is not in an unknown state; there is no preserved corrupt candidate to reconcile",
        )
    })?;
    let refused = unknown
        .faults
        .iter()
        .map(|fault| fault.candidate)
        .collect::<Vec<_>>();
    let mut actions = Vec::new();
    for disposition in &reconciliation.dispositions {
        if !refused.contains(&disposition.candidate) {
            return Err(rejected(
                "provider call ledger reconciliation names a candidate that is not a preserved corrupt candidate",
            ));
        }
        if actions.contains(&disposition.candidate) {
            return Err(rejected(
                "provider call ledger reconciliation names one candidate twice",
            ));
        }
        actions.push(disposition.candidate);
    }
    for candidate in &refused {
        if !actions.contains(candidate) {
            return Err(rejected(
                "provider call ledger reconciliation leaves a preserved corrupt candidate without an explicit disposition",
            ));
        }
    }
    let superseded = reconciliation
        .dispositions
        .iter()
        .filter_map(|disposition| {
            (disposition.action == ProviderCallLedgerCandidateAction::SupersedeWithRecoveredRecord)
                .then_some(disposition.candidate)
        })
        .collect::<Vec<_>>();
    if superseded.len() > 1 {
        return Err(rejected(
            "provider call ledger reconciliation supersedes more than one candidate",
        ));
    }
    if superseded
        .first()
        .is_some_and(|candidate| *candidate != ProviderCallLedgerCandidate::Current)
    {
        return Err(rejected(
            "the recovered provider call ledger record becomes the current ledger, so the superseded candidate must be the current one",
        ));
    }

    let Some(runtime) = path.parent() else {
        return Err(rejected("provider call ledger path has no runtime directory"));
    };
    let quarantine_dir = runtime.join(PROVIDER_CALL_LEDGER_QUARANTINE_DIR);

    let Some(superseded) = superseded.first().copied() else {
        if reconciliation.recovered_record_from.is_some() {
            return Err(rejected(
                "a recovered provider call ledger record was supplied without an explicit admission",
            ));
        }
        // Nothing is admitted, so nothing is written: every refused candidate
        // keeps its bytes in place and the state stays unknown.
        let mut quarantined = Vec::new();
        for candidate in &refused {
            quarantined.push(preserve_provider_call_ledger_candidate(
                &candidate.path(path),
                &quarantine_dir,
                *candidate,
            )?);
        }
        return Ok(ProviderCallLedgerReconciliationOutcome {
            admitted: None,
            quarantined,
            still_unknown: true,
        });
    };

    let Some(recovered_from) = reconciliation.recovered_record_from.as_deref() else {
        return Err(rejected(
            "superseding a preserved provider call ledger candidate requires the operator's own copy of the original recorded bytes",
        ));
    };
    fs::create_dir_all(&quarantine_dir)?;
    let original_bytes = fs::read(recovered_from)?;
    let admitted_path = quarantine_dir.join(format!(
        "admitted-{}.json",
        eliot_types::WorkLeaseId::new_v7()
    ));
    fs::write(&admitted_path, &original_bytes)?;
    // The admitted record is proven against the ORIGINAL recorded bytes with
    // the one decoder and the one validator every candidate is held to.
    let ledger = decode_provider_call_ledger(&admitted_path).map_err(|_| {
        rejected("the recovered provider call ledger record does not decode and validate")
    })?;
    validate_provider_call_ledger(&ledger)?;
    // Every candidate the operator dispositioned as preserved is copied
    // byte-for-byte and left refused in place.
    let mut quarantined = Vec::new();
    for candidate in &refused {
        if *candidate == superseded {
            continue;
        }
        quarantined.push(preserve_provider_call_ledger_candidate(
            &candidate.path(path),
            &quarantine_dir,
            *candidate,
        )?);
    }
    // The superseded corrupt evidence moves aside with its bytes intact, so the
    // install can neither truncate nor overwrite it.
    quarantined.push(displace_provider_call_ledger_candidate(
        &superseded.path(path),
        &quarantine_dir,
        superseded,
    )?);
    let displaced = quarantined
        .last()
        .ok_or_else(|| rejected("the superseded provider call ledger candidate is not preserved"))?
        .path
        .clone();
    if let Err(error) = fs::rename(&admitted_path, path) {
        let _ = fs::rename(&displaced, superseded.path(path));
        return Err(error.into());
    }
    Ok(ProviderCallLedgerReconciliationOutcome {
        admitted: Some(ledger),
        quarantined,
        still_unknown: false,
    })
}

/// The one quarantine file name one preserved candidate gets on one
/// reconciliation. The identity suffix keeps a later reconciliation from
/// overwriting an earlier preserved copy.
fn provider_call_ledger_quarantine_path(
    quarantine_dir: &Path,
    candidate: ProviderCallLedgerCandidate,
) -> PathBuf {
    quarantine_dir.join(format!(
        "{}-{}.corrupt",
        candidate.code(),
        eliot_types::WorkLeaseId::new_v7()
    ))
}

/// Copy the original bytes of a refused candidate into the quarantine area and
/// prove the copy is byte-identical. The candidate itself is left untouched.
fn preserve_provider_call_ledger_candidate(
    candidate_path: &Path,
    quarantine_dir: &Path,
    candidate: ProviderCallLedgerCandidate,
) -> Result<ProviderCallLedgerQuarantineEntry, EngineError> {
    let original = fs::read(candidate_path)?;
    let copy = provider_call_ledger_quarantine_path(quarantine_dir, candidate);
    fs::write(&copy, &original)?;
    if fs::read(&copy)? != original {
        return Err(rejected(
            "provider call ledger quarantine copy is not byte-identical to the preserved candidate",
        ));
    }
    Ok(ProviderCallLedgerQuarantineEntry {
        candidate,
        path: copy,
    })
}

/// Rename a refused candidate into the quarantine area. A rename preserves the
/// original bytes without rewriting them, so nothing is deleted or truncated.
fn displace_provider_call_ledger_candidate(
    candidate_path: &Path,
    quarantine_dir: &Path,
    candidate: ProviderCallLedgerCandidate,
) -> Result<ProviderCallLedgerQuarantineEntry, EngineError> {
    let preserved = provider_call_ledger_quarantine_path(quarantine_dir, candidate);
    fs::rename(candidate_path, &preserved)?;
    Ok(ProviderCallLedgerQuarantineEntry {
        candidate,
        path: preserved,
    })
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
            "provider_integration_health": health,
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

#[cfg(test)]
mod provider_call_ledger_reconciliation_tests {
    use super::*;
    use std::fs;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    const CAMPAIGN: &str = "provider-call-ledger-reconcile-campaign";
    const SECOND_CAMPAIGN: &str = "provider-call-ledger-reconcile-second-campaign";
    const OPERATOR: &str = "operator-936-reconcile";
    const CORRUPT_CURRENT: &[u8] = b"{\"budgets\": not-json";
    const CORRUPT_STAGED: &[u8] = b"{\"budgets\": [";
    const CORRUPT_BACKUP: &[u8] = b"";

    fn disposition(
        candidate: ProviderCallLedgerCandidate,
        action: ProviderCallLedgerCandidateAction,
    ) -> ProviderCallLedgerCandidateDisposition {
        ProviderCallLedgerCandidateDisposition { candidate, action }
    }

    fn preserved_bytes(candidate: ProviderCallLedgerCandidate) -> &'static [u8] {
        match candidate {
            ProviderCallLedgerCandidate::Current => CORRUPT_CURRENT,
            ProviderCallLedgerCandidate::Staged => CORRUPT_STAGED,
            ProviderCallLedgerCandidate::Backup => CORRUPT_BACKUP,
        }
    }

    fn test_error(message: &'static str) -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(std::io::Error::other(message))
    }

    /// One owner whose ledger is unknown because every candidate is corrupt,
    /// plus the original bytes an operator holds elsewhere as the record they
    /// would authorize.
    struct BlockedLedger {
        root: PathBuf,
        owner: ProviderCallReservationOwner,
        recovered: Vec<u8>,
        ledger_path: PathBuf,
    }

    fn blocked_owner(tag: &str) -> TestResult<BlockedLedger> {
        let root = std::env::temp_dir()
            .join(format!("eliot-936-ledger-reconcile-{tag}-{}", TaskId::new_v7()));
        let owner = ProviderCallReservationOwner::new(&root);
        owner.open_campaign(ProviderCallCampaignRequest {
            campaign_id: CAMPAIGN.to_owned(),
            max_calls: 2,
            closed: false,
        })?;
        let ledger_path = root.join("runtime").join("provider-call-ledger.json");
        let recovered = fs::read(&ledger_path)?;
        fs::write(&ledger_path, CORRUPT_CURRENT)?;
        fs::write(ledger_path.with_extension("json.next"), CORRUPT_STAGED)?;
        fs::write(ledger_path.with_extension("json.bak"), CORRUPT_BACKUP)?;
        if !matches!(
            owner.snapshot(),
            Err(EngineError::ProviderCallLedgerUnknown(_))
        ) {
            return Err(test_error(
                "a corrupt ledger must refuse before it is reconciled",
            ));
        }
        Ok(BlockedLedger {
            root,
            owner,
            recovered,
            ledger_path,
        })
    }

    /// Raw-byte fixtures for the durable provider-call ledger boundary.
    ///
    /// Every document below is text, never a `serde_json::Value`. A `Value`
    /// fixture is already the collapsed projection of the document, so it cannot
    /// carry a duplicate member, an unknown member spelling or a truncation at
    /// all: those are lexical facts that only the raw bytes carry, and they are
    /// the facts this boundary exists to refuse.
    const RAW_CAMPAIGN: &str = "provider-call-ledger-raw-campaign";
    const RAW_RESERVATION_ID: &str = "provider-call-reservation-raw-1";

    /// The one budget of the admitted ledger, as raw text.
    ///
    /// Every counter in it is re-derivable from [`RAW_RESERVATION`]: one
    /// reserved slot, no dispatched slot, no terminal slot, one consumed call of
    /// a ceiling of two, and the next free slot index is 2.
    const RAW_BUDGET: &str = r#"{"campaign_id":"provider-call-ledger-raw-campaign","schema_version":"provider-call-campaign-v1","max_calls":2,"next_slot_index":2,"reserved_slots":1,"dispatched_slots":0,"terminal_slots":0,"remaining_calls":1,"revision":1,"closed":false,"updated_at":"2026-10-01T00:00:00Z"}"#;

    /// The one reserved, not yet dispatched reservation of the admitted ledger,
    /// as raw text.
    const RAW_RESERVATION: &str = r#"{"reservation_id":"provider-call-reservation-raw-1","campaign_id":"provider-call-ledger-raw-campaign","task_id":"00000000-0000-7000-8000-000000000001","provider":"antigravity","idempotency_key":"provider-call-idempotency-raw-1","slot_index":1,"budget_revision":1,"gate_decision_ref":"gate-decision-raw-1","state":"reserved","reserved_at":"2026-10-01T00:00:00Z","dispatch_started_at":null,"external_invocation_ref":null,"review_ref":null,"terminal_at":null,"consumes_budget":true,"release_or_failure_reason":null}"#;

    /// A second reservation of the same campaign whose only collision with
    /// [`RAW_RESERVATION`] is its `reservation_id`. Its idempotency key, slot
    /// index and task are distinct, so a refusal of the pair is provably about
    /// the duplicated reservation identity and nothing else.
    const RAW_SECOND_RESERVATION: &str = r#"{"reservation_id":"provider-call-reservation-raw-1","campaign_id":"provider-call-ledger-raw-campaign","task_id":"00000000-0000-7000-8000-000000000002","provider":"antigravity","idempotency_key":"provider-call-idempotency-raw-2","slot_index":2,"budget_revision":1,"gate_decision_ref":"gate-decision-raw-2","state":"reserved","reserved_at":"2026-10-01T00:00:00Z","dispatch_started_at":null,"external_invocation_ref":null,"review_ref":null,"terminal_at":null,"consumes_budget":true,"release_or_failure_reason":null}"#;

    fn ledger_failure(message: String) -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(std::io::Error::other(message))
    }

    /// Splice one raw lexical fact into an assembled document.
    ///
    /// An absent segment is refused rather than ignored, because a silently
    /// unspliced fixture would quietly turn a negative case into a positive one
    /// and the whole case would then pass for the wrong reason.
    fn splice(raw: String, segment: &str, replacement: &str) -> String {
        assert!(
            raw.contains(segment),
            "unknown raw document segment {segment}"
        );
        raw.replacen(segment, replacement, 1)
    }

    /// One raw ledger document assembled from the raw segments above.
    fn raw_ledger(budget_fields: &[(&str, &str)], reservations: &[&str]) -> String {
        let mut budget = String::from(RAW_BUDGET);
        for (segment, replacement) in budget_fields {
            assert!(budget.contains(segment), "unknown raw budget segment {segment}");
            budget = budget.replacen(segment, replacement, 1);
        }
        format!(
            r#"{{"budgets":[{budget}],"reservations":[{}]}}"#,
            reservations.join(",")
        )
    }

    /// One raw reservation assembled from the raw segment above.
    fn raw_reservation(fields: &[(&str, &str)]) -> String {
        let mut reservation = String::from(RAW_RESERVATION);
        for (segment, replacement) in fields {
            assert!(
                reservation.contains(segment),
                "unknown raw reservation segment {segment}"
            );
            reservation = reservation.replacen(segment, replacement, 1);
        }
        reservation
    }

    /// The exact refusal the one strict DTO produces for these raw bytes.
    fn decode_refusal(raw: &str) -> TestResult<String> {
        match serde_json::from_str::<ProviderCallLedger>(raw) {
            Ok(_) => Err(ledger_failure(
                "the raw document decoded into trusted provider call ledger state".to_owned(),
            )),
            Err(refusal) => Ok(refusal.to_string()),
        }
    }

    /// The exact refusal the one validator produces for a decodable document.
    ///
    /// Reaching the validator at all proves the strict decoder admitted the
    /// bytes, so the refusal below is the ledger relation that refused them and
    /// not a lexical defect.
    fn validation_refusal(raw: &str) -> TestResult<String> {
        let ledger: ProviderCallLedger = serde_json::from_str(raw)?;
        match validate_provider_call_ledger(&ledger) {
            Ok(()) => Err(ledger_failure(
                "the raw document validated as complete provider call ledger state".to_owned(),
            )),
            Err(refusal) => Ok(refusal.to_string()),
        }
    }

    fn raw_ledger_root(tag: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!("eliot-936-ledger-raw-{tag}-{}", TaskId::new_v7()))
    }

    /// The typed unknown refusal a caller-visible ledger read must produce.
    fn provider_call_unknown_refusal(
        outcome: Result<ProviderCallLedger, EngineError>,
    ) -> TestResult<String> {
        match outcome {
            Err(EngineError::ProviderCallLedgerUnknown(refusal)) => Ok(refusal),
            other => Err(ledger_failure(format!(
                "a corrupt ledger must refuse as unknown, never answer: {other:?}"
            ))),
        }
    }

    /// One raw current-candidate file, refused through both the private loader
    /// the mutating funnel uses and the public snapshot.
    ///
    /// The bounded faults are read from the typed refusal itself rather than
    /// from its rendering, so a case can name the rule that fired and not merely
    /// that something refused. The original bytes are compared afterwards
    /// because a refused candidate must survive the refusal intact.
    fn blocked_by_raw_ledger(
        tag: &str,
        raw: &str,
    ) -> TestResult<Vec<(ProviderCallLedgerCandidate, &'static str)>> {
        let root = raw_ledger_root(tag);
        let owner = ProviderCallReservationOwner::new(&root);
        let runtime = root.join("runtime");
        fs::create_dir_all(&runtime)?;
        let ledger_path = runtime.join("provider-call-ledger.json");
        fs::write(&ledger_path, raw)?;
        let loaded = load_provider_call_ledger(&ledger_path);
        let published = owner.snapshot();
        let preserved = fs::read(&ledger_path)?;
        fs::remove_dir_all(&root)?;
        let faults = match loaded {
            Ok(_) => {
                return Err(ledger_failure(
                    "the raw candidate was admitted as current provider call ledger state".to_owned(),
                ));
            }
            Err(unknown) => unknown
                .faults
                .iter()
                .map(|entry| (entry.candidate, entry.fault.code()))
                .collect(),
        };
        let refusal = provider_call_unknown_refusal(published)?;
        for (candidate, fault) in &faults {
            assert!(
                refusal.contains(&format!("{}={}", candidate.code(), fault)),
                "the refusal must name the candidate role and its bounded fault: {refusal}"
            );
        }
        assert_eq!(
            preserved,
            raw.as_bytes(),
            "a refused candidate must keep its original bytes"
        );
        Ok(faults)
    }

    /// WORK_UNIT_CASE: 936/5 — an unknown member is refused by name at the
    /// envelope and inside a reservation, before any trusted ledger exists.
    #[test]
    fn unknown_ledger_members_refuse_by_name_at_both_levels() -> TestResult {
        let outer = splice(
            raw_ledger(&[], &[RAW_RESERVATION]),
            r#","reservations":["#,
            r#","ledger_authority":"granted","reservations":["#,
        );
        let nested = splice(
            raw_ledger(&[], &[RAW_RESERVATION]),
            r#""state":"reserved""#,
            r#""state":"reserved","authority":"granted""#,
        );
        for (tag, raw, member) in [
            ("unknown-outer", &outer, "ledger_authority"),
            ("unknown-nested", &nested, "authority"),
        ] {
            let refusal = decode_refusal(raw)?;
            assert!(
                refusal.contains("unknown field"),
                "an unknown member must be refused as unknown, not by an unrelated \
                 failure anywhere in the record: {refusal}"
            );
            assert!(
                refusal.contains(member),
                "the refusal must name the unknown member {member}: {refusal}"
            );
            assert_eq!(
                blocked_by_raw_ledger(tag, raw)?,
                vec![(ProviderCallLedgerCandidate::Current, "malformed")]
            );
        }
        Ok(())
    }

    /// WORK_UNIT_CASE: 936/6 — a duplicated member is refused by name at the
    /// budget and inside a reservation, even when both copies carry the same
    /// value, because a duplicate is a lexical fact no field-value check sees.
    #[test]
    fn duplicate_ledger_members_refuse_by_name_at_both_levels() -> TestResult {
        let budget = splice(
            raw_ledger(&[], &[RAW_RESERVATION]),
            r#""max_calls":2"#,
            r#""schema_version":"provider-call-campaign-v1","max_calls":2"#,
        );
        let reservation = raw_ledger(
            &[],
            &[&raw_reservation(&[(
                r#""slot_index":1"#,
                r#""slot_index":1,"slot_index":2"#,
            )])],
        );
        for (tag, raw, field) in [
            ("duplicate-budget", &budget, "schema_version"),
            ("duplicate-reservation-field", &reservation, "slot_index"),
        ] {
            let refusal = decode_refusal(raw)?;
            assert!(
                refusal.contains("duplicate field"),
                "a duplicated member must be refused as a duplicate, not by an \
                 unrelated failure anywhere in the record: {refusal}"
            );
            assert!(
                refusal.contains(&format!("`{field}`")),
                "the refusal must name the duplicated field {field}: {refusal}"
            );
            assert_eq!(
                blocked_by_raw_ledger(tag, raw)?,
                vec![(ProviderCallLedgerCandidate::Current, "malformed")]
            );
        }
        Ok(())
    }

    /// A truncated document is refused as the truncation it is, not read as an
    /// absent or empty ledger.
    #[test]
    fn a_truncated_ledger_document_refuses_without_becoming_empty() -> TestResult {
        let admitted = raw_ledger(&[], &[RAW_RESERVATION]);
        let truncated = &admitted[..admitted.len() / 2];
        assert!(
            admitted.starts_with(truncated) && truncated.len() < admitted.len(),
            "the refused bytes must be a strict prefix of an admitted ledger, so \
             truncation is the only defect present"
        );
        let refusal = decode_refusal(truncated)?;
        assert!(
            refusal.contains("line 1 column"),
            "a truncated single-line document must be refused for where the \
             document stops, not by an unrelated failure: {refusal}"
        );
        assert_eq!(
            blocked_by_raw_ledger("truncated", truncated)?,
            vec![(ProviderCallLedgerCandidate::Current, "malformed")]
        );
        Ok(())
    }

    /// WORK_UNIT_CASE: 936/7 — an empty protected reservation identity refuses
    /// by field name at the decoder, so `mark_dispatching("")` can never find
    /// and mutate a record a tampered file planted under that identity.
    #[test]
    fn an_empty_reservation_identity_refuses_by_field_name() -> TestResult {
        let raw = raw_ledger(
            &[],
            &[&raw_reservation(&[(
                r#""reservation_id":"provider-call-reservation-raw-1""#,
                r#""reservation_id":"""#,
            )])],
        );
        let refusal = decode_refusal(&raw)?;
        assert!(
            refusal.contains("empty protected identifier"),
            "a spelled-out empty reservation identity must be refused for being \
             empty, not by an unrelated failure: {refusal}"
        );
        assert!(
            refusal.contains("reservation_id"),
            "the refusal must name the offending field: {refusal}"
        );
        assert_eq!(
            blocked_by_raw_ledger("empty-reservation-id", &raw)?,
            vec![(ProviderCallLedgerCandidate::Current, "malformed")]
        );
        Ok(())
    }

    /// WORK_UNIT_CASE: 936/8 — a foreign campaign schema version refuses
    /// without guessing which version it is, and the refusal never echoes the
    /// version it refused.
    #[test]
    fn a_foreign_campaign_schema_version_refuses_naming_the_owned_one() -> TestResult {
        for (tag, foreign) in [
            ("schema-v2", "provider-call-campaign-v2"),
            ("schema-renamed", "provider-call-ledger-v1"),
        ] {
            let raw = raw_ledger(
                &[(
                    r#""schema_version":"provider-call-campaign-v1""#,
                    &format!(r#""schema_version":"{foreign}""#),
                )],
                &[RAW_RESERVATION],
            );
            let refusal = decode_refusal(&raw)?;
            assert!(
                refusal.contains("unsupported provider call schema version"),
                "a foreign schema version must be refused as unsupported, not by \
                 an unrelated failure: {refusal}"
            );
            assert!(
                refusal.contains(PROVIDER_CALL_CAMPAIGN_SCHEMA_VERSION),
                "the refusal must name the version this build owns: {refusal}"
            );
            assert!(
                !refusal.contains(foreign),
                "the refusal must not echo the foreign version onto a surface: {refusal}"
            );
            assert_eq!(
                blocked_by_raw_ledger(tag, &raw)?,
                vec![(ProviderCallLedgerCandidate::Current, "malformed")]
            );
        }
        Ok(())
    }

    /// A duplicated reservation identity refuses even though every other
    /// relation of the pair — idempotency key, slot index, budget binding,
    /// counters — is intact and would otherwise validate.
    #[test]
    fn a_duplicated_reservation_identity_refuses_by_field_name() -> TestResult {
        let raw = raw_ledger(
            &[
                (r#""next_slot_index":2"#, r#""next_slot_index":3"#),
                (r#""reserved_slots":1"#, r#""reserved_slots":2"#),
                (r#""remaining_calls":1"#, r#""remaining_calls":0"#),
            ],
            &[RAW_RESERVATION, RAW_SECOND_RESERVATION],
        );
        assert_eq!(
            validation_refusal(&raw)?,
            "write rejected: provider call reservation identity is not unique",
            "the duplicated reservation identity must be the rule that refuses"
        );
        assert_eq!(
            blocked_by_raw_ledger("duplicate-reservation-identity", &raw)?,
            vec![(ProviderCallLedgerCandidate::Current, "invalid")]
        );
        Ok(())
    }

    /// A reservation bound to no existing campaign refuses, and the budget is
    /// written so the document would otherwise validate: the orphan binding is
    /// provably the only defect it carries.
    #[test]
    fn an_orphan_reservation_refuses_by_field_name() -> TestResult {
        let orphan = raw_reservation(&[(
            r#""campaign_id":"provider-call-ledger-raw-campaign""#,
            r#""campaign_id":"provider-call-ledger-absent-campaign""#,
        )]);
        let raw = raw_ledger(
            &[
                (r#""next_slot_index":2"#, r#""next_slot_index":1"#),
                (r#""reserved_slots":1"#, r#""reserved_slots":0"#),
                (r#""remaining_calls":1"#, r#""remaining_calls":2"#),
            ],
            &[&orphan],
        );
        assert_eq!(
            validation_refusal(&raw)?,
            "write rejected: provider call reservation references no existing campaign",
            "the missing campaign binding must be the rule that refuses"
        );
        assert_eq!(
            blocked_by_raw_ledger("orphan-reservation", &raw)?,
            vec![(ProviderCallLedgerCandidate::Current, "invalid")]
        );
        Ok(())
    }

    /// A stored counter edited upward to unblock one more provider call refuses,
    /// because the counters are re-derived from the reservations rather than
    /// range-checked against themselves.
    #[test]
    fn a_tampered_budget_counter_refuses_by_field_name() -> TestResult {
        let raw = raw_ledger(
            &[(
                r#""remaining_calls":1"#,
                r#""remaining_calls":2"#,
            )],
            &[RAW_RESERVATION],
        );
        assert_eq!(
            validation_refusal(&raw)?,
            "write rejected: provider call budget counters are not recomputed from their reservations",
            "the tampered counter must be the rule that refuses"
        );
        assert_eq!(
            blocked_by_raw_ledger("tampered-counter", &raw)?,
            vec![(ProviderCallLedgerCandidate::Current, "invalid")]
        );
        Ok(())
    }

    /// WORK_UNIT_CASE: 936/15 — when every candidate is corrupt the loader
    /// refuses with one typed unknown disposition, and the refusal preserves
    /// the corrupt evidence byte-for-byte without producing a default ledger.
    #[test]
    fn every_corrupt_candidate_refuses_and_preserves_its_bytes() -> TestResult {
        let root = raw_ledger_root("all-corrupt");
        let owner = ProviderCallReservationOwner::new(&root);
        let runtime = root.join("runtime");
        fs::create_dir_all(&runtime)?;
        let ledger_path = runtime.join("provider-call-ledger.json");
        let admitted = raw_ledger(&[], &[RAW_RESERVATION]);
        let candidates = [
            (
                ProviderCallLedgerCandidate::Current,
                admitted[..admitted.len() / 2].to_owned(),
            ),
            (
                ProviderCallLedgerCandidate::Staged,
                splice(
                    raw_ledger(&[], &[RAW_RESERVATION]),
                    r#""max_calls":2"#,
                    r#""max_calls":2,"max_calls":2"#,
                ),
            ),
            (
                ProviderCallLedgerCandidate::Backup,
                raw_ledger(
                    &[(
                        r#""remaining_calls":1"#,
                        r#""remaining_calls":2"#,
                    )],
                    &[RAW_RESERVATION],
                ),
            ),
        ];
        for (candidate, raw) in &candidates {
            fs::write(candidate.path(&ledger_path), raw.as_bytes())?;
        }

        let faults = match load_provider_call_ledger(&ledger_path) {
            Ok(_) => {
                return Err(ledger_failure(
                    "three corrupt candidates decoded into current state".to_owned(),
                ));
            }
            Err(unknown) => unknown
                .faults
                .iter()
                .map(|entry| (entry.candidate, entry.fault.code()))
                .collect::<Vec<_>>(),
        };
        // Every candidate role is enumerated with its own bounded fault: none is
        // skipped, and a decodable-but-invalid ledger is not reported as the
        // same thing as bytes the decoder rejects.
        assert_eq!(
            faults,
            vec![
                (ProviderCallLedgerCandidate::Current, "malformed"),
                (ProviderCallLedgerCandidate::Staged, "malformed"),
                (ProviderCallLedgerCandidate::Backup, "invalid"),
            ]
        );

        let refusal = provider_call_unknown_refusal(owner.snapshot())?;
        for (candidate, fault) in &faults {
            assert!(
                refusal.contains(&format!("{}={}", candidate.code(), fault)),
                "the published refusal must name every refused candidate: {refusal}"
            );
        }
        assert!(
            !refusal.contains(RAW_CAMPAIGN) && !refusal.contains(RAW_RESERVATION_ID),
            "the refusal must carry bounded codes only, never ledger contents: {refusal}"
        );
        // The read-only projection and the single write funnel both refuse too,
        // so a reader cannot observe an empty budget the writer would refuse.
        provider_call_unknown_refusal(owner.snapshot_read_only())?;
        provider_call_unknown_refusal(owner.open_campaign(ProviderCallCampaignRequest {
            campaign_id: RAW_CAMPAIGN.to_owned(),
            max_calls: 1,
            closed: false,
        }))?;

        // Evidence preservation: no candidate byte moved, and no default or
        // empty ledger was produced anywhere in the runtime area.
        for (candidate, raw) in &candidates {
            assert_eq!(
                fs::read(candidate.path(&ledger_path))?,
                raw.as_bytes(),
                "{candidate:?} must survive the refusal byte-for-byte"
            );
        }
        let mut names = fs::read_dir(&runtime)?
            .map(|entry| {
                entry.map(|entry| entry.file_name().to_string_lossy().into_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        assert_eq!(
            names,
            vec![
                "provider-call-ledger.json",
                "provider-call-ledger.json.bak",
                "provider-call-ledger.json.lock",
                "provider-call-ledger.json.next",
            ],
            "the runtime area must hold only the preserved candidates and the lock"
        );
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    /// The positive case: the legitimate ledger these refusals are derived from
    /// is admitted as trusted state, through the same decoder and validator, and
    /// a reader and a writer both trust it.
    #[test]
    fn a_legitimate_raw_ledger_is_admitted_as_trusted_state() -> TestResult {
        let root = raw_ledger_root("admitted");
        let owner = ProviderCallReservationOwner::new(&root);
        let runtime = root.join("runtime");
        fs::create_dir_all(&runtime)?;
        let ledger_path = runtime.join("provider-call-ledger.json");
        let raw = raw_ledger(&[], &[RAW_RESERVATION]);
        fs::write(&ledger_path, raw.as_bytes())?;

        let admitted: ProviderCallLedger = serde_json::from_str(&raw)?;
        validate_provider_call_ledger(&admitted)?;
        assert_eq!(fs::read(&ledger_path)?, raw.as_bytes());

        let snapshot = owner.snapshot()?;
        assert_eq!(snapshot.budgets.len(), 1);
        assert_eq!(snapshot.budgets[0].campaign_id, RAW_CAMPAIGN);
        assert_eq!(
            snapshot.budgets[0].schema_version,
            PROVIDER_CALL_CAMPAIGN_SCHEMA_VERSION
        );
        assert_eq!(snapshot.budgets[0].remaining_calls, 1);
        assert_eq!(snapshot.reservations.len(), 1);
        assert_eq!(snapshot.reservations[0].reservation_id, RAW_RESERVATION_ID);
        assert_eq!(
            snapshot.reservations[0].state,
            ProviderCallReservationState::Reserved
        );
        assert_eq!(snapshot.reservations[0].slot_index, 1);

        // The admitted record is real state, not a decoded decoration: the
        // campaign it names is found, and reserving against it spends the one
        // remaining call its counters actually proved.
        let budget = owner.open_campaign(ProviderCallCampaignRequest {
            campaign_id: RAW_CAMPAIGN.to_owned(),
            max_calls: 2,
            closed: false,
        })?;
        assert_eq!(budget.max_calls, 2);
        assert_eq!(budget.reserved_slots, 1);
        let ProviderCallReservationDecision::Reserved(reservation) = owner.reserve(
            ProviderCallReservationRequest {
                campaign_id: RAW_CAMPAIGN.to_owned(),
                task_id: TaskId::new_v7(),
                provider: PROVIDER_ID.to_owned(),
                idempotency_key: "provider-call-idempotency-raw-admitted".to_owned(),
                gate_decision_ref: "gate-decision-raw-admitted".to_owned(),
            },
        )?
        else {
            return Err(ledger_failure(
                "the admitted campaign must admit a new reservation".to_owned(),
            ));
        };
        assert_eq!(reservation.slot_index, 2);
        assert_eq!(owner.snapshot()?.budgets[0].remaining_calls, 0);
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn explicit_disposition_admits_the_operator_record_and_unblocks() -> TestResult {
        let BlockedLedger {
            root,
            owner,
            recovered,
            ledger_path,
        } = blocked_owner("admit")?;
        let operator_copy = root.join("operator-recovered-provider-call-ledger.json");
        fs::write(&operator_copy, &recovered)?;

        let outcome = owner.reconcile_provider_call_ledger(&ProviderCallLedgerReconciliation {
            dispositions: vec![
                disposition(
                    ProviderCallLedgerCandidate::Current,
                    ProviderCallLedgerCandidateAction::SupersedeWithRecoveredRecord,
                ),
                disposition(
                    ProviderCallLedgerCandidate::Staged,
                    ProviderCallLedgerCandidateAction::PreserveAsQuarantine,
                ),
                disposition(
                    ProviderCallLedgerCandidate::Backup,
                    ProviderCallLedgerCandidateAction::PreserveAsQuarantine,
                ),
            ],
            recovered_record_from: Some(operator_copy),
            operator_ref: OPERATOR.to_owned(),
        })?;

        assert!(!outcome.still_unknown);
        assert!(outcome.admitted.is_some());
        // The admitted ledger is the operator's original bytes, verbatim.
        assert_eq!(fs::read(&ledger_path)?, recovered);
        // The corrupt evidence survives byte-for-byte at the reported paths.
        let superseded = outcome
            .quarantined
            .iter()
            .find(|entry| entry.candidate == ProviderCallLedgerCandidate::Current)
            .ok_or_else(|| test_error("the superseded candidate is not preserved"))?;
        assert_eq!(
            fs::read(&superseded.path)?,
            preserved_bytes(ProviderCallLedgerCandidate::Current)
        );
        // The other refused candidates were never touched: they are still
        // refused in place, and no ledger byte was rewritten for them.
        assert_eq!(
            fs::read(ledger_path.with_extension("json.next"))?,
            preserved_bytes(ProviderCallLedgerCandidate::Staged)
        );
        assert_eq!(
            fs::read(ledger_path.with_extension("json.bak"))?,
            preserved_bytes(ProviderCallLedgerCandidate::Backup)
        );
        // New provider calls are unblocked, and the admitted campaign survives.
        let second = owner.open_campaign(ProviderCallCampaignRequest {
            campaign_id: SECOND_CAMPAIGN.to_owned(),
            max_calls: 1,
            closed: false,
        })?;
        assert_eq!(second.max_calls, 1);
        assert!(
            owner
                .snapshot()?
                .budgets
                .iter()
                .any(|budget| budget.campaign_id == CAMPAIGN)
        );
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn absent_ambiguous_or_unauthorised_disposition_refuses_and_keeps_the_bytes() -> TestResult {
        let BlockedLedger {
            root,
            owner,
            recovered: _recovered,
            ledger_path,
        } = blocked_owner("refusal")?;

        // Absent intent: one refused candidate carries no disposition.
        assert!(
            owner
                .reconcile_provider_call_ledger(&ProviderCallLedgerReconciliation {
                    dispositions: vec![
                        disposition(
                            ProviderCallLedgerCandidate::Current,
                            ProviderCallLedgerCandidateAction::PreserveAsQuarantine,
                        ),
                        disposition(
                            ProviderCallLedgerCandidate::Staged,
                            ProviderCallLedgerCandidateAction::PreserveAsQuarantine,
                        ),
                    ],
                    recovered_record_from: None,
                    operator_ref: OPERATOR.to_owned(),
                })
                .is_err()
        );

        // Ambiguous intent: two candidates superseded at once.
        assert!(
            owner
                .reconcile_provider_call_ledger(&ProviderCallLedgerReconciliation {
                    dispositions: vec![
                        disposition(
                            ProviderCallLedgerCandidate::Current,
                            ProviderCallLedgerCandidateAction::SupersedeWithRecoveredRecord,
                        ),
                        disposition(
                            ProviderCallLedgerCandidate::Staged,
                            ProviderCallLedgerCandidateAction::SupersedeWithRecoveredRecord,
                        ),
                    ],
                    recovered_record_from: None,
                    operator_ref: OPERATOR.to_owned(),
                })
                .is_err()
        );

        // Unauthorised intent: no bounded operator identity.
        assert!(
            owner
                .reconcile_provider_call_ledger(&ProviderCallLedgerReconciliation {
                    dispositions: vec![
                        disposition(
                            ProviderCallLedgerCandidate::Current,
                            ProviderCallLedgerCandidateAction::PreserveAsQuarantine,
                        ),
                        disposition(
                            ProviderCallLedgerCandidate::Staged,
                            ProviderCallLedgerCandidateAction::PreserveAsQuarantine,
                        ),
                        disposition(
                            ProviderCallLedgerCandidate::Backup,
                            ProviderCallLedgerCandidateAction::PreserveAsQuarantine,
                        ),
                    ],
                    recovered_record_from: None,
                    operator_ref: String::new(),
                })
                .is_err()
        );

        // Nothing moved: every corrupt candidate is intact and the ledger is
        // still unknown, so new provider calls stay blocked.
        for (path, expected) in [
            (ledger_path.clone(), CORRUPT_CURRENT),
            (ledger_path.with_extension("json.next"), CORRUPT_STAGED),
            (ledger_path.with_extension("json.bak"), CORRUPT_BACKUP),
        ] {
            assert_eq!(fs::read(&path)?, expected);
        }
        assert!(matches!(
            owner.snapshot(),
            Err(EngineError::ProviderCallLedgerUnknown(_))
        ));
        assert!(!root
            .join("runtime")
            .join(PROVIDER_CALL_LEDGER_QUARANTINE_DIR)
            .exists());
        fs::remove_dir_all(&root)?;
        Ok(())
    }
}
