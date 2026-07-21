//! Responsibility contour resolution and bounded-autonomy state transitions.

use crate::{CompletionGate, EngineError, WriteAdmissionService, WriterHandle};
use eliot_types::{
    AgentId, AutonomyRunContract, AutonomyRunState, AutonomyRunTransitionReceipt, CommandContext,
    CompletionProof, CompletionStatus, ContourPolicyScope, ContourPreferredRoute,
    ContourRouteDecision, ContourRoutePolicy, LifecycleStatus, LiveContourRoute, OperatorCommand,
    ProjectId, ResponsibilityContour, RiskTier, SemanticCommand, SessionId, TaintClass, TaskId,
    ToolObservationRecordCommand, Visibility, WorkItemId, WorkItemStatus, WorkScope, WriteId,
    WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct ContourRouteRequest<'a> {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub work_item_id: WorkItemId,
    pub contour: ResponsibilityContour,
    pub policies: &'a [ContourRoutePolicy],
    pub live_routes: &'a [LiveContourRoute],
    pub now: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ContourRoutingService;

impl ContourRoutingService {
    pub fn resolve(request: &ContourRouteRequest<'_>) -> Result<ContourRouteDecision, EngineError> {
        let mut policies = request
            .policies
            .iter()
            .filter(|policy| policy_applies(policy, request))
            .collect::<Vec<_>>();
        policies.sort_by_key(|policy| (scope_rank(policy.scope), policy.policy_id.as_str()));
        if policies.is_empty() {
            return Err(EngineError::ServiceNotReady {
                service: "contour-routing".to_owned(),
                reason: "no effective policy for requested contour".to_owned(),
            });
        }

        let mut ordered = Vec::<ContourPreferredRoute>::new();
        let mut hard_allowed = None::<BTreeSet<String>>;
        for policy in &policies {
            let proposed = policy
                .preferred_routes
                .iter()
                .chain(&policy.allowed_fallbacks)
                .cloned()
                .collect::<Vec<_>>();
            let filtered = proposed
                .into_iter()
                .filter(|route| {
                    hard_allowed
                        .as_ref()
                        .is_none_or(|allowed| allowed.contains(&route.host_id))
                })
                .collect::<Vec<_>>();
            if filtered.is_empty() {
                return Err(EngineError::WriteRejected(format!(
                    "contour policy {} attempts to widen or erase stronger route policy",
                    policy.policy_id
                )));
            }
            ordered = dedupe_routes(filtered);
            hard_allowed = Some(ordered.iter().map(|route| route.host_id.clone()).collect());
        }

        let live_by_host = request
            .live_routes
            .iter()
            .map(|live| (live.route.host_id.as_str(), live))
            .collect::<HashMap<_, _>>();
        let eligible = ordered
            .iter()
            .filter_map(|route| {
                let live = live_by_host.get(route.host_id.as_str())?;
                let capabilities_match = route
                    .capability_requirements
                    .iter()
                    .all(|required| live.capability_evidence.contains(required));
                (live.available && live.retention_allowed && capabilities_match)
                    .then_some((route.clone(), *live))
            })
            .collect::<Vec<_>>();
        let Some((selected_route, selected_live)) = eligible.first() else {
            return Err(EngineError::ServiceNotReady {
                service: "contour-routing".to_owned(),
                reason: "no permitted route is live with required capabilities and retention"
                    .to_owned(),
            });
        };
        let fallback = eligible.get(1).map(|(route, _)| route.clone());
        let policy_refs = policies
            .iter()
            .map(|policy| format!("{}@{}", policy.policy_id, policy.policy_snapshot_id))
            .collect::<Vec<_>>();
        let receipt_body = json!({
            "task_id": request.task_id,
            "work_item_id": request.work_item_id,
            "contour": request.contour,
            "selected_host": selected_route.host_id,
            "policy_refs": policy_refs,
        });
        let decision_receipt = format!(
            "contour-route:{}",
            blake3::hash(&serde_json::to_vec(&receipt_body)?).to_hex()
        );
        Ok(ContourRouteDecision {
            task_id: request.task_id,
            work_item_id: request.work_item_id,
            contour: request.contour,
            candidate_routes: ordered,
            selected_route: selected_route.clone(),
            capability_evidence: selected_live.capability_evidence.clone(),
            availability_evidence: selected_live.availability_evidence.clone(),
            policy_refs,
            cost_latency_estimate: selected_live.cost_latency_estimate.clone(),
            fallback,
            decision_receipt,
        })
    }
}

fn policy_applies(policy: &ContourRoutePolicy, request: &ContourRouteRequest<'_>) -> bool {
    if policy.contour != request.contour
        || policy.effective_from > request.now
        || policy
            .expires_at
            .is_some_and(|expires| expires <= request.now)
    {
        return false;
    }
    match policy.scope {
        ContourPolicyScope::System => true,
        ContourPolicyScope::Project => policy.project_id == Some(request.project_id),
        ContourPolicyScope::Task => {
            policy.project_id.is_none_or(|id| id == request.project_id)
                && policy.task_id == Some(request.task_id)
        }
    }
}

const fn scope_rank(scope: ContourPolicyScope) -> u8 {
    match scope {
        ContourPolicyScope::System => 0,
        ContourPolicyScope::Project => 1,
        ContourPolicyScope::Task => 2,
    }
}

fn dedupe_routes(routes: Vec<ContourPreferredRoute>) -> Vec<ContourPreferredRoute> {
    let mut seen = BTreeSet::new();
    routes
        .into_iter()
        .filter(|route| seen.insert(route.host_id.clone()))
        .collect()
}

#[derive(Clone, Debug)]
pub struct AutonomyTransitionRequest {
    pub target: AutonomyRunState,
    pub reason: String,
    pub risk_tier: String,
    pub approval: Option<CanonicalR3ApprovalAuthorization>,
    pub verifier_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalR3ApprovalAuthorization {
    pub approval_id: String,
    pub exact_action_hash: String,
    pub decision_receipt: WriteReceiptRef,
    pub approved_by: SessionId,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AutonomyTripwirePolicy {
    pub repeated_failure_threshold: u32,
    pub no_novelty_tool_call_threshold: u32,
}

impl Default for AutonomyTripwirePolicy {
    fn default() -> Self {
        Self {
            repeated_failure_threshold: 3,
            no_novelty_tool_call_threshold: 5,
        }
    }
}

impl AutonomyTripwirePolicy {
    fn validate(&self) -> Result<(), EngineError> {
        if self.repeated_failure_threshold == 0 || self.no_novelty_tool_call_threshold == 0 {
            return contract_error("tripwire thresholds must be positive");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyTripwireKind {
    RepeatedFailedAction,
    NoNovelty,
    ContextSqueeze,
    CalibrationCollapse,
    RepeatedRefutation,
    ProviderRuntimeFailure,
    LeaseExpiry,
    WriteSetConflict,
    VerifierFailure,
    BudgetExhaustion,
    PolicyViolation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AutonomyTripwireRecord {
    pub tripwire_id: String,
    pub kind: AutonomyTripwireKind,
    pub signature: Option<String>,
    pub reason: String,
    pub ledger_revision: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AutonomyBudgetLedger {
    pub revision: u64,
    pub model_invocations: u32,
    pub tool_calls: u32,
    pub wall_time_seconds: u64,
    pub cost_or_token_units: u64,
    pub work_items_started: u32,
    pub active_agents: u32,
    pub tool_calls_since_novelty: u32,
    pub repeated_failure_signatures: BTreeMap<String, u32>,
    pub tripwires: Vec<AutonomyTripwireRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AutonomyStepIntent {
    pub project_id: ProjectId,
    pub paths: Vec<String>,
    pub effect: Option<String>,
    pub model_invocations: u32,
    pub tool_calls: u32,
    pub wall_time_seconds: u64,
    pub cost_or_token_units: u64,
    pub work_items_started: u32,
    pub active_agents: u32,
    pub novelty_observed: bool,
    pub failure_signature: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AutonomyBudgetDecision {
    pub accepted: bool,
    pub reasons: Vec<String>,
    pub ledger_revision: u64,
    pub tripwires: Vec<AutonomyTripwireRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AutonomyLeaseBinding {
    pub lease_ref: String,
    pub holder: AgentId,
    pub project_id: ProjectId,
    pub scope: WorkScope,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AutonomyWorkItem {
    pub work_item_id: WorkItemId,
    pub project_id: ProjectId,
    pub dependencies: Vec<WorkItemId>,
    pub status: WorkItemStatus,
    pub required: bool,
    pub required_verifiers: Vec<String>,
    pub verifier_refs: Vec<String>,
    pub assigned_agent: Option<AgentId>,
    pub lease: Option<AutonomyLeaseBinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyRecoveryAction {
    PauseBranch,
    ResumeBranch,
    RefreshCurrentTruth,
    Reassign,
    NarrowLease,
    CheapestDiscriminativeProbe,
    EscalateApproval,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AutonomyRecoveryReceipt {
    pub recovery_id: String,
    pub autonomy_run_id: String,
    pub work_item_id: WorkItemId,
    pub action: AutonomyRecoveryAction,
    pub tripwire_id: Option<String>,
    pub previous_agent: Option<AgentId>,
    pub next_agent: Option<AgentId>,
    pub reason: String,
    pub runtime_revision: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub recovered_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundedAutonomyRuntime {
    pub contract: AutonomyRunContract,
    pub tripwire_policy: AutonomyTripwirePolicy,
    pub ledger: AutonomyBudgetLedger,
    pub work_items: Vec<AutonomyWorkItem>,
    pub transition_receipts: Vec<AutonomyRunTransitionReceipt>,
    pub recovery_receipts: Vec<AutonomyRecoveryReceipt>,
    pub runtime_revision: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AutonomyRunService;

impl AutonomyRunService {
    pub fn validate_contract(contract: &AutonomyRunContract) -> Result<(), EngineError> {
        if !(2..=4).contains(&contract.max_work_items) {
            return contract_error("max_work_items must be in the bounded range 2..=4");
        }
        if contract.max_active_agents == 0 || contract.max_active_agents > 3 {
            return contract_error("max_active_agents must be in the bounded range 1..=3");
        }
        if contract.max_model_invocations == 0
            || contract.max_tool_calls == 0
            || contract.max_wall_time_seconds == 0
        {
            return contract_error(
                "model invocation, tool-call, and wall-time budgets must be positive",
            );
        }
        if contract.acceptance_items.is_empty()
            || contract.allowed_paths.is_empty()
            || contract.forbidden_effects.is_empty()
            || contract.required_verifiers.is_empty()
            || contract.pause_conditions.is_empty()
            || contract.stop_conditions.is_empty()
            || contract.fallback_routes.is_empty()
        {
            return contract_error(
                "acceptance, path/effect bounds, verifiers, pause/stop conditions, and fallback routes are required",
            );
        }
        if contract.contour_route_policy_ref.trim().is_empty()
            || contract.recovery_policy_ref.trim().is_empty()
            || contract.policy_snapshot_id.trim().is_empty()
        {
            return contract_error("route, recovery, and policy snapshot references are required");
        }
        if !contract.allowed_projects.is_empty()
            && !contract.allowed_projects.contains(&contract.project_id)
        {
            return contract_error("allowed_projects must include the root project");
        }
        if contract
            .allowed_paths
            .iter()
            .chain(&contract.forbidden_paths)
            .any(|path| path.trim().is_empty() || has_parent_traversal(path))
        {
            return contract_error("contract paths must be non-empty and traversal-free");
        }
        let allowed = contract
            .allowed_paths
            .iter()
            .map(|path| normalize_path(path))
            .collect::<BTreeSet<_>>();
        if contract
            .forbidden_paths
            .iter()
            .map(|path| normalize_path(path))
            .any(|path| allowed.contains(&path))
        {
            return contract_error("allowed_paths and forbidden_paths overlap");
        }
        if contract.allowed_risk_tiers.iter().any(|risk| {
            !matches!(
                risk.to_ascii_uppercase().as_str(),
                "R0" | "R1" | "R2" | "R3"
            )
        }) {
            return contract_error("allowed_risk_tiers contains an unknown tier");
        }
        if contract.allowed_risk_tiers.is_empty() {
            return contract_error("allowed_risk_tiers must not be empty");
        }
        if contract
            .allowed_risk_tiers
            .iter()
            .any(|risk| risk.eq_ignore_ascii_case("R3"))
            && !contract
                .approval_boundaries
                .iter()
                .any(|boundary| boundary.eq_ignore_ascii_case("R3"))
        {
            return contract_error("R3 requires an explicit approval boundary");
        }
        if contract
            .cost_or_token_budget
            .as_deref()
            .is_some_and(|budget| parse_budget_limit(budget).is_none())
        {
            return contract_error("cost_or_token_budget must contain a positive numeric limit");
        }
        Ok(())
    }

    pub fn transition(
        contract: &mut AutonomyRunContract,
        request: &AutonomyTransitionRequest,
    ) -> Result<AutonomyRunTransitionReceipt, EngineError> {
        Self::validate_contract(contract)?;
        if request.target == AutonomyRunState::DoneVerified {
            return contract_error("DONE_VERIFIED requires complete_verified with CompletionProof");
        }
        Self::apply_transition(contract, request)
    }

    pub fn complete_verified(
        contract: &mut AutonomyRunContract,
        request: &AutonomyTransitionRequest,
        proof: &CompletionProof,
        work_items: &[AutonomyWorkItem],
    ) -> Result<AutonomyRunTransitionReceipt, EngineError> {
        Self::validate_contract(contract)?;
        if request.target != AutonomyRunState::DoneVerified {
            return contract_error("complete_verified target must be DONE_VERIFIED");
        }
        if proof.project_id != contract.project_id
            || proof.task_id != contract.root_task_id.to_string()
        {
            return contract_error("CompletionProof does not match the autonomy root task");
        }
        let gate = CompletionGate::decide(proof);
        if gate.final_status != CompletionStatus::DoneVerified {
            return contract_error(&format!(
                "CompletionProof gate rejected DONE_VERIFIED: {}",
                gate.reasons.join(",")
            ));
        }
        let verified_acceptance = proof
            .acceptance_items
            .iter()
            .filter(|item| item.status == "verified")
            .map(|item| item.item.as_str())
            .collect::<BTreeSet<_>>();
        if contract
            .acceptance_items
            .iter()
            .any(|item| !verified_acceptance.contains(item.as_str()))
        {
            return contract_error("CompletionProof omits a contract acceptance item");
        }
        if work_items.is_empty()
            || work_items
                .iter()
                .any(|item| item.required && item.status != WorkItemStatus::Completed)
        {
            return contract_error("required work items are not DONE-verifier complete");
        }
        let checks = proof
            .checks_run
            .iter()
            .map(|check| check.trim().to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if contract
            .required_verifiers
            .iter()
            .map(|verifier| verifier.trim().to_ascii_lowercase())
            .any(|verifier| !checks.contains(&verifier))
        {
            return contract_error("CompletionProof omits a contract-required verifier");
        }
        if request.verifier_refs.is_empty() {
            return contract_error("DONE_VERIFIED requires canonical verifier references");
        }
        Self::apply_transition(contract, request)
    }

    pub fn validate_lease_scope(
        contract: &AutonomyRunContract,
        project_id: ProjectId,
        scope: &WorkScope,
    ) -> Result<(), EngineError> {
        if !project_allowed(contract, project_id) {
            return contract_error("lease project is outside allowed_projects");
        }
        let risk_tier = match scope.risk_tier {
            RiskTier::Low => "R1",
            RiskTier::Medium => "R2",
            RiskTier::High => "R3",
        };
        if !contract
            .allowed_risk_tiers
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(risk_tier))
        {
            return contract_error("lease risk tier is outside the frozen contract");
        }
        let paths = scope
            .read_set
            .iter()
            .chain(&scope.write_set)
            .cloned()
            .collect::<Vec<_>>();
        let reasons = path_policy_reasons(contract, &paths);
        if !reasons.is_empty() {
            return contract_error(&format!("lease scope rejected: {}", reasons.join(",")));
        }
        Ok(())
    }

    pub fn validate_lease_narrowing(
        current: &WorkScope,
        next: &WorkScope,
    ) -> Result<(), EngineError> {
        let read_narrows = next
            .read_set
            .iter()
            .all(|path| current.read_set.iter().any(|root| path_within(path, root)));
        let write_narrows = next
            .write_set
            .iter()
            .all(|path| current.write_set.iter().any(|root| path_within(path, root)));
        let authority_narrows = next
            .authority
            .permissions
            .is_subset(&current.authority.permissions);
        let verifiers_preserved = current
            .verifier_set
            .iter()
            .all(|verifier| next.verifier_set.contains(verifier));
        if normalize_path(&current.repo_root) != normalize_path(&next.repo_root)
            || !read_narrows
            || !write_narrows
            || !authority_narrows
            || risk_rank(next.risk_tier) > risk_rank(current.risk_tier)
            || next.max_files > current.max_files
            || !verifiers_preserved
        {
            return contract_error(
                "replacement lease widens authority, scope, risk, or drops verifiers",
            );
        }
        Ok(())
    }

    fn apply_transition(
        contract: &mut AutonomyRunContract,
        request: &AutonomyTransitionRequest,
    ) -> Result<AutonomyRunTransitionReceipt, EngineError> {
        if !transition_allowed(contract.state, request.target) {
            return contract_error(&format!(
                "invalid autonomy transition {:?} -> {:?}",
                contract.state, request.target
            ));
        }
        let risk = request.risk_tier.trim().to_ascii_uppercase();
        if !contract
            .allowed_risk_tiers
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&risk))
        {
            return contract_error("transition risk tier is outside the contract");
        }
        if request.risk_tier.eq_ignore_ascii_case("R3") {
            let Some(approval) = request.approval.as_ref() else {
                return contract_error("R3 transition requires canonical HumanOperator approval");
            };
            if approval.approval_id.trim().is_empty()
                || approval.exact_action_hash.trim().is_empty()
                || approval.expires_at <= OffsetDateTime::now_utc()
            {
                return contract_error(
                    "R3 transition requires an unexpired exact canonical approval",
                );
            }
        }
        let from = contract.state;
        contract.state = request.target;
        contract.state_revision = contract.state_revision.saturating_add(1);
        Ok(AutonomyRunTransitionReceipt {
            transition_id: format!("autonomy-transition-{}", WriteId::new_v7()),
            autonomy_run_id: contract.autonomy_run_id.clone(),
            from,
            to: request.target,
            state_revision: contract.state_revision,
            reason: request.reason.clone(),
            risk_tier: request.risk_tier.clone(),
            exact_approval_hash: request
                .approval
                .as_ref()
                .map(|approval| approval.exact_action_hash.clone()),
            verifier_refs: request.verifier_refs.clone(),
            transitioned_at: OffsetDateTime::now_utc(),
            canonical_receipt: None,
        })
    }
}

impl BoundedAutonomyRuntime {
    pub fn new(
        contract: AutonomyRunContract,
        tripwire_policy: AutonomyTripwirePolicy,
    ) -> Result<Self, EngineError> {
        AutonomyRunService::validate_contract(&contract)?;
        tripwire_policy.validate()?;
        Ok(Self {
            contract,
            tripwire_policy,
            ledger: AutonomyBudgetLedger::default(),
            work_items: Vec::new(),
            transition_receipts: Vec::new(),
            recovery_receipts: Vec::new(),
            runtime_revision: 0,
        })
    }

    pub fn to_json(&self) -> Result<Vec<u8>, EngineError> {
        serde_json::to_vec(self).map_err(Into::into)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, EngineError> {
        let runtime = serde_json::from_slice::<Self>(bytes)?;
        runtime.validate_restored_state()?;
        Ok(runtime)
    }

    pub fn transition(
        &mut self,
        request: &AutonomyTransitionRequest,
    ) -> Result<AutonomyRunTransitionReceipt, EngineError> {
        let receipt = AutonomyRunService::transition(&mut self.contract, request)?;
        self.runtime_revision = self.runtime_revision.saturating_add(1);
        self.transition_receipts.push(receipt.clone());
        Ok(receipt)
    }

    pub fn complete_verified(
        &mut self,
        request: &AutonomyTransitionRequest,
        proof: &CompletionProof,
    ) -> Result<AutonomyRunTransitionReceipt, EngineError> {
        let receipt = AutonomyRunService::complete_verified(
            &mut self.contract,
            request,
            proof,
            &self.work_items,
        )?;
        self.runtime_revision = self.runtime_revision.saturating_add(1);
        self.transition_receipts.push(receipt.clone());
        Ok(receipt)
    }

    pub fn record_step(
        &mut self,
        intent: &AutonomyStepIntent,
    ) -> Result<AutonomyBudgetDecision, EngineError> {
        AutonomyRunService::validate_contract(&self.contract)?;
        if self.contract.state != AutonomyRunState::Running {
            return contract_error("budgeted steps require a RUNNING autonomy run");
        }

        let mut policy_reasons = Vec::new();
        if !project_allowed(&self.contract, intent.project_id) {
            policy_reasons.push("project_outside_contract".to_owned());
        }
        policy_reasons.extend(path_policy_reasons(&self.contract, &intent.paths));
        if intent.effect.as_ref().is_some_and(|effect| {
            self.contract
                .forbidden_effects
                .iter()
                .any(|forbidden| forbidden.eq_ignore_ascii_case(effect.trim()))
        }) {
            policy_reasons.push("forbidden_effect".to_owned());
        }

        let budget_reasons = budget_reasons(&self.contract, &self.ledger, intent);
        if !policy_reasons.is_empty() || !budget_reasons.is_empty() {
            return Ok(self.reject_step(policy_reasons, budget_reasons));
        }

        let previous_calls_without_novelty = self.ledger.tool_calls_since_novelty;
        self.ledger.model_invocations = self
            .ledger
            .model_invocations
            .saturating_add(intent.model_invocations);
        self.ledger.tool_calls = self.ledger.tool_calls.saturating_add(intent.tool_calls);
        self.ledger.wall_time_seconds = self
            .ledger
            .wall_time_seconds
            .saturating_add(intent.wall_time_seconds);
        self.ledger.cost_or_token_units = self
            .ledger
            .cost_or_token_units
            .saturating_add(intent.cost_or_token_units);
        self.ledger.work_items_started = self
            .ledger
            .work_items_started
            .saturating_add(intent.work_items_started);
        self.ledger.active_agents = intent.active_agents;
        self.ledger.tool_calls_since_novelty = if intent.novelty_observed {
            0
        } else {
            previous_calls_without_novelty.saturating_add(intent.tool_calls)
        };
        self.ledger.revision = self.ledger.revision.saturating_add(1);
        self.runtime_revision = self.runtime_revision.saturating_add(1);

        let mut tripwires = Vec::new();
        if !intent.novelty_observed
            && previous_calls_without_novelty < self.tripwire_policy.no_novelty_tool_call_threshold
            && self.ledger.tool_calls_since_novelty
                >= self.tripwire_policy.no_novelty_tool_call_threshold
        {
            tripwires.push(self.push_tripwire(
                AutonomyTripwireKind::NoNovelty,
                None,
                "tool calls crossed the no-novelty threshold".to_owned(),
            ));
        }
        if let Some(signature) = intent.failure_signature.as_ref() {
            let count = self
                .ledger
                .repeated_failure_signatures
                .entry(signature.clone())
                .or_default();
            *count = count.saturating_add(1);
            if *count == self.tripwire_policy.repeated_failure_threshold {
                tripwires.push(self.push_tripwire(
                    AutonomyTripwireKind::RepeatedFailedAction,
                    Some(signature.clone()),
                    "failure signature reached the retry tripwire".to_owned(),
                ));
            }
        }
        Ok(AutonomyBudgetDecision {
            accepted: true,
            reasons: Vec::new(),
            ledger_revision: self.ledger.revision,
            tripwires,
        })
    }

    fn reject_step(
        &mut self,
        policy_reasons: Vec<String>,
        budget_reasons: Vec<String>,
    ) -> AutonomyBudgetDecision {
        self.ledger.revision = self.ledger.revision.saturating_add(1);
        self.runtime_revision = self.runtime_revision.saturating_add(1);
        let mut tripwires = Vec::new();
        if !policy_reasons.is_empty() {
            tripwires.push(self.push_tripwire(
                AutonomyTripwireKind::PolicyViolation,
                None,
                policy_reasons.join(","),
            ));
        }
        if !budget_reasons.is_empty() {
            tripwires.push(self.push_tripwire(
                AutonomyTripwireKind::BudgetExhaustion,
                None,
                budget_reasons.join(","),
            ));
        }
        let reasons = policy_reasons.into_iter().chain(budget_reasons).collect();
        AutonomyBudgetDecision {
            accepted: false,
            reasons,
            ledger_revision: self.ledger.revision,
            tripwires,
        }
    }

    pub fn record_external_tripwire(
        &mut self,
        kind: AutonomyTripwireKind,
        signature: Option<String>,
        reason: impl Into<String>,
    ) -> AutonomyTripwireRecord {
        self.ledger.revision = self.ledger.revision.saturating_add(1);
        self.runtime_revision = self.runtime_revision.saturating_add(1);
        self.push_tripwire(kind, signature, reason.into())
    }

    pub fn register_work_item(&mut self, item: AutonomyWorkItem) -> Result<(), EngineError> {
        if self.work_items.len() >= self.contract.max_work_items as usize {
            return contract_error("work-item budget exhausted");
        }
        if item.status != WorkItemStatus::Open
            || item.assigned_agent.is_some()
            || item.lease.is_some()
        {
            return contract_error("new work items must be unassigned and OPEN");
        }
        if !project_allowed(&self.contract, item.project_id) {
            return contract_error("work item project is outside allowed_projects");
        }
        if self
            .work_items
            .iter()
            .any(|existing| existing.work_item_id == item.work_item_id)
        {
            return contract_error("duplicate work_item_id");
        }
        let dependencies = item.dependencies.iter().copied().collect::<BTreeSet<_>>();
        if dependencies.len() != item.dependencies.len()
            || dependencies.contains(&item.work_item_id)
            || dependencies.iter().any(|dependency| {
                !self
                    .work_items
                    .iter()
                    .any(|existing| existing.work_item_id == *dependency)
            })
        {
            return contract_error("work-item dependencies must be unique existing predecessors");
        }
        if item.required && item.required_verifiers.is_empty() {
            return contract_error("required work item must declare a verifier");
        }
        self.work_items.push(item);
        self.runtime_revision = self.runtime_revision.saturating_add(1);
        Ok(())
    }

    pub fn ready_work_items(&self) -> Vec<WorkItemId> {
        self.work_items
            .iter()
            .filter(|item| {
                item.status == WorkItemStatus::Open
                    && item.dependencies.iter().all(|dependency| {
                        self.work_items.iter().any(|candidate| {
                            candidate.work_item_id == *dependency
                                && candidate.status == WorkItemStatus::Completed
                        })
                    })
            })
            .map(|item| item.work_item_id)
            .collect()
    }

    pub fn activate_work_item(
        &mut self,
        work_item_id: WorkItemId,
        lease: AutonomyLeaseBinding,
        now: OffsetDateTime,
    ) -> Result<(), EngineError> {
        if self.contract.state != AutonomyRunState::Running {
            return contract_error("work items can activate only while RUNNING");
        }
        let index = self
            .work_items
            .iter()
            .position(|item| item.work_item_id == work_item_id)
            .ok_or_else(|| EngineError::WriteRejected("unknown work_item_id".to_owned()))?;
        if !self.ready_work_items().contains(&work_item_id) {
            return contract_error("work-item dependencies are not complete");
        }
        if lease.lease_ref.trim().is_empty()
            || lease.expires_at <= now
            || lease.project_id != self.work_items[index].project_id
        {
            return contract_error("work-item lease is missing, expired, or project-mismatched");
        }
        AutonomyRunService::validate_lease_scope(&self.contract, lease.project_id, &lease.scope)?;
        let mut agents = self
            .work_items
            .iter()
            .filter(|item| item.status == WorkItemStatus::Active)
            .filter_map(|item| item.assigned_agent)
            .collect::<Vec<_>>();
        if !agents.contains(&lease.holder) {
            agents.push(lease.holder);
        }
        if agents.len() > self.contract.max_active_agents as usize {
            return contract_error("active-agent budget exhausted");
        }
        let item = &mut self.work_items[index];
        item.status = WorkItemStatus::Active;
        item.assigned_agent = Some(lease.holder);
        item.lease = Some(lease);
        self.ledger.active_agents = u32::try_from(agents.len()).unwrap_or(u32::MAX);
        self.ledger.work_items_started = self.ledger.work_items_started.saturating_add(1);
        self.runtime_revision = self.runtime_revision.saturating_add(1);
        Ok(())
    }

    pub fn complete_work_item(
        &mut self,
        work_item_id: WorkItemId,
        verifier_names: &[String],
        verifier_refs: Vec<String>,
        now: OffsetDateTime,
    ) -> Result<(), EngineError> {
        if self.contract.state != AutonomyRunState::Running {
            return contract_error("work items can complete only while RUNNING");
        }
        let item = self
            .work_items
            .iter_mut()
            .find(|item| item.work_item_id == work_item_id)
            .ok_or_else(|| EngineError::WriteRejected("unknown work_item_id".to_owned()))?;
        if item.status != WorkItemStatus::Active {
            return contract_error("only ACTIVE work items can complete");
        }
        if item
            .lease
            .as_ref()
            .is_none_or(|lease| lease.expires_at <= now)
        {
            return contract_error("active work-item lease expired before completion");
        }
        let observed = verifier_names
            .iter()
            .map(|name| name.trim().to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if item
            .required_verifiers
            .iter()
            .map(|name| name.trim().to_ascii_lowercase())
            .any(|required| !observed.contains(&required))
            || verifier_refs.is_empty()
        {
            return contract_error(
                "work-item completion is missing a required verifier or receipt",
            );
        }
        item.status = WorkItemStatus::Completed;
        item.verifier_refs = verifier_refs;
        item.assigned_agent = None;
        self.recalculate_active_agents();
        self.runtime_revision = self.runtime_revision.saturating_add(1);
        Ok(())
    }

    pub fn reassign_work_item(
        &mut self,
        work_item_id: WorkItemId,
        next_lease: AutonomyLeaseBinding,
        reason: impl Into<String>,
        now: OffsetDateTime,
    ) -> Result<AutonomyRecoveryReceipt, EngineError> {
        if !matches!(
            self.contract.state,
            AutonomyRunState::Running | AutonomyRunState::PausedByOperator
        ) {
            return contract_error("reassignment requires RUNNING or PAUSED_BY_OPERATOR");
        }
        let index = self
            .work_items
            .iter()
            .position(|item| item.work_item_id == work_item_id)
            .ok_or_else(|| EngineError::WriteRejected("unknown work_item_id".to_owned()))?;
        let previous = self.work_items[index].lease.clone().ok_or_else(|| {
            EngineError::WriteRejected("work item has no active lease".to_owned())
        })?;
        if self.work_items[index].status != WorkItemStatus::Active {
            return contract_error("only ACTIVE work items can be reassigned");
        }
        if next_lease.project_id != previous.project_id
            || next_lease.expires_at <= now
            || next_lease.lease_ref.trim().is_empty()
        {
            return contract_error("replacement lease is expired, missing, or project-mismatched");
        }
        AutonomyRunService::validate_lease_scope(
            &self.contract,
            next_lease.project_id,
            &next_lease.scope,
        )?;
        AutonomyRunService::validate_lease_narrowing(&previous.scope, &next_lease.scope)?;

        let next_agent = next_lease.holder;
        self.work_items[index].assigned_agent = Some(next_agent);
        self.work_items[index].lease = Some(next_lease);
        self.runtime_revision = self.runtime_revision.saturating_add(1);
        let receipt = AutonomyRecoveryReceipt {
            recovery_id: format!("autonomy-recovery-{}", WriteId::new_v7()),
            autonomy_run_id: self.contract.autonomy_run_id.clone(),
            work_item_id,
            action: AutonomyRecoveryAction::Reassign,
            tripwire_id: None,
            previous_agent: Some(previous.holder),
            next_agent: Some(next_agent),
            reason: reason.into(),
            runtime_revision: self.runtime_revision,
            recovered_at: now,
        };
        self.recovery_receipts.push(receipt.clone());
        self.recalculate_active_agents();
        Ok(receipt)
    }

    pub fn pause_for_recovery(
        &mut self,
        work_item_id: WorkItemId,
        tripwire_id: String,
        reason: impl Into<String>,
    ) -> Result<(AutonomyRunTransitionReceipt, AutonomyRecoveryReceipt), EngineError> {
        let reason = reason.into();
        let transition = self.transition(&AutonomyTransitionRequest {
            target: AutonomyRunState::PausedByOperator,
            reason: reason.clone(),
            risk_tier: "R1".to_owned(),
            approval: None,
            verifier_refs: Vec::new(),
        })?;
        let recovery = self.record_recovery(
            work_item_id,
            AutonomyRecoveryAction::PauseBranch,
            Some(tripwire_id),
            reason,
        )?;
        Ok((transition, recovery))
    }

    pub fn resume_after_recovery(
        &mut self,
        work_item_id: WorkItemId,
        reason: impl Into<String>,
    ) -> Result<(AutonomyRunTransitionReceipt, AutonomyRecoveryReceipt), EngineError> {
        let reason = reason.into();
        let transition = self.transition(&AutonomyTransitionRequest {
            target: AutonomyRunState::Running,
            reason: reason.clone(),
            risk_tier: "R1".to_owned(),
            approval: None,
            verifier_refs: Vec::new(),
        })?;
        let recovery = self.record_recovery(
            work_item_id,
            AutonomyRecoveryAction::ResumeBranch,
            None,
            reason,
        )?;
        Ok((transition, recovery))
    }

    pub fn record_recovery(
        &mut self,
        work_item_id: WorkItemId,
        action: AutonomyRecoveryAction,
        tripwire_id: Option<String>,
        reason: impl Into<String>,
    ) -> Result<AutonomyRecoveryReceipt, EngineError> {
        let item = self
            .work_items
            .iter()
            .find(|item| item.work_item_id == work_item_id)
            .ok_or_else(|| EngineError::WriteRejected("unknown work_item_id".to_owned()))?;
        self.runtime_revision = self.runtime_revision.saturating_add(1);
        let receipt = AutonomyRecoveryReceipt {
            recovery_id: format!("autonomy-recovery-{}", WriteId::new_v7()),
            autonomy_run_id: self.contract.autonomy_run_id.clone(),
            work_item_id,
            action,
            tripwire_id,
            previous_agent: item.assigned_agent,
            next_agent: item.assigned_agent,
            reason: reason.into(),
            runtime_revision: self.runtime_revision,
            recovered_at: OffsetDateTime::now_utc(),
        };
        self.recovery_receipts.push(receipt.clone());
        Ok(receipt)
    }

    fn validate_restored_state(&self) -> Result<(), EngineError> {
        AutonomyRunService::validate_contract(&self.contract)?;
        self.tripwire_policy.validate()?;
        if self.work_items.len() > self.contract.max_work_items as usize
            || self.ledger.model_invocations > self.contract.max_model_invocations
            || self.ledger.tool_calls > self.contract.max_tool_calls
            || self.ledger.wall_time_seconds > self.contract.max_wall_time_seconds
            || self.ledger.work_items_started > self.contract.max_work_items
            || self.ledger.active_agents > self.contract.max_active_agents
        {
            return contract_error("serialized autonomy state exceeds its frozen contract");
        }
        if let Some(limit) = self
            .contract
            .cost_or_token_budget
            .as_deref()
            .and_then(parse_budget_limit)
            && self.ledger.cost_or_token_units > limit
        {
            return contract_error("serialized autonomy state exceeds cost/token budget");
        }
        let ids = self
            .work_items
            .iter()
            .map(|item| item.work_item_id)
            .collect::<BTreeSet<_>>();
        if ids.len() != self.work_items.len()
            || self
                .work_items
                .iter()
                .flat_map(|item| &item.dependencies)
                .any(|dependency| !ids.contains(dependency))
            || !work_graph_is_acyclic(&self.work_items)
        {
            return contract_error("serialized work graph has duplicate or missing nodes");
        }
        for item in &self.work_items {
            let active_binding_valid = item.status != WorkItemStatus::Active
                || item.lease.as_ref().is_some_and(|lease| {
                    item.assigned_agent == Some(lease.holder) && lease.project_id == item.project_id
                });
            let completed_evidence_valid = item.status != WorkItemStatus::Completed
                || (!item.required || !item.verifier_refs.is_empty());
            if !active_binding_valid || !completed_evidence_valid {
                return contract_error("serialized work item has invalid lease or verifier state");
            }
            if let Some(lease) = item.lease.as_ref() {
                AutonomyRunService::validate_lease_scope(
                    &self.contract,
                    lease.project_id,
                    &lease.scope,
                )?;
            }
        }
        Ok(())
    }

    fn push_tripwire(
        &mut self,
        kind: AutonomyTripwireKind,
        signature: Option<String>,
        reason: String,
    ) -> AutonomyTripwireRecord {
        let record = AutonomyTripwireRecord {
            tripwire_id: format!("autonomy-tripwire-{}", WriteId::new_v7()),
            kind,
            signature,
            reason,
            ledger_revision: self.ledger.revision,
            observed_at: OffsetDateTime::now_utc(),
        };
        self.ledger.tripwires.push(record.clone());
        record
    }

    fn recalculate_active_agents(&mut self) {
        let mut agents = Vec::new();
        for agent in self
            .work_items
            .iter()
            .filter(|item| item.status == WorkItemStatus::Active)
            .filter_map(|item| item.assigned_agent)
        {
            if !agents.contains(&agent) {
                agents.push(agent);
            }
        }
        self.ledger.active_agents = u32::try_from(agents.len()).unwrap_or(u32::MAX);
    }
}

fn transition_allowed(from: AutonomyRunState, to: AutonomyRunState) -> bool {
    use AutonomyRunState::{
        BlockedByApproval, BlockedByUnknown, Cancelled, Degraded, DoneVerified, Draft, Failed,
        PartialProgress, PausedByOperator, Ready, Running, Verifying,
    };
    matches!(
        (from, to),
        (Draft, Ready)
            | (Ready, Running | Cancelled)
            | (
                Running,
                Verifying
                    | PausedByOperator
                    | BlockedByUnknown
                    | BlockedByApproval
                    | Degraded
                    | PartialProgress
                    | Cancelled
                    | Failed
            )
            | (
                Verifying,
                DoneVerified | Running | PausedByOperator | PartialProgress | Failed
            )
            | (
                PausedByOperator
                    | BlockedByUnknown
                    | BlockedByApproval
                    | Degraded
                    | PartialProgress,
                Running | Cancelled | Failed
            )
    )
}

fn project_allowed(contract: &AutonomyRunContract, project_id: ProjectId) -> bool {
    if contract.allowed_projects.is_empty() {
        project_id == contract.project_id
    } else {
        contract.allowed_projects.contains(&project_id)
    }
}

fn work_graph_is_acyclic(items: &[AutonomyWorkItem]) -> bool {
    let mut resolved = BTreeSet::new();
    loop {
        let before = resolved.len();
        for item in items {
            if !resolved.contains(&item.work_item_id)
                && item
                    .dependencies
                    .iter()
                    .all(|dependency| resolved.contains(dependency))
            {
                resolved.insert(item.work_item_id);
            }
        }
        if resolved.len() == items.len() {
            return true;
        }
        if resolved.len() == before {
            return false;
        }
    }
}

fn path_policy_reasons(contract: &AutonomyRunContract, paths: &[String]) -> Vec<String> {
    let mut reasons = Vec::new();
    for path in paths {
        if path.trim().is_empty() || has_parent_traversal(path) {
            reasons.push(format!("invalid_path:{path}"));
            continue;
        }
        if !contract
            .allowed_paths
            .iter()
            .any(|allowed| path_within(path, allowed))
        {
            reasons.push(format!("path_outside_allowed_scope:{path}"));
        }
        if contract
            .forbidden_paths
            .iter()
            .any(|forbidden| path_within(path, forbidden))
        {
            reasons.push(format!("forbidden_path:{path}"));
        }
    }
    reasons
}

fn budget_reasons(
    contract: &AutonomyRunContract,
    ledger: &AutonomyBudgetLedger,
    intent: &AutonomyStepIntent,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if ledger
        .model_invocations
        .saturating_add(intent.model_invocations)
        > contract.max_model_invocations
    {
        reasons.push("model_invocation_budget".to_owned());
    }
    if ledger.tool_calls.saturating_add(intent.tool_calls) > contract.max_tool_calls {
        reasons.push("tool_call_budget".to_owned());
    }
    if ledger
        .wall_time_seconds
        .saturating_add(intent.wall_time_seconds)
        > contract.max_wall_time_seconds
    {
        reasons.push("wall_time_budget".to_owned());
    }
    if ledger
        .work_items_started
        .saturating_add(intent.work_items_started)
        > contract.max_work_items
    {
        reasons.push("work_item_budget".to_owned());
    }
    if intent.active_agents > contract.max_active_agents {
        reasons.push("active_agent_budget".to_owned());
    }
    if let Some(limit) = contract
        .cost_or_token_budget
        .as_deref()
        .and_then(parse_budget_limit)
        && ledger
            .cost_or_token_units
            .saturating_add(intent.cost_or_token_units)
            > limit
    {
        reasons.push("cost_or_token_budget".to_owned());
    }
    reasons
}

fn parse_budget_limit(value: &str) -> Option<u64> {
    let compact = value.replace([',', '_'], "");
    let digits = compact
        .chars()
        .skip_while(|character| !character.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits.parse::<u64>().ok().filter(|limit| *limit > 0)
}

fn has_parent_traversal(path: &str) -> bool {
    path.replace('\\', "/").split('/').any(|part| part == "..")
}

fn path_within(path: &str, root: &str) -> bool {
    let path = normalize_path(path);
    let root = normalize_path(root);
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

const fn risk_rank(risk: RiskTier) -> u8 {
    match risk {
        RiskTier::Low => 0,
        RiskTier::Medium => 1,
        RiskTier::High => 2,
    }
}

fn contract_error<T>(reason: &str) -> Result<T, EngineError> {
    Err(EngineError::WriteRejected(reason.to_owned()))
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim()
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ControlPlaneMemoryWriter;

impl ControlPlaneMemoryWriter {
    pub async fn write_operator_command(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        session_id: SessionId,
        project_id: ProjectId,
        task_id: TaskId,
        command: &OperatorCommand,
    ) -> Result<WriteReceiptRef, EngineError> {
        write_control_observation(
            handle,
            admission,
            session_id,
            project_id,
            task_id,
            "operator_command",
            command,
        )
        .await
    }

    pub async fn write_contract(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        session_id: SessionId,
        contract: &AutonomyRunContract,
    ) -> Result<WriteReceiptRef, EngineError> {
        AutonomyRunService::validate_contract(contract)?;
        write_control_observation(
            handle,
            admission,
            session_id,
            contract.project_id,
            contract.root_task_id,
            "autonomy_run_contract",
            contract,
        )
        .await
    }

    pub async fn write_transition(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        session_id: SessionId,
        project_id: ProjectId,
        task_id: TaskId,
        transition: &mut AutonomyRunTransitionReceipt,
    ) -> Result<WriteReceiptRef, EngineError> {
        let receipt = write_control_observation(
            handle,
            admission,
            session_id,
            project_id,
            task_id,
            "autonomy_run_transition",
            transition,
        )
        .await?;
        transition.canonical_receipt = Some(receipt.clone());
        Ok(receipt)
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_control_observation<T>(
    handle: &WriterHandle,
    admission: &WriteAdmissionService,
    session_id: SessionId,
    project_id: ProjectId,
    task_id: TaskId,
    kind: &str,
    body: &T,
) -> Result<WriteReceiptRef, EngineError>
where
    T: Serialize,
{
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id: Some(session_id),
            project_id,
            task_id: Some(task_id),
            scope: "cognitive-control-plane-l8".to_owned(),
            authority: "governor-control-plane".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: "eliot_control_plane".to_owned(),
        observation: format!("Control-plane {kind} written through WriterActor"),
        payload: json!({
            "receipt_kind": kind,
            "receipt_body": serde_json::to_value(body)?,
            "writer_path": "semantic_command_writer_actor"
        }),
    });
    let envelope = admission.admit(&command)?;
    let receipt = handle.submit(envelope).await?;
    Ok(WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(host: &str) -> ContourPreferredRoute {
        ContourPreferredRoute {
            host_id: host.to_owned(),
            model_route_optional: None,
            requested_role: "worker".to_owned(),
            capability_requirements: vec!["rust".to_owned()],
        }
    }

    fn policy(
        scope: ContourPolicyScope,
        project_id: ProjectId,
        task_id: TaskId,
        hosts: &[&str],
    ) -> ContourRoutePolicy {
        ContourRoutePolicy {
            policy_id: format!("policy-{scope:?}"),
            scope,
            project_id: (scope != ContourPolicyScope::System).then_some(project_id),
            task_id: (scope == ContourPolicyScope::Task).then_some(task_id),
            contour: ResponsibilityContour::Implementation,
            preferred_routes: hosts.iter().map(|host| route(host)).collect(),
            allowed_fallbacks: Vec::new(),
            deterministic_adapter_preference: true,
            max_parallelism: 1,
            cost_or_token_budget: None,
            wall_time_budget_seconds: 600,
            required_evidence: vec!["diff".to_owned()],
            required_verifier: vec!["cargo test".to_owned()],
            escalation_route: None,
            effective_from: OffsetDateTime::UNIX_EPOCH,
            expires_at: None,
            policy_snapshot_id: "snapshot-1".to_owned(),
            owner: "test".to_owned(),
        }
    }

    fn live(host: &str, available: bool) -> LiveContourRoute {
        LiveContourRoute {
            route: route(host),
            available,
            retention_allowed: true,
            capability_evidence: vec!["rust".to_owned()],
            availability_evidence: vec![format!("session:{host}")],
            cost_latency_estimate: "local".to_owned(),
        }
    }

    #[test]
    fn task_override_cannot_widen_system_policy() {
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let policies = vec![
            policy(ContourPolicyScope::System, project_id, task_id, &["codex"]),
            policy(ContourPolicyScope::Task, project_id, task_id, &["claude"]),
        ];
        let result = ContourRoutingService::resolve(&ContourRouteRequest {
            project_id,
            task_id,
            work_item_id: WorkItemId::new_v7(),
            contour: ResponsibilityContour::Implementation,
            policies: &policies,
            live_routes: &[live("codex", true), live("claude", true)],
            now: OffsetDateTime::now_utc(),
        });
        let Err(error) = result else {
            panic!("widening must fail");
        };
        assert!(error.to_string().contains("widen"));
    }

    #[test]
    fn unavailable_preferred_route_uses_permitted_fallback() -> Result<(), EngineError> {
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let policies = vec![policy(
            ContourPolicyScope::System,
            project_id,
            task_id,
            &["claude", "codex"],
        )];
        let live_routes = vec![live("claude", false), live("codex", true)];
        let decision = ContourRoutingService::resolve(&ContourRouteRequest {
            project_id,
            task_id,
            work_item_id: WorkItemId::new_v7(),
            contour: ResponsibilityContour::Implementation,
            policies: &policies,
            live_routes: &live_routes,
            now: OffsetDateTime::now_utc(),
        })?;
        assert_eq!(decision.selected_route.host_id, "codex");
        Ok(())
    }

    fn contract() -> AutonomyRunContract {
        AutonomyRunContract {
            autonomy_run_id: "run-test".to_owned(),
            project_id: ProjectId::new_v7(),
            root_task_id: TaskId::new_v7(),
            user_goal: "bounded task".to_owned(),
            acceptance_items: vec!["tests pass".to_owned()],
            contour_route_policy_ref: "policy-1".to_owned(),
            allowed_projects: Vec::new(),
            max_work_items: 2,
            max_active_agents: 2,
            max_model_invocations: 6,
            max_tool_calls: 30,
            max_wall_time_seconds: 900,
            cost_or_token_budget: None,
            allowed_paths: vec!["crates/eliot-engine".to_owned()],
            forbidden_paths: vec![".git".to_owned()],
            forbidden_effects: vec!["unapproved_r3".to_owned()],
            allowed_risk_tiers: vec!["R0".to_owned(), "R1".to_owned(), "R2".to_owned()],
            required_verifiers: vec!["cargo test".to_owned()],
            approval_boundaries: vec!["R3".to_owned()],
            pause_conditions: vec!["material unknown".to_owned()],
            stop_conditions: vec!["acceptance verified".to_owned()],
            fallback_routes: vec![route("codex")],
            recovery_policy_ref: "recovery-policy-1".to_owned(),
            policy_snapshot_id: "snapshot-1".to_owned(),
            created_by: "operator".to_owned(),
            state: AutonomyRunState::Draft,
            state_revision: 0,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn bounded_run_requires_verifier_before_done() -> Result<(), EngineError> {
        let mut run = contract();
        for target in [
            AutonomyRunState::Ready,
            AutonomyRunState::Running,
            AutonomyRunState::Verifying,
        ] {
            AutonomyRunService::transition(
                &mut run,
                &AutonomyTransitionRequest {
                    target,
                    reason: "test".to_owned(),
                    risk_tier: "R1".to_owned(),
                    approval: None,
                    verifier_refs: Vec::new(),
                },
            )?;
        }
        let denied = AutonomyRunService::transition(
            &mut run,
            &AutonomyTransitionRequest {
                target: AutonomyRunState::DoneVerified,
                reason: "premature".to_owned(),
                risk_tier: "R1".to_owned(),
                approval: None,
                verifier_refs: Vec::new(),
            },
        );
        assert!(denied.is_err());
        Ok(())
    }

    #[test]
    fn r3_requires_canonical_approval_authorization() -> Result<(), EngineError> {
        let mut run = contract();
        AutonomyRunService::transition(
            &mut run,
            &AutonomyTransitionRequest {
                target: AutonomyRunState::Ready,
                reason: "validated".to_owned(),
                risk_tier: "R1".to_owned(),
                approval: None,
                verifier_refs: Vec::new(),
            },
        )?;
        let denied = AutonomyRunService::transition(
            &mut run,
            &AutonomyTransitionRequest {
                target: AutonomyRunState::Running,
                reason: "risk boundary".to_owned(),
                risk_tier: "R3".to_owned(),
                approval: None,
                verifier_refs: Vec::new(),
            },
        );
        assert!(denied.is_err());
        Ok(())
    }
}
