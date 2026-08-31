use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::{
    AttemptId, ContractError, EffectCeiling, EffectKind, ResultDisposition, WorkLeaseId,
};
use eliot_agent_contracts::{
    AgentAttemptId, CoordinationEntry, CoordinationMapView, DescendantTerminalState,
    LivePeerMessage, LivePeerMessageState, MessageId, ParentFinishCeiling, RevisionId, WorkItemId,
    contract_shape_digest,
};
use eliot_receipts::ProofCeiling;
use serde::Serialize;

use crate::SNAPSHOT_SCHEMA_VERSION;
use crate::model::{
    AdmissionId, AttemptRecord, CancelCommand, CancellationFinalReceipt, CancellationReceipt,
    CancellationReconciliationId, CandidateId, CandidateResultReceipt, CoordinatedAttemptState,
    CoordinatorConfig, CoordinatorError, CoordinatorEvent, CoordinatorSnapshot,
    DeliveryBoundaryReceipt, DescendantClosureCandidateReceipt, DescendantClosureSubmission,
    ExecutionContext, LostWorkerReceipt, OperationId, OutcomeReconciliationId, PeerMessageReceipt,
    PlanGap, ProviderAdmissionReceipt, ProviderBindingSnapshot, ProviderCancellationReconciliation,
    ProviderIdentity, ProviderReassignmentReceipt, ProviderUnknownOutcomeReconciliation,
    ProviderWorkerFenceReceipt, ReassignmentId, ReassignmentReceipt, RejectedRoute,
    ResultSubmission, RoleProfileManifest, RouteCandidateEvidence, RouteRejectionReason,
    RoutingReceipt, StaffingLaneCandidate, StaffingPlanCandidate, StaffingPlanRequest,
    SubmissionId, UnknownOutcomeFinalReceipt, WorkerId, validate_text,
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum ProviderProofKind {
    Admission,
    Cancellation,
    WorkerFence,
    Reassignment,
    Result,
    UnknownOutcome,
}

/// Sealed inside this crate so callers cannot implement an "always verified"
/// provider. A future accepted A-01/G-11 adapter must be added here and bind
/// its own authenticated receipts. Until then the public constructor installs
/// only a typed `PLAN_GAP` verifier.
pub(crate) trait ProviderVerifier: Send + Sync {
    fn binding(&self) -> ProviderBindingSnapshot;
    fn minimum_event_sequence(&self) -> u64;
    fn verify(
        &self,
        kind: ProviderProofKind,
        identity: &ProviderIdentity,
        proof_ref: &str,
        canonical_payload: &str,
    ) -> Result<(), CoordinatorError>;
}

struct GapProvider {
    gap: PlanGap,
}

impl ProviderVerifier for GapProvider {
    fn binding(&self) -> ProviderBindingSnapshot {
        ProviderBindingSnapshot::Gap {
            gap: self.gap.clone(),
        }
    }

    fn minimum_event_sequence(&self) -> u64 {
        0
    }

    fn verify(
        &self,
        _kind: ProviderProofKind,
        _identity: &ProviderIdentity,
        _proof_ref: &str,
        _canonical_payload: &str,
    ) -> Result<(), CoordinatorError> {
        Err(self.gap.clone().into())
    }
}

#[derive(Clone, Debug)]
struct AdmissionRecord {
    receipt: ProviderAdmissionReceipt,
}

#[derive(Clone, Debug)]
struct IdempotentRecord<T> {
    canonical_input: String,
    receipt: T,
}

#[derive(Clone, Debug)]
struct RouteCapacityRequest {
    requested: usize,
    capacity_identity: String,
    capacity_revision: RevisionId,
    capacity_limit: usize,
}

/// Deterministic A-02 execution projection. It owns no provider admission,
/// lease minting, process launch, task truth, canonical writer, or task graph.
pub struct AgentCoordinator {
    config: CoordinatorConfig,
    provider: Box<dyn ProviderVerifier>,
    plans: BTreeMap<CandidateId, StaffingPlanCandidate>,
    admissions: BTreeMap<AdmissionId, AdmissionRecord>,
    attempts: BTreeMap<AttemptId, AttemptRecord>,
    writer_holders: BTreeMap<String, AttemptId>,
    cancellation_ops: BTreeMap<OperationId, IdempotentRecord<CancellationReceipt>>,
    cancellation_reconciliations:
        BTreeMap<CancellationReconciliationId, IdempotentRecord<CancellationFinalReceipt>>,
    lost_observations: BTreeMap<crate::ObservationId, IdempotentRecord<LostWorkerReceipt>>,
    reassignments: BTreeMap<ReassignmentId, IdempotentRecord<ReassignmentReceipt>>,
    submissions: BTreeMap<SubmissionId, IdempotentRecord<CandidateResultReceipt>>,
    result_by_attempt: BTreeMap<AttemptId, SubmissionId>,
    outcome_reconciliations:
        BTreeMap<OutcomeReconciliationId, IdempotentRecord<UnknownOutcomeFinalReceipt>>,
    descendant_closures: BTreeMap<AttemptId, IdempotentRecord<DescendantClosureCandidateReceipt>>,
    peer_messages: BTreeMap<MessageId, IdempotentRecord<PeerMessageReceipt>>,
    peer_message_payloads: BTreeMap<MessageId, LivePeerMessage>,
    events: Vec<CoordinatorEvent>,
}

impl AgentCoordinator {
    /// Creates a plan-only coordinator. No accepted/live boolean or receipt can
    /// be supplied by the caller; all effecting operations return this gap.
    pub fn new(config: CoordinatorConfig, gap: PlanGap) -> Result<Self, CoordinatorError> {
        gap.validate()?;
        Self::with_provider(config, Box::new(GapProvider { gap }))
    }

    pub(crate) fn with_provider(
        config: CoordinatorConfig,
        provider: Box<dyn ProviderVerifier>,
    ) -> Result<Self, CoordinatorError> {
        config.validate()?;
        if let ProviderBindingSnapshot::Verified { identity } = provider.binding() {
            identity.validate()?;
            if identity.capacity_identity != config.capacity_identity
                || identity.capacity_revision != config.capacity_revision
            {
                return Err(CoordinatorError::StaleCapacity);
            }
        }
        Ok(Self {
            config,
            provider,
            plans: BTreeMap::new(),
            admissions: BTreeMap::new(),
            attempts: BTreeMap::new(),
            writer_holders: BTreeMap::new(),
            cancellation_ops: BTreeMap::new(),
            cancellation_reconciliations: BTreeMap::new(),
            lost_observations: BTreeMap::new(),
            reassignments: BTreeMap::new(),
            submissions: BTreeMap::new(),
            result_by_attempt: BTreeMap::new(),
            outcome_reconciliations: BTreeMap::new(),
            descendant_closures: BTreeMap::new(),
            peer_messages: BTreeMap::new(),
            peer_message_payloads: BTreeMap::new(),
            events: Vec::new(),
        })
    }

    /// Compiles deterministic candidate staffing. It never admits or starts an
    /// attempt and remains available while providers are a `PLAN_GAP`.
    #[allow(clippy::too_many_lines)]
    pub fn plan(
        &mut self,
        request: StaffingPlanRequest,
    ) -> Result<StaffingPlanCandidate, CoordinatorError> {
        request.launch.validate().map_err(provider_contract)?;
        validate_text(request.launch.id.as_str(), "launch_request_id")?;
        validate_text(request.launch.task_id.as_str(), "task_id")?;
        validate_text(&request.task_revision, "task_revision")?;
        validate_text(request.plan_revision.as_str(), "plan_revision")?;
        validate_state_fence(&request.state_fence)?;
        validate_recipe(&request)?;
        self.validate_launch_effect_ceiling(&request.launch)?;

        if request.lanes.is_empty() {
            return Err(CoordinatorError::InvalidField("lanes"));
        }
        let fanout = usize::try_from(request.launch.max_fanout).unwrap_or(usize::MAX);
        let recipe_limit = request.recipe.max_lanes.min(fanout);
        if request.lanes.len() > recipe_limit {
            return Err(CoordinatorError::Backpressure {
                active: 0,
                requested: request.lanes.len(),
                limit: recipe_limit,
            });
        }

        let ready = self
            .plans
            .iter()
            .filter(|(candidate_id, _)| {
                !self
                    .admissions
                    .values()
                    .any(|record| &record.receipt.candidate_id == *candidate_id)
            })
            .map(|(_, candidate)| candidate.lanes.len())
            .sum::<usize>();
        if ready.saturating_add(request.lanes.len()) > self.config.max_ready_items {
            return Err(CoordinatorError::Backpressure {
                active: ready,
                requested: request.lanes.len(),
                limit: self.config.max_ready_items,
            });
        }

        let work_units = request
            .launch
            .work_units
            .iter()
            .map(|work| (work.id.clone(), work))
            .collect::<BTreeMap<_, _>>();
        if work_units.len() != request.launch.work_units.len() {
            return Err(CoordinatorError::DuplicateIdentity("work_unit_id"));
        }
        let roles = request
            .recipe
            .role_profiles
            .iter()
            .map(|role| (role.role_id.clone(), role))
            .collect::<BTreeMap<_, _>>();

        let mut lane_keys = BTreeSet::new();
        let mut lanes = Vec::with_capacity(request.lanes.len());
        for lane in &request.lanes {
            let work = work_units
                .get(&lane.work_unit_id)
                .ok_or(CoordinatorError::IdentityConflict("work_unit_id"))?;
            let role = roles
                .get(&lane.role_id)
                .ok_or(CoordinatorError::IdentityConflict("role_id"))?;
            lane.budget.validate().map_err(provider_contract)?;
            lane.budget
                .is_within(&work.budget)
                .map_err(|_| CoordinatorError::BudgetExceeded)?;
            if !role
                .required_competence
                .iter()
                .all(|item| request.launch.required_competence.contains(item))
            {
                return Err(CoordinatorError::IdentityConflict("role_competence"));
            }
            let mutating = work
                .effect_ceiling
                .allowed
                .contains(&EffectKind::WriteCandidate);
            if mutating && lane.mutation_scope.is_none() {
                return Err(CoordinatorError::InvalidField("mutation_scope"));
            }
            if lane.mutation_scope.is_some() && !role.mutation_capable {
                return Err(CoordinatorError::IdentityConflict(
                    "role_mutation_capability",
                ));
            }
            if let Some(scope) = &lane.mutation_scope {
                validate_text(scope, "mutation_scope")?;
            }
            if !lane_keys.insert((lane.work_unit_id.clone(), lane.role_id.clone())) {
                return Err(CoordinatorError::DuplicateIdentity("work_unit_role"));
            }
            let routing =
                select_route(&self.config, &request, role, lane.route_candidates.clone())?;
            lanes.push(StaffingLaneCandidate {
                work_unit_id: lane.work_unit_id.clone(),
                role_id: lane.role_id.clone(),
                role_revision: role.manifest_revision.clone(),
                routing,
                budget: lane.budget.clone(),
                priority: lane.priority,
                mutation_scope: lane.mutation_scope.clone(),
            });
        }

        lanes.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.work_unit_id.cmp(&right.work_unit_id))
                .then_with(|| left.role_id.cmp(&right.role_id))
                .then_with(|| {
                    route_key(&left.routing.selected_route)
                        .cmp(&route_key(&right.routing.selected_route))
                })
        });

        let candidate = StaffingPlanCandidate {
            candidate_id: request.candidate_id.clone(),
            task_id: request.launch.task_id.clone(),
            launch_request_id: request.launch.id.clone(),
            recipe_id: request.recipe.recipe_id.clone(),
            recipe_revision: request.recipe.manifest_revision.clone(),
            task_revision: request.task_revision.clone(),
            plan_revision: request.plan_revision.clone(),
            state_fence: request.state_fence.clone(),
            privacy_class: request.privacy_class,
            lanes,
        };
        if let Some(existing) = self.plans.get(&candidate.candidate_id) {
            if existing == &candidate {
                return Ok(existing.clone());
            }
            return Err(CoordinatorError::IdentityConflict("candidate_id"));
        }
        self.plans
            .insert(candidate.candidate_id.clone(), candidate.clone());
        self.events.push(CoordinatorEvent::PlanCreated {
            request: Box::new(request),
        });
        Ok(candidate)
    }

    /// Reconciles only an admission accepted by the sealed verifier.
    #[allow(clippy::too_many_lines)]
    pub fn admit(
        &mut self,
        mut receipt: ProviderAdmissionReceipt,
    ) -> Result<ProviderAdmissionReceipt, CoordinatorError> {
        validate_admission_text(&receipt)?;
        receipt.admitted_lanes.sort_by(|left, right| {
            left.work_unit_id
                .cmp(&right.work_unit_id)
                .then_with(|| left.role_id.cmp(&right.role_id))
                .then_with(|| left.attempt_id.cmp(&right.attempt_id))
        });
        let canonical_receipt = canonical(&receipt)?;
        self.provider.verify(
            ProviderProofKind::Admission,
            &receipt.provider_identity,
            &receipt.g11_admission_receipt_ref,
            &canonical_receipt,
        )?;
        self.validate_provider_identity(&receipt.provider_identity)?;
        if let Some(existing) = self.admissions.get(&receipt.admission_id) {
            if existing.receipt == receipt {
                return Ok(existing.receipt.clone());
            }
            return Err(CoordinatorError::IdentityConflict("admission_id"));
        }
        if self
            .admissions
            .values()
            .any(|record| record.receipt.candidate_id == receipt.candidate_id)
        {
            return Err(CoordinatorError::IdentityConflict("candidate_admission"));
        }

        let candidate = self
            .plans
            .get(&receipt.candidate_id)
            .cloned()
            .ok_or(CoordinatorError::UnknownCandidate)?;
        validate_candidate_binding(&candidate, &receipt)?;
        let launch = self.launch_for_candidate(&candidate.candidate_id)?.clone();
        self.validate_launch_effect_ceiling(&launch)?;

        let active = self.active_attempt_count();
        if active.saturating_add(receipt.admitted_lanes.len()) > self.config.max_admitted_attempts {
            return Err(CoordinatorError::Backpressure {
                active,
                requested: receipt.admitted_lanes.len(),
                limit: self.config.max_admitted_attempts,
            });
        }

        let candidate_lanes = candidate
            .lanes
            .iter()
            .map(|lane| ((lane.work_unit_id.clone(), lane.role_id.clone()), lane))
            .collect::<BTreeMap<_, _>>();
        if receipt.admitted_lanes.len() != candidate_lanes.len() {
            return Err(CoordinatorError::IdentityConflict("admitted_lanes"));
        }
        let mut lane_keys = BTreeSet::new();
        let mut attempts = BTreeSet::new();
        let mut leases = BTreeSet::new();
        let mut workers = BTreeSet::new();
        let mut scopes = BTreeSet::new();
        let mut route_additions = BTreeMap::<String, RouteCapacityRequest>::new();
        for lane in &receipt.admitted_lanes {
            validate_admitted_lane(lane)?;
            let lane_key = (lane.work_unit_id.clone(), lane.role_id.clone());
            if !lane_keys.insert(lane_key.clone()) {
                return Err(CoordinatorError::DuplicateIdentity(
                    "admitted_work_unit_role",
                ));
            }
            let candidate_lane = candidate_lanes
                .get(&lane_key)
                .ok_or(CoordinatorError::IdentityConflict("admitted_lane"))?;
            let routing_digest = contract_shape_digest(&candidate_lane.routing)
                .map_err(|error| CoordinatorError::Serialization(error.to_string()))?;
            if lane.route != candidate_lane.routing.selected_route
                || lane.routing_receipt_digest != routing_digest
                || lane.role_revision != candidate_lane.role_revision
                || lane.budget != candidate_lane.budget
                || lane.priority != candidate_lane.priority
                || lane.mutation_scope != candidate_lane.mutation_scope
            {
                return Err(CoordinatorError::IdentityConflict("admitted_lane"));
            }
            if !attempts.insert(lane.attempt_id.clone())
                || self.attempts.contains_key(&lane.attempt_id)
            {
                return Err(CoordinatorError::DuplicateIdentity("attempt_id"));
            }
            if !leases.insert(lane.lease_id.clone()) || self.lease_exists(&lane.lease_id) {
                return Err(CoordinatorError::DuplicateIdentity("lease_id"));
            }
            if !workers.insert(lane.worker_id.clone()) || self.worker_exists(&lane.worker_id) {
                return Err(CoordinatorError::DuplicateIdentity("worker_id"));
            }
            if let Some(scope) = &lane.mutation_scope
                && (!scopes.insert(scope.clone()) || self.writer_holders.contains_key(scope))
            {
                return Err(CoordinatorError::MutatingWriterConflict(scope.clone()));
            }
            let capacity = RouteCapacityRequest {
                requested: 1,
                capacity_identity: candidate_lane.routing.capacity_identity.clone(),
                capacity_revision: candidate_lane.routing.capacity_revision.clone(),
                capacity_limit: candidate_lane.routing.capacity_limit,
            };
            match route_additions.entry(route_key(&lane.route)) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(capacity);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let current = entry.get_mut();
                    if current.capacity_identity != capacity.capacity_identity
                        || current.capacity_revision != capacity.capacity_revision
                        || current.capacity_limit != capacity.capacity_limit
                    {
                        return Err(CoordinatorError::RouteEvidence);
                    }
                    current.requested = current.requested.saturating_add(1);
                }
            }
        }
        self.validate_route_capacity(route_additions)?;

        for lane in &receipt.admitted_lanes {
            let candidate_lane = candidate_lanes
                .get(&(lane.work_unit_id.clone(), lane.role_id.clone()))
                .ok_or(CoordinatorError::IdentityConflict("admitted_lane"))?;
            let record = AttemptRecord {
                admission_id: receipt.admission_id.clone(),
                launch_request_id: receipt.launch_request_id.clone(),
                parent_attempt_id: launch.parent_attempt.clone(),
                recipe_id: receipt.recipe_id.clone(),
                recipe_revision: receipt.recipe_revision.clone(),
                task_id: receipt.task_id.clone(),
                task_revision: receipt.task_revision.clone(),
                plan_revision: receipt.plan_revision.clone(),
                state_fence: receipt.state_fence.clone(),
                work_unit_id: lane.work_unit_id.clone(),
                role_id: lane.role_id.clone(),
                role_revision: lane.role_revision.clone(),
                attempt_id: lane.attempt_id.clone(),
                lease_id: lane.lease_id.clone(),
                worker_id: lane.worker_id.clone(),
                route: lane.route.clone(),
                capacity_identity: candidate_lane.routing.capacity_identity.clone(),
                capacity_revision: candidate_lane.routing.capacity_revision.clone(),
                capacity_limit: candidate_lane.routing.capacity_limit,
                budget: lane.budget.clone(),
                priority: lane.priority,
                mutation_scope: lane.mutation_scope.clone(),
                state: CoordinatedAttemptState::Admitted,
                superseded_by: None,
            };
            if let Some(scope) = &record.mutation_scope {
                self.writer_holders
                    .insert(scope.clone(), record.attempt_id.clone());
            }
            self.attempts.insert(record.attempt_id.clone(), record);
        }
        self.admissions.insert(
            receipt.admission_id.clone(),
            AdmissionRecord {
                receipt: receipt.clone(),
            },
        );
        self.events.push(CoordinatorEvent::PlanAdmitted {
            receipt: Box::new(receipt.clone()),
        });
        Ok(receipt)
    }

    pub fn next_ready(&self) -> Option<AttemptRecord> {
        let mut ready = self
            .attempts
            .values()
            .filter(|attempt| attempt.state == CoordinatedAttemptState::Admitted)
            .cloned()
            .collect::<Vec<_>>();
        ready.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.work_unit_id.cmp(&right.work_unit_id))
                .then_with(|| left.role_id.cmp(&right.role_id))
                .then_with(|| left.attempt_id.cmp(&right.attempt_id))
        });
        ready.into_iter().next()
    }

    pub fn attempt(&self, attempt_id: &AttemptId) -> Option<&AttemptRecord> {
        self.attempts.get(attempt_id)
    }

    pub fn events(&self) -> &[CoordinatorEvent] {
        &self.events
    }

    pub fn start_attempt(
        &mut self,
        context: ExecutionContext,
        attempt_id: AttemptId,
    ) -> Result<AttemptRecord, CoordinatorError> {
        self.validate_context(&context)?;
        let current = self
            .attempts
            .get(&attempt_id)
            .cloned()
            .ok_or(CoordinatorError::UnknownAttempt)?;
        if current.admission_id != context.admission_id {
            return Err(CoordinatorError::StaleController);
        }
        if current.state != CoordinatedAttemptState::Admitted {
            return Err(CoordinatorError::InvalidAttemptState(current.state));
        }
        let record = self
            .attempts
            .get_mut(&attempt_id)
            .ok_or(CoordinatorError::UnknownAttempt)?;
        record.state = CoordinatedAttemptState::Running;
        let record = record.clone();
        self.events.push(CoordinatorEvent::AttemptStarted {
            context,
            attempt_id,
        });
        Ok(record)
    }

    pub fn request_cancellation(
        &mut self,
        context: ExecutionContext,
        command: CancelCommand,
    ) -> Result<CancellationReceipt, CoordinatorError> {
        self.validate_context(&context)?;
        let canonical_input = canonical(&command)?;
        if let Some(existing) = self.cancellation_ops.get(&command.operation_id) {
            return idempotent(existing, &canonical_input);
        }
        let current = self
            .attempts
            .get(&command.attempt_id)
            .cloned()
            .ok_or(CoordinatorError::UnknownAttempt)?;
        validate_attempt_binding(&current, &context, &command.lease_id, &command.worker_id)?;
        if !matches!(
            current.state,
            CoordinatedAttemptState::Admitted | CoordinatedAttemptState::Running
        ) {
            return Err(CoordinatorError::InvalidAttemptState(current.state));
        }
        self.attempts
            .get_mut(&command.attempt_id)
            .ok_or(CoordinatorError::UnknownAttempt)?
            .state = CoordinatedAttemptState::CancellationRequested;
        let receipt = CancellationReceipt {
            operation_id: command.operation_id.clone(),
            attempt_id: command.attempt_id.clone(),
            state: CoordinatedAttemptState::CancellationRequested,
        };
        self.cancellation_ops.insert(
            command.operation_id.clone(),
            IdempotentRecord {
                canonical_input,
                receipt: receipt.clone(),
            },
        );
        self.events.push(CoordinatorEvent::CancellationRequested {
            context,
            command: Box::new(command),
        });
        Ok(receipt)
    }

    pub fn reconcile_cancellation(
        &mut self,
        context: ExecutionContext,
        receipt: ProviderCancellationReconciliation,
    ) -> Result<CancellationFinalReceipt, CoordinatorError> {
        self.validate_context(&context)?;
        validate_text(
            &receipt.no_effect_or_cleanup_receipt_ref,
            "no_effect_or_cleanup_receipt_ref",
        )?;
        let canonical_input = canonical(&receipt)?;
        self.provider.verify(
            ProviderProofKind::Cancellation,
            &receipt.provider_identity,
            &receipt.no_effect_or_cleanup_receipt_ref,
            &canonical_input,
        )?;
        self.validate_provider_identity(&receipt.provider_identity)?;
        if let Some(existing) = self
            .cancellation_reconciliations
            .get(&receipt.reconciliation_id)
        {
            return idempotent(existing, &canonical_input);
        }
        let request = self
            .cancellation_ops
            .get(&receipt.request_operation_id)
            .ok_or(CoordinatorError::IdentityConflict(
                "cancellation_operation_id",
            ))?;
        if request.receipt.attempt_id != receipt.attempt_id {
            return Err(CoordinatorError::IdentityConflict("attempt_id"));
        }
        let current = self
            .attempts
            .get(&receipt.attempt_id)
            .cloned()
            .ok_or(CoordinatorError::UnknownAttempt)?;
        validate_attempt_binding(&current, &context, &receipt.lease_id, &receipt.worker_id)?;
        if current.state != CoordinatedAttemptState::CancellationRequested {
            return Err(CoordinatorError::InvalidAttemptState(current.state));
        }
        self.release_writer(&current);
        self.attempts
            .get_mut(&receipt.attempt_id)
            .ok_or(CoordinatorError::UnknownAttempt)?
            .state = CoordinatedAttemptState::Cancelled;
        let final_receipt = CancellationFinalReceipt {
            reconciliation_id: receipt.reconciliation_id.clone(),
            attempt_id: receipt.attempt_id.clone(),
            state: CoordinatedAttemptState::Cancelled,
        };
        self.cancellation_reconciliations.insert(
            receipt.reconciliation_id.clone(),
            IdempotentRecord {
                canonical_input,
                receipt: final_receipt.clone(),
            },
        );
        self.events.push(CoordinatorEvent::CancellationReconciled {
            context,
            receipt: Box::new(receipt),
        });
        Ok(final_receipt)
    }

    /// Releases a writer only after the injected provider verifies an exact
    /// lease/process fence receipt.
    pub fn mark_worker_lost(
        &mut self,
        context: ExecutionContext,
        receipt: ProviderWorkerFenceReceipt,
    ) -> Result<LostWorkerReceipt, CoordinatorError> {
        self.validate_context(&context)?;
        validate_text(&receipt.fence_receipt_ref, "fence_receipt_ref")?;
        validate_text(&receipt.evidence_ref, "evidence_ref")?;
        let canonical_input = canonical(&receipt)?;
        self.provider.verify(
            ProviderProofKind::WorkerFence,
            &receipt.provider_identity,
            &receipt.fence_receipt_ref,
            &canonical_input,
        )?;
        self.validate_provider_identity(&receipt.provider_identity)?;
        if let Some(existing) = self.lost_observations.get(&receipt.observation_id) {
            return idempotent(existing, &canonical_input);
        }
        let current = self
            .attempts
            .get(&receipt.attempt_id)
            .cloned()
            .ok_or(CoordinatorError::UnknownAttempt)?;
        validate_attempt_binding(&current, &context, &receipt.lease_id, &receipt.worker_id)?;
        if current.state.is_terminal() || current.state == CoordinatedAttemptState::UnknownOutcome {
            return Err(CoordinatorError::InvalidAttemptState(current.state));
        }
        self.release_writer(&current);
        self.attempts
            .get_mut(&receipt.attempt_id)
            .ok_or(CoordinatorError::UnknownAttempt)?
            .state = CoordinatedAttemptState::LostFenced;
        let result = LostWorkerReceipt {
            observation_id: receipt.observation_id.clone(),
            attempt_id: receipt.attempt_id.clone(),
            state: CoordinatedAttemptState::LostFenced,
        };
        self.lost_observations.insert(
            receipt.observation_id.clone(),
            IdempotentRecord {
                canonical_input,
                receipt: result.clone(),
            },
        );
        self.events.push(CoordinatorEvent::WorkerFenced {
            context,
            receipt: Box::new(receipt),
        });
        Ok(result)
    }

    #[allow(clippy::too_many_lines)]
    pub fn reassign(
        &mut self,
        context: ExecutionContext,
        receipt: ProviderReassignmentReceipt,
    ) -> Result<ReassignmentReceipt, CoordinatorError> {
        self.validate_context(&context)?;
        validate_text(&receipt.g11_receipt_ref, "g11_receipt_ref")?;
        receipt.route.validate().map_err(provider_contract)?;
        receipt.budget.validate().map_err(provider_contract)?;
        let canonical_input = canonical(&receipt)?;
        self.provider.verify(
            ProviderProofKind::Reassignment,
            &receipt.provider_identity,
            &receipt.g11_receipt_ref,
            &canonical_input,
        )?;
        self.validate_provider_identity(&receipt.provider_identity)?;
        if let Some(existing) = self.reassignments.get(&receipt.reassignment_id) {
            return idempotent(existing, &canonical_input);
        }
        if self.attempts.contains_key(&receipt.new_attempt_id) {
            return Err(CoordinatorError::DuplicateIdentity("new_attempt_id"));
        }
        if self.lease_exists(&receipt.new_lease_id) {
            return Err(CoordinatorError::DuplicateIdentity("new_lease_id"));
        }
        if self.worker_exists(&receipt.new_worker_id) {
            return Err(CoordinatorError::DuplicateIdentity("new_worker_id"));
        }
        let old = self
            .attempts
            .get(&receipt.old_attempt_id)
            .cloned()
            .ok_or(CoordinatorError::UnknownAttempt)?;
        if old.admission_id != context.admission_id {
            return Err(CoordinatorError::StaleController);
        }
        if old.lease_id != receipt.old_lease_id {
            return Err(CoordinatorError::StaleLease);
        }
        if old.state != CoordinatedAttemptState::LostFenced {
            return Err(CoordinatorError::InvalidAttemptState(old.state));
        }
        if receipt.route != old.route {
            return Err(CoordinatorError::RouteMismatch);
        }
        receipt
            .budget
            .is_within(&old.budget)
            .map_err(|_| CoordinatorError::BudgetExceeded)?;
        if self.active_attempt_count().saturating_add(1) > self.config.max_admitted_attempts {
            return Err(CoordinatorError::Backpressure {
                active: self.active_attempt_count(),
                requested: 1,
                limit: self.config.max_admitted_attempts,
            });
        }
        self.validate_route_capacity(BTreeMap::from([(
            route_key(&old.route),
            RouteCapacityRequest {
                requested: 1,
                capacity_identity: old.capacity_identity.clone(),
                capacity_revision: old.capacity_revision.clone(),
                capacity_limit: old.capacity_limit,
            },
        )]))?;
        if let Some(scope) = &old.mutation_scope
            && self.writer_holders.contains_key(scope)
        {
            return Err(CoordinatorError::MutatingWriterConflict(scope.clone()));
        }
        let new_record = AttemptRecord {
            admission_id: old.admission_id.clone(),
            launch_request_id: old.launch_request_id.clone(),
            parent_attempt_id: old.parent_attempt_id.clone(),
            recipe_id: old.recipe_id.clone(),
            recipe_revision: old.recipe_revision.clone(),
            task_id: old.task_id.clone(),
            task_revision: old.task_revision.clone(),
            plan_revision: old.plan_revision.clone(),
            state_fence: old.state_fence.clone(),
            work_unit_id: old.work_unit_id.clone(),
            role_id: old.role_id.clone(),
            role_revision: old.role_revision.clone(),
            attempt_id: receipt.new_attempt_id.clone(),
            lease_id: receipt.new_lease_id.clone(),
            worker_id: receipt.new_worker_id.clone(),
            route: receipt.route.clone(),
            capacity_identity: old.capacity_identity.clone(),
            capacity_revision: old.capacity_revision.clone(),
            capacity_limit: old.capacity_limit,
            budget: receipt.budget.clone(),
            priority: old.priority,
            mutation_scope: old.mutation_scope.clone(),
            state: CoordinatedAttemptState::Admitted,
            superseded_by: None,
        };
        if let Some(scope) = &new_record.mutation_scope {
            self.writer_holders
                .insert(scope.clone(), new_record.attempt_id.clone());
        }
        self.attempts
            .get_mut(&old.attempt_id)
            .ok_or(CoordinatorError::UnknownAttempt)?
            .superseded_by = Some(new_record.attempt_id.clone());
        self.attempts
            .insert(new_record.attempt_id.clone(), new_record.clone());
        let result = ReassignmentReceipt {
            reassignment_id: receipt.reassignment_id.clone(),
            old_attempt_id: receipt.old_attempt_id.clone(),
            new_attempt_id: receipt.new_attempt_id.clone(),
        };
        self.reassignments.insert(
            receipt.reassignment_id.clone(),
            IdempotentRecord {
                canonical_input,
                receipt: result.clone(),
            },
        );
        self.events.push(CoordinatorEvent::Reassigned {
            context,
            receipt: Box::new(receipt),
        });
        Ok(result)
    }

    pub fn submit_result(
        &mut self,
        context: ExecutionContext,
        submission: ResultSubmission,
    ) -> Result<CandidateResultReceipt, CoordinatorError> {
        self.validate_context(&context)?;
        validate_text(
            &submission.provider_result_receipt_ref,
            "provider_result_receipt_ref",
        )?;
        let canonical_input = canonical(&submission)?;
        self.provider.verify(
            ProviderProofKind::Result,
            &submission.provider_identity,
            &submission.provider_result_receipt_ref,
            &canonical_input,
        )?;
        self.validate_provider_identity(&submission.provider_identity)?;
        if let Some(existing) = self.submissions.get(&submission.submission_id) {
            return idempotent(existing, &canonical_input);
        }
        let current = self
            .attempts
            .get(&submission.result.attempt_id)
            .cloned()
            .ok_or(CoordinatorError::UnknownAttempt)?;
        validate_attempt_binding(
            &current,
            &context,
            &submission.lease_id,
            &submission.worker_id,
        )?;
        if current.state == CoordinatedAttemptState::LostFenced || current.superseded_by.is_some() {
            return Err(CoordinatorError::StaleResult);
        }
        if self.result_by_attempt.contains_key(&current.attempt_id) {
            return Err(CoordinatorError::DuplicateResult);
        }
        if current.state != CoordinatedAttemptState::Running {
            return Err(CoordinatorError::InvalidAttemptState(current.state));
        }
        let work_unit = self.work_unit_for(&current)?;
        submission
            .result
            .validate(&work_unit.effect_ceiling)
            .map_err(provider_contract)?;
        let actual = &submission.result.actual_route;
        if actual.requested != current.route
            || actual.observed.as_ref() != Some(&current.route)
            || actual.route_id.as_str().trim().is_empty()
        {
            return Err(CoordinatorError::RouteMismatch);
        }
        if submission.result.disposition == ResultDisposition::VerifiedComplete {
            self.require_descendant_closure(&current.attempt_id)?;
        }
        let receipt = CandidateResultReceipt {
            submission_id: submission.submission_id.clone(),
            attempt_id: current.attempt_id.clone(),
            provider_disposition: submission.result.disposition,
            proof_ceiling: ProofCeiling::CandidateArtifact,
            actual_route: submission.result.actual_route.clone(),
            evidence_refs: submission.result.evidence_refs.clone(),
            proposed_effect_count: submission.result.proposed_effects.len(),
        };
        let next_state = if submission.result.disposition == ResultDisposition::UnknownOutcome {
            CoordinatedAttemptState::UnknownOutcome
        } else {
            self.release_writer(&current);
            CoordinatedAttemptState::CandidateResultSubmitted
        };
        self.attempts
            .get_mut(&current.attempt_id)
            .ok_or(CoordinatorError::UnknownAttempt)?
            .state = next_state;
        self.result_by_attempt
            .insert(current.attempt_id.clone(), submission.submission_id.clone());
        self.submissions.insert(
            submission.submission_id.clone(),
            IdempotentRecord {
                canonical_input,
                receipt: receipt.clone(),
            },
        );
        self.events.push(CoordinatorEvent::ResultSubmitted {
            context,
            submission: Box::new(submission),
        });
        Ok(receipt)
    }

    pub fn reconcile_unknown_outcome(
        &mut self,
        context: ExecutionContext,
        receipt: ProviderUnknownOutcomeReconciliation,
    ) -> Result<UnknownOutcomeFinalReceipt, CoordinatorError> {
        self.validate_context(&context)?;
        validate_text(
            &receipt.effect_reconciliation_ref,
            "effect_reconciliation_ref",
        )?;
        let canonical_input = canonical(&receipt)?;
        self.provider.verify(
            ProviderProofKind::UnknownOutcome,
            &receipt.provider_identity,
            &receipt.effect_reconciliation_ref,
            &canonical_input,
        )?;
        self.validate_provider_identity(&receipt.provider_identity)?;
        if let Some(existing) = self.outcome_reconciliations.get(&receipt.reconciliation_id) {
            return idempotent(existing, &canonical_input);
        }
        let current = self
            .attempts
            .get(&receipt.attempt_id)
            .cloned()
            .ok_or(CoordinatorError::UnknownAttempt)?;
        validate_attempt_binding(&current, &context, &receipt.lease_id, &receipt.worker_id)?;
        if current.state != CoordinatedAttemptState::UnknownOutcome {
            return Err(CoordinatorError::InvalidAttemptState(current.state));
        }
        if self.result_by_attempt.get(&current.attempt_id) != Some(&receipt.submission_id) {
            return Err(CoordinatorError::IdentityConflict("submission_id"));
        }
        self.release_writer(&current);
        self.attempts
            .get_mut(&current.attempt_id)
            .ok_or(CoordinatorError::UnknownAttempt)?
            .state = CoordinatedAttemptState::CandidateResultSubmitted;
        let final_receipt = UnknownOutcomeFinalReceipt {
            reconciliation_id: receipt.reconciliation_id.clone(),
            attempt_id: receipt.attempt_id.clone(),
            resolution: receipt.resolution,
            state: CoordinatedAttemptState::CandidateResultSubmitted,
        };
        self.outcome_reconciliations.insert(
            receipt.reconciliation_id.clone(),
            IdempotentRecord {
                canonical_input,
                receipt: final_receipt.clone(),
            },
        );
        self.events
            .push(CoordinatorEvent::UnknownOutcomeReconciled {
                context,
                receipt: Box::new(receipt),
            });
        Ok(final_receipt)
    }

    pub fn reconcile_descendants(
        &mut self,
        context: ExecutionContext,
        submission: DescendantClosureSubmission,
    ) -> Result<DescendantClosureCandidateReceipt, CoordinatorError> {
        self.validate_context(&context)?;
        submission.receipt.validate().map_err(provider_contract)?;
        let canonical_input = canonical(&submission)?;
        if let Some(existing) = self.descendant_closures.get(&submission.parent_attempt_id) {
            return idempotent(existing, &canonical_input);
        }
        let parent = self
            .attempts
            .get(&submission.parent_attempt_id)
            .ok_or(CoordinatorError::UnknownAttempt)?;
        if parent.admission_id != context.admission_id {
            return Err(CoordinatorError::StaleController);
        }
        let expected = self
            .attempts
            .values()
            .filter(|attempt| {
                attempt.parent_attempt_id.as_ref() == Some(&submission.parent_attempt_id)
            })
            .map(|attempt| attempt.attempt_id.as_str())
            .collect::<BTreeSet<_>>();
        let admitted = submission
            .receipt
            .admitted_descendant_ids
            .iter()
            .map(AgentAttemptId::as_str)
            .collect::<BTreeSet<_>>();
        if expected != admitted {
            return Err(CoordinatorError::IncompleteDescendantClosure);
        }
        for disposition in &submission.receipt.dispositions {
            let attempt = self
                .attempts
                .values()
                .find(|attempt| attempt.attempt_id.as_str() == disposition.attempt_id.as_str())
                .ok_or(CoordinatorError::IncompleteDescendantClosure)?;
            let observed = match attempt.state {
                CoordinatedAttemptState::Admitted | CoordinatedAttemptState::Running => {
                    DescendantTerminalState::Live
                }
                CoordinatedAttemptState::CancellationRequested
                | CoordinatedAttemptState::UnknownOutcome => {
                    DescendantTerminalState::UnknownOutcome
                }
                CoordinatedAttemptState::LostFenced => DescendantTerminalState::Stale,
                CoordinatedAttemptState::Cancelled => DescendantTerminalState::Cancelled,
                CoordinatedAttemptState::CandidateResultSubmitted => self
                    .result_by_attempt
                    .get(&attempt.attempt_id)
                    .and_then(|submission_id| self.submissions.get(submission_id))
                    .map(|record| match record.receipt.provider_disposition {
                        ResultDisposition::VerifiedComplete => DescendantTerminalState::Completed,
                        ResultDisposition::Partial => DescendantTerminalState::Partial,
                        ResultDisposition::Cancelled => DescendantTerminalState::Cancelled,
                        ResultDisposition::UnknownOutcome => {
                            DescendantTerminalState::UnknownOutcome
                        }
                        ResultDisposition::Superseded => DescendantTerminalState::Stale,
                        ResultDisposition::Blocked
                        | ResultDisposition::FailedVerification
                        | ResultDisposition::DegradedNoProof
                        | ResultDisposition::UnsafeToFinish => DescendantTerminalState::Failed,
                    })
                    .ok_or(CoordinatorError::IncompleteDescendantClosure)?,
            };
            if observed != disposition.state {
                return Err(CoordinatorError::IncompleteDescendantClosure);
            }
        }
        let result = DescendantClosureCandidateReceipt {
            operation_id: submission.operation_id.clone(),
            parent_attempt_id: submission.parent_attempt_id.clone(),
            parent_finish_ceiling: submission.receipt.parent_finish_ceiling,
            proof_ceiling: ProofCeiling::CandidateArtifact,
        };
        self.descendant_closures.insert(
            submission.parent_attempt_id.clone(),
            IdempotentRecord {
                canonical_input,
                receipt: result.clone(),
            },
        );
        self.events.push(CoordinatorEvent::DescendantsReconciled {
            context,
            submission: Box::new(submission),
        });
        Ok(result)
    }

    /// Builds a read-only explicit recipient map from one frozen plan revision.
    pub fn coordination_map(
        &self,
        context: &ExecutionContext,
        wave_revision: RevisionId,
    ) -> Result<CoordinationMapView, CoordinatorError> {
        self.validate_context(context)?;
        let mut entries = Vec::new();
        for attempt in self
            .attempts
            .values()
            .filter(|attempt| attempt.plan_revision == context.plan_revision)
        {
            let work = self.work_unit_for(attempt)?;
            entries.push(CoordinationEntry {
                work_item_id: WorkItemId::new(attempt.work_unit_id.as_str())
                    .map_err(provider_contract)?,
                responsibility: work.objective,
                dependency_ids: Vec::new(),
                overlap_ids: Vec::new(),
                assigned_attempt_id: Some(attempt.attempt_id.clone()),
                assigned_role: Some(attempt.role_id.as_str().to_owned()),
                mailbox_route_handle: Some(format!("attempt:{}", attempt.attempt_id.as_str())),
            });
        }
        entries.sort_by(|left, right| left.work_item_id.cmp(&right.work_item_id));
        let view = CoordinationMapView {
            plan_revision: context.plan_revision.clone(),
            wave_revision,
            entries,
        };
        view.validate().map_err(provider_contract)?;
        Ok(view)
    }

    pub fn admit_peer_message(
        &mut self,
        context: ExecutionContext,
        message: LivePeerMessage,
    ) -> Result<PeerMessageReceipt, CoordinatorError> {
        self.validate_context(&context)?;
        let canonical_input = canonical(&message)?;
        if let Some(existing) = self.peer_messages.get(&message.message_id) {
            return idempotent(existing, &canonical_input);
        }
        if message.state != LivePeerMessageState::Draft {
            return Err(CoordinatorError::IdentityConflict("message_state"));
        }
        let sender = message.sender_attempt_id.clone();
        let sender_attempt = self
            .attempts
            .get(&sender)
            .ok_or(CoordinatorError::UnknownAttempt)?;
        if sender_attempt.work_unit_id.as_str() != message.sender_work_item_id.as_str()
            || sender_attempt.plan_revision != context.plan_revision
        {
            return Err(CoordinatorError::StaleResult);
        }
        let map = self.coordination_map(&context, message.wave_revision.clone())?;
        message
            .validate_against_map(&map)
            .map_err(provider_contract)?;
        let mut queued = message.clone();
        queued.state = LivePeerMessageState::Queued;
        let receipt = PeerMessageReceipt {
            message_id: message.message_id.clone(),
            state: LivePeerMessageState::Queued,
        };
        self.peer_messages.insert(
            message.message_id.clone(),
            IdempotentRecord {
                canonical_input,
                receipt: receipt.clone(),
            },
        );
        self.peer_message_payloads
            .insert(message.message_id.clone(), queued);
        self.events.push(CoordinatorEvent::PeerMessageQueued {
            context,
            message: Box::new(message),
        });
        Ok(receipt)
    }

    pub fn deliver_next_boundary(
        &mut self,
        context: ExecutionContext,
        recipient_attempt_id: AttemptId,
    ) -> Result<Option<DeliveryBoundaryReceipt>, CoordinatorError> {
        self.validate_context(&context)?;
        let attempt = self
            .attempts
            .get(&recipient_attempt_id)
            .ok_or(CoordinatorError::UnknownAttempt)?;
        if attempt.state != CoordinatedAttemptState::Running {
            return Err(CoordinatorError::InvalidAttemptState(attempt.state));
        }
        let contract_attempt = recipient_attempt_id.clone();
        let contract_work =
            WorkItemId::new(attempt.work_unit_id.as_str()).map_err(provider_contract)?;
        let message_id = self
            .peer_message_payloads
            .iter()
            .find(|(_, message)| {
                message.state == LivePeerMessageState::Queued
                    && message.recipients.iter().any(|recipient| {
                        recipient.attempt_id.as_ref() == Some(&contract_attempt)
                            || recipient.work_item_id.as_ref() == Some(&contract_work)
                    })
            })
            .map(|(id, _)| id.clone());
        match message_id {
            Some(message_id) => self
                .deliver_message(context, recipient_attempt_id, message_id)
                .map(Some),
            None => Ok(None),
        }
    }

    pub fn snapshot(&self) -> Result<CoordinatorSnapshot, CoordinatorError> {
        let provider_binding = self.provider.binding();
        let event_sequence = u64::try_from(self.events.len())
            .map_err(|_| CoordinatorError::Serialization("event sequence overflow".to_owned()))?;
        let event_digest = snapshot_digest(
            &self.config,
            &provider_binding,
            event_sequence,
            &self.events,
        )?;
        Ok(CoordinatorSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION.to_owned(),
            config: self.config.clone(),
            provider_binding,
            event_sequence,
            event_digest,
            events: self.events.clone(),
        })
    }

    pub fn snapshot_json(&self) -> Result<String, CoordinatorError> {
        serde_json::to_string(&self.snapshot()?)
            .map_err(|error| CoordinatorError::Serialization(error.to_string()))
    }

    /// Public restore remains plan-only because no accepted A-01/G-11 provider
    /// exists in this cell yet.
    pub fn restore(
        snapshot: CoordinatorSnapshot,
        live_config: CoordinatorConfig,
        gap: PlanGap,
    ) -> Result<Self, CoordinatorError> {
        gap.validate()?;
        Self::restore_with_provider(snapshot, live_config, Box::new(GapProvider { gap }))
    }

    pub fn restore_json(
        json: &str,
        live_config: CoordinatorConfig,
        gap: PlanGap,
    ) -> Result<Self, CoordinatorError> {
        let snapshot = serde_json::from_str(json)
            .map_err(|error| CoordinatorError::Serialization(error.to_string()))?;
        Self::restore(snapshot, live_config, gap)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn restore_with_provider(
        snapshot: CoordinatorSnapshot,
        live_config: CoordinatorConfig,
        provider: Box<dyn ProviderVerifier>,
    ) -> Result<Self, CoordinatorError> {
        if snapshot.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(CoordinatorError::UnsupportedSnapshot);
        }
        live_config.validate()?;
        if snapshot.config != live_config {
            return Err(CoordinatorError::StaleCapacity);
        }
        let live_binding = provider.binding();
        if snapshot.provider_binding != live_binding {
            return Err(CoordinatorError::StaleProviderBinding);
        }
        if snapshot.event_sequence
            != u64::try_from(snapshot.events.len())
                .map_err(|_| CoordinatorError::SnapshotRollback)?
            || snapshot.event_sequence < provider.minimum_event_sequence()
        {
            return Err(CoordinatorError::SnapshotRollback);
        }
        let digest = snapshot_digest(
            &snapshot.config,
            &snapshot.provider_binding,
            snapshot.event_sequence,
            &snapshot.events,
        )?;
        if digest != snapshot.event_digest {
            return Err(CoordinatorError::SnapshotDigest);
        }
        let expected_events = snapshot.events.clone();
        let mut coordinator = Self::with_provider(live_config, provider)?;
        for event in expected_events.clone() {
            match event {
                CoordinatorEvent::PlanCreated { request } => {
                    coordinator.plan(*request)?;
                }
                CoordinatorEvent::PlanAdmitted { receipt } => {
                    coordinator.admit(*receipt)?;
                }
                CoordinatorEvent::AttemptStarted {
                    context,
                    attempt_id,
                } => {
                    coordinator.start_attempt(context, attempt_id)?;
                }
                CoordinatorEvent::CancellationRequested { context, command } => {
                    coordinator.request_cancellation(context, *command)?;
                }
                CoordinatorEvent::CancellationReconciled { context, receipt } => {
                    coordinator.reconcile_cancellation(context, *receipt)?;
                }
                CoordinatorEvent::WorkerFenced { context, receipt } => {
                    coordinator.mark_worker_lost(context, *receipt)?;
                }
                CoordinatorEvent::Reassigned { context, receipt } => {
                    coordinator.reassign(context, *receipt)?;
                }
                CoordinatorEvent::ResultSubmitted {
                    context,
                    submission,
                } => {
                    coordinator.submit_result(context, *submission)?;
                }
                CoordinatorEvent::UnknownOutcomeReconciled { context, receipt } => {
                    coordinator.reconcile_unknown_outcome(context, *receipt)?;
                }
                CoordinatorEvent::DescendantsReconciled {
                    context,
                    submission,
                } => {
                    coordinator.reconcile_descendants(context, *submission)?;
                }
                CoordinatorEvent::PeerMessageQueued { context, message } => {
                    coordinator.admit_peer_message(context, *message)?;
                }
                CoordinatorEvent::PeerMessageDelivered {
                    context,
                    recipient_attempt_id,
                    message_id,
                } => {
                    coordinator.deliver_message(context, recipient_attempt_id, message_id)?;
                }
            }
        }
        if coordinator.events != expected_events {
            return Err(CoordinatorError::SnapshotDigest);
        }
        Ok(coordinator)
    }

    fn deliver_message(
        &mut self,
        context: ExecutionContext,
        recipient_attempt_id: AttemptId,
        message_id: MessageId,
    ) -> Result<DeliveryBoundaryReceipt, CoordinatorError> {
        self.validate_context(&context)?;
        let message = self
            .peer_message_payloads
            .get_mut(&message_id)
            .ok_or(CoordinatorError::UnknownMessage)?;
        if message.state != LivePeerMessageState::Queued {
            return Err(CoordinatorError::IdentityConflict("message_state"));
        }
        if message.delivery_policy == eliot_agent_contracts::DeliveryPolicy::Unavailable {
            return Err(CoordinatorError::DeliveryUnavailable);
        }
        message.state = LivePeerMessageState::Delivered;
        let receipt = DeliveryBoundaryReceipt {
            message_id: message_id.clone(),
            recipient_attempt_id: recipient_attempt_id.clone(),
            state: LivePeerMessageState::Delivered,
        };
        self.events.push(CoordinatorEvent::PeerMessageDelivered {
            context,
            recipient_attempt_id,
            message_id,
        });
        Ok(receipt)
    }

    fn validate_provider_identity(
        &self,
        identity: &ProviderIdentity,
    ) -> Result<(), CoordinatorError> {
        identity.validate()?;
        match self.provider.binding() {
            ProviderBindingSnapshot::Verified { identity: expected } if expected == *identity => {
                Ok(())
            }
            ProviderBindingSnapshot::Gap { gap } => Err(gap.into()),
            ProviderBindingSnapshot::Verified { .. } => Err(CoordinatorError::StaleProviderBinding),
        }
    }

    fn validate_context(
        &self,
        context: &ExecutionContext,
    ) -> Result<ProviderAdmissionReceipt, CoordinatorError> {
        let admission = self
            .admissions
            .get(&context.admission_id)
            .ok_or(CoordinatorError::UnknownAdmission)?;
        let receipt = &admission.receipt;
        if receipt.task_revision != context.task_revision {
            return Err(CoordinatorError::StaleTaskRevision);
        }
        if receipt.plan_revision != context.plan_revision {
            return Err(CoordinatorError::StalePlanRevision);
        }
        if receipt.state_fence != context.state_fence {
            return Err(CoordinatorError::StaleFence);
        }
        if receipt.controller_epoch != context.controller_epoch
            || receipt.coordinator_lease != context.coordinator_lease
        {
            return Err(CoordinatorError::StaleController);
        }
        Ok(receipt.clone())
    }

    fn active_attempt_count(&self) -> usize {
        self.attempts
            .values()
            .filter(|attempt| !attempt.state.is_terminal())
            .count()
    }

    fn validate_route_capacity(
        &self,
        route_additions: BTreeMap<String, RouteCapacityRequest>,
    ) -> Result<(), CoordinatorError> {
        for (route, addition) in route_additions {
            if addition.capacity_limit == 0
                || addition.capacity_identity != self.config.capacity_identity
                || addition.capacity_revision != self.config.capacity_revision
            {
                return Err(CoordinatorError::StaleCapacity);
            }
            let mut active = 0usize;
            let mut effective_limit = self
                .config
                .max_active_per_route
                .min(addition.capacity_limit);
            for attempt in self.attempts.values().filter(|attempt| {
                !attempt.state.is_terminal() && route_key(&attempt.route) == route
            }) {
                if attempt.capacity_identity != addition.capacity_identity
                    || attempt.capacity_revision != addition.capacity_revision
                    || attempt.capacity_limit == 0
                {
                    return Err(CoordinatorError::StaleCapacity);
                }
                active = active.saturating_add(1);
                effective_limit = effective_limit.min(attempt.capacity_limit);
            }
            if active.saturating_add(addition.requested) > effective_limit {
                return Err(CoordinatorError::Backpressure {
                    active,
                    requested: addition.requested,
                    limit: effective_limit,
                });
            }
        }
        Ok(())
    }

    fn lease_exists(&self, lease: &WorkLeaseId) -> bool {
        self.attempts
            .values()
            .any(|attempt| &attempt.lease_id == lease)
    }

    fn worker_exists(&self, worker: &WorkerId) -> bool {
        self.attempts
            .values()
            .any(|attempt| &attempt.worker_id == worker)
    }

    fn launch_for_candidate(
        &self,
        candidate_id: &CandidateId,
    ) -> Result<&eliot_agent_api::AgentLaunchRequest, CoordinatorError> {
        self.events
            .iter()
            .find_map(|event| match event {
                CoordinatorEvent::PlanCreated { request }
                    if &request.candidate_id == candidate_id =>
                {
                    Some(&request.launch)
                }
                _ => None,
            })
            .ok_or(CoordinatorError::UnknownCandidate)
    }

    fn work_unit_for(
        &self,
        attempt: &AttemptRecord,
    ) -> Result<eliot_agent_api::AgentWorkUnitBrief, CoordinatorError> {
        let admission = self
            .admissions
            .get(&attempt.admission_id)
            .ok_or(CoordinatorError::UnknownAdmission)?;
        self.launch_for_candidate(&admission.receipt.candidate_id)?
            .work_units
            .iter()
            .find(|work| work.id == attempt.work_unit_id)
            .cloned()
            .ok_or(CoordinatorError::IdentityConflict("work_unit_id"))
    }

    fn require_descendant_closure(&self, parent: &AttemptId) -> Result<(), CoordinatorError> {
        let has_descendants = self
            .attempts
            .values()
            .any(|attempt| attempt.parent_attempt_id.as_ref() == Some(parent));
        if !has_descendants {
            return Ok(());
        }
        let closure = self
            .descendant_closures
            .get(parent)
            .ok_or(CoordinatorError::IncompleteDescendantClosure)?;
        if closure.receipt.parent_finish_ceiling != ParentFinishCeiling::Complete {
            return Err(CoordinatorError::IncompleteDescendantClosure);
        }
        Ok(())
    }

    fn release_writer(&mut self, attempt: &AttemptRecord) {
        if let Some(scope) = &attempt.mutation_scope
            && self.writer_holders.get(scope) == Some(&attempt.attempt_id)
        {
            self.writer_holders.remove(scope);
        }
    }

    fn validate_launch_effect_ceiling(
        &self,
        launch: &eliot_agent_api::AgentLaunchRequest,
    ) -> Result<(), CoordinatorError> {
        let parent_ceiling = if let Some(parent_attempt) = &launch.parent_attempt {
            let parent = self
                .attempts
                .get(parent_attempt)
                .ok_or(CoordinatorError::UnknownAttempt)?;
            self.work_unit_for(parent)?.effect_ceiling
        } else {
            launch.effect_ceiling.clone()
        };
        if launch.parent_attempt.is_some() {
            validate_effect_ceiling(&launch.effect_ceiling, &parent_ceiling)?;
        }
        for work_unit in &launch.work_units {
            validate_effect_ceiling(&work_unit.effect_ceiling, &launch.effect_ceiling)?;
        }
        Ok(())
    }
}

fn validate_recipe(request: &StaffingPlanRequest) -> Result<(), CoordinatorError> {
    validate_text(request.recipe.recipe_id.as_str(), "recipe_id")?;
    validate_text(request.recipe.manifest_revision.as_str(), "recipe_revision")?;
    validate_text(
        request.recipe.route_policy_revision.as_str(),
        "route_policy_revision",
    )?;
    if request.recipe.max_lanes == 0 || request.recipe.role_profiles.is_empty() {
        return Err(CoordinatorError::InvalidField("recipe"));
    }
    if request.recipe.max_descendants > request.launch.cumulative_descendant_budget.max_descendants
    {
        return Err(CoordinatorError::BudgetExceeded);
    }
    let mut roles = BTreeSet::new();
    for role in &request.recipe.role_profiles {
        validate_text(role.role_id.as_str(), "role_id")?;
        validate_text(role.manifest_revision.as_str(), "role_revision")?;
        if role.required_competence.is_empty() || role.allowed_route_classes.is_empty() {
            return Err(CoordinatorError::InvalidField("role_profile"));
        }
        for value in role
            .required_competence
            .iter()
            .chain(role.allowed_route_classes.iter())
        {
            validate_text(value, "role_profile_value")?;
        }
        if !roles.insert(role.role_id.clone()) {
            return Err(CoordinatorError::DuplicateIdentity("role_id"));
        }
    }
    Ok(())
}

fn select_route(
    config: &CoordinatorConfig,
    request: &StaffingPlanRequest,
    role: &RoleProfileManifest,
    mut candidates: Vec<RouteCandidateEvidence>,
) -> Result<RoutingReceipt, CoordinatorError> {
    if candidates.is_empty() {
        return Err(CoordinatorError::RouteEvidence);
    }
    let mut identities = BTreeSet::new();
    for candidate in &candidates {
        candidate.route.validate().map_err(provider_contract)?;
        candidate
            .budget_evidence
            .validate()
            .map_err(provider_contract)?;
        validate_text(&candidate.capacity_identity, "capacity_identity")?;
        validate_text(candidate.capacity_revision.as_str(), "capacity_revision")?;
        if candidate.capacity_limit == 0
            || candidate.capacity_identity != config.capacity_identity
            || candidate.capacity_revision != config.capacity_revision
            || candidate.evidence_refs.is_empty()
        {
            return Err(CoordinatorError::RouteEvidence);
        }
        if !route_class_allowed(
            &request.launch.allowed_route_classes,
            &candidate.route.provider,
        ) || !route_class_allowed(&role.allowed_route_classes, &candidate.route.provider)
        {
            return Err(CoordinatorError::RouteEvidence);
        }
        for evidence in &candidate.evidence_refs {
            validate_text(evidence, "route_evidence_ref")?;
        }
        if !identities.insert(route_key(&candidate.route)) {
            return Err(CoordinatorError::DuplicateIdentity("route_candidate"));
        }
    }
    candidates.sort_by(|left, right| {
        left.preference_rank
            .cmp(&right.preference_rank)
            .then_with(|| route_key(&left.route).cmp(&route_key(&right.route)))
    });
    let selected = candidates.remove(0);
    let rejected_alternatives = candidates
        .into_iter()
        .map(|candidate| RejectedRoute {
            route: candidate.route,
            reason: RouteRejectionReason::LowerDeterministicRank,
        })
        .collect();
    Ok(RoutingReceipt {
        selected_route: selected.route,
        capacity_identity: selected.capacity_identity,
        capacity_revision: selected.capacity_revision,
        capacity_limit: selected.capacity_limit,
        budget_evidence: selected.budget_evidence,
        evidence_refs: selected.evidence_refs,
        rejected_alternatives,
        proof_ceiling: ProofCeiling::CandidateArtifact,
    })
}

fn route_class_allowed(allowed_route_classes: &[String], provider: &str) -> bool {
    allowed_route_classes
        .iter()
        .any(|class| class == provider || class == "*")
}

fn validate_admission_text(receipt: &ProviderAdmissionReceipt) -> Result<(), CoordinatorError> {
    receipt.provider_identity.validate()?;
    for (value, field) in [
        (receipt.launch_request_id.as_str(), "launch_request_id"),
        (receipt.recipe_id.as_str(), "recipe_id"),
        (receipt.recipe_revision.as_str(), "recipe_revision"),
        (receipt.task_id.as_str(), "task_id"),
        (&receipt.task_revision, "task_revision"),
        (receipt.plan_revision.as_str(), "plan_revision"),
        (receipt.coordinator_lease.as_str(), "coordinator_lease"),
        (
            &receipt.g11_admission_receipt_ref,
            "g11_admission_receipt_ref",
        ),
        (&receipt.durable_job_ref, "durable_job_ref"),
    ] {
        validate_text(value, field)?;
    }
    validate_state_fence(&receipt.state_fence)?;
    if receipt.controller_epoch != receipt.state_fence.authority_epoch {
        return Err(CoordinatorError::StaleController);
    }
    if receipt.admitted_lanes.is_empty() {
        return Err(CoordinatorError::InvalidField("admitted_lanes"));
    }
    Ok(())
}

fn validate_state_fence(fence: &eliot_agent_api::StateFence) -> Result<(), CoordinatorError> {
    fence
        .validate()
        .map_err(|error| CoordinatorError::ProviderContract(error.to_string()))
}

fn validate_candidate_binding(
    candidate: &StaffingPlanCandidate,
    receipt: &ProviderAdmissionReceipt,
) -> Result<(), CoordinatorError> {
    if receipt.task_id != candidate.task_id
        || receipt.launch_request_id != candidate.launch_request_id
        || receipt.recipe_id != candidate.recipe_id
        || receipt.recipe_revision != candidate.recipe_revision
    {
        return Err(CoordinatorError::IdentityConflict("candidate_identity"));
    }
    if receipt.task_revision != candidate.task_revision {
        return Err(CoordinatorError::StaleTaskRevision);
    }
    if receipt.plan_revision != candidate.plan_revision {
        return Err(CoordinatorError::StalePlanRevision);
    }
    if receipt.state_fence != candidate.state_fence {
        return Err(CoordinatorError::StaleFence);
    }
    Ok(())
}

fn validate_admitted_lane(lane: &crate::AdmittedLaneReceipt) -> Result<(), CoordinatorError> {
    validate_text(lane.work_unit_id.as_str(), "work_unit_id")?;
    validate_text(lane.role_id.as_str(), "role_id")?;
    validate_text(lane.role_revision.as_str(), "role_revision")?;
    validate_text(lane.attempt_id.as_str(), "attempt_id")?;
    validate_text(lane.lease_id.as_str(), "lease_id")?;
    validate_text(lane.worker_id.as_str(), "worker_id")?;
    validate_text(&lane.routing_receipt_digest, "routing_receipt_digest")?;
    lane.route.validate().map_err(provider_contract)?;
    lane.budget.validate().map_err(provider_contract)?;
    if let Some(scope) = &lane.mutation_scope {
        validate_text(scope, "mutation_scope")?;
    }
    Ok(())
}

fn validate_attempt_binding(
    attempt: &AttemptRecord,
    context: &ExecutionContext,
    lease_id: &WorkLeaseId,
    worker_id: &WorkerId,
) -> Result<(), CoordinatorError> {
    if attempt.admission_id != context.admission_id
        || attempt.task_revision != context.task_revision
        || attempt.plan_revision != context.plan_revision
        || attempt.state_fence != context.state_fence
    {
        return Err(CoordinatorError::StaleResult);
    }
    if &attempt.lease_id != lease_id {
        return Err(CoordinatorError::StaleLease);
    }
    if &attempt.worker_id != worker_id {
        return Err(CoordinatorError::StaleWorker);
    }
    Ok(())
}

fn provider_contract(error: impl std::fmt::Display) -> CoordinatorError {
    CoordinatorError::ProviderContract(error.to_string())
}

fn validate_effect_ceiling(
    child: &EffectCeiling,
    parent: &EffectCeiling,
) -> Result<(), CoordinatorError> {
    if !child.allowed.is_subset(&parent.allowed)
        || child.max_external_effects > parent.max_external_effects
    {
        return Err(provider_contract(ContractError::InsufficientAuthority));
    }
    Ok(())
}

fn route_key(route: &eliot_agent_api::RouteFingerprint) -> String {
    route
        .canonical_json()
        .unwrap_or_else(|_| "<invalid-route>".to_owned())
}

fn canonical(value: &impl Serialize) -> Result<String, CoordinatorError> {
    serde_json::to_string(value).map_err(|error| CoordinatorError::Serialization(error.to_string()))
}

fn snapshot_digest(
    config: &CoordinatorConfig,
    provider: &ProviderBindingSnapshot,
    event_sequence: u64,
    events: &[CoordinatorEvent],
) -> Result<String, CoordinatorError> {
    contract_shape_digest(&(
        SNAPSHOT_SCHEMA_VERSION,
        config,
        provider,
        event_sequence,
        events,
    ))
    .map_err(|error| CoordinatorError::Serialization(error.to_string()))
}

fn idempotent<T: Clone>(
    existing: &IdempotentRecord<T>,
    canonical_input: &str,
) -> Result<T, CoordinatorError> {
    if existing.canonical_input == canonical_input {
        Ok(existing.receipt.clone())
    } else {
        Err(CoordinatorError::IdempotencyConflict)
    }
}

#[cfg(test)]
mod admission_normalization_tests;
