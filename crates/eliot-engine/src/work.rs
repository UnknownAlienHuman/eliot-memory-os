use crate::{EngineError, WriteAdmissionService, WriterHandle};
use eliot_contracts::{
    WORK_LEASE_NAMESPACE, WORK_LEASE_WIRE_REVISION, WorkLeaseId as CanonicalWorkLeaseId,
    canonical_json_bytes, sha256_hex,
};
use eliot_types::{
    ActionLease, AgentId, AgentRole, AgentRun, AgentSession, AgentSessionId, AgentSessionStatus,
    AgentTransport, AuthorityProfile, BlackboardItem, CandidateDiff, CandidateDiffStatus,
    CandidateReview, CandidateReviewDecision, CollectiveTrace, CommandContext, LifecycleStatus,
    LostAgentRecoveryRecord, MailboxMessage, OperationStatus, ProjectId, RiskTier, SemanticCommand,
    TaintClass, TaskId, ToolObservationRecordCommand, VerifierRequirement, VerifierRun,
    VerifierRunRef, VerifierStatus, Visibility, WorkConflict, WorkConflictKind,
    WorkConflictResolution, WorkItem, WorkItemId, WorkItemStatus, WorkLease, WorkLeaseDecision,
    WorkLeaseDecisionKind, WorkLeaseDecisionReason, WorkLeaseId, WorkLeaseState, WorkScope,
    WorktreeLease, WriteId, WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

const DEFAULT_LEASE_TTL_MINUTES: i64 = 45;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkState {
    pub sessions: Vec<AgentSession>,
    pub work_items: Vec<WorkItem>,
    pub leases: Vec<WorkLease>,
    pub conflicts: Vec<WorkConflict>,
    pub agent_runs: Vec<AgentRun>,
    pub decisions: Vec<WorkLeaseDecision>,
    #[serde(default)]
    pub worktree_leases: Vec<WorktreeLease>,
    #[serde(default)]
    pub candidate_diffs: Vec<CandidateDiff>,
    #[serde(default)]
    pub candidate_reviews: Vec<CandidateReview>,
    #[serde(default)]
    pub action_leases: Vec<ActionLease>,
    #[serde(default)]
    pub blackboard_items: Vec<BlackboardItem>,
    #[serde(default)]
    pub mailbox_messages: Vec<MailboxMessage>,
    #[serde(default)]
    pub recovery_records: Vec<LostAgentRecoveryRecord>,
    #[serde(default)]
    pub collective_traces: Vec<CollectiveTrace>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkStatusReport {
    pub component: String,
    pub project: String,
    pub task: String,
    pub sessions: Vec<AgentSession>,
    pub work_items: Vec<WorkItem>,
    pub active_leases: Vec<WorkLease>,
    pub conflicts: Vec<WorkConflict>,
    pub decisions: Vec<WorkLeaseDecision>,
    pub worktree_leases: Vec<WorktreeLease>,
    pub candidate_diffs: Vec<CandidateDiff>,
    pub candidate_reviews: Vec<CandidateReview>,
    #[serde(rename = "final_status")]
    pub operation_status: OperationStatus,
}

#[derive(Clone, Debug)]
pub struct WorkCreateRequest {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub project: String,
    pub task: String,
    pub goal: String,
    pub scope: WorkScope,
    pub required: bool,
    pub created_by: AgentSessionId,
    pub required_verifiers: Vec<VerifierRequirement>,
}

#[derive(Clone, Copy, Debug)]
pub struct WorkClaimRequest {
    pub work_item_id: WorkItemId,
    pub agent_session_id: AgentSessionId,
    pub role: AgentRole,
    pub ttl_minutes: i64,
}

/// Classification of one canonical issuance attempt by the incumbent
/// `WorkLeaseService` owner.
///
/// Only [`Self::OwnerIssued`] carries a canonical
/// `eliot_contracts::WorkLeaseId`.
/// A normal denial creates no lease, while [`Self::LegacyQuarantined`] records
/// that the legacy grant exists but its exact owner evidence could not produce
/// the canonical object. Neither non-owner-issued disposition may satisfy a
/// later agent authority field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkLeaseIssuanceDisposition {
    OwnerIssued,
    NotGranted,
    LegacyQuarantined,
}

/// Fail-closed reason why an accepted legacy grant was not emitted as the
/// canonical owner-neutral `WorkLease` identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkLeaseIssuanceError {
    #[error("granted decision is missing its legacy source identity")]
    MissingSourceIdentity,
    #[error("exact owner grant evidence is missing")]
    MissingOwnerEvidence,
    #[error("owner grant evidence is ambiguous")]
    AmbiguousOwnerEvidence,
    #[error("owner grant evidence is internally inconsistent")]
    InconsistentOwnerEvidence,
    #[error("owner grant evidence could not be encoded canonically")]
    EvidenceEncodingRejected,
    #[error("canonical WorkLease contract rejected owner-issued evidence")]
    CanonicalContractRejected,
}

/// Exact owner evidence that bound one incumbent legacy lease grant to one
/// canonical owner-neutral `WorkLease` identity.
///
/// The canonical value is derived from the complete accepted issuance
/// snapshot, not from UUID spelling. The original UUID-backed lease, work item
/// and session remain available only as attributed legacy evidence. The
/// unkeyed evidence commitment is not authority proof by itself; issuance is
/// established only by the same-call transition through `WorkLeaseService`.
/// This package boundary is not a `StateFence`, process fence, durable-store
/// receipt, or proof that the current Governor daemon issued the lease.
#[derive(Clone, Debug)]
pub struct WorkLeaseIssuanceProvenance {
    canonical_work_lease_id: CanonicalWorkLeaseId,
    source_lease: WorkLease,
    source_work_item: WorkItem,
    source_session: AgentSession,
    evidence_commitment_sha256: String,
}

impl WorkLeaseIssuanceProvenance {
    /// Returns the canonical owner-neutral identity. No raw-text accessor is
    /// exposed by this boundary.
    #[must_use]
    pub const fn canonical_work_lease_id(&self) -> &CanonicalWorkLeaseId {
        &self.canonical_work_lease_id
    }

    /// Returns the exact UUID-backed lease retained as legacy source evidence.
    #[must_use]
    pub const fn source_lease(&self) -> &WorkLease {
        &self.source_lease
    }

    /// Returns the exact active work-item snapshot observed after the grant.
    #[must_use]
    pub const fn source_work_item(&self) -> &WorkItem {
        &self.source_work_item
    }

    /// Returns the exact active session snapshot observed after the grant.
    #[must_use]
    pub const fn source_session(&self) -> &AgentSession {
        &self.source_session
    }

    /// Returns the unkeyed commitment to the immutable issuance snapshot.
    /// This value commits the evidence bytes; it does not prove authority
    /// independently of the owner-issued result that carries it.
    #[must_use]
    pub fn evidence_commitment_sha256(&self) -> &str {
        &self.evidence_commitment_sha256
    }
}

#[derive(Clone, Debug)]
enum WorkLeaseIssuanceState {
    OwnerIssued(Box<WorkLeaseIssuanceProvenance>),
    NotGranted,
    LegacyQuarantined(WorkLeaseIssuanceError),
}

/// Result of asking the incumbent owner to claim work and emit canonical
/// issuance provenance in the same call.
///
/// Existing callers continue to use [`WorkLeaseService::claim`] unchanged.
/// A future #368 consumer is eligible to use only a result whose disposition
/// is [`WorkLeaseIssuanceDisposition::OwnerIssued`]. That later migration must
/// preserve this immutable issuance snapshot; this package proof does not add
/// durable storage or recovery. Raw coordination strings, synthetic
/// application leases and arbitrary legacy IDs never enter this boundary.
///
/// The exact future #368 migration envelope is limited to the lease fields in
/// `eliot-agent-api/src/lib.rs` (`AuthorityEnvelope::lease` and
/// `AgentAttempt::lease`), their `eliot-agent-coordinator/src/model.rs`
/// projections, and the typed lease ports in
/// `eliot-native-worker-core/src/ports.rs`. The current agent-API wrapper and
/// coordination strings remain loss-visible legacy/projection data until that
/// migration consumes an `OwnerIssued` result. UUID-backed engine/application
/// leases remain source evidence only; direct synthetic application leases are
/// ineligible. No field may migrate by matching text.
#[derive(Clone, Debug)]
pub struct WorkLeaseIssuanceResult {
    decision: WorkLeaseDecision,
    issuance: WorkLeaseIssuanceState,
}

impl WorkLeaseIssuanceResult {
    /// Returns the existing legacy decision without changing its wire or state.
    #[must_use]
    pub const fn decision(&self) -> &WorkLeaseDecision {
        &self.decision
    }

    /// Returns the loss-visible issuance classification.
    #[must_use]
    pub const fn disposition(&self) -> WorkLeaseIssuanceDisposition {
        match self.issuance {
            WorkLeaseIssuanceState::OwnerIssued(_) => WorkLeaseIssuanceDisposition::OwnerIssued,
            WorkLeaseIssuanceState::NotGranted => WorkLeaseIssuanceDisposition::NotGranted,
            WorkLeaseIssuanceState::LegacyQuarantined(_) => {
                WorkLeaseIssuanceDisposition::LegacyQuarantined
            }
        }
    }

    /// Returns provenance only for an exact same-call owner issuance.
    #[must_use]
    pub fn provenance(&self) -> Option<&WorkLeaseIssuanceProvenance> {
        match &self.issuance {
            WorkLeaseIssuanceState::OwnerIssued(provenance) => Some(provenance.as_ref()),
            WorkLeaseIssuanceState::NotGranted | WorkLeaseIssuanceState::LegacyQuarantined(_) => {
                None
            }
        }
    }

    /// Returns the typed quarantine reason when a legacy grant could not be
    /// bound to exact owner evidence.
    #[must_use]
    pub const fn error(&self) -> Option<WorkLeaseIssuanceError> {
        match self.issuance {
            WorkLeaseIssuanceState::LegacyQuarantined(error) => Some(error),
            WorkLeaseIssuanceState::OwnerIssued(_) | WorkLeaseIssuanceState::NotGranted => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkSessionEvent {
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub role: AgentRole,
    pub transport: AgentTransport,
    pub status: AgentSessionStatus,
    pub summary: String,
}

#[derive(Clone, Copy, Debug)]
struct ClaimSession {
    agent_session_id: AgentSessionId,
    agent_id: AgentId,
    status: AgentSessionStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkLeaseGuardError {
    Missing,
    Inactive,
    Mismatch,
    FileOutsideScope,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AgentSessionService;

#[derive(Clone, Copy, Debug, Default)]
pub struct WorkQueueService;

#[derive(Clone, Copy, Debug, Default)]
pub struct WorkLeaseService;

#[derive(Clone, Copy, Debug, Default)]
pub struct WorkConflictService;

pub struct WorkMemoryWriter;

impl AgentSessionService {
    #[must_use]
    pub fn create_controller(&self, state: &mut WorkState, project_id: ProjectId) -> AgentSession {
        self.create_for_role(state, project_id, AgentRole::Controller)
    }

    #[must_use]
    pub fn create_for_role(
        &self,
        state: &mut WorkState,
        project_id: ProjectId,
        role: AgentRole,
    ) -> AgentSession {
        let now = OffsetDateTime::now_utc();
        let session = AgentSession {
            agent_session_id: AgentSessionId::new_v7(),
            agent_id: AgentId::new_v7(),
            project_id,
            role,
            transport: AgentTransport::LocalCli,
            status: AgentSessionStatus::Active,
            parent_session_id: None,
            current_work_item_id: None,
            started_at: now,
            last_heartbeat_at: now,
            stopped_at: None,
            unavailable_reason: None,
            write_receipt: None,
        };
        state.sessions.push(session.clone());
        session
    }

    pub fn bind_for_role(
        &self,
        state: &mut WorkState,
        agent_session_id: AgentSessionId,
        project_id: ProjectId,
        role: AgentRole,
    ) -> Result<AgentSession, EngineError> {
        if let Some(session) = state
            .sessions
            .iter()
            .find(|session| session.agent_session_id == agent_session_id)
        {
            if session.project_id != project_id
                || session.role != role
                || session.status != AgentSessionStatus::Active
            {
                return Err(EngineError::WriteRejected(
                    "agent session binding does not match the requested active project role"
                        .to_owned(),
                ));
            }
            return Ok(session.clone());
        }

        let now = OffsetDateTime::now_utc();
        let session = AgentSession {
            agent_session_id,
            agent_id: AgentId::new_v7(),
            project_id,
            role,
            transport: AgentTransport::LocalCli,
            status: AgentSessionStatus::Active,
            parent_session_id: None,
            current_work_item_id: None,
            started_at: now,
            last_heartbeat_at: now,
            stopped_at: None,
            unavailable_reason: None,
            write_receipt: None,
        };
        state.sessions.push(session.clone());
        Ok(session)
    }

    #[must_use]
    pub fn create_subagent_unavailable(
        &self,
        state: &mut WorkState,
        project_id: ProjectId,
        parent_session_id: AgentSessionId,
        reason: impl Into<String>,
    ) -> AgentSession {
        let now = OffsetDateTime::now_utc();
        let session = AgentSession {
            agent_session_id: AgentSessionId::new_v7(),
            agent_id: AgentId::new_v7(),
            project_id,
            role: AgentRole::Reviewer,
            transport: AgentTransport::Unavailable,
            status: AgentSessionStatus::Unavailable,
            parent_session_id: Some(parent_session_id),
            current_work_item_id: None,
            started_at: now,
            last_heartbeat_at: now,
            stopped_at: Some(now),
            unavailable_reason: Some(reason.into()),
            write_receipt: None,
        };
        state.sessions.push(session.clone());
        session
    }

    pub fn heartbeat(
        &self,
        state: &mut WorkState,
        session_id: AgentSessionId,
    ) -> Option<AgentSession> {
        let session = state
            .sessions
            .iter_mut()
            .find(|session| session.agent_session_id == session_id)?;
        session.last_heartbeat_at = OffsetDateTime::now_utc();
        Some(session.clone())
    }

    pub fn stop(&self, state: &mut WorkState, session_id: AgentSessionId) -> Option<AgentSession> {
        let now = OffsetDateTime::now_utc();
        let session = state
            .sessions
            .iter_mut()
            .find(|session| session.agent_session_id == session_id)?;
        session.status = AgentSessionStatus::Stopped;
        session.stopped_at = Some(now);
        session.last_heartbeat_at = now;
        Some(session.clone())
    }
}

impl WorkQueueService {
    #[must_use]
    pub fn create_work_item(&self, state: &mut WorkState, request: WorkCreateRequest) -> WorkItem {
        let now = OffsetDateTime::now_utc();
        let item = WorkItem {
            work_item_id: WorkItemId::new_v7(),
            project_id: request.project_id,
            task_id: request.task_id,
            project: request.project,
            task: request.task,
            goal: request.goal,
            scope: request.scope,
            status: WorkItemStatus::Open,
            required: request.required,
            allowed_roles: vec![
                AgentRole::Controller,
                AgentRole::Implementer,
                AgentRole::Reviewer,
                AgentRole::Auditor,
                AgentRole::Verifier,
            ],
            required_verifiers: request.required_verifiers,
            verifier_run_refs: Vec::new(),
            candidate_review_refs: Vec::new(),
            created_by: request.created_by,
            active_lease_id: None,
            lease_refs: Vec::new(),
            conflict_refs: Vec::new(),
            created_at: now,
            updated_at: now,
            completed_at: None,
            write_receipt: None,
        };
        state.work_items.push(item.clone());
        item
    }

    pub fn complete_verified(
        &self,
        state: &mut WorkState,
        work_item_id: WorkItemId,
        verifier_runs: &[VerifierRun],
    ) -> Result<WorkItem, EngineError> {
        let item = state
            .work_items
            .iter()
            .find(|item| item.work_item_id == work_item_id)
            .cloned()
            .ok_or_else(|| EngineError::WriteRejected("work item not found".to_owned()))?;
        let mut verifier_run_refs = Vec::new();
        for requirement in item
            .required_verifiers
            .iter()
            .filter(|requirement| requirement.required_for_done)
        {
            let run = verifier_runs.iter().find(|run| {
                run.project_id == item.project_id
                    && run.task_id == item.task_id
                    && run.name == requirement.name
                    && run.command_kind == requirement.command_kind
                    && run.command_display == requirement.command_display
                    && run.required_for_done
                    && run.status == VerifierStatus::Passed
                    && run.write_receipt.is_some()
            });
            let Some(run) = run else {
                return Err(EngineError::WriteRejected(format!(
                    "required verifier evidence is missing or invalid: {}",
                    requirement.name
                )));
            };
            verifier_run_refs.push(VerifierRunRef {
                verifier_run_id: run.verifier_run_id,
                name: run.name.clone(),
                status: run.status,
            });
        }

        let latest_candidate = state
            .candidate_diffs
            .iter()
            .filter(|candidate| {
                candidate.work_item_id == work_item_id
                    && candidate.file_count > 0
                    && !candidate.changed_files.is_empty()
            })
            .max_by_key(|candidate| candidate.created_at);
        let mut candidate_review_refs = Vec::new();
        if let Some(candidate) = latest_candidate {
            if candidate.capture_status != CandidateDiffStatus::AcceptedForPatchRunner
                || candidate.write_receipt.is_none()
            {
                return Err(EngineError::WriteRejected(
                    "candidate code is not accepted for PatchRunner".to_owned(),
                ));
            }
            let review = state
                .candidate_reviews
                .iter()
                .filter(|review| review.candidate_diff_id == candidate.candidate_diff_id)
                .max_by_key(|review| review.created_at)
                .filter(|review| {
                    review.decision == CandidateReviewDecision::AcceptForPatchRunner
                        && review.write_receipt.is_some()
                })
                .ok_or_else(|| {
                    EngineError::WriteRejected(
                        "candidate code requires an accepted canonical CandidateReview".to_owned(),
                    )
                })?;
            candidate_review_refs.push(review.review_id.clone());
        }

        let now = OffsetDateTime::now_utc();
        let item = state
            .work_items
            .iter_mut()
            .find(|item| item.work_item_id == work_item_id)
            .ok_or_else(|| {
                EngineError::WriteRejected(
                    "work item disappeared before verified completion".to_owned(),
                )
            })?;
        item.status = WorkItemStatus::Completed;
        item.verifier_run_refs = verifier_run_refs;
        item.candidate_review_refs = candidate_review_refs;
        item.updated_at = now;
        item.completed_at = Some(now);
        Ok(item.clone())
    }

    #[must_use]
    pub fn status_report(&self, state: &WorkState, project: &str, task: &str) -> WorkStatusReport {
        let sessions = state
            .sessions
            .iter()
            .filter(|session| {
                state
                    .work_items
                    .iter()
                    .any(|item| item.project_id == session.project_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        let work_items = state
            .work_items
            .iter()
            .filter(|item| labels_match(item, project, task))
            .cloned()
            .collect::<Vec<_>>();
        let item_ids = work_items
            .iter()
            .map(|item| item.work_item_id)
            .collect::<BTreeSet<_>>();
        let active_leases = state
            .leases
            .iter()
            .filter(|lease| item_ids.contains(&lease.work_item_id) && work_lease_is_active(lease))
            .cloned()
            .collect::<Vec<_>>();
        let conflicts = state
            .conflicts
            .iter()
            .filter(|conflict| item_ids.contains(&conflict.work_item_id))
            .cloned()
            .collect::<Vec<_>>();
        let operation_status = if work_items.is_empty() {
            OperationStatus::OperationCompleted
        } else if work_items.iter().any(|item| {
            matches!(
                item.status,
                WorkItemStatus::Blocked | WorkItemStatus::Revoked | WorkItemStatus::Expired
            )
        }) {
            OperationStatus::Blocked
        } else if work_items
            .iter()
            .all(|item| !item.required || item.status == WorkItemStatus::Completed)
        {
            OperationStatus::OperationCompleted
        } else {
            OperationStatus::Active
        };
        WorkStatusReport {
            component: "work".to_owned(),
            project: project.to_owned(),
            task: task.to_owned(),
            sessions,
            work_items,
            active_leases,
            conflicts,
            decisions: state.decisions.clone(),
            worktree_leases: state
                .worktree_leases
                .iter()
                .filter(|lease| item_ids.contains(&lease.work_item_id))
                .cloned()
                .collect(),
            candidate_diffs: state
                .candidate_diffs
                .iter()
                .filter(|diff| item_ids.contains(&diff.work_item_id))
                .cloned()
                .collect(),
            candidate_reviews: state
                .candidate_reviews
                .iter()
                .filter(|review| {
                    state.candidate_diffs.iter().any(|diff| {
                        item_ids.contains(&diff.work_item_id)
                            && diff.candidate_diff_id == review.candidate_diff_id
                    })
                })
                .cloned()
                .collect(),
            operation_status,
        }
    }
}

impl WorkLeaseService {
    #[must_use]
    pub fn claim(&self, state: &mut WorkState, request: WorkClaimRequest) -> WorkLeaseDecision {
        let now = OffsetDateTime::now_utc();
        let Some(session) = active_session_for_claim(state, request) else {
            return push_decision(state, denied_inactive_session("agent session is missing"));
        };
        if session.status != AgentSessionStatus::Active {
            return push_decision(
                state,
                denied_inactive_session("agent session is not active"),
            );
        }
        let Some(item) = work_item_for_claim(state, request) else {
            return push_decision(state, denied_unknown_work_item());
        };
        if item.status == WorkItemStatus::Completed {
            return push_decision(state, denied_completed_work_item());
        }
        if let Some(denial) = deny_missing_verifier(state, &item) {
            return push_decision(state, denial);
        }
        if let Some(denial) = deny_write_conflicts(state, &item, request.role) {
            return push_decision(state, denial);
        }
        grant_work_lease(state, request, session, item, now)
    }

    /// Claims work through the existing owner and, only for an exact accepted
    /// grant, emits the canonical `WorkLease` object with complete source
    /// provenance.
    ///
    /// The existing legacy grant remains the lifecycle/storage identity. This
    /// additive boundary deliberately performs no engine/store/application or
    /// coordination migration; it exists so a later consumer migration can
    /// accept canonical identity only from owner evidence rather than text.
    #[must_use]
    pub fn claim_with_issuance(
        &self,
        state: &mut WorkState,
        request: WorkClaimRequest,
    ) -> WorkLeaseIssuanceResult {
        let decision = self.claim(state, request);
        classify_work_lease_issuance(state, decision)
    }

    pub fn renew(
        &self,
        state: &mut WorkState,
        lease_id: WorkLeaseId,
        ttl_minutes: i64,
    ) -> WorkLeaseDecision {
        let now = OffsetDateTime::now_utc();
        let Some(lease_index) = state
            .leases
            .iter()
            .position(|lease| lease.work_lease_id == lease_id)
        else {
            return push_decision(
                state,
                decision(
                    WorkLeaseDecisionKind::Denied,
                    WorkLeaseDecisionReason::LeaseNotFound,
                    "work lease is missing",
                    Some(lease_id),
                    Vec::new(),
                    None,
                ),
            );
        };
        let lease = &mut state.leases[lease_index];
        if !work_lease_is_active(lease) {
            let reason = inactive_reason(lease);
            let expires_at = lease.expires_at;
            return push_decision(
                state,
                decision(
                    WorkLeaseDecisionKind::Denied,
                    reason,
                    "work lease is not active",
                    Some(lease_id),
                    Vec::new(),
                    Some(expires_at),
                ),
            );
        }
        let expires_at = now + Duration::minutes(ttl_minutes.max(1));
        lease.state = WorkLeaseState::Renewed;
        lease.renewed_at = Some(now);
        lease.expires_at = expires_at;
        let renewed = decision(
            WorkLeaseDecisionKind::Renewed,
            WorkLeaseDecisionReason::NoConflict,
            "work lease renewed",
            Some(lease_id),
            Vec::new(),
            Some(expires_at),
        );
        lease.decision = renewed.clone();
        push_decision(state, renewed)
    }

    pub fn release(&self, state: &mut WorkState, lease_id: WorkLeaseId) -> WorkLeaseDecision {
        Self::finish_lease(
            state,
            lease_id,
            WorkLeaseState::Released,
            WorkLeaseDecisionKind::Released,
            WorkLeaseDecisionReason::ReleasedLease,
            "work lease released",
        )
    }

    pub fn revoke(&self, state: &mut WorkState, lease_id: WorkLeaseId) -> WorkLeaseDecision {
        Self::finish_lease(
            state,
            lease_id,
            WorkLeaseState::Revoked,
            WorkLeaseDecisionKind::Revoked,
            WorkLeaseDecisionReason::RevokedLease,
            "work lease revoked",
        )
    }

    pub fn active_lease_for_item<'a>(
        &self,
        state: &'a WorkState,
        work_item_id: WorkItemId,
    ) -> Option<&'a WorkLease> {
        state
            .leases
            .iter()
            .find(|lease| lease.work_item_id == work_item_id && work_lease_is_active(lease))
    }

    fn finish_lease(
        state: &mut WorkState,
        lease_id: WorkLeaseId,
        next_state: WorkLeaseState,
        kind: WorkLeaseDecisionKind,
        reason: WorkLeaseDecisionReason,
        message: &'static str,
    ) -> WorkLeaseDecision {
        let now = OffsetDateTime::now_utc();
        let Some(lease) = state
            .leases
            .iter_mut()
            .find(|lease| lease.work_lease_id == lease_id)
        else {
            return push_decision(
                state,
                decision(
                    WorkLeaseDecisionKind::Denied,
                    WorkLeaseDecisionReason::LeaseNotFound,
                    "work lease is missing",
                    Some(lease_id),
                    Vec::new(),
                    None,
                ),
            );
        };
        lease.state = next_state;
        match next_state {
            WorkLeaseState::Released => lease.released_at = Some(now),
            WorkLeaseState::Revoked => lease.revoked_at = Some(now),
            WorkLeaseState::Granted
            | WorkLeaseState::Renewed
            | WorkLeaseState::Expired
            | WorkLeaseState::Denied => {}
        }
        let work_item_id = lease.work_item_id;
        let result = decision(
            kind,
            reason,
            message,
            Some(lease_id),
            Vec::new(),
            Some(lease.expires_at),
        );
        lease.decision = result.clone();
        if let Some(item) = state
            .work_items
            .iter_mut()
            .find(|item| item.work_item_id == work_item_id)
        {
            item.active_lease_id = None;
            item.updated_at = now;
            if item.status != WorkItemStatus::Completed {
                item.status = WorkItemStatus::Open;
            }
        }
        push_decision(state, result)
    }
}

fn active_session_for_claim(state: &WorkState, request: WorkClaimRequest) -> Option<ClaimSession> {
    state
        .sessions
        .iter()
        .find(|session| session.agent_session_id == request.agent_session_id)
        .map(|session| ClaimSession {
            agent_session_id: session.agent_session_id,
            agent_id: session.agent_id,
            status: session.status,
        })
}

fn work_item_for_claim(state: &WorkState, request: WorkClaimRequest) -> Option<WorkItem> {
    state
        .work_items
        .iter()
        .find(|item| item.work_item_id == request.work_item_id)
        .cloned()
}

fn denied_inactive_session(message: &'static str) -> WorkLeaseDecision {
    decision(
        WorkLeaseDecisionKind::Denied,
        WorkLeaseDecisionReason::InactiveSession,
        message,
        None,
        Vec::new(),
        None,
    )
}

fn denied_unknown_work_item() -> WorkLeaseDecision {
    decision(
        WorkLeaseDecisionKind::Denied,
        WorkLeaseDecisionReason::UnknownWorkItem,
        "work item is missing",
        None,
        Vec::new(),
        None,
    )
}

fn denied_completed_work_item() -> WorkLeaseDecision {
    decision(
        WorkLeaseDecisionKind::Denied,
        WorkLeaseDecisionReason::AlreadyCompleted,
        "work item is already completed",
        None,
        Vec::new(),
        None,
    )
}

fn deny_missing_verifier(state: &mut WorkState, item: &WorkItem) -> Option<WorkLeaseDecision> {
    if !item.scope.authority.allows_write() || !item.required_verifiers.is_empty() {
        return None;
    }
    let conflict = conflict(
        item.work_item_id,
        WorkLeaseId::new_v7(),
        None,
        WorkConflictKind::MissingVerifier,
        item.scope.write_set.clone(),
        "mutating work item has no required verifier",
    );
    state.conflicts.push(conflict.clone());
    mark_item_blocked(state, item.work_item_id, &conflict.conflict_id);
    Some(decision(
        WorkLeaseDecisionKind::Denied,
        WorkLeaseDecisionReason::MissingVerifier,
        "mutating work item requires verifier evidence",
        None,
        Vec::new(),
        None,
    ))
}

fn deny_write_conflicts(
    state: &mut WorkState,
    item: &WorkItem,
    role: AgentRole,
) -> Option<WorkLeaseDecision> {
    let conflicts = WorkConflictService::active_write_conflicts(state, item, role);
    if conflicts.is_empty() {
        return None;
    }
    for conflict in &conflicts {
        state.conflicts.push(conflict.clone());
        mark_item_blocked(state, item.work_item_id, &conflict.conflict_id);
    }
    let conflicting_lease_ids = conflicts
        .iter()
        .filter_map(|conflict| conflict.conflicting_work_lease_id)
        .collect();
    Some(decision(
        WorkLeaseDecisionKind::Denied,
        WorkLeaseDecisionReason::OverlappingWriteScope,
        "overlapping active write scope",
        None,
        conflicting_lease_ids,
        None,
    ))
}

fn grant_work_lease(
    state: &mut WorkState,
    request: WorkClaimRequest,
    session: ClaimSession,
    item: WorkItem,
    now: OffsetDateTime,
) -> WorkLeaseDecision {
    let lease_id = WorkLeaseId::new_v7();
    let expires_at = now + Duration::minutes(request.ttl_minutes.max(1));
    let grant = decision(
        WorkLeaseDecisionKind::Granted,
        grant_reason(&item, request.role),
        "work lease granted",
        Some(lease_id),
        Vec::new(),
        Some(expires_at),
    );
    state.leases.push(WorkLease {
        work_lease_id: lease_id,
        work_item_id: item.work_item_id,
        agent_session_id: session.agent_session_id,
        agent_id: session.agent_id,
        project_id: item.project_id,
        task_id: item.task_id,
        role: request.role,
        state: WorkLeaseState::Granted,
        epoch: 0,
        scope: item.scope,
        decision: grant.clone(),
        conflict_refs: Vec::new(),
        granted_at: now,
        expires_at,
        renewed_at: None,
        released_at: None,
        revoked_at: None,
        write_receipt: None,
    });
    mark_claim_active(state, request, lease_id, now);
    push_decision(state, grant)
}

fn grant_reason(item: &WorkItem, role: AgentRole) -> WorkLeaseDecisionReason {
    if item.scope.write_set.is_empty() && role == AgentRole::Auditor {
        WorkLeaseDecisionReason::ReadOnlyOverlapAllowed
    } else {
        WorkLeaseDecisionReason::NoConflict
    }
}

#[derive(Serialize)]
struct WorkLeaseIssuanceEvidence<'a> {
    revision: &'static str,
    source_lease: &'a WorkLease,
    source_work_item: &'a WorkItem,
    source_session: &'a AgentSession,
    source_decision: &'a WorkLeaseDecision,
}

fn classify_work_lease_issuance(
    state: &WorkState,
    decision: WorkLeaseDecision,
) -> WorkLeaseIssuanceResult {
    if decision.kind != WorkLeaseDecisionKind::Granted {
        return WorkLeaseIssuanceResult {
            decision,
            issuance: WorkLeaseIssuanceState::NotGranted,
        };
    }
    match work_lease_issuance_from_owner_state(state, &decision) {
        Ok(provenance) => WorkLeaseIssuanceResult {
            decision,
            issuance: WorkLeaseIssuanceState::OwnerIssued(Box::new(provenance)),
        },
        Err(error) => WorkLeaseIssuanceResult {
            decision,
            issuance: WorkLeaseIssuanceState::LegacyQuarantined(error),
        },
    }
}

fn work_lease_issuance_from_owner_state(
    state: &WorkState,
    decision: &WorkLeaseDecision,
) -> Result<WorkLeaseIssuanceProvenance, WorkLeaseIssuanceError> {
    let source_work_lease_id = decision
        .work_lease_id
        .ok_or(WorkLeaseIssuanceError::MissingSourceIdentity)?;
    let source_lease = exact_owner_record(&state.leases, |lease| {
        lease.work_lease_id == source_work_lease_id
    })?;
    let source_work_item = exact_owner_record(&state.work_items, |item| {
        item.work_item_id == source_lease.work_item_id
    })?;
    let source_session = exact_owner_record(&state.sessions, |session| {
        session.agent_session_id == source_lease.agent_session_id
    })?;
    let decision_matches = canonical_evidence_equal(&source_lease.decision, decision)?;
    let scope_matches = canonical_evidence_equal(&source_lease.scope, &source_work_item.scope)?;
    let source_lease_ref_count = source_work_item
        .lease_refs
        .iter()
        .filter(|lease_id| **lease_id == source_work_lease_id)
        .count();
    if source_lease.state != WorkLeaseState::Granted
        || source_lease.work_lease_id != source_work_lease_id
        || !decision_matches
        || decision.expires_at != Some(source_lease.expires_at)
        || source_lease.granted_at >= source_lease.expires_at
        || source_work_item.status != WorkItemStatus::Active
        || source_work_item.active_lease_id != Some(source_work_lease_id)
        || source_lease_ref_count != 1
        || !scope_matches
        || !source_work_item.allowed_roles.contains(&source_lease.role)
        || source_work_item.project_id != source_lease.project_id
        || source_work_item.task_id != source_lease.task_id
        || source_session.status != AgentSessionStatus::Active
        || source_session.current_work_item_id != Some(source_lease.work_item_id)
        || source_session.project_id != source_lease.project_id
        || source_session.agent_id != source_lease.agent_id
        || source_session.role != source_lease.role
    {
        return Err(WorkLeaseIssuanceError::InconsistentOwnerEvidence);
    }
    let evidence = WorkLeaseIssuanceEvidence {
        revision: "eliot.engine.work-lease-issuance.v1",
        source_lease,
        source_work_item,
        source_session,
        source_decision: decision,
    };
    let evidence_bytes = canonical_json_bytes(&evidence)
        .map_err(|_| WorkLeaseIssuanceError::EvidenceEncodingRejected)?;
    let evidence_commitment_sha256 = sha256_hex(&evidence_bytes);
    let canonical_work_lease_id = serde_json::from_value(serde_json::json!({
        "namespace": WORK_LEASE_NAMESPACE,
        "revision": WORK_LEASE_WIRE_REVISION,
        "value": evidence_commitment_sha256,
    }))
    .map_err(|_| WorkLeaseIssuanceError::CanonicalContractRejected)?;
    Ok(WorkLeaseIssuanceProvenance {
        canonical_work_lease_id,
        source_lease: source_lease.clone(),
        source_work_item: source_work_item.clone(),
        source_session: source_session.clone(),
        evidence_commitment_sha256,
    })
}

fn exact_owner_record<T>(
    records: &[T],
    mut matches: impl FnMut(&T) -> bool,
) -> Result<&T, WorkLeaseIssuanceError> {
    let mut matching = records.iter().filter(|record| matches(record));
    let record = matching
        .next()
        .ok_or(WorkLeaseIssuanceError::MissingOwnerEvidence)?;
    if matching.next().is_some() {
        return Err(WorkLeaseIssuanceError::AmbiguousOwnerEvidence);
    }
    Ok(record)
}

fn canonical_evidence_equal<T: Serialize>(
    left: &T,
    right: &T,
) -> Result<bool, WorkLeaseIssuanceError> {
    let left =
        canonical_json_bytes(left).map_err(|_| WorkLeaseIssuanceError::EvidenceEncodingRejected)?;
    let right = canonical_json_bytes(right)
        .map_err(|_| WorkLeaseIssuanceError::EvidenceEncodingRejected)?;
    Ok(left == right)
}

fn mark_claim_active(
    state: &mut WorkState,
    request: WorkClaimRequest,
    lease_id: WorkLeaseId,
    now: OffsetDateTime,
) {
    if let Some(item) = state
        .work_items
        .iter_mut()
        .find(|item| item.work_item_id == request.work_item_id)
    {
        item.status = WorkItemStatus::Active;
        item.active_lease_id = Some(lease_id);
        item.lease_refs.push(lease_id);
        item.updated_at = now;
    }
    if let Some(session) = state
        .sessions
        .iter_mut()
        .find(|session| session.agent_session_id == request.agent_session_id)
    {
        session.current_work_item_id = Some(request.work_item_id);
        session.last_heartbeat_at = now;
    }
}

impl WorkConflictService {
    #[must_use]
    pub fn active_write_conflicts(
        state: &WorkState,
        item: &WorkItem,
        role: AgentRole,
    ) -> Vec<WorkConflict> {
        if item.scope.write_set.is_empty() && role == AgentRole::Auditor {
            return Vec::new();
        }
        state
            .leases
            .iter()
            .filter(|lease| work_lease_is_active(lease))
            .filter(|lease| lease.project_id == item.project_id)
            .filter(|lease| !lease.scope.write_set.is_empty() || !item.scope.write_set.is_empty())
            .filter_map(|lease| {
                let paths = overlapping_paths(&lease.scope.write_set, &item.scope.write_set);
                (!paths.is_empty()).then(|| {
                    conflict(
                        item.work_item_id,
                        WorkLeaseId::new_v7(),
                        Some(lease.work_lease_id),
                        WorkConflictKind::OverlappingWriteScope,
                        paths,
                        "active work lease overlaps requested write scope",
                    )
                })
            })
            .collect()
    }
}

impl WorkMemoryWriter {
    pub async fn write_session(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        session: &mut AgentSession,
    ) -> Result<(), EngineError> {
        let receipt = write_work_payload(
            writer,
            admission,
            WorkPayloadInput {
                project_id: session.project_id,
                task_id: None,
                agent_id: session.agent_id,
                scope: "agent-session",
                observation: format!(
                    "AgentSession {} status {:?}",
                    session.agent_session_id, session.status
                ),
                payload: serde_json::json!({ "agent_session": session }),
            },
        )
        .await?;
        session.write_receipt = Some(receipt);
        Ok(())
    }

    pub async fn write_work_item(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        item: &mut WorkItem,
    ) -> Result<(), EngineError> {
        let receipt = write_work_payload(
            writer,
            admission,
            WorkPayloadInput {
                project_id: item.project_id,
                task_id: Some(item.task_id),
                agent_id: AgentId::from_uuid(item.created_by.as_uuid()),
                scope: "work-item",
                observation: format!("WorkItem {} status {:?}", item.work_item_id, item.status),
                payload: serde_json::json!({ "work_item": item }),
            },
        )
        .await?;
        item.write_receipt = Some(receipt);
        Ok(())
    }

    pub async fn write_work_lease(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        lease: &mut WorkLease,
    ) -> Result<(), EngineError> {
        let receipt = write_work_payload(
            writer,
            admission,
            WorkPayloadInput {
                project_id: lease.project_id,
                task_id: Some(lease.task_id),
                agent_id: lease.agent_id,
                scope: "work-lease",
                observation: format!("WorkLease {} state {:?}", lease.work_lease_id, lease.state),
                payload: serde_json::json!({ "work_lease": lease }),
            },
        )
        .await?;
        lease.write_receipt = Some(receipt);
        Ok(())
    }

    pub async fn write_conflict(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        project_id: ProjectId,
        task_id: TaskId,
        agent_id: AgentId,
        conflict: &WorkConflict,
    ) -> Result<WriteReceiptRef, EngineError> {
        write_work_payload(
            writer,
            admission,
            WorkPayloadInput {
                project_id,
                task_id: Some(task_id),
                agent_id,
                scope: "work-conflict",
                observation: format!(
                    "WorkConflict {} kind {:?}",
                    conflict.conflict_id, conflict.kind
                ),
                payload: serde_json::json!({ "work_conflict": conflict }),
            },
        )
        .await
    }

    pub async fn write_event(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        event: &WorkSessionEvent,
    ) -> Result<WriteReceiptRef, EngineError> {
        write_work_payload(
            writer,
            admission,
            WorkPayloadInput {
                project_id: event.project_id,
                task_id: None,
                agent_id: event.agent_id,
                scope: "agent-session-event",
                observation: event.summary.clone(),
                payload: serde_json::json!({ "agent_session_event": event }),
            },
        )
        .await
    }
}

#[must_use]
pub fn default_work_scope(
    repo_root: impl Into<String>,
    read_set: Vec<String>,
    write_set: Vec<String>,
    verifier_set: Vec<String>,
) -> WorkScope {
    let authority = if write_set.is_empty() {
        AuthorityProfile::read_only()
    } else {
        AuthorityProfile::bounded_write()
    };
    WorkScope {
        repo_root: repo_root.into(),
        read_set,
        write_set,
        verifier_set,
        authority,
        risk_tier: RiskTier::Low,
        max_files: 12,
        requires_active_work_lease: true,
    }
}

#[must_use]
pub fn work_lease_is_active(lease: &WorkLease) -> bool {
    matches!(
        lease.state,
        WorkLeaseState::Granted | WorkLeaseState::Renewed
    ) && lease.expires_at > OffsetDateTime::now_utc()
}

pub fn guard_work_lease_for_files(
    work_lease: Option<&WorkLease>,
    project_id: ProjectId,
    task_id: TaskId,
    agent_id: AgentId,
    files: &[String],
) -> Result<(), WorkLeaseGuardError> {
    let Some(lease) = work_lease else {
        return Err(WorkLeaseGuardError::Missing);
    };
    if !work_lease_is_active(lease) {
        return Err(WorkLeaseGuardError::Inactive);
    }
    if lease.project_id != project_id || lease.task_id != task_id || lease.agent_id != agent_id {
        return Err(WorkLeaseGuardError::Mismatch);
    }
    if files
        .iter()
        .any(|file| !path_in_scope(file, &lease.scope.write_set))
    {
        return Err(WorkLeaseGuardError::FileOutsideScope);
    }
    Ok(())
}

#[must_use]
pub fn path_in_scope(path: &str, scope_paths: &[String]) -> bool {
    let path = normalize_path(path);
    scope_paths.iter().any(|scope_path| {
        let scope_path = normalize_path(scope_path);
        path == scope_path || path.starts_with(&format!("{scope_path}/"))
    })
}

#[must_use]
pub fn work_completion_satisfied(item: Option<&WorkItem>, lease: Option<&WorkLease>) -> bool {
    let Some(item) = item else {
        return false;
    };
    let Some(lease) = lease else {
        return false;
    };
    item.status == WorkItemStatus::Completed
        && !matches!(
            lease.state,
            WorkLeaseState::Revoked | WorkLeaseState::Expired | WorkLeaseState::Denied
        )
}

struct WorkPayloadInput {
    project_id: ProjectId,
    task_id: Option<TaskId>,
    agent_id: AgentId,
    scope: &'static str,
    observation: String,
    payload: serde_json::Value,
}

async fn write_work_payload(
    writer: &WriterHandle,
    admission: &WriteAdmissionService,
    input: WorkPayloadInput,
) -> Result<WriteReceiptRef, EngineError> {
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: input.agent_id,
            session_id: None,
            project_id: input.project_id,
            task_id: input.task_id,
            scope: format!("work/{}", input.scope),
            authority: "eliot-work-coordination-service".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: "eliot_work_coordination".to_owned(),
        observation: input.observation,
        payload: input.payload,
    });
    let receipt = writer.submit(admission.admit(&command)?).await?;
    Ok(WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    })
}

fn labels_match(item: &WorkItem, project: &str, task: &str) -> bool {
    (project.is_empty() || item.project == project) && (task.is_empty() || item.task == task)
}

fn decision(
    kind: WorkLeaseDecisionKind,
    reason: WorkLeaseDecisionReason,
    message: impl Into<String>,
    work_lease_id: Option<WorkLeaseId>,
    conflicting_lease_ids: Vec<WorkLeaseId>,
    expires_at: Option<OffsetDateTime>,
) -> WorkLeaseDecision {
    WorkLeaseDecision {
        kind,
        reason,
        message: message.into(),
        work_lease_id,
        conflicting_lease_ids,
        expires_at,
    }
}

fn push_decision(state: &mut WorkState, decision: WorkLeaseDecision) -> WorkLeaseDecision {
    state.decisions.push(decision.clone());
    decision
}

fn conflict(
    work_item_id: WorkItemId,
    work_lease_id: WorkLeaseId,
    conflicting_work_lease_id: Option<WorkLeaseId>,
    kind: WorkConflictKind,
    paths: Vec<String>,
    detail: impl Into<String>,
) -> WorkConflict {
    let raw = format!(
        "{}:{}:{}:{kind:?}",
        work_item_id,
        work_lease_id,
        conflicting_work_lease_id.map_or_else(String::new, |id| id.to_string())
    );
    let conflict_id = blake3::hash(raw.as_bytes())
        .to_hex()
        .chars()
        .take(24)
        .collect::<String>();
    WorkConflict {
        conflict_id,
        work_item_id,
        work_lease_id,
        conflicting_work_lease_id,
        kind,
        paths,
        resolution: Some(WorkConflictResolution::Denied),
        detail: detail.into(),
        detected_at: OffsetDateTime::now_utc(),
    }
}

fn mark_item_blocked(state: &mut WorkState, work_item_id: WorkItemId, conflict_id: &str) {
    if let Some(item) = state
        .work_items
        .iter_mut()
        .find(|item| item.work_item_id == work_item_id)
    {
        item.status = WorkItemStatus::Blocked;
        item.conflict_refs.push(conflict_id.to_owned());
        item.updated_at = OffsetDateTime::now_utc();
    }
}

fn inactive_reason(lease: &WorkLease) -> WorkLeaseDecisionReason {
    match lease.state {
        WorkLeaseState::Revoked => WorkLeaseDecisionReason::RevokedLease,
        WorkLeaseState::Released => WorkLeaseDecisionReason::ReleasedLease,
        WorkLeaseState::Denied => WorkLeaseDecisionReason::LeaseNotFound,
        WorkLeaseState::Expired | WorkLeaseState::Granted | WorkLeaseState::Renewed
            if lease.expires_at <= OffsetDateTime::now_utc() =>
        {
            WorkLeaseDecisionReason::ExpiredLease
        }
        WorkLeaseState::Granted | WorkLeaseState::Renewed => WorkLeaseDecisionReason::NoConflict,
        WorkLeaseState::Expired => WorkLeaseDecisionReason::ExpiredLease,
    }
}

fn overlapping_paths(left: &[String], right: &[String]) -> Vec<String> {
    let mut paths = BTreeSet::new();
    for left in left {
        for right in right {
            let left = normalize_path(left);
            let right = normalize_path(right);
            if left == right
                || left.starts_with(&format!("{right}/"))
                || right.starts_with(&format!("{left}/"))
            {
                paths.insert(if left.len() >= right.len() {
                    left
                } else {
                    right
                });
            }
        }
    }
    paths.into_iter().collect()
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("./")
        .trim_matches('/')
        .to_ascii_lowercase()
}

#[must_use]
pub fn default_lease_ttl_minutes() -> i64 {
    DEFAULT_LEASE_TTL_MINUTES
}

#[cfg(test)]
mod issuance_tests {
    use super::*;

    fn owner_issued_state() -> (WorkState, WorkLeaseDecision) {
        let mut state = WorkState::default();
        let project_id = ProjectId::new_v7();
        let session =
            AgentSessionService.create_for_role(&mut state, project_id, AgentRole::Implementer);
        let mut scope = default_work_scope(
            "C:/repo",
            vec!["src/lib.rs".to_owned()],
            Vec::new(),
            vec!["cargo check".to_owned()],
        );
        scope.authority = AuthorityProfile::read_only();
        let item = WorkQueueService.create_work_item(
            &mut state,
            WorkCreateRequest {
                project_id,
                task_id: TaskId::new_v7(),
                project: "issuance-test".to_owned(),
                task: "owner evidence".to_owned(),
                goal: "prove exact owner evidence".to_owned(),
                scope,
                required: true,
                created_by: session.agent_session_id,
                required_verifiers: Vec::new(),
            },
        );
        let result = WorkLeaseService.claim_with_issuance(
            &mut state,
            WorkClaimRequest {
                work_item_id: item.work_item_id,
                agent_session_id: session.agent_session_id,
                role: AgentRole::Implementer,
                ttl_minutes: default_lease_ttl_minutes(),
            },
        );
        assert_eq!(
            result.disposition(),
            WorkLeaseIssuanceDisposition::OwnerIssued
        );
        (state, result.decision().clone())
    }

    fn assert_quarantined(
        state: &WorkState,
        decision: &WorkLeaseDecision,
        expected: WorkLeaseIssuanceError,
    ) {
        let result = classify_work_lease_issuance(state, decision.clone());
        assert_eq!(
            result.disposition(),
            WorkLeaseIssuanceDisposition::LegacyQuarantined
        );
        assert_eq!(result.error(), Some(expected));
        assert!(result.provenance().is_none());
    }

    #[test]
    fn granted_decision_without_exact_owner_evidence_is_loss_visible_quarantine() {
        let now = OffsetDateTime::now_utc();
        let source_work_lease_id = WorkLeaseId::new_v7();
        let missing_state = classify_work_lease_issuance(
            &WorkState::default(),
            decision(
                WorkLeaseDecisionKind::Granted,
                WorkLeaseDecisionReason::NoConflict,
                "fabricated grant without owner state",
                Some(source_work_lease_id),
                Vec::new(),
                Some(now + Duration::minutes(1)),
            ),
        );
        assert_eq!(
            missing_state.disposition(),
            WorkLeaseIssuanceDisposition::LegacyQuarantined
        );
        assert_eq!(
            missing_state.error(),
            Some(WorkLeaseIssuanceError::MissingOwnerEvidence)
        );
        assert!(missing_state.provenance().is_none());

        let missing_identity = classify_work_lease_issuance(
            &WorkState::default(),
            decision(
                WorkLeaseDecisionKind::Granted,
                WorkLeaseDecisionReason::NoConflict,
                "fabricated grant without source identity",
                None,
                Vec::new(),
                Some(now + Duration::minutes(1)),
            ),
        );
        assert_eq!(
            missing_identity.error(),
            Some(WorkLeaseIssuanceError::MissingSourceIdentity)
        );
        assert!(missing_identity.provenance().is_none());
    }

    #[test]
    fn duplicate_owner_records_are_loss_visible_ambiguity() {
        let (state, decision) = owner_issued_state();

        let mut duplicate_lease = state.clone();
        duplicate_lease.leases.push(state.leases[0].clone());
        assert_quarantined(
            &duplicate_lease,
            &decision,
            WorkLeaseIssuanceError::AmbiguousOwnerEvidence,
        );

        let mut duplicate_item = state.clone();
        duplicate_item.work_items.push(state.work_items[0].clone());
        assert_quarantined(
            &duplicate_item,
            &decision,
            WorkLeaseIssuanceError::AmbiguousOwnerEvidence,
        );

        let mut duplicate_session = state.clone();
        duplicate_session.sessions.push(state.sessions[0].clone());
        assert_quarantined(
            &duplicate_session,
            &decision,
            WorkLeaseIssuanceError::AmbiguousOwnerEvidence,
        );
    }

    #[test]
    fn inconsistent_owner_cross_links_are_loss_visible_quarantine() {
        let (state, decision) = owner_issued_state();

        let mut altered_decision = state.clone();
        altered_decision.leases[0].decision.message = "substituted decision".to_owned();
        assert_quarantined(
            &altered_decision,
            &decision,
            WorkLeaseIssuanceError::InconsistentOwnerEvidence,
        );

        let mut altered_scope = state.clone();
        altered_scope.leases[0].scope.max_files += 1;
        assert_quarantined(
            &altered_scope,
            &decision,
            WorkLeaseIssuanceError::InconsistentOwnerEvidence,
        );

        let mut altered_role = state.clone();
        altered_role.work_items[0].allowed_roles.clear();
        assert_quarantined(
            &altered_role,
            &decision,
            WorkLeaseIssuanceError::InconsistentOwnerEvidence,
        );

        let mut missing_history = state;
        missing_history.work_items[0].lease_refs.clear();
        assert_quarantined(
            &missing_history,
            &decision,
            WorkLeaseIssuanceError::InconsistentOwnerEvidence,
        );
    }

    #[test]
    fn legacy_source_identity_is_attributed_input_not_canonical_text()
    -> Result<(), WorkLeaseIssuanceError> {
        let (state, decision) = owner_issued_state();
        let original = work_lease_issuance_from_owner_state(&state, &decision)?;

        let mut rebound_state = state;
        let mut rebound_decision = decision;
        let rebound_source_id = WorkLeaseId::new_v7();
        rebound_state.leases[0].work_lease_id = rebound_source_id;
        rebound_state.leases[0].decision.work_lease_id = Some(rebound_source_id);
        rebound_state.work_items[0].active_lease_id = Some(rebound_source_id);
        rebound_state.work_items[0].lease_refs[0] = rebound_source_id;
        rebound_decision.work_lease_id = Some(rebound_source_id);
        let rebound = work_lease_issuance_from_owner_state(&rebound_state, &rebound_decision)?;

        assert_ne!(
            original.canonical_work_lease_id,
            rebound.canonical_work_lease_id
        );
        assert_ne!(
            original.evidence_commitment_sha256,
            rebound.evidence_commitment_sha256
        );
        assert_ne!(
            rebound.evidence_commitment_sha256,
            rebound_source_id.to_string()
        );
        Ok(())
    }
}
