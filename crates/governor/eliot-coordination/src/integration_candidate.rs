use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ClockReading, EpochId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    CoordinationError, CoordinationEvent, CoordinationEventKind, CoordinationOwner,
    IntegrationLease, IntegrationLeaseDecision, IntegrationLeaseRequest,
};

/// Lifecycle of one immutable integration candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationCandidateStatus {
    Proposed,
    Ready,
    Stale,
    Integrating,
    Accepted,
    Rejected,
    Conflicted,
    UnknownOutcome,
}

/// Candidate state at one canonical coordination event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCandidateRevision {
    pub event_sequence: u64,
    pub status: IntegrationCandidateStatus,
    pub lease_id: Option<String>,
    pub observed_at: u64,
    pub evidence_refs: Vec<String>,
    pub unresolved_conflicts: Vec<String>,
    pub unknowns: Vec<String>,
}

/// The canonical candidate record stored in the coordination owner snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCandidate {
    pub candidate_id: String,
    pub task_id: String,
    pub source_work_item_id: String,
    pub producer_attempt: String,
    pub producer_lineage: Vec<String>,
    pub base_commit: String,
    pub state_fence: StateFence,
    pub worktree_or_artifact_refs: Vec<String>,
    pub diff_ref: String,
    pub changed_paths: BTreeSet<String>,
    pub declared_read_effects: BTreeSet<String>,
    pub declared_write_effects: BTreeSet<String>,
    pub evidence_refs: Vec<String>,
    pub verification_refs: Vec<String>,
    pub unresolved_conflicts: Vec<String>,
    pub unknowns: Vec<String>,
    pub rollback_or_compensation: Option<String>,
    pub target_scope: String,
    pub submitted_at: u64,
    pub status: IntegrationCandidateStatus,
    pub history: Vec<IntegrationCandidateRevision>,
}

/// Exact candidate submission request. `request_id` is the retry identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCandidateDraft {
    pub request_id: String,
    pub candidate_id: String,
    pub task_id: String,
    pub source_work_item_id: String,
    pub producer_attempt: String,
    pub producer_lineage: Vec<String>,
    pub session_id: String,
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
    pub base_commit: String,
    pub worktree_or_artifact_refs: Vec<String>,
    pub diff_ref: String,
    pub changed_paths: BTreeSet<String>,
    pub declared_read_effects: BTreeSet<String>,
    pub declared_write_effects: BTreeSet<String>,
    pub evidence_refs: Vec<String>,
    pub verification_refs: Vec<String>,
    pub unresolved_conflicts: Vec<String>,
    pub unknowns: Vec<String>,
    pub rollback_or_compensation: Option<String>,
    pub target_scope: String,
    pub now: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCandidateReceipt {
    pub candidate_id: String,
    pub target_scope: String,
    pub candidate: IntegrationCandidate,
    pub event: CoordinationEvent,
}

/// Read-only queue projection over canonical candidates and active target leases.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationQueue {
    pub candidates: Vec<IntegrationCandidate>,
    pub active_leases: Vec<IntegrationLease>,
}

/// Marks one candidate stale after its declared base has changed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaleIntegrationCandidateRequest {
    pub request_id: String,
    pub candidate_id: String,
    pub changed_from_base_commit: String,
    pub current_base_commit: String,
    pub target_scope: String,
    pub lease_id: String,
    pub session_id: String,
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
    pub now: u64,
}

struct StagedIntegrationClaim {
    lease: IntegrationLease,
    candidate: IntegrationCandidate,
    event: CoordinationEvent,
}

impl CoordinationOwner {
    /// Returns a queue view derived from stored candidates and current leases.
    pub fn integration_queue(&self, now: u64) -> IntegrationQueue {
        IntegrationQueue {
            candidates: self.integration_candidates.values().cloned().collect(),
            active_leases: self
                .integrations
                .values()
                .filter(|lease| {
                    lease.expires_at >= now
                        && self
                            .sessions
                            .get(&lease.holder_session_id)
                            .is_some_and(|session| {
                                session.state == crate::SessionState::Active
                                    && session.heartbeat_deadline >= now
                                    && session.state_fence == lease.state_fence
                                    && session
                                        .authority_epoch
                                        .is_same_authority(&lease.authority_epoch)
                            })
                })
                .cloned()
                .collect(),
        }
    }

    /// Reads the canonical candidate by identity.
    pub fn integration_candidate(&self, candidate_id: &str) -> Option<&IntegrationCandidate> {
        self.integration_candidates.get(candidate_id)
    }

    /// Appends a stale transition only when this candidate depends on the changed base.
    pub fn mark_integration_candidate_stale(
        &mut self,
        req: StaleIntegrationCandidateRequest,
    ) -> Result<IntegrationCandidateReceipt, CoordinationError> {
        mark_integration_candidate_stale(self, req)
    }
}

pub(crate) fn mark_integration_candidate_stale(
    owner: &mut CoordinationOwner,
    req: StaleIntegrationCandidateRequest,
) -> Result<IntegrationCandidateReceipt, CoordinationError> {
    validate_stale_candidate_request(owner, &req)?;
    if let Some(receipt) = exact_stale_candidate_replay(owner, &req)? {
        return Ok(receipt);
    }
    let (candidate, event) = stage_stale_candidate(owner, &req)?;
    let event = owner.commit(&req.request_id, event)?;
    owner
        .integration_candidates
        .insert(req.candidate_id, candidate.clone());
    Ok(IntegrationCandidateReceipt {
        candidate_id: candidate.candidate_id.clone(),
        target_scope: candidate.target_scope.clone(),
        candidate,
        event,
    })
}

fn validate_stale_candidate_request(
    owner: &CoordinationOwner,
    req: &StaleIntegrationCandidateRequest,
) -> Result<(), CoordinationError> {
    owner.request(&req.request_id)?;
    for (value, field) in [
        (&req.candidate_id, "candidate_id"),
        (&req.changed_from_base_commit, "changed_from_base_commit"),
        (&req.current_base_commit, "current_base_commit"),
        (&req.target_scope, "target_scope"),
        (&req.lease_id, "lease_id"),
        (&req.session_id, "session_id"),
    ] {
        crate::text(value, field)?;
    }
    owner.common(req.authority_epoch.clone(), &req.state_fence)?;
    crate::nonzero(req.now, "now")
}

fn exact_stale_candidate_replay(
    owner: &CoordinationOwner,
    req: &StaleIntegrationCandidateRequest,
) -> Result<Option<IntegrationCandidateReceipt>, CoordinationError> {
    let Some(event) = owner.event_by_request.get(&req.request_id) else {
        return Ok(None);
    };
    let Some(candidate) = owner.integration_candidates.get(&req.candidate_id) else {
        return Err(CoordinationError::InvalidState);
    };
    let exact_event = event.kind == CoordinationEventKind::IntegrationCandidateStaled
        && event.event_id == format!("candidate-stale:{}", req.candidate_id)
        && event.idempotency_key == req.request_id
        && event.subject_id == req.candidate_id
        && event.actor_id == req.session_id
        && event.payload_digest == req.current_base_commit
        && event.state_fence == req.state_fence
        && event.authority_epoch == req.authority_epoch;
    let exact_candidate = candidate.base_commit == req.changed_from_base_commit
        && candidate.base_commit != req.current_base_commit
        && candidate.target_scope == req.target_scope
        && candidate.status == IntegrationCandidateStatus::Stale
        && candidate.history.iter().any(|revision| {
            revision.event_sequence == event.sequence
                && revision.status == IntegrationCandidateStatus::Stale
                && revision.lease_id.as_deref() == Some(req.lease_id.as_str())
                && revision.observed_at == req.now
        });
    if !(exact_event && exact_candidate) {
        return Err(CoordinationError::IdempotencyConflict(
            req.request_id.clone(),
        ));
    }
    Ok(Some(IntegrationCandidateReceipt {
        candidate_id: candidate.candidate_id.clone(),
        target_scope: candidate.target_scope.clone(),
        candidate: candidate.clone(),
        event: event.clone(),
    }))
}

fn stage_stale_candidate(
    owner: &CoordinationOwner,
    req: &StaleIntegrationCandidateRequest,
) -> Result<(IntegrationCandidate, CoordinationEvent), CoordinationError> {
    let candidate = owner
        .integration_candidates
        .get(&req.candidate_id)
        .ok_or_else(|| CoordinationError::NotFound {
            kind: "integration_candidate",
            id: req.candidate_id.clone(),
        })?;
    if candidate.base_commit != req.changed_from_base_commit
        || candidate.base_commit == req.current_base_commit
        || candidate.target_scope != req.target_scope
    {
        return Err(CoordinationError::InvalidState);
    }
    if !matches!(
        candidate.status,
        IntegrationCandidateStatus::Proposed | IntegrationCandidateStatus::Ready
    ) {
        return Err(CoordinationError::IllegalTransition {
            from: format!("{:?}", candidate.status),
            to: "Stale".to_owned(),
        });
    }
    owner.validate_integration_lease(
        &req.target_scope,
        &req.lease_id,
        &req.session_id,
        req.now,
        &req.authority_epoch,
        &req.state_fence,
    )?;
    let event = owner.event(
        &req.request_id,
        format!("candidate-stale:{}", req.candidate_id),
        CoordinationEventKind::IntegrationCandidateStaled,
        req.candidate_id.clone(),
        req.session_id.clone(),
        (owner.sequence != 0).then_some(owner.sequence),
        req.authority_epoch.clone(),
        req.state_fence.clone(),
        req.current_base_commit.clone(),
        ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        },
    )?;
    let mut candidate = candidate.clone();
    candidate.status = IntegrationCandidateStatus::Stale;
    candidate.history.push(IntegrationCandidateRevision {
        event_sequence: event.sequence,
        status: IntegrationCandidateStatus::Stale,
        lease_id: Some(req.lease_id.clone()),
        observed_at: req.now,
        evidence_refs: candidate.evidence_refs.clone(),
        unresolved_conflicts: candidate.unresolved_conflicts.clone(),
        unknowns: candidate.unknowns.clone(),
    });
    Ok((candidate, event))
}

pub(crate) fn validate_candidate_text(
    draft: &IntegrationCandidateDraft,
) -> Result<(), CoordinationError> {
    for (value, field) in [
        (&draft.task_id, "task_id"),
        (&draft.candidate_id, "candidate_id"),
        (&draft.producer_attempt, "producer_attempt"),
        (&draft.base_commit, "base_commit"),
        (&draft.diff_ref, "diff_ref"),
        (&draft.target_scope, "target_scope"),
    ] {
        crate::text(value, field)?;
    }
    for values in [
        &draft.producer_lineage,
        &draft.worktree_or_artifact_refs,
        &draft.evidence_refs,
        &draft.verification_refs,
        &draft.unresolved_conflicts,
        &draft.unknowns,
    ] {
        for value in values {
            crate::text(value, "candidate_reference")?;
        }
    }
    if let Some(value) = &draft.rollback_or_compensation {
        crate::text(value, "rollback_or_compensation")?;
    }
    for values in [
        &draft.changed_paths,
        &draft.declared_read_effects,
        &draft.declared_write_effects,
    ] {
        for value in values {
            crate::text(value, "candidate_effect")?;
        }
    }
    Ok(())
}

pub(crate) fn exact_candidate_replay(
    candidates: &BTreeMap<String, IntegrationCandidate>,
    draft: &IntegrationCandidateDraft,
    event: &CoordinationEvent,
) -> Result<IntegrationCandidateReceipt, CoordinationError> {
    let candidate = candidates
        .get(&draft.candidate_id)
        .ok_or_else(|| CoordinationError::IdempotencyConflict(draft.request_id.clone()))?;
    if event.kind != CoordinationEventKind::IntegrationCandidateSubmitted
        || event.event_id != format!("candidate:{}", draft.candidate_id)
        || event.subject_id != draft.candidate_id
        || event.actor_id != draft.session_id
        || event.payload_digest != draft.candidate_id
        || event.state_fence != draft.state_fence
        || event.authority_epoch != draft.authority_epoch
        || candidate.task_id != draft.task_id
        || candidate.source_work_item_id != draft.source_work_item_id
        || candidate.producer_attempt != draft.producer_attempt
        || candidate.producer_lineage != draft.producer_lineage
        || candidate.base_commit != draft.base_commit
        || candidate.state_fence != draft.state_fence
        || candidate.worktree_or_artifact_refs != draft.worktree_or_artifact_refs
        || candidate.diff_ref != draft.diff_ref
        || candidate.changed_paths != draft.changed_paths
        || candidate.declared_read_effects != draft.declared_read_effects
        || candidate.declared_write_effects != draft.declared_write_effects
        || candidate.evidence_refs != draft.evidence_refs
        || candidate.verification_refs != draft.verification_refs
        || candidate.unresolved_conflicts != draft.unresolved_conflicts
        || candidate.unknowns != draft.unknowns
        || candidate.rollback_or_compensation != draft.rollback_or_compensation
        || candidate.target_scope != draft.target_scope
        || candidate.submitted_at != draft.now
        || !candidate.history.iter().any(|revision| {
            revision.event_sequence == event.sequence
                && revision.status == IntegrationCandidateStatus::Proposed
                && revision.lease_id.is_none()
                && revision.observed_at == draft.now
        })
    {
        return Err(CoordinationError::IdempotencyConflict(
            draft.request_id.clone(),
        ));
    }
    Ok(IntegrationCandidateReceipt {
        candidate_id: candidate.candidate_id.clone(),
        target_scope: candidate.target_scope.clone(),
        candidate: candidate.clone(),
        event: event.clone(),
    })
}

pub(crate) fn acquire_integration(
    owner: &mut CoordinationOwner,
    req: IntegrationLeaseRequest,
) -> Result<IntegrationLeaseDecision, CoordinationError> {
    let expires_at = validate_integration_request(owner, &req)?;
    let session = owner.session(
        &req.session_id,
        req.authority_epoch.clone(),
        &req.state_fence,
    )?;
    crate::validate_active_session_heartbeat(&session, Some(req.now))?;
    if let Some(decision) = exact_integration_replay(owner, &req, expires_at)? {
        return Ok(decision);
    }
    let staged = stage_integration_claim(owner, &req, expires_at)?;
    let event = owner.commit(&req.request_id, staged.event)?;
    owner
        .integrations
        .insert(req.target_scope.clone(), staged.lease.clone());
    owner
        .integration_lease_by_request
        .insert(req.request_id, staged.lease.clone());
    owner
        .integration_candidates
        .insert(req.candidate_id, staged.candidate);
    Ok(IntegrationLeaseDecision {
        lease: staged.lease,
        event,
    })
}

fn validate_integration_request(
    owner: &CoordinationOwner,
    req: &IntegrationLeaseRequest,
) -> Result<u64, CoordinationError> {
    for (value, field) in [
        (&req.request_id, "request_id"),
        (&req.lease_id, "lease_id"),
        (&req.candidate_id, "candidate_id"),
        (&req.target_scope, "target_scope"),
    ] {
        crate::text(value, field)?;
    }
    crate::nonzero(req.now, "now")?;
    crate::nonzero(req.lease_duration, "lease_duration")?;
    let expires_at = req
        .now
        .checked_add(req.lease_duration)
        .ok_or(CoordinationError::InvalidField("lease_duration"))?;
    owner.common(req.authority_epoch.clone(), &req.state_fence)?;
    owner.request(&req.request_id)?;
    Ok(expires_at)
}

fn exact_integration_replay(
    owner: &CoordinationOwner,
    req: &IntegrationLeaseRequest,
    expires_at: u64,
) -> Result<Option<IntegrationLeaseDecision>, CoordinationError> {
    let Some(event) = owner.event_by_request.get(&req.request_id) else {
        return Ok(None);
    };
    let Some(lease) = owner.integration_lease_by_request.get(&req.request_id) else {
        return Err(CoordinationError::IdempotencyConflict(
            req.request_id.clone(),
        ));
    };
    if event.kind != CoordinationEventKind::IntegrationClaimed
        || event.event_id != format!("integration:{}:{}", req.target_scope, req.lease_id)
        || event.subject_id != req.target_scope
        || event.actor_id != req.session_id
        || event.payload_digest != req.lease_id
        || event.state_fence != req.state_fence
        || event.authority_epoch != req.authority_epoch
        || lease.lease_id != req.lease_id
        || lease.candidate_id.as_deref() != Some(req.candidate_id.as_str())
        || lease.target_scope != req.target_scope
        || lease.holder_session_id != req.session_id
        || lease.expires_at != expires_at
        || lease.state_fence != req.state_fence
        || lease.authority_epoch != req.authority_epoch
    {
        return Err(CoordinationError::IdempotencyConflict(
            req.request_id.clone(),
        ));
    }
    Ok(Some(IntegrationLeaseDecision {
        lease: lease.clone(),
        event: event.clone(),
    }))
}

fn stage_integration_claim(
    owner: &CoordinationOwner,
    req: &IntegrationLeaseRequest,
    expires_at: u64,
) -> Result<StagedIntegrationClaim, CoordinationError> {
    let candidate = owner
        .integration_candidates
        .get(&req.candidate_id)
        .ok_or_else(|| CoordinationError::NotFound {
            kind: "integration_candidate",
            id: req.candidate_id.clone(),
        })?;
    let expired_same_candidate_lease =
        owner
            .integrations
            .get(&req.target_scope)
            .is_some_and(|lease| {
                lease.candidate_id.as_deref() == Some(req.candidate_id.as_str())
                    && lease.expires_at < req.now
            });
    let candidate_available = matches!(
        candidate.status,
        IntegrationCandidateStatus::Proposed | IntegrationCandidateStatus::Ready
    ) || (candidate.status == IntegrationCandidateStatus::Integrating
        && expired_same_candidate_lease);
    if candidate.target_scope != req.target_scope
        || candidate.state_fence != req.state_fence
        || !candidate_available
    {
        return Err(CoordinationError::InvalidState);
    }
    if owner.events.iter().any(|event| {
        event.kind == CoordinationEventKind::IntegrationClaimed
            && event.payload_digest == req.lease_id
    }) {
        return Err(CoordinationError::Duplicate(req.lease_id.clone()));
    }
    if owner
        .integrations
        .get(&req.target_scope)
        .is_some_and(|old| old.expires_at >= req.now)
    {
        return Err(CoordinationError::WorkAlreadyOwned);
    }
    let lease = IntegrationLease {
        lease_id: req.lease_id.clone(),
        candidate_id: Some(req.candidate_id.clone()),
        target_scope: req.target_scope.clone(),
        holder_session_id: req.session_id.clone(),
        authority_epoch: req.authority_epoch.clone(),
        state_fence: req.state_fence.clone(),
        expires_at,
    };
    let mut candidate = candidate.clone();
    let event = owner.event(
        &req.request_id,
        format!("integration:{}:{}", req.target_scope, req.lease_id),
        CoordinationEventKind::IntegrationClaimed,
        req.target_scope.clone(),
        req.session_id.clone(),
        (owner.sequence != 0).then_some(owner.sequence),
        req.authority_epoch.clone(),
        req.state_fence.clone(),
        req.lease_id.clone(),
        ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        },
    )?;
    candidate.status = IntegrationCandidateStatus::Integrating;
    candidate.history.push(IntegrationCandidateRevision {
        event_sequence: event.sequence,
        status: IntegrationCandidateStatus::Integrating,
        lease_id: Some(lease.lease_id.clone()),
        observed_at: req.now,
        evidence_refs: candidate.evidence_refs.clone(),
        unresolved_conflicts: candidate.unresolved_conflicts.clone(),
        unknowns: candidate.unknowns.clone(),
    });
    Ok(StagedIntegrationClaim {
        lease,
        candidate,
        event,
    })
}

pub(crate) fn validate_candidate_snapshot(
    owner: &CoordinationOwner,
) -> Result<(), CoordinationError> {
    for (candidate_id, candidate) in &owner.integration_candidates {
        validate_candidate_record(owner, candidate_id, candidate)?;
    }
    validate_integration_lease_history(owner)?;
    validate_current_integration_leases(owner)
}

fn validate_candidate_record(
    owner: &CoordinationOwner,
    candidate_id: &str,
    candidate: &IntegrationCandidate,
) -> Result<(), CoordinationError> {
    if candidate_id != candidate.candidate_id
        || candidate.history.is_empty()
        || candidate.history.last().map(|revision| revision.status) != Some(candidate.status)
        || candidate.state_fence.validate().is_err()
        || candidate
            .history
            .windows(2)
            .any(|pair| pair[0].event_sequence >= pair[1].event_sequence)
        || candidate
            .history
            .first()
            .is_none_or(|revision| revision.status != IntegrationCandidateStatus::Proposed)
    {
        return Err(CoordinationError::InvalidState);
    }
    for revision in &candidate.history {
        let event_index = revision
            .event_sequence
            .checked_sub(1)
            .ok_or(CoordinationError::InvalidState)?;
        let event_index =
            usize::try_from(event_index).map_err(|_| CoordinationError::InvalidState)?;
        let event = owner
            .events
            .get(event_index)
            .ok_or(CoordinationError::InvalidState)?;
        if event.sequence != revision.event_sequence
            || revision.observed_at == 0
            || !candidate_revision_matches_event(owner, candidate, revision, event)
            || revision.evidence_refs != candidate.evidence_refs
            || revision.unresolved_conflicts != candidate.unresolved_conflicts
            || revision.unknowns != candidate.unknowns
        {
            return Err(CoordinationError::InvalidState);
        }
    }
    Ok(())
}

fn candidate_revision_matches_event(
    owner: &CoordinationOwner,
    candidate: &IntegrationCandidate,
    revision: &IntegrationCandidateRevision,
    event: &CoordinationEvent,
) -> bool {
    match revision.status {
        IntegrationCandidateStatus::Proposed => {
            event.kind == CoordinationEventKind::IntegrationCandidateSubmitted
                && event.subject_id == candidate.candidate_id
                && revision.lease_id.is_none()
        }
        IntegrationCandidateStatus::Stale => {
            event.kind == CoordinationEventKind::IntegrationCandidateStaled
                && event.subject_id == candidate.candidate_id
                && revision.lease_id.as_ref().is_some_and(|lease_id| {
                    owner.integration_lease_by_request.values().any(|lease| {
                        lease.lease_id == *lease_id && lease.target_scope == candidate.target_scope
                    })
                })
        }
        IntegrationCandidateStatus::Integrating => {
            event.kind == CoordinationEventKind::IntegrationClaimed
                && owner
                    .integration_lease_by_request
                    .get(&event.idempotency_key)
                    .is_some_and(|lease| {
                        lease.candidate_id.as_deref() == Some(candidate.candidate_id.as_str())
                            && lease.target_scope == candidate.target_scope
                            && revision.lease_id.as_deref() == Some(lease.lease_id.as_str())
                    })
        }
        IntegrationCandidateStatus::Ready
        | IntegrationCandidateStatus::Accepted
        | IntegrationCandidateStatus::Rejected
        | IntegrationCandidateStatus::Conflicted
        | IntegrationCandidateStatus::UnknownOutcome => false,
    }
}

fn validate_integration_lease_history(owner: &CoordinationOwner) -> Result<(), CoordinationError> {
    for (request_id, lease) in &owner.integration_lease_by_request {
        let Some(event) = owner.event_by_request.get(request_id) else {
            return Err(CoordinationError::InvalidState);
        };
        if event.kind != CoordinationEventKind::IntegrationClaimed
            || event.idempotency_key != *request_id
            || event.event_id != format!("integration:{}:{}", lease.target_scope, lease.lease_id)
            || event.subject_id != lease.target_scope
            || event.actor_id != lease.holder_session_id
            || event.payload_digest != lease.lease_id
            || event.state_fence != lease.state_fence
        {
            return Err(CoordinationError::InvalidState);
        }
    }
    Ok(())
}

fn validate_current_integration_leases(owner: &CoordinationOwner) -> Result<(), CoordinationError> {
    for (target_scope, lease) in &owner.integrations {
        if target_scope != &lease.target_scope
            || lease.candidate_id.as_ref().is_some_and(|candidate_id| {
                !owner
                    .integration_candidates
                    .get(candidate_id)
                    .is_some_and(|candidate| {
                        candidate.target_scope == lease.target_scope
                            && candidate.history.iter().any(|revision| {
                                revision.status == IntegrationCandidateStatus::Integrating
                                    && owner.integration_lease_by_request.values().any(
                                        |history_lease| {
                                            history_lease.lease_id == lease.lease_id
                                                && history_lease.candidate_id
                                                    == Some(candidate_id.clone())
                                        },
                                    )
                            })
                    })
            })
        {
            return Err(CoordinationError::InvalidState);
        }
    }
    Ok(())
}
