use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ClockReading, EpochId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    CoordinationError, CoordinationEvent, CoordinationEventKind, CoordinationOwner,
    IntegrationLease, IntegrationLeaseDecision, IntegrationLeaseRequest, PeerReviewLifecycle,
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

/// One review correlated to a provenance subject by an exact recorded
/// identity string.
///
/// The match is correlation, never causation (I11.2): the review's
/// `artifact_id` equals the cited `matched_ref` character-for-character, and
/// both endpoints are reported so a reader can verify the shared string.
/// Sharing a string proves co-occurrence in one owner's records, not that
/// one record caused the other and not that either owns the other.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorrelatedReview {
    pub review_id: String,
    /// Reviewed operation identity exactly as the retained review carries
    /// it: the navigation start for decision-to-change movement.
    pub operation: String,
    pub artifact_revision: u64,
    pub artifact_digest: String,
    pub lifecycle: PeerReviewLifecycle,
    /// Exact recorded string shared with the provenance subject.
    pub matched_ref: String,
}

/// One candidate correlated to a code identity by an exact recorded string.
///
/// Same correlation contract as [`CorrelatedReview`]: the cited
/// `matched_ref` is character-for-character equal on both records, and the
/// candidate's own diff and base commit ride along so navigation reaches the
/// actual recorded change without choosing an arbitrary single origin.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorrelatedCandidate {
    pub candidate_id: String,
    /// Exact recorded string shared with the code identity.
    pub matched_ref: String,
    pub diff_ref: String,
    pub base_commit: String,
}

/// One retained revision digest behind a code identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetainedArtifactRevision {
    pub revision: u64,
    pub digest: String,
}

/// Recorded origins behind one integration candidate, forward from the
/// retained decision to the retained diff, code and verifier refs.
///
/// Every leg cites retained records only. Legs this owner does not retain
/// are listed in `gaps` with their reason instead of being invented:
/// public conversation references live outside this owner, and verifier
/// outcomes are never inferred from worker results, so a
/// `verification_ref` binds no artifact revision here. A passing run for
/// different bytes proves nothing about this candidate's bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateProvenance {
    pub candidate_id: String,
    /// Sequence of the retained submission event (`history[0]`), when that
    /// event is still present in the event stream and names this candidate.
    pub submission_event_sequence: Option<u64>,
    /// Every lease decision recorded against this candidate, in `lease_id`
    /// order. Indexes are rebuildable from the retained lease records.
    pub lease_ids: Vec<String>,
    /// Exact diff reference as retained on the candidate.
    pub diff_ref: String,
    /// Exact base commit as retained on the candidate.
    pub base_commit: String,
    /// Reviews sharing an exact recorded identity string with this
    /// candidate, in `review_id` order. Multiple origins are preserved; no
    /// arbitrary single origin is chosen.
    pub correlated_reviews: Vec<CorrelatedReview>,
    /// Verifier references as retained: recorded, unbound strings. They name
    /// evidence handles only; this owner records no outcome for them.
    pub verification_refs: Vec<String>,
    /// Missing legs with reasons: conversation, verifier binding, an absent
    /// submission event, an absent lease, absent correlated reviews.
    pub gaps: Vec<String>,
}

/// Recorded origins behind one code identity, reverse from current code to
/// the decisions, diffs and reviews that name it.
///
/// The lookup starts at the exact requested identity and reports what the
/// owner retains at and around it: the admitted head, every retained
/// revision digest, reviews bound to the artifact, and candidates sharing an
/// exact recorded string. Absence lands in `gaps`, never filled from a
/// nearest match: an unrun search stays incomplete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactProvenance {
    pub artifact_id: String,
    pub requested_revision: Option<u64>,
    pub current_revision: Option<u64>,
    pub current_digest: Option<String>,
    /// Every retained revision digest for this artifact, in revision order.
    /// The head entry equals the current pair when a head is admitted.
    pub retained_revisions: Vec<RetainedArtifactRevision>,
    /// Reviews retained against this exact artifact identity, in
    /// `review_id` order.
    pub reviews: Vec<CorrelatedReview>,
    /// Candidates sharing an exact recorded string with this artifact, in
    /// `candidate_id` order, each with the matched string cited.
    pub correlated_candidates: Vec<CorrelatedCandidate>,
    /// Missing coverage with reasons: no head, no retained revisions, no
    /// reviews, no correlated candidates, unavailable conversation.
    pub gaps: Vec<String>,
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

    /// Reads the recorded origins behind one integration candidate, forward
    /// from the retained lease decisions to the retained diff, code and
    /// verifier refs, with correlated reviews attached.
    ///
    /// The view is rebuilt from retained records on every call: the
    /// submission event is joined through `history[0]` against the retained
    /// event stream, leases through the retained lease records, and reviews
    /// through exact recorded-string correlation (see [`CorrelatedReview`]).
    /// Legs the owner does not retain land in `gaps` with their reason.
    /// `None` when no candidate carries the identity: a missing link stays
    /// missing, never synthesized.
    #[must_use]
    pub fn candidate_provenance(&self, candidate_id: &str) -> Option<CandidateProvenance> {
        let candidate = self.integration_candidates.get(candidate_id)?;
        let submission_event_sequence = candidate.history.first().and_then(|revision| {
            let index = revision.event_sequence.checked_sub(1)?;
            let index = usize::try_from(index).ok()?;
            let event = self.events.get(index)?;
            (event.sequence == revision.event_sequence
                && event.kind == CoordinationEventKind::IntegrationCandidateSubmitted
                && event.subject_id == candidate.candidate_id)
                .then_some(event.sequence)
        });
        let mut lease_ids: Vec<String> = self
            .integration_lease_by_request
            .values()
            .filter(|lease| lease.candidate_id.as_deref() == Some(candidate.candidate_id.as_str()))
            .map(|lease| lease.lease_id.clone())
            .collect();
        lease_ids.sort();
        lease_ids.dedup();
        let identity_strings: BTreeSet<&str> = candidate
            .worktree_or_artifact_refs
            .iter()
            .map(String::as_str)
            .chain(candidate.producer_lineage.iter().map(String::as_str))
            .collect();
        let correlated_reviews: Vec<CorrelatedReview> = self
            .peer_reviews
            .values()
            .filter(|review| identity_strings.contains(review.artifact_id.as_str()))
            .map(|review| CorrelatedReview {
                review_id: review.review_id.clone(),
                operation: review.operation.clone(),
                artifact_revision: review.artifact_revision,
                artifact_digest: review.artifact_digest.clone(),
                lifecycle: review.lifecycle,
                matched_ref: review.artifact_id.clone(),
            })
            .collect();
        let mut gaps = Vec::new();
        if submission_event_sequence.is_none() {
            gaps.push("submission event absent from the retained event stream".to_owned());
        }
        if lease_ids.is_empty() {
            gaps.push("no integration lease decision recorded against this candidate".to_owned());
        }
        if correlated_reviews.is_empty() {
            gaps.push(
                "no retained review shares an exact recorded identity string with this candidate"
                    .to_owned(),
            );
        }
        gaps.push("public conversation references are not retained by this owner".to_owned());
        gaps.push(
            "verification refs bind no artifact revision here; this owner records no verifier outcome"
                .to_owned(),
        );
        Some(CandidateProvenance {
            candidate_id: candidate.candidate_id.clone(),
            submission_event_sequence,
            lease_ids,
            diff_ref: candidate.diff_ref.clone(),
            base_commit: candidate.base_commit.clone(),
            correlated_reviews,
            verification_refs: candidate.verification_refs.clone(),
            gaps,
        })
    }

    /// Reads the recorded origins behind one code identity, reverse from the
    /// current admitted head to the retained revisions, reviews and
    /// correlated candidates.
    ///
    /// Every join is exact: the head and revision digests come from the
    /// retained artifact maps, reviews from the retained review records for
    /// the artifact identity, and candidates from exact recorded-string
    /// correlation (see [`CorrelatedCandidate`]). Requesting a revision the
    /// owner never retained is a reported gap, not a lookup into current
    /// code: history is never rewritten to the head.
    #[must_use]
    pub fn artifact_provenance(
        &self,
        artifact_id: &str,
        revision: Option<u64>,
    ) -> ArtifactProvenance {
        let head = self.peer_artifact_heads.get(artifact_id);
        let mut retained_revisions: Vec<RetainedArtifactRevision> = self
            .peer_artifact_revisions
            .iter()
            .filter(|((identity, _), _)| identity.as_str() == artifact_id)
            .map(|((_, retained), digest)| RetainedArtifactRevision {
                revision: *retained,
                digest: digest.clone(),
            })
            .collect();
        retained_revisions.sort_by_key(|entry| entry.revision);
        let reviews: Vec<CorrelatedReview> = self
            .peer_reviews
            .values()
            .filter(|review| review.artifact_id == artifact_id)
            .map(|review| CorrelatedReview {
                review_id: review.review_id.clone(),
                operation: review.operation.clone(),
                artifact_revision: review.artifact_revision,
                artifact_digest: review.artifact_digest.clone(),
                lifecycle: review.lifecycle,
                matched_ref: review.artifact_id.clone(),
            })
            .collect();
        let correlated_candidates: Vec<CorrelatedCandidate> = self
            .integration_candidates
            .values()
            .filter_map(|candidate| {
                candidate
                    .worktree_or_artifact_refs
                    .iter()
                    .chain(candidate.producer_lineage.iter())
                    .find(|entry| entry.as_str() == artifact_id)
                    .map(|matched| CorrelatedCandidate {
                        candidate_id: candidate.candidate_id.clone(),
                        matched_ref: matched.clone(),
                        diff_ref: candidate.diff_ref.clone(),
                        base_commit: candidate.base_commit.clone(),
                    })
            })
            .collect();
        let mut gaps = Vec::new();
        if head.is_none() {
            gaps.push("no admitted head for this artifact identity".to_owned());
        }
        if retained_revisions.is_empty() {
            gaps.push("no retained revision digests for this artifact identity".to_owned());
        }
        if revision.is_some_and(|requested| {
            !retained_revisions
                .iter()
                .any(|entry| entry.revision == requested)
        }) {
            gaps.push(
                "requested revision is not retained for this artifact identity".to_owned(),
            );
        }
        if reviews.is_empty() {
            gaps.push("no retained reviews for this artifact identity".to_owned());
        }
        if correlated_candidates.is_empty() {
            gaps.push(
                "no retained candidate shares an exact recorded identity string with this artifact"
                    .to_owned(),
            );
        }
        gaps.push("public conversation references are not retained by this owner".to_owned());
        ArtifactProvenance {
            artifact_id: artifact_id.to_owned(),
            requested_revision: revision,
            current_revision: head.map(|head| head.revision),
            current_digest: head.map(|head| head.digest.clone()),
            retained_revisions,
            reviews,
            correlated_candidates,
            gaps,
        }
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
