//! Kernel-owned leaseable integration-owner path per target (issue #1818, W3).
//!
//! Architecture: I10.16 governed integration of candidate implementations.
//! Each mutable target branch/deliverable has exactly one active integration
//! owner and lease. This module is the Kernel-mechanical half of that owner
//! path: the named advance ([`advance_integration_owner`], stable name
//! [`INTEGRATION_OWNER_ADVANCE_NAME`]) which projects the W1 queue for one
//! target, takes its head, and acquires the W2 single active lease for it,
//! plus the derived integration-pressure projection
//! ([`project_integration_pressure`], stable read name
//! [`INTEGRATION_OWNER_STATE_READ_NAME`]). Durability stays with the
//! canonical Store through the existing Store bridge; this module keeps no
//! rows, runs no scheduler, and owns no second store.
//!
//! # Production chain
//!
//! The owner path takes the caller-read-back candidate and lease views (the
//! Store bridge readback in production, read through W1's
//! `read_integration_candidate` and projected through W1's
//! `project_integration_queue`, never a second lookup scheme) plus the live
//! target observations the caller proved against the live target. It calls
//! W2's [`acquire_integration_lease`](crate::integration_lease::acquire_integration_lease)
//! for the queue head: a granted lease transitions the head to `Integrating`
//! for the bridge to persist before any verifier or apply work starts, a
//! target that already holds an active lease yields `TargetHeld` with the
//! head identified so the second candidate remains queued, and a moved base
//! the head depends on yields the `Stale` record which must never apply. The
//! stable [`INTEGRATION_OWNER_ADVANCE_NAME`] and
//! [`INTEGRATION_OWNER_STATE_READ_NAME`] constants are the exact keys the
//! Store bridge slice registers; they are declared here so the names cannot
//! drift between the Kernel surface and the bridge registration.
//!
//! The production caller is [`serve_integration_owner_request`]: it admits
//! the typed advance request, drives [`advance_integration_owner`], and
//! encodes the [`IntegrationOwnerResponse`] carrying the outcome, the lease
//! when granted, the exact transitioned records the bridge must persist, and
//! the pressure projection. Dispatch wiring stays with the owning slice per
//! the all-code-first owner order; no caller outside this module is claimed.
//!
//! # What this deliberately does not do
//!
//! No candidate creation or queue definition (W1), no lease-shape ownership
//! (W2), no verifier execution, no bridge apply, no `OutcomeReceipt`, and no
//! rollback/compensation execution: those live in the bridge-apply slice,
//! which admits only typed observations bound to the exact candidate, lease,
//! and environment and refuses fail-closed when any binding breaks. The
//! pressure projection counts queue and lifecycle states; it schedules
//! nothing and stores nothing.
//!
//! # Relation to the acceptance slice (A1)
//!
//! The two-candidate overlap case resolves here: when the target already
//! holds an active lease, the head is reported held and stays queued rather
//! than taking a second lease, and the leaseable-status plus path/effect
//! revalidation inside W2 keeps an overlapping but inadmissible candidate
//! out of the owner path. A base-moved candidate goes stale only through
//! W2's caller-joined `candidate_depends_on_base` flag, never by inference.
//! The pre-apply verifier receipt, post-apply `OutcomeReceipt`, and
//! rollback/compensation record belong to the bridge-apply slice; this path
//! supplies the lease, the `Integrating` transition, and the pressure
//! evidence that slice consumes.
//!
//! # Relation to the coordination record
//!
//! `eliot-coordination` already types coordination-side queue and lease
//! vocabulary for the Governor-side owner (coordination events, session-held
//! leases). That vocabulary is Governor semantics, which the Kernel
//! composition root must not duplicate or interpret (`bins/AGENTS.md`).
//! This path is the Kernel-mechanical admission shape built only from the
//! W1/W2 record types and bounded text: the target scope, the queue head,
//! the single active lease, and derived counters. It carries no session, no
//! expiry, and no coordination event.

use std::collections::BTreeSet;

use eliot_contracts::StateFence;
use serde::{Deserialize, Serialize};

use crate::integration_candidate::{
    IntegrationCandidate, IntegrationCandidateError, IntegrationCandidateRevision,
    IntegrationCandidateStatus, MAX_BASE_LEN, MAX_IDENTITY_LEN, project_integration_queue,
};
use crate::integration_lease::{
    IntegrationLeaseError, IntegrationOwnerLease, IntegrationOwnerLeaseRequest,
    acquire_integration_lease,
};

/// Stable named owner advance. The Store bridge slice registers this exact
/// name for the single leaseable integration-owner path per target.
pub const INTEGRATION_OWNER_ADVANCE_NAME: &str = "AdvanceIntegrationOwner";
/// Stable named owner-state read. The Store bridge slice registers this exact
/// name for the per-target owner state and pressure projection readback.
pub const INTEGRATION_OWNER_STATE_READ_NAME: &str = "GetIntegrationOwnerState";

/// Typed owner-path failures. Every refusal names its field or reason; the
/// lease and candidate cases carry the owning slice's typed error. No
/// failure grants a lease or transitions a candidate.
#[derive(Clone, Debug)]
pub enum IntegrationOwnerError {
    /// An advance-request field failed admission bounds. Nothing was
    /// advanced.
    InvalidField {
        /// Closed field name, never a value.
        field: &'static str,
        /// Stable reason, never a value.
        reason: &'static str,
    },
    /// The W1 queue projection or candidate read failed. Nothing was
    /// advanced.
    Candidate(Box<IntegrationCandidateError>),
    /// The W2 lease acquire refused for a reason other than held or stale
    /// (mismatch, dirty work, inadmissible status). The candidate keeps its
    /// status and remains queued. Nothing was advanced.
    Lease(Box<IntegrationLeaseError>),
}

impl std::fmt::Display for IntegrationOwnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField { field, reason } => {
                write!(f, "invalid integration owner field {field}: {reason}")
            }
            Self::Candidate(error) => {
                write!(f, "integration owner candidate: {error}")
            }
            Self::Lease(error) => {
                write!(f, "integration owner lease: {error}")
            }
        }
    }
}

impl std::error::Error for IntegrationOwnerError {}

/// Caller-observed advance input for one mutable target. The bridge slice
/// decodes this from its typed request and proves every observed set against
/// the live target before calling the owner path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationOwnerAdvanceRequest {
    /// Mutable target whose owner path advances.
    pub target_scope: String,
    /// Live base revision of the target at advance time.
    pub current_base_commit: String,
    /// Whether the queue head depends on the base it was produced against.
    /// A moved base marks the head stale only when this is true; the
    /// dependency itself is joined from the queue/dependency projection by
    /// the caller, never inferred here.
    pub candidate_depends_on_base: bool,
    /// Live State Fence of the target at advance time.
    pub current_fence: StateFence,
    /// Caller-observed changed paths at advance time; must exactly match
    /// the head's manifest.
    pub observed_changed_paths: BTreeSet<String>,
    /// Caller-observed declared read effects; must exactly match.
    pub observed_read_effects: BTreeSet<String>,
    /// Caller-observed declared write effects; must exactly match.
    pub observed_write_effects: BTreeSet<String>,
    /// Dirty human paths observed in the target at advance time. Any
    /// overlap with the head's manifest fails closed.
    pub dirty_paths: BTreeSet<String>,
    /// Caller-observed time of the advance, Unix milliseconds, never zero.
    pub observed_at_unix_ms: u64,
}

/// Derived integration-pressure projection for one mutable target. This is a
/// pure view over already-known candidates and leases, never a scheduler or
/// a store: it counts queue and lifecycle states so the owner can observe
/// integration pressure without creating another owner for the target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationPressure {
    /// Target scope this projection was derived for.
    pub target_scope: String,
    /// Admissible (`Proposed` or `Ready`) candidates waiting for the lease.
    pub queued: usize,
    /// Candidate holding the target's single active lease, when one exists.
    pub active_lease_holder: Option<String>,
    /// Candidates parked as stale on a moved base they depend on.
    pub stale: usize,
    /// Candidates held as durable semantic-conflict work, never auto-merged.
    pub conflicted: usize,
    /// Candidates currently held by the lease for integration work.
    pub integrating: usize,
    /// Candidates applied through the governed bridge with an outcome.
    pub accepted: usize,
    /// Candidates refused before apply; history retained.
    pub rejected: usize,
    /// Candidates whose apply outcome is unknown; retried by exact retry
    /// identity only.
    pub unknown_outcome: usize,
    /// Pairs of queued candidates sharing at least one changed path or one
    /// declared write effect. A non-zero count is overlap pressure on the
    /// single active lease, never a reason to take a second one.
    pub overlapping_queued_pairs: usize,
}

/// One owner-path step outcome for a target. A granted lease carries the
/// `Integrating` record for the bridge to persist before any verifier or
/// apply work; every other outcome carries the pressure projection so the
/// bridge can observe the target without re-deriving it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum OwnerAdvanceOutcome {
    /// The queue head took the target's single active lease. The carried
    /// record is already transitioned to `Integrating` for the bridge to
    /// persist.
    LeaseGranted {
        /// The single active lease for the target.
        lease: IntegrationOwnerLease,
        /// Head record transitioned to `Integrating` with its history entry.
        integrating: IntegrationCandidate,
        /// Pressure observed at advance time.
        pressure: IntegrationPressure,
    },
    /// The target already holds an active lease. The carried head remains
    /// queued; no second lease was taken.
    TargetHeld {
        /// Candidate holding the target's active lease.
        holder_candidate_id: String,
        /// Queue head that remains queued behind the active lease.
        queued_head: IntegrationCandidate,
        /// Pressure observed at advance time.
        pressure: IntegrationPressure,
    },
    /// No admissible candidate waits for the target. Nothing was advanced.
    QueueEmpty {
        /// Pressure observed at advance time.
        pressure: IntegrationPressure,
    },
    /// The head's base moved and the head depends on it. The carried record
    /// is already transitioned to `Stale` for the bridge to persist; it must
    /// never apply.
    StaleRecorded {
        /// Head record transitioned to `Stale` with its history entry.
        stale: IntegrationCandidate,
        /// Pressure observed at advance time.
        pressure: IntegrationPressure,
    },
}

/// Stable outcome kind for the owner response wire shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationOwnerOutcomeKind {
    /// Head took the single active lease.
    LeaseGranted,
    /// Target already leased; head remains queued.
    TargetHeld,
    /// No admissible candidate waits.
    QueueEmpty,
    /// Head went stale on a moved base it depends on.
    StaleRecorded,
}

/// Encoded owner-path response. The bridge persists every carried
/// `persist_candidates` record and routes the outcome onward; this response
/// stores nothing itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationOwnerResponse {
    /// Which owner-path step ran.
    pub outcome: IntegrationOwnerOutcomeKind,
    /// The single active lease, present only when the head took it.
    pub lease: Option<IntegrationOwnerLease>,
    /// Transitioned records the bridge must persist (`Integrating` on a
    /// grant, `Stale` on a base move, empty otherwise).
    pub persist_candidates: Vec<IntegrationCandidate>,
    /// Pressure observed at advance time.
    pub pressure: IntegrationPressure,
}

/// Derives the integration-pressure projection for one target scope.
///
/// Counts queue and lifecycle states over the caller-read-back candidate
/// view plus the caller-read-back lease view (the Store bridge readback in
/// production). The overlapping-pair count joins queued candidates sharing
/// a changed path or a declared write effect. Pure: no lease is taken, no
/// record transitions, nothing is stored.
pub fn project_integration_pressure(
    candidates: &[IntegrationCandidate],
    active_leases: &[IntegrationOwnerLease],
    target_scope: &str,
) -> Result<IntegrationPressure, IntegrationOwnerError> {
    require_text(target_scope, "target_scope", MAX_IDENTITY_LEN)?;
    let scoped: Vec<&IntegrationCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.target_scope == target_scope)
        .collect();
    let count = |status: IntegrationCandidateStatus| {
        scoped
            .iter()
            .filter(|candidate| candidate.status == status)
            .count()
    };
    let queued: Vec<&IntegrationCandidate> = scoped
        .iter()
        .filter(|candidate| is_queued_status(candidate.status))
        .copied()
        .collect();
    Ok(IntegrationPressure {
        target_scope: target_scope.to_owned(),
        queued: queued.len(),
        active_lease_holder: active_leases
            .iter()
            .find(|lease| lease.target_scope == target_scope)
            .map(|lease| lease.candidate_id.clone()),
        stale: count(IntegrationCandidateStatus::Stale),
        conflicted: count(IntegrationCandidateStatus::Conflicted),
        integrating: count(IntegrationCandidateStatus::Integrating),
        accepted: count(IntegrationCandidateStatus::Accepted),
        rejected: count(IntegrationCandidateStatus::Rejected),
        unknown_outcome: count(IntegrationCandidateStatus::UnknownOutcome),
        overlapping_queued_pairs: count_overlapping_pairs(&queued),
    })
}

/// Advances one target's leaseable integration-owner path by a single step.
///
/// Projects the W1 queue for `request.target_scope`, takes its head, and
/// acquires the W2 single active lease for it against the live target
/// observations carried in `request`. A granted lease transitions the head
/// to `Integrating` for the bridge to persist; an already-leased target
/// reports the holder with the head still queued; a moved base the head
/// depends on reports the `Stale` record; any other refusal leaves the head
/// queued with its status intact. Only every check passing grants the lease,
/// and at most one lease per target can come out of this path.
pub fn advance_integration_owner(
    candidates: &[IntegrationCandidate],
    active_leases: &[IntegrationOwnerLease],
    request: &IntegrationOwnerAdvanceRequest,
) -> Result<OwnerAdvanceOutcome, IntegrationOwnerError> {
    validate_advance_request(request)?;
    let queue = project_integration_queue(candidates, &request.target_scope)
        .map_err(|error| IntegrationOwnerError::Candidate(Box::new(error)))?;
    let pressure = project_integration_pressure(candidates, active_leases, &request.target_scope)?;
    let Some(head) = queue.queued.first() else {
        return Ok(OwnerAdvanceOutcome::QueueEmpty { pressure });
    };
    let lease_request = IntegrationOwnerLeaseRequest {
        target_scope: request.target_scope.clone(),
        candidate_id: head.candidate_id.clone(),
        current_base_commit: request.current_base_commit.clone(),
        candidate_depends_on_base: request.candidate_depends_on_base,
        current_fence: request.current_fence.clone(),
        observed_changed_paths: request.observed_changed_paths.clone(),
        observed_read_effects: request.observed_read_effects.clone(),
        observed_write_effects: request.observed_write_effects.clone(),
        dirty_paths: request.dirty_paths.clone(),
        observed_at_unix_ms: request.observed_at_unix_ms,
    };
    match acquire_integration_lease(candidates, active_leases, &lease_request) {
        Ok(lease) => Ok(OwnerAdvanceOutcome::LeaseGranted {
            lease,
            integrating: transition_to_integrating(head, request.observed_at_unix_ms),
            pressure,
        }),
        Err(IntegrationLeaseError::LeaseHeld {
            holder_candidate_id,
            ..
        }) => Ok(OwnerAdvanceOutcome::TargetHeld {
            holder_candidate_id,
            queued_head: head.clone(),
            pressure,
        }),
        Err(IntegrationLeaseError::StaleMarked { stale }) => {
            Ok(OwnerAdvanceOutcome::StaleRecorded {
                stale: *stale,
                pressure,
            })
        }
        Err(other) => Err(IntegrationOwnerError::Lease(Box::new(other))),
    }
}

/// Serves one typed owner-path request: admits the advance request, drives
/// [`advance_integration_owner`], and encodes the [`IntegrationOwnerResponse`]
/// with the outcome, the lease when granted, the exact transitioned records
/// the bridge must persist, and the pressure projection. This is the
/// production caller of the owner advance; dispatch wiring stays with the
/// owning slice per the all-code-first owner order.
pub fn serve_integration_owner_request(
    candidates: &[IntegrationCandidate],
    active_leases: &[IntegrationOwnerLease],
    request: &IntegrationOwnerAdvanceRequest,
) -> Result<IntegrationOwnerResponse, IntegrationOwnerError> {
    validate_advance_request(request)?;
    match advance_integration_owner(candidates, active_leases, request)? {
        OwnerAdvanceOutcome::LeaseGranted {
            lease,
            integrating,
            pressure,
        } => Ok(IntegrationOwnerResponse {
            outcome: IntegrationOwnerOutcomeKind::LeaseGranted,
            lease: Some(lease),
            persist_candidates: vec![integrating],
            pressure,
        }),
        OwnerAdvanceOutcome::TargetHeld { pressure, .. } => Ok(IntegrationOwnerResponse {
            outcome: IntegrationOwnerOutcomeKind::TargetHeld,
            lease: None,
            persist_candidates: Vec::new(),
            pressure,
        }),
        OwnerAdvanceOutcome::QueueEmpty { pressure } => Ok(IntegrationOwnerResponse {
            outcome: IntegrationOwnerOutcomeKind::QueueEmpty,
            lease: None,
            persist_candidates: Vec::new(),
            pressure,
        }),
        OwnerAdvanceOutcome::StaleRecorded { stale, pressure } => {
            Ok(IntegrationOwnerResponse {
                outcome: IntegrationOwnerOutcomeKind::StaleRecorded,
                lease: None,
                persist_candidates: vec![stale],
                pressure,
            })
        }
    }
}

/// Validates the advance request bounds once, so both the advance and its
/// serving caller refuse a malformed request identically. Live-set agreement
/// (paths, effects, fence) is revalidated inside W2 against the head, never
/// here.
fn validate_advance_request(
    request: &IntegrationOwnerAdvanceRequest,
) -> Result<(), IntegrationOwnerError> {
    require_text(&request.target_scope, "target_scope", MAX_IDENTITY_LEN)?;
    require_base_commit(&request.current_base_commit)?;
    require_time(request.observed_at_unix_ms, "observed_at_unix_ms")?;
    Ok(())
}

/// Transitions a lease-winning head to `Integrating` with its history entry.
/// The bridge persists the returned record before any verifier or apply
/// work; the holder moves off this status only on the outcome path.
fn transition_to_integrating(
    head: &IntegrationCandidate,
    observed_at_unix_ms: u64,
) -> IntegrationCandidate {
    let mut integrating = head.clone();
    integrating.status = IntegrationCandidateStatus::Integrating;
    integrating.history.push(IntegrationCandidateRevision {
        status: IntegrationCandidateStatus::Integrating,
        observed_at_unix_ms,
    });
    integrating
}

/// Whether a lifecycle status may wait for the single active lease. Only
/// admissible, pre-integration statuses count toward queue pressure; the
/// lease holder itself counts as integrating, never queued.
fn is_queued_status(status: IntegrationCandidateStatus) -> bool {
    matches!(
        status,
        IntegrationCandidateStatus::Proposed | IntegrationCandidateStatus::Ready
    )
}

/// Counts queued pairs sharing at least one changed path or one declared
/// write effect. Each pair is overlap pressure on the single active lease:
/// exactly one of the two may hold it at a time.
fn count_overlapping_pairs(queued: &[&IntegrationCandidate]) -> usize {
    let mut pairs = 0;
    for (index, first) in queued.iter().enumerate() {
        for second in queued.iter().skip(index + 1) {
            if shares_path_or_write_effect(first, second) {
                pairs += 1;
            }
        }
    }
    pairs
}

/// Whether two queued candidates overlap on a changed path or a declared
/// write effect. Read-effect overlap alone never blocks the lease.
fn shares_path_or_write_effect(
    first: &IntegrationCandidate,
    second: &IntegrationCandidate,
) -> bool {
    first
        .changed_paths
        .intersection(&second.changed_paths)
        .next()
        .is_some()
        || first
            .declared_write_effects
            .intersection(&second.declared_write_effects)
            .next()
            .is_some()
}

/// Requires bounded, non-blank text with no control characters, mirroring
/// the Store owner's text rule plus an admission length bound.
fn require_text(
    value: &str,
    field: &'static str,
    max_len: usize,
) -> Result<(), IntegrationOwnerError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(IntegrationOwnerError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    if value.len() > max_len {
        return Err(IntegrationOwnerError::InvalidField {
            field,
            reason: "exceeds admission bound",
        });
    }
    Ok(())
}

/// Requires the live base revision to be compact visible ASCII with no
/// whitespace, mirroring the candidate and lease base rules so the three
/// can be compared exactly.
fn require_base_commit(base_commit: &str) -> Result<(), IntegrationOwnerError> {
    require_text(base_commit, "current_base_commit", MAX_BASE_LEN)?;
    if !base_commit.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(IntegrationOwnerError::InvalidField {
            field: "current_base_commit",
            reason: "must be visible ASCII with no whitespace",
        });
    }
    Ok(())
}

/// Requires a caller-observed time that is never zero.
fn require_time(value: u64, field: &'static str) -> Result<(), IntegrationOwnerError> {
    if value == 0 {
        return Err(IntegrationOwnerError::InvalidField {
            field,
            reason: "must carry the caller-observed time, never zero",
        });
    }
    Ok(())
}
