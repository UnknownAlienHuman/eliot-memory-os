//! Kernel-owned single integration-owner lease path (issue #1818, W2).
//!
//! Architecture: I10.16 governed integration of candidate implementations.
//! Each mutable target (branch/deliverable) has exactly one active
//! integration owner and lease. This module is the Kernel-mechanical half of
//! that owner path: the lease shape, the named acquire check
//! [`acquire_integration_lease`] (stable name
//! [`INTEGRATION_LEASE_ACQUIRE_NAME`]) which revalidates base revision, State
//! Fence, changed paths, declared effects, and dirty human work against the
//! W1 candidate record before any integration work starts, and the stale
//! transition it produces when the target base moved under a candidate that
//! depends on it. Durability stays with the canonical Store through the
//! existing Store bridge; this module keeps no rows and runs no verifier.
//!
//! # Production chain
//!
//! The governed bridge-apply slice (W3) calls [`acquire_integration_lease`]
//! for the queued candidate it intends to integrate, passing the
//! already-known candidates it read back through the Store bridge (so the
//! candidate is loaded through W1's `read_integration_candidate`, never a
//! second lookup scheme) together with the live target base, the live State
//! Fence, the caller-observed path/effect sets, the observed dirty paths,
//! and the currently active leases. A granted lease gates the W3 pre-apply
//! verifier and the governed bridge apply; a typed refusal leaves the
//! candidate queued, and a stale base produces the `Stale` record the bridge
//! persists instead of applying. The stable [`INTEGRATION_LEASE_ACQUIRE_NAME`]
//! and [`INTEGRATION_LEASE_SCHEMA_V1`] constants are the exact keys the
//! bridge-apply slice registers on the Store bridge; they are declared here
//! so the names cannot drift between the Kernel surface and the bridge
//! registration.
//!
//! # What this deliberately does not do
//!
//! No verifier execution, no bridge apply, no `OutcomeReceipt`, no
//! integration-pressure counters, and no release or expiry: those are the
//! W3/A1 slices. A granted lease covers exactly one `(target, candidate)`
//! pair; the holder releases it through the W3 outcome path before any
//! re-acquire, so a re-acquire while held (even by the same candidate) is
//! the typed [`IntegrationLeaseError::LeaseHeld`] refusal, never a second
//! lease.
//!
//! # Relation to the coordination record
//!
//! `eliot-coordination` already types an `IntegrationLease` for the
//! Governor-side coordination owner (session-held, expiring coordination
//! events). That vocabulary is Governor semantics, which the Kernel
//! composition root must not duplicate or interpret (`bins/AGENTS.md`).
//! This lease is the Kernel-mechanical admission shape built only from the
//! W1 record types and foundation contracts (`StateFence` and
//! `fences_match_exact`): the target scope, the exact base commit, the exact
//! fence, and the revalidated path/effect sets. It carries no session, no
//! expiry, and no coordination event.

use std::collections::BTreeSet;

use eliot_contracts::{ContractError, StateFence, fences_match_exact};
use serde::{Deserialize, Serialize};

use crate::integration_candidate::{
    IntegrationCandidate, IntegrationCandidateError, IntegrationCandidateRevision,
    IntegrationCandidateStatus, MAX_BASE_LEN, MAX_IDENTITY_LEN, read_integration_candidate,
};

/// Schema identifier for persisted lease rows. The Store bridge slice
/// registers this exact key; the Kernel surface never mints a second one.
pub const INTEGRATION_LEASE_SCHEMA_V1: &str = "eliot.integration.lease.v1";
/// Stable named acquire. The bridge-apply slice registers this exact name
/// for the single leaseable integration-owner path.
pub const INTEGRATION_LEASE_ACQUIRE_NAME: &str = "AcquireIntegrationLease";

/// Typed lease-surface failures. Every refusal names its reason; the held
/// and stale cases name the exact target, holder, or carried record. No
/// refusal grants a lease.
#[derive(Clone, Debug)]
pub enum IntegrationLeaseError {
    /// A lease-request field failed admission bounds. No lease was granted.
    InvalidField {
        /// Closed field name, never a value.
        field: &'static str,
        /// Stable reason, never a value.
        reason: &'static str,
    },
    /// The W1 candidate read failed. No lease was granted.
    Candidate(Box<IntegrationCandidateError>),
    /// The candidate targets a different scope than the requested lease.
    /// No lease was granted.
    TargetMismatch {
        /// Requested lease scope.
        target_scope: String,
        /// Scope the candidate record carries.
        candidate_target: String,
    },
    /// The candidate is not admissible for the lease (only `Proposed` and
    /// `Ready` may take it). The candidate keeps its status. No lease was
    /// granted.
    CandidateNotQueued {
        /// Exact identity that was refused.
        candidate_id: String,
        /// Status that made it inadmissible.
        status: IntegrationCandidateStatus,
    },
    /// The target already has an active lease held by another candidate.
    /// The requesting candidate remains queued. No lease was granted.
    LeaseHeld {
        /// Target scope the active lease covers.
        target_scope: String,
        /// Candidate holding the active lease.
        holder_candidate_id: String,
    },
    /// The target base moved under a candidate that depends on it. The
    /// carried record is already transitioned to `Stale` for the bridge to
    /// persist; it must never be applied.
    StaleMarked {
        /// Candidate record transitioned to `Stale` with its history entry.
        stale: Box<IntegrationCandidate>,
    },
    /// The carried State Fence failed its own owner validation.
    Foundation(ContractError),
    /// The live State Fence does not exactly match the candidate's fence.
    /// No lease was granted.
    FenceMismatch,
    /// The caller-observed changed paths do not exactly match the
    /// candidate's manifest. No lease was granted.
    PathMismatch,
    /// The caller-observed declared effects do not exactly match the
    /// candidate's declared sets. No lease was granted.
    EffectMismatch,
    /// Dirty human work overlaps the candidate's changed paths. Fail-closed:
    /// no lease was granted.
    DirtyHumanChanges {
        /// Sorted overlapping repo-relative paths.
        overlapping: Vec<String>,
    },
}

impl std::fmt::Display for IntegrationLeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField { field, reason } => {
                write!(f, "invalid integration lease field {field}: {reason}")
            }
            Self::Candidate(error) => {
                write!(f, "integration lease candidate: {error}")
            }
            Self::TargetMismatch {
                target_scope,
                candidate_target,
            } => write!(
                f,
                "integration lease target mismatch: lease asks {target_scope}, candidate carries {candidate_target}"
            ),
            Self::CandidateNotQueued {
                candidate_id,
                status,
            } => write!(
                f,
                "integration candidate {candidate_id} is not leaseable in status {status:?}"
            ),
            Self::LeaseHeld {
                target_scope,
                holder_candidate_id,
            } => write!(
                f,
                "integration lease for {target_scope} already held by {holder_candidate_id}"
            ),
            Self::StaleMarked { stale } => write!(
                f,
                "integration candidate {} is stale on its base and must never apply",
                stale.candidate_id
            ),
            Self::Foundation(error) => {
                write!(f, "integration lease foundation contract: {error}")
            }
            Self::FenceMismatch => write!(
                f,
                "integration lease fence mismatch: live fence is not the candidate fence"
            ),
            Self::PathMismatch => write!(
                f,
                "integration lease path mismatch: observed paths are not the candidate manifest"
            ),
            Self::EffectMismatch => write!(
                f,
                "integration lease effect mismatch: observed effects are not the candidate sets"
            ),
            Self::DirtyHumanChanges { overlapping } => write!(
                f,
                "integration lease refused: dirty human changes overlap {}",
                overlapping.join(",")
            ),
        }
    }
}

impl std::error::Error for IntegrationLeaseError {}

/// Caller-observed acquire input for one `(target, candidate)` pair. The
/// bridge-apply slice decodes this from its typed request and proves every
/// observed set against the live target before calling
/// [`acquire_integration_lease`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationOwnerLeaseRequest {
    /// Mutable target the lease is acquired for.
    pub target_scope: String,
    /// Candidate taking the lease.
    pub candidate_id: String,
    /// Live base revision of the target at acquire time.
    pub current_base_commit: String,
    /// Whether the candidate depends on the base it was produced against.
    /// A moved base marks the candidate stale only when this is true; a
    /// candidate that does not depend on the moved base is unaffected.
    /// The dependency itself is joined from the queue/dependency projection
    /// by the caller, never inferred here.
    pub candidate_depends_on_base: bool,
    /// Live State Fence of the target at acquire time.
    pub current_fence: StateFence,
    /// Caller-observed changed paths at acquire time; must exactly match
    /// the candidate manifest.
    pub observed_changed_paths: BTreeSet<String>,
    /// Caller-observed declared read effects; must exactly match.
    pub observed_read_effects: BTreeSet<String>,
    /// Caller-observed declared write effects; must exactly match.
    pub observed_write_effects: BTreeSet<String>,
    /// Dirty human paths observed in the target at acquire time. Any
    /// overlap with the candidate manifest fails closed.
    pub dirty_paths: BTreeSet<String>,
    /// Caller-observed time of the acquire, Unix milliseconds, never zero.
    pub observed_at_unix_ms: u64,
}

/// The single active integration-owner lease for one mutable target. Bound
/// to the exact candidate, base, and fence revalidated at acquire time;
/// the path/effect sets that were proven live with the lease.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationOwnerLease {
    /// Mutable target this lease covers. Exactly one active lease exists
    /// per scope.
    pub target_scope: String,
    /// Candidate holding the lease.
    pub candidate_id: String,
    /// Base revision revalidated at acquire time.
    pub base_commit: String,
    /// State Fence revalidated at acquire time.
    pub state_fence: StateFence,
    /// Lease-bound changed-path manifest proven at acquire time.
    pub changed_paths: BTreeSet<String>,
    /// Lease-bound declared read effects proven at acquire time.
    pub declared_read_effects: BTreeSet<String>,
    /// Lease-bound declared write effects proven at acquire time.
    pub declared_write_effects: BTreeSet<String>,
    /// Acquire time, Unix milliseconds.
    pub acquired_at_unix_ms: u64,
}

/// Named acquire (`AcquireIntegrationLease`).
///
/// Revalidates the W1 candidate record for `request.candidate_id` (read
/// through `read_integration_candidate` over the caller-read-back view;
/// this function stores nothing itself) against the live target carried in
/// `request`, and grants the single active lease for the target.
///
/// Checks run in order: request bounds, candidate identity, target-scope
/// agreement, leaseable status, single active lease per target, stale base
/// (moved base the candidate depends on yields the `Stale` record and never
/// applies), State Fence owner validation plus exact fence match,
/// changed-path set match, declared-effect set match, and dirty human work
/// overlap. The first failure wins; only every check passing grants the
/// lease. `active_leases` is the caller-read-back lease view (the Store
/// bridge readback in production).
pub fn acquire_integration_lease(
    candidates: &[IntegrationCandidate],
    active_leases: &[IntegrationOwnerLease],
    request: &IntegrationOwnerLeaseRequest,
) -> Result<IntegrationOwnerLease, IntegrationLeaseError> {
    require_text(&request.target_scope, "target_scope", MAX_IDENTITY_LEN)?;
    require_text(&request.candidate_id, "candidate_id", MAX_IDENTITY_LEN)?;
    require_base_commit(&request.current_base_commit)?;
    if request.observed_at_unix_ms == 0 {
        return Err(IntegrationLeaseError::InvalidField {
            field: "observed_at_unix_ms",
            reason: "must carry the caller-observed time, never zero",
        });
    }
    let candidate = read_integration_candidate(candidates, &request.candidate_id)
        .map_err(|error| IntegrationLeaseError::Candidate(Box::new(error)))?;
    if candidate.target_scope != request.target_scope {
        return Err(IntegrationLeaseError::TargetMismatch {
            target_scope: request.target_scope.clone(),
            candidate_target: candidate.target_scope.clone(),
        });
    }
    if !is_leaseable_status(candidate.status) {
        return Err(IntegrationLeaseError::CandidateNotQueued {
            candidate_id: candidate.candidate_id.clone(),
            status: candidate.status,
        });
    }
    if let Some(holder) = active_leases
        .iter()
        .find(|lease| lease.target_scope == request.target_scope)
    {
        return Err(IntegrationLeaseError::LeaseHeld {
            target_scope: request.target_scope.clone(),
            holder_candidate_id: holder.candidate_id.clone(),
        });
    }
    if candidate.base_commit != request.current_base_commit && request.candidate_depends_on_base {
        return Err(IntegrationLeaseError::StaleMarked {
            stale: Box::new(mark_stale(candidate, request.observed_at_unix_ms)),
        });
    }
    candidate
        .state_fence
        .validate()
        .map_err(IntegrationLeaseError::Foundation)?;
    request
        .current_fence
        .validate()
        .map_err(IntegrationLeaseError::Foundation)?;
    if !fences_match_exact(&candidate.state_fence, &request.current_fence) {
        return Err(IntegrationLeaseError::FenceMismatch);
    }
    if candidate.changed_paths != request.observed_changed_paths {
        return Err(IntegrationLeaseError::PathMismatch);
    }
    if candidate.declared_read_effects != request.observed_read_effects
        || candidate.declared_write_effects != request.observed_write_effects
    {
        return Err(IntegrationLeaseError::EffectMismatch);
    }
    let overlapping: Vec<String> = candidate
        .changed_paths
        .iter()
        .filter(|path| request.dirty_paths.contains(*path))
        .cloned()
        .collect();
    if !overlapping.is_empty() {
        return Err(IntegrationLeaseError::DirtyHumanChanges { overlapping });
    }
    Ok(IntegrationOwnerLease {
        target_scope: request.target_scope.clone(),
        candidate_id: candidate.candidate_id.clone(),
        base_commit: candidate.base_commit.clone(),
        state_fence: candidate.state_fence.clone(),
        changed_paths: candidate.changed_paths.clone(),
        declared_read_effects: candidate.declared_read_effects.clone(),
        declared_write_effects: candidate.declared_write_effects.clone(),
        acquired_at_unix_ms: request.observed_at_unix_ms,
    })
}

/// Whether a lifecycle status may take the single active lease. Only
/// admissible, pre-integration statuses qualify; the holder itself moves to
/// `Integrating` on the W3 outcome path, never here.
fn is_leaseable_status(status: IntegrationCandidateStatus) -> bool {
    matches!(
        status,
        IntegrationCandidateStatus::Proposed | IntegrationCandidateStatus::Ready
    )
}

/// Transitions a base-moved record to `Stale` with its history entry. The
/// bridge persists the returned record; the stale candidate is never
/// applied.
fn mark_stale(candidate: &IntegrationCandidate, observed_at_unix_ms: u64) -> IntegrationCandidate {
    let mut stale = candidate.clone();
    stale.status = IntegrationCandidateStatus::Stale;
    stale.history.push(IntegrationCandidateRevision {
        status: IntegrationCandidateStatus::Stale,
        observed_at_unix_ms,
    });
    stale
}

/// Requires bounded, non-blank text with no control characters, mirroring
/// the Store owner's text rule plus an admission length bound.
fn require_text(
    value: &str,
    field: &'static str,
    max_len: usize,
) -> Result<(), IntegrationLeaseError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(IntegrationLeaseError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    if value.len() > max_len {
        return Err(IntegrationLeaseError::InvalidField {
            field,
            reason: "exceeds admission bound",
        });
    }
    Ok(())
}

/// Requires the live base revision to be compact visible ASCII with no
/// whitespace, mirroring the candidate base rule so the two can be
/// compared exactly.
fn require_base_commit(base_commit: &str) -> Result<(), IntegrationLeaseError> {
    require_text(base_commit, "current_base_commit", MAX_BASE_LEN)?;
    if !base_commit.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(IntegrationLeaseError::InvalidField {
            field: "current_base_commit",
            reason: "must be visible ASCII with no whitespace",
        });
    }
    Ok(())
}
