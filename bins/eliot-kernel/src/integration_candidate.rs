//! Kernel-owned canonical integration-candidate record (issue #1818, W1).
//!
//! Architecture: I10.16 governed integration of candidate implementations.
//! Every mutating swarm result must create a canonical `IntegrationCandidate`
//! carrying identity, task/work-item, producer lineage, base commit and State
//! Fence, artifact/worktree refs, changed-path manifest, declared effects,
//! verification evidence, unresolved conflicts, rollback/compensation, and an
//! explicit lifecycle status. `IntegrationQueue` is only a projection over
//! candidates, never a second scheduler or store.
//!
//! This module is the Kernel-mechanical half of that contract: the record
//! shape, the named create mutation
//! ([`create_integration_candidate`], stable name
//! [`INTEGRATION_CANDIDATE_CREATE_NAME`]) which validates base, fence, paths
//! and effects and rejects duplicate identities, the named read by identity
//! ([`read_integration_candidate`], stable name
//! [`INTEGRATION_CANDIDATE_READ_NAME`]), and the derived queue projection
//! ([`project_integration_queue`]). Durability stays with the canonical Store
//! through the existing Store bridge; this module builds no scheduler, keeps
//! no rows, and owns no lease.
//!
//! # Production chain
//!
//! The W2 lease path calls [`create_integration_candidate`] for every
//! mutating swarm result before any integration work starts, passing the
//! already-known candidates it read back through the Store bridge so a
//! retried submission with a reused identity is rejected as
//! [`IntegrationCandidateError::Duplicate`] instead of recorded twice. The
//! governed bridge-apply slice (W3) calls [`read_integration_candidate`] by
//! exact identity and renders [`project_integration_queue`] per target scope
//! to decide which candidate the single active integration lease may take.
//! The stable `*_NAME` and `*_SCHEMA_V1` constants are the exact keys those
//! slices register on the Store bridge; they are declared here so the names
//! cannot drift between the Kernel surface and the bridge registration.
//!
//! # Live status
//!
//! [`create_integration_candidate`] has no caller. Measured on this tree, no
//! code in any crate names it other than its defining line and the prose above,
//! and the daemon front door registers no `INTEGRATION_CANDIDATE_CREATE_NAME`
//! key — only `INTEGRATION_BRIDGE_APPLY_NAME` is dispatched — so the
//! create-then-read chain this paragraph describes is not compiled. The read
//! and queue halves are reached: the W2 lease path and the W3 bridge-apply path
//! both call [`read_integration_candidate`], and the owner advance calls
//! [`project_integration_queue`]. The create half is the unwired one; no
//! caller was invented to close it.
//!
//! # What this deliberately does not do
//!
//! No lease path, no verifier execution, no bridge apply, no
//! `OutcomeReceipt`, no integration-pressure counters, and no stale-marking:
//! those are the W2/W3/A1 slices. A candidate created here starts at
//! [`IntegrationCandidateStatus::Proposed`]; every later transition is owned
//! by the slice that performs it.
//!
//! # Relation to the coordination record
//!
//! `eliot-coordination` already types an `IntegrationCandidate` for the
//! Governor-side coordination owner (coordination events, lease decisions,
//! peer-review correlation). That vocabulary is Governor semantics, which the
//! Kernel composition root must not duplicate or interpret
//! (`bins/AGENTS.md`). This record is the Kernel-mechanical admission shape
//! built only from foundation contracts (`StateFence`) and plain bounded
//! text, following the `blackboard` precedent: Kernel binds the candidate to
//! its task, fence, paths and effects, while semantic meaning stays with the
//! producing owner.

use std::collections::BTreeSet;

use eliot_contracts::{ContractError, StateFence};
use serde::{Deserialize, Serialize};

/// Schema identifier for persisted candidate records. The Store bridge slice
/// registers this exact key; the Kernel surface never mints a second one.
pub const INTEGRATION_CANDIDATE_SCHEMA_V1: &str = "eliot.integration.candidate.v1";
/// Stable named create mutation. The bridge-apply slice registers this exact
/// name for candidate admission.
pub const INTEGRATION_CANDIDATE_CREATE_NAME: &str = "CreateIntegrationCandidate";
/// Stable named read. The bridge-apply slice registers this exact name for
/// exact-identity candidate readback.
pub const INTEGRATION_CANDIDATE_READ_NAME: &str = "GetIntegrationCandidate";

/// Bound for every identity-shaped field: candidate, task, work-item,
/// producer attempt, target scope, and request identities.
pub const MAX_IDENTITY_LEN: usize = 256;
/// Bound for the base revision a candidate was produced against.
pub const MAX_BASE_LEN: usize = 128;
/// Bound for one reference entry: lineage, worktree/artifact, evidence,
/// verification, conflict, and rollback/compensation text.
pub const MAX_REF_LEN: usize = 1024;
/// Bound for one changed-path manifest entry (repo-relative path text).
pub const MAX_PATH_LEN: usize = 1024;
/// Bound for one declared effect entry (`domain.action:scope` text).
pub const MAX_EFFECT_LEN: usize = 256;
/// Maximum producer-lineage entries retained on one candidate.
pub const MAX_LINEAGE_ENTRIES: usize = 64;
/// Maximum worktree/artifact refs retained on one candidate.
pub const MAX_CANDIDATE_REFS: usize = 256;
/// Maximum evidence, verification, and conflict entries each.
pub const MAX_EVIDENCE_ENTRIES: usize = 256;
/// Maximum changed paths in one manifest.
pub const MAX_CHANGED_PATHS: usize = 4096;
/// Maximum declared read plus write effects on one candidate.
pub const MAX_DECLARED_EFFECTS: usize = 1024;

/// Typed candidate-surface failures. Every rejection names its field and
/// reason; duplicates and misses name the exact identity.
#[derive(Clone, Debug)]
pub enum IntegrationCandidateError {
    /// A field failed admission bounds. No candidate was recorded.
    InvalidField {
        /// Closed field name, never a value.
        field: &'static str,
        /// Stable reason, never a value.
        reason: &'static str,
    },
    /// The candidate identity is already known. No second record was created.
    Duplicate {
        /// Exact identity that collided.
        candidate_id: String,
    },
    /// No candidate carries the requested identity.
    NotFound {
        /// Exact identity that was looked up.
        candidate_id: String,
    },
    /// The carried State Fence failed its own owner validation.
    Foundation(ContractError),
}

impl std::fmt::Display for IntegrationCandidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField { field, reason } => {
                write!(f, "invalid integration candidate field {field}: {reason}")
            }
            Self::Duplicate { candidate_id } => {
                write!(f, "duplicate integration candidate {candidate_id}")
            }
            Self::NotFound { candidate_id } => {
                write!(f, "integration candidate not found: {candidate_id}")
            }
            Self::Foundation(error) => {
                write!(f, "integration candidate foundation contract: {error}")
            }
        }
    }
}

impl std::error::Error for IntegrationCandidateError {}

/// Explicit lifecycle status of one canonical candidate.
///
/// W1 creates every candidate as [`Proposed`](Self::Proposed). The lease path
/// (W2) advances `Proposed` to `Ready` and `Integrating`; the bridge-apply
/// slice (W3) records `Accepted`, `Rejected`, `Conflicted`, or
/// `UnknownOutcome` and marks `Stale`. No transition happens here.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationCandidateStatus {
    /// Admitted by [`create_integration_candidate`], awaiting review/lease.
    Proposed,
    /// Reviewed and admissible for the single active integration lease (W2).
    Ready,
    /// Superseded by a newer base it depends on; needs a fresh draft (W3).
    Stale,
    /// Held by the single active integration lease for its target (W2).
    Integrating,
    /// Applied through the governed bridge with an `OutcomeReceipt` (W3).
    Accepted,
    /// Refused before apply; history retained (W3).
    Rejected,
    /// Semantic conflict held as durable conflict work, never auto-merged (W3).
    Conflicted,
    /// Apply outcome unknown; reconcile by exact retry identity only (W3).
    UnknownOutcome,
}

/// One immutable lifecycle observation on a candidate. W1 records exactly the
/// creation observation; later slices append their own transitions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCandidateRevision {
    /// Lifecycle status observed at this revision.
    pub status: IntegrationCandidateStatus,
    /// Producer-observed time of the observation, Unix milliseconds.
    pub observed_at_unix_ms: u64,
}

/// Unvalidated creation input for one mutating swarm result. `request_id` is
/// the exact retry identity: a retried submission reuses it, and the bridge
/// reconciles an unknown outcome against it instead of recording a second
/// candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCandidateDraft {
    /// Exact retry identity for this submission.
    pub request_id: String,
    /// Stable identity for the candidate across its lifecycle.
    pub candidate_id: String,
    /// Task that owns the work.
    pub task_id: String,
    /// Work item the mutating result was produced for.
    pub source_work_item_id: String,
    /// Producer attempt that produced the result.
    pub producer_attempt: String,
    /// Producer lineage evidence supplied by the semantic producer. The Kernel
    /// retains this evidence but does not authenticate its provenance.
    pub producer_lineage: Vec<String>,
    /// Base revision the result was produced against.
    pub base_commit: String,
    /// Fence at which the candidate was admitted.
    pub state_fence: StateFence,
    /// Worktree or artifact refs locating the implementation.
    pub worktree_or_artifact_refs: Vec<String>,
    /// Repo-relative changed-path manifest.
    pub changed_paths: BTreeSet<String>,
    /// Declared read effects (`domain.action:scope`).
    pub declared_read_effects: BTreeSet<String>,
    /// Declared write effects (`domain.action:scope`).
    pub declared_write_effects: BTreeSet<String>,
    /// Verification evidence refs known at creation; the pre-apply verifier
    /// receipt arrives on the lease path (W2).
    pub verification_refs: Vec<String>,
    /// Conflicts known at creation; empty when none are known.
    pub unresolved_conflicts: Vec<String>,
    /// Declared rollback or compensation; executed on failure by W3.
    pub rollback_or_compensation: Option<String>,
    /// Mutable target this candidate integrates into.
    pub target_scope: String,
    /// Producer-observed submission time, Unix milliseconds, never zero.
    pub submitted_at_unix_ms: u64,
}

/// The Kernel-owned canonical candidate record. Immutable after creation;
/// every later lifecycle step appends history through its owning slice.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCandidate {
    /// Exact retry identity that created this record.
    pub request_id: String,
    /// Stable identity for the candidate across its lifecycle.
    pub candidate_id: String,
    /// Task that owns the work.
    pub task_id: String,
    /// Work item the mutating result was produced for.
    pub source_work_item_id: String,
    /// Producer attempt that produced the result.
    pub producer_attempt: String,
    /// Producer lineage evidence supplied by the semantic producer.
    pub producer_lineage: Vec<String>,
    /// Base revision the result was produced against.
    pub base_commit: String,
    /// Fence at which the candidate was admitted.
    pub state_fence: StateFence,
    /// Worktree or artifact refs locating the implementation.
    pub worktree_or_artifact_refs: Vec<String>,
    /// Repo-relative changed-path manifest.
    pub changed_paths: BTreeSet<String>,
    /// Declared read effects (`domain.action:scope`).
    pub declared_read_effects: BTreeSet<String>,
    /// Declared write effects (`domain.action:scope`).
    pub declared_write_effects: BTreeSet<String>,
    /// Verification evidence refs known so far.
    pub verification_refs: Vec<String>,
    /// Conflicts known so far; empty when none are known.
    pub unresolved_conflicts: Vec<String>,
    /// Declared rollback or compensation.
    pub rollback_or_compensation: Option<String>,
    /// Mutable target this candidate integrates into.
    pub target_scope: String,
    /// Producer-observed submission time, Unix milliseconds.
    pub submitted_at_unix_ms: u64,
    /// Explicit lifecycle status, starting at `Proposed`.
    pub status: IntegrationCandidateStatus,
    /// Immutable lifecycle observations, starting with creation.
    pub history: Vec<IntegrationCandidateRevision>,
}

/// Derived queue projection for one mutable target. This is a pure view over
/// already-known candidates, never a scheduler or a store: lease,
/// dependency, and approval narrowing join this projection in W2/W3.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationQueue {
    /// Target scope this projection was derived for.
    pub target_scope: String,
    /// Admissible candidates ordered by `(submitted_at_unix_ms, candidate_id)`.
    pub queued: Vec<IntegrationCandidate>,
}

/// Named create mutation (`CreateIntegrationCandidate`).
///
/// Validates the draft's base, fence, paths, and effects, rejects a draft
/// whose identity is already present in `existing`, and returns the canonical
/// record starting at [`IntegrationCandidateStatus::Proposed`] with its
/// creation revision. `existing` is the caller-read-back candidate view (the
/// Store bridge readback in production); this function stores nothing itself.
pub fn create_integration_candidate(
    draft: IntegrationCandidateDraft,
    existing: &[IntegrationCandidate],
) -> Result<IntegrationCandidate, IntegrationCandidateError> {
    validate_candidate_draft(&draft)?;
    reject_duplicate_candidate(&draft, existing)?;
    let creation = IntegrationCandidateRevision {
        status: IntegrationCandidateStatus::Proposed,
        observed_at_unix_ms: draft.submitted_at_unix_ms,
    };
    Ok(IntegrationCandidate {
        request_id: draft.request_id,
        candidate_id: draft.candidate_id,
        task_id: draft.task_id,
        source_work_item_id: draft.source_work_item_id,
        producer_attempt: draft.producer_attempt,
        producer_lineage: draft.producer_lineage,
        base_commit: draft.base_commit,
        state_fence: draft.state_fence,
        worktree_or_artifact_refs: draft.worktree_or_artifact_refs,
        changed_paths: draft.changed_paths,
        declared_read_effects: draft.declared_read_effects,
        declared_write_effects: draft.declared_write_effects,
        verification_refs: draft.verification_refs,
        unresolved_conflicts: draft.unresolved_conflicts,
        rollback_or_compensation: draft.rollback_or_compensation,
        target_scope: draft.target_scope,
        submitted_at_unix_ms: draft.submitted_at_unix_ms,
        status: IntegrationCandidateStatus::Proposed,
        history: vec![creation],
    })
}

/// Named read by identity (`GetIntegrationCandidate`).
///
/// Returns the exact candidate carrying `candidate_id`, or
/// [`IntegrationCandidateError::NotFound`]. The caller supplies the
/// read-back view; this function interprets nothing beyond identity.
pub fn read_integration_candidate<'a>(
    candidates: &'a [IntegrationCandidate],
    candidate_id: &str,
) -> Result<&'a IntegrationCandidate, IntegrationCandidateError> {
    require_text(candidate_id, "candidate_id", MAX_IDENTITY_LEN)?;
    candidates
        .iter()
        .find(|candidate| candidate.candidate_id == candidate_id)
        .ok_or_else(|| IntegrationCandidateError::NotFound {
            candidate_id: candidate_id.to_owned(),
        })
}

/// Derives the integration queue for one target scope.
///
/// The projection holds the scope's `Proposed` and `Ready` candidates ordered
/// by `(submitted_at_unix_ms, candidate_id)`. Terminal (`Accepted`,
/// `Rejected`) and parked (`Stale`, `Conflicted`, `Integrating`,
/// `UnknownOutcome`) candidates stay addressable through
/// [`read_integration_candidate`] but never join the queue, so the single
/// active lease (W2) can only take an admissible candidate.
pub fn project_integration_queue(
    candidates: &[IntegrationCandidate],
    target_scope: &str,
) -> Result<IntegrationQueue, IntegrationCandidateError> {
    require_text(target_scope, "target_scope", MAX_IDENTITY_LEN)?;
    let mut queued: Vec<IntegrationCandidate> = candidates
        .iter()
        .filter(|candidate| {
            candidate.target_scope == target_scope && is_queued_status(candidate.status)
        })
        .cloned()
        .collect();
    queued.sort_by(|a, b| {
        (a.submitted_at_unix_ms, &a.candidate_id).cmp(&(b.submitted_at_unix_ms, &b.candidate_id))
    });
    Ok(IntegrationQueue {
        target_scope: target_scope.to_owned(),
        queued,
    })
}

/// Validates every draft field: identities, base, fence, lineage, refs,
/// changed-path manifest, declared effects, rollback plan, and timestamp.
fn validate_candidate_draft(
    draft: &IntegrationCandidateDraft,
) -> Result<(), IntegrationCandidateError> {
    require_text(&draft.request_id, "request_id", MAX_IDENTITY_LEN)?;
    require_text(&draft.candidate_id, "candidate_id", MAX_IDENTITY_LEN)?;
    require_text(&draft.task_id, "task_id", MAX_IDENTITY_LEN)?;
    require_text(
        &draft.source_work_item_id,
        "source_work_item_id",
        MAX_IDENTITY_LEN,
    )?;
    require_text(
        &draft.producer_attempt,
        "producer_attempt",
        MAX_IDENTITY_LEN,
    )?;
    require_text(&draft.target_scope, "target_scope", MAX_IDENTITY_LEN)?;
    require_base_commit(&draft.base_commit)?;
    draft
        .state_fence
        .validate()
        .map_err(IntegrationCandidateError::Foundation)?;
    require_ref_list(
        &draft.producer_lineage,
        "producer_lineage",
        MAX_LINEAGE_ENTRIES,
        1,
    )?;
    require_ref_list(
        &draft.worktree_or_artifact_refs,
        "worktree_or_artifact_refs",
        MAX_CANDIDATE_REFS,
        1,
    )?;
    require_ref_list(
        &draft.verification_refs,
        "verification_refs",
        MAX_EVIDENCE_ENTRIES,
        0,
    )?;
    require_ref_list(
        &draft.unresolved_conflicts,
        "unresolved_conflicts",
        MAX_EVIDENCE_ENTRIES,
        0,
    )?;
    require_changed_paths(&draft.changed_paths)?;
    require_declared_effects(&draft.declared_read_effects, &draft.declared_write_effects)?;
    if let Some(plan) = &draft.rollback_or_compensation {
        require_text(plan, "rollback_or_compensation", MAX_REF_LEN)?;
    }
    if draft.submitted_at_unix_ms == 0 {
        return Err(IntegrationCandidateError::InvalidField {
            field: "submitted_at_unix_ms",
            reason: "must carry the producer-observed time, never zero",
        });
    }
    Ok(())
}

/// Rejects a draft whose candidate identity is already known. A retried
/// submission keeps its identity and is reconciled by `request_id` on the
/// bridge path (W3); it is never recorded twice here.
fn reject_duplicate_candidate(
    draft: &IntegrationCandidateDraft,
    existing: &[IntegrationCandidate],
) -> Result<(), IntegrationCandidateError> {
    if existing
        .iter()
        .any(|candidate| candidate.candidate_id == draft.candidate_id)
    {
        return Err(IntegrationCandidateError::Duplicate {
            candidate_id: draft.candidate_id.clone(),
        });
    }
    Ok(())
}

/// Whether a lifecycle status may wait in the derived queue. Only admissible,
/// pre-integration statuses qualify; terminal and parked statuses stay
/// readable but never queueable.
fn is_queued_status(status: IntegrationCandidateStatus) -> bool {
    matches!(
        status,
        IntegrationCandidateStatus::Proposed | IntegrationCandidateStatus::Ready
    )
}

/// Requires bounded, non-blank text with no control characters, mirroring the
/// Store owner's text rule plus an admission length bound.
fn require_text(
    value: &str,
    field: &'static str,
    max_len: usize,
) -> Result<(), IntegrationCandidateError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(IntegrationCandidateError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    if value.len() > max_len {
        return Err(IntegrationCandidateError::InvalidField {
            field,
            reason: "exceeds admission bound",
        });
    }
    Ok(())
}

/// Requires a bounded reference list with at least `min_entries` entries.
/// Every entry is bounded non-blank text.
fn require_ref_list(
    refs: &[String],
    field: &'static str,
    max_entries: usize,
    min_entries: usize,
) -> Result<(), IntegrationCandidateError> {
    if refs.len() < min_entries {
        return Err(IntegrationCandidateError::InvalidField {
            field,
            reason: "must name at least one entry",
        });
    }
    if refs.len() > max_entries {
        return Err(IntegrationCandidateError::InvalidField {
            field,
            reason: "exceeds admission bound",
        });
    }
    for entry in refs {
        require_text(entry, field, MAX_REF_LEN)?;
    }
    Ok(())
}

/// Requires the base revision to be compact visible ASCII with no whitespace:
/// a blank, multi-line, or unbounded base cannot be revalidated against the
/// live target on the lease path (W2), so it is refused here.
fn require_base_commit(base_commit: &str) -> Result<(), IntegrationCandidateError> {
    require_text(base_commit, "base_commit", MAX_BASE_LEN)?;
    if !base_commit.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(IntegrationCandidateError::InvalidField {
            field: "base_commit",
            reason: "must be visible ASCII with no whitespace",
        });
    }
    Ok(())
}

/// Requires a non-empty, bounded, repo-relative changed-path manifest. The
/// manifest is the scope the lease path (W2) checks for dirty human work and
/// effect overlap, so absolute paths and parent escapes are refused here
/// rather than widened silently at apply time (W3).
fn require_changed_paths(paths: &BTreeSet<String>) -> Result<(), IntegrationCandidateError> {
    if paths.is_empty() {
        return Err(IntegrationCandidateError::InvalidField {
            field: "changed_paths",
            reason: "a mutating result must declare at least one changed path",
        });
    }
    if paths.len() > MAX_CHANGED_PATHS {
        return Err(IntegrationCandidateError::InvalidField {
            field: "changed_paths",
            reason: "exceeds admission bound",
        });
    }
    for path in paths {
        require_changed_path(path)?;
    }
    Ok(())
}

/// Requires one manifest entry to be bounded text that stays inside the
/// target scope: repo-relative, never absolute, never escaping via `..`.
fn require_changed_path(path: &str) -> Result<(), IntegrationCandidateError> {
    require_text(path, "changed_paths", MAX_PATH_LEN)?;
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(IntegrationCandidateError::InvalidField {
            field: "changed_paths",
            reason: "must be repo-relative, never absolute",
        });
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(IntegrationCandidateError::InvalidField {
            field: "changed_paths",
            reason: "must be repo-relative, never absolute",
        });
    }
    if path.split(['/', '\\']).any(|segment| segment == "..") {
        return Err(IntegrationCandidateError::InvalidField {
            field: "changed_paths",
            reason: "must not escape the target scope",
        });
    }
    Ok(())
}

/// Requires bounded declared effects with at least one write effect. A
/// mutating result that declares no write effect would silently never overlap
/// on the W2 conflict check, so the empty write set is refused fail-closed.
fn require_declared_effects(
    reads: &BTreeSet<String>,
    writes: &BTreeSet<String>,
) -> Result<(), IntegrationCandidateError> {
    if reads.len() + writes.len() > MAX_DECLARED_EFFECTS {
        return Err(IntegrationCandidateError::InvalidField {
            field: "declared_effects",
            reason: "exceeds admission bound",
        });
    }
    for effect in reads.iter().chain(writes.iter()) {
        require_text(effect, "declared_effects", MAX_EFFECT_LEN)?;
    }
    if writes.is_empty() {
        return Err(IntegrationCandidateError::InvalidField {
            field: "declared_write_effects",
            reason: "a mutating result must declare at least one write effect",
        });
    }
    Ok(())
}
