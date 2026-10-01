//! Kernel-owned governed integration bridge-apply path (issue #1818, W3).
//!
//! Architecture: I10.16 governed integration of candidate implementations.
//! Each mutable target has exactly one active integration owner and lease.
//! This module is the Kernel-mechanical half of the apply path: the named
//! bridge apply ([`apply_integration_candidate`], stable name
//! [`INTEGRATION_BRIDGE_APPLY_NAME`]) which acquires the W2 lease first, runs
//! the declared verifier in the candidate environment before apply, applies
//! only through the candidate's changed-path manifest, records a post-apply
//! [`OutcomeReceipt`] (durable under [`INTEGRATION_OUTCOME_SCHEMA_V1`]), and
//! executes declared rollback/compensation on failure while retaining
//! history. Durability stays with the canonical Store through the existing
//! Store bridge; this module keeps no rows and runs no scheduler.
//!
//! # Production chain
//!
//! The bridge takes the caller-read-back candidate and lease views (the Store
//! bridge readback in production, read through W1's
//! `read_integration_candidate`, never a second lookup scheme) plus the live
//! target observations the caller proved against the live target. It calls
//! W2's [`acquire_integration_lease`](crate::integration_lease::acquire_integration_lease)
//! first: a granted lease gates the pre-apply verifier and the governed
//! apply, a typed refusal leaves the candidate queued, and a moved base the
//! candidate depends on yields the `Stale` record which must never apply.
//! The caller persists the returned transitioned candidate and the
//! [`OutcomeReceipt`]; the stable [`INTEGRATION_BRIDGE_APPLY_NAME`] and
//! [`INTEGRATION_OUTCOME_SCHEMA_V1`] constants are the exact keys the Store
//! bridge slice registers, declared here so the names cannot drift between
//! the Kernel surface and the bridge registration.
//!
//! # What this deliberately does not do
//!
//! No candidate creation or queue projection (W1), no lease-shape ownership
//! (W2), no integration-pressure counters and no proof assembly (A1). The
//! verifier, the governed write, and the rollback/compensation execute in
//! the candidate environment through the owning bridge operator; this module
//! admits only their typed observations, binds each observation to the exact
//! candidate, lease, and environment it claims, and refuses fail-closed when
//! any binding breaks. Unrelated dirty work is preserved structurally: the
//! only path set this module may record as applied is exactly the
//! candidate's changed-path manifest, there is no operation here that
//! addresses any other path (never `git reset --hard`), and any live dirty
//! overlap with the manifest refuses before apply.
//!
//! # Relation to other owners
//!
//! Governor-side coordination vocabulary (`eliot-coordination`) and receipt
//! vocabulary (`eliot-receipts`) stay with their owners; this bridge is the
//! Kernel-mechanical admission shape built only from the W1/W2 types and the
//! foundation contracts (`StateFence`), following the `blackboard`
//! precedent. Semantic conflicts become durable [`IntegrationCandidateStatus::Conflicted`]
//! work with their detail in the receipt, never an automatic text merge.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::integration_candidate::{
    IntegrationCandidate, IntegrationCandidateError, IntegrationCandidateRevision,
    IntegrationCandidateStatus, MAX_BASE_LEN, MAX_IDENTITY_LEN, MAX_REF_LEN,
    read_integration_candidate,
};
use crate::integration_lease::{
    IntegrationLeaseError, IntegrationOwnerLease, IntegrationOwnerLeaseRequest,
    acquire_integration_lease,
};

/// Stable named bridge apply. The Store bridge slice registers this exact
/// name for the single governed integration-apply path.
pub const INTEGRATION_BRIDGE_APPLY_NAME: &str = "ApplyIntegrationCandidateBridge";
/// Schema identifier for persisted outcome receipts. The Store bridge slice
/// registers this exact key; the Kernel surface never mints a second one.
pub const INTEGRATION_OUTCOME_SCHEMA_V1: &str = "eliot.integration.outcome.v1";

/// Typed bridge-apply failures. Every refusal names its reason; the
/// verifier-failure case carries the receipt that records the
/// rollback/compensation result while the candidate/history stays intact.
/// No refusal applies anything.
#[derive(Clone, Debug)]
pub enum IntegrationBridgeError {
    /// A bridge-request field failed admission bounds. Nothing was applied.
    InvalidField {
        /// Closed field name, never a value.
        field: &'static str,
        /// Stable reason, never a value.
        reason: &'static str,
    },
    /// The W1 candidate read failed. Nothing was applied.
    Candidate(Box<IntegrationCandidateError>),
    /// The W2 lease acquire refused. The candidate remains queued (or stale
    /// when the carried record moved under a base it depends on, which must
    /// never apply). Nothing was applied.
    Lease(Box<IntegrationLeaseError>),
    /// The granted lease binds a different candidate than the one requested.
    /// Nothing was applied.
    LeaseMismatch {
        /// Candidate identity the granted lease actually binds.
        candidate_id: String,
    },
    /// The verifier observation names an environment outside the candidate's
    /// worktree/artifact refs. Nothing was applied.
    EnvironmentMismatch {
        /// Which observation failed binding: `pre_apply` or `post_apply`.
        role: &'static str,
    },
    /// The declared pre-apply verifier did not pass in the candidate
    /// environment. The candidate and its history are intact; the carried
    /// receipt records the failure and any rollback/compensation result.
    VerifierFailed {
        /// Receipt recording the failure. Never applied.
        receipt: Box<OutcomeReceipt>,
    },
    /// The governed write set is not exactly the candidate manifest.
    /// Nothing was applied.
    ApplyScopeMismatch,
    /// Live dirty human work overlaps the candidate manifest at apply time.
    /// Fail-closed: nothing was applied and unrelated dirty work is intact.
    DirtyHumanChanges {
        /// Sorted overlapping repo-relative paths.
        overlapping: Vec<String>,
    },
    /// A post-apply failure (or conflict-free failed apply) left declared
    /// rollback/compensation unexecuted while the candidate declares a
    /// handle. Execute the declared handle and re-present its evidence.
    /// Nothing further was applied.
    RollbackMissing {
        /// Declared handle that must be executed.
        handle: String,
    },
}

impl std::fmt::Display for IntegrationBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField { field, reason } => {
                write!(f, "invalid integration bridge field {field}: {reason}")
            }
            Self::Candidate(error) => {
                write!(f, "integration bridge candidate: {error}")
            }
            Self::Lease(error) => {
                write!(f, "integration bridge lease: {error}")
            }
            Self::LeaseMismatch { candidate_id } => write!(
                f,
                "integration bridge lease binds {candidate_id}, not the requested candidate"
            ),
            Self::EnvironmentMismatch { role } => write!(
                f,
                "integration bridge {role} verifier ran outside the candidate environment"
            ),
            Self::VerifierFailed { receipt } => write!(
                f,
                "integration bridge pre-apply verifier failed for {}; candidate intact",
                receipt.candidate_id
            ),
            Self::ApplyScopeMismatch => write!(
                f,
                "integration bridge apply set is not the candidate manifest"
            ),
            Self::DirtyHumanChanges { overlapping } => write!(
                f,
                "integration bridge refused: dirty human changes overlap {}",
                overlapping.join(",")
            ),
            Self::RollbackMissing { handle } => write!(
                f,
                "integration bridge requires executed rollback {handle} before recording failure"
            ),
        }
    }
}

impl std::error::Error for IntegrationBridgeError {}

/// Pass/fail verdict of one verifier run observed in an environment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierVerdict {
    /// The declared verifier passed in the bound environment.
    Pass,
    /// The declared verifier failed in the bound environment.
    Fail,
}

/// One typed verifier-run observation. The bridge operator runs the declared
/// verifier in the candidate environment; this observation binds the run to
/// the exact verifier handle, environment, and verdict it claims.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRunObservation {
    /// Declared verifier handle; must be declared in the candidate's
    /// verification refs when the candidate declares any.
    pub verifier_ref: String,
    /// Environment the run executed in; must be one of the candidate's
    /// worktree/artifact refs.
    pub environment_ref: String,
    /// Observed verdict.
    pub verdict: VerifierVerdict,
    /// Caller-observed time of the run, Unix milliseconds, never zero.
    pub observed_at_unix_ms: u64,
}

/// Outcome of one executed rollback/compensation run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackOutcome {
    /// The applied change was reverted.
    Reverted,
    /// The applied change was compensated.
    Compensated,
    /// The rollback/compensation itself failed.
    Failed,
}

/// One typed rollback/compensation execution observation. The bridge
/// operator executes the candidate's declared handle on failure; this
/// observation binds the run to the exact handle and outcome it claims.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackExecution {
    /// Executed handle; must equal the candidate's declared
    /// rollback/compensation handle.
    pub handle: String,
    /// Observed outcome.
    pub outcome: RollbackOutcome,
    /// Caller-observed time of the run, Unix milliseconds, never zero.
    pub observed_at_unix_ms: u64,
}

/// Unvalidated bridge-apply input for one leased candidate. The caller
/// proves every live set against the live target; the bridge admits only
/// their typed observations and binds each one before recording anything.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeApplyRequest {
    /// Stable operation name; must equal [`INTEGRATION_BRIDGE_APPLY_NAME`].
    pub operation: String,
    /// Candidate to integrate; must equal the lease request identity.
    pub candidate_id: String,
    /// W2 acquire input for this `(target, candidate)` pair, carrying the
    /// live base, fence, path/effect sets, and dirty paths the caller proved
    /// at apply time.
    pub lease_request: IntegrationOwnerLeaseRequest,
    /// Declared-verifier run observed in the candidate environment before
    /// apply. A `Fail` verdict leaves the candidate/history intact.
    pub pre_apply: VerifierRunObservation,
    /// Exact governed write set the bridge wrote; must equal the candidate
    /// manifest, so no unrelated path is ever addressed.
    pub applied_changed_paths: BTreeSet<String>,
    /// Dirty human paths observed in the target at apply time. Any overlap
    /// with the manifest refuses before apply.
    pub dirty_paths: BTreeSet<String>,
    /// Declared-verifier run observed after apply. Read only when the
    /// pre-apply verdict passed and no semantic conflict was declared.
    pub post_apply: VerifierRunObservation,
    /// Whether the apply surfaced a semantic conflict. A conflict becomes
    /// durable conflict work; it is never auto-merged and never applied.
    pub semantic_conflict: bool,
    /// Conflict detail; required exactly when `semantic_conflict` is set.
    pub semantic_conflict_detail: Option<String>,
    /// Executed rollback/compensation evidence. Required on a post-apply
    /// failure exactly when the candidate declares a handle.
    pub rollback: Option<RollbackExecution>,
    /// Caller-observed time of the apply, Unix milliseconds, never zero.
    pub observed_at_unix_ms: u64,
}

/// Post-apply outcome receipt for one bridge apply. The caller persists this
/// under [`INTEGRATION_OUTCOME_SCHEMA_V1`]; it binds the candidate retry
/// identity, the granting lease, both verifier runs, the governed write
/// set, and any rollback/compensation result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeReceipt {
    /// Stable identity of the integrated candidate.
    pub candidate_id: String,
    /// Exact retry identity that created the candidate; an `UnknownOutcome`
    /// reconciles by this identity only, never by recording a second
    /// candidate.
    pub request_id: String,
    /// Mutable target the candidate integrated into.
    pub target_scope: String,
    /// Single active lease that gated this apply, with its revalidated base,
    /// fence, and path/effect sets.
    pub lease: IntegrationOwnerLease,
    /// Pre-apply verifier run bound to the candidate environment.
    pub pre_apply: VerifierRunObservation,
    /// Exact governed write set recorded as applied; empty when nothing was
    /// applied (pre-apply failure or semantic conflict).
    pub applied_changed_paths: BTreeSet<String>,
    /// Post-apply verifier run; absent when no apply ran.
    pub post_apply: Option<VerifierRunObservation>,
    /// Whether a semantic conflict was declared; held as durable work.
    pub semantic_conflict: bool,
    /// Conflict detail, present exactly on the conflict path.
    pub semantic_conflict_detail: Option<String>,
    /// Executed rollback/compensation result, when any ran.
    pub rollback: Option<RollbackExecution>,
    /// Lifecycle status the candidate now carries.
    pub final_status: IntegrationCandidateStatus,
    /// Caller-observed time the receipt was recorded, Unix milliseconds.
    pub observed_at_unix_ms: u64,
}

/// Successful bridge apply: the transitioned candidate record (with its
/// appended history entry) and the post-apply receipt. The caller persists
/// both through the Store bridge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeApplySuccess {
    /// Candidate record after its W3 lifecycle transition.
    pub candidate: IntegrationCandidate,
    /// Post-apply outcome receipt.
    pub receipt: OutcomeReceipt,
}

/// Named bridge apply (`ApplyIntegrationCandidateBridge`).
///
/// Acquires the W2 lease first over the caller-read-back views, then runs
/// the declared pre-apply verifier binding, applies only through the exact
/// candidate manifest, records the [`OutcomeReceipt`], and executes declared
/// rollback/compensation on failure with history retained. Semantic
/// conflicts become durable `Conflicted` work and are never merged. Only
/// base-dependent stale marking applies (see [`mark_stale_dependents`] for
/// the queue-wide sweep); the single path propagates W2's stale record and
/// never applies it.
pub fn apply_integration_candidate(
    candidates: &[IntegrationCandidate],
    active_leases: &[IntegrationOwnerLease],
    request: &BridgeApplyRequest,
) -> Result<BridgeApplySuccess, IntegrationBridgeError> {
    if request.operation != INTEGRATION_BRIDGE_APPLY_NAME {
        return Err(IntegrationBridgeError::InvalidField {
            field: "operation",
            reason: "must name the governed bridge apply",
        });
    }
    require_time(request.observed_at_unix_ms, "observed_at_unix_ms")?;
    if request.candidate_id != request.lease_request.candidate_id {
        return Err(IntegrationBridgeError::InvalidField {
            field: "candidate_id",
            reason: "must equal the lease request identity",
        });
    }
    let candidate = read_integration_candidate(candidates, &request.candidate_id)
        .map_err(|error| IntegrationBridgeError::Candidate(Box::new(error)))?;
    let lease = acquire_integration_lease(candidates, active_leases, &request.lease_request)
        .map_err(|error| IntegrationBridgeError::Lease(Box::new(error)))?;
    if lease.candidate_id != candidate.candidate_id || lease.target_scope != candidate.target_scope
    {
        return Err(IntegrationBridgeError::LeaseMismatch {
            candidate_id: lease.candidate_id.clone(),
        });
    }
    let overlapping: Vec<String> = candidate
        .changed_paths
        .iter()
        .filter(|path| request.dirty_paths.contains(*path))
        .cloned()
        .collect();
    if !overlapping.is_empty() {
        return Err(IntegrationBridgeError::DirtyHumanChanges { overlapping });
    }
    check_verifier_observation(
        candidate,
        &request.pre_apply,
        "pre_apply.verifier_ref",
        "pre_apply.environment_ref",
        "pre_apply",
    )?;
    if request.pre_apply.verdict == VerifierVerdict::Fail {
        let rollback = check_rollback_evidence(candidate, request.rollback.clone())?;
        let receipt = finish_receipt(
            candidate,
            lease,
            request,
            BTreeSet::new(),
            None,
            rollback,
            candidate.status,
        );
        return Err(IntegrationBridgeError::VerifierFailed {
            receipt: Box::new(receipt),
        });
    }
    if request.semantic_conflict {
        let detail = request.semantic_conflict_detail.as_ref().ok_or(
            IntegrationBridgeError::InvalidField {
                field: "semantic_conflict_detail",
                reason: "a declared conflict must carry its detail",
            },
        )?;
        require_text(detail, "semantic_conflict_detail", MAX_REF_LEN)?;
        let rollback = check_rollback_evidence(candidate, request.rollback.clone())?;
        let transitioned = transition(
            candidate,
            IntegrationCandidateStatus::Conflicted,
            request.observed_at_unix_ms,
        );
        let receipt = finish_receipt(
            candidate,
            lease,
            request,
            BTreeSet::new(),
            None,
            rollback,
            IntegrationCandidateStatus::Conflicted,
        );
        return Ok(BridgeApplySuccess {
            candidate: transitioned,
            receipt,
        });
    }
    if request.semantic_conflict_detail.is_some() {
        return Err(IntegrationBridgeError::InvalidField {
            field: "semantic_conflict_detail",
            reason: "present without a declared conflict",
        });
    }
    if request.applied_changed_paths != candidate.changed_paths {
        return Err(IntegrationBridgeError::ApplyScopeMismatch);
    }
    check_verifier_observation(
        candidate,
        &request.post_apply,
        "post_apply.verifier_ref",
        "post_apply.environment_ref",
        "post_apply",
    )?;
    if request.post_apply.verdict == VerifierVerdict::Fail {
        if let Some(handle) = candidate.rollback_or_compensation.clone() {
            if request.rollback.is_none() {
                return Err(IntegrationBridgeError::RollbackMissing { handle });
            }
        }
        let rollback = check_rollback_evidence(candidate, request.rollback.clone())?;
        let status = match rollback.as_ref().map(|run| run.outcome) {
            Some(RollbackOutcome::Failed) => IntegrationCandidateStatus::UnknownOutcome,
            _ => IntegrationCandidateStatus::Rejected,
        };
        let transitioned = transition(candidate, status, request.observed_at_unix_ms);
        let receipt = finish_receipt(
            candidate,
            lease,
            request,
            request.applied_changed_paths.clone(),
            Some(request.post_apply.clone()),
            rollback,
            status,
        );
        return Ok(BridgeApplySuccess {
            candidate: transitioned,
            receipt,
        });
    }
    if request.rollback.is_some() {
        return Err(IntegrationBridgeError::InvalidField {
            field: "rollback",
            reason: "no failure to compensate on the passing path",
        });
    }
    let transitioned = transition(
        candidate,
        IntegrationCandidateStatus::Accepted,
        request.observed_at_unix_ms,
    );
    let receipt = finish_receipt(
        candidate,
        lease,
        request,
        request.applied_changed_paths.clone(),
        Some(request.post_apply.clone()),
        None,
        IntegrationCandidateStatus::Accepted,
    );
    Ok(BridgeApplySuccess {
        candidate: transitioned,
        receipt,
    })
}

/// Queue-wide stale sweep for one target scope.
///
/// Transitions exactly the `Proposed`/`Ready` candidates of `target_scope`
/// whose base moved under them and which depend on that base (joined from
/// the queue/dependency projection by the caller, never inferred here) to
/// `Stale` with their history entry. Candidates that do not depend on the
/// moved base, that already moved past the leaseable statuses, or that still
/// sit on the current base are never touched and never returned. The caller
/// persists every returned record; no stale record is ever applied.
pub fn mark_stale_dependents(
    candidates: &[IntegrationCandidate],
    target_scope: &str,
    current_base_commit: &str,
    dependent_candidate_ids: &BTreeSet<String>,
    observed_at_unix_ms: u64,
) -> Result<Vec<IntegrationCandidate>, IntegrationBridgeError> {
    require_text(target_scope, "target_scope", MAX_IDENTITY_LEN)?;
    require_base_commit(current_base_commit)?;
    require_time(observed_at_unix_ms, "observed_at_unix_ms")?;
    let mut marked = Vec::new();
    for candidate in candidates {
        if candidate.target_scope != target_scope {
            continue;
        }
        if !matches!(
            candidate.status,
            IntegrationCandidateStatus::Proposed | IntegrationCandidateStatus::Ready
        ) {
            continue;
        }
        if candidate.base_commit == current_base_commit {
            continue;
        }
        if !dependent_candidate_ids.contains(&candidate.candidate_id) {
            continue;
        }
        marked.push(transition(
            candidate,
            IntegrationCandidateStatus::Stale,
            observed_at_unix_ms,
        ));
    }
    Ok(marked)
}

/// Appends one W3 lifecycle observation, preserving every prior entry.
/// History is retained on every path, including failure.
fn transition(
    candidate: &IntegrationCandidate,
    status: IntegrationCandidateStatus,
    observed_at_unix_ms: u64,
) -> IntegrationCandidate {
    let mut next = candidate.clone();
    next.status = status;
    next.history.push(IntegrationCandidateRevision {
        status,
        observed_at_unix_ms,
    });
    next
}

/// Binds one verifier-run observation to the candidate: bounded handles, a
/// nonzero time, the environment inside the candidate's worktree/artifact
/// refs, and the verifier among the candidate's declared verification refs
/// when the candidate declares any.
fn check_verifier_observation(
    candidate: &IntegrationCandidate,
    observation: &VerifierRunObservation,
    verifier_field: &'static str,
    environment_field: &'static str,
    role: &'static str,
) -> Result<(), IntegrationBridgeError> {
    require_text(&observation.verifier_ref, verifier_field, MAX_REF_LEN)?;
    require_text(&observation.environment_ref, environment_field, MAX_REF_LEN)?;
    require_time(observation.observed_at_unix_ms, "observed_at_unix_ms")?;
    if !candidate
        .worktree_or_artifact_refs
        .contains(&observation.environment_ref)
    {
        return Err(IntegrationBridgeError::EnvironmentMismatch { role });
    }
    if !candidate.verification_refs.is_empty()
        && !candidate
            .verification_refs
            .contains(&observation.verifier_ref)
    {
        return Err(IntegrationBridgeError::InvalidField {
            field: verifier_field,
            reason: "must run the declared verifier",
        });
    }
    Ok(())
}

/// Admits rollback/compensation evidence bound to the candidate's declared
/// handle. Absent evidence is admitted here; the post-apply failure path
/// demands it separately when a handle is declared.
fn check_rollback_evidence(
    candidate: &IntegrationCandidate,
    evidence: Option<RollbackExecution>,
) -> Result<Option<RollbackExecution>, IntegrationBridgeError> {
    let Some(run) = evidence else {
        return Ok(None);
    };
    require_text(&run.handle, "rollback.handle", MAX_REF_LEN)?;
    require_time(run.observed_at_unix_ms, "observed_at_unix_ms")?;
    match &candidate.rollback_or_compensation {
        Some(declared) if *declared == run.handle => Ok(Some(run)),
        Some(_) => Err(IntegrationBridgeError::InvalidField {
            field: "rollback.handle",
            reason: "must execute the declared handle",
        }),
        None => Err(IntegrationBridgeError::InvalidField {
            field: "rollback",
            reason: "the candidate declares no rollback or compensation",
        }),
    }
}

/// Records the post-apply receipt binding the candidate retry identity, the
/// granting lease, both verifier runs, the governed write set, and any
/// rollback/compensation result.
#[allow(clippy::too_many_arguments)]
fn finish_receipt(
    candidate: &IntegrationCandidate,
    lease: IntegrationOwnerLease,
    request: &BridgeApplyRequest,
    applied_changed_paths: BTreeSet<String>,
    post_apply: Option<VerifierRunObservation>,
    rollback: Option<RollbackExecution>,
    final_status: IntegrationCandidateStatus,
) -> OutcomeReceipt {
    OutcomeReceipt {
        candidate_id: candidate.candidate_id.clone(),
        request_id: candidate.request_id.clone(),
        target_scope: candidate.target_scope.clone(),
        lease,
        pre_apply: request.pre_apply.clone(),
        applied_changed_paths,
        post_apply,
        semantic_conflict: request.semantic_conflict,
        semantic_conflict_detail: request.semantic_conflict_detail.clone(),
        rollback,
        final_status,
        observed_at_unix_ms: request.observed_at_unix_ms,
    }
}

/// Requires bounded, non-blank text with no control characters, mirroring
/// the W1 admission text rule.
fn require_text(
    value: &str,
    field: &'static str,
    max_len: usize,
) -> Result<(), IntegrationBridgeError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(IntegrationBridgeError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    if value.len() > max_len {
        return Err(IntegrationBridgeError::InvalidField {
            field,
            reason: "exceeds admission bound",
        });
    }
    Ok(())
}

/// Requires the live base revision to be compact visible ASCII with no
/// whitespace, mirroring the W1/W2 base rule so the two compare exactly.
fn require_base_commit(base_commit: &str) -> Result<(), IntegrationBridgeError> {
    require_text(base_commit, "current_base_commit", MAX_BASE_LEN)?;
    if !base_commit.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(IntegrationBridgeError::InvalidField {
            field: "current_base_commit",
            reason: "must be visible ASCII with no whitespace",
        });
    }
    Ok(())
}

/// Requires a caller-observed time that is never zero. Kernel keeps
/// point-in-time values separate from causal order; a zero time carries no
/// observation.
fn require_time(value: u64, field: &'static str) -> Result<(), IntegrationBridgeError> {
    if value == 0 {
        return Err(IntegrationBridgeError::InvalidField {
            field,
            reason: "must carry the caller-observed time, never zero",
        });
    }
    Ok(())
}
