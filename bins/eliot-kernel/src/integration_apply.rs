//! Kernel-owned governed bridge-apply half and dispatch hook (issue #1818, W3).
//!
//! Architecture: I10.16 governed integration of candidate implementations.
//! The owner advance (W3, [`crate::integration_owner`]) grants the single
//! active integration lease per target and transitions the queue head to
//! `Integrating`. This module is the Kernel-mechanical half that consumes
//! that lease: the governed apply ([`apply_integration_candidate`], stable
//! name [`INTEGRATION_APPLY_NAME`]) which revalidates the lease binding,
//! base, State Fence, paths, effects, and dirty human work, admits the
//! pre-apply verifier receipt, applies only through the governed Git/artifact
//! bridge report, admits the post-apply verifier receipt, records an
//! [`OutcomeReceipt`], and records the declared rollback/compensation
//! result on failure. Durability stays with the canonical Store through the
//! existing Store bridge; this module keeps no rows, runs no scheduler, owns
//! no second store, and executes no Git or verifier itself.
//!
//! # Production chain
//!
//! The bridge-apply slice calls [`serve_integration_apply_request`] with the
//! caller-read-back candidate and lease views (the Store bridge readback in
//! production) plus the live observations it proved against the live target
//! and the candidate worktree/environment. The serve caller admits the typed
//! request, drives [`apply_integration_candidate`], and encodes the
//! [`IntegrationApplyResponse`] carrying the outcome, the `OutcomeReceipt`
//! when one was recorded, and the exact transitioned records the bridge must
//! persist. The dispatch hook ([`route_lease_holder_to_apply`]) is the
//! production dispatch entry: it names the single lease-holding
//! (`Integrating`, lease-covered) candidate for a target so dispatch routes
//! exactly that candidate into the apply, and refuses fail-closed when the
//! lease binding breaks or a second holder or lease appears. The stable
//! [`INTEGRATION_APPLY_NAME`], [`INTEGRATION_APPLY_RECEIPT_READ_NAME`], and
//! [`INTEGRATION_APPLY_SCHEMA_V1`] constants are the exact keys the Store
//! bridge slice registers; they are declared here so the names cannot drift
//! between the Kernel surface and the bridge registration.
//!
//! # What this deliberately does not do
//!
//! No candidate creation or queue definition (W1), no lease-shape ownership
//! or acquire (W2), no owner advance or pressure projection (W3 owner half),
//! and no Git, worktree, or verifier execution: the caller executes the
//! governed bridge and both verifiers and proves what it did through the
//! typed request. Semantic conflicts become durable [`IntegrationCandidate`]
//! conflict work through the `Conflicted` transition, never an automatic text
//! merge: a request that reports a performed text merge is refused
//! fail-closed. Unrelated dirty work is carried through as
//! `preserved_dirty_paths` on the receipt; the bridge never relies on
//! `git reset --hard`, and a request that reports one is refused fail-closed.
//! A verifier failure leaves the candidate record and its history intact and
//! still records its rollback or compensation result on the receipt.
//!
//! # Relation to the acceptance slice (A1)
//!
//! One active lease per target is enforced twice: the hook routes at most the
//! single lease-covered holder and refuses when a second lease or holder
//! appears, and the apply re-requires the exact covering lease. A moved base
//! marks the candidate stale only through the caller-joined
//! `candidate_depends_on_base` flag, never by inference. Every terminal
//! transition appends history and is returned for the bridge to persist, so
//! failure retains history and a verifier failure additionally keeps the
//! candidate row itself untouched.

use std::collections::BTreeSet;

use eliot_contracts::{ContractError, StateFence, fences_match_exact};
use serde::{Deserialize, Serialize};

use crate::integration_candidate::{
    IntegrationCandidate, IntegrationCandidateError, IntegrationCandidateRevision,
    IntegrationCandidateStatus, MAX_BASE_LEN, MAX_CHANGED_PATHS, MAX_EVIDENCE_ENTRIES,
    MAX_IDENTITY_LEN, MAX_PATH_LEN, MAX_REF_LEN, read_integration_candidate,
};
use crate::integration_lease::IntegrationOwnerLease;

/// Schema identifier for persisted apply outcome receipts. The Store bridge
/// slice registers this exact key; the Kernel surface never mints a second
/// one.
pub const INTEGRATION_APPLY_SCHEMA_V1: &str = "eliot.integration.apply.v1";
/// Stable named governed apply. The Store bridge slice registers this exact
/// name for the bridge-apply half of the leaseable integration-owner path.
pub const INTEGRATION_APPLY_NAME: &str = "ApplyIntegrationCandidate";
/// Stable named outcome-receipt read. The Store bridge slice registers this
/// exact name for exact-identity receipt readback.
pub const INTEGRATION_APPLY_RECEIPT_READ_NAME: &str = "GetIntegrationOutcomeReceipt";

/// Typed bridge-apply failures. Every refusal names its field or reason; a
/// refused request transitions nothing, records no receipt, and grants no
/// lease. The candidate keeps its status and its history stays intact.
#[derive(Clone, Debug)]
pub enum IntegrationApplyError {
    /// An apply-request field failed admission bounds. Nothing was applied.
    InvalidField {
        /// Closed field name, never a value.
        field: &'static str,
        /// Stable reason, never a value.
        reason: &'static str,
    },
    /// The W1 candidate read failed. Nothing was applied.
    Candidate(Box<IntegrationCandidateError>),
    /// The candidate targets a different scope than the requested apply.
    /// Nothing was applied.
    TargetMismatch {
        /// Requested apply scope.
        target_scope: String,
        /// Scope the candidate record carries.
        candidate_target: String,
    },
    /// The candidate does not hold the lease for apply (only `Integrating`
    /// may apply). The candidate keeps its status. Nothing was applied.
    CandidateNotIntegrating {
        /// Exact identity that was refused.
        candidate_id: String,
        /// Status that made it inadmissible for apply.
        status: IntegrationCandidateStatus,
    },
    /// No active lease covers the candidate for the target. Nothing was
    /// applied.
    LeaseNotHeld {
        /// Target scope with no covering lease.
        target_scope: String,
    },
    /// The carried lease does not bind this exact candidate, target, and
    /// base, or a second active lease covers the target. Nothing was
    /// applied.
    LeaseMismatch {
        /// Target scope of the broken binding.
        target_scope: String,
    },
    /// The carried State Fence failed its own owner validation.
    Foundation(ContractError),
    /// The live State Fence does not exactly match the candidate's fence.
    /// Nothing was applied.
    FenceMismatch,
    /// The caller-observed changed paths do not exactly match the
    /// candidate's manifest. Nothing was applied.
    PathMismatch,
    /// The caller-observed declared effects do not exactly match the
    /// candidate's declared sets. Nothing was applied.
    EffectMismatch,
    /// Dirty human work overlaps the candidate's changed paths. Fail-closed:
    /// nothing was applied and unrelated dirty work is untouched.
    DirtyHumanChanges {
        /// Sorted overlapping repo-relative paths.
        overlapping: Vec<String>,
    },
}

impl std::fmt::Display for IntegrationApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField { field, reason } => {
                write!(f, "invalid integration apply field {field}: {reason}")
            }
            Self::Candidate(error) => {
                write!(f, "integration apply candidate: {error}")
            }
            Self::TargetMismatch {
                target_scope,
                candidate_target,
            } => write!(
                f,
                "integration apply target mismatch: apply asks {target_scope}, candidate carries {candidate_target}"
            ),
            Self::CandidateNotIntegrating {
                candidate_id,
                status,
            } => write!(
                f,
                "integration candidate {candidate_id} is not lease-holding in status {status:?}"
            ),
            Self::LeaseNotHeld { target_scope } => write!(
                f,
                "integration apply refused: no active lease covers the candidate for {target_scope}"
            ),
            Self::LeaseMismatch { target_scope } => write!(
                f,
                "integration apply refused: lease binding broken or second lease for {target_scope}"
            ),
            Self::Foundation(error) => {
                write!(f, "integration apply foundation contract: {error}")
            }
            Self::FenceMismatch => write!(
                f,
                "integration apply fence mismatch: live fence is not the candidate fence"
            ),
            Self::PathMismatch => write!(
                f,
                "integration apply path mismatch: observed paths are not the candidate manifest"
            ),
            Self::EffectMismatch => write!(
                f,
                "integration apply effect mismatch: observed effects are not the candidate sets"
            ),
            Self::DirtyHumanChanges { overlapping } => write!(
                f,
                "integration apply refused: dirty human changes overlap {}",
                overlapping.join(",")
            ),
        }
    }
}

impl std::error::Error for IntegrationApplyError {}

/// Declared rollback or compensation result for one apply outcome. The caller
/// executes the candidate's declared `rollback_or_compensation` plan on
/// failure and records what happened here; the Kernel retains the record but
/// never executes the plan itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationRollbackReport {
    /// Whether the declared plan was executed. A pre-apply failure executes
    /// nothing and records `false` with the stand-by result.
    pub executed: bool,
    /// Bounded ref naming the rollback or compensation result evidence.
    pub result_ref: String,
    /// Caller-observed time of the report, Unix milliseconds, never zero.
    pub observed_at_unix_ms: u64,
}

/// Durable semantic-conflict work for one candidate. Carries the conflict
/// work refs the bridge must retain; the candidate transitions to
/// `Conflicted` and is never text-merged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationSemanticConflict {
    /// Bounded refs naming the durable conflict work. Never empty.
    pub conflict_work_refs: Vec<String>,
    /// Caller-observed time of the conflict finding, Unix milliseconds,
    /// never zero.
    pub observed_at_unix_ms: u64,
}

/// Closed apply outcome recorded on an [`OutcomeReceipt`]. The receipt
/// records exactly one of these; terminal candidate transitions mirror it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationApplyOutcomeKind {
    /// Applied through the governed bridge; post-apply verifier passed.
    Applied,
    /// Pre-apply verifier failed; nothing applied, candidate intact.
    PreApplyVerifierFailed,
    /// Post-apply verifier failed; declared rollback/compensation recorded.
    PostApplyVerifierFailed,
    /// Semantic conflict held as durable conflict work, never auto-merged.
    ConflictHeld,
}

/// Post-apply receipt for one governed bridge application. Recorded for
/// every apply attempt that passes lease and revalidation binding, including
/// verifier failures and semantic conflicts, so the attempt, the preserved
/// dirty work, and the rollback or compensation result stay durable.
/// Persisted by the bridge under [`INTEGRATION_APPLY_SCHEMA_V1`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeReceipt {
    /// Exact retry identity taken from the candidate for reconcile.
    pub request_id: String,
    /// Candidate the receipt records the apply attempt for.
    pub candidate_id: String,
    /// Mutable target the candidate applied into.
    pub target_scope: String,
    /// Lease base the holder ran under, taken from the covering lease.
    pub lease_base_commit: String,
    /// Lease acquire time taken from the covering lease, Unix milliseconds.
    pub lease_acquired_at_unix_ms: u64,
    /// Which outcome this receipt records.
    pub outcome: IntegrationApplyOutcomeKind,
    /// Whether the pre-apply verifier passed in the candidate environment.
    pub pre_apply_verifier_passed: bool,
    /// Bounded ref naming the pre-apply verifier receipt evidence.
    pub pre_apply_verifier_receipt: String,
    /// Bounded ref naming the candidate worktree/environment the pre-apply
    /// verifier ran in.
    pub pre_apply_verifier_environment: String,
    /// Repo-relative paths the governed bridge applied. Exactly the
    /// candidate manifest on success, empty otherwise.
    pub applied_paths: BTreeSet<String>,
    /// Unrelated dirty paths the bridge preserved untouched. Exactly the
    /// observed dirty set, always disjoint from the manifest.
    pub preserved_dirty_paths: BTreeSet<String>,
    /// Whether the bridge relied on `git reset --hard`. Always false; a
    /// bridge that reports true is refused before any receipt is recorded.
    pub reset_hard_used: bool,
    /// Whether the post-apply verifier passed. False when no post-apply
    /// verifier ran (pre-apply failure, conflict hold).
    pub post_apply_verifier_passed: bool,
    /// Bounded ref naming the post-apply verifier receipt evidence. Present
    /// exactly when a post-apply verifier ran.
    pub post_apply_verifier_receipt: Option<String>,
    /// Declared rollback or compensation result. Present on every failure
    /// outcome, absent on success.
    pub rollback: Option<IntegrationRollbackReport>,
    /// Caller-observed time of the outcome, Unix milliseconds, never zero.
    pub observed_at_unix_ms: u64,
}

/// Caller-observed governed-apply input for one lease-holding candidate. The
/// bridge-apply slice decodes this from its typed request: it proves every
/// observed set against the live target, runs the declared verifier in the
/// candidate worktree/environment before apply, applies only through the
/// governed Git/artifact bridge, runs the post-apply verifier, and executes
/// the declared rollback/compensation on failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationBridgeApplyRequest {
    /// Mutable target the candidate applies into.
    pub target_scope: String,
    /// Lease-holding candidate to apply.
    pub candidate_id: String,
    /// The single active lease the candidate holds for the target. Must
    /// bind this exact candidate, target, and base.
    pub lease: IntegrationOwnerLease,
    /// Live base revision of the target at apply time.
    pub current_base_commit: String,
    /// Whether the candidate depends on the base it was produced against.
    /// A moved base marks the candidate stale only when this is true; the
    /// dependency itself is joined from the queue/dependency projection by
    /// the caller, never inferred here.
    pub candidate_depends_on_base: bool,
    /// Live State Fence of the target at apply time.
    pub current_fence: StateFence,
    /// Caller-observed changed paths at apply time; must exactly match the
    /// candidate manifest.
    pub observed_changed_paths: BTreeSet<String>,
    /// Caller-observed declared read effects; must exactly match.
    pub observed_read_effects: BTreeSet<String>,
    /// Caller-observed declared write effects; must exactly match.
    pub observed_write_effects: BTreeSet<String>,
    /// Dirty human paths observed in the target at apply time. Any overlap
    /// with the manifest fails closed; the disjoint remainder is the
    /// unrelated dirty work the bridge preserves.
    pub dirty_paths: BTreeSet<String>,
    /// Whether the pre-apply verifier passed in the candidate environment.
    pub pre_apply_verifier_passed: bool,
    /// Bounded ref naming the pre-apply verifier receipt evidence.
    pub pre_apply_verifier_receipt: String,
    /// Bounded ref naming the candidate worktree/environment the pre-apply
    /// verifier ran in.
    pub pre_apply_verifier_environment: String,
    /// Repo-relative paths the governed bridge applied. Must exactly equal
    /// the candidate manifest when the bridge applied, empty otherwise.
    pub applied_paths: BTreeSet<String>,
    /// Unrelated dirty paths the bridge preserved untouched. Must exactly
    /// equal `dirty_paths` and stay disjoint from the manifest.
    pub preserved_dirty_paths: BTreeSet<String>,
    /// Whether the bridge relied on `git reset --hard`. Must always be
    /// false; true is refused fail-closed.
    pub used_reset_hard: bool,
    /// Whether the bridge performed an automatic text merge. Must always be
    /// false; true is refused fail-closed and the conflict stays durable
    /// work.
    pub performed_text_merge: bool,
    /// Semantic conflict held as durable work instead of applied. Present
    /// exactly when the bridge found a semantic conflict; nothing applies
    /// while this is present.
    pub semantic_conflict: Option<IntegrationSemanticConflict>,
    /// Whether the post-apply verifier passed.
    pub post_apply_verifier_passed: bool,
    /// Bounded ref naming the post-apply verifier receipt evidence.
    /// Required exactly when a post-apply verifier ran.
    pub post_apply_verifier_receipt: Option<String>,
    /// Declared rollback or compensation result. Required on every failure
    /// outcome, absent on success.
    pub rollback: Option<IntegrationRollbackReport>,
    /// Caller-observed time of the apply, Unix milliseconds, never zero.
    pub observed_at_unix_ms: u64,
}

/// One governed-apply step outcome. A recorded receipt always accompanies the
/// outcome except the dependency-scoped stale mark, which mirrors the lease
/// path and persists the record alone. Boxed payloads keep the outcome
/// small at the dispatch boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ApplyOutcome {
    /// Applied through the governed bridge with a post-apply receipt. The
    /// carried record is already transitioned to `Accepted`.
    Applied {
        /// Post-apply receipt for the bridge to persist.
        receipt: Box<OutcomeReceipt>,
        /// Candidate record transitioned to `Accepted` with its history.
        accepted: Box<IntegrationCandidate>,
    },
    /// Pre-apply verifier failed. Nothing applied; the carried candidate is
    /// unchanged with its history intact, and the receipt records the
    /// rollback or compensation stand-by result.
    PreApplyVerifierFailed {
        /// Receipt recording the failure and the rollback result.
        receipt: Box<OutcomeReceipt>,
        /// Candidate record unchanged, history intact.
        candidate: Box<IntegrationCandidate>,
    },
    /// Post-apply verifier failed. The carried record is already
    /// transitioned to `Rejected` when the declared rollback executed, or
    /// to `UnknownOutcome` when it did not; history is retained either way
    /// and the receipt records the rollback or compensation result.
    PostApplyVerifierFailed {
        /// Receipt recording the failure and the rollback result.
        receipt: Box<OutcomeReceipt>,
        /// Candidate record transitioned with its history entry.
        recorded: Box<IntegrationCandidate>,
    },
    /// Semantic conflict held as durable conflict work. The carried record
    /// is already transitioned to `Conflicted`; nothing was merged.
    ConflictHeld {
        /// Receipt recording the held conflict.
        receipt: Box<OutcomeReceipt>,
        /// Candidate record transitioned to `Conflicted` with its history.
        conflicted: Box<IntegrationCandidate>,
    },
    /// The target base moved under a candidate that depends on it. The
    /// carried record is already transitioned to `Stale`; it must never
    /// apply and no receipt is recorded.
    StaleRecorded {
        /// Candidate record transitioned to `Stale` with its history.
        stale: Box<IntegrationCandidate>,
    },
}

/// Stable outcome kind for the apply response wire shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationApplyOutcomeKind {
    /// Applied with a post-apply receipt.
    Applied,
    /// Pre-apply verifier failed; candidate intact.
    PreApplyVerifierFailed,
    /// Post-apply verifier failed; rollback recorded.
    PostApplyVerifierFailed,
    /// Semantic conflict held as durable work.
    ConflictHeld,
    /// Base moved under a dependent candidate; stale, never applies.
    StaleRecorded,
}

/// Encoded governed-apply response. The bridge persists the receipt when one
/// was recorded and every carried `persist_candidates` record; this response
/// stores nothing itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationApplyResponse {
    /// Which apply step ran.
    pub outcome: IntegrationApplyOutcomeKind,
    /// The recorded receipt, absent only on the stale mark.
    pub receipt: Option<OutcomeReceipt>,
    /// Transitioned records the bridge must persist (`Accepted`,
    /// `Rejected`/`UnknownOutcome`, or `Conflicted` on a recorded outcome,
    /// `Stale` on a base move, empty when the candidate stays intact).
    pub persist_candidates: Vec<IntegrationCandidate>,
}

/// Dispatch routing decision for one target. The hook names at most the
/// single lease-holding candidate dispatch may route into the bridge apply;
/// every other candidate for the target remains queued behind the active
/// lease. A refusal never routes and grants nothing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ApplyRouteDecision {
    /// Exactly one lease-holding candidate may route into the apply. The
    /// carried lease is the target's single active lease covering it.
    Ready {
        /// Candidate dispatch must route into the bridge apply.
        candidate_id: String,
        /// The single active lease covering the candidate.
        lease: Box<IntegrationOwnerLease>,
    },
    /// No lease-holding candidate waits for the target. Nothing routes.
    NoHolder {
        /// Target scope with nothing to route.
        target_scope: String,
    },
    /// Routing refused fail-closed: the lease binding broke, or a second
    /// holder or second lease appeared. Nothing routes.
    Refused {
        /// Target scope that was refused.
        target_scope: String,
        /// Stable reason, never a value.
        reason: &'static str,
    },
}

/// Routes the lease-holding candidate for one target into the bridge apply.
///
/// Dispatch calls this hook with the caller-read-back candidate and lease
/// views before admitting any verifier or bridge observations. It reports
/// `Ready` with the exact candidate and its covering lease only when exactly
/// one `Integrating` candidate exists for the target under exactly one active
/// lease; otherwise it reports `NoHolder` or refuses. Pure: no lease is
/// taken, no record transitions, nothing is stored.
pub fn route_lease_holder_to_apply(
    candidates: &[IntegrationCandidate],
    active_leases: &[IntegrationOwnerLease],
    target_scope: &str,
) -> Result<ApplyRouteDecision, IntegrationApplyError> {
    require_text(target_scope, "target_scope", MAX_IDENTITY_LEN)?;
    let leases: Vec<&IntegrationOwnerLease> = active_leases
        .iter()
        .filter(|lease| lease.target_scope == target_scope)
        .collect();
    if leases.len() > 1 {
        return Ok(ApplyRouteDecision::Refused {
            target_scope: target_scope.to_owned(),
            reason: "second active lease for target",
        });
    }
    let holders: Vec<&IntegrationCandidate> = candidates
        .iter()
        .filter(|candidate| {
            candidate.target_scope == target_scope
                && candidate.status == IntegrationCandidateStatus::Integrating
        })
        .collect();
    if holders.len() > 1 {
        return Ok(ApplyRouteDecision::Refused {
            target_scope: target_scope.to_owned(),
            reason: "second lease-holding candidate for target",
        });
    }
    let Some(holder) = holders.first() else {
        return Ok(ApplyRouteDecision::NoHolder {
            target_scope: target_scope.to_owned(),
        });
    };
    let Some(lease) = leases.first() else {
        return Ok(ApplyRouteDecision::Refused {
            target_scope: target_scope.to_owned(),
            reason: "holder without covering lease",
        });
    };
    if lease.candidate_id != holder.candidate_id
        || lease.base_commit != holder.base_commit
        || lease.target_scope != holder.target_scope
    {
        return Ok(ApplyRouteDecision::Refused {
            target_scope: target_scope.to_owned(),
            reason: "lease binding broken for holder",
        });
    }
    Ok(ApplyRouteDecision::Ready {
        candidate_id: holder.candidate_id.clone(),
        lease: Box::new((*lease).clone()),
    })
}

/// Applies one lease-holding candidate through the governed Git/artifact
/// bridge report.
///
/// The caller proves the live target observations, the pre-apply verifier
/// run in the candidate worktree/environment, the exact bridge report
/// (applied paths, preserved unrelated dirty work, no `reset --hard`, no
/// text merge), the post-apply verifier run, and the declared
/// rollback/compensation result on failure. Checks run in order: request
/// bounds (including the `reset --hard` and text-merge prohibitions),
/// candidate identity, target-scope agreement, lease-holding status, single
/// covering lease binding, dependency-scoped stale base, State Fence owner
/// validation plus exact fence match, changed-path set match,
/// declared-effect set match, and dirty human work overlap. The first failure
/// wins; only every check passing reaches the verifier and bridge report.
/// `candidates` and `active_leases` are the caller-read-back views (the Store
/// bridge readback in production); this function stores nothing itself.
#[allow(clippy::too_many_lines)]
pub fn apply_integration_candidate(
    candidates: &[IntegrationCandidate],
    active_leases: &[IntegrationOwnerLease],
    request: &IntegrationBridgeApplyRequest,
) -> Result<ApplyOutcome, IntegrationApplyError> {
    validate_apply_request(request)?;
    let candidate = read_integration_candidate(candidates, &request.candidate_id)
        .map_err(|error| IntegrationApplyError::Candidate(Box::new(error)))?;
    if candidate.target_scope != request.target_scope {
        return Err(IntegrationApplyError::TargetMismatch {
            target_scope: request.target_scope.clone(),
            candidate_target: candidate.target_scope.clone(),
        });
    }
    if candidate.status != IntegrationCandidateStatus::Integrating {
        return Err(IntegrationApplyError::CandidateNotIntegrating {
            candidate_id: candidate.candidate_id.clone(),
            status: candidate.status,
        });
    }
    let covering: Vec<&IntegrationOwnerLease> = active_leases
        .iter()
        .filter(|lease| lease.target_scope == request.target_scope)
        .collect();
    let Some(lease) = covering.first() else {
        return Err(IntegrationApplyError::LeaseNotHeld {
            target_scope: request.target_scope.clone(),
        });
    };
    if covering.len() > 1
        || lease.candidate_id != candidate.candidate_id
        || lease.target_scope != candidate.target_scope
        || lease.base_commit != candidate.base_commit
    {
        return Err(IntegrationApplyError::LeaseMismatch {
            target_scope: request.target_scope.clone(),
        });
    }
    if candidate.base_commit != request.current_base_commit
        && request.candidate_depends_on_base
    {
        return Ok(ApplyOutcome::StaleRecorded {
            stale: Box::new(transition_candidate(
                candidate,
                IntegrationCandidateStatus::Stale,
                request.observed_at_unix_ms,
            )),
        });
    }
    candidate
        .state_fence
        .validate()
        .map_err(IntegrationApplyError::Foundation)?;
    request
        .current_fence
        .validate()
        .map_err(IntegrationApplyError::Foundation)?;
    if !fences_match_exact(&candidate.state_fence, &request.current_fence) {
        return Err(IntegrationApplyError::FenceMismatch);
    }
    if candidate.changed_paths != request.observed_changed_paths {
        return Err(IntegrationApplyError::PathMismatch);
    }
    if candidate.declared_read_effects != request.observed_read_effects
        || candidate.declared_write_effects != request.observed_write_effects
    {
        return Err(IntegrationApplyError::EffectMismatch);
    }
    let overlapping: Vec<String> = candidate
        .changed_paths
        .iter()
        .filter(|path| request.dirty_paths.contains(*path))
        .cloned()
        .collect();
    if !overlapping.is_empty() {
        return Err(IntegrationApplyError::DirtyHumanChanges { overlapping });
    }
    if let Some(conflict) = &request.semantic_conflict {
        if !request.applied_paths.is_empty() {
            return Err(IntegrationApplyError::InvalidField {
                field: "applied_paths",
                reason: "a semantic conflict never applies paths",
            });
        }
        let receipt = OutcomeReceipt {
            request_id: candidate.request_id.clone(),
            candidate_id: candidate.candidate_id.clone(),
            target_scope: candidate.target_scope.clone(),
            lease_base_commit: lease.base_commit.clone(),
            lease_acquired_at_unix_ms: lease.acquired_at_unix_ms,
            outcome: IntegrationApplyOutcomeKind::ConflictHeld,
            pre_apply_verifier_passed: request.pre_apply_verifier_passed,
            pre_apply_verifier_receipt: request.pre_apply_verifier_receipt.clone(),
            pre_apply_verifier_environment: request.pre_apply_verifier_environment.clone(),
            applied_paths: BTreeSet::new(),
            preserved_dirty_paths: request.preserved_dirty_paths.clone(),
            reset_hard_used: false,
            post_apply_verifier_passed: false,
            post_apply_verifier_receipt: None,
            rollback: request.rollback.clone(),
            observed_at_unix_ms: conflict.observed_at_unix_ms,
        };
        return Ok(ApplyOutcome::ConflictHeld {
            receipt: Box::new(receipt),
            conflicted: Box::new(transition_candidate(
                candidate,
                IntegrationCandidateStatus::Conflicted,
                conflict.observed_at_unix_ms,
            )),
        });
    }
    if !request.pre_apply_verifier_passed {
        let rollback =
            request
                .rollback
                .clone()
                .ok_or(IntegrationApplyError::InvalidField {
                    field: "rollback",
                    reason: "a verifier failure must record its rollback or compensation result",
                })?;
        let receipt = OutcomeReceipt {
            request_id: candidate.request_id.clone(),
            candidate_id: candidate.candidate_id.clone(),
            target_scope: candidate.target_scope.clone(),
            lease_base_commit: lease.base_commit.clone(),
            lease_acquired_at_unix_ms: lease.acquired_at_unix_ms,
            outcome: IntegrationApplyOutcomeKind::PreApplyVerifierFailed,
            pre_apply_verifier_passed: false,
            pre_apply_verifier_receipt: request.pre_apply_verifier_receipt.clone(),
            pre_apply_verifier_environment: request.pre_apply_verifier_environment.clone(),
            applied_paths: BTreeSet::new(),
            preserved_dirty_paths: request.preserved_dirty_paths.clone(),
            reset_hard_used: false,
            post_apply_verifier_passed: false,
            post_apply_verifier_receipt: None,
            rollback: Some(rollback),
            observed_at_unix_ms: request.observed_at_unix_ms,
        };
        return Ok(ApplyOutcome::PreApplyVerifierFailed {
            receipt: Box::new(receipt),
            candidate: Box::new(candidate.clone()),
        });
    }
    if request.applied_paths != candidate.changed_paths {
        return Err(IntegrationApplyError::InvalidField {
            field: "applied_paths",
            reason: "the bridge must apply exactly the candidate manifest",
        });
    }
    if request.preserved_dirty_paths != request.dirty_paths {
        return Err(IntegrationApplyError::InvalidField {
            field: "preserved_dirty_paths",
            reason: "the bridge must preserve all unrelated dirty work",
        });
    }
    if !request.post_apply_verifier_passed {
        let rollback =
            request
                .rollback
                .clone()
                .ok_or(IntegrationApplyError::InvalidField {
                    field: "rollback",
                    reason:
                        "a post-apply failure must record its rollback or compensation result",
                })?;
        let receipt = OutcomeReceipt {
            request_id: candidate.request_id.clone(),
            candidate_id: candidate.candidate_id.clone(),
            target_scope: candidate.target_scope.clone(),
            lease_base_commit: lease.base_commit.clone(),
            lease_acquired_at_unix_ms: lease.acquired_at_unix_ms,
            outcome: IntegrationApplyOutcomeKind::PostApplyVerifierFailed,
            pre_apply_verifier_passed: true,
            pre_apply_verifier_receipt: request.pre_apply_verifier_receipt.clone(),
            pre_apply_verifier_environment: request.pre_apply_verifier_environment.clone(),
            applied_paths: request.applied_paths.clone(),
            preserved_dirty_paths: request.preserved_dirty_paths.clone(),
            reset_hard_used: false,
            post_apply_verifier_passed: false,
            post_apply_verifier_receipt: request.post_apply_verifier_receipt.clone(),
            rollback: Some(rollback.clone()),
            observed_at_unix_ms: request.observed_at_unix_ms,
        };
        let status = if rollback.executed {
            IntegrationCandidateStatus::Rejected
        } else {
            IntegrationCandidateStatus::UnknownOutcome
        };
        return Ok(ApplyOutcome::PostApplyVerifierFailed {
            receipt: Box::new(receipt),
            recorded: Box::new(transition_candidate(
                candidate,
                status,
                request.observed_at_unix_ms,
            )),
        });
    }
    if request.rollback.is_some() {
        return Err(IntegrationApplyError::InvalidField {
            field: "rollback",
            reason: "a successful apply records no rollback",
        });
    }
    let receipt = OutcomeReceipt {
        request_id: candidate.request_id.clone(),
        candidate_id: candidate.candidate_id.clone(),
        target_scope: candidate.target_scope.clone(),
        lease_base_commit: lease.base_commit.clone(),
        lease_acquired_at_unix_ms: lease.acquired_at_unix_ms,
        outcome: IntegrationApplyOutcomeKind::Applied,
        pre_apply_verifier_passed: true,
        pre_apply_verifier_receipt: request.pre_apply_verifier_receipt.clone(),
        pre_apply_verifier_environment: request.pre_apply_verifier_environment.clone(),
        applied_paths: request.applied_paths.clone(),
        preserved_dirty_paths: request.preserved_dirty_paths.clone(),
        reset_hard_used: false,
        post_apply_verifier_passed: true,
        post_apply_verifier_receipt: request.post_apply_verifier_receipt.clone(),
        rollback: None,
        observed_at_unix_ms: request.observed_at_unix_ms,
    };
    Ok(ApplyOutcome::Applied {
        receipt: Box::new(receipt),
        accepted: Box::new(transition_candidate(
            candidate,
            IntegrationCandidateStatus::Accepted,
            request.observed_at_unix_ms,
        )),
    })
}

/// Serves one typed governed-apply request: admits the apply request, drives
/// [`apply_integration_candidate`], and encodes the
/// [`IntegrationApplyResponse`] with the outcome, the recorded receipt when
/// one exists, and the exact transitioned records the bridge must persist.
/// This is the production caller of the governed apply; dispatch reaches it
/// through [`route_lease_holder_to_apply`], which names the single
/// lease-holding candidate the request must carry.
pub fn serve_integration_apply_request(
    candidates: &[IntegrationCandidate],
    active_leases: &[IntegrationOwnerLease],
    request: &IntegrationBridgeApplyRequest,
) -> Result<IntegrationApplyResponse, IntegrationApplyError> {
    validate_apply_request(request)?;
    match apply_integration_candidate(candidates, active_leases, request)? {
        ApplyOutcome::Applied { receipt, accepted } => Ok(IntegrationApplyResponse {
            outcome: IntegrationApplyOutcomeKind::Applied,
            receipt: Some(*receipt),
            persist_candidates: vec![*accepted],
        }),
        ApplyOutcome::PreApplyVerifierFailed { receipt, .. } => Ok(IntegrationApplyResponse {
            outcome: IntegrationApplyOutcomeKind::PreApplyVerifierFailed,
            receipt: Some(*receipt),
            persist_candidates: Vec::new(),
        }),
        ApplyOutcome::PostApplyVerifierFailed { receipt, recorded } => {
            Ok(IntegrationApplyResponse {
                outcome: IntegrationApplyOutcomeKind::PostApplyVerifierFailed,
                receipt: Some(*receipt),
                persist_candidates: vec![*recorded],
            })
        }
        ApplyOutcome::ConflictHeld {
            receipt,
            conflicted,
        } => Ok(IntegrationApplyResponse {
            outcome: IntegrationApplyOutcomeKind::ConflictHeld,
            receipt: Some(*receipt),
            persist_candidates: vec![*conflicted],
        }),
        ApplyOutcome::StaleRecorded { stale } => Ok(IntegrationApplyResponse {
            outcome: IntegrationApplyOutcomeKind::StaleRecorded,
            receipt: None,
            persist_candidates: vec![*stale],
        }),
    }
}

/// Validates the apply request bounds once, so both the apply and its
/// serving caller refuse a malformed request identically. Live-set agreement
/// (lease binding, paths, effects, fence) is revalidated inside
/// [`apply_integration_candidate`] against the candidate, never here.
fn validate_apply_request(
    request: &IntegrationBridgeApplyRequest,
) -> Result<(), IntegrationApplyError> {
    require_text(&request.target_scope, "target_scope", MAX_IDENTITY_LEN)?;
    require_text(&request.candidate_id, "candidate_id", MAX_IDENTITY_LEN)?;
    require_base_commit(&request.current_base_commit)?;
    require_text(
        &request.pre_apply_verifier_receipt,
        "pre_apply_verifier_receipt",
        MAX_REF_LEN,
    )?;
    require_text(
        &request.pre_apply_verifier_environment,
        "pre_apply_verifier_environment",
        MAX_REF_LEN,
    )?;
    require_path_set(&request.applied_paths, "applied_paths")?;
    require_path_set(
        &request.preserved_dirty_paths,
        "preserved_dirty_paths",
    )?;
    for path in request.preserved_dirty_paths.iter() {
        if request.applied_paths.contains(path) {
            return Err(IntegrationApplyError::InvalidField {
                field: "preserved_dirty_paths",
                reason: "preserved work stays disjoint from applied paths",
            });
        }
    }
    if request.used_reset_hard {
        return Err(IntegrationApplyError::InvalidField {
            field: "used_reset_hard",
            reason: "the governed bridge never relies on git reset --hard",
        });
    }
    if request.performed_text_merge {
        return Err(IntegrationApplyError::InvalidField {
            field: "performed_text_merge",
            reason: "semantic conflicts become durable work, never auto-merged text",
        });
    }
    if let Some(conflict) = &request.semantic_conflict {
        require_ref_list(
            &conflict.conflict_work_refs,
            "conflict_work_refs",
            MAX_EVIDENCE_ENTRIES,
        )?;
        require_time(
            conflict.observed_at_unix_ms,
            "conflict observed_at_unix_ms",
        )?;
    }
    if request.semantic_conflict.is_some() {
        if request.post_apply_verifier_passed
            || request.post_apply_verifier_receipt.is_some()
        {
            return Err(IntegrationApplyError::InvalidField {
                field: "post_apply_verifier_receipt",
                reason: "no post-apply verifier runs on a conflict hold",
            });
        }
    } else if !request.pre_apply_verifier_passed {
        if request.post_apply_verifier_passed
            || request.post_apply_verifier_receipt.is_some()
        {
            return Err(IntegrationApplyError::InvalidField {
                field: "post_apply_verifier_receipt",
                reason: "no post-apply verifier runs after a pre-apply failure",
            });
        }
    } else {
        match &request.post_apply_verifier_receipt {
            Some(receipt) => {
                require_text(receipt, "post_apply_verifier_receipt", MAX_REF_LEN)?;
            }
            None => {
                return Err(IntegrationApplyError::InvalidField {
                    field: "post_apply_verifier_receipt",
                    reason: "a run post-apply verifier must name its receipt",
                });
            }
        }
    }
    if let Some(rollback) = &request.rollback {
        require_text(&rollback.result_ref, "rollback result_ref", MAX_REF_LEN)?;
        require_time(
            rollback.observed_at_unix_ms,
            "rollback observed_at_unix_ms",
        )?;
    }
    require_time(request.observed_at_unix_ms, "observed_at_unix_ms")?;
    Ok(())
}

/// Transitions a candidate to a terminal or parked apply status with its
/// history entry. History is appended, never rewritten: the bridge persists
/// the returned record and every earlier observation stays retained.
fn transition_candidate(
    candidate: &IntegrationCandidate,
    status: IntegrationCandidateStatus,
    observed_at_unix_ms: u64,
) -> IntegrationCandidate {
    let mut transitioned = candidate.clone();
    transitioned.status = status;
    transitioned.history.push(IntegrationCandidateRevision {
        status,
        observed_at_unix_ms,
    });
    transitioned
}

/// Requires bounded, non-blank text with no control characters, mirroring
/// the Store owner's text rule plus an admission length bound.
fn require_text(
    value: &str,
    field: &'static str,
    max_len: usize,
) -> Result<(), IntegrationApplyError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(IntegrationApplyError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    if value.len() > max_len {
        return Err(IntegrationApplyError::InvalidField {
            field,
            reason: "exceeds admission bound",
        });
    }
    Ok(())
}

/// Requires the live base revision to be compact visible ASCII with no
/// whitespace, mirroring the candidate and lease base rules so the three
/// can be compared exactly.
fn require_base_commit(base_commit: &str) -> Result<(), IntegrationApplyError> {
    require_text(base_commit, "current_base_commit", MAX_BASE_LEN)?;
    if !base_commit.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(IntegrationApplyError::InvalidField {
            field: "current_base_commit",
            reason: "must be visible ASCII with no whitespace",
        });
    }
    Ok(())
}

/// Requires a bounded repo-relative path set that stays inside the target
/// scope: never absolute, never escaping via `..`. The empty set is allowed
/// here because conflict holds and verifier failures apply nothing; the
/// manifest-equality check on the success path requires the exact manifest.
fn require_path_set(
    paths: &BTreeSet<String>,
    field: &'static str,
) -> Result<(), IntegrationApplyError> {
    if paths.len() > MAX_CHANGED_PATHS {
        return Err(IntegrationApplyError::InvalidField {
            field,
            reason: "exceeds admission bound",
        });
    }
    for path in paths {
        require_text(path, field, MAX_PATH_LEN)?;
        if path.starts_with('/') || path.starts_with('\\') {
            return Err(IntegrationApplyError::InvalidField {
                field,
                reason: "must be repo-relative, never absolute",
            });
        }
        let bytes = path.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err(IntegrationApplyError::InvalidField {
                field,
                reason: "must be repo-relative, never absolute",
            });
        }
        if path.split(['/', '\\']).any(|segment| segment == "..") {
            return Err(IntegrationApplyError::InvalidField {
                field,
                reason: "must not escape the target scope",
            });
        }
    }
    Ok(())
}

/// Requires a non-empty bounded reference list of bounded non-blank text.
fn require_ref_list(
    refs: &[String],
    field: &'static str,
    max_entries: usize,
) -> Result<(), IntegrationApplyError> {
    if refs.is_empty() {
        return Err(IntegrationApplyError::InvalidField {
            field,
            reason: "must name at least one entry",
        });
    }
    if refs.len() > max_entries {
        return Err(IntegrationApplyError::InvalidField {
            field,
            reason: "exceeds admission bound",
        });
    }
    for entry in refs {
        require_text(entry, field, MAX_REF_LEN)?;
    }
    Ok(())
}

/// Requires a caller-observed time that is never zero.
fn require_time(
    value: u64,
    field: &'static str,
) -> Result<(), IntegrationApplyError> {
    if value == 0 {
        return Err(IntegrationApplyError::InvalidField {
            field,
            reason: "must carry the caller-observed time, never zero",
        });
    }
    Ok(())
}
