//! Task-binding admission for the daemon ingress boundary (issue #1929).
//!
//! Implements I5.5 capture/promotion split at the `eliotd` admission edge:
//! `eliot.observe` may retain a safe raw cold [`ObservationCandidate`] when
//! task selection is absent or ambiguous, while reusable task memory,
//! Claim/Failure/Procedure promotion, and task-control writes require the
//! canonical Governor [`TaskSelectionEvidence`] plus a valid current fence
//! and a `Compatible` disposition.
//!
//! The selection evidence is the canonical Governor-owned contract
//! (`eliot-observation`); this module defines no parallel shape and parses
//! no invented marker syntax. Field names, types, and validation rules come
//! from that contract: exact task handle, non-zero `TaskContract` revision,
//! lowercase acceptance digest, `WorkScope` identity, selection source and
//! evidence handles. The fence is bound by the authenticated caller context
//! (the `state_fence`/`expected_fence` parameters), matching the canonical
//! consumer where the submission envelope carries the single fence.
//!
//! This module is a pure validator. It owns no journal, store, task lifecycle,
//! or promotion state machine; it only classifies one admission attempt so the
//! Governor/store owners keep semantic ownership. It never selects the most
//! recent or open task and never guesses from resolver output: ambiguous input
//! stays cold. A contaminated selection (canonical crossover marker) never
//! promotes: captures stay cold and task-bound promotion rejects.
//!
//! # Daemon ingress entries, and which of them are live (issue #1929)
//!
//! Without an entry below this module was unreachable from the daemon: the
//! `eliotd` ingress admitted a capture or a task-relative write and only the
//! downstream store gate could object, so the daemon itself was a bypass
//! around I5.5. Three entries were added to close that chain:
//!
//! - [`admit_canonical_write`] — the composition-root named-mutation intake.
//!   The caller presents its compiled
//!   [`OnboardingReadinessReceipt`](eliot_workscope::OnboardingReadinessReceipt),
//!   so this is the only entry that can see the exact
//!   `TaskSelectionEvidence`: [`resolve_task_selection`] reads the owner-issued
//!   `CurrentTaskContract` and routes a capture through [`admit_capture`] and
//!   every task-relative transition through [`admit_task_bound`]. I5.6 step 4
//!   verbatim — "resolve `TaskSelectionEvidence` and `TaskContract`
//!   compatibility when the command is task-relative".
//! - [`admit_named_mutation_capture`] — the transport edge
//!   (`DaemonKernelClient::apply_prepared`). No typed selection exists there, so
//!   this entry only decides the capture leg: a `CaptureObservation` naming no
//!   task is a cold unbound candidate and is never treated here as task-bound.
//!   It deliberately does not restate the store bridge's presence/agreement
//!   rule for task-bearing writes; that rule belongs to
//!   `eliot-store-surreal::task_binding_gate`, which re-derives it from the
//!   opaque proof handles before provider I/O. Neither replaces the other.
//! - [`observe_explicit_workspace`] — the daemon half of the `WorkScope`
//!   attach trigger. The daemon observes the explicit root mechanically; the
//!   Governor stays the receipt/admission owner
//!   (`GovernorComposition::admit_observed_scope_attach`), so this module
//!   mints no receipt of its own.
//!
//! No entry creates a second write path, re-derives a downstream layer's
//! decision, or accepts a task the caller did not name.
//!
//! # Measured reachability (issue #1929)
//!
//! Recorded because a checklist item satisfied against call-graph-dead code is
//! exactly the defect this issue audits. Measured on this tree by symbol, not
//! inferred:
//!
//! - [`admit_canonical_write`] has **one** production call site:
//!   [`DaemonComposition::commit_canonical_and_refresh`](super::DaemonComposition).
//!   An earlier revision of this file recorded *zero* call sites for it; that
//!   was false and is corrected here.
//! - `DaemonComposition::commit_canonical_and_refresh` itself has **zero**
//!   production call sites — its only in-tree mentions are documentation and a
//!   source-string assertion in `bins/eliotd/tests/agent_fabric_wiring.rs`. It
//!   is the composition-root canonical-commit entry and nothing in production
//!   calls it yet, so the typed evidence leg this module owns is reached from
//!   no live daemon path.
//! - [`admit_named_mutation_capture`] **is** live, through the neutral
//!   transport port: `PreparedKernelExchange::exchange` calls
//!   `KernelTransitionPort::apply_prepared`, implemented by
//!   `DaemonKernelClient` in `bins/eliotd/src/kernel_transition_client.rs`,
//!   whose `check_identity_binding` calls this entry before any transport is
//!   touched. The daemon run loop drives that port for its `TestD` terminal
//!   finish legs.
//! - [`observe_and_admit_task`] has **zero call sites**, so
//!   [`admit_task_bound_with_observed_scope`] is transitively dead with it.
//! - [`DaemonComposition::admit_scope_attach`](super::DaemonComposition) — the
//!   only caller of [`ScopeAttachIngress`] — has **zero call sites**, and
//!   `GovernorComposition::admit_observed_scope_attach` fails closed unless a
//!   `WorkScope` owner is *already* retained, so the entry is additionally
//!   circular: its only producer of the state it requires is itself.
//!
//! The single blocking symbol for the evidence leg is the compiled readiness
//! receipt. `TaskSelectionEvidence` needs a non-zero `task_revision` and a
//! lowercase `acceptance_digest`, and this repository has exactly one
//! production constructor of [`OnboardingReadinessReceipt`](eliot_workscope::OnboardingReadinessReceipt):
//! `eliot_workscope::ColdStartController::compile`. Its only production caller
//! is `eliot_workscope::OnboardingSingleFlight::compile_and_publish`, so the
//! receipt is reachable only through
//! `eliot_governor::GovernorComposition::compile_cold_start_at_trigger`, which
//! itself has zero call sites. No carrier on the write path holds the receipt
//! or the evidence: `eliot_protocol::RequestIdentity`,
//! `eliot_store_api::PreparedTransition`, `eliot_canonical::CanonicalWriteEnvelope`,
//! `DaemonKernelClient`, and `GovernorComposition`'s retained
//! `WorkScopeBindingOwner` all carry at most a bare `task_id`, and
//! `WorkScopeBindingSnapshot` is documented as carrying "no task, plan, session,
//! principal or kernel-generation authority".
//!
//! Consequence, stated rather than hidden: because `commit_canonical_and_refresh`
//! is not called, the typed task-bound leg of [`admit_canonical_write`] is
//! currently unreachable from the daemon. The two stable codes remain enforced
//! on the real write path by `eliot_store_surreal::task_binding_gate::gate_apply`,
//! which re-derives them from the opaque proof handles the transition actually
//! carries, and the live transport edge reports `ColdUnbound`, which is the
//! complete and honest answer for a task-free capture. Threading a selection
//! onto the transport edge requires the receipt owner above to exist first; it
//! must never be filled with a synthesized, reconstructed, or defaulted
//! selection.
//!
//! # Where a cold unbound candidate is retained (issue #1929)
//!
//! Retention is not this module's work and is not the `tracing` line its
//! callers emit — a log record is neither durable nor listable.
//! `eliot_store_surreal::task_binding_gate::gate_apply` classifies the unbound
//! capture `GateDisposition::ColdUnbound` so the write *proceeds* instead of
//! being rejected, and the durable owner is the store adapter:
//! `eliot_store_surreal_adapter`'s `plan::evidence_records` builds one
//! `EvidenceRecord` per `CaptureObservation` regardless of task binding, and
//! `apply::atomic_write` binds those records into the `write_receipt` row in
//! the same transaction that creates the receipt. The read-back symbol is the
//! `GetEvidencePack` named read served by
//! `eliot_store_surreal_adapter`'s `apply::read_boundary::read_evidence_records`.
//! A later governed binding transition therefore has a durable, listable
//! candidate to read, and the daemon's own contribution is the admission
//! decision plus its log projection.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use eliot_bootstrap::capture::observe_workspace_instance;
use eliot_contracts::{RequestMetadata, StateFence, TaskId};
use eliot_governor::{
    CanonicalWriteEnvelope, GenerationEvidence, GoverningSourceSet, PrivacyProfile, ScopeBinding,
    TaskScopeOutcome, WorkScopeDescriptor, WorkspaceInstanceIdentity, check_task_observation,
    derive_observed_resources,
};
use eliot_observation::TaskSelectionEvidence;
use eliot_security_contracts::PrivacyClass;
use eliot_store_api::{NamedMutationOperation, PreparedTransition};
use eliot_workscope::{ObservedScopeResources, OnboardingReadinessReceipt, TaskBindingState};

/// Stable rejection code when task-bound promotion lacks current evidence.
pub const TASK_SELECTION_REQUIRED: &str = "TASK_SELECTION_REQUIRED";
/// Stable rejection code when evidence names another/incompatible `WorkScope`.
pub const TASK_SCOPE_INCOMPATIBLE: &str = "TASK_SCOPE_INCOMPATIBLE";

/// Compatibility disposition computed by the owning selector.
///
/// `Compatible` is the only disposition that admits reusable/task-bound
/// promotion. Any other disposition keeps the observation cold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatibilityDisposition {
    /// Selection, contract revision, digest, scope, and fence all agree.
    Compatible,
    /// Selection names another scope or an incompatible contract revision.
    Incompatible,
}

/// Safe raw cold candidate retained when selection is absent or ambiguous.
///
/// Carries no task activation, no support/influence promotion, and no finish
/// relevance: durable capture-first bytes only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationCandidate {
    /// Stable candidate identity derived by the caller.
    pub candidate_id: String,
    /// Fence under which the bytes were captured.
    pub state_fence: StateFence,
    /// Bounded reason; always the unbound-capture marker here.
    pub reason_ref: String,
}

impl ObservationCandidate {
    /// Builds the single cold unbound shape this module ever emits.
    pub fn cold_unbound(candidate_id: String, state_fence: StateFence) -> Self {
        Self {
            candidate_id,
            state_fence,
            reason_ref: "unbound-capture".to_owned(),
        }
    }

    /// Whether this candidate can affect task memory/support/finish (never).
    #[must_use]
    pub const fn affects_task(&self) -> bool {
        false
    }
}

/// Typed admission failure carrying exactly one stable code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskBindingError {
    code: &'static str,
    detail: String,
}

impl TaskBindingError {
    fn selection_required(detail: impl Into<String>) -> Self {
        Self {
            code: TASK_SELECTION_REQUIRED,
            detail: detail.into(),
        }
    }

    fn scope_incompatible(detail: impl Into<String>) -> Self {
        Self {
            code: TASK_SCOPE_INCOMPATIBLE,
            detail: detail.into(),
        }
    }

    /// Stable wire code (`TASK_SELECTION_REQUIRED` / `TASK_SCOPE_INCOMPATIBLE`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Bounded human detail (never a task guess).
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl std::fmt::Display for TaskBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for TaskBindingError {}

/// Result of splitting capture admission from task-bound promotion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureAdmission {
    /// Durably retainable cold bytes with no task effects.
    ColdUnbound(ObservationCandidate),
    /// Exact selection admitted for a later governed binding transition.
    TaskBound(TaskSelectionEvidence),
}

/// Disposition of one daemon ingress attempt (issue #1929).
///
/// The variant, not the transport, decides what the write means: a cold
/// candidate carries no task activation, support/influence promotion, or
/// finish relevance, while `TaskBound` is only ever returned after the exact
/// selection evidence passed [`admit_task_bound`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskBindingAdmission {
    /// Cold unbound capture: durable bytes with no task effect.
    ColdUnbound(ObservationCandidate),
    /// Exact task-bound transition admitted toward the governed owner commit.
    TaskBound,
    /// Task-relative transition whose selection decision belongs to the
    /// caller that owns the exact selection evidence, never to a capture
    /// edge. Reported, never admitted and never silently downgraded.
    TaskRelative,
    /// Not a capture-first or task-relative write; no binding is required.
    NotTaskRelative,
}

/// Task-selection disposition a caller-presented readiness receipt carries.
///
/// This is the I5.6 step-4 resolution result: exactly one current
/// `TaskContract` revision plus its acceptance digest becomes selection
/// evidence; a missing, exploratory, stale, or multi-candidate binding does
/// not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskSelectionDisposition {
    /// No current exact selection: absent, exploratory (non-material), or stale.
    Absent,
    /// More than one candidate task handle survived selection; none is chosen.
    Ambiguous(usize),
    /// Exactly one current `TaskContract` revision with an acceptance digest.
    Current(TaskSelectionEvidence),
}

/// Admits one `eliot.observe` capture without ever guessing a task.
///
/// - `selection = None` or `candidate_count != 1` (absent/ambiguous) admits
///   only [`CaptureAdmission::ColdUnbound`]: no activation, promotion, or
///   finish relevance.
/// - Exactly one canonical, valid, compatible, uncontaminated selection admits
///   [`CaptureAdmission::TaskBound`] for a later governed binding transition;
///   this function still performs no promotion itself. A contaminated
///   selection (canonical crossover marker) stays cold, mirroring the
///   Governor `Quarantined` disposition.
/// - There is deliberately no `latest_task`, `open_task`, or resolver-guess
///   input: ambiguity stays cold.
pub fn admit_capture(
    candidate_id: String,
    state_fence: StateFence,
    selection: Option<&TaskSelectionEvidence>,
    candidate_count: usize,
    compatibility: CompatibilityDisposition,
) -> Result<CaptureAdmission, TaskBindingError> {
    if state_fence.validate().is_err() {
        return Err(TaskBindingError::selection_required(
            "capture.state_fence is invalid",
        ));
    }
    if candidate_id.trim().is_empty() || candidate_id.chars().any(char::is_control) {
        return Err(TaskBindingError::selection_required(
            "capture.candidate_id is blank",
        ));
    }
    match selection {
        None => Ok(CaptureAdmission::ColdUnbound(
            ObservationCandidate::cold_unbound(candidate_id, state_fence),
        )),
        Some(evidence) => {
            if candidate_count != 1 {
                return Ok(CaptureAdmission::ColdUnbound(
                    ObservationCandidate::cold_unbound(candidate_id, state_fence),
                ));
            }
            evidence.validate().map_err(|error| {
                TaskBindingError::selection_required(format!(
                    "task selection evidence invalid: {error}"
                ))
            })?;
            if evidence.is_contaminated() {
                return Ok(CaptureAdmission::ColdUnbound(
                    ObservationCandidate::cold_unbound(candidate_id, state_fence),
                ));
            }
            match compatibility {
                CompatibilityDisposition::Compatible => {
                    Ok(CaptureAdmission::TaskBound(evidence.clone()))
                }
                CompatibilityDisposition::Incompatible => {
                    Err(TaskBindingError::scope_incompatible(
                        "task selection is incompatible with observation scope",
                    ))
                }
            }
        }
    }
}

/// Admits one task-relative reusable/control transition.
///
/// Requires the canonical selection evidence, the expected task and
/// `WorkScope` handles, a valid current fence that scopes this admission,
/// and a `Compatible` disposition. Missing evidence rejects with
/// `TASK_SELECTION_REQUIRED`; a `WorkScope`/task mismatch or an incompatible
/// disposition rejects with `TASK_SCOPE_INCOMPATIBLE` without changing either
/// task (this function mutates nothing). A contaminated selection never
/// promotes: it rejects as non-current evidence.
pub fn admit_task_bound(
    selection: Option<&TaskSelectionEvidence>,
    expected_task_ref: &str,
    expected_work_scope_ref: &str,
    expected_fence: &StateFence,
    compatibility: CompatibilityDisposition,
) -> Result<(), TaskBindingError> {
    let Some(evidence) = selection else {
        return Err(TaskBindingError::selection_required(
            "task-bound promotion requires current TaskSelectionEvidence",
        ));
    };
    evidence.validate().map_err(|error| {
        TaskBindingError::selection_required(format!("task selection evidence invalid: {error}"))
    })?;
    if evidence.is_contaminated() {
        return Err(TaskBindingError::selection_required(
            "task selection is contaminated",
        ));
    }
    if evidence.task_ref != expected_task_ref {
        return Err(TaskBindingError::scope_incompatible(
            "task selection names a different task",
        ));
    }
    if evidence.work_scope_ref != expected_work_scope_ref {
        return Err(TaskBindingError::scope_incompatible(
            "task selection names a different WorkScope",
        ));
    }
    if expected_fence.validate().is_err() {
        return Err(TaskBindingError::selection_required(
            "task-bound promotion requires a valid current fence",
        ));
    }
    match compatibility {
        CompatibilityDisposition::Compatible => Ok(()),
        CompatibilityDisposition::Incompatible => Err(TaskBindingError::scope_incompatible(
            "task selection is incompatible with the target WorkScope",
        )),
    }
}

/// Admits one task-relative transition with observed workspace identity.
///
/// Extends [`admit_task_bound`] with the scope-identity legs for the first
/// tool-event trigger: the evidence's `WorkScope` claim is checked against
/// the retained Governor binding (`expected`) and the host-observed workspace
/// instance and generation. A mismatching checkout fails closed with
/// `TASK_SCOPE_INCOMPATIBLE` naming the exact disposition
/// (`DIFFERENT_INSTANCE`, `AMBIGUOUS`, or `STALE_BINDING`); the retained
/// binding, task state, and project memory are untouched. When the
/// observation agrees, the existing alias, fence, and compatibility checks
/// run unchanged. Lineage is enforced on lineage-observing paths, not here:
/// the daemon edge does not observe it.
///
/// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
#[allow(
    clippy::too_many_arguments,
    reason = "admission joins the retained binding, live observation, fence, and compatibility in one edge"
)]
pub fn admit_task_bound_with_observed_scope(
    selection: Option<&TaskSelectionEvidence>,
    expected_task_ref: &str,
    expected: &ScopeBinding,
    observed_instance: &WorkspaceInstanceIdentity,
    observed_generation: &GenerationEvidence,
    expected_fence: &StateFence,
    compatibility: CompatibilityDisposition,
) -> Result<(), TaskBindingError> {
    let Some(evidence) = selection else {
        return admit_task_bound(
            None,
            expected_task_ref,
            &expected.scope.scope_ref,
            expected_fence,
            compatibility,
        );
    };
    let check = check_task_observation(
        expected,
        &evidence.work_scope_ref,
        observed_instance,
        observed_generation,
    );
    match check.outcome {
        TaskScopeOutcome::Clear => {}
        TaskScopeOutcome::DifferentInstance
        | TaskScopeOutcome::Ambiguous
        | TaskScopeOutcome::StaleBinding => {
            return Err(TaskBindingError::scope_incompatible(format!(
                "task observation scope identity check {:?}: {}",
                check.outcome, check.detail
            )));
        }
    }
    admit_task_bound(
        selection,
        expected_task_ref,
        &expected.scope.scope_ref,
        expected_fence,
        compatibility,
    )
}

/// Resolves the exact task-selection disposition of one caller-presented
/// readiness receipt (I5.6 step 4, issue #1929).
///
/// This is the only producer of [`TaskSelectionEvidence`] in the daemon, and
/// it invents nothing: a `CurrentTaskContract` binding is the owner-issued
/// `task_ref` + `task_revision` + `acceptance_digest` triple from the receipt's
/// own `task_binding`, joined with the receipt's exact `WorkScope` identity and
/// reference handles. Every other binding state resolves to no selection:
///
/// - [`TaskBindingState::None_`] — the caller selected no task;
/// - `Exploratory` — a task is named but the binding is explicitly
///   non-material, so it is not a current `TaskContract`;
/// - `Stale` — the named revision is no longer current;
/// - `Ambiguous` — several candidate handles survived selection and the receipt
///   is forbidden to prefer one, so the candidate count is preserved and the
///   disposition stays non-material.
///
/// There is deliberately no latest-task, open-task, or resolver-guess leg here:
/// ambiguity is reported, never resolved.
#[must_use]
pub fn resolve_task_selection(receipt: &OnboardingReadinessReceipt) -> TaskSelectionDisposition {
    match &receipt.task_binding {
        TaskBindingState::CurrentTaskContract {
            task_ref,
            task_revision,
            acceptance_digest,
        } => TaskSelectionDisposition::Current(TaskSelectionEvidence {
            task_ref: task_ref.clone(),
            task_revision: *task_revision,
            acceptance_digest: acceptance_digest.clone(),
            work_scope_ref: receipt.scope.scope_ref.clone(),
            selection_source_ref: receipt.governance_profile_ref.clone(),
            evidence_ref: receipt.receipt_ref.clone(),
            contamination_flags: Vec::new(),
        }),
        TaskBindingState::Ambiguous { candidate_handles } => {
            TaskSelectionDisposition::Ambiguous(candidate_handles.len())
        }
        TaskBindingState::None_
        | TaskBindingState::Exploratory { .. }
        | TaskBindingState::Stale { .. } => TaskSelectionDisposition::Absent,
    }
}

/// Computes the `TaskContract` compatibility disposition for one write from
/// the caller's receipt: the selection is compatible only when the receipt was
/// compiled at the exact write fence and resolved the exact `WorkScope` the
/// write addresses.
///
/// Anything else is `Incompatible` and therefore rejects the task-relative
/// transition with `TASK_SCOPE_INCOMPATIBLE` instead of admitting it. This
/// reads only caller-presented terms; it resolves no authority of its own.
fn compatibility_for(
    receipt: &OnboardingReadinessReceipt,
    envelope: &CanonicalWriteEnvelope,
    write_fence: &StateFence,
) -> CompatibilityDisposition {
    if eliot_contracts::fences_match_exact(&receipt.state_fence, write_fence)
        && receipt.scope.scope_ref == envelope.scope_id.as_str()
    {
        CompatibilityDisposition::Compatible
    } else {
        CompatibilityDisposition::Incompatible
    }
}

/// Admits one daemon named-mutation write at the composition-root ingress
/// (issue #1929, I5.5 capture/promotion split, I5.6 step 4).
///
/// This is the composition-root named-mutation intake, and the only entry that
/// consumes a caller-presented [`OnboardingReadinessReceipt`]. Its one
/// production call site is
/// [`DaemonComposition::commit_canonical_and_refresh`](super::DaemonComposition);
/// that caller itself has zero production call sites, so the entry is not yet
/// reached in production. See the module's "Measured reachability" section for
/// the exact measurement. The write is split by what it actually is:
///
/// - a capture naming no task — the capture-first case — goes through
///   [`admit_capture`] and is returned as
///   [`TaskBindingAdmission::ColdUnbound`] unless the caller resolved one exact
///   compatible selection **and** the authenticated request names the task that
///   selection names. A selection naming a different task rejects with
///   `TASK_SCOPE_INCOMPATIBLE`; a selection whose admitted request names no task
///   at all stays cold, because that capture has no exact task selection for
///   this transition. It never affects task memory, support, influence, or
///   finish while cold;
/// - any task-relative write — one that names a task, or a task-control,
///   finish, or other task-bearing transition — requires the exact selection
///   and is admitted only through [`admit_task_bound`]. Absent, exploratory, or
///   stale evidence rejects with `TASK_SELECTION_REQUIRED`; a selection naming
///   a different task, `WorkScope`, or a moved fence rejects with
///   `TASK_SCOPE_INCOMPATIBLE`, mutating nothing;
/// - anything else is [`TaskBindingAdmission::NotTaskRelative`].
///
/// This entry never selects a task the caller did not name and never consults
/// recency, proximity, or the newest/open task. Its typed evidence is exactly
/// what the store bridge cannot see: the store gate re-derives presence and
/// agreement from the opaque proof handles, this gate verifies the
/// `TaskSelectionEvidence` values against the caller's own receipt.
pub fn admit_canonical_write(
    candidate_id: String,
    context: &RequestMetadata,
    envelope: &CanonicalWriteEnvelope,
    receipt: &OnboardingReadinessReceipt,
    write_fence: &StateFence,
) -> Result<TaskBindingAdmission, TaskBindingError> {
    let disposition = resolve_task_selection(receipt);
    let compatibility = compatibility_for(receipt, envelope, write_fence);
    let (selection, candidate_count) = match &disposition {
        TaskSelectionDisposition::Absent => (None, 0_usize),
        TaskSelectionDisposition::Ambiguous(count) => (None, *count),
        TaskSelectionDisposition::Current(evidence) => (Some(evidence), 1_usize),
    };
    let carries = |operation: NamedMutationOperation| {
        envelope
            .semantic_commands
            .iter()
            .any(|command| command.operation == operation)
    };
    let captures = carries(NamedMutationOperation::CaptureObservation);
    let task_relative = envelope.task_id.is_some()
        || carries(NamedMutationOperation::UpdateTaskState)
        || carries(NamedMutationOperation::RecordFinishDecision)
        || carries(NamedMutationOperation::RecordFinishEvidence);

    if captures && !task_relative {
        // `admit_capture` consumes the candidate identity on each of its cold
        // arms, so the caller's own value is kept here: a capture that cannot
        // be shown to be task-bound is still retained cold, and this edge
        // mints no second candidate identity.
        let cold_candidate_id = candidate_id.clone();
        return match admit_capture(
            candidate_id,
            context.state_fence.clone(),
            selection,
            candidate_count,
            compatibility,
        )? {
            CaptureAdmission::ColdUnbound(candidate) => {
                Ok(TaskBindingAdmission::ColdUnbound(candidate))
            }
            CaptureAdmission::TaskBound(evidence) => {
                // The expected task is the one the authenticated admitted
                // request names, never the evidence's own value. Passing
                // `evidence.task_ref` as the expectation made this leg a
                // tautology: every check `admit_task_bound` performs here was
                // either already made by `admit_capture` (validate, not
                // contaminated) or structurally guaranteed by
                // `compatibility_for` (same fence, same `WorkScope`), so the
                // call could not reject and a `CurrentTaskContract` naming a
                // task other than the admitted one was still reported
                // task-bound. I5.5 requires the wrong-task case to reject.
                let Some(admitted_task_ref) = context.task_id.as_ref().map(TaskId::as_str) else {
                    // A capture whose admitted request names no task has no
                    // exact task selection for this transition. I5.5 keeps the
                    // capture-first observation cold instead of rejecting it,
                    // so the original observation is never discarded.
                    return Ok(TaskBindingAdmission::ColdUnbound(
                        ObservationCandidate::cold_unbound(
                            cold_candidate_id,
                            context.state_fence.clone(),
                        ),
                    ));
                };
                if evidence.task_ref != admitted_task_ref {
                    return Err(TaskBindingError::scope_incompatible(
                        "task-bound capture names a different task than the admitted context",
                    ));
                }
                admit_task_bound(
                    Some(&evidence),
                    admitted_task_ref,
                    envelope.scope_id.as_str(),
                    write_fence,
                    compatibility,
                )?;
                Ok(TaskBindingAdmission::TaskBound)
            }
        };
    }

    if task_relative {
        let Some(expected_task_ref) = envelope.task_id.as_deref() else {
            return Err(TaskBindingError::selection_required(
                "task-relative write names no task binding",
            ));
        };
        if let Some(context_task) = context.task_id.as_ref().map(TaskId::as_str)
            && context_task != expected_task_ref
        {
            return Err(TaskBindingError::scope_incompatible(
                "task-relative write names a different task than the admitted context",
            ));
        }
        admit_task_bound(
            selection,
            expected_task_ref,
            envelope.scope_id.as_str(),
            write_fence,
            compatibility,
        )?;
        return Ok(TaskBindingAdmission::TaskBound);
    }

    Ok(TaskBindingAdmission::NotTaskRelative)
}

/// Admits the capture leg of one prepared transition at the daemon transport
/// edge (issue #1929, I5.5).
///
/// This is the production entry for `DaemonKernelClient::apply_prepared`'s
/// pre-transport admission: the last point inside the daemon where a
/// `CaptureObservation` can still be classified before it reaches Kernel and
/// the store. Its only decision is the capture leg:
///
/// - a `CaptureObservation` naming no task on either the admitted context or
///   the transition has no unique task selection, so it is admitted through
///   [`admit_capture`] as [`TaskBindingAdmission::ColdUnbound`] with no task
///   activation, support/influence promotion, or finish relevance;
/// - a `CaptureObservation` that names a task is task-relative, and this edge
///   reports [`TaskBindingAdmission::TaskRelative`] rather than guessing: the
///   binding decision belongs to the ingress that owns the exact selection
///   ([`admit_canonical_write`]) and is re-derived at the store gate from the
///   proof handles the transition actually carries. A typed selection is never
///   manufactured here, and an absent one is never treated as compatible;
/// - a transition with no capture at all is
///   [`TaskBindingAdmission::NotTaskRelative`].
///
/// It never selects the most recent or open task and never falls back to
/// resolver output.
///
/// # Why this entry has no `selection` parameter (issue #1929)
///
/// This edge is reached from `DaemonKernelClient::apply_prepared`, which
/// receives only a `PreparedTransition` and an `eliot_protocol::RequestIdentity`.
/// Neither carries a compiled readiness receipt or a `TaskSelectionEvidence`,
/// and neither does `DaemonKernelClient` or the retained Governor
/// `WorkScopeBindingOwner`; a `TaskSelectionEvidence` additionally requires a
/// non-zero `task_revision` and an `acceptance_digest` that this edge has no
/// legitimate source for. Adding the parameter anyway and passing `None` would
/// reproduce the present state under a new name, and synthesizing those two
/// fields would turn every typed rejection on this path into a rejection of
/// fabricated evidence — strictly worse than the `ColdUnbound` this edge
/// reports. The signature therefore has no selection parameter, which makes the
/// missing evidence owner structural rather than an assertion. The ingress that
/// would carry it, [`admit_canonical_write`], does have a production call site,
/// but that caller has none; see the module's "Measured reachability" section.
pub fn admit_named_mutation_capture(
    context: &RequestMetadata,
    transition: &PreparedTransition,
) -> Result<TaskBindingAdmission, TaskBindingError> {
    let captures = transition
        .named_operations
        .iter()
        .any(|named| named.operation == NamedMutationOperation::CaptureObservation);
    if !captures {
        return Ok(TaskBindingAdmission::NotTaskRelative);
    }
    let names_a_task = transition.task_id.is_some() || context.task_id.is_some();
    if names_a_task {
        return Ok(TaskBindingAdmission::TaskRelative);
    }
    match admit_capture(
        transition.identity.operation_id.as_str().to_owned(),
        context.state_fence.clone(),
        None,
        0,
        CompatibilityDisposition::Compatible,
    )? {
        CaptureAdmission::ColdUnbound(candidate) => {
            Ok(TaskBindingAdmission::ColdUnbound(candidate))
        }
        CaptureAdmission::TaskBound(evidence) => {
            Err(TaskBindingError::selection_required(format!(
                "task-free capture must not carry a task selection: {}",
                evidence.evidence_ref
            )))
        }
    }
}

/// Observes one explicit workspace root and admits one task-relative
/// transition against the live observation.
///
/// This is the daemon trigger ingress for scope identity: absent selection
/// stays on the cold path with no observation performed, while a present
/// selection observes the explicit root mechanically (filesystem/VCS/project
/// facts, never invented), derives the observed instance and generation, and
/// admits only through [`admit_task_bound_with_observed_scope`]. A root that
/// cannot be observed, or an observation that disagrees with the retained
/// binding, fails closed with `TASK_SCOPE_INCOMPATIBLE`; the retained
/// binding, task state, and project memory are untouched. The root is always
/// explicit — the daemon never infers a workspace from cwd, proximity, or
/// recency.
///
/// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
///
/// # Not yet reached (issue #1929)
///
/// This entry takes a caller-presented selection rather than owning one, and it
/// currently has zero call sites, which also makes
/// [`admit_task_bound_with_observed_scope`] transitively dead. Its two
/// remaining inputs are the reason: the daemon holds no retained
/// `ScopeBinding` (that requires `DaemonComposition::admit_scope_attach`, which
/// is itself uncalled and circular) and no explicit user workspace root — only
/// its own config and state directories, which are not a user `WorkScope` and
/// must never be attached as one. A production caller therefore needs the
/// attach-transport ingress named in the module's "Measured reachability"
/// section.
pub fn observe_and_admit_task(
    workspace_root: &Path,
    selection: Option<&TaskSelectionEvidence>,
    expected_task_ref: &str,
    expected: &ScopeBinding,
    expected_fence: &StateFence,
    compatibility: CompatibilityDisposition,
) -> Result<(), TaskBindingError> {
    if selection.is_none() {
        return admit_task_bound(
            None,
            expected_task_ref,
            &expected.scope.scope_ref,
            expected_fence,
            compatibility,
        );
    }
    let facts = observe_workspace_instance(workspace_root).map_err(|error| {
        TaskBindingError::scope_incompatible(format!("workspace observation failed: {error}"))
    })?;
    let observed = derive_observed_resources(&facts, expected_fence.resource_generation, None)
        .map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "observed workspace resources invalid: {error}"
            ))
        })?;
    let instance = observed.instances.first().ok_or_else(|| {
        TaskBindingError::scope_incompatible("observed workspace has no instance".to_owned())
    })?;
    admit_task_bound_with_observed_scope(
        selection,
        expected_task_ref,
        expected,
        instance,
        &observed.generation,
        expected_fence,
        compatibility,
    )
}

/// Authenticated attach ingress payload assembled from owned evidence.
///
/// The attach trigger builds exactly one of these per attach attempt from
/// evidence it already owns — never inferred from the activation ticket
/// (correlation-only by contract), the current directory, proximity, or
/// recency:
///
/// - `explicit_root`: the explicit host/session workspace path the trigger
///   was asked to attach (absolute; observed live, never a display name);
/// - `receipt_ref`: fresh bounded receipt identity minted per attempt;
/// - `descriptor`: the retained scope description the trigger resolves from
///   the onboarding path (the producer requires it to describe the live
///   owner binding on every identity field);
/// - `authorizing_ref`: the authenticated session/host authorization evidence
///   reference (the explicit Human/host binding token or session attach
///   record the trigger authenticated through owned IPC/session state) — a
///   reference only; the producer enforces non-blank, the trigger owns the
///   authentication;
/// - `privacy_class`, `governing_source_generation`, `sources`, `privacy`:
///   the scope's admitted privacy class and the onboarding-retained source
///   closure that authenticates the observed instance;
/// - `owner_revision`: caller-sequenced durable revision for the admitted
///   owner (same convention as the sibling admission entries).
///
/// [`ScopeAttachIngress::validate`] checks shape only: it never authenticates
/// the scope, the lineage, or the authorization — the live owner read at the
/// fence, the `MATCHED` guard, and the source closure inside
/// `GovernorComposition::admit_observed_scope_attach` do. Call sequence:
/// `validate`, then [`observe_explicit_workspace`] on `explicit_root`, then
/// `GovernorComposition::admit_observed_scope_attach` with every field below.
/// That call order is the production one in
/// `DaemonComposition::admit_scope_attach`.
///
/// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
#[derive(Clone, Debug)]
pub struct ScopeAttachIngress {
    /// Explicit absolute workspace root to observe live and attach.
    pub explicit_root: PathBuf,
    /// Fresh bounded receipt identity minted per attempt.
    pub receipt_ref: String,
    /// Retained scope description the observed instance attaches to.
    pub descriptor: WorkScopeDescriptor,
    /// Trigger-authenticated session/host authorization evidence reference.
    pub authorizing_ref: String,
    /// Admitted privacy class for the new binding.
    pub privacy_class: PrivacyClass,
    /// Source generation the onboarding closure authenticates.
    pub governing_source_generation: u64,
    /// Onboarding-retained governing sources for the observed instance.
    pub sources: GoverningSourceSet,
    /// Privacy boundary the new binding must satisfy.
    pub privacy: PrivacyProfile,
    /// Caller-sequenced durable revision for the admitted owner.
    pub owner_revision: u64,
}

impl ScopeAttachIngress {
    /// Validates the payload shape without authenticating anything.
    ///
    /// Malformed caller fields (blank references, zero counters) fail as
    /// `TASK_SELECTION_REQUIRED`; scope-identity disagreements (a descriptor
    /// that does not validate, a privacy class outside the admitted
    /// boundary) fail as `TASK_SCOPE_INCOMPATIBLE`. A non-absolute root
    /// fails as incompatible: only an explicit absolute path may be
    /// observed. The governing source set itself is checked at admission
    /// against the observed scope, never here.
    pub fn validate(&self) -> Result<(), TaskBindingError> {
        if !self.explicit_root.is_absolute() {
            return Err(TaskBindingError::scope_incompatible(
                "attach ingress explicit_root must be absolute",
            ));
        }
        if self.receipt_ref.trim().is_empty() || self.receipt_ref.chars().any(char::is_control) {
            return Err(TaskBindingError::selection_required(
                "attach ingress receipt_ref is blank",
            ));
        }
        if self.authorizing_ref.trim().is_empty()
            || self.authorizing_ref.chars().any(char::is_control)
        {
            return Err(TaskBindingError::selection_required(
                "attach ingress authorizing_ref is blank",
            ));
        }
        if self.governing_source_generation == 0 {
            return Err(TaskBindingError::selection_required(
                "attach ingress governing_source_generation is zero",
            ));
        }
        if self.owner_revision == 0 {
            return Err(TaskBindingError::selection_required(
                "attach ingress owner_revision is zero",
            ));
        }
        self.descriptor.validate().map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "attach ingress descriptor invalid: {error}"
            ))
        })?;
        self.privacy.validate().map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "attach ingress privacy boundary invalid: {error}"
            ))
        })?;
        if !self.privacy.admits(self.privacy_class) {
            return Err(TaskBindingError::scope_incompatible(
                "attach ingress privacy class is outside the admitted boundary",
            ));
        }
        Ok(())
    }
}

/// Observes one explicit workspace root and derives the observed scope
/// resources the `WorkScope` attach trigger admits against.
///
/// This is the daemon half of the attach ingress and the only mechanical step
/// it owns: the explicit absolute root is observed from filesystem/VCS/project
/// facts (never invented, never inferred from cwd, proximity, or recency) and
/// the observation is derived at the admission fence generation through the
/// same `derive_observed_resources` the CLI scope-observe ingress runs. A root
/// that cannot be observed, or one whose derived resources are invalid, fails
/// closed with `TASK_SCOPE_INCOMPATIBLE` carrying the exact detail; the
/// retained binding, task state, and project memory are untouched.
///
/// Receipt production and admission stay with the Governor owner
/// (`GovernorComposition::admit_observed_scope_attach`): this function mints no
/// receipt and installs no binding, so the daemon cannot become a second
/// `WorkScope` writer. The caller's admitted owner read, the fresh `MATCHED`
/// source-closure check, and the explicit authorization reference are the
/// Governor's terms, not this crate's.
pub fn observe_explicit_workspace(
    workspace_root: &Path,
    fence: &StateFence,
) -> Result<ObservedScopeResources, TaskBindingError> {
    let facts = observe_workspace_instance(workspace_root).map_err(|error| {
        TaskBindingError::scope_incompatible(format!("workspace observation failed: {error}"))
    })?;
    derive_observed_resources(&facts, fence.resource_generation, None).map_err(|error| {
        TaskBindingError::scope_incompatible(format!(
            "observed workspace resources invalid: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fence() -> StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("seq")).expect("epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    #[test]
    fn missing_selection_is_cold_without_task_effects() {
        let admission = admit_capture(
            "candidate-1".to_owned(),
            fence(),
            None,
            0,
            CompatibilityDisposition::Compatible,
        )
        .expect("absent selection stays cold");
        match admission {
            CaptureAdmission::ColdUnbound(candidate) => {
                assert_eq!(candidate.reason_ref, "unbound-capture");
                assert!(!candidate.affects_task());
            }
            CaptureAdmission::TaskBound(_) => panic!("absent selection must not bind a task"),
        }
    }
}
