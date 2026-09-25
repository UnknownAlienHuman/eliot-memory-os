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

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use eliot_bootstrap::capture::observe_workspace_instance;
use eliot_contracts::StateFence;
use eliot_governor::{
    GenerationEvidence, GoverningSourceSet, PrivacyProfile, ScopeBinding,
    ScopeRelocationOrAttachReceipt, TaskScopeOutcome, WorkScopeBindingOwner, WorkScopeDescriptor,
    WorkspaceInstanceIdentity, check_task_observation, derive_observed_resources,
    produce_attach_receipt,
};
use eliot_observation::TaskSelectionEvidence;
use eliot_security_contracts::PrivacyClass;

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
/// `validate`, then `observe_workspace_instance` on `explicit_root`,
/// `derive_observed_resources` at the admission fence generation, then
/// `GovernorComposition::admit_observed_scope_attach` with every field below.
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

/// Observes one explicit workspace root and produces an authorized attach
/// receipt for the newly observed instance.
///
/// This is the daemon trigger ingress for scope attach: the explicit root is
/// observed mechanically (filesystem/VCS/project facts, never invented), the
/// observation is derived at the admission fence generation through the same
/// `derive_observed_resources` the CLI scope-observe ingress runs, and the
/// owner-issued attach receipt is produced from that live observation, the
/// retained descriptor and owner, and the explicit authorization reference. A
/// root that cannot be observed, or an observation that is not exactly one
/// new same-lineage instance of the bound scope, fails closed with
/// `TASK_SCOPE_INCOMPATIBLE` carrying the exact producer detail; the retained
/// binding, task state, and project memory are untouched.
///
/// The returned receipt binds nothing by itself: admission runs in the owning
/// caller through the Governor relocation entry (`admit_scope_relocation`),
/// which rebinds with the receipt and requires a fresh `MATCHED`
/// source-closure check for the observed instance. The root is always
/// explicit — the daemon never infers a workspace from cwd, proximity, or
/// recency.
///
/// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
pub fn observe_and_produce_attach_receipt(
    workspace_root: &Path,
    receipt_ref: &str,
    descriptor: &WorkScopeDescriptor,
    owner: &WorkScopeBindingOwner,
    authorizing_ref: &str,
    fence: &StateFence,
) -> Result<ScopeRelocationOrAttachReceipt, TaskBindingError> {
    let facts = observe_workspace_instance(workspace_root).map_err(|error| {
        TaskBindingError::scope_incompatible(format!("workspace observation failed: {error}"))
    })?;
    let observed =
        derive_observed_resources(&facts, fence.resource_generation, None).map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "observed workspace resources invalid: {error}"
            ))
        })?;
    produce_attach_receipt(
        receipt_ref,
        descriptor,
        owner,
        &observed,
        authorizing_ref,
        fence,
    )
    .map_err(|error| {
        TaskBindingError::scope_incompatible(format!("attach receipt production failed: {error}"))
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
