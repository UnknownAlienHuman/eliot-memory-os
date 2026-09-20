//! Canonical `UnderstandingBootstrap` and ambiguity-safe task binding (I7.17).
//!
//! Architecture: I7.17 (convenience surfaces) projection of I4.4.1
//! (`OnboardingReadinessReceipt`, owned by the Governor/WorkScopeResolver) plus
//! I7.16 (actual `GovernanceProfile` with limiting integration evidence).
//!
//! Ownership: this module is a bounded read composition for bridge delivery
//! only. It creates no competing readiness authority: the canonical readiness
//! decision stays with `OnboardingReadinessReceipt`; this projection carries
//! its reference and disposition and can never report a stronger assessment
//! ([`cap_assessment`]). Task authority stays with the owning Governor/task
//! controller; this module only projects selection evidence and computes
//! `BOUND | UNIQUE | AMBIGUOUS | NONE` deterministically. It never silently
//! selects among multiple open candidates, and a task sourced solely via a
//! prior evaluation candidate stays [`CROSSOVER_CONTAMINATED`] until an
//! independent binding record is supplied.
//!
//! Non-ownership: onboarding compilation, task admission, governance
//! derivation, coverage observation, and canonical stores. Field names mirror
//! the Governor-owned `TaskSelectionEvidence` where they overlap so the
//! projection stays comparable without duplicating that contract.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Marker preserved from the selection route while a task lacks an
/// independent binding record.
pub const CROSSOVER_CONTAMINATED: &str = "CROSSOVER_CONTAMINATED";

/// Maximum candidate task handles projected in one bootstrap.
pub const MAX_CANDIDATE_HANDLES: usize = 16;
/// Maximum relevant/orientation/attention/problem/revision handles per list.
pub const MAX_HANDLES: usize = 32;
/// Maximum limiting integration evidence handles.
pub const MAX_EVIDENCE_HANDLES: usize = 8;
/// Maximum length of one opaque handle or reference.
pub const MAX_HANDLE_LEN: usize = 256;

/// Deterministic task-selection outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskSelectionDisposition {
    /// Authoritative selection evidence bound exactly one eligible task.
    Bound,
    /// Exactly one eligible task exists; no choice was made.
    Unique,
    /// Multiple candidates with no authoritative single selection; none chosen.
    Ambiguous,
    /// No bindable task (zero candidates or all blocked).
    None,
}

/// Scope level the selection evidence applies to.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeLevel {
    Session,
    Task,
    Project,
    Portfolio,
}

/// Agent-facing assessment. Never stronger than the referenced canonical
/// readiness disposition (see [`cap_assessment`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CurrentAssessment {
    NotOnboarded,
    Stale,
    Ready,
    Degraded,
}

/// Canonical readiness disposition from the referenced
/// `OnboardingReadinessReceipt` (I4.4.1 lifecycle).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadinessDisposition {
    Unseen,
    Scanning,
    NeedsScope,
    NeedsTask,
    NeedsSources,
    ReadyReadOnly,
    ReadyMaterial,
    Degraded,
    Conflicted,
}

/// Actual Governor-derived profile with its limiting integration evidence.
///
/// `limiting_integration_evidence` carries the concrete coverage handles that
/// bound authority (I7.16); at least one is required so a bootstrap can never
/// present an unbounded profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceEvidence {
    pub profile_ref: String,
    pub profile_revision: String,
    pub limiting_integration_evidence: Vec<String>,
}

/// One task candidate considered for binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCandidate {
    pub handle: String,
    pub task_revision: Option<u64>,
    pub acceptance_digest: Option<String>,
    /// True when this handle arrived only through a prior evaluation
    /// candidate and has no independent binding record yet.
    #[serde(default)]
    pub prior_evaluation_candidate_only: bool,
    /// True when an independent binding record for this handle was supplied.
    #[serde(default)]
    pub independent_binding_supplied: bool,
}

/// Authoritative evidence selecting exactly one candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeSelection {
    pub selected_handle: String,
    pub reason: String,
    pub source: String,
}

/// Task-selection inputs for one composition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapTaskInputs {
    pub scope_level: ScopeLevel,
    #[serde(default)]
    pub candidates: Vec<TaskCandidate>,
    #[serde(default)]
    pub authoritative_selection: Option<AuthoritativeSelection>,
}

/// Owner-supplied context composed into one bootstrap.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapContext {
    pub principal_ref: String,
    pub profile_ref: String,
    pub workscope_ref: String,
    pub onboarding_readiness_ref: String,
    pub onboarding_disposition: ReadinessDisposition,
    #[serde(default)]
    pub revision_refs: Vec<String>,
    #[serde(default)]
    pub orientation_handles: Vec<String>,
    #[serde(default)]
    pub attention_handles: Vec<String>,
    #[serde(default)]
    pub problem_handles: Vec<String>,
    pub role_lease_ref: String,
    pub state_fence_ref: String,
    pub governance: GovernanceEvidence,
    #[serde(default)]
    pub supported_count: u32,
    #[serde(default)]
    pub verified_count: u32,
    #[serde(default)]
    pub candidate_count: u32,
    #[serde(default)]
    pub conflicts_unknowns: Vec<String>,
    pub next_safe_expansion: String,
}

/// Selected task identity with its exact revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedTask {
    pub task_ref: String,
    pub task_revision: u64,
}

/// Projected task-selection evidence (I7.17 `TaskSelectionEvidence` row).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSelectionView {
    pub disposition: TaskSelectionDisposition,
    pub scope_level: ScopeLevel,
    pub candidate_task_handles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_task_and_revision: Option<SelectedTask>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance_digest: Option<String>,
    pub selection_source_and_reason: String,
    #[serde(default)]
    pub contamination_flags: Vec<String>,
}

/// Bounded agent-facing projection of onboarding readiness plus current
/// cognitive state (I7.17 `UnderstandingBootstrap`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnderstandingBootstrap {
    pub onboarding_readiness_ref: String,
    pub onboarding_readiness_disposition: ReadinessDisposition,
    pub principal_ref: String,
    pub profile_ref: String,
    pub workscope_ref: String,
    pub task_selection: TaskSelectionView,
    pub role_lease_ref: String,
    pub state_fence_ref: String,
    pub current_assessment: CurrentAssessment,
    pub supported_count: u32,
    pub verified_count: u32,
    pub candidate_count: u32,
    pub relevant_handles: Vec<String>,
    pub attention_handles: Vec<String>,
    pub problem_handles: Vec<String>,
    pub revision_refs: Vec<String>,
    pub conflicts_unknowns: Vec<String>,
    pub next_safe_expansion: String,
    pub governance: GovernanceEvidence,
}

/// Fail-closed composition error; carries codes only, no secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapError {
    pub code: &'static str,
    pub detail: String,
}

impl BootstrapError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.code, self.detail)
    }
}

impl std::error::Error for BootstrapError {}

fn non_blank(value: &str, field: &'static str) -> Result<(), BootstrapError> {
    if value.trim().is_empty() {
        return Err(BootstrapError::new(field, "must be a non-blank reference"));
    }
    if value.len() > MAX_HANDLE_LEN {
        return Err(BootstrapError::new(field, "reference exceeds bound"));
    }
    Ok(())
}

fn bounded_list(values: &[String], field: &'static str, max: usize) -> Result<(), BootstrapError> {
    if values.len() > max {
        return Err(BootstrapError::new(field, "handle list exceeds bound"));
    }
    for value in values {
        non_blank(value, field)?;
    }
    Ok(())
}

fn validate_governance(governance: &GovernanceEvidence) -> Result<(), BootstrapError> {
    non_blank(&governance.profile_ref, "GOVERNANCE_PROFILE_MISSING")?;
    non_blank(&governance.profile_revision, "GOVERNANCE_REVISION_MISSING")?;
    if governance.limiting_integration_evidence.is_empty() {
        return Err(BootstrapError::new(
            "GOVERNANCE_EVIDENCE_MISSING",
            "actual GovernanceProfile must carry at least one limiting integration evidence handle",
        ));
    }
    bounded_list(
        &governance.limiting_integration_evidence,
        "GOVERNANCE_EVIDENCE_BOUND",
        MAX_EVIDENCE_HANDLES,
    )
}

fn validate_context(context: &BootstrapContext) -> Result<(), BootstrapError> {
    non_blank(&context.principal_ref, "PRINCIPAL_MISSING")?;
    non_blank(&context.profile_ref, "PROFILE_MISSING")?;
    non_blank(&context.workscope_ref, "WORKSCOPE_MISSING")?;
    non_blank(&context.onboarding_readiness_ref, "READINESS_REF_MISSING")?;
    non_blank(&context.role_lease_ref, "ROLE_LEASE_MISSING")?;
    non_blank(&context.state_fence_ref, "STATE_FENCE_MISSING")?;
    non_blank(&context.next_safe_expansion, "NEXT_SAFE_EXPANSION_MISSING")?;
    if context.revision_refs.is_empty() {
        return Err(BootstrapError::new(
            "REVISIONS_MISSING",
            "at least one current revision/freshness handle is required",
        ));
    }
    bounded_list(&context.revision_refs, "REVISIONS_BOUND", MAX_HANDLES)?;
    bounded_list(
        &context.orientation_handles,
        "ORIENTATION_BOUND",
        MAX_HANDLES,
    )?;
    bounded_list(&context.attention_handles, "ATTENTION_BOUND", MAX_HANDLES)?;
    bounded_list(&context.problem_handles, "PROBLEMS_BOUND", MAX_HANDLES)?;
    bounded_list(&context.conflicts_unknowns, "CONFLICTS_BOUND", MAX_HANDLES)?;
    validate_governance(&context.governance)
}

fn validate_tasks(tasks: &BootstrapTaskInputs) -> Result<(), BootstrapError> {
    if tasks.candidates.len() > MAX_CANDIDATE_HANDLES {
        return Err(BootstrapError::new(
            "CANDIDATES_BOUND",
            "candidate task handles exceed bound",
        ));
    }
    for candidate in &tasks.candidates {
        non_blank(&candidate.handle, "CANDIDATE_HANDLE_MISSING")?;
        if let Some(digest) = &candidate.acceptance_digest {
            non_blank(digest, "ACCEPTANCE_DIGEST_MISSING")?;
        }
    }
    if let Some(selection) = &tasks.authoritative_selection {
        non_blank(&selection.selected_handle, "SELECTION_HANDLE_MISSING")?;
        non_blank(&selection.reason, "SELECTION_REASON_MISSING")?;
        non_blank(&selection.source, "SELECTION_SOURCE_MISSING")?;
    }
    Ok(())
}

/// Whether a candidate is blocked until independently rebound.
const fn is_crossover(candidate: &TaskCandidate) -> bool {
    candidate.prior_evaluation_candidate_only && !candidate.independent_binding_supplied
}

const fn assessment_rank(assessment: CurrentAssessment) -> u8 {
    match assessment {
        CurrentAssessment::NotOnboarded => 0,
        CurrentAssessment::Stale => 1,
        CurrentAssessment::Degraded => 2,
        CurrentAssessment::Ready => 3,
    }
}

/// Caps the projected assessment at the referenced canonical readiness so the
/// bootstrap can never overstate readiness. `READY_READ_ONLY` readiness cannot
/// support a `READY` assessment; anything before material readiness caps at
/// `NOT_ONBOARDED`, except `SCANNING` which caps at `STALE`.
#[must_use]
pub const fn cap_assessment(
    readiness: ReadinessDisposition,
    requested: CurrentAssessment,
) -> CurrentAssessment {
    let cap: u8 = match readiness {
        ReadinessDisposition::ReadyMaterial => 3,
        ReadinessDisposition::ReadyReadOnly
        | ReadinessDisposition::Degraded
        | ReadinessDisposition::Conflicted => 2,
        ReadinessDisposition::Scanning => 1,
        ReadinessDisposition::Unseen
        | ReadinessDisposition::NeedsScope
        | ReadinessDisposition::NeedsTask
        | ReadinessDisposition::NeedsSources => 0,
    };
    let wanted = assessment_rank(requested);
    let clamped = if wanted < cap { wanted } else { cap };
    match clamped {
        0 => CurrentAssessment::NotOnboarded,
        1 => CurrentAssessment::Stale,
        2 => CurrentAssessment::Degraded,
        _ => CurrentAssessment::Ready,
    }
}

fn compose_selection(tasks: &BootstrapTaskInputs) -> Result<TaskSelectionView, BootstrapError> {
    let contaminated = tasks.candidates.iter().any(is_crossover);
    let mut contamination_flags = Vec::new();
    if contaminated {
        contamination_flags.push(CROSSOVER_CONTAMINATED.to_owned());
    }
    let handles = tasks
        .candidates
        .iter()
        .map(|candidate| candidate.handle.clone())
        .collect::<Vec<_>>();

    if let Some(selection) = &tasks.authoritative_selection {
        let Some(matched) = tasks
            .candidates
            .iter()
            .find(|candidate| candidate.handle == selection.selected_handle)
        else {
            return Err(BootstrapError::new(
                "SELECTION_UNKNOWN_HANDLE",
                "authoritative selection names no listed candidate; refusing to choose",
            ));
        };
        if is_crossover(matched) {
            return Err(BootstrapError::new(
                "SELECTION_CONTAMINATED",
                "authoritative selection names a crossover-contaminated candidate without an independent binding record; refusing to bind",
            ));
        }
        let Some(revision) = matched.task_revision else {
            return Err(BootstrapError::new(
                "SELECTION_REVISION_MISSING",
                "authoritative selection target carries no exact task revision; refusing to bind",
            ));
        };
        return Ok(TaskSelectionView {
            disposition: TaskSelectionDisposition::Bound,
            scope_level: tasks.scope_level,
            candidate_task_handles: handles,
            selected_task_and_revision: Some(SelectedTask {
                task_ref: matched.handle.clone(),
                task_revision: revision,
            }),
            acceptance_digest: matched.acceptance_digest.clone(),
            selection_source_and_reason: format!("{}: {}", selection.source, selection.reason),
            contamination_flags,
        });
    }

    if tasks.candidates.is_empty() {
        return Ok(TaskSelectionView {
            disposition: TaskSelectionDisposition::None,
            scope_level: tasks.scope_level,
            candidate_task_handles: handles,
            selected_task_and_revision: None,
            acceptance_digest: None,
            selection_source_and_reason: "no candidates; no task bound".to_owned(),
            contamination_flags,
        });
    }
    if tasks.candidates.len() == 1 {
        let only = &tasks.candidates[0];
        if is_crossover(only) {
            return Ok(TaskSelectionView {
                disposition: TaskSelectionDisposition::None,
                scope_level: tasks.scope_level,
                candidate_task_handles: handles,
                selected_task_and_revision: None,
                acceptance_digest: None,
                selection_source_and_reason:
                    "sole candidate is crossover-contaminated; independent rebinding required"
                        .to_owned(),
                contamination_flags,
            });
        }
        let Some(revision) = only.task_revision else {
            return Err(BootstrapError::new(
                "SELECTION_REVISION_MISSING",
                "sole candidate carries no exact task revision; refusing to bind",
            ));
        };
        return Ok(TaskSelectionView {
            disposition: TaskSelectionDisposition::Unique,
            scope_level: tasks.scope_level,
            candidate_task_handles: handles,
            selected_task_and_revision: Some(SelectedTask {
                task_ref: only.handle.clone(),
                task_revision: revision,
            }),
            acceptance_digest: only.acceptance_digest.clone(),
            selection_source_and_reason: "single eligible candidate; no choice made".to_owned(),
            contamination_flags,
        });
    }
    Ok(TaskSelectionView {
        disposition: TaskSelectionDisposition::Ambiguous,
        scope_level: tasks.scope_level,
        candidate_task_handles: handles,
        selected_task_and_revision: None,
        acceptance_digest: None,
        selection_source_and_reason:
            "multiple eligible candidates without authoritative selection evidence; refusing to choose"
                .to_owned(),
        contamination_flags,
    })
}

/// Composes the bounded `UnderstandingBootstrap` over existing owners.
///
/// Validates the supplied context and task inputs, computes the deterministic
/// task-selection disposition, and caps the assessment at the referenced
/// canonical readiness. Fails closed whenever governance evidence, identity,
/// revisions, or selection integrity are missing.
pub fn get_understanding_bootstrap(
    context: &BootstrapContext,
    tasks: &BootstrapTaskInputs,
    requested_assessment: CurrentAssessment,
) -> Result<UnderstandingBootstrap, BootstrapError> {
    validate_context(context)?;
    validate_tasks(tasks)?;
    let task_selection = compose_selection(tasks)?;
    let mut relevant_handles = context.orientation_handles.clone();
    relevant_handles.truncate(MAX_HANDLES);
    Ok(UnderstandingBootstrap {
        onboarding_readiness_ref: context.onboarding_readiness_ref.clone(),
        onboarding_readiness_disposition: context.onboarding_disposition,
        principal_ref: context.principal_ref.clone(),
        profile_ref: context.profile_ref.clone(),
        workscope_ref: context.workscope_ref.clone(),
        task_selection,
        role_lease_ref: context.role_lease_ref.clone(),
        state_fence_ref: context.state_fence_ref.clone(),
        current_assessment: cap_assessment(context.onboarding_disposition, requested_assessment),
        supported_count: context.supported_count,
        verified_count: context.verified_count,
        candidate_count: context.candidate_count,
        relevant_handles,
        attention_handles: context.attention_handles.clone(),
        problem_handles: context.problem_handles.clone(),
        revision_refs: context.revision_refs.clone(),
        conflicts_unknowns: context.conflicts_unknowns.clone(),
        next_safe_expansion: context.next_safe_expansion.clone(),
        governance: context.governance.clone(),
    })
}

/// Once-per-session auto-boot delivery gate.
///
/// The first successful ELIOT response in a session carries the bootstrap
/// exactly once; later responses carry none, while bounded explicit retrieval
/// through [`get_understanding_bootstrap`] stays available.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BootstrapSession {
    auto_boot_delivered: bool,
}

impl BootstrapSession {
    /// Returns the bootstrap on the first successful response, `None` after.
    /// Composition failures also yield `None` rather than an unbounded or
    /// invented bootstrap; the session still counts as undelivered so a later
    /// response with complete inputs can carry it.
    pub fn take_auto_boot(
        &mut self,
        context: &BootstrapContext,
        tasks: &BootstrapTaskInputs,
        requested_assessment: CurrentAssessment,
    ) -> Option<UnderstandingBootstrap> {
        if self.auto_boot_delivered {
            return None;
        }
        let bootstrap = get_understanding_bootstrap(context, tasks, requested_assessment).ok()?;
        self.auto_boot_delivered = true;
        Some(bootstrap)
    }

    /// Whether the once-per-session bootstrap was already delivered.
    #[must_use]
    pub const fn auto_boot_delivered(&self) -> bool {
        self.auto_boot_delivered
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fixture_governance() -> GovernanceEvidence {
        GovernanceEvidence {
            profile_ref: "governance-profile-1".to_owned(),
            profile_revision: "rev-7".to_owned(),
            limiting_integration_evidence: vec![
                "coverage:PreToolUse:ENFORCED".to_owned(),
                "coverage:PostToolUse:OBSERVED".to_owned(),
            ],
        }
    }

    fn fixture_context(disposition: ReadinessDisposition) -> BootstrapContext {
        BootstrapContext {
            principal_ref: "principal-1".to_owned(),
            profile_ref: "SPINE_FUNCTIONAL".to_owned(),
            workscope_ref: "workscope-1".to_owned(),
            onboarding_readiness_ref: "readiness-receipt-1".to_owned(),
            onboarding_disposition: disposition,
            revision_refs: vec!["source-gen-9".to_owned()],
            orientation_handles: vec!["orientation:project".to_owned()],
            attention_handles: vec!["attention:conflict-1".to_owned()],
            problem_handles: vec!["problem:stale-proof".to_owned()],
            role_lease_ref: "role-lease-1".to_owned(),
            state_fence_ref: "fence-epoch-3-gen-7".to_owned(),
            governance: fixture_governance(),
            supported_count: 4,
            verified_count: 3,
            candidate_count: 1,
            conflicts_unknowns: vec![],
            next_safe_expansion: "bind task before material effects".to_owned(),
        }
    }

    fn eligible_task(index: usize) -> TaskCandidate {
        TaskCandidate {
            handle: format!("task-{index}"),
            task_revision: Some(u64::try_from(index + 1).expect("index must fit")),
            acceptance_digest: Some("a".repeat(64)),
            prior_evaluation_candidate_only: false,
            independent_binding_supplied: true,
        }
    }

    #[test]
    fn first_response_carries_bounded_bootstrap_with_governance_evidence() {
        let context = fixture_context(ReadinessDisposition::ReadyMaterial);
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Session,
            candidates: Vec::new(),
            authoritative_selection: None,
        };
        let mut session = BootstrapSession::default();
        let first = session
            .take_auto_boot(&context, &tasks, CurrentAssessment::Ready)
            .expect("first response must carry the bootstrap");
        assert_eq!(first.current_assessment, CurrentAssessment::Ready);
        assert_eq!(first.governance.profile_ref, "governance-profile-1");
        assert_eq!(first.governance.profile_revision, "rev-7");
        assert!(!first.governance.limiting_integration_evidence.is_empty());
        assert!(first.task_selection.candidate_task_handles.len() <= MAX_CANDIDATE_HANDLES);
        assert!(first.relevant_handles.len() <= MAX_HANDLES);
        assert!(first.revision_refs.len() <= MAX_HANDLES);
        assert!(session.auto_boot_delivered());
        assert!(
            session
                .take_auto_boot(&context, &tasks, CurrentAssessment::Ready)
                .is_none(),
            "bootstrap must be delivered exactly once per session",
        );
        let framed = serde_json::to_vec(&first).expect("bootstrap must serialize");
        assert!(!framed.is_empty());
    }

    #[test]
    fn ten_eligible_tasks_are_ambiguous_and_select_none() {
        let context = fixture_context(ReadinessDisposition::ReadyMaterial);
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Project,
            candidates: (0..10).map(eligible_task).collect(),
            authoritative_selection: None,
        };
        let bootstrap = get_understanding_bootstrap(&context, &tasks, CurrentAssessment::Ready)
            .expect("composition must succeed");
        assert_eq!(
            bootstrap.task_selection.disposition,
            TaskSelectionDisposition::Ambiguous
        );
        assert_eq!(bootstrap.task_selection.candidate_task_handles.len(), 10);
        assert!(
            bootstrap
                .task_selection
                .selected_task_and_revision
                .is_none(),
            "ambiguous selection must choose no task",
        );
        assert!(bootstrap.task_selection.acceptance_digest.is_none());
    }

    #[test]
    fn prior_evaluation_candidate_stays_crossover_contaminated_until_rebound() {
        let context = fixture_context(ReadinessDisposition::ReadyMaterial);
        let contaminated = TaskCandidate {
            handle: "task-eval-1".to_owned(),
            task_revision: Some(2),
            acceptance_digest: Some("b".repeat(64)),
            prior_evaluation_candidate_only: true,
            independent_binding_supplied: false,
        };
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Task,
            candidates: vec![contaminated],
            authoritative_selection: None,
        };
        let blocked = get_understanding_bootstrap(&context, &tasks, CurrentAssessment::Ready)
            .expect("composition must succeed");
        assert_eq!(
            blocked.task_selection.disposition,
            TaskSelectionDisposition::None
        );
        assert!(blocked.task_selection.selected_task_and_revision.is_none());
        assert!(
            blocked
                .task_selection
                .contamination_flags
                .contains(&CROSSOVER_CONTAMINATED.to_owned())
        );
        let rebound_tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Task,
            candidates: vec![TaskCandidate {
                handle: "task-eval-1".to_owned(),
                task_revision: Some(2),
                acceptance_digest: Some("b".repeat(64)),
                prior_evaluation_candidate_only: true,
                independent_binding_supplied: true,
            }],
            authoritative_selection: None,
        };
        let rebound =
            get_understanding_bootstrap(&context, &rebound_tasks, CurrentAssessment::Ready)
                .expect("composition must succeed");
        assert_eq!(
            rebound.task_selection.disposition,
            TaskSelectionDisposition::Unique
        );
        assert!(
            !rebound
                .task_selection
                .contamination_flags
                .contains(&CROSSOVER_CONTAMINATED.to_owned())
        );
        let selected = rebound
            .task_selection
            .selected_task_and_revision
            .expect("rebound task must be selected");
        assert_eq!(selected.task_ref, "task-eval-1");
    }

    #[test]
    fn assessment_never_stronger_than_readiness() {
        let context = fixture_context(ReadinessDisposition::NeedsTask);
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Session,
            candidates: Vec::new(),
            authoritative_selection: None,
        };
        let bootstrap = get_understanding_bootstrap(&context, &tasks, CurrentAssessment::Ready)
            .expect("composition must succeed");
        assert_eq!(
            bootstrap.current_assessment,
            CurrentAssessment::NotOnboarded
        );
        let read_only = fixture_context(ReadinessDisposition::ReadyReadOnly);
        let capped = get_understanding_bootstrap(&read_only, &tasks, CurrentAssessment::Ready)
            .expect("composition must succeed");
        assert_eq!(capped.current_assessment, CurrentAssessment::Degraded);
    }

    #[test]
    fn missing_governance_evidence_fails_closed() {
        let mut context = fixture_context(ReadinessDisposition::ReadyMaterial);
        context.governance.limiting_integration_evidence.clear();
        let tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Session,
            candidates: Vec::new(),
            authoritative_selection: None,
        };
        let error = get_understanding_bootstrap(&context, &tasks, CurrentAssessment::Ready)
            .expect_err("bootstrap without limiting integration evidence must fail");
        assert_eq!(error.code, "GOVERNANCE_EVIDENCE_MISSING");
    }
}
