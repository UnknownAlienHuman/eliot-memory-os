//! Governor-owned canonical projection composer (CC-004).
//!
//! Pure deterministic composer from the four Governor snapshots to the
//! owner-neutral projection set consumed through contracts. It takes only
//! shared references (`TaskLifecycleSnapshot`, `SessionLifecycleSnapshot`,
//! `WorkScopeBindingSnapshot`, and `ObservationJournalEntry` slices), enforces
//! one fence via [`eliot_contracts::fences_match_exact`], and reports gaps as
//! explicit [`ProjectionOmission`] records. It opens no store, touches no
//! Kernel port, and defines no new port: the output is data for the Smart
//! contract set, never an effect.
//!
//! Two pure producers sit here, in this order, and both are owner-neutral data
//! out of one owner:
//!
//! 1. [`compose_canonical_projections`] computes the Governor's own
//!    [`GovernorProjectionSet`] from canonical snapshots, with absent members
//!    recorded as [`ProjectionOmission`]s.
//! 2. [`emit_canonical_projection_set`] emits the Smart contract's
//!    [`CanonicalProjectionSet`] that the consumed value must present, under
//!    the shared [`ContextBinding`] the runtime already holds. It is reached in
//!    production through
//!    [`GovernorComposition::canonical_projections`](crate::GovernorComposition::canonical_projections),
//!    which feeds both producers this composition's own retained owners.
//!
//! The second step never mints the shared binding: `attempt_id` and
//! `decision_id` belong to the attempt and decision owners, so the binding
//! arrives as the caller parameter exactly as the Governor's own Context
//! composition receives it. Nothing here invents canonical state, role prose, or
//! an omission the Governor does not own.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_context_contracts::{
    AffordanceProjection, CANONICAL_PROJECTIONS_SCHEMA_VERSION, CanonicalProjectionSet,
    ContextBinding, ContextError, ContinuityProjection, SafetyProjection, TaskProjection,
};
use eliot_contracts::{StateFence, TaskId, fences_match_exact};
use eliot_observation::ObservationJournalEntry;
use eliot_session::SessionLifecycleSnapshot;
use eliot_task::{TaskLifecycleSnapshot, TaskState};
use eliot_workscope::WorkScopeBindingSnapshot;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact schema version accepted by the projection shapes.
pub const GOVERNOR_PROJECTIONS_SCHEMA_VERSION: u32 = 1;
/// Maximum negative-memory triggers carried by one safety projection.
pub const MAX_SAFETY_TRIGGERS: usize = 64;
/// Maximum affordances carried by one affordance projection.
pub const MAX_AFFORDANCES: usize = 64;
/// Maximum omissions carried by one set.
pub const MAX_PROJECTION_OMISSIONS: usize = 64;
/// Maximum bytes of one projection text field.
pub const MAX_PROJECTION_TEXT: usize = 1024;

/// Fail-closed errors from the pure composer.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GovernorProjectionError {
    /// The supplied fence is invalid.
    #[error("governor projection fence is invalid")]
    InvalidFence,
    /// A canonical fence does not match the requested fence.
    #[error("governor projection fence mismatch")]
    FenceMismatch,
    /// A canonical snapshot failed its own validation.
    #[error("governor projection snapshot is invalid: {0}")]
    InvalidSnapshot(&'static str),
    /// A projection text field is malformed or over bound.
    #[error("governor projection field is invalid: {0}")]
    InvalidField(&'static str),
    /// A repeated field exceeds its bound or carries duplicates.
    #[error("governor projection bound exceeded: {0}")]
    Bounds(&'static str),
    /// One composed member is absent under this fence, so the contract set
    /// that requires it cannot be emitted.
    ///
    /// The consumer contract carries all four projections as mandatory members
    /// and its `omissions` field holds Context-compilation omission records
    /// (an atom identity, a source identity, a decision revision, and a
    /// reversal handle) that this owner cannot mint from canonical task, plan,
    /// safety, or scope state. An absent member therefore stays absent: the
    /// exact owner reason stays readable in the emitted side's
    /// [`ProjectionOmission`] list and this typed refusal carries only which
    /// member is missing.
    #[error("governor projection member is absent: {0}")]
    MemberOmitted(&'static str),
    /// The emitted value failed the consumer contract's own validation.
    ///
    /// The contract error is carried verbatim instead of being flattened to a
    /// field name, so the exact cause a consumer would raise stays readable at
    /// this boundary. That includes the contract's own
    /// [`ContextError::MissingField`] for an empty `affordances` list, which is
    /// the reason an authorized-but-empty affordance projection cannot be
    /// emitted rather than filled.
    #[error("canonical projection set is not admitted: {0}")]
    Contract(ContextError),
}

fn check_text(value: &str, field: &'static str) -> Result<(), GovernorProjectionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(GovernorProjectionError::InvalidField(field));
    }
    if value.len() > MAX_PROJECTION_TEXT {
        return Err(GovernorProjectionError::Bounds(field));
    }
    Ok(())
}

fn check_entries(values: &[String], field: &'static str) -> Result<(), GovernorProjectionError> {
    if values.len() > MAX_SAFETY_TRIGGERS.max(MAX_AFFORDANCES) {
        return Err(GovernorProjectionError::Bounds(field));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        check_text(value, field)?;
        if !seen.insert(value.clone()) {
            return Err(GovernorProjectionError::Bounds(field));
        }
    }
    Ok(())
}

fn check_version(version: u32) -> Result<(), GovernorProjectionError> {
    if version != GOVERNOR_PROJECTIONS_SCHEMA_VERSION {
        return Err(GovernorProjectionError::InvalidField(
            "projections.schema_version",
        ));
    }
    Ok(())
}

/// Canonical task/goal projection composed from one [`TaskRecord`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GovernorTaskProjection {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Projected task identity.
    pub task_id: TaskId,
    /// Goal copied verbatim from the canonical record.
    pub goal: String,
    /// State copied verbatim from the canonical record.
    pub state: TaskState,
    /// Revision copied verbatim from the canonical record.
    pub revision: u64,
}

impl GovernorTaskProjection {
    /// Validates intrinsic bounds.
    pub fn validate(&self) -> Result<(), GovernorProjectionError> {
        check_version(self.schema_version)?;
        check_text(&self.goal, "task.goal")?;
        if self.revision == 0 {
            return Err(GovernorProjectionError::InvalidField("task.revision"));
        }
        Ok(())
    }
}

/// Continuity/plan projection composed from task plus session liveness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GovernorContinuityProjection {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Projected task identity.
    pub task_id: TaskId,
    /// Mechanical plan state (`<STATE-WIRE>:rev<N>:<K>-open`).
    pub plan_state: String,
    /// Non-terminal sessions bound to this task.
    pub open_sessions: u64,
    /// Last task sequence observed in the snapshot.
    pub last_sequence: u64,
}

impl GovernorContinuityProjection {
    /// Validates intrinsic bounds.
    pub fn validate(&self) -> Result<(), GovernorProjectionError> {
        check_version(self.schema_version)?;
        check_text(&self.plan_state, "continuity.plan_state")?;
        Ok(())
    }
}

/// Safety projection with exact negative-memory triggers.
///
/// Triggers are the verbatim contract-error strings from rejected journal
/// entries; this composer never invents trigger prose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GovernorSafetyProjection {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Projected task identity.
    pub task_id: TaskId,
    /// Mechanical safety note (counts only, no new prose).
    pub safety_note: String,
    /// Exact negative-memory trigger identities from rejections.
    pub negative_memory_triggers: Vec<String>,
}

impl GovernorSafetyProjection {
    /// Validates intrinsic bounds.
    pub fn validate(&self) -> Result<(), GovernorProjectionError> {
        check_version(self.schema_version)?;
        check_text(&self.safety_note, "safety.safety_note")?;
        if self.negative_memory_triggers.len() > MAX_SAFETY_TRIGGERS {
            return Err(GovernorProjectionError::Bounds(
                "safety.negative_memory_triggers",
            ));
        }
        check_entries(
            &self.negative_memory_triggers,
            "safety.negative_memory_triggers",
        )?;
        Ok(())
    }
}

/// Affordance projection composed from the current `WorkScope` binding.
///
/// Affordances are the verbatim scope/instance identities from the admitted
/// binding; capability is never invented here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GovernorAffordanceProjection {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Projected task identity.
    pub task_id: TaskId,
    /// Scope the affordances are authorized for.
    pub scope_ref: String,
    /// Authorized scope/instance identities.
    pub affordances: Vec<String>,
}

impl GovernorAffordanceProjection {
    /// Validates intrinsic bounds.
    pub fn validate(&self) -> Result<(), GovernorProjectionError> {
        check_version(self.schema_version)?;
        check_text(&self.scope_ref, "affordance.scope_ref")?;
        if self.affordances.is_empty() || self.affordances.len() > MAX_AFFORDANCES {
            return Err(GovernorProjectionError::Bounds("affordance.affordances"));
        }
        check_entries(&self.affordances, "affordance.affordances")?;
        Ok(())
    }
}

/// Explicit omission for one missing projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectionOmission {
    /// Which projection is missing (`task`, `continuity`, `safety`, `affordance`).
    pub missing: String,
    /// Stable reason class (`task-not-found`, `fence-filtered`, ...).
    pub reason: String,
}

impl ProjectionOmission {
    /// Validates the omission record.
    pub fn validate(&self) -> Result<(), GovernorProjectionError> {
        match self.missing.as_str() {
            "task" | "continuity" | "safety" | "affordance" => {}
            _ => {
                return Err(GovernorProjectionError::InvalidField("omission.missing"));
            }
        }
        check_text(&self.reason, "omission.reason")?;
        Ok(())
    }
}

/// One composed set under a single shared fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GovernorProjectionSet {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Shared fence every composed value satisfies.
    pub fence: StateFence,
    /// Projected task identity.
    pub task_id: TaskId,
    /// Scope the affordances are authorized for.
    pub scope_ref: String,
    /// Task projection when the record exists under this fence.
    pub task: Option<GovernorTaskProjection>,
    /// Continuity projection when the task exists under this fence.
    pub continuity: Option<GovernorContinuityProjection>,
    /// Safety projection with exact rejection triggers.
    pub safety: Option<GovernorSafetyProjection>,
    /// Affordance projection from the current scope binding.
    pub affordance: Option<GovernorAffordanceProjection>,
    /// Explicit omissions, one per missing projection.
    pub omissions: Vec<ProjectionOmission>,
}

impl GovernorProjectionSet {
    /// Returns whether one fence can share this set's decision scope.
    ///
    /// Exact in both directions, so an absent optional revision on the
    /// presented fence is not a wildcard for this set's revision.
    #[must_use]
    pub fn is_compatible_with(&self, fence: &StateFence) -> bool {
        fences_match_exact(&self.fence, fence)
    }

    /// Validates the set: versions, fence, members, and omission coverage.
    pub fn validate(&self) -> Result<(), GovernorProjectionError> {
        check_version(self.schema_version)?;
        self.fence
            .validate()
            .map_err(|_| GovernorProjectionError::InvalidFence)?;
        check_text(&self.scope_ref, "projections.scope_ref")?;
        if self.omissions.len() > MAX_PROJECTION_OMISSIONS {
            return Err(GovernorProjectionError::Bounds("projections.omissions"));
        }
        for omission in &self.omissions {
            omission.validate()?;
        }
        if let Some(task) = &self.task {
            task.validate()?;
            if task.task_id != self.task_id {
                return Err(GovernorProjectionError::InvalidField("task.task_id"));
            }
        }
        if let Some(continuity) = &self.continuity {
            continuity.validate()?;
            if continuity.task_id != self.task_id {
                return Err(GovernorProjectionError::InvalidField("continuity.task_id"));
            }
        }
        if let Some(safety) = &self.safety {
            safety.validate()?;
            if safety.task_id != self.task_id {
                return Err(GovernorProjectionError::InvalidField("safety.task_id"));
            }
        }
        if let Some(affordance) = &self.affordance {
            affordance.validate()?;
            if affordance.task_id != self.task_id {
                return Err(GovernorProjectionError::InvalidField("affordance.task_id"));
            }
            if affordance.scope_ref != self.scope_ref {
                return Err(GovernorProjectionError::InvalidField(
                    "affordance.scope_ref",
                ));
            }
        }
        for name in ["task", "continuity", "safety", "affordance"] {
            let present = match name {
                "task" => self.task.is_some(),
                "continuity" => self.continuity.is_some(),
                "safety" => self.safety.is_some(),
                "affordance" => self.affordance.is_some(),
                _ => false,
            };
            let omitted = self.omissions.iter().any(|o| o.missing == name);
            if !present && !omitted {
                return Err(GovernorProjectionError::InvalidField(
                    "projections.omissions",
                ));
            }
            if present && omitted {
                return Err(GovernorProjectionError::InvalidField(
                    "projections.omissions",
                ));
            }
        }
        Ok(())
    }
}

fn state_wire(state: TaskState) -> Result<String, GovernorProjectionError> {
    let value = serde_json::to_value(state)
        .map_err(|_| GovernorProjectionError::InvalidField("task.state"))?;
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(GovernorProjectionError::InvalidField("task.state"))
}

fn project_task(
    task_snapshot: &TaskLifecycleSnapshot,
    task_id: &TaskId,
    fence: &StateFence,
    omissions: &mut Vec<ProjectionOmission>,
) -> Result<Option<GovernorTaskProjection>, GovernorProjectionError> {
    let Some(record) = task_snapshot.tasks.get(task_id) else {
        omissions.push(ProjectionOmission {
            missing: "task".to_owned(),
            reason: "task-not-found".to_owned(),
        });
        return Ok(None);
    };
    if !fences_match_exact(&record.state_fence, fence) {
        return Err(GovernorProjectionError::FenceMismatch);
    }
    check_text(&record.goal, "task.goal")?;
    Ok(Some(GovernorTaskProjection {
        schema_version: GOVERNOR_PROJECTIONS_SCHEMA_VERSION,
        task_id: task_id.clone(),
        goal: record.goal.clone(),
        state: record.state,
        revision: record.revision,
    }))
}

fn project_continuity(
    task: Option<&GovernorTaskProjection>,
    session_snapshot: &SessionLifecycleSnapshot,
    task_snapshot: &TaskLifecycleSnapshot,
    task_id: &TaskId,
    fence: &StateFence,
    omissions: &mut Vec<ProjectionOmission>,
) -> Result<Option<GovernorContinuityProjection>, GovernorProjectionError> {
    let Some(projected) = task else {
        omissions.push(ProjectionOmission {
            missing: "continuity".to_owned(),
            reason: "task-not-found".to_owned(),
        });
        return Ok(None);
    };
    let wanted = task_id.as_str().to_owned();
    let mut open: u64 = 0;
    for session in session_snapshot.sessions.values() {
        if session.task_scope.as_deref() != Some(wanted.as_str()) {
            continue;
        }
        if fences_match_exact(&session.state_fence, fence) && !session.status.terminal() {
            open = open.saturating_add(1);
        }
    }
    let wire = state_wire(projected.state)?;
    check_text(&wire, "continuity.plan_state")?;
    let plan_state = std::format!("{}:rev{}:{}-open", wire, projected.revision, open);
    check_text(&plan_state, "continuity.plan_state")?;
    let last_sequence = task_snapshot.next_sequence.saturating_sub(1);
    Ok(Some(GovernorContinuityProjection {
        schema_version: GOVERNOR_PROJECTIONS_SCHEMA_VERSION,
        task_id: task_id.clone(),
        plan_state,
        open_sessions: open,
        last_sequence,
    }))
}

fn project_affordance(
    scope_snapshot: &WorkScopeBindingSnapshot,
    scope_ref: &str,
    task_id: &TaskId,
) -> Result<GovernorAffordanceProjection, GovernorProjectionError> {
    let instance_ref = scope_snapshot.binding.scope.instance_ref.clone();
    check_text(&instance_ref, "affordance.scope_ref")?;
    let mut affordances = vec![scope_ref.to_owned()];
    if instance_ref != scope_ref {
        affordances.push(instance_ref);
    }
    affordances.sort();
    affordances.dedup();
    check_entries(&affordances, "affordance.affordances")?;
    Ok(GovernorAffordanceProjection {
        schema_version: GOVERNOR_PROJECTIONS_SCHEMA_VERSION,
        task_id: task_id.clone(),
        scope_ref: scope_ref.to_owned(),
        affordances,
    })
}

/// Composes the canonical projection set from four snapshot references.
///
/// The function is pure and deterministic: same snapshots always yield the
/// same ordered set. It enforces one fence — the scope binding fence and the
/// task record fence must each be compatible with `fence` in both directions
/// — and reports missing task/continuity data as explicit omissions instead
/// of filler. No store, Kernel, network, or clock is touched.
///
/// # Errors
///
/// Returns [`GovernorProjectionError`] when the fence is invalid, the scope
/// snapshot is invalid, a fence gate fails, or a composed text/bound rule
/// fails.
pub fn compose_canonical_projections(
    task_snapshot: &TaskLifecycleSnapshot,
    session_snapshot: &SessionLifecycleSnapshot,
    scope_snapshot: &WorkScopeBindingSnapshot,
    _journal: &[ObservationJournalEntry],
    task_id: &TaskId,
    fence: &StateFence,
) -> Result<GovernorProjectionSet, GovernorProjectionError> {
    fence
        .validate()
        .map_err(|_| GovernorProjectionError::InvalidFence)?;
    scope_snapshot
        .validate()
        .map_err(|_| GovernorProjectionError::InvalidSnapshot("workscope"))?;
    if !fences_match_exact(&scope_snapshot.state_fence, fence) {
        return Err(GovernorProjectionError::FenceMismatch);
    }
    let scope_ref = scope_snapshot.binding.scope.scope_ref.clone();
    check_text(&scope_ref, "projections.scope_ref")?;

    let mut omissions = Vec::new();
    let task = project_task(task_snapshot, task_id, fence, &mut omissions)?;
    let continuity = project_continuity(
        task.as_ref(),
        session_snapshot,
        task_snapshot,
        task_id,
        fence,
        &mut omissions,
    )?;
    // Rejection diagnostics remain in the retained ObservationJournal, but
    // those rows carry no exact task-selection evidence to bind them to this
    // requested task. Keep safety absent until a governed task-bound source is
    // available instead of presenting an empty list as a clean safety result.
    let safety = None;
    omissions.push(ProjectionOmission {
        missing: "safety".to_owned(),
        reason: "no-governed-task-safety-source".to_owned(),
    });
    let affordance = Some(project_affordance(scope_snapshot, &scope_ref, task_id)?);

    let set = GovernorProjectionSet {
        schema_version: GOVERNOR_PROJECTIONS_SCHEMA_VERSION,
        fence: fence.clone(),
        task_id: task_id.clone(),
        scope_ref,
        task,
        continuity,
        safety,
        affordance,
        omissions,
    };
    set.validate()?;
    Ok(set)
}

/// Emits the owner-neutral CC-004 projection set a consumer must present.
///
/// [`compose_canonical_projections`] proves the composed set first (versions,
/// exact fence, member validation, and the present/omitted closure of its
/// omissions), then this function re-proves the same exact fence against the
/// caller's [`ContextBinding`] with [`fences_match_exact`] before emitting. The
/// binding is a parameter and is never minted: `attempt_id` and `decision_id`
/// belong to the attempt and decision owners, exactly as the Governor's own
/// Context composition receives a binding rather than deriving one. The shared
/// binding is copied verbatim onto all four members, which is what the contract
/// set's own [`CanonicalProjectionSet::validate`] then requires to be equal and
/// to share one exact fence.
///
/// Prose discipline: `goal`, `plan_state`, `safety_note`, and every
/// `negative_memory_triggers`/`affordances` entry are the verbatim
/// Governor-computed values. The one composed field is `continuity_note`,
/// because the Governor holds the resume edge only as counts; it is the same
/// mechanical wire shape [`project_continuity`] already composes for
/// `plan_state` (`<STATE-WIRE>:rev<N>:<K>-open:<seq>`), not narrative text. An
/// absent member is never filled: it returns
/// [`GovernorProjectionError::MemberOmitted`] naming the member while the exact
/// owner reason stays readable in the composed set's own omissions.
///
/// `omissions` travels empty on the emitted value, which is what completeness
/// means here rather than a dropped field: all four members are present, so the
/// composed set's own present/omitted closure already proved it carries no
/// omission, and the contract's `omissions` holds Context-compilation records
/// this owner does not mint.
///
/// # Errors
///
/// Returns [`GovernorProjectionError::MemberOmitted`] when a member is absent
/// under this fence, [`GovernorProjectionError::FenceMismatch`] when the
/// composed fence and the supplied binding disagree,
/// [`GovernorProjectionError::InvalidField`] when the binding is itself
/// invalid or names another task, and [`GovernorProjectionError::Contract`]
/// carrying the consumer's own error when the emitted set fails the contract's
/// validation. No value is emitted that the consumer's `validate()` would not
/// accept.
pub fn emit_canonical_projection_set(
    binding: &ContextBinding,
    set: &GovernorProjectionSet,
) -> Result<CanonicalProjectionSet, GovernorProjectionError> {
    set.validate()?;
    if !fences_match_exact(&set.fence, &binding.state_fence) {
        return Err(GovernorProjectionError::FenceMismatch);
    }
    // A fence match alone does not make this set the binding's set: two tasks can
    // share one epoch and generation. Carrying one task's goal under another
    // task's binding would pass every contract validation while answering a
    // different question, so the task identity is compared before emission.
    if set.task_id != binding.task_id {
        return Err(GovernorProjectionError::InvalidField(
            "context binding.task_id",
        ));
    }
    binding
        .validate()
        .map_err(|_| GovernorProjectionError::InvalidField("context binding"))?;

    let task = match &set.task {
        Some(task) => TaskProjection {
            schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
            binding: binding.clone(),
            goal: task.goal.clone(),
            // The Governor computes the goal and its revision, not a
            // commitment list; the contract admits an empty one and inventing
            // commitments would be fabricated role prose.
            commitments: Vec::new(),
        },
        None => return Err(omitted_member(set, "task")),
    };
    let continuity = match &set.continuity {
        Some(continuity) => ContinuityProjection {
            schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
            binding: binding.clone(),
            plan_state: continuity.plan_state.clone(),
            continuity_note: std::format!(
                "{}:{}-open:{}",
                continuity.plan_state,
                continuity.open_sessions,
                continuity.last_sequence
            ),
        },
        None => return Err(omitted_member(set, "continuity")),
    };
    let safety = match &set.safety {
        Some(safety) => SafetyProjection {
            schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
            binding: binding.clone(),
            safety_note: safety.safety_note.clone(),
            negative_memory_triggers: safety.negative_memory_triggers.clone(),
        },
        None => return Err(omitted_member(set, "safety")),
    };
    let affordance = match &set.affordance {
        Some(affordance) => AffordanceProjection {
            schema_version: CANONICAL_PROJECTIONS_SCHEMA_VERSION,
            binding: binding.clone(),
            affordances: affordance.affordances.clone(),
        },
        None => return Err(omitted_member(set, "affordance")),
    };

    let emitted = CanonicalProjectionSet {
        binding: binding.clone(),
        task,
        continuity,
        safety,
        affordance,
        omissions: Vec::new(),
    };
    // The contract's own `validate` is the admission gate, and its error is
    // carried verbatim. An empty `affordances` list therefore surfaces here as
    // the contract's `ContextError::MissingField("affordance.affordances")`
    // rather than as a Governor-side field name, because the Governor does not
    // own that rule and must not restate it.
    emitted
        .validate()
        .map_err(GovernorProjectionError::Contract)?;
    Ok(emitted)
}

/// Maps one absent member to its typed omission refusal.
///
/// The member must already appear in the composed set's own omission list —
/// [`GovernorProjectionSet::validate`] proved the present/omitted closure
/// above, so an absent member always does. The check is re-stated here because
/// this function is the boundary a caller reads: a member absent with no owner
/// reason to show is an owner defect, and it must not be reported as a covered
/// omission.
fn omitted_member(set: &GovernorProjectionSet, member: &'static str) -> GovernorProjectionError {
    if set
        .omissions
        .iter()
        .any(|omission| omission.missing == member)
    {
        GovernorProjectionError::MemberOmitted(member)
    } else {
        GovernorProjectionError::InvalidField("projections.omissions")
    }
}
