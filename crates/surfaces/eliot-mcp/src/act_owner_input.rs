//! `eliot.act` surface-boundary binding of caller contributions to owner
//! inputs (issue #1742, work item 1).
//!
//! The issue's `## Current source` section states the measured position: the
//! `ActInput` contract "has `ActInput` with public intent, expected observable,
//! uncertainty and requested resources. These are caller contributions, not
//! current ActionContract/authority evidence. #1739 must connect this request to
//! the actual owner; a submitted host record is not permission to execute."
//!
//! This module is that surface boundary and nothing more. It:
//!
//! - resolves the effect class from the registered
//!   [`ToolSemanticProfile`](crate::ToolSemanticProfile) - the single semantic
//!   owner - and never from the tool name or from caller text;
//! - refuses a downgrade: a caller-declared read-only framing, or a resource
//!   claim under a profile that owns the read-only class, cannot lower a
//!   material effect;
//! - binds the caller's fields as [`CallerContribution`] values that are
//!   explicitly *not* evidence, and resolves the owner inputs the surface can
//!   resolve exactly (the retained State Fence and the task/acceptance
//!   revision) while naming - not fabricating - every owner input the semantic
//!   owner must still supply;
//! - fails closed when an owner input the operation structurally depends on is
//!   absent, naming the owner that must issue it.
//!
//! The module grants no authority, selects no task, and evaluates no
//! Decision Safety Floor: those belong to the Governor/Task Controller, Context,
//! and Kernel owners named in the issue's owner split. The applicable-floor
//! compiler itself is invoked by `eliot_context_admission::admit_material_decision`
//! at the owner side; this binding only refuses to let a caller submission stand
//! in for it.

use crate::{ActInput, BridgeError, EffectClass, OperationAccessClass, OperationRequirement};
use eliot_contracts::{StateFence, TaskRevision};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Owner that must resolve the action's effect/impact class and the applicable
/// Decision Safety Floor.
pub const OWNER_ACTION_MODEL: &str = "Governor action model and Task Controller";

/// Owner that must issue the active directives and the Governance Profile.
pub const OWNER_POLICY: &str = "Governance Profile and active-directive owner";

/// One owner input the semantic owner must still resolve for this request.
///
/// Each entry names an input and its owner. Nothing here fabricates a value, and
/// nothing here admits a default: an unlisted input is not a satisfied input.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredOwnerInput {
    /// Exact owner input that is still owed.
    pub input: String,
    /// Owner that must issue it.
    pub owner: String,
}

/// One caller-contributed `ActInput` value, explicitly not owner evidence.
///
/// The `ActInput` doc comment already says "Requested affected resources;
/// authority is not accepted here." This type makes that binding explicit and
/// machine-checkable: a contribution can be presented, forwarded, and audited,
/// but it is never read as an `ActionContract`, an authority grant, a Safety
/// Floor member, or proof that anything is retained or permitted.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerContribution {
    /// Exact field the caller populated.
    pub field: String,
    /// The caller-contributed text, verbatim.
    pub value: String,
    /// Always true: a caller contribution is not owner evidence.
    pub is_owner_evidence: bool,
}

impl CallerContribution {
    /// Bind one caller field as a non-evidence contribution.
    fn new(field: &str, value: &str) -> Self {
        Self {
            field: field.to_owned(),
            value: value.to_owned(),
            is_owner_evidence: false,
        }
    }
}

/// The surface-boundary binding of one `eliot.act` request to its owner inputs.
///
/// This is the exact record the surface hands inward. It states the
/// owner-resolved effect class, the retained fence, the task/acceptance revision
/// the request is bound to, every caller contribution verbatim, and every owner
/// input still owed. It carries no authority and no floor: those are the
/// semantic owner's decision, reached after this binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActOwnerInputBinding {
    /// Effect class resolved from the registered semantic profile owner.
    pub effect_class: EffectClass,
    /// Whether the canonical operation's contract classification is
    /// task-relative and effectful, so the applicable Decision Safety Floor and
    /// the phase-aware decision lineage apply to this request.
    pub task_relative_effectful: bool,
    /// Exact owner-resolved task identity for this request, when one is bound.
    pub task_id: Option<String>,
    /// Exact owner-resolved task/acceptance revision, when the fence carries one.
    pub acceptance_revision: Option<u64>,
    /// Retained State Fence the request is bound to.
    pub state_fence: StateFence,
    /// Exact task reference the dispatch gate is given.
    pub owner_task_ref: Option<String>,
    /// Every caller contribution, verbatim and marked as non-evidence.
    pub contributions: Vec<CallerContribution>,
    /// Owner inputs the semantic owner must still resolve.
    pub owner_inputs_owed: Vec<RequiredOwnerInput>,
}

impl ActOwnerInputBinding {
    /// Whether this request is task-relative and effectful, so the applicable
    /// Decision Safety Floor and the phase-aware decision lineage apply.
    #[must_use]
    pub const fn requires_decision_safety_floor(&self) -> bool {
        self.task_relative_effectful
    }

    /// Exact owner inputs still owed, as stable field tokens.
    #[must_use]
    pub fn owed_input_tokens(&self) -> Vec<&str> {
        self.owner_inputs_owed
            .iter()
            .map(|required| required.input.as_str())
            .collect()
    }
}

/// Bind one validated `eliot.act` request to its owner inputs.
///
/// `requirement` is the contract classification of the canonical operation
/// ([`crate::CanonicalOperation::requirement`]) and `profile` is the single
/// registered semantic owner it resolved to; both are produced by the existing
/// owner path, never reconstructed here. `fence` is the retained State Fence
/// from the authenticated request, and `task_id` is the Kernel-verified task
/// identity carried in request metadata when one is present.
///
/// # Errors
///
/// Fails closed, never with a synthesized value:
///
/// - `act.downgrade_effect_class` when the caller names affected resources under
///   a profile whose owner effect class is [`EffectClass::ReadOnly`]: a resource
///   claim is a state transition, and a read-only owner class cannot carry it.
///   A caller therefore cannot downgrade a material effect by choosing a tool
///   whose profile reads as read-only.
/// - `act.missing_task_revision` when the request is task-relative and effectful
///   but the retained fence carries no task/acceptance revision. The acceptance
///   revision is an owner input; the surface refuses rather than admitting an
///   action request whose applicable floor cannot be bound to a revision.
pub fn bind_act_owner_inputs(
    input: &ActInput,
    requirement: &OperationRequirement,
    profile: &crate::ToolSemanticProfile,
    fence: &StateFence,
    task_id: Option<&str>,
) -> Result<ActOwnerInputBinding, BridgeError> {
    let access_class = requirement.access_class;
    let effect_class = profile.effect_class;
    if matches!(effect_class, EffectClass::ReadOnly) && !input.affected_resources.is_empty() {
        return Err(BridgeError::InvalidArgument {
            field: "act.affected_resources",
            reason: "the registered semantic owner classifies this operation as read-only; a \
                     resource claim is a state transition and cannot be downgraded into one"
                .to_owned(),
        });
    }
    let acceptance_revision = fence.task_revision.map(TaskRevision::value);
    let task_relative_effectful =
        matches!(access_class, OperationAccessClass::TaskRelativeEffectful)
            && !matches!(effect_class, EffectClass::ReadOnly);
    if task_relative_effectful && acceptance_revision.is_none() {
        return Err(BridgeError::InvalidArgument {
            field: "act.acceptance_revision",
            reason: format!(
                "the retained State Fence carries no task/acceptance revision; {OWNER_ACTION_MODEL} \
                 must issue the current acceptance revision before an effectful action request is \
                 admitted"
            ),
        });
    }
    Ok(ActOwnerInputBinding {
        effect_class,
        task_relative_effectful,
        task_id: task_id.map(str::to_owned),
        acceptance_revision,
        state_fence: fence.clone(),
        owner_task_ref: owner_task_ref(task_id, acceptance_revision),
        contributions: act_contributions(input),
        owner_inputs_owed: owed_owner_inputs(effect_class),
    })
}

/// The exact task reference the dispatch gate is given.
///
/// Same spelling as the pre-existing request-metadata join, now derived through
/// the explicit owner-input binding: a request with no task and no task revision
/// binds `None` rather than an invented reference.
fn owner_task_ref(task_id: Option<&str>, acceptance_revision: Option<u64>) -> Option<String> {
    match (task_id, acceptance_revision) {
        (Some(task), Some(revision)) => Some(format!("{task}@{revision}")),
        (Some(task), None) => Some(task.to_owned()),
        (None, Some(revision)) => Some(format!("task-revision:{revision}")),
        (None, None) => None,
    }
}

/// Every `ActInput` field, bound verbatim as a non-evidence contribution.
fn act_contributions(input: &ActInput) -> Vec<CallerContribution> {
    let mut contributions = vec![
        CallerContribution::new("intent", &input.intent),
        CallerContribution::new("expected_observable", &input.expected_observable),
        CallerContribution::new("remaining_uncertainty", &input.remaining_uncertainty),
    ];
    for resource in &input.affected_resources {
        contributions.push(CallerContribution::new("affected_resources", resource));
    }
    contributions
}

/// The owner inputs this operation still owes, named rather than fabricated.
///
/// The two material entries are exactly the ones a caller submission can never
/// stand in for: the action's effect/impact class with its applicable Decision
/// Safety Floor, and the Governance Profile with its active directives. The
/// read-only class is listed too, because "no applicable floor" must itself be
/// an owner-issued statement rather than a consequence of the tool name.
fn owed_owner_inputs(effect_class: EffectClass) -> Vec<RequiredOwnerInput> {
    let mut owed = vec![
        RequiredOwnerInput {
            input: "action_effect_class_and_applicable_floor".to_owned(),
            owner: OWNER_ACTION_MODEL.to_owned(),
        },
        RequiredOwnerInput {
            input: "governance_profile_and_active_directives".to_owned(),
            owner: OWNER_POLICY.to_owned(),
        },
    ];
    if matches!(effect_class, EffectClass::ReadOnly) {
        owed.push(RequiredOwnerInput {
            input: "read_only_class_attestation".to_owned(),
            owner: OWNER_ACTION_MODEL.to_owned(),
        });
    }
    owed
}

/// Whether the canonical tool request is an `eliot.act` request.
///
/// Used by the request-admission seam to route exactly the action requests
/// through [`bind_act_owner_inputs`]; every other canonical tool is unaffected.
#[must_use]
pub const fn is_act_request(request: &crate::ToolRequest) -> bool {
    matches!(request, crate::ToolRequest::Act(_))
}
