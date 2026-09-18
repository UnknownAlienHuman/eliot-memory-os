//! Bind a sealed swarm-launch candidate to exact A-02 staffing.
//!
//! [`bind_swarm_launch`] consumes one sealed in-process [`SwarmCommandCandidate`]
//! whose kind is [`SwarmCommandKind::RequestSwarmLaunch`] (compiled by the 484
//! launch compiler) plus the current [`ModelCatalogueSnapshot`] and
//! [`HumanModelPreferencePolicy`] supplied by their injected owners. It
//! revalidates the exact candidate bindings — account scope, catalogue
//! snapshot ID/digest, preference policy ID/revision/digest, view
//! revision/StateFence, and the sealed source digest — recompiles one
//! deterministic [`ModelSelectionReceipt`] per demanded role through the exact
//! owner entrypoint [`compile_model_selection`], and projects the receipts
//! into a bounded [`SwarmStaffingCandidate`] through the exact owner
//! entrypoint [`compile_swarm_staffing`]. There is no second selector,
//! scheduler, ranking, or staffing path: eligibility, ranking, receipt
//! minting, slot admission, and gap classification stay owned by those two
//! compilers; this module only admits exact current values and records the
//! resulting [`SwarmLaunchBinding`].
//!
//! Fail-closed binding, in deterministic precedence:
//!
//! 1. sealed-candidate structural validation (tampered bytes are rejected by
//!    the candidate digest closure before any other check);
//! 2. launch-kind admission (a non-launch candidate is not a launch binding);
//! 3. single-generation agreement across the admitted set (account scope,
//!    catalogue snapshot ID, Human policy ID/revision);
//! 4. full-generation digest closure: the catalogue/policy digests recomputed
//!    from the current values must equal the sealed pins, otherwise
//!    [`SwarmLaunchBindError::StaleCatalogue`] /
//!    [`SwarmLaunchBindError::StalePolicy`]. Route-bearing bytes are covered
//!    by the catalogue digest pin, so a route change under the same snapshot
//!    identity also fails closed here as stale;
//! 5. per-role exact-current construction: one deterministic selection per
//!    demanded role through [`compile_model_selection`], each asserted to
//!    reproduce the sealed route binding byte-identically (post-closure this
//!    assertion passes for honest inputs; a mismatch means an incoherent
//!    candidate and fails closed);
//! 6. bounded staffing admission (`duplicate role/ordinal/selection identity`
//!    and reused catalogue entries fail closed inside
//!    [`compile_swarm_staffing`]; missing roles, rejected routes, and
//!    independence/diversity limitations surface as typed [`StaffingGap`]
//!    values preserved verbatim, never promoted or repaired).
//!
//! The output is structurally candidate-only: `candidate_only` is true,
//! `dispatch_authority` is false, execution counters are zero, and the value
//! carries no `WorkLeaseId`, `AttemptId`, route admission receipt, process
//! control, mailbox/Concilium state, Task completion, or Finish authority. It
//! performs no provider/model call, no process launch or cancel, no
//! lease/fence issuance, no route admission, no Task write, and no automatic
//! fallback.
//!
//! Deliberately NOT constructed here: `StaffingPlanRequest` /
//! `AgentLaunchRequest`. Those admission inputs require recipe, work-unit
//! (`RoleProfileId`/`WorkUnitId`), budget, and competence identities that are
//! absent from the sealed launch candidate, and no owner maps `ModelRole`
//! slots onto that lane system (cf. the 486 Contract Challenge). Inventing
//! those identities locally would mint authority the issue forbids; the
//! binding instead carries the exact staffed slots, per-role selection
//! receipts, and task/plan/view pins the downstream admission owner binds
//! against, with canonical digests over all of them.
//!
//! Proof ceiling: `SWARM_LAUNCH_BINDING_PACKAGE_PROOF_ONLY`. Provider process
//! execution, live `WorkLease`/`StateFence` issuance, route admission,
//! mailbox/Concilium, strict Finish, and Product Pulse remain separate.

use eliot_agent_api::StateFence;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::model_control::{
    HumanModelPreferencePolicy, ModelCatalogueSnapshot, ModelControlError, ModelRole,
    ModelSelectionReceipt, ZeroModelExecutionCounters, canonical_digest, catalogue_digest,
    compile_model_selection, preference_policy_digest, validate_canonical_digest,
};
use crate::swarm_command_candidate::{
    SwarmCommandCandidate, SwarmCommandCandidateError, SwarmCommandKind,
};
use crate::swarm_staffing::{
    MAX_STAFFING_SLOTS, SwarmStaffingCandidate, SwarmStaffingError, SwarmStaffingRequest,
    compile_swarm_staffing,
};

/// Schema identity for the candidate-only launch-binding value.
pub const SWARM_LAUNCH_BINDING_VERSION: &str = "eliot.agent-swarm-launch-binding/v1";

fn validate_text(value: &str, field: &'static str) -> Result<(), SwarmLaunchBindError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SwarmLaunchBindError::InvalidField(field));
    }
    Ok(())
}

/// Fail-closed launch-binding errors. Every production path returns these
/// instead of panicking; a malformed, unauthorized, stale, mismatched, or
/// conflicting binding is rejected, never repaired.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SwarmLaunchBindError {
    #[error(transparent)]
    ModelControl(#[from] ModelControlError),
    #[error(transparent)]
    CommandCandidate(#[from] SwarmCommandCandidateError),
    #[error(transparent)]
    Staffing(#[from] SwarmStaffingError),
    #[error("invalid swarm launch-binding field: {0}")]
    InvalidField(&'static str),
    #[error("swarm launch binding pins a stale catalogue generation")]
    StaleCatalogue,
    #[error("swarm launch binding pins a stale Human preference policy generation")]
    StalePolicy,
    #[error("swarm launch binding identity conflict: same id with changed bytes")]
    IdentityConflict,
}

/// Exact binding input: the sealed in-process launch candidate plus the
/// current catalogue/policy generation observed at `now_unix_ms`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmLaunchBindRequest {
    pub candidate: SwarmCommandCandidate,
    pub catalogue: ModelCatalogueSnapshot,
    pub policy: HumanModelPreferencePolicy,
    pub now_unix_ms: u64,
}

/// Deterministic, bounded, candidate-only launch binding. Replaying the exact
/// input reproduces the exact value; reusing the command identity with
/// changed bytes is a conflict detected by
/// [`SwarmLaunchBinding::replay_disposition`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmLaunchBinding {
    pub schema_version: String,
    pub command_id: String,
    pub command_digest: String,
    pub account_scope: String,
    pub view_revision: String,
    pub view_fence: StateFence,
    pub task_id: String,
    pub plan_revision: String,
    pub catalogue_snapshot_id: String,
    pub catalogue_digest: String,
    pub preference_policy_id: String,
    pub preference_revision: String,
    pub preference_policy_digest: String,
    pub staffing_id: String,
    pub staffing_digest: String,
    /// One deterministic selection per demanded role in canonical
    /// [`ModelRole`] order. Each receipt is byte-identical to a direct
    /// [`compile_model_selection`] call against the bound generation.
    pub selections: Vec<ModelSelectionReceipt>,
    /// Bounded staffing compiled from exactly the bound selections.
    pub staffing: SwarmStaffingCandidate,
    /// Canonical digest over the binding identity plus every bound pin,
    /// including the sealed source digest and the staffing digest.
    /// Validators recompute; a tampered copy is rejected.
    pub binding_digest: String,
    pub execution: ZeroModelExecutionCounters,
    pub candidate_only: bool,
    pub dispatch_authority: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SwarmLaunchBindingFields {
    schema_version: String,
    command_id: String,
    command_digest: String,
    account_scope: String,
    view_revision: String,
    view_fence: StateFence,
    task_id: String,
    plan_revision: String,
    catalogue_snapshot_id: String,
    catalogue_digest: String,
    preference_policy_id: String,
    preference_revision: String,
    preference_policy_digest: String,
    staffing_id: String,
    staffing_digest: String,
    selections: Vec<ModelSelectionReceipt>,
    staffing: SwarmStaffingCandidate,
    binding_digest: String,
    execution: ZeroModelExecutionCounters,
    candidate_only: bool,
    dispatch_authority: bool,
}

impl<'de> Deserialize<'de> for SwarmLaunchBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = SwarmLaunchBindingFields::deserialize(deserializer)?;
        let binding = Self {
            schema_version: fields.schema_version,
            command_id: fields.command_id,
            command_digest: fields.command_digest,
            account_scope: fields.account_scope,
            view_revision: fields.view_revision,
            view_fence: fields.view_fence,
            task_id: fields.task_id,
            plan_revision: fields.plan_revision,
            catalogue_snapshot_id: fields.catalogue_snapshot_id,
            catalogue_digest: fields.catalogue_digest,
            preference_policy_id: fields.preference_policy_id,
            preference_revision: fields.preference_revision,
            preference_policy_digest: fields.preference_policy_digest,
            staffing_id: fields.staffing_id,
            staffing_digest: fields.staffing_digest,
            selections: fields.selections,
            staffing: fields.staffing,
            binding_digest: fields.binding_digest,
            execution: fields.execution,
            candidate_only: fields.candidate_only,
            dispatch_authority: fields.dispatch_authority,
        };
        binding.validate().map_err(D::Error::custom)?;
        Ok(binding)
    }
}

impl SwarmLaunchBinding {
    fn digest(&self) -> Result<String, ModelControlError> {
        let selection_digests: Vec<&str> = self
            .selections
            .iter()
            .map(|selection| selection.selection_digest.as_str())
            .collect();
        canonical_digest(&(
            SWARM_LAUNCH_BINDING_VERSION,
            self.command_id.as_str(),
            self.command_digest.as_str(),
            self.account_scope.as_str(),
            self.view_revision.as_str(),
            &self.view_fence,
            self.task_id.as_str(),
            self.plan_revision.as_str(),
            self.catalogue_snapshot_id.as_str(),
            self.catalogue_digest.as_str(),
            self.preference_policy_id.as_str(),
            self.preference_revision.as_str(),
            self.preference_policy_digest.as_str(),
            self.staffing_id.as_str(),
            self.staffing_digest.as_str(),
            selection_digests,
        ))
    }

    /// Validates identity, ordering, selection/staffing binding, pin
    /// agreement, digest closure, and the candidate-only ceiling. Called on
    /// deserialization and after binding. Full revalidation against the
    /// sealed candidate and the current catalogue/policy generation requires
    /// [`bind_swarm_launch`]; this check covers internal consistency only.
    pub fn validate(&self) -> Result<(), SwarmLaunchBindError> {
        if self.schema_version != SWARM_LAUNCH_BINDING_VERSION {
            return Err(SwarmLaunchBindError::ModelControl(
                ModelControlError::UnsupportedSchema("swarm_launch_binding"),
            ));
        }
        for (value, field) in [
            (self.command_id.as_str(), "launch.command_id"),
            (self.account_scope.as_str(), "launch.account_scope"),
            (self.view_revision.as_str(), "launch.view_revision"),
            (self.task_id.as_str(), "launch.task_id"),
            (self.plan_revision.as_str(), "launch.plan_revision"),
            (
                self.catalogue_snapshot_id.as_str(),
                "launch.catalogue_snapshot_id",
            ),
            (
                self.preference_policy_id.as_str(),
                "launch.preference_policy_id",
            ),
            (
                self.preference_revision.as_str(),
                "launch.preference_revision",
            ),
            (self.staffing_id.as_str(), "launch.staffing_id"),
        ] {
            validate_text(value, field)?;
        }
        validate_canonical_digest(&self.command_digest, "launch.command_digest")?;
        validate_canonical_digest(&self.catalogue_digest, "launch.catalogue_digest")?;
        validate_canonical_digest(
            &self.preference_policy_digest,
            "launch.preference_policy_digest",
        )?;
        validate_canonical_digest(&self.staffing_digest, "launch.staffing_digest")?;
        validate_canonical_digest(&self.binding_digest, "launch.binding_digest")?;
        if self.view_fence.validate().is_err() {
            return Err(SwarmLaunchBindError::InvalidField("launch.view_fence"));
        }
        self.validate_selections()?;
        self.staffing.validate()?;
        if self.staffing_id != self.staffing.staffing_id
            || self.staffing_digest != self.staffing.staffing_digest
        {
            return Err(SwarmLaunchBindError::InvalidField("launch.staffing"));
        }
        if self.account_scope != self.staffing.account_scope
            || self.catalogue_snapshot_id != self.staffing.catalogue_snapshot_id
            || self.catalogue_digest != self.staffing.catalogue_digest
            || self.preference_policy_id != self.staffing.preference_policy_id
            || self.preference_revision != self.staffing.preference_revision
            || self.preference_policy_digest != self.staffing.preference_policy_digest
        {
            return Err(SwarmLaunchBindError::InvalidField("launch.generation"));
        }
        if !self.candidate_only || self.dispatch_authority {
            return Err(SwarmLaunchBindError::InvalidField("launch.authority"));
        }
        if self.execution != ZeroModelExecutionCounters::zero() {
            return Err(SwarmLaunchBindError::InvalidField("launch.execution"));
        }
        if self.binding_digest != self.digest()? {
            return Err(SwarmLaunchBindError::InvalidField("launch.binding_digest"));
        }
        Ok(())
    }

    fn validate_selections(&self) -> Result<(), SwarmLaunchBindError> {
        if self.selections.is_empty() || self.selections.len() > MAX_STAFFING_SLOTS {
            return Err(SwarmLaunchBindError::InvalidField("launch.selections"));
        }
        if !self.selections.is_sorted_by_key(|selection| selection.role)
            || has_duplicates_by(&self.selections, |selection| selection.role)
        {
            return Err(SwarmLaunchBindError::InvalidField("launch.selections"));
        }
        for selection in &self.selections {
            selection.validate()?;
            if selection.account_scope != self.account_scope
                || selection.catalogue_snapshot_id != self.catalogue_snapshot_id
                || selection.catalogue_digest != self.catalogue_digest
                || selection.preference_policy_id != self.preference_policy_id
                || selection.preference_revision != self.preference_revision
                || selection.preference_policy_digest != self.preference_policy_digest
            {
                return Err(SwarmLaunchBindError::InvalidField("launch.generation"));
            }
            let Some(slot) = self
                .staffing
                .slots
                .iter()
                .find(|slot| slot.role == selection.role)
            else {
                // A bound selection without its staffed slot is either a
                // missing-role gap the staffing refuses (slots and gaps are
                // exclusive) or a tampered binding; both fail closed.
                return Err(SwarmLaunchBindError::InvalidField("launch.staffing"));
            };
            if slot.selection_id != selection.selection_id
                || slot.selection_digest != selection.selection_digest
            {
                return Err(SwarmLaunchBindError::InvalidField("launch.staffing"));
            }
        }
        Ok(())
    }

    /// Bindings never execute: the counter receipt is always zero.
    #[must_use]
    pub const fn execution(&self) -> ZeroModelExecutionCounters {
        ZeroModelExecutionCounters::zero()
    }

    /// Bindings never grant dispatch authority.
    #[must_use]
    pub const fn dispatch_authority(&self) -> bool {
        false
    }

    /// Bindings are candidate preparation only.
    #[must_use]
    pub const fn candidate_only(&self) -> bool {
        true
    }

    /// Exact-replay/conflict rule: identical canonical bytes replay, a reused
    /// command id with changed bytes conflicts, and a different command id is
    /// a new binding rather than a replay.
    pub fn replay_disposition(
        &self,
        previous: &Self,
    ) -> Result<SwarmLaunchReplayDisposition, SwarmLaunchBindError> {
        self.validate()?;
        previous.validate()?;
        if self.command_id != previous.command_id {
            return Ok(SwarmLaunchReplayDisposition::NewBinding);
        }
        if self.binding_digest == previous.binding_digest {
            Ok(SwarmLaunchReplayDisposition::ExactReplay)
        } else {
            Err(SwarmLaunchBindError::IdentityConflict)
        }
    }
}

/// Outcome of [`SwarmLaunchBinding::replay_disposition`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SwarmLaunchReplayDisposition {
    ExactReplay,
    NewBinding,
}

fn has_duplicates_by<T, K: Eq>(values: &[T], mut key: impl FnMut(&T) -> K) -> bool {
    values.iter().enumerate().any(|(index, left)| {
        values
            .iter()
            .skip(index + 1)
            .any(|right| key(left) == key(right))
    })
}

/// Probe selection-identity role key. This repeats the 484 launch compiler's
/// deterministic probe naming (`{command_id}/{ROLE_KEY}`) so the per-role
/// revalidation reproduces the exact sealed probe receipts; the canonical
/// mapping itself stays owned by the selection compiler inputs, not by this
/// module.
const fn role_probe_key(role: ModelRole) -> &'static str {
    match role {
        ModelRole::MainAgent => "MAIN_AGENT",
        ModelRole::Worker => "WORKER",
        ModelRole::Challenger => "CHALLENGER",
        ModelRole::Verifier => "VERIFIER",
        ModelRole::Researcher => "RESEARCHER",
        ModelRole::Synthesis => "SYNTHESIS",
        ModelRole::Watchdog => "WATCHDOG",
        ModelRole::Dreamer => "DREAMER",
    }
}

fn probe_selection_id(command_id: &str, role: ModelRole) -> String {
    format!("{command_id}/{}", role_probe_key(role))
}

/// Binds the sealed launch candidate to exact staffing against the current
/// generation. Pure and deterministic: no provider/model call, no process
/// launch or cancel, no lease/fence issuance, no route admission, no Task
/// write, no fallback. Any stale, mismatched, missing, or tampered binding
/// fails closed; typed staffing gaps are preserved verbatim.
pub fn bind_swarm_launch(
    request: &SwarmLaunchBindRequest,
) -> Result<SwarmLaunchBinding, SwarmLaunchBindError> {
    request.candidate.validate()?;
    let SwarmCommandKind::RequestSwarmLaunch {
        task_id,
        plan_revision,
        catalogue_snapshot_id,
        catalogue_digest: sealed_catalogue_digest,
        preference_policy_id,
        preference_revision,
        preference_policy_digest: sealed_policy_digest,
        demand,
        routes,
    } = &request.candidate.kind
    else {
        return Err(SwarmLaunchBindError::InvalidField("launch.kind"));
    };
    if request.now_unix_ms == 0 {
        return Err(SwarmLaunchBindError::InvalidField("launch.now_unix_ms"));
    }
    if demand.is_empty() || demand.len() > MAX_STAFFING_SLOTS {
        return Err(SwarmLaunchBindError::InvalidField("launch.demand"));
    }
    request.catalogue.validate()?;
    request.policy.validate()?;
    if request.catalogue.account_scope != request.candidate.account_scope
        || request.policy.account_scope != request.candidate.account_scope
        || request.catalogue.account_scope != request.policy.account_scope
    {
        return Err(SwarmLaunchBindError::InvalidField("launch.account_scope"));
    }
    if *catalogue_snapshot_id != request.catalogue.snapshot_id {
        return Err(SwarmLaunchBindError::StaleCatalogue);
    }
    if *preference_policy_id != request.policy.policy_id
        || *preference_revision != request.policy.revision
    {
        return Err(SwarmLaunchBindError::StalePolicy);
    }
    if catalogue_digest(&request.catalogue)? != *sealed_catalogue_digest {
        return Err(SwarmLaunchBindError::StaleCatalogue);
    }
    if preference_policy_digest(&request.policy)? != *sealed_policy_digest {
        return Err(SwarmLaunchBindError::StalePolicy);
    }

    // Per-role exact-current construction after full-generation digest
    // closure: every sealed route binding must reproduce byte-identically
    // against the current generation. Post-closure this assertion passes for
    // honest inputs (compilation is deterministic); a mismatch means an
    // incoherent candidate and fails closed without staffing anything.
    let mut selections = Vec::with_capacity(demand.len());
    for role in demand {
        let probe_id = probe_selection_id(&request.candidate.command_id, *role);
        let receipt = compile_model_selection(
            &request.catalogue,
            &request.policy,
            *role,
            &probe_id,
            request.now_unix_ms,
        )?;
        let Some(route) = routes.iter().find(|route| route.role == *role) else {
            return Err(SwarmLaunchBindError::InvalidField("launch.routes"));
        };
        if receipt.selection_digest != route.selection_digest
            || receipt.selected.entry_id != route.entry_id
        {
            return Err(SwarmLaunchBindError::InvalidField("launch.routes"));
        }
        selections.push(receipt);
    }

    let staffing_id = format!("{}/staffing", request.candidate.command_id.as_str());
    let staffing_request = SwarmStaffingRequest {
        staffing_id: staffing_id.clone(),
        demand: demand.clone(),
        selections: selections.clone(),
        catalogue: request.catalogue.clone(),
        policy: request.policy.clone(),
        now_unix_ms: request.now_unix_ms,
    };
    let staffing = compile_swarm_staffing(&staffing_request)?;

    let mut binding = SwarmLaunchBinding {
        schema_version: SWARM_LAUNCH_BINDING_VERSION.to_owned(),
        command_id: request.candidate.command_id.clone(),
        command_digest: request.candidate.command_digest.clone(),
        account_scope: request.candidate.account_scope.clone(),
        view_revision: request.candidate.view_revision.clone(),
        view_fence: request.candidate.view_fence.clone(),
        task_id: task_id.clone(),
        plan_revision: plan_revision.clone(),
        catalogue_snapshot_id: request.catalogue.snapshot_id.clone(),
        catalogue_digest: catalogue_digest(&request.catalogue)?,
        preference_policy_id: request.policy.policy_id.clone(),
        preference_revision: request.policy.revision.clone(),
        preference_policy_digest: preference_policy_digest(&request.policy)?,
        staffing_id,
        staffing_digest: staffing.staffing_digest.clone(),
        selections,
        staffing,
        binding_digest: String::new(),
        execution: ZeroModelExecutionCounters::zero(),
        candidate_only: true,
        dispatch_authority: false,
    };
    binding.binding_digest = binding.digest()?;
    binding.validate()?;
    Ok(binding)
}
