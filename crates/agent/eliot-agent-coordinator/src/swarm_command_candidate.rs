//! Pure, unauthenticated, capability-agnostic Swarm command candidates.
//!
//! [`compile_refresh_catalogue_candidate`],
//! [`compile_replace_policy_candidate`], [`compile_launch_swarm_candidate`],
//! and [`compile_cancel_attempt_candidate`] compile the four operator command
//! kinds against exact current A-02 catalogue/policy identities and the exact
//! visible [`SwarmAttemptProjection`] rows. Compilation follows the
//! `swarm_staffing.rs` digest/validate pattern: every candidate carries an
//! immutable canonical [`SwarmCommandCandidate::command_digest`], exact replay
//! reproduces the exact value, and reusing a command identity with changed
//! bytes is an [`SwarmCommandCandidateError::IdentityConflict`] detected by
//! [`SwarmCommandCandidate::replay_disposition`].
//!
//! Caller capability arrives as plain-data input flags
//! ([`SwarmCommandCallerBinding::capability_present`] plus a capability scope
//! text that must equal the command account scope). This module never imports
//! `AccessBinding`, `ActionCapability`, or `ControlBoardError` from
//! `eliot-controlboard`: the dependency direction is one-way
//! `eliot-controlboard -> eliot-agent-coordinator`, so real capability
//! verification stays owned by the authenticated `ControlBoard` edge (MGR01
//! lane) while this compiler only admits the plain-data flag.
//!
//! The output is structurally candidate-only: `candidate_only` is true,
//! `dispatch_authority` is false, execution counters are zero, and the value
//! carries no `WorkLease`, `StateFence` issuance, process control,
//! redispatch, canonical write, or Finish authority. It performs no
//! provider/model call, no settings file/store write, no staffing, and no
//! launch: the launch candidate only proves that a dispatchable eligible
//! route exists for every requested role via read-only
//! [`compile_model_selection`](crate::model_control::compile_model_selection)
//! probes.
//!
//! Proof ceiling:
//! `AUTHENTICATED_SWARM_COMMAND_CANDIDATE_PACKAGE_PROOF_ONLY`. Real
//! `AccessBinding` verification inside `ControlBoard` remains residual.

use eliot_agent_api::{AttemptId, StateFence};
use eliot_contracts::fences_match_exact;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::model_control::{
    HumanModelPreferencePolicy, ModelCatalogueSnapshot, ModelControlError, ModelRole,
    ZeroModelExecutionCounters, canonical_digest, catalogue_digest, compile_model_selection,
    preference_policy_digest, validate_canonical_digest,
};
use crate::swarm_controlboard::SwarmAttemptProjection;
use crate::swarm_staffing::MAX_STAFFING_SLOTS;

/// Schema identity for the candidate-only swarm command value.
pub const SWARM_COMMAND_CANDIDATE_VERSION: &str = "eliot.agent-swarm-command-candidate/v1";

/// Maximum visible attempt rows a cancel candidate may be compiled against.
/// Mirrors the read-model bound without duplicating its projection logic.
pub const MAX_COMMAND_VISIBLE_ATTEMPTS: usize = 4096;

fn validate_text(value: &str, field: &'static str) -> Result<(), SwarmCommandCandidateError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SwarmCommandCandidateError::InvalidField(field));
    }
    Ok(())
}

/// Fail-closed command-candidate errors. Every production path returns these
/// instead of panicking; a malformed, unauthorized, stale, or conflicting
/// command is rejected, never repaired.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SwarmCommandCandidateError {
    #[error(transparent)]
    ModelControl(#[from] ModelControlError),
    #[error("invalid swarm command-candidate field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate swarm command-candidate identity: {0}")]
    DuplicateIdentity(&'static str),
    #[error("swarm command candidate lacks capability for the account scope")]
    MissingCapability,
    #[error("swarm command candidate pins a stale view revision or fence")]
    StaleView,
    #[error("swarm command candidate pins a stale expected policy revision or digest")]
    StalePolicy,
    #[error("swarm command candidate targets an attempt outside the visible view")]
    UnknownAttempt,
    #[error("swarm command identity conflict: same id with changed bytes")]
    IdentityConflict,
}

/// Plain-data caller binding shared by all four compilers. Capability is a
/// boolean flag plus scope text only; view currency is an exact
/// `(revision, fence)` pin: the observed source-view identity must equal the
/// caller-supplied expectation, otherwise the view moved under the caller and
/// compilation fails closed with [`SwarmCommandCandidateError::StaleView`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmCommandCallerBinding {
    pub command_id: String,
    pub capability_present: bool,
    pub capability_scope: String,
    pub view_revision: String,
    pub expected_view_revision: String,
    pub view_fence: StateFence,
    pub expected_view_fence: StateFence,
    pub now_unix_ms: u64,
}

impl SwarmCommandCallerBinding {
    fn validate_for(&self, account_scope: &str) -> Result<(), SwarmCommandCandidateError> {
        validate_text(&self.command_id, "command.command_id")?;
        if !self.capability_present {
            return Err(SwarmCommandCandidateError::MissingCapability);
        }
        validate_text(&self.capability_scope, "command.capability_scope")?;
        if self.capability_scope != account_scope {
            return Err(SwarmCommandCandidateError::MissingCapability);
        }
        validate_text(&self.view_revision, "command.view_revision")?;
        validate_text(
            &self.expected_view_revision,
            "command.expected_view_revision",
        )?;
        if self.view_revision != self.expected_view_revision {
            return Err(SwarmCommandCandidateError::StaleView);
        }
        if self.view_fence.validate().is_err()
            || self.expected_view_fence.validate().is_err()
        {
            return Err(SwarmCommandCandidateError::InvalidField("command.view_fence"));
        }
        if !fences_match_exact(&self.view_fence, &self.expected_view_fence) {
            return Err(SwarmCommandCandidateError::StaleView);
        }
        if self.now_unix_ms == 0 {
            return Err(SwarmCommandCandidateError::InvalidField(
                "command.now_unix_ms",
            ));
        }
        Ok(())
    }
}

/// Catalogue-refresh command input: the exact generation the refresh was
/// compiled against, plus a human-readable reason. The catalogue may be stale
/// (that is why a refresh is requested); structural validity and scope
/// agreement are still required.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshCatalogueRequest {
    pub binding: SwarmCommandCallerBinding,
    pub account_scope: String,
    pub catalogue: ModelCatalogueSnapshot,
    pub reason: String,
}

/// Preference-replacement input: the exact full replacement policy plus the
/// caller-pinned expected revision/digest. The expectation must equal the
/// replacement's own revision and recomputed digest, so an expectation copied
/// from a superseded revision fails closed with
/// [`SwarmCommandCandidateError::StalePolicy`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacePreferencePolicyRequest {
    pub binding: SwarmCommandCallerBinding,
    pub account_scope: String,
    pub policy: HumanModelPreferencePolicy,
    pub expected_policy_revision: String,
    pub expected_policy_digest: String,
}

/// Bounded launch input: exact catalogue/policy identities plus immutable role
/// demand. Compilation proves a dispatchable eligible route for every
/// requested role via read-only selection probes; it never staffs slots or
/// launches anything.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSwarmRequest {
    pub binding: SwarmCommandCallerBinding,
    pub account_scope: String,
    pub catalogue: ModelCatalogueSnapshot,
    pub policy: HumanModelPreferencePolicy,
    pub task_id: String,
    pub plan_revision: String,
    pub demand: Vec<ModelRole>,
}

/// Attempt-cancel input: the visible rows plus the single target attempt.
/// The target must be a member of the visible view, otherwise compilation
/// fails closed with [`SwarmCommandCandidateError::UnknownAttempt`].
///
/// Serialize-only (no `Deserialize`): [`SwarmAttemptProjection`] is a
/// render-only read-model row by design, so cancel inputs are constructed in
/// memory from the compiled projection, never parsed back from a wire.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CancelAttemptRequest {
    pub binding: SwarmCommandCallerBinding,
    pub account_scope: String,
    pub visible_attempts: Vec<SwarmAttemptProjection>,
    pub attempt_id: AttemptId,
    pub reason: String,
}

/// Per-role launch binding: proof that a dispatchable eligible route exists
/// for one demanded role. The `selection_digest` is the read-only probe
/// receipt digest bound to the command identity plus the exact
/// catalogue/policy generation; it pins the route without staffing it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRoleBinding {
    pub role: ModelRole,
    pub entry_id: String,
    pub selection_digest: String,
}

impl LaunchRoleBinding {
    fn validate(&self, demand: &[ModelRole]) -> Result<(), SwarmCommandCandidateError> {
        if !demand.contains(&self.role) {
            return Err(SwarmCommandCandidateError::InvalidField("command.routes"));
        }
        validate_text(&self.entry_id, "command.routes.entry_id")?;
        validate_canonical_digest(&self.selection_digest, "command.routes.selection_digest")
            .map_err(|_| SwarmCommandCandidateError::InvalidField("command.routes.selection_digest"))
    }
}

/// The four command payloads. Every variant binds the exact source-view and
/// catalogue/policy/attempt identities the candidate was compiled against.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum SwarmCommandKind {
    RefreshCatalogue {
        catalogue_snapshot_id: String,
        catalogue_digest: String,
        reason: String,
    },
    ReplacePreferencePolicy {
        preference_policy_id: String,
        preference_revision: String,
        preference_policy_digest: String,
        policy: HumanModelPreferencePolicy,
    },
    RequestSwarmLaunch {
        task_id: String,
        plan_revision: String,
        catalogue_snapshot_id: String,
        catalogue_digest: String,
        preference_policy_id: String,
        preference_revision: String,
        preference_policy_digest: String,
        demand: Vec<ModelRole>,
        routes: Vec<LaunchRoleBinding>,
    },
    CancelAttempt {
        attempt_id: AttemptId,
        selection_id: String,
        selection_digest: String,
        role: ModelRole,
        reason: String,
    },
}

fn validate_refresh_payload(
    catalogue_snapshot_id: &str,
    catalogue_digest_value: &str,
    reason: &str,
) -> Result<(), SwarmCommandCandidateError> {
    validate_text(
        catalogue_snapshot_id,
        "command.catalogue_snapshot_id",
    )?;
    validate_canonical_digest(catalogue_digest_value, "command.catalogue_digest").map_err(
        |_| SwarmCommandCandidateError::InvalidField("command.catalogue_digest"),
    )?;
    validate_text(reason, "command.reason")
}

fn validate_replace_payload(
    preference_policy_id: &str,
    preference_revision: &str,
    expected_digest: &str,
    policy: &HumanModelPreferencePolicy,
) -> Result<(), SwarmCommandCandidateError> {
    validate_text(preference_policy_id, "command.preference_policy_id")?;
    validate_text(preference_revision, "command.preference_revision")?;
    validate_canonical_digest(
        expected_digest,
        "command.preference_policy_digest",
    )
    .map_err(|_| {
        SwarmCommandCandidateError::InvalidField("command.preference_policy_digest")
    })?;
    policy.validate()?;
    if policy.policy_id != *preference_policy_id || policy.revision != *preference_revision {
        return Err(SwarmCommandCandidateError::InvalidField(
            "command.preference_identity",
        ));
    }
    let actual_digest = preference_policy_digest(policy)?;
    if actual_digest != *expected_digest {
        return Err(SwarmCommandCandidateError::StalePolicy);
    }
    Ok(())
}

fn validate_launch_identities(
    task_id: &str,
    plan_revision: &str,
    catalogue_snapshot_id: &str,
    catalogue_digest_value: &str,
    preference_policy_id: &str,
    preference_revision: &str,
    policy_digest_value: &str,
) -> Result<(), SwarmCommandCandidateError> {
    validate_text(task_id, "command.task_id")?;
    validate_text(plan_revision, "command.plan_revision")?;
    validate_text(
        catalogue_snapshot_id,
        "command.catalogue_snapshot_id",
    )?;
    validate_canonical_digest(
        catalogue_digest_value,
        "command.catalogue_digest",
    )
    .map_err(|_| {
        SwarmCommandCandidateError::InvalidField("command.catalogue_digest")
    })?;
    validate_text(preference_policy_id, "command.preference_policy_id")?;
    validate_text(preference_revision, "command.preference_revision")?;
    validate_canonical_digest(
        policy_digest_value,
        "command.preference_policy_digest",
    )
    .map_err(|_| {
        SwarmCommandCandidateError::InvalidField("command.preference_policy_digest")
    })
}

fn validate_launch_routes(
    demand: &[ModelRole],
    routes: &[LaunchRoleBinding],
) -> Result<(), SwarmCommandCandidateError> {
    if demand.is_empty() || demand.len() > MAX_STAFFING_SLOTS {
        return Err(SwarmCommandCandidateError::InvalidField("command.demand"));
    }
    if !demand.is_sorted() || has_duplicates(demand) {
        return Err(SwarmCommandCandidateError::InvalidField("command.demand"));
    }
    if !routes.is_sorted_by_key(|route| route.role)
        || has_duplicates_by(routes, |route| route.role)
    {
        return Err(SwarmCommandCandidateError::InvalidField("command.routes"));
    }
    for route in routes {
        route.validate(demand)?;
    }
    // Every demanded role resolves to exactly one route binding: unlike
    // staffing gaps, a launch candidate is complete or it does not exist.
    for role in demand {
        if !routes.iter().any(|route| &route.role == role) {
            return Err(SwarmCommandCandidateError::InvalidField("command.routes"));
        }
    }
    Ok(())
}

fn validate_cancel_payload(
    selection_id: &str,
    selection_digest: &str,
    reason: &str,
) -> Result<(), SwarmCommandCandidateError> {
    validate_text(selection_id, "command.selection_id")?;
    validate_canonical_digest(selection_digest, "command.selection_digest").map_err(|_| {
        SwarmCommandCandidateError::InvalidField("command.selection_digest")
    })?;
    validate_text(reason, "command.reason")
}

impl SwarmCommandKind {
    fn validate(&self) -> Result<(), SwarmCommandCandidateError> {
        match self {
            Self::RefreshCatalogue {
                catalogue_snapshot_id,
                catalogue_digest,
                reason,
            } => validate_refresh_payload(catalogue_snapshot_id, catalogue_digest, reason),
            Self::ReplacePreferencePolicy {
                preference_policy_id,
                preference_revision,
                preference_policy_digest: expected_digest,
                policy,
            } => validate_replace_payload(
                preference_policy_id,
                preference_revision,
                expected_digest,
                policy,
            ),
            Self::RequestSwarmLaunch {
                task_id,
                plan_revision,
                catalogue_snapshot_id,
                catalogue_digest: catalogue_digest_value,
                preference_policy_id,
                preference_revision,
                preference_policy_digest: policy_digest_value,
                demand,
                routes,
            } => {
                validate_launch_identities(
                    task_id,
                    plan_revision,
                    catalogue_snapshot_id,
                    catalogue_digest_value,
                    preference_policy_id,
                    preference_revision,
                    policy_digest_value,
                )?;
                validate_launch_routes(demand, routes)
            }
            Self::CancelAttempt {
                selection_id,
                selection_digest,
                reason,
                ..
            } => validate_cancel_payload(selection_id, selection_digest, reason),
        }
    }
}

/// Deterministic, bounded, candidate-only swarm command. Replaying the exact
/// input reproduces the exact value; reusing the command identity with
/// changed bytes is a conflict detected by
/// [`SwarmCommandCandidate::replay_disposition`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmCommandCandidate {
    pub schema_version: String,
    pub command_id: String,
    pub command_digest: String,
    pub account_scope: String,
    pub capability_scope: String,
    pub view_revision: String,
    pub view_fence: StateFence,
    pub kind: SwarmCommandKind,
    pub execution: ZeroModelExecutionCounters,
    pub candidate_only: bool,
    pub dispatch_authority: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SwarmCommandCandidateFields {
    schema_version: String,
    command_id: String,
    command_digest: String,
    account_scope: String,
    capability_scope: String,
    view_revision: String,
    view_fence: StateFence,
    kind: SwarmCommandKind,
    execution: ZeroModelExecutionCounters,
    candidate_only: bool,
    dispatch_authority: bool,
}

impl<'de> Deserialize<'de> for SwarmCommandCandidate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = SwarmCommandCandidateFields::deserialize(deserializer)?;
        let candidate = Self {
            schema_version: fields.schema_version,
            command_id: fields.command_id,
            command_digest: fields.command_digest,
            account_scope: fields.account_scope,
            capability_scope: fields.capability_scope,
            view_revision: fields.view_revision,
            view_fence: fields.view_fence,
            kind: fields.kind,
            execution: fields.execution,
            candidate_only: fields.candidate_only,
            dispatch_authority: fields.dispatch_authority,
        };
        candidate.validate().map_err(D::Error::custom)?;
        Ok(candidate)
    }
}

impl SwarmCommandCandidate {
    fn digest(&self) -> Result<String, ModelControlError> {
        canonical_digest(&(
            SWARM_COMMAND_CANDIDATE_VERSION,
            self.command_id.as_str(),
            self.account_scope.as_str(),
            self.capability_scope.as_str(),
            self.view_revision.as_str(),
            &self.view_fence,
            &self.kind,
        ))
    }

    /// Validates identity, capability-scope binding, view-fence validity,
    /// kind binding, digest closure, and the candidate-only ceiling. Called
    /// on deserialization and after compilation.
    pub fn validate(&self) -> Result<(), SwarmCommandCandidateError> {
        if self.schema_version != SWARM_COMMAND_CANDIDATE_VERSION {
            return Err(SwarmCommandCandidateError::ModelControl(
                ModelControlError::UnsupportedSchema("swarm_command_candidate"),
            ));
        }
        validate_text(&self.command_id, "command.command_id")?;
        validate_text(&self.account_scope, "command.account_scope")?;
        validate_text(&self.capability_scope, "command.capability_scope")?;
        if self.capability_scope != self.account_scope {
            return Err(SwarmCommandCandidateError::MissingCapability);
        }
        validate_text(&self.view_revision, "command.view_revision")?;
        validate_canonical_digest(&self.command_digest, "command.command_digest").map_err(
            |_| SwarmCommandCandidateError::InvalidField("command.command_digest"),
        )?;
        if self.view_fence.validate().is_err() {
            return Err(SwarmCommandCandidateError::InvalidField("command.view_fence"));
        }
        self.kind.validate()?;
        if !self.candidate_only || self.dispatch_authority {
            return Err(SwarmCommandCandidateError::InvalidField("command.authority"));
        }
        if self.execution != ZeroModelExecutionCounters::zero() {
            return Err(SwarmCommandCandidateError::InvalidField("command.execution"));
        }
        if self.command_digest != self.digest()? {
            return Err(SwarmCommandCandidateError::InvalidField(
                "command.command_digest",
            ));
        }
        Ok(())
    }

    /// Commands never execute: the counter receipt is always zero.
    #[must_use]
    pub const fn execution(&self) -> ZeroModelExecutionCounters {
        ZeroModelExecutionCounters::zero()
    }

    /// Commands never grant dispatch authority.
    #[must_use]
    pub const fn dispatch_authority(&self) -> bool {
        false
    }

    /// Commands are candidate requests only.
    #[must_use]
    pub const fn candidate_only(&self) -> bool {
        true
    }

    /// Exact-replay/conflict rule: identical canonical bytes replay, a reused
    /// command id with changed bytes conflicts, and a different command id is
    /// a new command rather than a replay.
    pub fn replay_disposition(
        &self,
        previous: &Self,
    ) -> Result<SwarmCommandReplayDisposition, SwarmCommandCandidateError> {
        self.validate()?;
        previous.validate()?;
        if self.command_id != previous.command_id {
            return Ok(SwarmCommandReplayDisposition::NewCommand);
        }
        if self.command_digest == previous.command_digest {
            Ok(SwarmCommandReplayDisposition::ExactReplay)
        } else {
            Err(SwarmCommandCandidateError::IdentityConflict)
        }
    }
}

/// Outcome of [`SwarmCommandCandidate::replay_disposition`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SwarmCommandReplayDisposition {
    ExactReplay,
    NewCommand,
}

fn has_duplicates<T: Eq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, left)| values.iter().skip(index + 1).any(|right| left == right))
}

fn has_duplicates_by<T, K: Eq>(values: &[T], mut key: impl FnMut(&T) -> K) -> bool {
    values.iter().enumerate().any(|(index, left)| {
        values
            .iter()
            .skip(index + 1)
            .any(|right| key(left) == key(right))
    })
}

const fn role_command_key(role: ModelRole) -> &'static str {
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

fn canonical_demand(demand: &[ModelRole]) -> Result<Vec<ModelRole>, SwarmCommandCandidateError> {
    if demand.is_empty() || demand.len() > MAX_STAFFING_SLOTS {
        return Err(SwarmCommandCandidateError::InvalidField("command.demand"));
    }
    let mut canonical = demand.to_vec();
    canonical.sort();
    canonical.dedup();
    if canonical.len() != demand.len() {
        return Err(SwarmCommandCandidateError::DuplicateIdentity("command.demand"));
    }
    Ok(canonical)
}

fn finalize_candidate(
    binding: &SwarmCommandCallerBinding,
    account_scope: &str,
    kind: SwarmCommandKind,
) -> Result<SwarmCommandCandidate, SwarmCommandCandidateError> {
    let mut candidate = SwarmCommandCandidate {
        schema_version: SWARM_COMMAND_CANDIDATE_VERSION.to_owned(),
        command_id: binding.command_id.clone(),
        command_digest: String::new(),
        account_scope: account_scope.to_owned(),
        capability_scope: binding.capability_scope.clone(),
        view_revision: binding.view_revision.clone(),
        view_fence: binding.view_fence.clone(),
        kind,
        execution: ZeroModelExecutionCounters::zero(),
        candidate_only: true,
        dispatch_authority: false,
    };
    candidate.command_digest = candidate.digest()?;
    candidate.validate()?;
    Ok(candidate)
}

/// Compiles the catalogue-refresh candidate against the exact generation the
/// refresh was requested from. Pure and deterministic: no provider call, no
/// catalogue mutation, no dispatch.
pub fn compile_refresh_catalogue_candidate(
    request: &RefreshCatalogueRequest,
) -> Result<SwarmCommandCandidate, SwarmCommandCandidateError> {
    validate_text(&request.account_scope, "command.account_scope")?;
    request.binding.validate_for(&request.account_scope)?;
    request.catalogue.validate()?;
    if request.catalogue.account_scope != request.account_scope {
        return Err(SwarmCommandCandidateError::InvalidField(
            "command.account_scope",
        ));
    }
    validate_text(&request.reason, "command.reason")?;
    let kind = SwarmCommandKind::RefreshCatalogue {
        catalogue_snapshot_id: request.catalogue.snapshot_id.clone(),
        catalogue_digest: catalogue_digest(&request.catalogue)?,
        reason: request.reason.clone(),
    };
    finalize_candidate(&request.binding, &request.account_scope, kind)
}

/// Compiles the preference-replacement candidate preserving the exact full
/// Human policy plus the source-view identity. The caller-pinned expected
/// revision/digest must equal the replacement's own revision and recomputed
/// digest; a stale expectation fails closed.
pub fn compile_replace_policy_candidate(
    request: &ReplacePreferencePolicyRequest,
) -> Result<SwarmCommandCandidate, SwarmCommandCandidateError> {
    validate_text(&request.account_scope, "command.account_scope")?;
    request.binding.validate_for(&request.account_scope)?;
    request.policy.validate()?;
    if request.policy.account_scope != request.account_scope {
        return Err(SwarmCommandCandidateError::InvalidField(
            "command.account_scope",
        ));
    }
    validate_text(
        &request.expected_policy_revision,
        "command.expected_policy_revision",
    )?;
    validate_text(
        &request.expected_policy_digest,
        "command.expected_policy_digest",
    )?;
    if request.policy.revision != request.expected_policy_revision {
        return Err(SwarmCommandCandidateError::StalePolicy);
    }
    let actual_digest = preference_policy_digest(&request.policy)?;
    if actual_digest != request.expected_policy_digest {
        return Err(SwarmCommandCandidateError::StalePolicy);
    }
    let kind = SwarmCommandKind::ReplacePreferencePolicy {
        preference_policy_id: request.policy.policy_id.clone(),
        preference_revision: request.policy.revision.clone(),
        preference_policy_digest: actual_digest,
        policy: request.policy.clone(),
    };
    finalize_candidate(&request.binding, &request.account_scope, kind)
}

/// Compiles the bounded launch candidate from exact catalogue/policy
/// identities plus immutable role demand. Every requested role must resolve
/// to a dispatchable eligible route through a read-only selection probe;
/// any unstaffable role fails the whole command closed. No slots are
/// staffed and nothing is launched.
pub fn compile_launch_swarm_candidate(
    request: &LaunchSwarmRequest,
) -> Result<SwarmCommandCandidate, SwarmCommandCandidateError> {
    validate_text(&request.account_scope, "command.account_scope")?;
    request.binding.validate_for(&request.account_scope)?;
    request.catalogue.validate()?;
    request.policy.validate()?;
    if request.catalogue.account_scope != request.account_scope
        || request.policy.account_scope != request.account_scope
    {
        return Err(SwarmCommandCandidateError::InvalidField(
            "command.account_scope",
        ));
    }
    validate_text(&request.task_id, "command.task_id")?;
    validate_text(&request.plan_revision, "command.plan_revision")?;
    let demand = canonical_demand(&request.demand)?;
    let mut routes = Vec::with_capacity(demand.len());
    for role in &demand {
        let probe_id = format!(
            "{}/{}",
            request.binding.command_id.as_str(),
            role_command_key(*role)
        );
        let probe = compile_model_selection(
            &request.catalogue,
            &request.policy,
            *role,
            &probe_id,
            request.binding.now_unix_ms,
        )?;
        routes.push(LaunchRoleBinding {
            role: *role,
            entry_id: probe.selected.entry_id.clone(),
            selection_digest: probe.selection_digest.clone(),
        });
    }
    let kind = SwarmCommandKind::RequestSwarmLaunch {
        task_id: request.task_id.clone(),
        plan_revision: request.plan_revision.clone(),
        catalogue_snapshot_id: request.catalogue.snapshot_id.clone(),
        catalogue_digest: catalogue_digest(&request.catalogue)?,
        preference_policy_id: request.policy.policy_id.clone(),
        preference_revision: request.policy.revision.clone(),
        preference_policy_digest: preference_policy_digest(&request.policy)?,
        demand,
        routes,
    };
    finalize_candidate(&request.binding, &request.account_scope, kind)
}

/// Compiles the attempt-cancel candidate for one attempt visible in the
/// source view. The target must be a member of the supplied visible rows;
/// an absent attempt fails closed. No process is signalled and no attempt
/// state is mutated.
pub fn compile_cancel_attempt_candidate(
    request: &CancelAttemptRequest,
) -> Result<SwarmCommandCandidate, SwarmCommandCandidateError> {
    validate_text(&request.account_scope, "command.account_scope")?;
    request.binding.validate_for(&request.account_scope)?;
    if request.visible_attempts.len() > MAX_COMMAND_VISIBLE_ATTEMPTS {
        return Err(SwarmCommandCandidateError::InvalidField(
            "command.visible_attempts",
        ));
    }
    validate_text(&request.reason, "command.reason")?;
    let mut seen_attempts = std::collections::BTreeSet::new();
    for visible in &request.visible_attempts {
        if !seen_attempts.insert(visible.health.attempt_id.clone()) {
            return Err(SwarmCommandCandidateError::DuplicateIdentity(
                "command.visible_attempts",
            ));
        }
    }
    let Some(target) = request
        .visible_attempts
        .iter()
        .find(|visible| visible.health.attempt_id == request.attempt_id)
    else {
        return Err(SwarmCommandCandidateError::UnknownAttempt);
    };
    if target.account_scope != request.account_scope {
        return Err(SwarmCommandCandidateError::InvalidField(
            "command.account_scope",
        ));
    }
    validate_text(&target.selection_id, "command.visible_attempt.selection_id")?;
    validate_canonical_digest(
        &target.selection_digest,
        "command.visible_attempt.selection_digest",
    )
    .map_err(|_| {
        SwarmCommandCandidateError::InvalidField("command.visible_attempt.selection_digest")
    })?;
    let kind = SwarmCommandKind::CancelAttempt {
        attempt_id: request.attempt_id.clone(),
        selection_id: target.selection_id.clone(),
        selection_digest: target.selection_digest.clone(),
        role: target.role,
        reason: request.reason.clone(),
    };
    finalize_candidate(&request.binding, &request.account_scope, kind)
}
