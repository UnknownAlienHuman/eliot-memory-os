//! Versioned, owner-neutral restart policy values and class eligibility.
//!
//! This module validates policy declarations and decides whether a restart is
//! eligible under the declared class. It does not account for intensity,
//! authorize effects, reconcile process identity, or launch a replacement.

use eliot_contracts::{ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::RuntimeContractError;

/// Encoding or contract validation failure for restart policy bindings.
#[derive(Debug, Error)]
pub enum RestartPolicyError {
    /// A policy or state-fence contract rejected its value.
    #[error(transparent)]
    Contract(#[from] RuntimeContractError),
    /// Canonical policy serialization failed.
    #[error("restart policy encoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
}

/// The restart class declared for one supervised child.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartClass {
    Permanent,
    Transient,
    Temporary,
}

/// Strategy declared for a named supervision group.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartGroupStrategy {
    OneForOne,
    RestForOne,
    OneForAll,
}

/// How a declared dependency affects activation and recovery.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartDependencyKind {
    Required,
    Optional,
    Advisory,
}

/// A locally declared event that invalidates dependent operational state.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RestartInvalidationTrigger {
    RequiredProtocolDigestMismatch,
    OperationalStateInvalidated,
    StateFenceInvalidated,
    HealthContractFailed,
}

/// One typed dependency edge in a restart policy. This declaration is not a
/// validated graph; graph-wide cycle and transitive-closure checks belong to
/// the catalog activation path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartDependency {
    pub dependency_id: String,
    pub kind: RestartDependencyKind,
    pub invalidation_triggers: Vec<RestartInvalidationTrigger>,
}

/// Bounded restart-intensity, delay, healthy-reset, and escalation values.
/// Every number is supplied by the admitted policy/profile; this contract has
/// no numeric defaults or global limits.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartIntensityPolicy {
    pub max_attempts_in_window: u32,
    pub window_millis: u64,
    pub backoff_initial_millis: u64,
    pub backoff_max_millis: u64,
    pub jitter_max_millis: u64,
    pub cooldown_millis: u64,
    pub reset_after_healthy_millis: u64,
    pub quarantine_after_attempts: u32,
    pub escalation_target: String,
}

/// Complete local versioned restart declaration value.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartPolicyV1 {
    pub policy_version: u16,
    pub subject_id: String,
    pub restart_class: RestartClass,
    pub group_id: String,
    pub group_strategy: RestartGroupStrategy,
    pub one_for_all_rationale: Option<String>,
    pub dependencies: Vec<RestartDependency>,
    pub intensity: RestartIntensityPolicy,
    pub source_manifest_revision: u64,
    pub source_profile_revision: u64,
}

impl RestartPolicyV1 {
    /// Validates locally provable policy consistency. This does not validate a
    /// complete dependency graph or prove an accepted measured group rationale.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        if self.policy_version != 1 {
            return Err(invalid(
                "policy_version",
                "unsupported restart policy version",
            ));
        }
        text(&self.subject_id, "subject_id")?;
        text(&self.group_id, "group_id")?;
        if self.source_manifest_revision == 0 || self.source_profile_revision == 0 {
            return Err(invalid(
                "source_revision",
                "manifest and profile revisions must be non-zero",
            ));
        }
        match (self.group_strategy, self.one_for_all_rationale.as_deref()) {
            (RestartGroupStrategy::OneForAll, Some(rationale)) => {
                text(rationale, "one_for_all_rationale")?;
            }
            (RestartGroupStrategy::OneForAll, None) => {
                return Err(invalid(
                    "one_for_all_rationale",
                    "one_for_all requires a named rationale",
                ));
            }
            (_, Some(_)) => {
                return Err(invalid(
                    "one_for_all_rationale",
                    "rationale is only valid for one_for_all",
                ));
            }
            (_, None) => {}
        }

        let mut dependency_ids = std::collections::BTreeSet::new();
        for dependency in &self.dependencies {
            text(&dependency.dependency_id, "dependency_id")?;
            if dependency.dependency_id == self.subject_id {
                return Err(invalid("dependency_id", "self dependency is invalid"));
            }
            if !dependency_ids.insert(&dependency.dependency_id) {
                return Err(invalid("dependencies", "dependency ids must be unique"));
            }
            if dependency.invalidation_triggers.is_empty() {
                return Err(invalid(
                    "invalidation_triggers",
                    "each declared edge requires an invalidation trigger",
                ));
            }
            let mut triggers = std::collections::BTreeSet::new();
            if dependency
                .invalidation_triggers
                .iter()
                .any(|trigger| !triggers.insert(*trigger))
            {
                return Err(invalid(
                    "invalidation_triggers",
                    "invalidation triggers must be unique",
                ));
            }
        }

        let intensity = &self.intensity;
        if intensity.max_attempts_in_window == 0
            || intensity.window_millis == 0
            || intensity.reset_after_healthy_millis == 0
            || intensity.quarantine_after_attempts == 0
            || intensity.quarantine_after_attempts > intensity.max_attempts_in_window
        {
            return Err(invalid(
                "intensity",
                "attempt, window, reset, and quarantine values are inconsistent",
            ));
        }
        if intensity.backoff_initial_millis > intensity.backoff_max_millis {
            return Err(invalid(
                "backoff_max_millis",
                "maximum backoff must not be below initial backoff",
            ));
        }
        text(&intensity.escalation_target, "escalation_target")?;
        Ok(())
    }

    /// Computes the canonical policy digest used by admission bindings.
    pub fn digest(&self) -> Result<String, RestartPolicyError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)?;
        Ok(sha256_hex(&bytes))
    }

    /// Binds this declaration to the admitted generation and its state fence.
    pub fn bind(
        &self,
        admitted_generation: ResourceGeneration,
        state_fence: StateFence,
    ) -> Result<RestartPolicyAdmissionBinding, RestartPolicyError> {
        state_fence.validate().map_err(RuntimeContractError::from)?;
        if admitted_generation != state_fence.resource_generation {
            return Err(invalid(
                "restart_policy_binding",
                "admitted generation must match the state fence generation",
            )
            .into());
        }
        Ok(RestartPolicyAdmissionBinding {
            policy_digest: self.digest()?,
            source_manifest_revision: self.source_manifest_revision,
            source_profile_revision: self.source_profile_revision,
            admitted_generation,
            state_fence,
        })
    }
}

/// Digest and immutable admission identity for a restart policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartPolicyAdmissionBinding {
    pub policy_digest: String,
    pub source_manifest_revision: u64,
    pub source_profile_revision: u64,
    pub admitted_generation: ResourceGeneration,
    pub state_fence: StateFence,
}

impl RestartPolicyAdmissionBinding {
    /// Checks that this admission carries the exact supplied policy digest and
    /// source revisions. The owner still verifies generation and fence currentness.
    pub fn validate_for(
        &self,
        policy: &RestartPolicyV1,
        admitted_generation: &ResourceGeneration,
        state_fence: &StateFence,
    ) -> Result<(), RestartPolicyError> {
        state_fence.validate().map_err(RuntimeContractError::from)?;
        if self.policy_digest != policy.digest()?
            || self.source_manifest_revision != policy.source_manifest_revision
            || self.source_profile_revision != policy.source_profile_revision
            || &self.admitted_generation != admitted_generation
            || &self.state_fence != state_fence
            || self.admitted_generation != self.state_fence.resource_generation
        {
            return Err(invalid(
                "restart_policy_binding",
                "policy, source revision, generation, or state fence does not match",
            )
            .into());
        }
        Ok(())
    }
}

/// Current owner lifecycle relevant to automatic restart eligibility.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartOwnerLifecycle {
    Running,
    PlannedShutdown,
    Cancellation,
    Quiescing,
    Retiring,
}

/// Whether the old child identity is exact enough to permit replacement.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartIdentityEvidence {
    Exact,
    MissingOrAmbiguous,
}

/// Exit and health evidence supplied by the existing process/health owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartFailureEvidence {
    NormalExit,
    AbnormalExit,
    FailedHealthContract,
    NoRestartCondition,
}

/// Policy eligibility result. `Eligible` grants no launch or effect authority.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticRestartDecision {
    Eligible,
    SuppressedByOwnerLifecycle,
    TemporaryChild,
    NoMatchingFailureCondition,
    BlockedByUncertainIdentity,
}

/// Evaluates only the class/lifecycle/identity rule; no budget or effect
/// authorization is performed here.
pub fn decide_automatic_restart(
    policy: &RestartPolicyV1,
    owner_lifecycle: RestartOwnerLifecycle,
    identity: RestartIdentityEvidence,
    failure: RestartFailureEvidence,
) -> Result<AutomaticRestartDecision, RuntimeContractError> {
    policy.validate()?;
    if owner_lifecycle != RestartOwnerLifecycle::Running {
        return Ok(AutomaticRestartDecision::SuppressedByOwnerLifecycle);
    }
    if policy.restart_class == RestartClass::Temporary {
        return Ok(AutomaticRestartDecision::TemporaryChild);
    }
    if identity != RestartIdentityEvidence::Exact {
        return Ok(AutomaticRestartDecision::BlockedByUncertainIdentity);
    }
    let eligible = match policy.restart_class {
        RestartClass::Permanent => matches!(
            failure,
            RestartFailureEvidence::NormalExit | RestartFailureEvidence::AbnormalExit
        ),
        RestartClass::Transient => matches!(
            failure,
            RestartFailureEvidence::AbnormalExit | RestartFailureEvidence::FailedHealthContract
        ),
        RestartClass::Temporary => false,
    };
    Ok(if eligible {
        AutomaticRestartDecision::Eligible
    } else {
        AutomaticRestartDecision::NoMatchingFailureCondition
    })
}

fn text(value: &str, field: &'static str) -> Result<(), RuntimeContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(invalid(
            field,
            "must be non-blank and contain no control characters",
        ));
    }
    Ok(())
}

fn invalid(field: &'static str, reason: &'static str) -> RuntimeContractError {
    RuntimeContractError::InvalidField { field, reason }
}
