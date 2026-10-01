//! Installation-approved recovery-policy load (issue #1757 W1; I8.3, I1.4).
//!
//! This cell loads the installation's pre-authorized recovery policy into the
//! sibling [`ApprovedRecoveryPolicy`] shape (owned by
//! `host_identity_observation`, read-only here) and decides recovery
//! eligibility from a responsiveness verdict plus the durable used-attempt
//! count. It selects no artifact, mutates no SCM configuration, and invents
//! no budget: the used-attempt count must be read from the durable Watchdog
//! journal (`watchdog.redb`) by the composition/spool lane (#1754 writer) and
//! is threaded through here unchanged, so exhaustion persists across Watchdog
//! restarts. Only [`RecoveryBudgetDecision::Admitted`] permits requesting one
//! fenced SCM effect, and only through the stop/start-separated operation
//! record owned by the Host-state lane; every other decision forbids effects.
//!
//! The read-only challenge permission remains usable while the Host is hung:
//! loading a policy never requires a fresh grant from the Host being
//! recovered.

use eliot_platform::PlatformHandle;
use thiserror::Error;

use crate::host_identity_observation::{
    ApprovedRecoveryPolicy, HostResponsiveness, RecoveryBudgetDecision,
};

/// Raw installer-provided policy inputs. All strings are coordination
/// identities (installation, service, digests); never nonces, credentials,
/// paths, or user data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledRecoveryPolicyInput {
    pub installation: String,
    pub service: String,
    pub owner_epoch_digest: String,
    pub recipe_digest: String,
    pub failure_threshold: u32,
    pub max_attempts: u32,
    pub budget_window_secs: u64,
    pub cooldown_secs: u64,
    pub exclusive_attempt: bool,
    pub audit_failure_refuses_effects: bool,
}

/// Typed policy-load failure. Identity names only; no secret material.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum RecoveryPolicyLoadError {
    #[error("installed recovery policy identity is blank or not a coordination identity: {0}")]
    BlankIdentity(&'static str),
    #[error("installed recovery policy handle is not admitted: {0}")]
    InvalidHandle(&'static str),
    #[error("installed recovery policy admits no countable failure")]
    NoCountableFailure,
    #[error("installed recovery policy has no durable budget window")]
    NoDurableWindow,
}

fn policy_handle(value: &str, field: &'static str) -> Result<PlatformHandle, RecoveryPolicyLoadError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(RecoveryPolicyLoadError::BlankIdentity(field));
    }
    PlatformHandle::new(value.to_owned())
        .map_err(|_| RecoveryPolicyLoadError::InvalidHandle(field))
}

/// Loads the installation-approved recovery policy.
///
/// Binds the exact service/installation, the admissible Host owner-epoch
/// lineage digest, the permitted stop/start recipe identity, the failure
/// threshold, the budget window, the cooldown, the concurrent-attempt
/// exclusion, and the audit-failure disposition. Shape validation is the
/// sibling policy validator: a zero failure threshold (no countable failure)
/// or a zero budget window (no durable accounting) is refused. A zero
/// `max_attempts` is a valid policy that admits nothing — every decision then
/// exhausts.
///
/// # Errors
///
/// Returns [`RecoveryPolicyLoadError`] for a blank or inadmissible identity,
/// a zero failure threshold, or a zero budget window.
pub fn load_installed_recovery_policy(
    input: &InstalledRecoveryPolicyInput,
) -> Result<ApprovedRecoveryPolicy, RecoveryPolicyLoadError> {
    if input.failure_threshold == 0 {
        return Err(RecoveryPolicyLoadError::NoCountableFailure);
    }
    if input.budget_window_secs == 0 {
        return Err(RecoveryPolicyLoadError::NoDurableWindow);
    }
    let policy = ApprovedRecoveryPolicy {
        installation: policy_handle(input.installation.as_str(), "installation")?,
        service: policy_handle(input.service.as_str(), "service")?,
        owner_epoch_digest: policy_handle(input.owner_epoch_digest.as_str(), "owner epoch lineage")?,
        recipe_digest: policy_handle(input.recipe_digest.as_str(), "stop/start recipe")?,
        failure_threshold: input.failure_threshold,
        max_attempts: input.max_attempts,
        budget_window_secs: input.budget_window_secs,
        cooldown_secs: input.cooldown_secs,
        exclusive_attempt: input.exclusive_attempt,
        audit_failure_refuses_effects: input.audit_failure_refuses_effects,
    };
    policy
        .validate()
        .map_err(|_| RecoveryPolicyLoadError::NoCountableFailure)?;
    Ok(policy)
}

/// Decides recovery eligibility from a verdict, the loaded policy, and the
/// durable used-attempt count.
///
/// `durable_used_attempts` is the count read from the durable Watchdog
/// journal — never invented from a constant and never reset by a Watchdog
/// restart. An exhausted (or zero-budget) policy yields `Exhausted`: zero SCM
/// effects. An unresolved challenge yields `ChallengeUnresolved`: eligibility
/// unknown, effects refused. Durable journaling of the decision itself is
/// owned by the composition/spool lane (STITCH: #1754 writer); fenced SCM
/// execution is owned by the Host-state lane (STITCH: Host composition lane).
#[must_use]
pub fn decide_recovery(
    verdict: HostResponsiveness,
    policy: &ApprovedRecoveryPolicy,
    durable_used_attempts: u64,
) -> RecoveryBudgetDecision {
    verdict.recovery_eligibility(policy, durable_used_attempts)
}
