//! Watchdog-side responsiveness-challenge issuance (issue #1757 W1; I8.3).
//!
//! Architecture: I8.3 (deterministic supervision loop), I1.4 (independent SCM
//! branches), I13.5 (stale generation/revision is a conflict).
//!
//! This cell binds one Watchdog challenge to the installation's
//! pre-authorized recovery contour: challenge identity, fresh 256-bit nonce
//! digest, Watchdog installation and policy binding, expected Host
//! owner-epoch digest, approved service registration and generation,
//! absolute deadline, and protocol revision. The nonce itself never travels —
//! only its sha256 digest — and no credential, raw path, or user data is a
//! field here.
//!
//! The wire contract stays owned by `eliot-host-service::runtime_control` and
//! the endpoint binding by `eliot-host-control-endpoint`; this crate does not
//! depend on either (no new binary dependency), so this cell mirrors only
//! coordination identities and reuses the sibling outcome classifier
//! (`host_identity_observation`, read-only) for verdicts. It introduces no
//! spool/journal writer (Watchdog composition/spool lane, #1754 writer), no
//! SCM execution (Host lane), and no sensor, Signal, or escalation duplicate
//! (#1755/#1756/#1759 are consumed, not copied).

use std::collections::HashSet;

use eliot_platform::PlatformHandle;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::host_identity_observation::{
    BoundedChallengeWait, ChallengeAttemptOutcome, ChallengeUncertainty, HostObservation,
    HostObservationState, HostResponsiveness, MAX_CHALLENGE_WAIT_SECS,
};

/// Protocol revision mirrored from the Host wire owner. The endpoint lane
/// validates equality at bind time; a stale or foreign revision never issues
/// here.
pub const WATCHDOG_CHALLENGE_PROTOCOL_REVISION: u16 = 1;

/// Typed issuance failure. Identity names only; no secret or path material.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum WatchdogChallengeError {
    #[error("watchdog challenge identity is blank or not a coordination identity: {0}")]
    BlankIdentity(&'static str),
    #[error("watchdog challenge handle is not admitted: {0}")]
    InvalidHandle(&'static str),
    #[error("watchdog challenge wait is outside the bounded owner-queue guarantee")]
    WaitOutOfBound,
    #[error("watchdog challenge deadline overflows")]
    DeadlineOverflow,
    #[error("watchdog challenge identity was already answered; replay refused")]
    AlreadyAnswered,
}

/// Installer-bound inputs for one challenge. All strings are coordination
/// identities (digests, approved names, generations); never nonces,
/// credentials, paths, or user data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogChallengeSpec {
    pub installation: String,
    pub policy_digest: String,
    pub expected_owner_digest: String,
    pub approved_service: String,
    pub approved_generation: String,
}

/// One issued Watchdog challenge binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogChallengeBinding {
    pub challenge_id: PlatformHandle,
    pub nonce_digest: PlatformHandle,
    pub installation: PlatformHandle,
    pub policy_digest: PlatformHandle,
    pub expected_owner_digest: PlatformHandle,
    pub approved_service: PlatformHandle,
    pub approved_generation: PlatformHandle,
    pub deadline_unix_ms: u64,
    pub wait_secs: u64,
    pub protocol_revision: u16,
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn coordination_handle(value: &str, field: &'static str) -> Result<PlatformHandle, WatchdogChallengeError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(WatchdogChallengeError::BlankIdentity(field));
    }
    PlatformHandle::new(value.to_owned())
        .map_err(|_| WatchdogChallengeError::InvalidHandle(field))
}

impl WatchdogChallengeBinding {
    /// Issues one challenge binding for a fresh challenge identity.
    ///
    /// The nonce digest is derived as sha256 over the challenge identity,
    /// issue time, installation, and wait: unique per challenge identity
    /// without importing the nonce itself. The absolute deadline is
    /// `issued_at_unix_ms + wait_secs`; waits are bounded by
    /// [`MAX_CHALLENGE_WAIT_SECS`] so no observation outlives the owner-queue
    /// guarantee.
    ///
    /// # Errors
    ///
    /// Returns [`WatchdogChallengeError`] for a blank or inadmissible
    /// identity, a zero or over-bound wait, or a deadline overflow.
    pub fn issue(
        spec: &WatchdogChallengeSpec,
        challenge_id: &str,
        issued_at_unix_ms: u64,
        wait_secs: u64,
    ) -> Result<Self, WatchdogChallengeError> {
        if wait_secs == 0 || wait_secs > MAX_CHALLENGE_WAIT_SECS {
            return Err(WatchdogChallengeError::WaitOutOfBound);
        }
        let challenge_id = coordination_handle(challenge_id, "challenge identity")?;
        let installation = coordination_handle(spec.installation.as_str(), "installation")?;
        let policy_digest = coordination_handle(spec.policy_digest.as_str(), "policy binding")?;
        let expected_owner_digest =
            coordination_handle(spec.expected_owner_digest.as_str(), "expected owner epoch")?;
        let approved_service =
            coordination_handle(spec.approved_service.as_str(), "approved service")?;
        let approved_generation =
            coordination_handle(spec.approved_generation.as_str(), "approved generation")?;
        let nonce_material = format!(
            "{}:{issued_at_unix_ms}:{}:{wait_secs}",
            challenge_id.as_str(),
            installation.as_str(),
        );
        let nonce_digest = PlatformHandle::new(sha256_hex(nonce_material.as_bytes()))
            .map_err(|_| WatchdogChallengeError::InvalidHandle("nonce digest"))?;
        let deadline_unix_ms = issued_at_unix_ms
            .checked_add(
                wait_secs
                    .checked_mul(1000)
                    .ok_or(WatchdogChallengeError::DeadlineOverflow)?,
            )
            .ok_or(WatchdogChallengeError::DeadlineOverflow)?;
        if deadline_unix_ms <= issued_at_unix_ms {
            return Err(WatchdogChallengeError::DeadlineOverflow);
        }
        Ok(Self {
            challenge_id,
            nonce_digest,
            installation,
            policy_digest,
            expected_owner_digest,
            approved_service,
            approved_generation,
            deadline_unix_ms,
            wait_secs,
            protocol_revision: WATCHDOG_CHALLENGE_PROTOCOL_REVISION,
        })
    }

    /// Whether the binding still holds at `now_unix_ms`.
    #[must_use]
    pub const fn live_at(self, now_unix_ms: u64) -> bool {
        now_unix_ms <= self.deadline_unix_ms
    }
}

/// Challenger-side replay guard: one challenge identity answers once.
///
/// A second answer under the same identity is a replay and is refused; the
/// challenger issues a fresh identity for the next interval instead.
#[derive(Clone, Debug, Default)]
pub struct ChallengeReplayGuard {
    answered: HashSet<String>,
}

impl ChallengeReplayGuard {
    #[must_use]
    pub fn new() -> Self {
        Self {
            answered: HashSet::new(),
        }
    }

    /// Consumes one challenge identity after its answer validated.
    ///
    /// # Errors
    ///
    /// Returns [`WatchdogChallengeError::AlreadyAnswered`] when this identity
    /// already answered once.
    pub fn consume(&mut self, challenge_id: &str) -> Result<(), WatchdogChallengeError> {
        if !self.answered.insert(challenge_id.to_owned()) {
            return Err(WatchdogChallengeError::AlreadyAnswered);
        }
        Ok(())
    }

    /// Whether this identity already answered once.
    #[must_use]
    pub fn already_answered(&self, challenge_id: &str) -> bool {
        self.answered.contains(challenge_id)
    }
}

/// Classifies one challenge attempt with target identity rechecked around the
/// bounded observation interval.
///
/// Both the pre-interval (`before`) and post-interval (`after`) observations
/// must be `Running` with the same retained process identity; any change —
/// including a target that was never live — is an explicit
/// [`ChallengeUncertainty::TargetChanged`], never health and never automatic
/// restart eligibility. A rechecked live target delegates to the sibling pure
/// classifier (`Running` plus a competently attempted challenge that timed
/// out inside an uncancelled bounded wait is `AliveUnresponsive`).
#[must_use]
pub fn rechecked_responsiveness(
    before: &HostObservation,
    after: &HostObservation,
    wait: &BoundedChallengeWait,
    attempt: &ChallengeAttemptOutcome,
) -> HostResponsiveness {
    if wait.is_cancelled() {
        return after.responsiveness(wait, attempt);
    }
    let target_stable = matches!(before.state, HostObservationState::Running)
        && matches!(after.state, HostObservationState::Running)
        && before.identity.is_some()
        && before.identity == after.identity;
    if !target_stable {
        return HostResponsiveness::Uncertain(ChallengeUncertainty::TargetChanged);
    }
    after.responsiveness(wait, attempt)
}
