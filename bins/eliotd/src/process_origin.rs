//! Governor-owned process-origin observation, kept separate from control authority.
//!
//! Issue #1960: a known path/port/process triple is **observable** but never
//! **controllable** on the strength of observation alone. Observation answers
//! what was seen; only a current Governor-issued [`OwnershipChallengeReceipt`]
//! bound to the exact [`ProcessOriginEvidence`] authorizes a control effect.
//!
//! Ownership and authority stay with the Governor and the Kernel:
//!
//! - [`ProcessOriginEvidence`] is an observation record only. It carries no
//!   PID/name/path/port ownership inference (per `bins/AGENTS.md` a binary
//!   name, path, port, or exit never creates lifecycle or authority
//!   ownership) and no control capability.
//! - [`OperationDisposition`] is the pure policy-step outcome computed by
//!   [`gate_process_control`] **before** any Kernel forward. Control
//!   operations (`Kill`, `Mutate`, `Adopt`, `AttachCredential`) resolve to
//!   [`OperationDisposition::ForwardableToKernel`] only with a current
//!   matching challenge; otherwise they resolve to
//!   [`OperationDisposition::Denied`]. Probes and status reads resolve to
//!   [`OperationDisposition::Observed`] and are never forwardable: probes
//!   observe only.
//! - [`check_kernel_forward`] is the fail-closed enforcement point the daemon
//!   calls before forwarding a gated operation over the neutral authenticated
//!   Kernel port. It returns `Ok` only for the exact
//!   evidence + operation + current-matching-challenge triple.
//! - [`check_shutdown_authorized`] proves the acceptance boundary: a read
//!   status receipt ([`ProcessStatusReceipt`]) never authorizes shutdown, no
//!   matter how fresh or well-formed. Only a current matching ownership
//!   challenge does.
//!
//! This module performs no I/O, retains no clients or threads, and invents no
//! receipts: every authorizing receipt is Governor-issued and validated here
//! field-for-field before use.

#![forbid(unsafe_code)]

use eliot_contracts::{StateFence, fences_match_exact, sha256_hex};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors raised by the process-origin policy step.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProcessOriginError {
    /// An evidence, challenge, or receipt field is malformed.
    #[error("process-origin contract: {0}")]
    Contract(String),
    /// No challenge was presented for an operation that requires one.
    #[error("process-origin denied: control requires a current matching ownership challenge")]
    ChallengeRequired,
    /// The challenge does not bind the presented evidence.
    #[error("process-origin denied: ownership challenge does not match the observed origin")]
    ChallengeMismatch,
    /// The challenge is not current at the presented time.
    #[error("process-origin denied: ownership challenge is not current")]
    ChallengeNotCurrent,
    /// A status/read receipt was presented where control authority is required.
    #[error("process-origin denied: a read status receipt never authorizes shutdown or control")]
    StatusNeverAuthorizes,
    /// The operation is observe-only and must never be forwarded to the Kernel.
    #[error("process-origin denied: probes observe only and are never forwarded")]
    ObserveOnly,
}

/// Governor-owned observation of one process origin.
///
/// Observation only: the known path, port, and process label describe what
/// was seen. They grant no stop, adopt, mutate, or credential-attach
/// authority, and no ownership is inferred from them. The `origin_digest`
/// binds the observed triple plus the admitted fence so a challenge can match
/// exactly one observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessOriginEvidence {
    /// Observed executable path (known-path probe answer, verbatim).
    pub observed_path: String,
    /// Observed port (known-port probe answer).
    pub observed_port: u16,
    /// Observed process label (human/process-table label, verbatim).
    pub observed_process: String,
    /// Lowercase hex SHA-256 over the canonical observed triple plus fence.
    pub origin_digest: String,
    /// Admitted fence under which the observation was taken.
    pub state_fence: StateFence,
    /// Unix milliseconds at which the observation was taken.
    pub observed_at_unix_ms: u64,
}

/// Control operation requested against an observed process origin.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum ProcessControlOperation {
    /// Read-only status probe. Observe only, never forwarded.
    ReadStatus,
    /// General observation probe. Observe only, never forwarded.
    ProbeObserve,
    /// Stop the observed process. Requires a current matching challenge.
    Kill,
    /// Mutate the observed process. Requires a current matching challenge.
    Mutate,
    /// Adopt the observed process. Requires a current matching challenge.
    Adopt,
    /// Attach a credential to the observed process. Requires a current matching challenge.
    AttachCredential,
}

impl ProcessControlOperation {
    /// Returns whether the operation needs a current matching ownership
    /// challenge before any Kernel forward.
    #[must_use]
    pub const fn requires_challenge(self) -> bool {
        match self {
            Self::ReadStatus | Self::ProbeObserve => false,
            Self::Kill | Self::Mutate | Self::Adopt | Self::AttachCredential => true,
        }
    }

    /// Returns whether the operation may ever be forwarded to the Kernel.
    /// Probes and status reads are observe-only.
    #[must_use]
    pub const fn is_forwardable(self) -> bool {
        match self {
            Self::ReadStatus | Self::ProbeObserve => false,
            Self::Kill | Self::Mutate | Self::Adopt | Self::AttachCredential => true,
        }
    }
}

/// Governor-issued ownership challenge receipt.
///
/// The single control capability in this module. It authorizes exactly one
/// observed origin (`origin_digest`), under exactly one fence
/// (`state_fence`), while current (`issued_at_unix_ms..=expires_at_unix_ms`
/// contains `now`). Kernel issues through the Governor; this crate only
/// validates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipChallengeReceipt {
    /// Governor-issued challenge identity.
    pub challenge_id: String,
    /// Origin digest this challenge binds (must equal the evidence digest).
    pub origin_digest: String,
    /// Fence this challenge binds (must match the evidence fence exactly).
    pub state_fence: StateFence,
    /// Unix milliseconds at which the challenge was issued.
    pub issued_at_unix_ms: u64,
    /// Unix milliseconds at which the challenge expires (inclusive).
    pub expires_at_unix_ms: u64,
    /// Lowercase hex SHA-256 over the canonical challenge fields.
    pub receipt_digest: String,
}

/// Read-only status receipt for an observed process origin.
///
/// Observation answer only: it reports what a status probe saw. It carries
/// no challenge, no fence authority beyond the observed fence echo, and no
/// control capability. There is deliberately **no** constructor or conversion
/// from this type into anything [`check_shutdown_authorized`] or
/// [`check_kernel_forward`] accepts: type shape alone keeps a status receipt
/// from authorizing shutdown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStatusReceipt {
    /// Origin digest the status was read from.
    pub origin_digest: String,
    /// Fence echoed from the observation (verbatim, not authority).
    pub state_fence: StateFence,
    /// Bounded status projection (e.g. `"running"`, `"unknown"`).
    pub status: String,
    /// Unix milliseconds at which the status was read.
    pub read_at_unix_ms: u64,
}

/// Pure policy-step outcome for one gated operation.
///
/// Computed by [`gate_process_control`] before any Kernel forward. Either the
/// operation was observe-only ([`OperationDisposition::Observed`]), it is
/// authorized for Kernel forward ([`OperationDisposition::ForwardableToKernel`]),
/// or it is denied with an explicit reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationDisposition {
    /// Observe-only outcome: answered from evidence, never forwarded.
    Observed,
    /// The exact evidence + operation + current-matching-challenge triple
    /// validated; the caller may now forward to the Kernel.
    ForwardableToKernel,
    /// Denied with an explicit fail-closed reason.
    Denied {
        /// Machine-readable denial reason.
        reason: &'static str,
    },
}

/// Computes the canonical origin digest over the observed triple plus fence.
#[must_use]
pub fn canonical_origin_digest(path: &str, port: u16, process: &str, fence: &StateFence) -> String {
    let fence_bytes = serde_json::to_vec(fence).unwrap_or_default();
    let mut canonical = Vec::with_capacity(path.len() + process.len() + fence_bytes.len() + 16);
    canonical.extend_from_slice(path.as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(&port.to_be_bytes());
    canonical.push(0);
    canonical.extend_from_slice(process.as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(&fence_bytes);
    sha256_hex(&canonical)
}

/// Computes the canonical receipt digest over the challenge fields.
#[must_use]
pub fn canonical_challenge_digest(
    challenge_id: &str,
    origin_digest: &str,
    fence: &StateFence,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> String {
    let fence_bytes = serde_json::to_vec(fence).unwrap_or_default();
    let mut canonical =
        Vec::with_capacity(challenge_id.len() + origin_digest.len() + fence_bytes.len() + 32);
    canonical.extend_from_slice(challenge_id.as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(origin_digest.as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(&fence_bytes);
    canonical.push(0);
    canonical.extend_from_slice(&issued_at_unix_ms.to_be_bytes());
    canonical.push(0);
    canonical.extend_from_slice(&expires_at_unix_ms.to_be_bytes());
    sha256_hex(&canonical)
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ProcessOriginError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProcessOriginError::Contract(format!(
            "{field} must be lowercase hex sha256"
        )));
    }
    Ok(())
}

impl ProcessOriginEvidence {
    /// Validates the observation record field-for-field.
    ///
    /// Validation proves the record is well-formed; it never proves control
    /// authority. A valid record authorizes observation answers only.
    pub fn validate(&self) -> Result<(), ProcessOriginError> {
        if self.observed_path.trim().is_empty() {
            return Err(ProcessOriginError::Contract(
                "observed_path must not be empty".to_owned(),
            ));
        }
        if self.observed_path.contains("..") {
            return Err(ProcessOriginError::Contract(
                "observed_path must not contain parent traversal".to_owned(),
            ));
        }
        if self.observed_port == 0 {
            return Err(ProcessOriginError::Contract(
                "observed_port must be nonzero".to_owned(),
            ));
        }
        if self.observed_process.trim().is_empty() {
            return Err(ProcessOriginError::Contract(
                "observed_process must not be empty".to_owned(),
            ));
        }
        self.state_fence
            .validate()
            .map_err(|error| ProcessOriginError::Contract(format!("state_fence: {error}")))?;
        if self.observed_at_unix_ms == 0 {
            return Err(ProcessOriginError::Contract(
                "observed_at_unix_ms must be nonzero".to_owned(),
            ));
        }
        validate_digest(&self.origin_digest, "origin_digest")?;
        let expected = canonical_origin_digest(
            &self.observed_path,
            self.observed_port,
            &self.observed_process,
            &self.state_fence,
        );
        if self.origin_digest != expected {
            return Err(ProcessOriginError::Contract(
                "origin_digest does not bind the observed triple and fence".to_owned(),
            ));
        }
        Ok(())
    }
}

impl OwnershipChallengeReceipt {
    /// Validates the challenge record field-for-field, without a clock.
    pub fn validate(&self) -> Result<(), ProcessOriginError> {
        if self.challenge_id.trim().is_empty() {
            return Err(ProcessOriginError::Contract(
                "challenge_id must not be empty".to_owned(),
            ));
        }
        self.state_fence
            .validate()
            .map_err(|error| ProcessOriginError::Contract(format!("state_fence: {error}")))?;
        if self.expires_at_unix_ms < self.issued_at_unix_ms {
            return Err(ProcessOriginError::Contract(
                "expires_at_unix_ms must not precede issued_at_unix_ms".to_owned(),
            ));
        }
        validate_digest(&self.origin_digest, "origin_digest")?;
        validate_digest(&self.receipt_digest, "receipt_digest")?;
        let expected = canonical_challenge_digest(
            &self.challenge_id,
            &self.origin_digest,
            &self.state_fence,
            self.issued_at_unix_ms,
            self.expires_at_unix_ms,
        );
        if self.receipt_digest != expected {
            return Err(ProcessOriginError::Contract(
                "receipt_digest does not bind the challenge fields".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns whether the challenge is current at `now_unix_ms`.
    #[must_use]
    pub fn is_current(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.issued_at_unix_ms && now_unix_ms <= self.expires_at_unix_ms
    }

    /// Returns whether this challenge authorizes control over `evidence` at
    /// `now_unix_ms`: valid records, exact digest bind, exact fence match,
    /// and current window.
    pub fn matches_evidence(
        &self,
        evidence: &ProcessOriginEvidence,
        now_unix_ms: u64,
    ) -> Result<(), ProcessOriginError> {
        self.validate()?;
        evidence.validate()?;
        if now_unix_ms == 0 {
            return Err(ProcessOriginError::Contract(
                "now_unix_ms must be nonzero".to_owned(),
            ));
        }
        if !self.is_current(now_unix_ms) {
            return Err(ProcessOriginError::ChallengeNotCurrent);
        }
        if self.origin_digest != evidence.origin_digest {
            return Err(ProcessOriginError::ChallengeMismatch);
        }
        if !fences_match_exact(&self.state_fence, &evidence.state_fence) {
            return Err(ProcessOriginError::ChallengeMismatch);
        }
        Ok(())
    }
}

impl ProcessStatusReceipt {
    /// Validates the status receipt as an observation answer only.
    pub fn validate(&self) -> Result<(), ProcessOriginError> {
        if self.status.trim().is_empty() || self.status.len() > 64 {
            return Err(ProcessOriginError::Contract(
                "status must be a nonempty bounded projection".to_owned(),
            ));
        }
        self.state_fence
            .validate()
            .map_err(|error| ProcessOriginError::Contract(format!("state_fence: {error}")))?;
        if self.read_at_unix_ms == 0 {
            return Err(ProcessOriginError::Contract(
                "read_at_unix_ms must be nonzero".to_owned(),
            ));
        }
        validate_digest(&self.origin_digest, "origin_digest")?;
        Ok(())
    }
}

/// Pure policy step: computes the disposition of one operation against one
/// observed origin, before any Kernel forward.
///
/// - `ReadStatus`/`ProbeObserve` always resolve to
///   [`OperationDisposition::Observed`]: answered from evidence, never
///   forwarded, and a presented challenge changes nothing.
/// - `Kill`/`Mutate`/`Adopt`/`AttachCredential` resolve to
///   [`OperationDisposition::ForwardableToKernel`] only when `challenge` is
///   `Some` and [`OwnershipChallengeReceipt::matches_evidence`] succeeds at
///   `now_unix_ms`; otherwise they resolve to
///   [`OperationDisposition::Denied`] with an explicit reason. A known path,
///   port, or process label alone never authorizes them.
#[must_use]
pub fn gate_process_control(
    evidence: &ProcessOriginEvidence,
    operation: ProcessControlOperation,
    challenge: Option<&OwnershipChallengeReceipt>,
    now_unix_ms: u64,
) -> OperationDisposition {
    if evidence.validate().is_err() {
        return OperationDisposition::Denied {
            reason: "invalid process-origin evidence",
        };
    }
    if !operation.requires_challenge() {
        return OperationDisposition::Observed;
    }
    let Some(receipt) = challenge else {
        return OperationDisposition::Denied {
            reason: "control requires a current matching ownership challenge",
        };
    };
    match receipt.matches_evidence(evidence, now_unix_ms) {
        Ok(()) => OperationDisposition::ForwardableToKernel,
        Err(ProcessOriginError::ChallengeNotCurrent) => OperationDisposition::Denied {
            reason: "ownership challenge is not current",
        },
        Err(ProcessOriginError::ChallengeMismatch) => OperationDisposition::Denied {
            reason: "ownership challenge does not match the observed origin",
        },
        Err(_) => OperationDisposition::Denied {
            reason: "invalid ownership challenge",
        },
    }
}

/// Fail-closed enforcement point called immediately before a Kernel forward.
///
/// Returns `Ok(())` only when the operation is forwardable **and** the exact
/// evidence + operation + current-matching-challenge triple validates at
/// `now_unix_ms`. Observe-only operations always fail with
/// [`ProcessOriginError::ObserveOnly`]: probes observe only and are never
/// forwarded, even with a challenge. Control operations without a current
/// matching challenge fail with the corresponding denial.
pub fn check_kernel_forward(
    evidence: &ProcessOriginEvidence,
    operation: ProcessControlOperation,
    challenge: Option<&OwnershipChallengeReceipt>,
    now_unix_ms: u64,
) -> Result<(), ProcessOriginError> {
    if !operation.is_forwardable() {
        return Err(ProcessOriginError::ObserveOnly);
    }
    evidence.validate()?;
    let Some(receipt) = challenge else {
        return Err(ProcessOriginError::ChallengeRequired);
    };
    receipt.matches_evidence(evidence, now_unix_ms)
}

/// Shutdown authorization: only a current matching ownership challenge
/// authorizes shutdown of the observed origin.
///
/// A [`ProcessStatusReceipt`] is deliberately not an accepted input: read
/// status never authorizes shutdown, no matter how fresh or well-formed.
/// There is no overload taking a status receipt, so the type system — plus
/// the test below — keeps the read path from becoming a control path.
pub fn check_shutdown_authorized(
    evidence: &ProcessOriginEvidence,
    challenge: &OwnershipChallengeReceipt,
    now_unix_ms: u64,
) -> Result<(), ProcessOriginError> {
    evidence.validate()?;
    challenge.matches_evidence(evidence, now_unix_ms)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_fence(generation: u64) -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
                NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(generation).expect("generation"),
        )
    }

    fn evidence(fence: &StateFence) -> ProcessOriginEvidence {
        let origin_digest = canonical_origin_digest("/srv/eliot/worker", 4217, "worker-7", fence);
        ProcessOriginEvidence {
            observed_path: "/srv/eliot/worker".to_owned(),
            observed_port: 4217,
            observed_process: "worker-7".to_owned(),
            origin_digest,
            state_fence: fence.clone(),
            observed_at_unix_ms: 1_700_000_000_000,
        }
    }

    fn challenge(fence: &StateFence, origin_digest: &str) -> OwnershipChallengeReceipt {
        let receipt_digest = canonical_challenge_digest(
            "ch-1",
            origin_digest,
            fence,
            1_700_000_000_000,
            1_700_000_060_000,
        );
        OwnershipChallengeReceipt {
            challenge_id: "ch-1".to_owned(),
            origin_digest: origin_digest.to_owned(),
            state_fence: fence.clone(),
            issued_at_unix_ms: 1_700_000_000_000,
            expires_at_unix_ms: 1_700_000_060_000,
            receipt_digest,
        }
    }

    fn status_receipt(fence: &StateFence, origin_digest: &str) -> ProcessStatusReceipt {
        ProcessStatusReceipt {
            origin_digest: origin_digest.to_owned(),
            state_fence: fence.clone(),
            status: "running".to_owned(),
            read_at_unix_ms: 1_700_000_030_000,
        }
    }

    #[test]
    fn known_origin_is_observable_but_not_stoppable_adoptable_or_mutable_without_challenge() {
        let fence = test_fence(1);
        let observed = evidence(&fence);
        observed.validate().expect("fixture evidence binds");
        let now = 1_700_000_030_000;

        assert_eq!(
            gate_process_control(&observed, ProcessControlOperation::ReadStatus, None, now),
            OperationDisposition::Observed
        );
        assert_eq!(
            gate_process_control(&observed, ProcessControlOperation::ProbeObserve, None, now),
            OperationDisposition::Observed
        );
        for operation in [
            ProcessControlOperation::Kill,
            ProcessControlOperation::Mutate,
            ProcessControlOperation::Adopt,
            ProcessControlOperation::AttachCredential,
        ] {
            assert!(
                matches!(
                    gate_process_control(&observed, operation, None, now),
                    OperationDisposition::Denied { .. }
                ),
                "{operation:?} without a challenge must be denied"
            );
            assert!(check_kernel_forward(&observed, operation, None, now).is_err());
        }
    }

    #[test]
    fn current_matching_challenge_authorizes_each_control_operation_before_kernel_forward() {
        let fence = test_fence(1);
        let observed = evidence(&fence);
        let receipt = challenge(&fence, &observed.origin_digest);
        let now = 1_700_000_030_000;

        for operation in [
            ProcessControlOperation::Kill,
            ProcessControlOperation::Mutate,
            ProcessControlOperation::Adopt,
            ProcessControlOperation::AttachCredential,
        ] {
            assert_eq!(
                gate_process_control(&observed, operation, Some(&receipt), now),
                OperationDisposition::ForwardableToKernel,
                "{operation:?} with a current matching challenge must be forwardable"
            );
            check_kernel_forward(&observed, operation, Some(&receipt), now)
                .expect("gated forward authorizes");
        }
        check_shutdown_authorized(&observed, &receipt, now).expect("shutdown authorizes");
    }

    #[test]
    fn stale_or_mismatched_challenge_never_authorizes_control() {
        let fence = test_fence(1);
        let observed = evidence(&fence);
        let receipt = challenge(&fence, &observed.origin_digest);

        let expired_now = 1_700_000_060_001;
        assert!(matches!(
            gate_process_control(
                &observed,
                ProcessControlOperation::Kill,
                Some(&receipt),
                expired_now
            ),
            OperationDisposition::Denied { .. }
        ));
        assert!(
            check_kernel_forward(
                &observed,
                ProcessControlOperation::Adopt,
                Some(&receipt),
                expired_now
            )
            .is_err()
        );

        let other_fence = test_fence(2);
        let other = evidence(&other_fence);
        assert!(matches!(
            gate_process_control(
                &other,
                ProcessControlOperation::Mutate,
                Some(&receipt),
                1_700_000_030_000
            ),
            OperationDisposition::Denied { .. }
        ));
        assert!(check_shutdown_authorized(&other, &receipt, 1_700_000_030_000).is_err());

        let mut tampered = receipt.clone();
        tampered.origin_digest = "0".repeat(64);
        assert!(matches!(
            gate_process_control(
                &observed,
                ProcessControlOperation::Kill,
                Some(&tampered),
                1_700_000_030_000
            ),
            OperationDisposition::Denied { .. }
        ));
    }

    #[test]
    fn read_status_receipt_does_not_authorize_shutdown_and_probes_never_forward() {
        let fence = test_fence(1);
        let observed = evidence(&fence);
        let receipt = challenge(&fence, &observed.origin_digest);
        let status = status_receipt(&fence, &observed.origin_digest);
        status.validate().expect("fixture status reads");
        let now = 1_700_000_030_000;

        // The status receipt type has no path into shutdown or Kernel-forward
        // authorization: only the challenge authorizes. Reading status stays
        // observe-only even beside a valid challenge.
        assert_eq!(
            gate_process_control(
                &observed,
                ProcessControlOperation::ReadStatus,
                Some(&receipt),
                now
            ),
            OperationDisposition::Observed
        );
        assert!(matches!(
            check_kernel_forward(
                &observed,
                ProcessControlOperation::ReadStatus,
                Some(&receipt),
                now
            ),
            Err(ProcessOriginError::ObserveOnly)
        ));
        assert!(matches!(
            check_kernel_forward(
                &observed,
                ProcessControlOperation::ProbeObserve,
                Some(&receipt),
                now
            ),
            Err(ProcessOriginError::ObserveOnly)
        ));
        // A well-formed fresh status receipt cannot substitute for the
        // challenge: shutdown still requires the challenge itself.
        assert!(check_shutdown_authorized(&observed, &receipt, now).is_ok());
        let status_digest_replay = status.origin_digest.clone();
        assert_eq!(status_digest_replay, observed.origin_digest);
    }
}
