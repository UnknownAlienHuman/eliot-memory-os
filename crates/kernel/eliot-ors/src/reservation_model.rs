//! Reservation data-contract cell — mechanical split from
//! `crates/kernel/eliot-ors/src/model.rs:1524-1627` (parent `07a391dad6fc71d193271fafaed3e0dbffa845fc`).
//! Architecture: P-06 ORS / durable non-semantic Operational Recovery State (cf. `lib.rs:1-6`).
//! This cell is a **data-contract boundary, not canonical truth** — it defines
//! the reservation request/token/record shapes and their local validation
//! (`ReservationRequest::validate`, `ReservationState::is_terminal`) without
//! granting ordering authority, advancing heads, or interpreting payloads.
//! Canonical ordering heads, receipt reconciliation, and store recovery remain
//! with `store.rs` / `model.rs` (canonical scope observation, reconciliation,
//! terminal receipts). Recovery application/migration, process/provider/handshake,
//! authority redesign, and Dreamer/Luna/integrated cells are explicitly excluded.
//! Source parity: `ScopeReservationRequest`, `ReservationRequest` + `validate`,
//! `ReservedScope`, `WriterReservationToken`, `ReservationState` + `is_terminal`,
//! `ReservationRecord` moved verbatim (derives, `serde` attrs, variants, fields,
//! `pub(crate)` seams unchanged except `ReservationState::is_terminal`, widened
//! to `pub` for Kernel-route fixture drain/retention assertions, issue #2031);
//! `serde` shape and public API otherwise preserved via `lib.rs` re-export.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::model::validate_digest;
use crate::{
    EpochLineage, ExpectedOrderingHead, MAX_RECOVERY_PAGE, OpaqueLabel, OperationIdentity,
    OrderingScope, OrsError, RecoveryOwner, RecoveryPayloadEnvelope, StateFenceSnapshot,
};
use eliot_receipts::ReceiptEnvelope;

/// One requested scope and the canonical head it must extend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeReservationRequest {
    pub scope: OrderingScope,
    pub expected_head: ExpectedOrderingHead,
}

/// Atomic reservation request. All scopes are reserved or none are.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRequest {
    pub reservation_id: OperationIdentity,
    pub envelope: RecoveryPayloadEnvelope,
    pub writer_epoch: EpochLineage,
    pub scopes: Vec<ScopeReservationRequest>,
    pub prepared_transition_sha256: String,
    pub expires_at_ms: i64,
    pub recovery_owner: RecoveryOwner,
}

impl ReservationRequest {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        self.envelope.validate()?;
        self.writer_epoch.validate()?;
        validate_digest(
            &self.prepared_transition_sha256,
            "prepared_transition_sha256",
        )?;
        if self.writer_epoch.current != self.envelope.authority_epoch.current {
            return Err(OrsError::EpochMismatch);
        }
        if self.scopes.is_empty() {
            return Err(OrsError::EmptyScopeSet);
        }
        if self.scopes.len() > usize::from(MAX_RECOVERY_PAGE) {
            return Err(OrsError::InvalidCursorLimit);
        }
        let mut seen = BTreeSet::new();
        for scope in &self.scopes {
            scope.expected_head.validate()?;
            if !seen.insert(scope.scope.clone()) {
                return Err(OrsError::DuplicateScope);
            }
        }
        if self.expires_at_ms <= self.envelope.created_at_ms {
            return Err(OrsError::InvalidExpiry);
        }
        Ok(())
    }
}

/// One scope sequence allocated by the coordinator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedScope {
    pub scope: OrderingScope,
    pub reserved_sequence: u64,
    pub expected_head: ExpectedOrderingHead,
}

/// Immutable token checked throughout the writer lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterReservationToken {
    pub reservation_id: OperationIdentity,
    pub operation_id: OperationIdentity,
    pub writer_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub reservation_order: u64,
    pub scopes: Vec<ReservedScope>,
    pub prepared_transition_sha256: String,
    pub expires_at_ms: i64,
    pub recovery_owner: RecoveryOwner,
}

/// Durable reservation lifecycle. Terminal states never become executable again.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReservationState {
    Reserved,
    Eligible,
    Executing,
    Reconciling,
    Finalized,
    Released,
}

impl ReservationState {
    /// Reports whether the lifecycle state is terminal.
    ///
    /// Public so test-usable Kernel-route fixtures can assert drain/retention
    /// without a second local definition of terminality. Terminal states never
    /// become executable again.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Released)
    }
}

/// Durable reservation record recovered after restart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRecord {
    pub token: WriterReservationToken,
    pub state: ReservationState,
    pub unknown_reason: Option<OpaqueLabel>,
    pub terminal_receipt_id: Option<OpaqueLabel>,
    /// Durable poison-operation record for a reservation that exhausted its
    /// bounded retry budget (issue #1684, `I14.9`).
    ///
    /// `None` for every ordinary reservation, so a reservation without a
    /// poison record keeps the exact pre-existing on-disk shape. `Some` only
    /// for a reservation whose attempts are accounted for; the record is the
    /// owner of the attempt counter, the last classified attempt outcome and
    /// the preserved no-effect evidence, so attempt accounting survives
    /// restart instead of restarting from zero in a new process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poison: Option<PoisonAttemptRecord>,
}

/// Closed classification of one spent attempt on a poison operation
/// (issue #1684, `I14.9`).
///
/// The owner vocabulary restates the neutral contract
/// `eliot_store_api::PoisonAttemptOutcome` without importing the canonical
/// write contract, matching this cell's data-contract boundary: ORS records
/// the classification and never re-derives it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PoisonAttemptClassification {
    /// Rejected before sequence assignment: no ordering position was
    /// allocated, so nothing can be dead-lettered or dispositioned.
    Refused,
    /// The attempt is spent; the reserved position is unchanged and another
    /// bounded attempt is admitted while budget remains.
    Retry,
    /// The attempt is spent and the canonical owner proved the original
    /// mutation was not applied. This is the only no-effect classification.
    TerminalProvenNoEffect,
    /// The attempt left the outcome ambiguous (timeout, lost response, expired
    /// lease, missing receipt, failed query). Not a no-effect proof.
    Unknown,
}

/// Durable attempt accounting and preserved no-effect evidence for one poison
/// operation (issue #1684).
///
/// This is the state that makes bounded retries survive a restart: `attempts`
/// is written before any further attempt is admitted, and the recorded
/// `classification` is the last observed arm. `Unknown` is terminal for the
/// *attempt budget* but never for the operation: an ambiguous outcome keeps
/// the reservation under reconciliation with its original identity, and the
/// gap stays open (`I5.19`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoisonAttemptRecord {
    /// Bounded retry-policy revision this reservation was admitted under.
    pub policy_revision: u32,
    /// Bounded attempt budget; non-zero.
    pub max_attempts: u32,
    /// Attempts already spent. Written durably before a possible retry, so a
    /// restart re-reads this count instead of restarting the budget.
    pub attempts: u32,
    /// Classification of the last spent attempt.
    pub last_classification: PoisonAttemptClassification,
    /// Digest of the exact no-effect evidence for a
    /// `TerminalProvenNoEffect` classification; `None` for every other arm.
    ///
    /// A digest only: the evidence bytes stay with the canonical owner that
    /// produced them, and ORS never interprets them.
    pub no_effect_evidence_sha256: Option<String>,
}

impl PoisonAttemptRecord {
    /// Checks the bounded budget and the classification/evidence agreement.
    ///
    /// A `TerminalProvenNoEffect` classification MUST carry the evidence
    /// digest that proves non-application: without it there is no no-effect
    /// proof, and a terminal classification without one is refused here rather
    /// than allowed to look terminal downstream. Every other arm MUST NOT
    /// carry one, so a no-effect proof can never be attached to an ambiguous
    /// outcome.
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        if self.max_attempts == 0 {
            return Err(OrsError::InvalidField {
                field: "poison_max_attempts",
                reason: "must be greater than zero",
            });
        }
        if self.attempts > self.max_attempts {
            return Err(OrsError::InvalidField {
                field: "poison_attempts",
                reason: "spent attempts must not exceed the bounded budget",
            });
        }
        match (&self.last_classification, &self.no_effect_evidence_sha256) {
            (PoisonAttemptClassification::TerminalProvenNoEffect, Some(digest)) => {
                validate_digest(digest, "poison_no_effect_evidence_sha256")
            }
            (PoisonAttemptClassification::TerminalProvenNoEffect, None) => {
                Err(OrsError::InvalidField {
                    field: "poison_no_effect_evidence_sha256",
                    reason: "terminal classification requires the exact no-effect evidence digest",
                })
            }
            (_, Some(_)) => Err(OrsError::InvalidField {
                field: "poison_no_effect_evidence_sha256",
                reason: "only a proven no-effect classification carries no-effect evidence",
            }),
            (_, None) => Ok(()),
        }
    }

    /// Reports whether the bounded retry budget is exhausted.
    ///
    /// Exhaustion never terminalizes an ambiguous outcome: it only refuses a
    /// further attempt, leaving the reservation under reconciliation.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.attempts >= self.max_attempts
    }

    /// Reports whether the last spent attempt proved the original mutation was
    /// not applied. Only a proven no-effect arm can request dead lettering.
    #[must_use]
    pub const fn is_proven_no_effect(&self) -> bool {
        matches!(
            self.last_classification,
            PoisonAttemptClassification::TerminalProvenNoEffect
        )
    }
}

/// Exact canonical evidence that resolves one blocked reserved position
/// (issue #1684).
///
/// This is the ORS-side mirror of the committed `SequenceDisposition`: the
/// receipt envelope the canonical Store issued for the disposition transition,
/// plus the disposition's own binding to the reservation being resolved. ORS
/// validates the binding and advances every scope of the reservation
/// atomically; it never interprets the disposition payload's semantics, and the
/// canonical Store remains the only owner of gap meaning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceGapReconciliation {
    /// The reservation whose blocked position is resolved. Must match the
    /// persisted record exactly.
    pub reservation_id: OperationIdentity,
    /// The original operation identity of the dead-lettered work. Preserved
    /// forever; never a fresh identity.
    pub operation_id: OperationIdentity,
    /// Single-coordinator precedence of the reservation being resolved.
    pub reservation_order: u64,
    /// Fence snapshot the reservation was taken under.
    pub state_fence: StateFenceSnapshot,
    /// Recovery owner of the reservation, preserved.
    pub recovery_owner: RecoveryOwner,
    /// Every scope of the reservation, with the reserved sequence the
    /// disposition covers. Must be the complete reserved scope set.
    pub scopes: Vec<ReservedScope>,
    /// The committed canonical `SequenceDisposition` receipt envelope.
    pub receipt: ReceiptEnvelope,
    /// Digest of the poison-operation record the disposition was taken
    /// against. Binds the decision to the exact evidence on record, so a
    /// duplicate-but-changed disposition fails closed.
    pub poison_record_sha256: String,
}

#[cfg(test)]
mod reservation_terminal_tests {
    use super::ReservationState;

    #[test]
    fn only_finalized_and_released_are_terminal() {
        assert!(ReservationState::Finalized.is_terminal());
        assert!(ReservationState::Released.is_terminal());
        assert!(!ReservationState::Reserved.is_terminal());
        assert!(!ReservationState::Eligible.is_terminal());
        assert!(!ReservationState::Executing.is_terminal());
        assert!(!ReservationState::Reconciling.is_terminal());
    }
}
