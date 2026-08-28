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
//! `pub(crate)` seams unchanged); `serde` shape and public API preserved via
//! `lib.rs` re-export.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::model::validate_digest;
use crate::{
    EpochLineage, ExpectedOrderingHead, MAX_RECOVERY_PAGE, OpaqueLabel, OperationIdentity,
    OrderingScope, OrsError, RecoveryOwner, RecoveryPayloadEnvelope, StateFenceSnapshot,
};

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
    pub(crate) const fn is_terminal(self) -> bool {
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
}
