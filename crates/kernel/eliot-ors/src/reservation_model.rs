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

use crate::model::{validate_digest, validate_text};
use crate::{
    EpochLineage, ExpectedOrderingHead, OpaqueLabel, OperationIdentity, OrderingScope, OrsError,
    RecoveryOwner, RecoveryPayload, RecoveryPayloadEnvelope, RecoveryWriteBinding,
    StateFenceSnapshot,
};

/// One requested scope and the canonical head it must extend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeReservationRequest {
    pub scope: OrderingScope,
    pub expected_head: ExpectedOrderingHead,
}

/// Atomic reservation request for one canonical write. Its complete admitted
/// write identity and encrypted recovery payload are required; all scopes are
/// reserved or none are. Older retained non-write envelopes remain readable
/// without this binding but cannot enter the canonical write reservation path.
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
        let write_binding = self
            .envelope
            .write_binding
            .as_ref()
            .ok_or(OrsError::InvalidField {
                field: "recovery_write_binding",
                reason: "required for a canonical write reservation",
            })?;
        write_binding.validate()?;
        if write_binding.prepared_transition_sha256 != self.prepared_transition_sha256 {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        if !matches!(&self.envelope.payload, RecoveryPayload::Encrypted { .. }) {
            return Err(OrsError::InvalidField {
                field: "recovery_payload",
                reason: "canonical write reservations require an encrypted payload",
            });
        }
        self.writer_epoch.validate()?;
        validate_digest(
            &self.prepared_transition_sha256,
            "prepared_transition_sha256",
        )?;
        if self.writer_epoch != self.envelope.authority_epoch {
            return Err(OrsError::EpochMismatch);
        }
        if write_binding.authority_epoch != self.writer_epoch {
            return Err(OrsError::EpochMismatch);
        }
        if write_binding.state_fence != self.envelope.state_fence {
            return Err(OrsError::FenceMismatch);
        }
        if write_binding.protected_payload_sha256 != self.envelope.payload_sha256
            || write_binding.protected_payload_length != self.envelope.payload_length
            || !matches!(
                &self.envelope.payload,
                RecoveryPayload::Encrypted { key, .. }
                    if key == &write_binding.payload_key_reference
            )
        {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        if self.scopes.is_empty() {
            return Err(OrsError::EmptyScopeSet);
        }
        let mut seen = BTreeSet::new();
        for scope in &self.scopes {
            scope.expected_head.validate()?;
            if !seen.insert(scope.scope.clone()) {
                return Err(OrsError::DuplicateScope);
            }
        }
        let bound_scopes = write_binding
            .ordering_scopes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if seen != bound_scopes {
            return Err(OrsError::InvalidField {
                field: "ordering_scopes",
                reason: "reservation scopes must equal the complete admitted scope set",
            });
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
    /// Original submitted write identity, absent only on legacy retained rows.
    #[serde(default)]
    pub write_binding: Option<RecoveryWriteBinding>,
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
}

impl ReservationRecord {
    /// Revalidates one persisted reservation before a complete Store-stop
    /// census treats its lifecycle state as authoritative.
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        let token = &self.token;
        validate_text(token.reservation_id.as_str(), "reservation_id")?;
        validate_text(token.operation_id.as_str(), "reservation_operation_id")?;
        validate_text(token.recovery_owner.as_str(), "reservation_recovery_owner")?;
        validate_digest(
            &token.prepared_transition_sha256,
            "prepared_transition_sha256",
        )?;
        token.writer_epoch.validate()?;
        token
            .state_fence
            .validate_against_lineage(&token.writer_epoch)?;
        if token.reservation_order == 0 || token.scopes.is_empty() {
            return Err(OrsError::IntegrityProblem {
                record_type: "reservation",
                reason: "reservation order or scope set is incomplete".to_owned(),
            });
        }
        let mut seen = BTreeSet::new();
        for scope in &token.scopes {
            scope.expected_head.validate()?;
            if scope.reserved_sequence == 0 || !seen.insert(scope.scope.clone()) {
                return Err(OrsError::IntegrityProblem {
                    record_type: "reservation",
                    reason: "reservation scope sequence or identity is invalid".to_owned(),
                });
            }
        }
        if let Some(binding) = &token.write_binding {
            binding.validate()?;
            let bound_scopes = binding
                .ordering_scopes
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            if binding.operation_id != token.operation_id
                || binding.authority_epoch != token.writer_epoch
                || binding.state_fence != token.state_fence
                || binding.prepared_transition_sha256 != token.prepared_transition_sha256
                || bound_scopes != seen
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: "reservation",
                    reason: "write binding does not match its reservation token".to_owned(),
                });
            }
        }
        if let Some(reason) = &self.unknown_reason {
            validate_text(reason.as_str(), "reservation_unknown_reason")?;
        }
        if let Some(receipt_id) = &self.terminal_receipt_id {
            validate_text(receipt_id.as_str(), "reservation_terminal_receipt_id")?;
        }
        let reconciling = self.state == ReservationState::Reconciling;
        let finalized = self.state == ReservationState::Finalized;
        if self.unknown_reason.is_some() != reconciling
            || (finalized && self.terminal_receipt_id.is_none())
            || (!matches!(self.state, ReservationState::Finalized | ReservationState::Released)
                && self.terminal_receipt_id.is_some())
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "reservation",
                reason: "reservation lifecycle and terminal evidence disagree".to_owned(),
            });
        }
        Ok(())
    }
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
