//! Architecture: A13.6 / ARCH-MOD-02 — persistence codec isolated from storage.
//! ORS durable codec boundary; no `Store`, `SurrealDB`, or recovery semantics.
//! Implementation: I18.7 — pure encode/decode with validation.
//! Ownership: I5/I18 — existing ORS handles; codec-only, no writer, semantic `Store`, `SurrealDB`, or recovery authority.

use std::collections::BTreeSet;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::DurableInboxRecord;
use super::DurableOperationalRecord;
use super::DurableSupervisionLeaseResult;
use super::OperationalKind;
use super::ScopeReservationHead;
use crate::AuthorityHandoffRecord;
use crate::CanonicalDisposition;
use crate::OpaqueLabel;
use crate::OperationalPhase;
use crate::OrsError;
use crate::ProcessEvidenceRecord;
use crate::ProcessStartReplayRecord;
use crate::RecoveryInboxDisposition;
use crate::RecoveryPayload;
use crate::RecoveryPayloadEnvelope;
use crate::ReservationRecord;
use crate::ReservationState;
use crate::ScopeTerminalReceipt;
use crate::SupervisionLeaseSnapshot;
use crate::SupervisionLeaseStageReceipt;
use crate::SupervisionLeaseStageResolution;
use eliot_runtime_contracts::GenerationCutoverState;

pub(super) fn encode<T: Serialize>(value: &T) -> Result<String, OrsError> {
    serde_json::to_string(value).map_err(|error| OrsError::Encoding(error.to_string()))
}

pub(super) trait PersistedValue: DeserializeOwned {
    const RECORD_TYPE: &'static str;

    fn validate_persisted(&self) -> Result<(), OrsError>;
}

impl PersistedValue for RecoveryPayloadEnvelope {
    const RECORD_TYPE: &'static str = "recovery_envelope";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for ProcessStartReplayRecord {
    const RECORD_TYPE: &'static str = "process_start_replay";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for AuthorityHandoffRecord {
    const RECORD_TYPE: &'static str = "authority_handoff";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for ProcessEvidenceRecord {
    const RECORD_TYPE: &'static str = "process_evidence";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for ScopeReservationHead {
    const RECORD_TYPE: &'static str = "scope_head";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.writer_epoch.validate()?;
        self.canonical_head.validate()?;
        if self.last_reserved_sequence < self.canonical_head.sequence
            || self.last_terminal_sequence > self.last_reserved_sequence
        {
            return Err(OrsError::OrderingHeadMismatch);
        }
        Ok(())
    }
}

impl PersistedValue for ReservationRecord {
    const RECORD_TYPE: &'static str = "reservation";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.token.writer_epoch.validate()?;
        self.token.state_fence.validate()?;
        if self.token.reservation_order == 0
            || self.token.scopes.is_empty()
            || self.token.writer_epoch.current.epoch
                != self.token.state_fence.observed_authority_epoch
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "invalid token order, scope set, or epoch fence".to_owned(),
            });
        }
        crate::model::validate_digest(
            &self.token.prepared_transition_sha256,
            "prepared_transition_sha256",
        )?;
        let mut scopes = BTreeSet::new();
        for scope in &self.token.scopes {
            scope.expected_head.validate()?;
            if scope.reserved_sequence <= scope.expected_head.sequence
                || !scopes.insert(scope.scope.clone())
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: "invalid or duplicate reserved scope".to_owned(),
                });
            }
        }
        if self.state == ReservationState::Reconciling && self.unknown_reason.is_none() {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "reconciling record has no recovery reason".to_owned(),
            });
        }
        if self.state != ReservationState::Reconciling && self.unknown_reason.is_some() {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "terminal and unknown markers conflict".to_owned(),
            });
        }
        Ok(())
    }
}

impl PersistedValue for DurableOperationalRecord {
    const RECORD_TYPE: &'static str = "operational_record";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.input.validate()?;
        if self.operation_order == 0
            || self.terminal_receipt_id.is_some() != self.terminal_receipt_sha256.is_some()
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "invalid order or partial terminal receipt binding".to_owned(),
            });
        }
        if let Some(digest) = &self.terminal_receipt_sha256 {
            crate::model::validate_digest(digest, "terminal_receipt_sha256")?;
        }
        if let Some(record) = &self.generation_cutover {
            record
                .validate()
                .map_err(|error| OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: error.to_string(),
                })?;
            let expected_record_id =
                OpaqueLabel::new(format!("generation-cutover:{}", record.cutover_id))?;
            let expected_subject = OpaqueLabel::new(record.route_scope.clone())?;
            if !matches!(
                self.kind,
                OperationalKind::GenerationTransition | OperationalKind::GenerationCutover
            ) || self.input.record_id != expected_record_id
                || self.input.subject_id != expected_subject
                || self.input.authority_epoch.current.epoch != record.old_epoch.value()
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: "generation input identity does not match typed cutover".to_owned(),
                });
            }
            if !matches!(
                &self.input.payload,
                RecoveryPayload::ImmutableLocator { locator }
                    if locator.as_str() == format!("ors:generation-cutover:{}", record.cutover_id)
            ) {
                return Err(OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: "generation input locator does not match typed cutover".to_owned(),
                });
            }
            let valid_phase = matches!(
                (self.kind, self.phase, record.state),
                (
                    OperationalKind::GenerationTransition,
                    OperationalPhase::Applying,
                    GenerationCutoverState::Armed,
                ) | (
                    OperationalKind::GenerationTransition,
                    OperationalPhase::Reconciling,
                    GenerationCutoverState::Reconciling,
                ) | (
                    OperationalKind::GenerationTransition,
                    OperationalPhase::Fenced,
                    GenerationCutoverState::FailedRequiresForwardCutover,
                ) | (
                    OperationalKind::GenerationCutover,
                    OperationalPhase::Active,
                    GenerationCutoverState::Committed,
                )
            );
            if !valid_phase {
                return Err(OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: "generation state and operational phase disagree".to_owned(),
                });
            }
        }
        Ok(())
    }
}

impl PersistedValue for DurableInboxRecord {
    const RECORD_TYPE: &'static str = "recovery_inbox";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.item.validate()?;
        if self.operation_order == 0
            || self.terminal_receipt_id.is_some() != self.terminal_receipt_sha256.is_some()
            || (self.disposition == RecoveryInboxDisposition::Imported
                && self.terminal_receipt_id.is_some())
            || (self.disposition != RecoveryInboxDisposition::Imported
                && self.terminal_receipt_id.is_none())
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "invalid inbox phase or terminal binding".to_owned(),
            });
        }
        if let Some(digest) = &self.terminal_receipt_sha256 {
            crate::model::validate_digest(digest, "inbox_terminal_receipt_sha256")?;
        }
        Ok(())
    }
}

impl PersistedValue for ScopeTerminalReceipt {
    const RECORD_TYPE: &'static str = "scope_terminal";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        crate::model::validate_digest(&self.receipt_sha256, "scope_terminal_receipt_sha256")?;
        if self.reserved_sequence == 0
            || self.gap != (self.disposition == CanonicalDisposition::Rejected)
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "invalid terminal sequence or gap disposition".to_owned(),
            });
        }
        Ok(())
    }
}

impl PersistedValue for SupervisionLeaseStageReceipt {
    const RECORD_TYPE: &'static str = "supervision_lease_staged";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for SupervisionLeaseSnapshot {
    const RECORD_TYPE: &'static str = "supervision_lease_snapshot";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for SupervisionLeaseStageResolution {
    const RECORD_TYPE: &'static str = "supervision_lease_stage_resolution";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for DurableSupervisionLeaseResult {
    const RECORD_TYPE: &'static str = "supervision_lease_result";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.ticket.validate()?;
        self.snapshot.validate()?;
        if self.snapshot.record.artifact != self.artifact {
            return Err(OrsError::SupervisionLeaseBindingMismatch);
        }
        Ok(())
    }
}

impl PersistedValue for crate::StoreRebindReplayRecord {
    const RECORD_TYPE: &'static str = "store_rebind_replay";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

pub(super) fn decode<T: PersistedValue>(value: &str) -> Result<T, OrsError> {
    decode_named(value, T::RECORD_TYPE)
}

pub(super) fn decode_named<T: PersistedValue>(
    value: &str,
    record_type: &'static str,
) -> Result<T, OrsError> {
    let decoded: T = serde_json::from_str(value).map_err(|error| OrsError::IntegrityProblem {
        record_type,
        reason: error.to_string(),
    })?;
    decoded
        .validate_persisted()
        .map_err(|error| OrsError::IntegrityProblem {
            record_type,
            reason: error.to_string(),
        })?;
    Ok(decoded)
}
