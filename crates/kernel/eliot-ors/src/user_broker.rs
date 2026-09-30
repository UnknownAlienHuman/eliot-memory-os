//! Typed, non-semantic readback for the User Broker's current ORS row.
//!
//! The encrypted operational payload remains opaque to ORS. This module only
//! exposes the current row, its phase/order, and the store-issued receipt so
//! Kernel can compare an authenticated operation with the exact durable owner
//! state before issuing or renewing a broker grant.

use serde::{Deserialize, Serialize};

use crate::{
    OperationalMutationReceipt, OperationalPhase, OperationalRecordInput, OrsError,
    UserBrokerRegistrationReceipt, UserBrokerResourceSelection, UserBrokerResourceSelectionReceipt,
};

/// An opaque heartbeat renewal payload for a User Broker registration.
///
/// The payload must be encrypted or an immutable locator, as required by
/// [`OperationalRecordInput`]. ORS does not decode or interpret its contents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserBrokerHeartbeat(OperationalRecordInput);

impl UserBrokerHeartbeat {
    /// Creates a heartbeat write from a validated opaque operational record.
    pub fn new(record: OperationalRecordInput) -> Result<Self, OrsError> {
        record.validate()?;
        if matches!(
            &record.payload,
            crate::RecoveryPayload::CanonicalRequest { .. }
        ) {
            return Err(OrsError::InvalidField {
                field: "user_broker_payload",
                reason: "canonical requests are not User Broker records",
            });
        }
        Ok(Self(record))
    }

    pub(crate) fn into_record(self) -> OperationalRecordInput {
        self.0
    }
}

/// Read-only view of the single current User Broker operational row.
///
/// The payload is an encrypted envelope or immutable locator, never a
/// decoded registration. The receipt is recomputed from the exact persisted
/// row before this view is returned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UserBrokerRegistrationSnapshot {
    record: OperationalRecordInput,
    phase: OperationalPhase,
    operation_order: u64,
    receipt: UserBrokerRegistrationReceipt,
}

impl UserBrokerRegistrationSnapshot {
    pub(crate) fn from_store(
        record: OperationalRecordInput,
        phase: OperationalPhase,
        operation_order: u64,
        receipt: OperationalMutationReceipt,
    ) -> Result<Self, OrsError> {
        record.validate()?;
        if operation_order == 0
            || receipt.record_id() != &record.record_id
            || receipt.subject_id() != &record.subject_id
            || receipt.operation_order() != operation_order
            || receipt.phase() != phase
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "user_broker_registration",
                reason: "snapshot fields do not match the store-issued receipt".to_owned(),
            });
        }
        Ok(Self {
            record,
            phase,
            operation_order,
            receipt: UserBrokerRegistrationReceipt::from_receipt(receipt),
        })
    }

    /// Returns the exact opaque operational input read from ORS.
    pub const fn record(&self) -> &OperationalRecordInput {
        &self.record
    }

    /// Returns the non-semantic ORS lifecycle phase.
    pub const fn phase(&self) -> OperationalPhase {
        self.phase
    }

    /// Returns the store-assigned order of this current row.
    pub const fn operation_order(&self) -> u64 {
        self.operation_order
    }

    /// Returns the integrity-bound receipt for this exact current row.
    pub const fn receipt(&self) -> &UserBrokerRegistrationReceipt {
        &self.receipt
    }
}

/// Read-only ORS evidence for one exact Kernel-issued native resource
/// selection. The typed selection and its expiry ceilings are validated on
/// both write and readback; the receipt binds the store's exact record and
/// subject identities, lifecycle phase, and operation order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UserBrokerResourceSelectionSnapshot {
    record: UserBrokerResourceSelection,
    phase: OperationalPhase,
    operation_order: u64,
    receipt: UserBrokerResourceSelectionReceipt,
}

impl UserBrokerResourceSelectionSnapshot {
    pub(crate) fn from_store(
        record: UserBrokerResourceSelection,
        phase: OperationalPhase,
        operation_order: u64,
        receipt: OperationalMutationReceipt,
    ) -> Result<Self, OrsError> {
        record.validate()?;
        let expected_record_id = record.record_id()?;
        let expected_subject_id = record.subject_id()?;
        if !matches!(phase, OperationalPhase::Active | OperationalPhase::Fenced)
            || operation_order == 0
            || receipt.record_id() != &expected_record_id
            || receipt.subject_id() != &expected_subject_id
            || receipt.operation_order() != operation_order
            || receipt.phase() != phase
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "user_broker_resource_selection",
                reason:
                    "snapshot selection identity, phase, order, or store-issued receipt mismatch"
                        .to_owned(),
            });
        }
        Ok(Self {
            record,
            phase,
            operation_order,
            receipt: UserBrokerResourceSelectionReceipt::from_receipt(receipt),
        })
    }

    /// Returns the exact typed selection and its grant expiry limits read from
    /// the durable owner.
    pub const fn record(&self) -> &UserBrokerResourceSelection {
        &self.record
    }

    /// Returns the non-semantic ORS lifecycle phase.
    pub const fn phase(&self) -> OperationalPhase {
        self.phase
    }

    /// Returns the store-assigned order of this current row.
    pub const fn operation_order(&self) -> u64 {
        self.operation_order
    }

    /// Returns the integrity-bound receipt for this exact selection row.
    pub const fn receipt(&self) -> &UserBrokerResourceSelectionReceipt {
        &self.receipt
    }
}
