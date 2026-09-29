//! Typed, non-semantic readback for the User Broker's current ORS row.
//!
//! The encrypted operational payload remains opaque to ORS. This module only
//! exposes the current row, its phase/order, and the store-issued receipt so
//! Kernel can compare an authenticated operation with the exact durable owner
//! state before issuing or renewing a broker grant.

use serde::{Deserialize, Serialize};

use crate::{
    OperationalMutationReceipt, OperationalPhase, OperationalRecordInput, OrsError,
    UserBrokerRegistrationReceipt,
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
        if matches!(&record.payload, crate::RecoveryPayload::CanonicalRequest { .. }) {
            return Err(OrsError::InvalidField {
                field: "user_broker_payload",
                reason: "canonical requests are not User Broker records",
            });
        }
        Ok(Self(record))
    }

    /// Returns the exact opaque operational record.
    pub fn record(&self) -> &OperationalRecordInput {
        &self.0
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
