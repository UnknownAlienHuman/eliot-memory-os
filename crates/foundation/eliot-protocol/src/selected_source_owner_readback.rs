//! Data-only transport for original selected-source owner readbacks.
//!
//! This carrier is not a receipt, capability, or authority token. It contains
//! exact serialized owner values so the receiving owner can decode and
//! independently validate the original records. In particular, it never
//! carries or reconstructs ORS's sealed `ActiveAdmissionReservation`.

use crate::{
    ProtocolError, RequestIdentity, SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_ID,
    SelectedSourceCaptureInvocation,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Stable discriminator for selected-source owner readback transport.
pub const SELECTED_SOURCE_OWNER_READBACK_WIRE_ID: &str =
    "eliot.protocol.selected-source-owner-readback";
/// Version of the selected-source owner readback transport.
pub const SELECTED_SOURCE_OWNER_READBACK_WIRE_VERSION: u16 = 1;

/// Exact selected-source queue and owner readback data returned by Kernel.
///
/// The JSON projections preserve the owner-issued records and receipts but do
/// not make them trusted. Consumers must decode the original types, compare
/// them with their independently retained proposal/receipt values, and call
/// the owning validators before using the result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectedSourceOwnerReadback {
    /// Versioned transport discriminator.
    pub wire_id: String,
    /// Versioned transport contract.
    pub wire_version: u16,
    /// Exact authenticated request identity retained by Kernel's queue.
    pub request_identity: RequestIdentity,
    /// Exact closed selected-source operation/path/selector retained by Kernel.
    pub invocation: SelectedSourceCaptureInvocation,
    /// Exact typed ProposedAttempt returned by the canonical owner.
    pub proposed_attempt_record: Value,
    /// Exact canonical recovery row containing the ProposedAttempt bytes.
    pub proposed_attempt_recovery_record: Value,
    /// Exact original canonical Store `WriteReceipt`.
    pub canonical_write_receipt: Value,
    /// Exact original canonical causal receipt projection.
    pub canonical_causal_write_receipt: Value,
    /// Exact current ORS admission-reservation record.
    pub admission_reservation_record: Value,
    /// Exact current ORS store-issued mutation receipt for that record.
    pub admission_reservation_receipt: Value,
    /// Current Kernel-observed authority epoch lineage.
    pub observed_authority_epoch: Value,
    /// Current Kernel-observed ORS State Fence snapshot.
    pub observed_state_fence: Value,
    /// Kernel clock sample taken immediately before its launch-prerequisite check.
    pub observed_at_unix_ms: i64,
}

impl SelectedSourceOwnerReadback {
    /// Packages original owner values without deriving a new digest or receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn from_owner_readback(
        request_identity: RequestIdentity,
        invocation: SelectedSourceCaptureInvocation,
        proposed_attempt_record: Value,
        proposed_attempt_recovery_record: Value,
        canonical_write_receipt: Value,
        canonical_causal_write_receipt: Value,
        admission_reservation_record: Value,
        admission_reservation_receipt: Value,
        observed_authority_epoch: Value,
        observed_state_fence: Value,
        observed_at_unix_ms: i64,
    ) -> Result<Self, ProtocolError> {
        let readback = Self {
            wire_id: SELECTED_SOURCE_OWNER_READBACK_WIRE_ID.to_owned(),
            wire_version: SELECTED_SOURCE_OWNER_READBACK_WIRE_VERSION,
            request_identity,
            invocation,
            proposed_attempt_record,
            proposed_attempt_recovery_record,
            canonical_write_receipt,
            canonical_causal_write_receipt,
            admission_reservation_record,
            admission_reservation_receipt,
            observed_authority_epoch,
            observed_state_fence,
            observed_at_unix_ms,
        };
        readback.validate()?;
        Ok(readback)
    }

    /// Validates transport shape only; this does not authenticate owner data.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != SELECTED_SOURCE_OWNER_READBACK_WIRE_ID
            || self.wire_version != SELECTED_SOURCE_OWNER_READBACK_WIRE_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "selected_source_owner_readback.wire",
                reason: "unsupported selected-source owner readback version",
            });
        }
        self.request_identity.validate()?;
        self.invocation.validate()?;
        if self.observed_at_unix_ms <= 0 {
            return Err(ProtocolError::InvalidField {
                field: "selected_source_owner_readback.observed_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        for (value, field) in [
            (
                &self.proposed_attempt_record,
                "selected_source_owner_readback.proposed_attempt_record",
            ),
            (
                &self.proposed_attempt_recovery_record,
                "selected_source_owner_readback.proposed_attempt_recovery_record",
            ),
            (
                &self.canonical_write_receipt,
                "selected_source_owner_readback.canonical_write_receipt",
            ),
            (
                &self.canonical_causal_write_receipt,
                "selected_source_owner_readback.canonical_causal_write_receipt",
            ),
            (
                &self.admission_reservation_record,
                "selected_source_owner_readback.admission_reservation_record",
            ),
            (
                &self.admission_reservation_receipt,
                "selected_source_owner_readback.admission_reservation_receipt",
            ),
            (
                &self.observed_authority_epoch,
                "selected_source_owner_readback.observed_authority_epoch",
            ),
            (
                &self.observed_state_fence,
                "selected_source_owner_readback.observed_state_fence",
            ),
        ] {
            if !value.is_object() {
                return Err(ProtocolError::InvalidField {
                    field,
                    reason: "must carry the original owner object",
                });
            }
        }
        if self.invocation.wire_id != SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_ID {
            return Err(ProtocolError::InvalidField {
                field: "selected_source_owner_readback.invocation",
                reason: "must preserve the original selected-source invocation",
            });
        }
        Ok(())
    }
}
