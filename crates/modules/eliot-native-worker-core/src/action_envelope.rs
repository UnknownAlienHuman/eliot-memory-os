//! Opaque governed-action envelope carrier for declared external-adapter ops.
//!
//! Issue #1911: Kernel-authored dispatch material may carry one carrier per
//! driven operation (`register`, `claim`, `reconcile`, `start_claimed`,
//! `serve_stdio`). The carrier is MECHANICS ONLY: a bounded operation name
//! plus the opaque canonical JSON bytes of the governed action envelope. It
//! performs no admission, derives no impact, checks no authority, fence, or
//! epoch, and grants nothing — the composition root decodes the bytes through
//! its governed action gate, which owns all policy (see
//! `eliot-native-worker::governed_action`). Carrier authenticity rides the
//! surrounding material trust (Kernel session plus claim-binding validation);
//! shape validation here is a bound check so malformed presenter bytes fail
//! closed at parse time.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Maximum canonical envelope JSON bytes carried for one operation.
pub const MAX_ACTION_ENVELOPE_BYTES: usize = 16 * 1024;
/// Maximum operation name length (declared external-adapter ops are short).
pub const MAX_ACTION_ENVELOPE_OP_LEN: usize = 64;

/// Opaque carrier for one driven operation's governed action envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionEnvelopeCarrier {
    /// Declared external-adapter operation this envelope authorizes.
    pub operation: String,
    /// Canonical UTF-8 JSON text of the governed action envelope
    /// (bins `governed_action::ActionEnvelope` schema).
    pub envelope_json: String,
}

/// Fail-closed carrier shape errors (bounds only, never policy).
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ActionEnvelopeCarrierError {
    /// The operation name is blank or oversized.
    #[error("action envelope carrier operation is missing or oversized")]
    BadOperation,
    /// The envelope JSON is empty or oversized.
    #[error("action envelope carrier JSON is missing or oversized")]
    BadEnvelopeBytes,
}

impl ActionEnvelopeCarrier {
    /// Validates the carrier shape: bounded operation name and bounded
    /// non-empty envelope JSON. Performs no semantic check.
    pub fn validate_shape(&self) -> Result<(), ActionEnvelopeCarrierError> {
        if self.operation.trim().is_empty() || self.operation.len() > MAX_ACTION_ENVELOPE_OP_LEN {
            return Err(ActionEnvelopeCarrierError::BadOperation);
        }
        if self.envelope_json.is_empty() || self.envelope_json.len() > MAX_ACTION_ENVELOPE_BYTES {
            return Err(ActionEnvelopeCarrierError::BadEnvelopeBytes);
        }
        Ok(())
    }
}
