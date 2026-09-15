//! Durable authority-revocation-history wire contract (issue #686).
//!
//! The Governor records committed influence revocations through the
//! `RecordAuthorityRevocation` named mutation and serves the CURRENT
//! revocation history through the `GetAuthorityRevocationHistory` named
//! read. Both operations are known-but-unsupported until a store-owned
//! slice activates their catalogue rows with proven handlers: the typed
//! parameter contracts and this payload shape are already closed so the
//! Governor decision edge (envelope construction, evidence decoding) is
//! exact before activation.
//!
//! The read payload carries only actually recorded revocations under the
//! exact response fence — never a synthesized default. An empty `closures`
//! array with a nonzero `source_revision` is the source explicitly
//! attesting zero revocations; a missing history is not representable here
//! and refuses upstream, never as an empty closure.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use eliot_security_contracts::RevocationReason;

use crate::StoreError;

/// Version of the revocation-history payload shape served by the named read.
///
/// Consumers match on this version before interpreting `closures`; any
/// shape change bumps it on every side, mirroring
/// `EVIDENCE_PACK_PAYLOAD_VERSION`.
pub const REVOCATION_HISTORY_PAYLOAD_VERSION: u32 = 1;

/// Maximum revocation closures one history read may return.
///
/// The bound is explicit per request (`max_records` decimal-string
/// selector) and every handler refuses an over-bound request with
/// [`StoreError::PayloadTooLarge`] instead of returning a successful
/// over-bound view. 32 keeps the worst case far below
/// [`READ_MAX_OUTPUT_BYTES`](crate::operation_catalogue::READ_MAX_OUTPUT_BYTES):
/// each closure carries short stable references plus fixed provenance.
pub const REVOCATION_HISTORY_MAX_RECORDS: u32 = 32;

/// One durably recorded revocation served by the history read.
///
/// This is the recorded form of one `eliot-influence` revocation closure:
/// the revoked origin, its exact affected set (origin plus dependents, in
/// affected order), the terminal invalidation reason, and the durable
/// history revision the record was committed at. `current_influence` is
/// implied `Revoked` by construction: only committed revocations are
/// recorded, so unknown or partial outcomes can never appear here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordedRevocation {
    /// Stable closure identity from the recording mutation.
    pub closure_id: String,
    /// Revoked origin named by the closure.
    pub root_ref: String,
    /// Exact affected references: the origin plus every dependent.
    pub dependent_refs: Vec<String>,
    /// Terminal reason the origin was invalidated.
    pub invalidation_reason: RevocationReason,
    /// Durable history revision this record was committed at.
    pub revision: u64,
}

impl RecordedRevocation {
    /// Validates the recorded closure shape without interpreting authority.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_reference(&self.closure_id, "closure_id")?;
        validate_reference(&self.root_ref, "root_ref")?;
        if self.dependent_refs.is_empty() {
            return Err(StoreError::InvalidField {
                field: "dependent_refs",
                reason: "recorded revocation must name its dependents",
            });
        }
        for dependent in &self.dependent_refs {
            validate_reference(dependent, "dependent_ref")?;
        }
        if self.revision == 0 {
            return Err(StoreError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// Versioned exact revocation-history payload for one read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationHistoryPayload {
    /// Payload shape version (see [`REVOCATION_HISTORY_PAYLOAD_VERSION`]).
    pub version: u32,
    /// Exact origin selector echoed from the request.
    pub origin_ref: String,
    /// Durable history revision this view is current at.
    pub source_revision: u64,
    /// Recorded revocation closures affecting the origin, in closure order.
    pub closures: Vec<RecordedRevocation>,
}

impl RevocationHistoryPayload {
    /// Validates the complete history view before it is consumed.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.version != REVOCATION_HISTORY_PAYLOAD_VERSION {
            return Err(StoreError::InvalidField {
                field: "version",
                reason: "unsupported revocation-history payload version",
            });
        }
        validate_reference(&self.origin_ref, "origin_ref")?;
        if self.source_revision == 0 {
            return Err(StoreError::InvalidField {
                field: "source_revision",
                reason: "must be non-zero",
            });
        }
        let mut previous: Option<&str> = None;
        for closure in &self.closures {
            closure.validate()?;
            if let Some(previous) = previous
                && previous >= closure.closure_id.as_str()
            {
                return Err(StoreError::InvalidField {
                    field: "closures",
                    reason: "must arrive in strictly increasing closure_id order",
                });
            }
            previous = Some(closure.closure_id.as_str());
        }
        Ok(())
    }
}

/// Parses and validates one revocation-history payload value.
///
/// Rejects a wrong-version, malformed, unordered, or unknown-field payload
/// fail-closed instead of serving a lossy history view.
pub fn parse_revocation_history_payload(
    payload: &Value,
) -> Result<RevocationHistoryPayload, StoreError> {
    let parsed: RevocationHistoryPayload =
        serde_json::from_value(payload.clone()).map_err(|_| StoreError::InvalidField {
            field: "payload",
            reason: "revocation-history payload is malformed",
        })?;
    parsed.validate()?;
    Ok(parsed)
}

fn validate_reference(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field,
            reason: "revocation reference must be a non-blank string",
        });
    }
    Ok(())
}
