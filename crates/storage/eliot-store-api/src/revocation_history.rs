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

use crate::{StoreError, canonical_json_bytes, sha256_hex};

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
/// the revoked origin, its exact sorted affected set (origin plus dependents),
/// the terminal invalidation reason, and the durable history revision the
/// record was committed at. `current_influence` is implied `Revoked` by
/// construction: only committed revocations are recorded, so unknown or
/// partial outcomes can never appear here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordedRevocation {
    /// Stable closure identity from the recording mutation.
    pub closure_id: String,
    /// Revoked origin named by the closure.
    pub root_ref: String,
    /// Exact sorted affected references: the origin plus every dependent.
    pub dependent_refs: Vec<String>,
    /// Terminal reason the origin was invalidated.
    pub invalidation_reason: RevocationReason,
    /// Durable history revision this record was committed at.
    pub revision: u64,
}

impl RecordedRevocation {
    /// Computes the canonical digest of one exact affected-reference set.
    ///
    /// This is the single Store-contract implementation of the
    /// `affected_digest` commitment used by `RecordAuthorityRevocation`.
    /// Backends and the Governor must call this function instead of
    /// independently choosing serialization, sorting, or delimiter rules.
    /// The input must already be the strictly sorted complete set returned by
    /// the grant-closure owner; this function never silently reorders caller
    /// bytes before hashing.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the affected set is empty, contains a blank
    /// or control-bearing reference, is not strictly sorted and unique, or
    /// cannot be canonicalized.
    pub fn affected_set_digest(affected_refs: &[String]) -> Result<String, StoreError> {
        validate_affected_refs(affected_refs)?;
        let bytes = canonical_json_bytes(&affected_refs)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// Materializes one durable history record from an exact owner closure.
    ///
    /// The function closes the missing common handler step for both Store
    /// backends. It verifies the presented affected-set count and digest over
    /// the exact sorted references, requires the revoked root to occur in that
    /// set, and then constructs the typed record at the Store-assigned durable
    /// history revision. It performs no persistence and does not activate the
    /// named operations; backend handlers call it only after their existing
    /// catalogue, fence, ordering and compare-and-swap gates admit the
    /// mutation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when any identity is malformed, the history
    /// revision is zero, the affected set is empty, unsorted, duplicated or
    /// missing the root, or the presented count/digest does not bind the exact
    /// affected references.
    pub fn from_recording_parts(
        closure_id: impl Into<String>,
        root_ref: impl Into<String>,
        affected_refs: Vec<String>,
        invalidation_reason: RevocationReason,
        history_revision: u64,
        expected_affected_digest: &str,
        expected_affected_count: u64,
    ) -> Result<Self, StoreError> {
        let closure_id = closure_id.into();
        let root_ref = root_ref.into();
        validate_reference(&closure_id, "closure_id")?;
        validate_reference(&root_ref, "root_ref")?;
        validate_digest(expected_affected_digest, "affected_digest")?;
        if history_revision == 0 {
            return Err(StoreError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        if expected_affected_count == 0 {
            return Err(StoreError::InvalidField {
                field: "affected_count",
                reason: "must include at least the revoked origin",
            });
        }
        let actual_count = u64::try_from(affected_refs.len()).map_err(|_| {
            StoreError::InvalidField {
                field: "affected_count",
                reason: "affected set exceeds the wire count range",
            }
        })?;
        if actual_count != expected_affected_count {
            return Err(StoreError::InvalidField {
                field: "affected_count",
                reason: "does not bind the exact affected-reference set",
            });
        }
        validate_affected_refs(&affected_refs)?;
        if affected_refs
            .binary_search_by(|reference| reference.as_str().cmp(root_ref.as_str()))
            .is_err()
        {
            return Err(StoreError::InvalidField {
                field: "dependent_refs",
                reason: "affected set must contain the revoked origin",
            });
        }
        if Self::affected_set_digest(&affected_refs)? != expected_affected_digest {
            return Err(StoreError::InvalidField {
                field: "affected_digest",
                reason: "does not bind the exact sorted affected-reference set",
            });
        }
        let record = Self {
            closure_id,
            root_ref,
            dependent_refs: affected_refs,
            invalidation_reason,
            revision: history_revision,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates the recorded closure shape without interpreting authority.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_reference(&self.closure_id, "closure_id")?;
        validate_reference(&self.root_ref, "root_ref")?;
        validate_affected_refs(&self.dependent_refs)?;
        if self
            .dependent_refs
            .binary_search_by(|reference| reference.as_str().cmp(self.root_ref.as_str()))
            .is_err()
        {
            return Err(StoreError::InvalidField {
                field: "dependent_refs",
                reason: "recorded revocation must contain its root_ref",
            });
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

fn validate_affected_refs(affected_refs: &[String]) -> Result<(), StoreError> {
    if affected_refs.is_empty() {
        return Err(StoreError::InvalidField {
            field: "dependent_refs",
            reason: "recorded revocation must name its affected set",
        });
    }
    for reference in affected_refs {
        validate_reference(reference, "dependent_ref")?;
    }
    if affected_refs
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(StoreError::InvalidField {
            field: "dependent_refs",
            reason: "affected references must be strictly sorted and unique",
        });
    }
    Ok(())
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

fn validate_digest(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(StoreError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}
