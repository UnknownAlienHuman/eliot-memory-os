//! Protocol-owned invalid-ticket terminal artifact (issue #202, owner decision ii).
//!
//! When the daemon claim arm receives ticket bytes that fail closed validation,
//! the ticket cannot bind a digest-bound
//! [`AgentActivationResolutionResult`](crate::AgentActivationResolutionResult):
//! constructing one requires a validated ticket identity, digest, and fence.
//! This additive v1 contract is the terminal artifact for exactly that case.
//!
//! Authority boundaries (admission gating only, materiality stays upstream):
//!
//! * the artifact preserves the raw ticket bytes verbatim plus the best-effort
//!   ticket identity, so the Kernel can attribute the rejection;
//! * it is callable pre-Governor: construction takes only the claimed bytes, a
//!   bounded validation-failure reason, and an observation clock. It never
//!   reads the Governor and takes no Governor handle;
//! * it never constructs a digest-bound result from the invalid ticket and
//!   carries no retry directive: `is_terminal` always holds, so holders must
//!   idle the flight and continue the loop instead of retrying the rejected
//!   revision;
//! * it is a separate type with its own wire identity, not a digest-bound
//!   result: it structurally cannot decode as (or encode into) an
//!   `AgentActivationResolutionResult`.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{MAX_FRAME_BYTES, ProtocolError};

/// Stable wire identity for a protocol-owned invalid-ticket terminal artifact.
pub const AGENT_ACTIVATION_INVALID_TICKET_WIRE_ID: &str =
    "eliot.protocol.agent-activation-invalid-ticket";
/// Current invalid-ticket terminal artifact contract version.
pub const AGENT_ACTIVATION_INVALID_TICKET_WIRE_VERSION: u16 = 1;
/// Hard maximum for preserved raw ticket bytes (the EBP frame bound).
pub const MAX_INVALID_TICKET_BYTES: usize = MAX_FRAME_BYTES;
const MAX_INVALID_TICKET_TEXT_BYTES: usize = 512;
/// Fallback identity when the raw bytes carry no extractable ticket identity.
pub const UNKNOWN_INVALID_TICKET_ID: &str = "unknown";

fn bounded_text(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.trim() != value {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be non-blank without surrounding whitespace",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > MAX_INVALID_TICKET_TEXT_BYTES {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "exceeds the bounded wire length",
        });
    }
    Ok(())
}

fn lowercase_sha256(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

/// Best-effort ticket identity extraction from untrusted raw bytes.
///
/// Returns the `ticket_id` string carried by the bytes verbatim when it is
/// present and non-empty, else [`UNKNOWN_INVALID_TICKET_ID`]. The raw bytes
/// are always preserved verbatim regardless of the outcome.
fn extract_ticket_id(ticket_bytes: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(ticket_bytes)
        .ok()
        .and_then(|value| {
            value
                .get("ticket_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .filter(|candidate| !candidate.is_empty())
        .unwrap_or_else(|| UNKNOWN_INVALID_TICKET_ID.to_owned())
}

/// Protocol-owned terminal artifact for one invalid activation ticket.
///
/// This is admission gating only: it records that the claimed bytes failed
/// closed validation before any Governor read. It issues no Session, fence,
/// capability, or effect authority, binds no semantic digest, and schedules
/// no retry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationInvalidTicket {
    /// Terminal artifact wire identity.
    pub wire_id: String,
    /// Terminal artifact wire version.
    pub wire_version: u16,
    /// Best-effort ticket identity (`unknown` when the bytes carry none).
    pub ticket_id: String,
    /// Raw claimed ticket bytes preserved verbatim.
    pub ticket_bytes: Vec<u8>,
    /// Lowercase SHA-256 over the exact preserved `ticket_bytes`.
    pub ticket_bytes_sha256: String,
    /// Bounded validation-failure reason (never a semantic digest).
    pub reason: String,
    /// Observation clock in Unix milliseconds.
    pub observed_at_unix_ms: u64,
    /// Lowercase SHA-256 over every artifact field except this field.
    pub terminal_sha256: String,
}

impl AgentActivationInvalidTicket {
    /// Current terminal artifact contract version.
    pub const CONTRACT_VERSION: u16 = AGENT_ACTIVATION_INVALID_TICKET_WIRE_VERSION;

    /// Records one invalid ticket as terminal, pre-Governor.
    ///
    /// Takes only the claimed bytes, a bounded validation-failure reason, and
    /// the observation clock. No Governor handle is taken or read, no
    /// digest-bound result is constructed, and no retry is scheduled.
    pub fn rejected(
        ticket_bytes: Vec<u8>,
        reason: impl Into<String>,
        observed_at_unix_ms: u64,
    ) -> Result<Self, ProtocolError> {
        const BYTES_FIELD: &str = "agent_activation_invalid_ticket.ticket_bytes";
        if ticket_bytes.is_empty() {
            return Err(ProtocolError::InvalidField {
                field: BYTES_FIELD,
                reason: "must preserve at least one claimed ticket byte",
            });
        }
        if ticket_bytes.len() > MAX_INVALID_TICKET_BYTES {
            return Err(ProtocolError::OversizeFrame {
                actual: ticket_bytes.len(),
                maximum: MAX_INVALID_TICKET_BYTES,
            });
        }
        let reason = reason.into();
        bounded_text(&reason, "agent_activation_invalid_ticket.reason")?;
        if observed_at_unix_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_invalid_ticket.observed_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        let artifact = Self {
            wire_id: AGENT_ACTIVATION_INVALID_TICKET_WIRE_ID.to_owned(),
            wire_version: Self::CONTRACT_VERSION,
            ticket_id: extract_ticket_id(&ticket_bytes),
            ticket_bytes_sha256: sha256_hex(&ticket_bytes),
            ticket_bytes,
            reason,
            observed_at_unix_ms,
            terminal_sha256: String::new(),
        }
        .with_computed_digest()?;
        artifact.validate()?;
        Ok(artifact)
    }

    /// Returns canonical bytes covered by `terminal_sha256`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut unsigned = self.clone();
        unsigned.terminal_sha256.clear();
        canonical_json_bytes(&unsigned).map_err(|error| ProtocolError::Json(error.to_string()))
    }

    /// Computes the canonical terminal artifact digest.
    pub fn compute_digest(&self) -> Result<String, ProtocolError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical terminal artifact digest.
    pub fn with_computed_digest(mut self) -> Result<Self, ProtocolError> {
        self.terminal_sha256 = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the closed terminal shape without reading any Governor.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != AGENT_ACTIVATION_INVALID_TICKET_WIRE_ID
            || self.wire_version != Self::CONTRACT_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_invalid_ticket.wire",
                reason: "unsupported invalid-ticket terminal artifact",
            });
        }
        if self.ticket_id.is_empty() {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_invalid_ticket.ticket_id",
                reason: "must carry the preserved ticket identity",
            });
        }
        if self.ticket_bytes.is_empty() {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_invalid_ticket.ticket_bytes",
                reason: "must preserve at least one claimed ticket byte",
            });
        }
        if self.ticket_bytes.len() > MAX_INVALID_TICKET_BYTES {
            return Err(ProtocolError::OversizeFrame {
                actual: self.ticket_bytes.len(),
                maximum: MAX_INVALID_TICKET_BYTES,
            });
        }
        lowercase_sha256(
            &self.ticket_bytes_sha256,
            "agent_activation_invalid_ticket.ticket_bytes_sha256",
        )?;
        if self.ticket_bytes_sha256 != sha256_hex(&self.ticket_bytes) {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_invalid_ticket.ticket_bytes_sha256",
                reason: "raw ticket bytes digest mismatch",
            });
        }
        bounded_text(&self.reason, "agent_activation_invalid_ticket.reason")?;
        if self.observed_at_unix_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_invalid_ticket.observed_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        lowercase_sha256(
            &self.terminal_sha256,
            "agent_activation_invalid_ticket.terminal_sha256",
        )?;
        if self.terminal_sha256 != self.compute_digest()? {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_invalid_ticket.terminal_sha256",
                reason: "terminal digest mismatch",
            });
        }
        Ok(())
    }

    /// Terminality marker: an invalid ticket is never retried.
    ///
    /// Always true. The artifact carries no retry directive and no
    /// digest-bound result, so holders must idle the flight and continue the
    /// loop instead of retrying the rejected revision.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        true
    }
}
