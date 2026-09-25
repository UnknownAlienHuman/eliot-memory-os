//! Import-only decoder for the retired v1 activation decision wire.
//!
//! This module is intentionally not re-exported at the protocol crate root.
//! It exists for archival/migration tooling that must inspect historical v1
//! bytes. Production daemon and Kernel paths must use the closed v2 envelope
//! and must never call this decoder as a fallback.

use eliot_contracts::{StateFence, canonical_json_bytes};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AgentActivationResolutionTicket, ProtocolError};

/// Historical v1 wire identity.
pub const AGENT_ACTIVATION_RESOLUTION_DECISION_WIRE_ID: &str =
    "eliot.protocol.agent-activation-resolution-decision";
/// Historical v1 wire version.
pub const AGENT_ACTIVATION_RESOLUTION_DECISION_WIRE_VERSION: u16 = 1;
const MAX_V1_TEXT_BYTES: usize = 512;

fn bounded_text(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be non-blank bounded text without control characters",
        });
    }
    if value.len() > MAX_V1_TEXT_BYTES {
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

/// Immutable historical v1 decision retained as an import artifact.
///
/// The type is namespaced under this module on purpose. It is not a v2
/// production result and has no `From` conversion into
/// `AgentActivationResolutionResult`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationResolutionDecision {
    pub wire_id: String,
    pub wire_version: u16,
    pub ticket_id: String,
    pub ticket_sha256: String,
    pub state_fence: StateFence,
    pub principal_id: String,
    pub session_id: String,
    pub task_id: String,
    pub work_unit_id: String,
    pub work_scope_id: String,
    pub task_revision: String,
    pub plan_id: String,
    pub plan_revision: String,
    pub decision_sha256: String,
}

impl AgentActivationResolutionDecision {
    pub const CONTRACT_VERSION: u16 = AGENT_ACTIVATION_RESOLUTION_DECISION_WIRE_VERSION;

    fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut unsigned = self.clone();
        unsigned.decision_sha256.clear();
        canonical_json_bytes(&unsigned).map_err(|error| ProtocolError::Json(error.to_string()))
    }

    fn compute_digest(&self) -> Result<String, ProtocolError> {
        Ok(eliot_contracts::sha256_hex(
            &self.canonical_unsigned_bytes()?,
        ))
    }

    /// Validates the historical wire shape and its self digest.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != AGENT_ACTIVATION_RESOLUTION_DECISION_WIRE_ID
            || self.wire_version != Self::CONTRACT_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_decision.wire",
                reason: "unsupported historical activation decision",
            });
        }
        bounded_text(
            &self.ticket_id,
            "agent_activation_resolution_decision.ticket_id",
        )?;
        lowercase_sha256(
            &self.ticket_sha256,
            "agent_activation_resolution_decision.ticket_sha256",
        )?;
        self.state_fence
            .validate()
            .map_err(ProtocolError::Foundation)?;
        for (value, field) in [
            (
                self.principal_id.as_str(),
                "agent_activation_resolution_decision.principal_id",
            ),
            (
                self.session_id.as_str(),
                "agent_activation_resolution_decision.session_id",
            ),
            (
                self.task_id.as_str(),
                "agent_activation_resolution_decision.task_id",
            ),
            (
                self.work_unit_id.as_str(),
                "agent_activation_resolution_decision.work_unit_id",
            ),
            (
                self.work_scope_id.as_str(),
                "agent_activation_resolution_decision.work_scope_id",
            ),
            (
                self.task_revision.as_str(),
                "agent_activation_resolution_decision.task_revision",
            ),
            (
                self.plan_id.as_str(),
                "agent_activation_resolution_decision.plan_id",
            ),
            (
                self.plan_revision.as_str(),
                "agent_activation_resolution_decision.plan_revision",
            ),
        ] {
            bounded_text(value, field)?;
        }
        lowercase_sha256(
            &self.decision_sha256,
            "agent_activation_resolution_decision.decision_sha256",
        )?;
        if self.decision_sha256 != self.compute_digest()? {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_decision.decision_sha256",
                reason: "historical decision digest mismatch",
            });
        }
        Ok(())
    }

    /// Binds the imported artifact to an exact current ticket identity.
    pub fn validate_against(
        &self,
        ticket: &AgentActivationResolutionTicket,
    ) -> Result<(), ProtocolError> {
        self.validate()?;
        ticket.validate()?;
        if self.ticket_id != ticket.ticket_id
            || self.ticket_sha256 != ticket.ticket_sha256
            || self.state_fence != ticket.state_fence
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_decision.binding",
                reason: "must bind the exact historical ticket identity",
            });
        }
        Ok(())
    }
}

/// Decodes historical v1 bytes only for an explicit import/migration tool.
///
/// The decoder is closed, validates the old digest, and returns an immutable
/// artifact. It never returns a v2 result and has no production fallback path.
pub fn decode_activation_resolution_v1_import(
    bytes: &[u8],
) -> Result<AgentActivationResolutionDecision, ProtocolError> {
    let decision: AgentActivationResolutionDecision =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidField {
            field: "agent_activation_resolution_decision",
            reason: "does not decode as the closed historical v1 shape",
        })?;
    decision.validate()?;
    Ok(decision)
}

/// Explicitly named alias for callers that want the historical type in an
/// import namespace. The root protocol API intentionally does not export it.
pub fn decode_agent_activation_resolution_decision_v1(
    bytes: &[u8],
) -> Result<AgentActivationResolutionDecision, ProtocolError> {
    decode_activation_resolution_v1_import(bytes)
}
