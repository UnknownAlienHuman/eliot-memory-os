//! Typed semantic-resolution results for agent activation.
//!
//! This additive v2 contract represents one exact semantic result for one
//! Kernel-owned activation ticket. It creates no Session, capability, nonce,
//! effect authority, or hidden retry loop. The older
//! `AgentActivationResolutionDecision` remains a success-only compatibility
//! surface until parent issue #66 migrates every consumer.

use std::collections::BTreeSet;

use eliot_contracts::{StateFence, canonical_json_bytes};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AgentActivationResolutionTicket, ProtocolError};

pub const AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_ID: &str =
    "eliot.protocol.agent-activation-resolution-result";
pub const AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_VERSION: u16 = 2;
pub const MAX_AGENT_ACTIVATION_CANDIDATES: usize = 32;
const MAX_ACTIVATION_RESULT_TEXT_BYTES: usize = 512;

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
    if value.len() > MAX_ACTIVATION_RESULT_TEXT_BYTES {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationResolvedBinding {
    pub principal_id: String,
    pub session_id: String,
    pub task_id: String,
    pub work_unit_id: String,
    pub work_scope_id: String,
    pub task_revision: String,
    pub plan_id: String,
    pub plan_revision: String,
}

impl AgentActivationResolvedBinding {
    fn validate(&self) -> Result<(), ProtocolError> {
        for (value, field) in [
            (
                self.principal_id.as_str(),
                "agent_activation_resolution_result.principal_id",
            ),
            (
                self.session_id.as_str(),
                "agent_activation_resolution_result.session_id",
            ),
            (
                self.task_id.as_str(),
                "agent_activation_resolution_result.task_id",
            ),
            (
                self.work_unit_id.as_str(),
                "agent_activation_resolution_result.work_unit_id",
            ),
            (
                self.work_scope_id.as_str(),
                "agent_activation_resolution_result.work_scope_id",
            ),
            (
                self.task_revision.as_str(),
                "agent_activation_resolution_result.task_revision",
            ),
            (
                self.plan_id.as_str(),
                "agent_activation_resolution_result.plan_id",
            ),
            (
                self.plan_revision.as_str(),
                "agent_activation_resolution_result.plan_revision",
            ),
        ] {
            bounded_text(value, field)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentActivationCandidateCoverage {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationSelectionDirective {
    pub candidate_handles: Vec<String>,
    pub candidate_coverage: AgentActivationCandidateCoverage,
    pub recovery_handle: String,
}

impl AgentActivationSelectionDirective {
    fn validate_common(&self, field: &'static str) -> Result<(), ProtocolError> {
        if self.candidate_handles.len() > MAX_AGENT_ACTIVATION_CANDIDATES {
            return Err(ProtocolError::InvalidField {
                field,
                reason: "exceeds the bounded candidate count",
            });
        }
        let mut seen = BTreeSet::new();
        for candidate in &self.candidate_handles {
            bounded_text(candidate, field)?;
            if !seen.insert(candidate) {
                return Err(ProtocolError::InvalidField {
                    field,
                    reason: "must not contain duplicate candidate handles",
                });
            }
        }
        match self.candidate_coverage {
            AgentActivationCandidateCoverage::Partial if self.candidate_handles.is_empty() => {
                return Err(ProtocolError::InvalidField {
                    field,
                    reason: "PARTIAL coverage requires at least one known candidate",
                });
            }
            AgentActivationCandidateCoverage::Unknown if !self.candidate_handles.is_empty() => {
                return Err(ProtocolError::InvalidField {
                    field,
                    reason: "UNKNOWN coverage cannot claim exact candidate handles",
                });
            }
            _ => {}
        }
        bounded_text(
            &self.recovery_handle,
            "agent_activation_resolution_result.recovery_handle",
        )
    }

    fn validate_task_selection(&self) -> Result<(), ProtocolError> {
        self.validate_common("agent_activation_resolution_result.task_candidate_handles")
    }

    fn validate_scope_selection(&self) -> Result<(), ProtocolError> {
        self.validate_common("agent_activation_resolution_result.scope_candidate_handles")
    }

    fn validate_scope_ambiguity(&self) -> Result<(), ProtocolError> {
        self.validate_scope_selection()?;
        if self.candidate_handles.len() < 2
            || self.candidate_coverage == AgentActivationCandidateCoverage::Unknown
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.scope_candidate_handles",
                reason: "SCOPE_AMBIGUOUS requires at least two exact candidates",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationRetryDirective {
    pub dependency_ref: String,
    pub observed_dependency_revision: String,
    pub not_before_unix_ms: u64,
}

impl AgentActivationRetryDirective {
    fn validate(&self) -> Result<(), ProtocolError> {
        bounded_text(
            &self.dependency_ref,
            "agent_activation_resolution_result.retry.dependency_ref",
        )?;
        bounded_text(
            &self.observed_dependency_revision,
            "agent_activation_resolution_result.retry.observed_dependency_revision",
        )?;
        if self.not_before_unix_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.retry.not_before_unix_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }

    fn validate_window(
        &self,
        resolved_at_unix_ms: u64,
        ticket_deadline_unix_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.validate()?;
        if self.not_before_unix_ms <= resolved_at_unix_ms {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.retry.not_before_unix_ms",
                reason: "must be later than semantic result observation",
            });
        }
        if self.not_before_unix_ms >= ticket_deadline_unix_ms {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.retry.not_before_unix_ms",
                reason: "must be earlier than the Kernel ticket deadline",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum AgentActivationResolutionDisposition {
    Resolved {
        binding: Box<AgentActivationResolvedBinding>,
    },
    TaskSelectionRequired {
        selection: AgentActivationSelectionDirective,
    },
    ScopeSelectionRequired {
        selection: AgentActivationSelectionDirective,
    },
    ScopeAmbiguous {
        selection: AgentActivationSelectionDirective,
    },
    NotReady {
        recovery_handle: String,
        retry: AgentActivationRetryDirective,
    },
    StaleFence {
        recovery_handle: String,
        observed_state_fence: Option<StateFence>,
    },
    FailedInternal {
        failure_handle: String,
    },
}

impl AgentActivationResolutionDisposition {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Resolved { binding } => binding.validate(),
            Self::TaskSelectionRequired { selection } => selection.validate_task_selection(),
            Self::ScopeSelectionRequired { selection } => selection.validate_scope_selection(),
            Self::ScopeAmbiguous { selection } => selection.validate_scope_ambiguity(),
            Self::NotReady {
                recovery_handle,
                retry,
            } => {
                bounded_text(
                    recovery_handle,
                    "agent_activation_resolution_result.recovery_handle",
                )?;
                retry.validate()
            }
            Self::StaleFence {
                recovery_handle,
                observed_state_fence,
            } => {
                bounded_text(
                    recovery_handle,
                    "agent_activation_resolution_result.recovery_handle",
                )?;
                if let Some(fence) = observed_state_fence {
                    fence.validate().map_err(ProtocolError::Foundation)?;
                }
                Ok(())
            }
            Self::FailedInternal { failure_handle } => bounded_text(
                failure_handle,
                "agent_activation_resolution_result.failure_handle",
            ),
        }
    }

    fn validate_against(
        &self,
        ticket: &AgentActivationResolutionTicket,
        resolved_at_unix_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.validate()?;
        match self {
            Self::NotReady { retry, .. } => {
                retry.validate_window(resolved_at_unix_ms, ticket.kernel_deadline_unix_ms)
            }
            Self::StaleFence {
                observed_state_fence: Some(observed),
                ..
            } if observed == &ticket.state_fence => Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.observed_state_fence",
                reason: "must differ from the ticket fence when supplied",
            }),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationResolutionResult {
    pub wire_id: String,
    pub wire_version: u16,
    pub ticket_id: String,
    pub ticket_sha256: String,
    pub ticket_state_fence: StateFence,
    pub resolved_at_unix_ms: u64,
    pub disposition: AgentActivationResolutionDisposition,
    pub result_sha256: String,
}

impl AgentActivationResolutionResult {
    pub const CONTRACT_VERSION: u16 = AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_VERSION;

    pub fn new(
        ticket: &AgentActivationResolutionTicket,
        resolved_at_unix_ms: u64,
        disposition: AgentActivationResolutionDisposition,
    ) -> Result<Self, ProtocolError> {
        ticket.validate()?;
        if resolved_at_unix_ms == 0 || resolved_at_unix_ms >= ticket.kernel_deadline_unix_ms {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.resolved_at_unix_ms",
                reason: "must be non-zero and earlier than the Kernel ticket deadline",
            });
        }
        let result = Self {
            wire_id: AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_ID.to_owned(),
            wire_version: Self::CONTRACT_VERSION,
            ticket_id: ticket.ticket_id.clone(),
            ticket_sha256: ticket.ticket_sha256.clone(),
            ticket_state_fence: ticket.state_fence.clone(),
            resolved_at_unix_ms,
            disposition,
            result_sha256: String::new(),
        }
        .with_computed_digest()?;
        result.validate_against(ticket)?;
        Ok(result)
    }

    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut unsigned = self.clone();
        unsigned.result_sha256.clear();
        canonical_json_bytes(&unsigned).map_err(|error| ProtocolError::Json(error.to_string()))
    }

    pub fn compute_digest(&self) -> Result<String, ProtocolError> {
        Ok(eliot_contracts::sha256_hex(
            &self.canonical_unsigned_bytes()?,
        ))
    }

    pub fn with_computed_digest(mut self) -> Result<Self, ProtocolError> {
        self.result_sha256 = self.compute_digest()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_ID
            || self.wire_version != Self::CONTRACT_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.wire",
                reason: "unsupported semantic resolution result",
            });
        }
        bounded_text(
            &self.ticket_id,
            "agent_activation_resolution_result.ticket_id",
        )?;
        lowercase_sha256(
            &self.ticket_sha256,
            "agent_activation_resolution_result.ticket_sha256",
        )?;
        self.ticket_state_fence
            .validate()
            .map_err(ProtocolError::Foundation)?;
        if self.resolved_at_unix_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.resolved_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        self.disposition.validate()?;
        lowercase_sha256(
            &self.result_sha256,
            "agent_activation_resolution_result.result_sha256",
        )?;
        if self.result_sha256 != self.compute_digest()? {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.result_sha256",
                reason: "result digest mismatch",
            });
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        ticket: &AgentActivationResolutionTicket,
    ) -> Result<(), ProtocolError> {
        self.validate()?;
        ticket.validate()?;
        if self.ticket_id != ticket.ticket_id
            || self.ticket_sha256 != ticket.ticket_sha256
            || self.ticket_state_fence != ticket.state_fence
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.binding",
                reason: "must bind the exact ticket identity, digest, and fence",
            });
        }
        if self.resolved_at_unix_ms >= ticket.kernel_deadline_unix_ms {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.resolved_at_unix_ms",
                reason: "must be earlier than the Kernel ticket deadline",
            });
        }
        self.disposition
            .validate_against(ticket, self.resolved_at_unix_ms)
    }

    #[must_use]
    pub fn is_transient_retry(&self) -> bool {
        matches!(
            &self.disposition,
            AgentActivationResolutionDisposition::NotReady { .. }
        )
    }

    #[must_use]
    pub fn resolved_binding(&self) -> Option<&AgentActivationResolvedBinding> {
        match &self.disposition {
            AgentActivationResolutionDisposition::Resolved { binding } => Some(binding),
            _ => None,
        }
    }
}
