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

// ---------------------------------------------------------------------------
// Wave 2 receiver transport: closed v2 submit/reconcile envelope.
// ---------------------------------------------------------------------------

/// Wire identity of the daemon-to-Kernel v2 semantic-result submission.
///
/// The submission envelope carries its own wire identity and version so the
/// Kernel can reject unknown submission versions before adopting (parsing or
/// trusting) the inner [`AgentActivationResolutionResult`]. It is versioned
/// independently of the result it carries: a future submission revision does
/// not change result v2 semantics by itself.
pub const AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_ID: &str =
    "eliot.protocol.agent-activation-result-submit";
/// Current submission envelope contract version.
pub const AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_VERSION: u16 = 2;

/// Wire identity of the daemon-to-Kernel lost-acknowledgement reconcile query.
///
/// A reconcile query carries only the ticket identity and the result digest
/// the daemon believes it submitted. It never carries semantic content and
/// never triggers a second Governor read.
pub const AGENT_ACTIVATION_RESULT_RECONCILE_WIRE_ID: &str =
    "eliot.protocol.agent-activation-result-reconcile";
/// Current reconcile query contract version.
pub const AGENT_ACTIVATION_RESULT_RECONCILE_WIRE_VERSION: u16 = 2;

/// Wire identity of the Kernel-to-daemon typed acknowledgement.
///
/// The acknowledgement echoes the exact retained result (including its full
/// typed disposition) so no disposition is coerced or dropped on the daemon
/// leg, even though the thin agent-bridge wire carries a narrower denial
/// vocabulary owned outside this contract.
pub const AGENT_ACTIVATION_RESULT_ACK_WIRE_ID: &str = "eliot.protocol.agent-activation-result-ack";
/// Current acknowledgement contract version.
pub const AGENT_ACTIVATION_RESULT_ACK_WIRE_VERSION: u16 = 2;

/// Closed v2 submission carrying exactly one semantic result for one ticket.
///
/// The legacy v1 `AgentActivationResolutionDecision` shape is untouched: it
/// uses a different wire identity, a different payload key on the daemon
/// operation, and `deny_unknown_fields` in both directions, so a v1 decoder
/// structurally cannot trial-decode this envelope or the result inside it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationResultSubmit {
    /// Submission envelope wire identity.
    pub wire_id: String,
    /// Submission envelope wire version.
    pub wire_version: u16,
    /// The exact semantic result being submitted.
    pub result: AgentActivationResolutionResult,
}

impl AgentActivationResultSubmit {
    /// Current submission envelope contract version.
    pub const CONTRACT_VERSION: u16 = AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_VERSION;

    /// Wraps an exact semantic result in a versioned submission envelope.
    pub fn new(result: AgentActivationResolutionResult) -> Result<Self, ProtocolError> {
        let submit = Self {
            wire_id: AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_ID.to_owned(),
            wire_version: Self::CONTRACT_VERSION,
            result,
        };
        submit.validate()?;
        Ok(submit)
    }

    /// Validates the envelope wire identity first, then the inner result.
    ///
    /// Unknown envelope versions are rejected before the inner result is
    /// adopted in any way.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_ID
            || self.wire_version != Self::CONTRACT_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_result_submit.wire",
                reason: "unsupported semantic result submission",
            });
        }
        self.result.validate()
    }
}

/// Lost-acknowledgement reconcile query: ticket identity plus believed digest.
///
/// The Kernel answers purely from its retained per-ticket result record. A
/// query for an unknown ticket is answered `Unknown` (the daemon then submits
/// its retained result, or re-reads only when nothing was ever retained); it
/// is never answered by recomputing semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationResultReconcile {
    /// Reconcile query wire identity.
    pub wire_id: String,
    /// Reconcile query wire version.
    pub wire_version: u16,
    /// Exact resolution ticket identity being reconciled.
    pub ticket_id: String,
    /// Result digest the daemon believes it submitted for this ticket.
    pub result_sha256: String,
}

impl AgentActivationResultReconcile {
    /// Current reconcile query contract version.
    pub const CONTRACT_VERSION: u16 = AGENT_ACTIVATION_RESULT_RECONCILE_WIRE_VERSION;

    /// Builds a reconcile query for one ticket and one believed digest.
    pub fn new(ticket_id: String, result_sha256: String) -> Result<Self, ProtocolError> {
        let query = Self {
            wire_id: AGENT_ACTIVATION_RESULT_RECONCILE_WIRE_ID.to_owned(),
            wire_version: Self::CONTRACT_VERSION,
            ticket_id,
            result_sha256,
        };
        query.validate()?;
        Ok(query)
    }

    /// Validates the closed reconcile query shape.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != AGENT_ACTIVATION_RESULT_RECONCILE_WIRE_ID
            || self.wire_version != Self::CONTRACT_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_result_reconcile.wire",
                reason: "unsupported semantic result reconcile query",
            });
        }
        bounded_text(
            &self.ticket_id,
            "agent_activation_result_reconcile.ticket_id",
        )?;
        lowercase_sha256(
            &self.result_sha256,
            "agent_activation_result_reconcile.result_sha256",
        )?;
        Ok(())
    }
}

/// Typed Kernel acknowledgement outcome for one submit/reconcile operation.
///
/// `Accepted` answers a fresh commit, `ExactReplay` answers a byte-identical
/// resubmission, `Reconciled` answers a lost-acknowledgement query whose
/// digest matches retention, and `Unknown` answers a query for a ticket with
/// no retained result. All four are decided from retained identity and
/// digests only; human detail and log text never participate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentActivationResultAckOutcome {
    /// A fresh result was committed for this ticket.
    Accepted,
    /// The same result digest is already retained; nothing changed.
    ExactReplay,
    /// A reconcile query matched the retained ticket plus digest.
    Reconciled,
    /// No result is retained for this ticket.
    Unknown,
}

/// Typed Kernel acknowledgement carrying the exact retained result.
///
/// For every outcome except `Unknown`, `result` holds the retained
/// [`AgentActivationResolutionResult`] verbatim, so all seven dispositions
/// survive the daemon leg without fallback or default coercion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationResultAck {
    /// Acknowledgement wire identity.
    pub wire_id: String,
    /// Acknowledgement wire version.
    pub wire_version: u16,
    /// Exact resolution ticket identity this acknowledgement answers.
    pub ticket_id: String,
    /// Digest of the retained result, or the queried digest when `Unknown`.
    pub result_sha256: String,
    /// Which retained-identity path produced this acknowledgement.
    pub outcome: AgentActivationResultAckOutcome,
    /// The exact retained result; absent only for `Unknown`.
    pub result: Option<AgentActivationResolutionResult>,
    /// Lowercase SHA-256 over every acknowledgement field except this field.
    pub ack_sha256: String,
}

impl AgentActivationResultAck {
    /// Current acknowledgement contract version.
    pub const CONTRACT_VERSION: u16 = AGENT_ACTIVATION_RESULT_ACK_WIRE_VERSION;

    fn new(
        ticket_id: String,
        result_sha256: String,
        outcome: AgentActivationResultAckOutcome,
        result: Option<AgentActivationResolutionResult>,
    ) -> Result<Self, ProtocolError> {
        let ack = Self {
            wire_id: AGENT_ACTIVATION_RESULT_ACK_WIRE_ID.to_owned(),
            wire_version: Self::CONTRACT_VERSION,
            ticket_id,
            result_sha256,
            outcome,
            result,
            ack_sha256: String::new(),
        }
        .with_computed_digest()?;
        ack.validate()?;
        Ok(ack)
    }

    /// Acknowledges a fresh commit of the exact retained result.
    pub fn accepted(result: &AgentActivationResolutionResult) -> Result<Self, ProtocolError> {
        result.validate()?;
        Self::new(
            result.ticket_id.clone(),
            result.result_sha256.clone(),
            AgentActivationResultAckOutcome::Accepted,
            Some(result.clone()),
        )
    }

    /// Acknowledges a byte-identical resubmission without state change.
    pub fn replayed(result: &AgentActivationResolutionResult) -> Result<Self, ProtocolError> {
        result.validate()?;
        Self::new(
            result.ticket_id.clone(),
            result.result_sha256.clone(),
            AgentActivationResultAckOutcome::ExactReplay,
            Some(result.clone()),
        )
    }

    /// Answers a lost-acknowledgement query from retention, without recompute.
    pub fn reconciled(result: &AgentActivationResolutionResult) -> Result<Self, ProtocolError> {
        result.validate()?;
        Self::new(
            result.ticket_id.clone(),
            result.result_sha256.clone(),
            AgentActivationResultAckOutcome::Reconciled,
            Some(result.clone()),
        )
    }

    /// Answers a reconcile query for a ticket with no retained result.
    pub fn unknown(query: &AgentActivationResultReconcile) -> Result<Self, ProtocolError> {
        query.validate()?;
        Self::new(
            query.ticket_id.clone(),
            query.result_sha256.clone(),
            AgentActivationResultAckOutcome::Unknown,
            None,
        )
    }

    /// Returns canonical bytes covered by `ack_sha256`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut unsigned = self.clone();
        unsigned.ack_sha256.clear();
        canonical_json_bytes(&unsigned).map_err(|error| ProtocolError::Json(error.to_string()))
    }

    /// Computes the canonical acknowledgement digest.
    pub fn compute_digest(&self) -> Result<String, ProtocolError> {
        Ok(eliot_contracts::sha256_hex(
            &self.canonical_unsigned_bytes()?,
        ))
    }

    /// Populates the canonical acknowledgement digest.
    pub fn with_computed_digest(mut self) -> Result<Self, ProtocolError> {
        self.ack_sha256 = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the closed acknowledgement shape and digest.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != AGENT_ACTIVATION_RESULT_ACK_WIRE_ID
            || self.wire_version != Self::CONTRACT_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_result_ack.wire",
                reason: "unsupported semantic result acknowledgement",
            });
        }
        bounded_text(&self.ticket_id, "agent_activation_result_ack.ticket_id")?;
        lowercase_sha256(
            &self.result_sha256,
            "agent_activation_result_ack.result_sha256",
        )?;
        match (&self.outcome, &self.result) {
            (AgentActivationResultAckOutcome::Unknown, None) => {}
            (AgentActivationResultAckOutcome::Unknown, Some(_)) => {
                return Err(ProtocolError::InvalidField {
                    field: "agent_activation_result_ack.result",
                    reason: "an unknown acknowledgement retains no result",
                });
            }
            (_, None) => {
                return Err(ProtocolError::InvalidField {
                    field: "agent_activation_result_ack.result",
                    reason: "a retained acknowledgement must carry the exact result",
                });
            }
            (_, Some(result)) => {
                result.validate()?;
                if result.ticket_id != self.ticket_id || result.result_sha256 != self.result_sha256
                {
                    return Err(ProtocolError::InvalidField {
                        field: "agent_activation_result_ack.binding",
                        reason: "must echo the exact retained ticket identity and digest",
                    });
                }
            }
        }
        lowercase_sha256(&self.ack_sha256, "agent_activation_result_ack.ack_sha256")?;
        if self.ack_sha256 != self.compute_digest()? {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_result_ack.ack_sha256",
                reason: "acknowledgement digest mismatch",
            });
        }
        Ok(())
    }
}
