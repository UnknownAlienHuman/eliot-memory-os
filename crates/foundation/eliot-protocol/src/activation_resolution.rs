//! Typed semantic-resolution results for agent activation.
//!
//! This additive v2 contract represents one exact semantic result for one
//! Kernel-owned activation ticket. It creates no Session, capability, nonce,
//! effect authority, or hidden retry loop. The retired v1 decision remains
//! available only through the namespaced import module; it has no root export,
//! production conversion, or production fallback.

use std::collections::BTreeSet;

use eliot_contracts::{StateFence, canonical_json_bytes};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AgentActivationResolutionTicket, ProtocolError};

pub const AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_ID: &str =
    "eliot.protocol.agent-activation-resolution-result";
pub const AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_VERSION: u16 = 2;
/// Stable semantic owner identity for activation results produced by `eliotd`.
///
/// This is evidence about the authenticated producer of the semantic
/// snapshot, not a replacement Governor or a Kernel-side semantic resolver.
pub const AGENT_ACTIVATION_OWNER_ID: &str = "eliotd";
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

/// Immutable authenticated-owner evidence attached to one `Resolved` binding.
///
/// The Governor/eliotd owner creates this evidence while it reads the one
/// coherent semantic snapshot. Kernel validates the evidence against the
/// ticket and the exact binding before creating a transport Session; it does
/// not read or re-resolve task, scope, or plan semantics itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationOwnerEvidence {
    /// Authenticated semantic owner module.
    pub owner_id: String,
    /// Monotonic owner revision observed by the trusted semantic owner.
    pub owner_revision: u64,
    /// State Fence at which the owner observed the binding.
    pub state_fence: StateFence,
    /// Exact resolved binding observed by the authenticated owner. The full
    /// value is retained so Kernel can compare every semantic identity field,
    /// not only an opaque digest, before creating a transport Session.
    pub binding: Box<AgentActivationResolvedBinding>,
    /// Digest of the exact resolved binding carried by the result.
    pub binding_sha256: String,
    /// Digest over all preceding evidence fields.
    pub evidence_sha256: String,
}

impl AgentActivationOwnerEvidence {
    /// Creates evidence for one exact binding and owner revision.
    pub fn for_binding(
        binding: &AgentActivationResolvedBinding,
        owner_revision: u64,
        state_fence: StateFence,
    ) -> Result<Self, ProtocolError> {
        if owner_revision == 0 {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_owner_evidence.owner_revision",
                reason: "must be greater than zero",
            });
        }
        let binding_sha256 = binding_digest(binding)?;
        Self {
            owner_id: AGENT_ACTIVATION_OWNER_ID.to_owned(),
            owner_revision,
            state_fence,
            binding: Box::new(binding.clone()),
            binding_sha256,
            evidence_sha256: String::new(),
        }
        .with_computed_digest()
    }

    /// Sets the exact owner-observed fence and computes the evidence digest.
    pub fn with_state_fence(mut self, state_fence: StateFence) -> Result<Self, ProtocolError> {
        state_fence.validate().map_err(ProtocolError::Foundation)?;
        self.state_fence = state_fence;
        self.with_computed_digest()
    }

    /// Returns canonical bytes covered by `evidence_sha256`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut unsigned = self.clone();
        unsigned.evidence_sha256.clear();
        canonical_json_bytes(&unsigned).map_err(|error| ProtocolError::Json(error.to_string()))
    }

    /// Computes the evidence digest.
    pub fn compute_digest(&self) -> Result<String, ProtocolError> {
        Ok(eliot_contracts::sha256_hex(
            &self.canonical_unsigned_bytes()?,
        ))
    }

    /// Populates the evidence digest.
    pub fn with_computed_digest(mut self) -> Result<Self, ProtocolError> {
        self.evidence_sha256 = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the evidence shape and digest.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        bounded_text(&self.owner_id, "agent_activation_owner_evidence.owner_id")?;
        if self.owner_id != AGENT_ACTIVATION_OWNER_ID {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_owner_evidence.owner_id",
                reason: "must be the authenticated eliotd semantic owner",
            });
        }
        if self.owner_revision == 0 {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_owner_evidence.owner_revision",
                reason: "must be greater than zero",
            });
        }
        self.state_fence
            .validate()
            .map_err(ProtocolError::Foundation)?;
        self.binding.validate()?;
        lowercase_sha256(
            &self.binding_sha256,
            "agent_activation_owner_evidence.binding_sha256",
        )?;
        if self.binding_sha256 != binding_digest(&self.binding)? {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_owner_evidence.binding_sha256",
                reason: "must bind the exact owner-observed binding",
            });
        }
        lowercase_sha256(
            &self.evidence_sha256,
            "agent_activation_owner_evidence.evidence_sha256",
        )?;
        if self.evidence_sha256 != self.compute_digest()? {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_owner_evidence.evidence_sha256",
                reason: "owner evidence digest mismatch",
            });
        }
        Ok(())
    }

    /// Validates that this evidence is the exact evidence for `binding` and
    /// the supplied owner-observed fence.
    pub fn validate_against_binding(
        &self,
        binding: &AgentActivationResolvedBinding,
        state_fence: &StateFence,
    ) -> Result<(), ProtocolError> {
        self.validate()?;
        if self.state_fence != *state_fence
            || self.binding.as_ref() != binding
            || self.binding_sha256 != binding_digest(binding)?
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_owner_evidence.binding",
                reason: "must bind every exact resolved identity field and owner fence",
            });
        }
        Ok(())
    }
}

/// Exact Kernel P-07 owner projection captured with a semantic owner readback.
///
/// The semantic binding and the Kernel owner bundle are separate owner
/// surfaces.  The revision/digest pair is carried so the Kernel can compare
/// the exact owner projection it retained at dispatch time with the one it
/// still owns while publishing a transport Session.  A missing pair is valid
/// only for protocol/test constructors; the production daemon and Kernel
/// admission gates require it for `Resolved`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationKernelOwnerReadback {
    pub revision: u64,
    pub bundle_sha256: String,
}

impl AgentActivationKernelOwnerReadback {
    pub fn new(revision: u64, bundle_sha256: String) -> Result<Self, ProtocolError> {
        let readback = Self {
            revision,
            bundle_sha256,
        };
        readback.validate()?;
        Ok(readback)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.revision == 0 {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_kernel_owner_readback.revision",
                reason: "must be greater than zero",
            });
        }
        lowercase_sha256(
            &self.bundle_sha256,
            "agent_activation_kernel_owner_readback.bundle_sha256",
        )?;
        Ok(())
    }
}

/// Independent current-owner readback captured immediately before result
/// submission. It is distinct from the result's semantic evidence: the owner
/// supplies a fresh, timestamped readback of the same binding so Kernel can
/// detect a semantic-owner change without resolving task meaning itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationOwnerReadback {
    pub evidence: AgentActivationOwnerEvidence,
    pub observed_at_unix_ms: u64,
    /// Exact P-07 owner revision/digest observed by the authenticated daemon
    /// immediately before submission. Production `Resolved` admission requires
    /// this projection; the optional shape keeps protocol-only fixtures
    /// source-compatible without weakening the production Kernel gate.
    #[serde(default)]
    pub kernel_owner: Option<AgentActivationKernelOwnerReadback>,
    pub readback_sha256: String,
}

impl AgentActivationOwnerReadback {
    pub fn from_evidence(
        evidence: AgentActivationOwnerEvidence,
        observed_at_unix_ms: u64,
    ) -> Result<Self, ProtocolError> {
        if observed_at_unix_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_owner_readback.observed_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        let mut readback = Self {
            evidence,
            observed_at_unix_ms,
            kernel_owner: None,
            readback_sha256: String::new(),
        };
        readback.readback_sha256 = readback.compute_digest()?;
        readback.validate()?;
        Ok(readback)
    }

    /// Attaches the exact Kernel P-07 owner revision/digest observed by the
    /// authenticated daemon and reseals the readback digest.
    pub fn with_kernel_owner_readback(
        mut self,
        kernel_owner: AgentActivationKernelOwnerReadback,
    ) -> Result<Self, ProtocolError> {
        kernel_owner.validate()?;
        self.kernel_owner = Some(kernel_owner);
        self.readback_sha256 = String::new();
        self.readback_sha256 = self.compute_digest()?;
        self.validate()?;
        Ok(self)
    }

    fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut unsigned = self.clone();
        unsigned.readback_sha256.clear();
        canonical_json_bytes(&unsigned).map_err(|error| ProtocolError::Json(error.to_string()))
    }

    pub fn compute_digest(&self) -> Result<String, ProtocolError> {
        Ok(eliot_contracts::sha256_hex(
            &self.canonical_unsigned_bytes()?,
        ))
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.evidence.validate()?;
        if self.observed_at_unix_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_owner_readback.observed_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        if let Some(kernel_owner) = &self.kernel_owner {
            kernel_owner.validate()?;
        }
        lowercase_sha256(
            &self.readback_sha256,
            "agent_activation_owner_readback.readback_sha256",
        )?;
        if self.readback_sha256 != self.compute_digest()? {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_owner_readback.readback_sha256",
                reason: "owner readback digest mismatch",
            });
        }
        Ok(())
    }

    pub fn validate_against_binding(
        &self,
        binding: &AgentActivationResolvedBinding,
        state_fence: &StateFence,
    ) -> Result<(), ProtocolError> {
        self.validate()?;
        self.evidence.validate_against_binding(binding, state_fence)
    }

    /// Semantic equality for exact replay. Observation time and a monotonic
    /// owner revision are readback metadata; the result identity remains the
    /// exact owner/fence/binding projection, so a newer readback cannot turn
    /// an otherwise exact result replay into a conflict.
    #[must_use]
    pub fn same_owner_projection(&self, other: &Self) -> bool {
        self.evidence.owner_id == other.evidence.owner_id
            && self.evidence.state_fence == other.evidence.state_fence
            && self.evidence.binding == other.evidence.binding
    }
}

/// Computes the canonical digest of the semantic fields in a resolved binding.
pub fn binding_digest(binding: &AgentActivationResolvedBinding) -> Result<String, ProtocolError> {
    binding.validate()?;
    Ok(eliot_contracts::sha256_hex(
        &canonical_json_bytes(binding).map_err(|error| ProtocolError::Json(error.to_string()))?,
    ))
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
pub struct AgentActivationDependencyObservation {
    pub dependency_ref: String,
    pub observed_dependency_revision: String,
    pub owner_id: String,
    pub owner_revision: u64,
    pub state_fence: StateFence,
    pub evidence_sha256: String,
}

impl AgentActivationDependencyObservation {
    /// Creates one fresh semantic-owner observation for a successor ticket.
    pub fn for_successor(
        ticket: &AgentActivationResolutionTicket,
        dependency_ref: impl Into<String>,
        observed_dependency_revision: impl Into<String>,
        owner_revision: u64,
    ) -> Result<Self, ProtocolError> {
        let successor_of = ticket
            .successor_of
            .as_ref()
            .ok_or(ProtocolError::InvalidField {
                field: "agent_activation_dependency_observation.ticket",
                reason: "dependency observation requires a successor ticket",
            })?;
        let dependency_ref = dependency_ref.into();
        let observed_dependency_revision = observed_dependency_revision.into();
        bounded_text(
            &dependency_ref,
            "agent_activation_dependency_observation.dependency_ref",
        )?;
        bounded_text(
            &observed_dependency_revision,
            "agent_activation_dependency_observation.observed_dependency_revision",
        )?;
        if dependency_ref != successor_of.dependency_ref {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_dependency_observation.dependency_ref",
                reason: "must match the predecessor's named dependency",
            });
        }
        if observed_dependency_revision == successor_of.observed_dependency_revision {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_dependency_observation.observed_dependency_revision",
                reason: "must materially differ from the predecessor revision",
            });
        }
        let observation = Self {
            dependency_ref,
            observed_dependency_revision,
            owner_id: AGENT_ACTIVATION_OWNER_ID.to_owned(),
            owner_revision,
            state_fence: ticket.state_fence.clone(),
            evidence_sha256: String::new(),
        }
        .with_computed_digest()?;
        observation.validate()?;
        Ok(observation)
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        bounded_text(
            &self.dependency_ref,
            "agent_activation_dependency_observation.dependency_ref",
        )?;
        bounded_text(
            &self.observed_dependency_revision,
            "agent_activation_dependency_observation.observed_dependency_revision",
        )?;
        if self.owner_id != AGENT_ACTIVATION_OWNER_ID || self.owner_revision == 0 {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_dependency_observation.owner",
                reason: "must name the authenticated eliotd owner at a non-zero revision",
            });
        }
        self.state_fence
            .validate()
            .map_err(ProtocolError::Foundation)?;
        lowercase_sha256(
            &self.evidence_sha256,
            "agent_activation_dependency_observation.evidence_sha256",
        )?;
        if self.evidence_sha256 != self.compute_digest()? {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_dependency_observation.evidence_sha256",
                reason: "dependency observation digest mismatch",
            });
        }
        Ok(())
    }

    fn validate_against(
        &self,
        ticket: &AgentActivationResolutionTicket,
        resolved_at_unix_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.validate()?;
        let successor_of = ticket
            .successor_of
            .as_ref()
            .ok_or(ProtocolError::InvalidField {
                field: "agent_activation_dependency_observation.ticket",
                reason: "initial tickets cannot claim successor dependency evidence",
            })?;
        if self.state_fence != ticket.state_fence
            || self.dependency_ref != successor_of.dependency_ref
            || self.observed_dependency_revision == successor_of.observed_dependency_revision
            || resolved_at_unix_ms < successor_of.not_before_unix_ms
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_dependency_observation.binding",
                reason: "must bind the exact successor fence, dependency, due time, and changed revision",
            });
        }
        Ok(())
    }

    fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut unsigned = self.clone();
        unsigned.evidence_sha256.clear();
        canonical_json_bytes(&unsigned).map_err(|error| ProtocolError::Json(error.to_string()))
    }

    fn compute_digest(&self) -> Result<String, ProtocolError> {
        Ok(eliot_contracts::sha256_hex(
            &self.canonical_unsigned_bytes()?,
        ))
    }

    fn with_computed_digest(mut self) -> Result<Self, ProtocolError> {
        self.evidence_sha256 = self.compute_digest()?;
        Ok(self)
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
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
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
    /// Exact cancellation identity inherited from the immutable ticket.
    pub cancellation_id: String,
    pub resolved_at_unix_ms: u64,
    pub disposition: AgentActivationResolutionDisposition,
    /// Fresh authenticated owner observation required for a successor ticket.
    #[serde(default)]
    pub dependency_observation: Option<AgentActivationDependencyObservation>,
    /// Authenticated owner evidence is required for `Resolved` and absent for
    /// every negative disposition.
    #[serde(default)]
    pub owner_evidence: Option<AgentActivationOwnerEvidence>,
    pub result_sha256: String,
}

impl AgentActivationResolutionResult {
    pub const CONTRACT_VERSION: u16 = AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_VERSION;

    pub fn new(
        ticket: &AgentActivationResolutionTicket,
        resolved_at_unix_ms: u64,
        disposition: AgentActivationResolutionDisposition,
    ) -> Result<Self, ProtocolError> {
        let owner_revision = match &disposition {
            AgentActivationResolutionDisposition::Resolved { binding } => binding
                .task_revision
                .parse::<u64>()
                .ok()
                .filter(|revision| *revision > 0)
                .unwrap_or(1),
            _ => 1,
        };
        Self::new_with_owner_evidence(ticket, resolved_at_unix_ms, disposition, owner_revision)
    }

    /// Constructs a result with explicit owner revision evidence.
    ///
    /// Production Governor projection uses this entry point so the owner
    /// revision comes from the same coherent semantic snapshot as the
    /// binding. The compatibility constructor above supplies a deterministic
    /// non-zero revision for callers that only exercise the protocol shape.
    pub fn new_with_owner_evidence(
        ticket: &AgentActivationResolutionTicket,
        resolved_at_unix_ms: u64,
        disposition: AgentActivationResolutionDisposition,
        owner_revision: u64,
    ) -> Result<Self, ProtocolError> {
        ticket.validate()?;
        if resolved_at_unix_ms == 0 || resolved_at_unix_ms >= ticket.kernel_deadline_unix_ms {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.resolved_at_unix_ms",
                reason: "must be non-zero and earlier than the Kernel ticket deadline",
            });
        }
        let owner_evidence = match &disposition {
            AgentActivationResolutionDisposition::Resolved { binding } => {
                Some(AgentActivationOwnerEvidence::for_binding(
                    binding,
                    owner_revision,
                    ticket.state_fence.clone(),
                )?)
            }
            _ => None,
        };
        let result = Self {
            wire_id: AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_ID.to_owned(),
            wire_version: Self::CONTRACT_VERSION,
            ticket_id: ticket.ticket_id.clone(),
            ticket_sha256: ticket.ticket_sha256.clone(),
            ticket_state_fence: ticket.state_fence.clone(),
            cancellation_id: ticket.cancellation_id.clone(),
            resolved_at_unix_ms,
            disposition,
            dependency_observation: None,
            owner_evidence,
            result_sha256: String::new(),
        }
        .with_computed_digest()?;
        result.validate_against(ticket)?;
        Ok(result)
    }

    /// Constructs a result for one fresh successor ticket. The observation is
    /// mandatory and is sealed into the same result digest.
    pub fn new_for_successor(
        ticket: &AgentActivationResolutionTicket,
        resolved_at_unix_ms: u64,
        disposition: AgentActivationResolutionDisposition,
        owner_revision: u64,
        observed_dependency_revision: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        let successor_of = ticket
            .successor_of
            .as_ref()
            .ok_or(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.successor",
                reason: "successor constructor requires predecessor evidence",
            })?;
        // Build the result against the predecessor-free shape first so the
        // common constructor can validate owner evidence before the
        // successor-only dependency observation is attached. Recompute that
        // temporary ticket digest, then restore the exact successor ticket
        // digest and reseal the result before the final ticket join.
        let mut initial_ticket = ticket.clone();
        initial_ticket.successor_of = None;
        initial_ticket.ticket_sha256 = initial_ticket.compute_digest()?;
        let result = Self::new_with_owner_evidence(
            &initial_ticket,
            resolved_at_unix_ms,
            disposition,
            owner_revision,
        )?;
        let observation = AgentActivationDependencyObservation::for_successor(
            ticket,
            successor_of.dependency_ref.clone(),
            observed_dependency_revision,
            owner_revision,
        )?;
        let mut result = result.with_dependency_observation(observation)?;
        result.ticket_sha256.clone_from(&ticket.ticket_sha256);
        result.result_sha256 = String::new();
        result.result_sha256 = result.compute_digest()?;
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

    /// Attaches the fresh authenticated owner observation required by a
    /// successor ticket and reseals the result digest.
    pub fn with_dependency_observation(
        mut self,
        observation: AgentActivationDependencyObservation,
    ) -> Result<Self, ProtocolError> {
        self.dependency_observation = Some(observation);
        self.result_sha256 = String::new();
        self.result_sha256 = self.compute_digest()?;
        self.validate()?;
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
        bounded_text(
            &self.cancellation_id,
            "agent_activation_resolution_result.cancellation_id",
        )?;
        if self.resolved_at_unix_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.resolved_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        self.disposition.validate()?;
        if let Some(observation) = &self.dependency_observation {
            observation.validate()?;
        }
        match (&self.disposition, &self.owner_evidence) {
            (AgentActivationResolutionDisposition::Resolved { binding }, Some(evidence)) => {
                evidence.validate_against_binding(binding, &self.ticket_state_fence)?;
            }
            (AgentActivationResolutionDisposition::Resolved { .. }, None) => {
                return Err(ProtocolError::InvalidField {
                    field: "agent_activation_resolution_result.owner_evidence",
                    reason: "Resolved requires authenticated owner evidence",
                });
            }
            (_, Some(_)) => {
                return Err(ProtocolError::InvalidField {
                    field: "agent_activation_resolution_result.owner_evidence",
                    reason: "negative dispositions must not carry owner evidence",
                });
            }
            (_, None) => {}
        }
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
            || self.cancellation_id != ticket.cancellation_id
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.binding",
                reason: "must bind the exact ticket identity, digest, fence, and cancellation identity",
            });
        }
        if self.resolved_at_unix_ms >= ticket.kernel_deadline_unix_ms {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_resolution_result.resolved_at_unix_ms",
                reason: "must be earlier than the Kernel ticket deadline",
            });
        }
        match (
            ticket.successor_of.as_ref(),
            self.dependency_observation.as_ref(),
        ) {
            (None, None) => {}
            (Some(_), Some(observation)) => {
                observation.validate_against(ticket, self.resolved_at_unix_ms)?;
                if let AgentActivationResolutionDisposition::NotReady { retry, .. } =
                    &self.disposition
                    && (retry.dependency_ref != observation.dependency_ref
                        || retry.observed_dependency_revision
                            != observation.observed_dependency_revision)
                {
                    return Err(ProtocolError::InvalidField {
                        field: "agent_activation_resolution_result.dependency_observation",
                        reason: "NotReady retry must repeat the exact fresh dependency observation",
                    });
                }
            }
            _ => {
                return Err(ProtocolError::InvalidField {
                    field: "agent_activation_resolution_result.dependency_observation",
                    reason: "successor tickets require one fresh observation and initial tickets forbid it",
                });
            }
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

/// Wire identity of the authenticated pre-claim dependency observation.
pub const AGENT_ACTIVATION_CLAIM_WIRE_ID: &str = "eliot.protocol.agent-activation-claim";
/// Current pre-claim observation contract version.
pub const AGENT_ACTIVATION_CLAIM_WIRE_VERSION: u16 = 2;

/// Fresh owner observation carried with one daemon claim request.
///
/// The observation is deliberately opaque to Kernel: the daemon owns the
/// semantic dependency read, while Kernel only compares the named revision
/// discriminator mechanically before a successor ticket can become `Claimed`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationClaimRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub dependency_ref: String,
    pub dependency_revision: String,
    pub observed_at_unix_ms: u64,
}

impl AgentActivationClaimRequest {
    pub fn new(
        dependency_ref: String,
        dependency_revision: String,
        observed_at_unix_ms: u64,
    ) -> Result<Self, ProtocolError> {
        let request = Self {
            wire_id: AGENT_ACTIVATION_CLAIM_WIRE_ID.to_owned(),
            wire_version: Self::CONTRACT_VERSION,
            dependency_ref,
            dependency_revision,
            observed_at_unix_ms,
        };
        request.validate()?;
        Ok(request)
    }

    pub const CONTRACT_VERSION: u16 = AGENT_ACTIVATION_CLAIM_WIRE_VERSION;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != AGENT_ACTIVATION_CLAIM_WIRE_ID
            || self.wire_version != Self::CONTRACT_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_claim_request.wire",
                reason: "unsupported activation claim observation",
            });
        }
        bounded_text(
            &self.dependency_ref,
            "agent_activation_claim_request.dependency_ref",
        )?;
        bounded_text(
            &self.dependency_revision,
            "agent_activation_claim_request.dependency_revision",
        )?;
        if self.observed_at_unix_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_claim_request.observed_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Closed v2 submission carrying exactly one semantic result for one ticket.
///
/// The retired v1 decision shape used a different wire identity, a different
/// payload key on the daemon operation, and `deny_unknown_fields` in both
/// directions. Its namespaced import artifact therefore cannot trial-decode
/// this envelope or the result inside it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentActivationResultSubmit {
    /// Submission envelope wire identity.
    pub wire_id: String,
    /// Submission envelope wire version.
    pub wire_version: u16,
    /// The exact semantic result being submitted.
    pub result: AgentActivationResolutionResult,
    /// Fresh authenticated owner readback captured by the daemon's current
    /// semantic read. Kernel stores this as its current owner join before a
    /// Resolved binding can become a transport Session.
    pub owner_readback: Option<AgentActivationOwnerReadback>,
}

impl AgentActivationResultSubmit {
    /// Current submission envelope contract version.
    pub const CONTRACT_VERSION: u16 = AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_VERSION;

    /// Wraps an exact semantic result in a versioned submission envelope.
    pub fn new(result: AgentActivationResolutionResult) -> Result<Self, ProtocolError> {
        let readback_at = result.resolved_at_unix_ms;
        let owner_readback = result
            .owner_evidence
            .clone()
            .map(|evidence| AgentActivationOwnerReadback::from_evidence(evidence, readback_at))
            .transpose()?;
        Self::new_with_owner_readback(result, owner_readback)
    }

    /// Wraps a result with a separately captured current owner readback.
    /// The readback is mechanically compared with the result binding by
    /// [`Self::validate`]; it is not a second semantic resolver.
    pub fn new_with_owner_readback(
        result: AgentActivationResolutionResult,
        owner_readback: Option<AgentActivationOwnerReadback>,
    ) -> Result<Self, ProtocolError> {
        let submit = Self {
            wire_id: AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_ID.to_owned(),
            wire_version: Self::CONTRACT_VERSION,
            result,
            owner_readback,
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
        self.result.validate()?;
        match (&self.result.disposition, &self.owner_readback) {
            (AgentActivationResolutionDisposition::Resolved { binding }, Some(readback)) => {
                readback.validate_against_binding(binding, &self.result.ticket_state_fence)?;
                if self.result.owner_evidence.as_ref().is_some_and(|evidence| {
                    readback.evidence.owner_id != evidence.owner_id
                        || readback.evidence.owner_revision < evidence.owner_revision
                }) {
                    return Err(ProtocolError::InvalidField {
                        field: "agent_activation_result_submit.owner_readback",
                        reason: "must not be older than the result owner evidence",
                    });
                }
            }
            (AgentActivationResolutionDisposition::Resolved { .. }, None) => {
                return Err(ProtocolError::InvalidField {
                    field: "agent_activation_result_submit.owner_readback",
                    reason: "Resolved requires a current owner readback",
                });
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(ProtocolError::InvalidField {
                    field: "agent_activation_result_submit.owner_readback",
                    reason: "negative dispositions must not carry owner readback",
                });
            }
        }
        Ok(())
    }

    /// Validates the envelope and binds its result to the exact Kernel ticket.
    pub fn validate_against(
        &self,
        ticket: &AgentActivationResolutionTicket,
    ) -> Result<(), ProtocolError> {
        self.validate()?;
        self.result.validate_against(ticket)
    }
}

/// Decodes the closed v2 submit envelope without trying any alternate result
/// shape. The outer identity and version are inspected before the inner
/// result is deserialized, so an unknown version cannot trigger a legacy or
/// raw-result trial decode.
pub fn decode_agent_activation_result_submit(
    value: &serde_json::Value,
) -> Result<AgentActivationResultSubmit, ProtocolError> {
    let object = value.as_object().ok_or(ProtocolError::InvalidField {
        field: "agent_activation_result_submit",
        reason: "must be a closed JSON object",
    })?;
    if object.len() != 4
        || !object.contains_key("wire_id")
        || !object.contains_key("wire_version")
        || !object.contains_key("result")
        || !object.contains_key("owner_readback")
    {
        return Err(ProtocolError::InvalidField {
            field: "agent_activation_result_submit",
            reason: "contains unknown or missing envelope fields",
        });
    }
    let wire_id = object
        .get("wire_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(ProtocolError::InvalidField {
            field: "agent_activation_result_submit.wire_id",
            reason: "must be a string",
        })?;
    if wire_id != AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_ID {
        return Err(ProtocolError::InvalidField {
            field: "agent_activation_result_submit.wire_id",
            reason: "unsupported semantic result submission",
        });
    }
    let wire_version = object
        .get("wire_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or(ProtocolError::InvalidField {
            field: "agent_activation_result_submit.wire_version",
            reason: "must be an integer",
        })?;
    if wire_version != u64::from(AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_VERSION) {
        return Err(ProtocolError::InvalidField {
            field: "agent_activation_result_submit.wire_version",
            reason: "unsupported semantic result submission",
        });
    }
    let result = serde_json::from_value(object.get("result").cloned().ok_or(
        ProtocolError::InvalidField {
            field: "agent_activation_result_submit.result",
            reason: "is required",
        },
    )?)
    .map_err(|_| ProtocolError::InvalidField {
        field: "agent_activation_result_submit.result",
        reason: "does not decode as the closed v2 result",
    })?;
    let owner_readback: Option<AgentActivationOwnerReadback> =
        serde_json::from_value(object.get("owner_readback").cloned().ok_or(
            ProtocolError::InvalidField {
                field: "agent_activation_result_submit.owner_readback",
                reason: "is required",
            },
        )?)
        .map_err(|_| ProtocolError::InvalidField {
            field: "agent_activation_result_submit.owner_readback",
            reason: "does not decode as authenticated owner readback",
        })?;
    let submit = AgentActivationResultSubmit {
        wire_id: wire_id.to_owned(),
        wire_version: u16::try_from(wire_version).map_err(|_| ProtocolError::InvalidField {
            field: "agent_activation_result_submit.wire_version",
            reason: "does not fit the contract version",
        })?,
        result,
        owner_readback,
    };
    submit.validate()?;
    Ok(submit)
}
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
/// `Accepted` is the stable terminal acknowledgement returned for a fresh
/// commit, an exact replay, or a matching reconcile. Keeping one positive
/// acknowledgement shape makes the response byte-stable for the retained
/// ticket/result identity. `Unknown` is reserved for a reconcile query with no
/// retained result. Both outcomes are decided from retained identity and
/// digests only; human detail and log text never participate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentActivationResultAckOutcome {
    /// The exact result is durably retained and acknowledged.
    Accepted,
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

    /// Builds the one stable positive acknowledgement for an exact retained
    /// result. Fresh commit, exact replay, and reconcile all call this same
    /// constructor, so none can change the acknowledgement bytes.
    pub fn accepted(result: &AgentActivationResolutionResult) -> Result<Self, ProtocolError> {
        result.validate()?;
        Self::new(
            result.ticket_id.clone(),
            result.result_sha256.clone(),
            AgentActivationResultAckOutcome::Accepted,
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

    /// Returns the semantic replay key. The full response digest may include
    /// the delivery outcome, but replay identity is always ticket plus result.
    #[must_use]
    pub fn replay_key(&self) -> (&str, &str) {
        (self.ticket_id.as_str(), self.result_sha256.as_str())
    }

    /// Validates that this positive acknowledgement is the exact retained
    /// result submitted by the caller.
    pub fn validate_against_result(
        &self,
        expected: &AgentActivationResolutionResult,
    ) -> Result<(), ProtocolError> {
        self.validate()?;
        expected.validate()?;
        if self.outcome == AgentActivationResultAckOutcome::Unknown
            || self.result.as_ref() != Some(expected)
            || self.replay_key() != (expected.ticket_id.as_str(), expected.result_sha256.as_str())
        {
            return Err(ProtocolError::InvalidField {
                field: "agent_activation_result_ack.result",
                reason: "must echo the exact submitted result identity and payload",
            });
        }
        Ok(())
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
