//! Immutable host integration coverage used to qualify requested modes.

use eliot_contracts::{ContractIdentity, ResourceGeneration, StateFence};
use eliot_evidence::EvidenceEnvelope;
use eliot_protocol::{ReactiveContextContentRef, ReactiveContextPrivacy};
use eliot_receipts::{EffectClass, ProofCeiling, ReceiptEnvelope};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ReactiveInputError, SnapshotCompleteness, bounded_preflight, canonical_planning_digest,
};

const MAX_EVENTS: usize = 64;
const MAX_GAPS: usize = 128;
const MAX_EVIDENCE: usize = 128;
const COVERAGE_CLAIM_DOMAIN: &str = "eliot.context-contracts.reactive.coverage-observation";
const COVERAGE_CLAIM_VERSION: u16 = 1;
const I716_EVENTS: [&str; 10] = [
    "SessionStart",
    "UserPromptSubmit",
    "SubagentStart",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PreCompact",
    "PostCompact",
    "SubagentStop",
    "Stop/FinishAttempt",
];

#[derive(Serialize)]
struct CanonicalProfile<'a> {
    host_id: &'a str,
    runtime_id: &'a str,
    interface_id: &'a str,
    contract: &'a ContractIdentity,
    recipient_id: &'a str,
    host_generation: &'a ResourceGeneration,
    runtime_generation: &'a ResourceGeneration,
    recipient_generation: &'a ResourceGeneration,
    profile_revision: &'a str,
    completeness: &'a SnapshotCompleteness,
    supported_modes: &'a [ReactiveDeliveryMode],
    privacy_ceiling: &'a ReactiveContextPrivacy,
    effect_ceiling: &'a EffectClass,
    proof_ceiling: &'a ProofCeiling,
    state_fence: &'a StateFence,
    events: &'a [CoverageEvidence],
    gaps: &'a [String],
}

fn text(value: &str, field: &'static str) -> Result<(), ReactiveInputError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ReactiveInputError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

fn known_event(value: &str) -> bool {
    matches!(
        value,
        "SessionStart"
            | "UserPromptSubmit"
            | "SubagentStart"
            | "PreToolUse"
            | "PermissionRequest"
            | "PostToolUse"
            | "PreCompact"
            | "PostCompact"
            | "SubagentStop"
            | "Stop/FinishAttempt"
    ) || value
        .strip_prefix("UNKNOWN:")
        .is_some_and(|suffix| !suffix.trim().is_empty())
}

/// Per-event observation/enforcement axis from I7.16.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageAxis {
    Enforced,
    Observed,
    ExplicitObserve,
    Unavailable,
}

/// Freshness of the owner evidence supporting one event axis.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageFreshness {
    Fresh,
    Stale,
    ExplicitlyUnavailable,
    Unknown,
}

/// Requested delivery contour; mode is a request, never authority evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReactiveDeliveryMode {
    EventIntegrated,
    ToolOnly,
    ObserveOnly,
    OfflineWorker,
}

/// One immutable event coverage observation and its gap evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageEvidence {
    pub owner_id: String,
    pub claim_artifact_id: eliot_contracts::ArtifactId,
    pub claim_digest: String,
    pub event: String,
    pub host_id: String,
    pub runtime_id: String,
    pub interface_id: String,
    pub contract: ContractIdentity,
    pub recipient_id: String,
    pub host_generation: ResourceGeneration,
    pub runtime_generation: ResourceGeneration,
    pub recipient_generation: ResourceGeneration,
    pub state_fence: StateFence,
    pub axis: CoverageAxis,
    pub completeness: SnapshotCompleteness,
    pub ordering: String,
    pub proof_ceiling: ProofCeiling,
    pub freshness: CoverageFreshness,
    pub source: ReactiveContextContentRef,
    pub gaps: Vec<String>,
    pub receipts: Vec<ReceiptEnvelope>,
    pub evidence: Vec<EvidenceEnvelope>,
}

#[derive(Serialize)]
struct CanonicalCoverageClaim<'a> {
    domain: &'static str,
    version: u16,
    owner_id: &'a str,
    claim_artifact_id: &'a eliot_contracts::ArtifactId,
    host_id: &'a str,
    runtime_id: &'a str,
    interface_id: &'a str,
    contract: &'a ContractIdentity,
    recipient_id: &'a str,
    host_generation: &'a ResourceGeneration,
    runtime_generation: &'a ResourceGeneration,
    recipient_generation: &'a ResourceGeneration,
    state_fence: &'a StateFence,
    event: &'a str,
    axis: &'a CoverageAxis,
    completeness: &'a SnapshotCompleteness,
    ordering: &'a str,
    proof_ceiling: &'a ProofCeiling,
    freshness: &'a CoverageFreshness,
    source: &'a ReactiveContextContentRef,
    gaps: &'a [String],
    evidence: &'a [EvidenceEnvelope],
}

impl CoverageEvidence {
    pub fn canonical_claim_digest(&self) -> Result<String, ReactiveInputError> {
        canonical_planning_digest(&CanonicalCoverageClaim {
            domain: COVERAGE_CLAIM_DOMAIN,
            version: COVERAGE_CLAIM_VERSION,
            owner_id: &self.owner_id,
            claim_artifact_id: &self.claim_artifact_id,
            host_id: &self.host_id,
            runtime_id: &self.runtime_id,
            interface_id: &self.interface_id,
            contract: &self.contract,
            recipient_id: &self.recipient_id,
            host_generation: &self.host_generation,
            runtime_generation: &self.runtime_generation,
            recipient_generation: &self.recipient_generation,
            state_fence: &self.state_fence,
            event: &self.event,
            axis: &self.axis,
            completeness: &self.completeness,
            ordering: &self.ordering,
            proof_ceiling: &self.proof_ceiling,
            freshness: &self.freshness,
            source: &self.source,
            gaps: &self.gaps,
            evidence: &self.evidence,
        })
    }

    fn validate_support(&self) -> Result<(), ReactiveInputError> {
        for receipt in &self.receipts {
            receipt
                .validate()
                .map_err(|_| ReactiveInputError::InvalidField {
                    field: "coverage.receipts",
                    reason: "invalid retained ReceiptEnvelope",
                })?;
            if receipt.core.work_scope.state_fence != self.state_fence {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "coverage.receipt_binding",
                });
            }
            if self.source.artifact_id.as_ref().is_none_or(|artifact_id| {
                !receipt.core.artifacts.iter().any(|artifact| {
                    &artifact.artifact_id == artifact_id
                        && artifact.sha256 == self.source.content_sha256
                        && artifact.source_revision.as_deref()
                            == Some(self.source.source_revision.as_str())
                })
            }) {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "coverage.receipt_source_binding",
                });
            }
        }
        for evidence in &self.evidence {
            evidence
                .validate()
                .map_err(|_| ReactiveInputError::InvalidField {
                    field: "coverage.evidence.item",
                    reason: "invalid retained EvidenceEnvelope",
                })?;
            if evidence.state_fence != self.state_fence
                || evidence.provenance.revision.as_deref()
                    != Some(self.source.source_revision.as_str())
                || evidence.provenance.raw_handle.as_deref()
                    != Some(self.source.content_sha256.as_str())
            {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "coverage.evidence_binding",
                });
            }
        }
        if self.freshness == CoverageFreshness::Fresh
            && (self.evidence.is_empty() || self.receipts.is_empty())
        {
            return Err(ReactiveInputError::InvalidField {
                field: "coverage.evidence",
                reason: "fresh coverage needs retained evidence",
            });
        }
        Ok(())
    }

    /// Validate one evidence vector without treating a label as proof.
    pub fn validate(&self) -> Result<(), ReactiveInputError> {
        bounded_preflight(self, "coverage.event.preflight")?;
        text(&self.event, "coverage.event")?;
        if !known_event(&self.event) {
            return Err(ReactiveInputError::InvalidField {
                field: "coverage.event",
                reason: "event is outside the I7.16 logical set",
            });
        }
        text(&self.host_id, "coverage.host_id")?;
        text(&self.runtime_id, "coverage.runtime_id")?;
        text(&self.interface_id, "coverage.interface_id")?;
        text(&self.recipient_id, "coverage.recipient_id")?;
        text(&self.owner_id, "coverage.owner_id")?;
        text(
            self.claim_artifact_id.as_str(),
            "coverage.claim_artifact_id",
        )?;
        text(&self.claim_digest, "coverage.claim_digest")?;
        if !matches!(
            self.ordering.as_str(),
            "PRE_DISPATCH" | "POST_DISPATCH" | "UNKNOWN"
        ) {
            return Err(ReactiveInputError::InvalidField {
                field: "coverage.ordering",
                reason: "ordering must be PRE_DISPATCH, POST_DISPATCH, or UNKNOWN",
            });
        }
        self.contract
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "coverage.contract",
                reason: "invalid contract identity",
            })?;
        if self.host_generation.value() == 0
            || self.runtime_generation.value() == 0
            || self.recipient_generation.value() == 0
        {
            return Err(ReactiveInputError::InvalidField {
                field: "coverage.generation",
                reason: "generation must be non-zero",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "coverage.state_fence",
                reason: "invalid State Fence",
            })?;
        self.source
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "coverage.source",
                reason: "invalid source binding",
            })?;
        if self.gaps.len() > MAX_GAPS
            || self.receipts.len() > MAX_EVIDENCE
            || self.evidence.len() > MAX_EVIDENCE
        {
            return Err(ReactiveInputError::InvalidField {
                field: "coverage.evidence",
                reason: "evidence exceeds bounded collection size",
            });
        }
        for gap in &self.gaps {
            text(gap, "coverage.gaps.item")?;
        }
        self.validate_support()?;
        if self.claim_digest != self.canonical_claim_digest()? {
            return Err(ReactiveInputError::DigestMismatch {
                field: "coverage.claim_digest",
            });
        }
        let claim_receipt = self.receipts.iter().any(|receipt| {
            matches!(
                &receipt.core.disposition,
                eliot_receipts::ReceiptDisposition::Success { .. }
            ) && receipt.core.authority.authority_owner == self.owner_id
                && receipt.core.artifacts.iter().any(|artifact| {
                    artifact.artifact_id == self.claim_artifact_id
                        && artifact.sha256 == self.claim_digest
                        && artifact.source_revision.as_deref()
                            == Some(self.source.source_revision.as_str())
                })
        });
        if self.freshness == CoverageFreshness::Fresh && !claim_receipt {
            return Err(ReactiveInputError::BindingMismatch {
                field: "coverage.claim_receipt",
            });
        }
        if self.freshness == CoverageFreshness::ExplicitlyUnavailable && self.gaps.is_empty() {
            return Err(ReactiveInputError::InvalidField {
                field: "coverage.gaps",
                reason: "explicit unavailability needs a gap reason",
            });
        }
        Ok(())
    }
}

/// Immutable host/runtime/interface capability profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCoverageProfile {
    pub host_id: String,
    pub runtime_id: String,
    pub interface_id: String,
    pub contract: ContractIdentity,
    pub recipient_id: String,
    pub host_generation: ResourceGeneration,
    pub runtime_generation: ResourceGeneration,
    pub recipient_generation: ResourceGeneration,
    pub profile_revision: String,
    pub completeness: SnapshotCompleteness,
    pub supported_modes: Vec<ReactiveDeliveryMode>,
    pub privacy_ceiling: ReactiveContextPrivacy,
    pub effect_ceiling: EffectClass,
    pub proof_ceiling: ProofCeiling,
    pub state_fence: StateFence,
    pub events: Vec<CoverageEvidence>,
    pub gaps: Vec<String>,
    pub profile_digest: String,
}

impl IntegrationCoverageProfile {
    fn validate_identity(&self) -> Result<(), ReactiveInputError> {
        for (value, field) in [
            (&self.host_id, "coverage.host_id"),
            (&self.runtime_id, "coverage.runtime_id"),
            (&self.interface_id, "coverage.interface_id"),
            (&self.recipient_id, "coverage.recipient_id"),
            (&self.profile_revision, "coverage.profile_revision"),
        ] {
            text(value, field)?;
        }
        self.contract
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "coverage.contract",
                reason: "invalid contract identity",
            })?;
        self.state_fence
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "coverage.state_fence",
                reason: "invalid State Fence",
            })?;
        if self.host_generation.value() == 0
            || self.runtime_generation.value() == 0
            || self.recipient_generation.value() == 0
        {
            return Err(ReactiveInputError::InvalidField {
                field: "coverage.generation",
                reason: "generation must be non-zero",
            });
        }
        Ok(())
    }

    fn validate_events(&self) -> Result<(), ReactiveInputError> {
        let mut names = std::collections::BTreeSet::new();
        for event in &self.events {
            event.validate()?;
            if event.host_id != self.host_id
                || event.runtime_id != self.runtime_id
                || event.interface_id != self.interface_id
                || event.contract != self.contract
                || event.recipient_id != self.recipient_id
                || event.host_generation != self.host_generation
                || event.runtime_generation != self.runtime_generation
                || event.recipient_generation != self.recipient_generation
                || event.state_fence != self.state_fence
                || event.source.contract != self.contract
                || event.source.source_revision != self.profile_revision
            {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "coverage.event_profile_binding",
                });
            }
            if !names.insert(event.event.clone()) {
                return Err(ReactiveInputError::InvalidField {
                    field: "coverage.events",
                    reason: "duplicate lifecycle event",
                });
            }
        }
        if matches!(self.completeness, SnapshotCompleteness::Complete)
            && (self.events.len() != I716_EVENTS.len()
                || I716_EVENTS.iter().any(|event| !names.contains(*event)))
        {
            return Err(ReactiveInputError::InvalidField {
                field: "coverage.events",
                reason: "complete profile must contain the ten I7.16 events",
            });
        }
        Ok(())
    }

    /// Compute the digest over every safety-relevant profile field.
    pub fn canonical_digest(&self) -> Result<String, ReactiveInputError> {
        canonical_planning_digest(&CanonicalProfile {
            host_id: &self.host_id,
            runtime_id: &self.runtime_id,
            interface_id: &self.interface_id,
            contract: &self.contract,
            recipient_id: &self.recipient_id,
            host_generation: &self.host_generation,
            runtime_generation: &self.runtime_generation,
            recipient_generation: &self.recipient_generation,
            profile_revision: &self.profile_revision,
            completeness: &self.completeness,
            supported_modes: &self.supported_modes,
            privacy_ceiling: &self.privacy_ceiling,
            effect_ceiling: &self.effect_ceiling,
            proof_ceiling: &self.proof_ceiling,
            state_fence: &self.state_fence,
            events: &self.events,
            gaps: &self.gaps,
        })
    }

    /// Validate exact identities, event evidence, gaps, and profile digest.
    pub fn validate(&self) -> Result<(), ReactiveInputError> {
        bounded_preflight(self, "coverage.preflight")?;
        self.validate_identity()?;
        if self.events.len() > MAX_EVENTS || self.gaps.len() > MAX_GAPS {
            return Err(ReactiveInputError::InvalidField {
                field: "coverage.events",
                reason: "profile exceeds bounded collection size",
            });
        }
        if !matches!(self.completeness, SnapshotCompleteness::Complete) && self.gaps.is_empty() {
            return Err(ReactiveInputError::InvalidField {
                field: "coverage.gaps",
                reason: "incomplete profile needs explicit gaps",
            });
        }
        self.validate_events()?;
        let mut modes = Vec::new();
        for mode in &self.supported_modes {
            if modes.contains(mode) {
                return Err(ReactiveInputError::InvalidField {
                    field: "coverage.supported_modes",
                    reason: "supported modes must be unique",
                });
            }
            modes.push(*mode);
        }
        for gap in &self.gaps {
            text(gap, "coverage.gaps.item")?;
        }
        let expected = self.canonical_digest()?;
        if self.profile_digest != expected {
            return Err(ReactiveInputError::DigestMismatch {
                field: "coverage.profile_digest",
            });
        }
        Ok(())
    }
}
