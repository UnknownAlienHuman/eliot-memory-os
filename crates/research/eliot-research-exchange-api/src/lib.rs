//! Stable, store-neutral contracts for the ELIOT Research federation channel.
//!
//! These records deliberately do not contain provider credentials, arbitrary
//! URLs as authority, or promotion decisions.  A bridge may acquire material,
//! while Governor-owned code remains responsible for admission and lifecycle.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{ClockReading, ContractVersion, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.research.exchange-api";
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ResearchContractError {
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    #[error("{field} contains a duplicate identity")]
    DuplicateIdentity { field: &'static str },
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("state fence is not valid or does not match")]
    InvalidFence,
    #[error("citation references a source outside the allowed manifest")]
    CitationNotAllowed,
    #[error("citation precision exceeds the declared source anchor")]
    UnsupportedPrecision,
    #[error("bundle disposition is incompatible with its evidence")]
    InvalidDisposition,
}

fn text(value: &str, field: &'static str) -> Result<(), ResearchContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ResearchContractError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn texts(values: &[String], field: &'static str) -> Result<(), ResearchContractError> {
    if values.is_empty() {
        return Err(ResearchContractError::EmptyCollection { field });
    }
    for value in values {
        text(value, field)?;
    }
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        return Err(ResearchContractError::DuplicateIdentity { field });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), ResearchContractError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        Err(ResearchContractError::InvalidDigest { field })
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceClass {
    Paper,
    Documentation,
    Dataset,
    Repository,
    Web,
    Report,
    ServiceDossier,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureClass {
    Private,
    ProjectBound,
    ExportableRedacted,
    Public,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompletionDisposition {
    AnsweredWithSupportedResult,
    NoMatchInCompleteScope,
    NoNewUsefulEvidence,
    SourceUnavailable,
    StaleSourceOrIndex,
    PolicyOrDisclosureDenied,
    IncompleteCoverage,
    Inconclusive,
    Cancelled,
}

impl CompletionDisposition {
    #[must_use]
    pub const fn may_close_inquiry(self) -> bool {
        matches!(
            self,
            Self::AnsweredWithSupportedResult | Self::NoMatchInCompleteScope
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AllowedReferenceManifest {
    pub run_id: String,
    pub state_fence: StateFence,
    pub source_handles: Vec<String>,
    pub evidence_handles: Vec<String>,
    pub artifact_handles: Vec<String>,
    pub allowed_anchor_precision: AnchorPrecision,
    pub stale_or_revoked_handles: Vec<String>,
    pub digest: String,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AnchorPrecision {
    Source,
    Document,
    Page,
    Section,
    Paragraph,
    Line,
    ByteRange,
}

impl AnchorPrecision {
    fn permits(self, requested: Self) -> bool {
        self >= requested
    }
}

impl AllowedReferenceManifest {
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        text(&self.run_id, "manifest.run_id")?;
        self.state_fence
            .validate()
            .map_err(|_| ResearchContractError::InvalidFence)?;
        texts(&self.source_handles, "manifest.source_handles")?;
        for values in [&self.evidence_handles, &self.artifact_handles] {
            if !values.is_empty() {
                texts(values, "manifest.handles")?;
            }
        }
        for value in &self.stale_or_revoked_handles {
            text(value, "manifest.stale_or_revoked_handles")?;
        }
        digest(&self.digest, "manifest.digest")
    }
    #[must_use]
    pub fn allows(&self, handle: &str) -> bool {
        (self
            .source_handles
            .iter()
            .chain(&self.evidence_handles)
            .chain(&self.artifact_handles))
        .any(|candidate| candidate == handle)
            && !self.stale_or_revoked_handles.iter().any(|x| x == handle)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchQueryRequest {
    pub exchange_id: String,
    pub protocol_revision: ContractVersion,
    pub bridge_generation: String,
    pub idempotency_key: String,
    pub requester_principal: String,
    pub state_fence: StateFence,
    pub question: String,
    pub question_scope: String,
    pub expected_decision: String,
    pub source_classes: Vec<SourceClass>,
    pub coverage_goal: String,
    pub allowed_references: AllowedReferenceManifest,
    pub disclosure: DisclosureClass,
    pub retention: String,
    pub license_policy: String,
    pub budget_units: u64,
    pub deadline_ms: i64,
    pub required_schema: String,
}

impl ResearchQueryRequest {
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        for (value, field) in [
            (&self.exchange_id, "exchange_id"),
            (&self.bridge_generation, "bridge_generation"),
            (&self.idempotency_key, "idempotency_key"),
            (&self.requester_principal, "requester_principal"),
            (&self.question, "question"),
            (&self.question_scope, "question_scope"),
            (&self.expected_decision, "expected_decision"),
            (&self.coverage_goal, "coverage_goal"),
            (&self.retention, "retention"),
            (&self.license_policy, "license_policy"),
            (&self.required_schema, "required_schema"),
        ] {
            text(value, field)?;
        }
        self.state_fence
            .validate()
            .map_err(|_| ResearchContractError::InvalidFence)?;
        self.allowed_references.validate()?;
        if self.allowed_references.state_fence != self.state_fence
            || self.budget_units == 0
            || self.deadline_ms <= 0
            || self.source_classes.is_empty()
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshot {
    pub source_handle: String,
    pub class: SourceClass,
    pub title: String,
    pub locator: String,
    pub snapshot_digest: String,
    pub captured_at: ClockReading,
    pub coverage: String,
    pub disclosure: DisclosureClass,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExactCitation {
    pub source_handle: String,
    pub anchor: String,
    pub precision: AnchorPrecision,
    pub excerpt: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchClaim {
    pub claim_id: String,
    pub statement: String,
    pub citations: Vec<ExactCitation>,
    pub counterclaim_ids: Vec<String>,
    pub confidence_note: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchEvidenceBundle {
    pub exchange_id: String,
    pub job_id: String,
    pub system_generation: String,
    pub immutable_bundle_digest: String,
    pub origin_authentication: String,
    pub state_fence: StateFence,
    pub sources: Vec<SourceSnapshot>,
    pub claims: Vec<ResearchClaim>,
    pub bounded_excerpts: Vec<String>,
    pub artifact_handles: Vec<String>,
    pub coverage_unknowns: Vec<String>,
    pub failed_acquisition: Vec<String>,
    pub disposition: CompletionDisposition,
    pub synthesis_is_candidate: bool,
    pub disclosure: DisclosureClass,
    pub invalidation: Option<String>,
}

impl ResearchEvidenceBundle {
    pub fn validate_against(
        &self,
        request: &ResearchQueryRequest,
    ) -> Result<(), ResearchContractError> {
        if self.exchange_id != request.exchange_id
            || self.state_fence != request.state_fence
            || !self.synthesis_is_candidate
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        digest(
            &self.immutable_bundle_digest,
            "bundle.immutable_bundle_digest",
        )?;
        text(&self.job_id, "bundle.job_id")?;
        text(&self.system_generation, "bundle.system_generation")?;
        text(&self.origin_authentication, "bundle.origin_authentication")?;
        if self.sources.is_empty()
            && self.disposition == CompletionDisposition::AnsweredWithSupportedResult
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        for source in &self.sources {
            text(&source.source_handle, "source.source_handle")?;
            digest(&source.snapshot_digest, "source.snapshot_digest")?;
            source
                .captured_at
                .validate()
                .map_err(|_| ResearchContractError::InvalidDisposition)?;
        }
        for claim in &self.claims {
            text(&claim.claim_id, "claim.claim_id")?;
            text(&claim.statement, "claim.statement")?;
            text(&claim.confidence_note, "claim.confidence_note")?;
            if claim.citations.is_empty()
                && self.disposition == CompletionDisposition::AnsweredWithSupportedResult
            {
                return Err(ResearchContractError::CitationNotAllowed);
            }
            for citation in &claim.citations {
                if !request.allowed_references.allows(&citation.source_handle)
                    || !request
                        .allowed_references
                        .allowed_anchor_precision
                        .permits(citation.precision)
                    || !self
                        .sources
                        .iter()
                        .any(|s| s.source_handle == citation.source_handle)
                {
                    return Err(ResearchContractError::CitationNotAllowed);
                }
                text(&citation.anchor, "citation.anchor")?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchExportBundle {
    pub exchange_id: String,
    pub product_identity: String,
    pub payload_handle: String,
    pub source_handles: Vec<String>,
    pub redactions: Vec<String>,
    pub purpose: String,
    pub allowed_use: String,
    pub retention: String,
    pub return_channel: String,
    pub disclosure_decision: String,
}

impl ResearchExportBundle {
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        for (value, field) in [
            (&self.exchange_id, "export.exchange_id"),
            (&self.product_identity, "export.product_identity"),
            (&self.payload_handle, "export.payload_handle"),
            (&self.purpose, "export.purpose"),
            (&self.allowed_use, "export.allowed_use"),
            (&self.retention, "export.retention"),
            (&self.return_channel, "export.return_channel"),
            (&self.disclosure_decision, "export.disclosure_decision"),
        ] {
            text(value, field)?;
        }
        texts(&self.source_handles, "export.source_handles")
    }
}
